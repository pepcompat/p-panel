/**
 * P5 Center side with in-process fake Loki / Prometheus / notification receiver:
 * log ingest (redaction, spoofing, dedupe, 413, 429, 503, dropped counters), scrape endpoint,
 * metrics API, logs query + SSE tail (tail tokens), alert evaluator → incidents → notifications
 * (HMAC) → ack → resolve (P5-T01), channels (SSRF, secrets never returned), RBAC scope (P5-T02),
 * redaction (P5-T03), rate limits, audit.
 */
import { createHmac } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import zlib from 'node:zlib';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AlertEngineService } from '../../src/observability/alert-engine.service';
import { LogIngestService } from '../../src/observability/log-ingest.service';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  type EnrolledAgent,
  heartbeatBody,
  login,
  resetDb,
  type TestApp,
} from './helpers';
import {
  createManagedApp,
  entry,
  logBatch,
  postLogs,
  readSse,
  startFakeLoki,
  startFakeProm,
  startReceiver,
} from './p5-fixtures';

const SCRAPE_TOKEN = 'scrape-token-0123456789abcdef0123456789abcdef';
const APP_SECRET = 'Sup3r-Known-App-Secret-77';
const SIGNING_SECRET = 'whsec-signing-secret-0123456789';
const BOT_TOKEN = '123456789:AAFakeBotTokenForTests_0123456789abc';
const JWT =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

let loki: Awaited<ReturnType<typeof startFakeLoki>>;
let prom: Awaited<ReturnType<typeof startFakeProm>>;
let receiver: Awaited<ReturnType<typeof startReceiver>>;
let t: TestApp;
let gw: number;
let base: string;
let owner: string;
let admin: string;
let viewer: string;
let a: EnrolledAgent;
let b: EnrolledAgent;
let ownerId: string;
let seq = 1;
let engine: AlertEngineService;

beforeAll(async () => {
  loki = await startFakeLoki();
  prom = await startFakeProm();
  receiver = await startReceiver();
  t = await bootApp({
    PPANEL_LOKI_URL: loki.url,
    PPANEL_PROMETHEUS_URL: prom.url,
    PPANEL_METRICS_SCRAPE_TOKEN: SCRAPE_TOKEN,
    PPANEL_WEBHOOK_HTTP_ALLOWLIST: '127.0.0.1',
    PPANEL_WEBHOOK_ALLOWLIST: '127.0.0.1',
    PPANEL_TELEGRAM_API_BASE: receiver.url,
    PPANEL_NOTIFY_RETRY_BASE_MS: '5',
    PPANEL_NOTIFY_TIMEOUT_MS: '5000',
    PPANEL_LOG_INGEST_RATE_BYTES: '2048',
    PPANEL_LOG_INGEST_BURST_BYTES: '600000',
    PPANEL_LOG_TAIL_POLL_MS: '200',
    PPANEL_LOG_TAIL_MAX_SEC: '2',
    PPANEL_PUBLIC_WEB_URL: 'https://panel.example.test',
  });
  gw = await t.gateway.start(0, '127.0.0.1');
  await t.app.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${(t.app.getHttpServer().address() as AddressInfo).port}`;
  engine = t.app.get(AlertEngineService);
  engine.serverOfflineGraceUntil = new Date(0); // F-14 startup grace covered by its own test
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
  await Promise.all([loki.close(), prom.close(), receiver.close()]);
});
beforeEach(async () => {
  t.limiter.reset();
  t.app.get(LogIngestService).bucket.reset();
  t.app.get(LogIngestService).invalidateSecrets();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  viewer = await login(t, 'user1');
  ownerId = (await t.prisma.user.findUniqueOrThrow({ where: { email: 'superadmin@ppanel.local' } }))
    .id;
  a = await enrollAgent(t, owner, { name: 'node-a', environment: 'production' });
  b = await enrollAgent(t, owner, { name: 'node-b', environment: 'development' });
  await hb(a);
  await hb(b);
  loki.state.mode = 'up';
  loki.state.streams.length = 0;
  loki.state.queries.length = 0;
  prom.state.mode = 'up';
  prom.state.queries.length = 0;
  receiver.state.status = 200;
  receiver.requests.length = 0;
});

async function hb(agent: EnrolledAgent, extra: Record<string, unknown> = {}) {
  const r = await agentCall(gw, agent.creds, 'POST', '/agent/v1/heartbeat', {
    ...heartbeatBody(seq++),
    ...extra,
  });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
}

/** A user bound to exactly one server with `role`. */
async function scopedUser(role: string, serverId: string, name: string): Promise<string> {
  const email = `${name}@ppanel.local`;
  const r = await t.http
    .post('/api/v1/users')
    .set(bearer(owner))
    .send({
      email,
      password: 'scoped-password-123',
      displayName: name,
      bindings: [{ roleKey: role, scopeType: 'server', scopeId: serverId }],
    });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  const res = await t.http
    .post('/api/v1/auth/login')
    .send({ email, password: 'scoped-password-123' });
  return res.body.data.accessToken as string;
}

const staleServer = (id: string, ageSec: number) =>
  t.prisma.server.update({
    where: { id },
    data: { lastHeartbeatAt: new Date(Date.now() - ageSec * 1000) },
  });

// ================================================================ log ingest

describe('log ingest (POST /agent/v1/logs)', () => {
  it('P5-T03: re-redacts (patterns + known app secret), labels from Center records', async () => {
    const app = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
      secrets: { DB_PASSWORD: APP_SECRET },
    });
    const batch = logBatch([
      entry('GET /api?api_key=sk_live_51HxQ2abcdef123456 200'),
      entry('Authorization: Bearer abc.def-ghi_123', { level: 'warn' }),
      entry(`token=${JWT}`, { source: 'nginx_error', level: 'error' }),
      entry(`connecting with ${APP_SECRET} now`, {
        source: 'container',
        app: 'web',
        container: app.containerName,
        stream: 'stderr',
        // agent-supplied extra labels are ignored (schema strips them)
        labels: { server_id: b.serverId },
      }),
    ]);
    const r = await postLogs(gw, a.creds, batch);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data).toEqual({ accepted: 4, duplicate: false, rejected: 0 });
    const pushed = JSON.stringify(loki.state.streams);
    for (const secret of ['sk_live_51HxQ2abcdef123456', 'abc.def-ghi_123', JWT, APP_SECRET])
      expect(pushed).not.toContain(secret);
    expect(pushed).toContain('[REDACTED]');
    const labels = loki.state.streams.map((s) => s.stream);
    expect(labels).toContainEqual({
      server_id: a.serverId,
      environment: 'production',
      source: 'container',
      app_id: app.appId,
      level: 'info',
    });
    expect(labels.every((l) => l.server_id === a.serverId)).toBe(true);
    // and read back through the API: still redacted
    const q = await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(owner));
    expect(q.status, JSON.stringify(q.body)).toBe(200);
    expect(q.body.data).toHaveLength(4);
    expect(JSON.stringify(q.body)).not.toContain(APP_SECRET);
    expect(q.body.data.find((e: { appId: string | null }) => e.appId === app.appId)).toMatchObject({
      source: 'container',
      serverId: a.serverId,
      line: 'connecting with [REDACTED] now',
    });
  });

  it('P5-T03: also redacts on read lines that reached Loki unredacted (defence in depth)', async () => {
    await createManagedApp(t, {
      serverId: a.serverId,
      name: 'api',
      createdBy: ownerId,
      secrets: { API_TOKEN_VALUE: APP_SECRET },
    });
    const ns = (BigInt(Date.now()) * 1_000_000n).toString();
    loki.state.streams.push({
      stream: { server_id: a.serverId, environment: 'production', source: 'agent' },
      values: [
        [
          ns,
          `legacy line password=hunter22 and ${APP_SECRET} and ghp_0123456789abcdefghijABCDEFGHIJ`,
        ],
      ],
    });
    const q = await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(owner));
    expect(q.status).toBe(200);
    expect(q.body.data[0].line).toBe(
      'legacy line password=[REDACTED] and [REDACTED] and [REDACTED]',
    );
  });

  it('drops spoofed app/container labels (other server app, foreign container, unknown app)', async () => {
    const onA = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
    });
    const onB = await createManagedApp(t, {
      serverId: b.serverId,
      name: 'shop',
      createdBy: ownerId,
    });
    const r = await postLogs(
      gw,
      b.creds,
      logBatch([
        entry('claims app of server A', {
          source: 'container',
          app: 'web',
          container: onA.containerName,
        }),
        entry('unknown app', { source: 'container', app: 'ghost' }),
        entry('foreign container', {
          source: 'container',
          app: 'shop',
          container: 'ppanel-web-1a2b3c4d',
        }),
        entry('container source without app', { source: 'container' }),
        entry('legit', { source: 'container', app: 'shop', container: onB.containerName }),
        entry('legit nginx', { source: 'nginx_access', level: null }),
      ]),
    );
    expect(r.status).toBe(200);
    expect(r.body.data).toEqual({ accepted: 2, duplicate: false, rejected: 4 });
    expect(loki.state.streams.every((s) => s.stream.server_id === b.serverId)).toBe(true);
    expect(loki.state.streams.some((s) => s.stream.app_id === onA.appId)).toBe(false);
    const tel = await t.prisma.serverTelemetry.findUniqueOrThrow({
      where: { serverId: b.serverId },
    });
    expect(Number(tel.centerDroppedTotal)).toBe(4);
    const audit = await t.prisma.auditEvent.findFirst({
      where: { action: 'logs.ingest.rejected', targetId: b.serverId },
    });
    expect(audit?.metadata).toMatchObject({ rejected: 4 });
  });

  it('dedupes by batchId (24 h); agent drops counted as deltas of the cumulative heartbeat value', async () => {
    const batch = logBatch([entry('once')], {
      dropped: { entries: 7, since: new Date().toISOString() },
    });
    const r1 = await postLogs(gw, a.creds, batch);
    const r2 = await postLogs(gw, a.creds, batch);
    expect(r1.body.data).toMatchObject({ accepted: 1, duplicate: false });
    expect(r2.body.data).toEqual({ accepted: 0, duplicate: true });
    expect(loki.state.streams).toHaveLength(1);
    const ship = (n: number) => ({
      logShipping: {
        bufferedBytes: 0,
        bufferCapBytes: 67108864,
        droppedEntries: n,
        lastShippedAt: null,
      },
    });
    await hb(a, ship(7));
    await hb(a, ship(7)); // unchanged cumulative → no double count
    await hb(a, ship(10));
    const tel = await t.prisma.serverTelemetry.findUniqueOrThrow({
      where: { serverId: a.serverId },
    });
    expect(Number(tel.agentDroppedTotal)).toBe(10); // batch `dropped` is informational only
    expect(tel.lastDroppedAt).not.toBeNull();
  });

  it('accepts real agent entries with every optional key null (Go encoding)', async () => {
    const e = {
      ts: '2026-11-23T10:00:00.123456789Z',
      source: 'nginx_access',
      app: null,
      service: null,
      container: null,
      file: '/var/log/nginx/access.log',
      stream: null,
      level: null,
      line: 'GET / 200',
    };
    const r = await postLogs(
      gw,
      a.creds,
      logBatch([{ ...e, ts: new Date().toISOString() }], { dropped: { entries: 0, since: null } }),
    );
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data.accepted).toBe(1);
  });

  it('413 when > 1 MiB compressed or > 8 MiB decompressed; 400 on bad encoding', async () => {
    const big = await postLogs(gw, a.creds, null, { raw: zlib.gzipSync(randomBytes(1_200_000)) });
    expect(big.status).toBe(413);
    const bomb = zlib.gzipSync(Buffer.alloc(9 * 1024 * 1024, 0x61));
    expect(bomb.length).toBeLessThan(1024 * 1024);
    const r = await new Promise<number>((resolve, reject) => {
      // send pre-gzipped bytes with the gzip header
      import('node:https').then(({ default: https }) => {
        const req = https.request(
          {
            host: '127.0.0.1',
            port: gw,
            servername: 'localhost',
            method: 'POST',
            path: '/agent/v1/logs',
            key: a.creds.keyPem,
            cert: a.creds.certPem,
            ca: a.creds.caPem,
            agent: false,
            headers: { 'Content-Encoding': 'gzip', 'Content-Length': bomb.length },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on('error', reject);
        req.end(bomb);
      });
    });
    expect(r).toBe(413);
    expect(loki.state.streams).toHaveLength(0);
  });

  it('429 + Retry-After when the per-server byte budget is exhausted (batch not consumed)', async () => {
    const line = 'x'.repeat(10_000);
    const big = logBatch(Array.from({ length: 40 }, () => entry(line))); // ~420 KB decompressed
    const first = await postLogs(gw, a.creds, big);
    expect(first.status).toBe(200);
    const second = logBatch(Array.from({ length: 40 }, () => entry(line)));
    const r = await postLogs(gw, a.creds, second);
    expect(r.status).toBe(429);
    expect(Number(r.headers['retry-after'])).toBeGreaterThanOrEqual(1);
    expect(r.body.error.code).toBe('RATE_LIMITED');
    // other servers have their own budget
    expect((await postLogs(gw, b.creds, logBatch([entry('b ok')]))).status).toBe(200);
    // retried later → accepted (not recorded as duplicate)
    t.app.get(LogIngestService).bucket.reset();
    const retry = await postLogs(gw, a.creds, second);
    expect(retry.body.data).toMatchObject({ accepted: 40, duplicate: false });
  });

  it('503 when Loki is unavailable, the batch is retried successfully afterwards', async () => {
    loki.state.mode = 'down';
    const batch = logBatch([entry('during outage')]);
    const r = await postLogs(gw, a.creds, batch);
    expect(r.status).toBe(503);
    expect(r.body.error.code).toBe('LOGS_BACKEND_UNAVAILABLE');
    expect(r.headers['retry-after']).toBeDefined();
    loki.state.mode = 'up';
    const again = await postLogs(gw, a.creds, batch);
    expect(again.body.data).toEqual({ accepted: 1, duplicate: false, rejected: 0 });
  });

  it('heartbeat extension stores container samples + log shipping state', async () => {
    const app = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
    });
    await hb(a, {
      metrics: {
        cpuPct: 10,
        memPct: 20,
        diskPct: 30,
        load1: 0.1,
        netRxBytes: 1000,
        netTxBytes: 2000,
      },
      containers: [
        {
          name: app.containerName,
          app: 'web',
          state: 'running',
          health: 'healthy',
          restartCount: 2,
          cpuPct: 3.5,
          memBytes: 1048576,
        },
        { name: 'ppanel-ghost-12345678', app: 'ghost', state: 'running' },
      ],
      logShipping: { bufferedBytes: 100, bufferCapBytes: 67108864, droppedEntries: 0 },
    });
    const rows = await t.prisma.containerSample.findMany({ where: { serverId: a.serverId } });
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.name === app.containerName)?.applicationId).toBe(app.appId);
    expect(rows.find((r) => r.appName === 'ghost')?.applicationId).toBeNull();
    const fleet = await t.http.get('/api/v1/metrics/fleet').set(bearer(owner));
    const fa = fleet.body.data.find((f: { serverId: string }) => f.serverId === a.serverId);
    expect(fa).toMatchObject({
      status: 'online',
      stale: false,
      containers: { total: 2, running: 2, unhealthy: 0 },
      logShipping: { bufferedBytes: 100, droppedEntries: 0 },
    });
    // next heartbeat without the ghost container replaces the set
    await hb(a, { containers: [] });
    expect(await t.prisma.containerSample.count({ where: { serverId: a.serverId } })).toBe(0);
  });
});

// ================================================================ scrape endpoint

describe('GET /internal/metrics (Prometheus scrape)', () => {
  it('requires the static bearer and is not under /api/v1', async () => {
    expect((await t.http.get('/internal/metrics')).status).toBe(401);
    expect(
      (await t.http.get('/internal/metrics').set('Authorization', 'Bearer wrong-token')).status,
    ).toBe(401);
    expect(
      (await t.http.get('/internal/metrics').set('Authorization', `Bearer ${owner}`)).status,
    ).toBe(401);
    expect(
      (await t.http.get('/api/v1/internal/metrics').set('Authorization', `Bearer ${SCRAPE_TOKEN}`))
        .status,
    ).toBe(404); // not routed under /api/v1
  });

  it('exports fresh samples only; stale servers get ppanel_server_up 0 and no samples', async () => {
    const app = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
    });
    await hb(a, {
      metrics: { cpuPct: 42, memPct: 50, diskPct: 60, load1: 0.5, netRxBytes: 123 },
      containers: [
        {
          name: app.containerName,
          app: 'web',
          state: 'running',
          health: 'healthy',
          restartCount: 1,
          cpuPct: 2,
          memBytes: 2048,
        },
        { name: 'ppanel-web-ffffffff', app: 'web', state: 'running' }, // not the current container
      ],
    });
    await staleServer(b.serverId, 60);
    const r = await t.http.get('/internal/metrics').set('Authorization', `Bearer ${SCRAPE_TOKEN}`);
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toContain('text/plain');
    const text = r.text;
    expect(text).toContain(
      `ppanel_server_cpu_percent{server_id="${a.serverId}",environment="production"} 42`,
    );
    expect(text).toContain(
      `ppanel_server_net_rx_bytes_total{server_id="${a.serverId}",environment="production"} 123`,
    );
    expect(text).toContain(
      `ppanel_server_up{server_id="${a.serverId}",environment="production"} 1`,
    );
    expect(text).toContain(
      `ppanel_server_up{server_id="${b.serverId}",environment="development"} 0`,
    );
    expect(text).not.toMatch(new RegExp(`ppanel_server_cpu_percent\\{server_id="${b.serverId}"`));
    expect(text).toContain(
      `ppanel_container_up{server_id="${a.serverId}",environment="production",app_id="${app.appId}",service="app"} 1`,
    );
    expect(text).toContain(
      `ppanel_container_restarts_total{server_id="${a.serverId}",environment="production",app_id="${app.appId}",service="app"} 1`,
    );
    expect(text.match(/ppanel_container_cpu_percent\{/g)).toHaveLength(1);
    expect(text).toContain('# TYPE ppanel_log_dropped_entries_total counter');
  });
});

// ================================================================ metrics API

describe('metrics API (§9.2)', () => {
  it('series: fixed PromQL, null points + gaps, lastSampleAt/stale from DB', async () => {
    const r = await t.http
      .get(`/api/v1/metrics/series?scope=server&id=${a.serverId}&metric=cpu&range=1h`)
      .set(bearer(viewer));
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const d = r.body.data;
    expect(prom.state.queries[0]!.get('query')).toBe(
      `max(ppanel_server_cpu_percent{server_id="${a.serverId}"})`,
    );
    expect(d).toMatchObject({ metric: 'cpu', unit: 'percent', step: 15, stale: false });
    expect(d.points).toHaveLength(241);
    expect(d.points[0][1]).toBe(12.5);
    expect(d.points[1][1]).toBe(0); // a real 0 stays 0
    expect(d.points[2][1]).toBeNull(); // missing is null, never 0
    expect(d.gaps).toEqual([[d.points[2][0], d.to]]);
    expect(d.lastSampleAt).toBeTruthy();
    await staleServer(a.serverId, 300);
    const s = await t.http
      .get(`/api/v1/metrics/series?scope=server&id=${a.serverId}&metric=net_rx&range=24h`)
      .set(bearer(viewer));
    expect(s.body.data).toMatchObject({ stale: true, step: 300, unit: 'bytes_per_second' });
    expect(prom.state.queries[1]!.get('query')).toContain('rate(ppanel_server_net_rx_bytes_total');
  });

  it('rejects client query strings / unknown metrics; 503 when Prometheus is down', async () => {
    const bad = await t.http
      .get(`/api/v1/metrics/series?scope=server&id=${a.serverId}&metric=cpu&query=up`)
      .set(bearer(owner));
    expect(bad.status).toBe(422);
    const wrong = await t.http
      .get(`/api/v1/metrics/series?scope=app&id=${a.serverId}&metric=disk`)
      .set(bearer(owner));
    expect(wrong.status).toBe(422);
    prom.state.mode = 'down';
    const down = await t.http
      .get(`/api/v1/metrics/series?scope=server&id=${a.serverId}&metric=cpu`)
      .set(bearer(owner));
    expect(down.status).toBe(503);
    expect(down.body.error.code).toBe('METRICS_BACKEND_UNAVAILABLE');
  });

  it('rate limit: 60 metric queries / min / user → 429 Retry-After', async () => {
    for (let i = 0; i < 60; i++)
      expect((await t.http.get('/api/v1/metrics/fleet').set(bearer(viewer))).status).toBe(200);
    const r = await t.http.get('/api/v1/metrics/fleet').set(bearer(viewer));
    expect(r.status).toBe(429);
    expect(r.headers['retry-after']).toBeDefined();
    expect((await t.http.get('/api/v1/metrics/fleet').set(bearer(owner))).status).toBe(200);
  });
});

// ================================================================ P5-T02 scope

describe('P5-T02: a user bound to one server cannot reach another server', () => {
  it('metrics, logs, incidents, tail tokens of server B → 404/empty; injection escaped', async () => {
    const scoped = await scopedUser('viewer', a.serverId, 'scoped-viewer');
    const appB = await createManagedApp(t, {
      serverId: b.serverId,
      name: 'shop',
      createdBy: ownerId,
    });
    await postLogs(gw, a.creds, logBatch([entry('line from A')]));
    await postLogs(gw, b.creds, logBatch([entry('line from B secret-ish')]));

    // fleet: only A
    const fleet = await t.http.get('/api/v1/metrics/fleet').set(bearer(scoped));
    expect(fleet.body.data.map((f: { serverId: string }) => f.serverId)).toEqual([a.serverId]);
    // metrics series of B / app on B → 404 (no existence oracle)
    for (const url of [
      `/api/v1/metrics/series?scope=server&id=${b.serverId}&metric=cpu`,
      `/api/v1/metrics/series?scope=app&id=${appB.appId}&metric=cpu`,
      `/api/v1/logs/query?serverId=${b.serverId}`,
      `/api/v1/logs/query?appId=${appB.appId}`,
      `/api/v1/logs/query?appId=${appB.appId}&serverId=${a.serverId}`,
    ]) {
      const r = await t.http.get(url).set(bearer(scoped));
      expect(r.status, url).toBe(404);
    }
    expect(prom.state.queries).toHaveLength(0);
    const tok = await t.http
      .post('/api/v1/logs/tail-token')
      .set(bearer(scoped))
      .send({ serverId: b.serverId });
    expect(tok.status).toBe(404);
    // no ids → scoped roles must pick a server
    expect((await t.http.get('/api/v1/logs/query').set(bearer(scoped))).status).toBe(422);

    // own server: Loki (fake) returns A AND B streams; the Center filters to scope
    const own = await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(scoped));
    expect(own.status).toBe(200);
    expect(own.body.data.map((e: { line: string }) => e.line)).toEqual(['line from A']);
    expect(loki.state.queries.at(-1)!.get('query')).toBe(`{server_id="${a.serverId}"}`);

    // LogQL injection attempts are escaped into the line filter, never parsed as selectors
    const inj = `"} |= "" or {server_id=~".+`;
    const r = await t.http
      .get(`/api/v1/logs/query?serverId=${a.serverId}&q=${encodeURIComponent(inj)}`)
      .set(bearer(scoped));
    expect(r.status).toBe(200);
    expect(loki.state.queries.at(-1)!.get('query')).toBe(
      `{server_id="${a.serverId}"} |= "\\"} |= \\"\\" or {server_id=~\\".+"`,
    );
    expect(r.body.data.every((e: { serverId: string }) => e.serverId === a.serverId)).toBe(true);
    // crafted raw LogQL params are rejected outright
    expect(
      (await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}&query={}`).set(bearer(scoped)))
        .status,
    ).toBe(422);

    // global user without ids → server_id=~ every server
    const all = await t.http.get('/api/v1/logs/query').set(bearer(viewer));
    expect(all.status).toBe(200);
    const sent = loki.state.queries.at(-1)!.get('query')!;
    expect(sent).toMatch(/^\{server_id=~"[0-9a-f-|]+"\}$/);
    expect(sent).toContain(a.serverId);
    expect(sent).toContain(b.serverId);
    expect(all.body.data).toHaveLength(2);
    expect(all.body.paginate).toEqual({ limit: 200, hasMore: false, nextCursor: null });
    expect(all.body.meta.retention).toEqual({ days: 7 });

    // incidents of B are invisible to the scoped user
    const rule = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ name: 'offline', scopeType: 'global', kind: 'server_offline', forSec: 90 });
    expect(rule.status).toBe(201);
    await staleServer(b.serverId, 400);
    await engine.tick(new Date(Date.now() - 95_000)); // pending
    await engine.tick();
    const inc = await t.prisma.incident.findFirstOrThrow({ where: { targetId: b.serverId } });
    expect((await t.http.get('/api/v1/incidents').set(bearer(scoped))).body.data).toEqual([]);
    expect((await t.http.get(`/api/v1/incidents/${inc.id}`).set(bearer(scoped))).status).toBe(404);
    expect(
      (await t.http.post(`/api/v1/incidents/${inc.id}/acknowledge`).set(bearer(scoped)).send({}))
        .status,
    ).toBe(404);
    expect((await t.http.get('/api/v1/incidents').set(bearer(viewer))).body.data).toHaveLength(1);
  });

  it('logs rate limit: 30 / min / user → 429; Loki down → 503', async () => {
    for (let i = 0; i < 30; i++)
      expect(
        (await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(viewer))).status,
      ).toBe(200);
    const r = await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(viewer));
    expect(r.status).toBe(429);
    loki.state.mode = 'down';
    const d = await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(owner));
    expect(d.status).toBe(503);
    expect(d.body.error.code).toBe('LOGS_BACKEND_UNAVAILABLE');
  });

  it('cursor pagination and span limits', async () => {
    await postLogs(
      gw,
      a.creds,
      logBatch(
        [1, 2, 3].map((i) =>
          entry(`line ${i}`, { ts: new Date(Date.now() - i * 1000).toISOString() }),
        ),
      ),
    );
    const p1 = await t.http
      .get(`/api/v1/logs/query?serverId=${a.serverId}&limit=2`)
      .set(bearer(owner));
    expect(p1.body.data.map((e: { line: string }) => e.line)).toEqual(['line 1', 'line 2']);
    expect(p1.body.paginate.hasMore).toBe(true);
    const p2 = await t.http
      .get(
        `/api/v1/logs/query?serverId=${a.serverId}&limit=2&cursor=${p1.body.paginate.nextCursor}`,
      )
      .set(bearer(owner));
    expect(loki.state.queries.at(-1)!.get('end')).toBe(p1.body.paginate.nextCursor);
    expect(p2.status).toBe(200);
    const span = await t.http
      .get(
        `/api/v1/logs/query?serverId=${a.serverId}&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z`,
      )
      .set(bearer(owner));
    expect(span.status).toBe(422);
  });
});

// ================================================================ live tail

describe('live tail (SSE + single-use tail token)', () => {
  it('streams log events, ends after the max duration, token is single-use and param-bound', async () => {
    await postLogs(gw, a.creds, logBatch([entry('tail me'), entry('and me', { level: 'error' })]));
    const tok = await t.http
      .post('/api/v1/logs/tail-token')
      .set(bearer(viewer))
      .send({ serverId: a.serverId });
    expect(tok.status).toBe(201);
    const { token, url } = tok.body.data;
    expect(url).toBe(`/api/v1/logs/tail?serverId=${a.serverId}&token=${token}`);
    const s = await readSse(`${base}${url}`, { timeoutMs: 6000 });
    expect(s.status).toBe(200);
    expect(s.headers['content-type']).toContain('text/event-stream');
    const logs = s.events.filter((e) => e.event === 'log');
    expect(logs.map((e) => (e.data as { line: string }).line).sort()).toEqual([
      'and me',
      'tail me',
    ]);
    expect(logs[0]!.id).toMatch(/^\d{19}$/);
    expect(s.events.at(-1)).toEqual({ event: 'end', data: { reason: 'max_duration' } });
    // reuse → 401
    const again = await readSse(`${base}${url}`, { timeoutMs: 2000 });
    expect(again.status).toBe(401);
    expect(again.body).toContain('TAIL_TOKEN_INVALID');
    // bound to params: token for A used with B → 401
    const tok2 = await t.http
      .post('/api/v1/logs/tail-token')
      .set(bearer(owner))
      .send({ serverId: a.serverId });
    const swapped = await readSse(
      `${base}/api/v1/logs/tail?serverId=${b.serverId}&token=${tok2.body.data.token}`,
      { timeoutMs: 2000 },
    );
    expect(swapped.status).toBe(401);
    // no token → 422, garbage → 401
    expect(
      (await readSse(`${base}/api/v1/logs/tail?serverId=${a.serverId}`, { timeoutMs: 2000 }))
        .status,
    ).toBe(422);
  });

  it('max 3 concurrent tails per user → 429 TAIL_LIMIT_REACHED', async () => {
    const tokens = [];
    for (let i = 0; i < 4; i++)
      tokens.push(
        (
          await t.http
            .post('/api/v1/logs/tail-token')
            .set(bearer(owner))
            .send({ serverId: a.serverId })
        ).body.data.url as string,
      );
    const open = tokens.slice(0, 3).map((u) => readSse(`${base}${u}`, { timeoutMs: 4000 }));
    await new Promise((r) => setTimeout(r, 300));
    const fourth = await readSse(`${base}${tokens[3]}`, { timeoutMs: 2000 });
    expect(fourth.status).toBe(429);
    expect(fourth.body).toContain('TAIL_LIMIT_REACHED');
    for (const s of await Promise.all(open)) expect(s.status).toBe(200);
  });
});

// ================================================================ channels

describe('notification channels', () => {
  it('validates URLs (scheme / SSRF), never returns secrets, audits, RBAC', async () => {
    const mk = (config: Record<string, unknown>, token = owner) =>
      t.http
        .post('/api/v1/notification-channels')
        .set(bearer(token))
        .send({
          type: 'webhook',
          name: 'hook',
          config: { signingSecret: SIGNING_SECRET, ...config },
        });
    expect((await mk({ url: 'http://hooks.example.com/x' })).body.error.code).toBe(
      'WEBHOOK_URL_NOT_ALLOWED',
    );
    const meta = await mk({ url: 'https://169.254.169.254/latest/meta-data' });
    expect(meta.status).toBe(422);
    expect(meta.body.error.details).toEqual({ reason: 'metadata_address' });
    expect((await mk({ url: 'https://10.0.0.8/hook' })).body.error.details).toEqual({
      reason: 'private_address',
    });
    expect((await mk({ url: `${receiver.url}/hook` }, viewer)).status).toBe(403);
    const ok = await mk({ url: `${receiver.url}/hook/secret-path-token` });
    expect(ok.status, JSON.stringify(ok.body)).toBe(201);
    expect(ok.body.data.config).toEqual({
      url: `${receiver.url}/…`,
      signingSecret: { set: true },
    });
    const tg = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'telegram',
        name: 'tg',
        config: { botToken: BOT_TOKEN, chatId: '-100200300' },
      });
    expect(tg.status).toBe(201);
    const list = await t.http.get('/api/v1/notification-channels').set(bearer(owner));
    const get = await t.http
      .get(`/api/v1/notification-channels/${tg.body.data.id}`)
      .set(bearer(owner));
    const patch = await t.http
      .patch(`/api/v1/notification-channels/${ok.body.data.id}`)
      .set(bearer(owner))
      .set('If-Match', '1')
      .send({ name: 'hook2', config: { signingSecret: 'another-signing-secret-123' } });
    expect(patch.status, JSON.stringify(patch.body)).toBe(200);
    expect(patch.body.data.version).toBe(2);
    const stale = await t.http
      .patch(`/api/v1/notification-channels/${ok.body.data.id}`)
      .set(bearer(owner))
      .set('If-Match', '1')
      .send({ name: 'x' });
    expect(stale.status).toBe(409);
    for (const res of [ok, tg, list, get, patch])
      for (const secret of [
        SIGNING_SECRET,
        BOT_TOKEN,
        'another-signing-secret-123',
        'secret-path-token',
      ])
        expect(JSON.stringify(res.body)).not.toContain(secret);
    const row = await t.prisma.notificationChannel.findUniqueOrThrow({
      where: { id: tg.body.data.id },
    });
    expect(row.configEncrypted).not.toContain(BOT_TOKEN);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'notification_channel.create', result: 'success' },
      }),
    ).toBe(2);
    const audits = await t.prisma.auditEvent.findMany({
      where: { action: { startsWith: 'notification_channel' } },
    });
    expect(JSON.stringify(audits)).not.toContain(BOT_TOKEN);
  });

  it('test endpoint: webhook (HMAC) + telegram (fake API base) delivered and recorded', async () => {
    const hook = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'webhook',
        name: 'hook',
        config: { url: `${receiver.url}/hook`, signingSecret: SIGNING_SECRET },
      });
    const res = await t.http
      .post(`/api/v1/notification-channels/${hook.body.data.id}/test`)
      .set(bearer(owner));
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ delivered: true });
    const req = receiver.requests.at(-1)!;
    expect(req.headers['x-ppanel-event']).toBe('test');
    expect(req.headers['x-ppanel-signature']).toBe(
      `sha256=${createHmac('sha256', SIGNING_SECRET).update(req.body).digest('hex')}`,
    );
    expect(JSON.parse(req.body)).toMatchObject({ event: 'test', incident: null });

    const tg = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'telegram',
        name: 'tg',
        config: { botToken: BOT_TOKEN, chatId: '-100200300' },
      });
    const tr = await t.http
      .post(`/api/v1/notification-channels/${tg.body.data.id}/test`)
      .set(bearer(owner));
    expect(tr.body.data.delivered).toBe(true);
    const treq = receiver.requests.at(-1)!;
    expect(treq.path).toBe(`/bot${BOT_TOKEN}/sendMessage`);
    expect(JSON.parse(treq.body)).toMatchObject({ chat_id: '-100200300' });
    expect(JSON.stringify(tr.body)).not.toContain(BOT_TOKEN);

    receiver.state.status = 500;
    const fail = await t.http
      .post(`/api/v1/notification-channels/${tg.body.data.id}/test`)
      .set(bearer(owner));
    expect(fail.body.data).toMatchObject({ delivered: false, error: 'telegram HTTP 500' });
    const d = await t.prisma.notificationDelivery.findUniqueOrThrow({
      where: { id: fail.body.data.deliveryId },
    });
    expect(d).toMatchObject({ status: 'failed', attempts: 4 });
    const lst = await t.http
      .get(`/api/v1/notification-channels/${tg.body.data.id}`)
      .set(bearer(owner));
    expect(lst.body.data.lastDelivery).toMatchObject({ status: 'failed' });
  });
});

// ================================================================ alerts / incidents (P5-T01)

describe('P5-T01: alerts → incidents → notifications → ack → resolve', () => {
  async function webhookChannel(): Promise<string> {
    const r = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'webhook',
        name: 'ops',
        config: { url: `${receiver.url}/hook`, signingSecret: SIGNING_SECRET },
      });
    expect(r.status).toBe(201);
    return r.body.data.id as string;
  }

  it('server offline → pending → firing after forSec → HMAC webhook → ack (actor) → resolved', async () => {
    const ch = await webhookChannel();
    const rule = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({
        name: 'Node A offline',
        scopeType: 'server',
        scopeId: a.serverId,
        kind: 'server_offline',
        severity: 'critical',
        forSec: 90,
        channelIds: [ch],
      });
    expect(rule.status, JSON.stringify(rule.body)).toBe(201);
    expect(rule.body.data).toMatchObject({
      active: true,
      version: 1,
      allowedActions: ['edit', 'delete'],
    });

    const t0 = new Date(Date.now() - 100_000); // evaluate in the past so timeline order is real
    await staleServer(a.serverId, 300); // offline (> 120 s before t0)
    await engine.tick(t0);
    const pending = await t.prisma.alertState.findMany({ where: { ruleId: rule.body.data.id } });
    expect(pending).toMatchObject([{ status: 'pending', targetId: a.serverId }]);
    expect(await t.prisma.incident.count()).toBe(0);

    await engine.tick(new Date(t0.getTime() + 30_000)); // still within forSec
    expect(await t.prisma.incident.count()).toBe(0);
    await engine.tick(new Date(t0.getTime() + 91_000));
    await engine.tick(new Date(t0.getTime() + 95_000)); // dedupe: still one incident
    const incidents = await t.prisma.incident.findMany();
    expect(incidents).toHaveLength(1);
    const inc = incidents[0]!;
    expect(inc).toMatchObject({
      status: 'firing',
      severity: 'critical',
      targetName: 'node-a',
      kind: 'server_offline',
    });

    const hook = receiver.requests.filter((r) => r.path === '/hook');
    expect(hook).toHaveLength(1);
    const sig = createHmac('sha256', SIGNING_SECRET).update(hook[0]!.body).digest('hex');
    expect(hook[0]!.headers['x-ppanel-signature']).toBe(`sha256=${sig}`);
    expect(hook[0]!.headers['x-ppanel-event']).toBe('fired');
    const payload = JSON.parse(hook[0]!.body);
    expect(payload.incident).toMatchObject({
      id: inc.id,
      ruleName: 'Node A offline',
      severity: 'critical',
      target: { type: 'server', id: a.serverId, name: 'node-a' },
      url: `https://panel.example.test/incidents/${inc.id}`,
    });
    expect(hook[0]!.body).not.toContain(SIGNING_SECRET);

    // viewer may see but not acknowledge (403, audited)
    const list = await t.http.get('/api/v1/incidents?status=firing').set(bearer(viewer));
    expect(list.body.data).toHaveLength(1);
    expect(list.body.data[0].allowedActions).toEqual([]);
    expect(list.body.paginate).toMatchObject({ total: 1 });
    const denied = await t.http
      .post(`/api/v1/incidents/${inc.id}/acknowledge`)
      .set(bearer(viewer))
      .send({});
    expect(denied.status).toBe(403);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'incident.acknowledge', result: 'denied' },
      }),
    ).toBe(1);

    const ack = await t.http
      .post(`/api/v1/incidents/${inc.id}/acknowledge`)
      .set(bearer(admin))
      .send({ comment: 'looking into it' });
    expect(ack.status, JSON.stringify(ack.body)).toBe(200);
    expect(ack.body.data).toMatchObject({
      status: 'acknowledged',
      acknowledgedBy: { displayName: 'Ops Admin' },
      allowedActions: ['comment'],
    });
    expect(
      (await t.http.post(`/api/v1/incidents/${inc.id}/acknowledge`).set(bearer(admin)).send({}))
        .body.error.code,
    ).toBe('INCIDENT_STATE_INVALID');
    const adminId = (
      await t.prisma.user.findUniqueOrThrow({ where: { email: 'admin@ppanel.local' } })
    ).id;
    const auditAck = await t.prisma.auditEvent.findFirstOrThrow({
      where: { action: 'incident.acknowledge', result: 'success' },
    });
    expect(auditAck).toMatchObject({ actorId: adminId, targetId: inc.id });
    const cm = await t.http
      .post(`/api/v1/incidents/${inc.id}/comment`)
      .set(bearer(admin))
      .send({ comment: 'restarted' });
    expect(cm.status).toBe(201);

    // server back → resolved (+ resolved notification)
    await hb(a);
    await engine.tick(new Date());
    const resolved = await t.http.get(`/api/v1/incidents/${inc.id}`).set(bearer(viewer));
    expect(resolved.body.data.status).toBe('resolved');
    expect(resolved.body.data.timeline.map((e: { type: string }) => e.type)).toEqual([
      'fired',
      'notified',
      'acknowledged',
      'comment',
      'resolved',
      'notified',
    ]);
    const ackEvent = resolved.body.data.timeline.find(
      (e: { type: string }) => e.type === 'acknowledged',
    );
    expect(ackEvent).toMatchObject({
      actor: { id: adminId, displayName: 'Ops Admin' },
      detail: { comment: 'looking into it' },
    });
    expect(
      receiver.requests.filter((r) => r.path === '/hook').map((r) => r.headers['x-ppanel-event']),
    ).toEqual(['fired', 'resolved']);
    expect(await t.prisma.alertState.count()).toBe(0);
  });

  it('F-14: server_offline startup grace window, legacy short forSec clamped to the minimum', async () => {
    // legacy rule (created before the 90 s minimum) straight in the DB
    const rule = await t.prisma.alertRule.create({
      data: {
        id: '01900000-0000-7000-8000-00000000f014',
        name: 'legacy offline',
        scopeType: 'server',
        scopeId: a.serverId,
        kind: 'server_offline',
        severity: 'warning',
        forSec: 15,
        createdBy: ownerId,
      },
    });
    await staleServer(a.serverId, 600);
    const t0 = new Date(Date.now() - 120_000);
    // inside the grace window after Center start: stale servers are unknown → nothing pending
    engine.serverOfflineGraceUntil = new Date(t0.getTime() + 60_000);
    try {
      await engine.tick(t0);
      await engine.tick(new Date(t0.getTime() + 30_000));
      expect(await t.prisma.alertState.count({ where: { ruleId: rule.id } })).toBe(0);
      // grace over → pending; forSec 15 is clamped to 90, so no incident 30 s later
      await engine.tick(new Date(t0.getTime() + 61_000));
      expect(await t.prisma.alertState.findMany({ where: { ruleId: rule.id } })).toMatchObject([
        { status: 'pending' },
      ]);
      await engine.tick(new Date(t0.getTime() + 91_000));
      expect(await t.prisma.incident.count({ where: { ruleId: rule.id } })).toBe(0);
      await engine.tick(new Date(t0.getTime() + 152_000));
      expect(await t.prisma.incident.count({ where: { ruleId: rule.id } })).toBe(1);
    } finally {
      engine.serverOfflineGraceUntil = new Date(0);
    }
  });

  it('app_down: current container exited → firing; running again → resolved; manual recovery fires', async () => {
    const app = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
    });
    const rule = await t.http.post('/api/v1/alert-rules').set(bearer(owner)).send({
      name: 'web down',
      scopeType: 'app',
      scopeId: app.appId,
      kind: 'app_down',
      forSec: 0,
    });
    expect(rule.status, JSON.stringify(rule.body)).toBe(201);
    // agent not reporting containers yet → unknown, no incident
    await engine.tick();
    expect(await t.prisma.incident.count()).toBe(0);
    await hb(a, {
      containers: [{ name: app.containerName, app: 'web', state: 'exited', restartCount: 3 }],
    });
    await engine.tick();
    const inc = await t.prisma.incident.findFirstOrThrow();
    expect(inc).toMatchObject({
      targetType: 'app',
      targetId: app.appId,
      status: 'firing',
      lastValue: 1,
    });
    await hb(a, {
      containers: [{ name: app.containerName, app: 'web', state: 'running', health: 'healthy' }],
    });
    await engine.tick();
    expect((await t.prisma.incident.findUniqueOrThrow({ where: { id: inc.id } })).status).toBe(
      'resolved',
    );
    // unhealthy counts as down
    await hb(a, {
      containers: [{ name: app.containerName, app: 'web', state: 'running', health: 'unhealthy' }],
    });
    await engine.tick();
    expect(await t.prisma.incident.count({ where: { status: 'firing' } })).toBe(1);
    // last deployment requires manual recovery
    const app2 = await createManagedApp(t, {
      serverId: b.serverId,
      name: 'shop',
      createdBy: ownerId,
      status: 'requires_manual_recovery',
    });
    const r2 = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ name: 'apps down', scopeType: 'global', kind: 'app_down', forSec: 0 });
    expect(r2.status).toBe(201);
    await engine.tick();
    expect(
      await t.prisma.incident.count({ where: { targetId: app2.appId, status: 'firing' } }),
    ).toBe(1);
  });

  it('metric_threshold fires on fresh samples only (stale data never fires)', async () => {
    const rule = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({
        name: 'cpu',
        scopeType: 'environment',
        scopeId: 'production',
        kind: 'metric_threshold',
        params: { metric: 'cpu', op: 'gt', value: 80 },
        forSec: 0,
      });
    expect(rule.status, JSON.stringify(rule.body)).toBe(201);
    await hb(a, { metrics: { cpuPct: 50, memPct: 1, diskPct: 1 } });
    await engine.tick();
    expect(await t.prisma.incident.count()).toBe(0);
    // stale server with a high last sample → nothing
    await hb(a, { metrics: { cpuPct: 99, memPct: 1, diskPct: 1 } });
    await staleServer(a.serverId, 60);
    await t.prisma.server.update({
      where: { id: a.serverId },
      data: { metricsSampledAt: new Date(Date.now() - 60_000) },
    });
    await engine.tick();
    expect(await t.prisma.incident.count()).toBe(0);
    expect(await t.prisma.alertState.count()).toBe(0);
    // fresh high sample → fires (env scope: only production servers)
    await hb(a, { metrics: { cpuPct: 95, memPct: 1, diskPct: 1 } });
    await hb(b, { metrics: { cpuPct: 99, memPct: 1, diskPct: 1 } });
    await engine.tick();
    const incs = await t.prisma.incident.findMany();
    expect(incs).toHaveLength(1);
    expect(incs[0]).toMatchObject({ targetId: a.serverId, lastValue: 95 });
    // a firing threshold is NOT resolved by missing data; recovers on a fresh low value
    await staleServer(a.serverId, 60);
    await engine.tick();
    expect((await t.prisma.incident.findFirstOrThrow()).status).toBe('firing');
    await hb(a, { metrics: { cpuPct: 10, memPct: 1, diskPct: 1 } });
    await engine.tick();
    expect((await t.prisma.incident.findFirstOrThrow()).status).toBe('resolved');
  });

  it('log_dropped fires after the agent reports drops; notify failures land in the timeline', async () => {
    const ch = await webhookChannel();
    receiver.state.status = 500;
    await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({
        name: 'drops',
        scopeType: 'global',
        kind: 'log_dropped',
        forSec: 0,
        channelIds: [ch],
      });
    await hb(a, {
      logShipping: {
        bufferedBytes: 0,
        bufferCapBytes: 1048576,
        droppedEntries: 12,
        lastShippedAt: null,
      },
    });
    await engine.tick();
    const inc = await t.prisma.incident.findFirstOrThrow();
    expect(inc).toMatchObject({ kind: 'log_dropped', targetId: a.serverId, lastValue: 12 });
    const ev = await t.prisma.incidentEvent.findMany({
      where: { incidentId: inc.id },
      orderBy: { at: 'asc' },
    });
    expect(ev.map((e) => e.type)).toEqual(['fired', 'notify_failed']);
    expect(ev[1]!.detail).toMatchObject({ error: 'HTTP 500', attempts: 4 });
    expect(receiver.requests.filter((r) => r.path === '/hook')).toHaveLength(4); // 1 + 3 retries
  });

  it('rules: scope-bound RBAC, If-Match, unknown channel, disable resolves open incidents', async () => {
    const scopedOps = await scopedUser('ops_admin', a.serverId, 'scoped-ops');
    const body = { name: 'r', kind: 'server_offline', forSec: 90 };
    expect(
      (
        await t.http
          .post('/api/v1/alert-rules')
          .set(bearer(scopedOps))
          .send({ ...body, scopeType: 'global' })
      ).status,
    ).toBe(403);
    expect(
      (
        await t.http
          .post('/api/v1/alert-rules')
          .set(bearer(scopedOps))
          .send({ ...body, scopeType: 'server', scopeId: b.serverId })
      ).status,
    ).toBe(403);
    const own = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(scopedOps))
      .send({ ...body, scopeType: 'server', scopeId: a.serverId });
    expect(own.status).toBe(201);
    expect(
      (
        await t.http
          .post('/api/v1/alert-rules')
          .set(bearer(viewer))
          .send({ ...body, scopeType: 'global' })
      ).status,
    ).toBe(403);
    expect(
      (
        await t.http
          .post('/api/v1/alert-rules')
          .set(bearer(owner))
          .send({
            ...body,
            scopeType: 'global',
            channelIds: ['01900000-0000-7000-8000-000000000999'],
          })
      ).body.error.code,
    ).toBe('CHANNEL_NOT_FOUND');
    const global = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ ...body, scopeType: 'global' });
    // scoped admin lists only rules it can manage
    const mine = await t.http.get('/api/v1/alert-rules').set(bearer(scopedOps));
    expect(mine.body.data.map((r: { id: string }) => r.id)).toEqual([own.body.data.id]);
    expect(
      (await t.http.get(`/api/v1/alert-rules/${global.body.data.id}`).set(bearer(scopedOps)))
        .status,
    ).toBe(404);

    await staleServer(a.serverId, 400);
    await engine.tick(new Date(Date.now() - 95_000)); // pending (forSec 90)
    await engine.tick();
    expect(await t.prisma.incident.count({ where: { status: 'firing' } })).toBe(2);
    // F-14: forSec below the server_offline minimum → 422 (create and PATCH)
    const short = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ ...body, scopeType: 'global', forSec: 15 });
    expect([short.status, short.body.error.code]).toEqual([422, 'VALIDATION_FAILED']);
    expect(short.body.error.details).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: 'forSec' })]),
    );
    const shortPatch = await t.http
      .patch(`/api/v1/alert-rules/${own.body.data.id}`)
      .set(bearer(scopedOps))
      .send({ forSec: 30 });
    expect([shortPatch.status, shortPatch.body.error.code]).toEqual([422, 'VALIDATION_FAILED']);
    // omitted forSec → the server_offline minimum (not the generic 60)
    const dflt = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ name: 'dflt', kind: 'server_offline', scopeType: 'server', scopeId: b.serverId });
    expect(dflt.body.data.forSec).toBe(90);
    await t.http.delete(`/api/v1/alert-rules/${dflt.body.data.id}`).set(bearer(owner));
    const conflict = await t.http
      .patch(`/api/v1/alert-rules/${own.body.data.id}`)
      .set(bearer(scopedOps))
      .set('If-Match', '9')
      .send({ enabled: false });
    expect(conflict.status).toBe(409);
    const kindChange = await t.http
      .patch(`/api/v1/alert-rules/${own.body.data.id}`)
      .set(bearer(scopedOps))
      .send({ kind: 'app_down' });
    expect(kindChange.status).toBe(422);
    const off = await t.http
      .patch(`/api/v1/alert-rules/${own.body.data.id}`)
      .set(bearer(scopedOps))
      .set('If-Match', '1')
      .send({ enabled: false });
    expect(off.status, JSON.stringify(off.body)).toBe(200);
    expect(off.body.data).toMatchObject({ enabled: false, version: 2 });
    const resolved = await t.prisma.incident.findFirstOrThrow({
      where: { ruleId: own.body.data.id },
    });
    expect(resolved.status).toBe('resolved');
    // scoped ops can acknowledge the global rule's incident on its own server
    const gi = await t.prisma.incident.findFirstOrThrow({ where: { ruleId: global.body.data.id } });
    expect(
      (await t.http.post(`/api/v1/incidents/${gi.id}/acknowledge`).set(bearer(scopedOps)).send({}))
        .status,
    ).toBe(200);
    const del = await t.http
      .delete(`/api/v1/alert-rules/${global.body.data.id}`)
      .set(bearer(owner));
    expect(del.status).toBe(204);
    expect((await t.prisma.incident.findUniqueOrThrow({ where: { id: gi.id } })).status).toBe(
      'resolved',
    );
    for (const action of ['alert_rule.create', 'alert_rule.update', 'alert_rule.delete'])
      expect(
        await t.prisma.auditEvent.count({ where: { action, result: 'success' } }),
        action,
      ).toBeGreaterThan(0);
    expect(
      await t.prisma.auditEvent.count({ where: { action: 'alert_rule.create', result: 'denied' } }),
    ).toBeGreaterThanOrEqual(2);
  });

  it('backup_failed is active since P6; deleting a channel detaches it from rules', async () => {
    const ch = await webhookChannel();
    const r = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ name: 'bk', scopeType: 'global', kind: 'backup_failed', channelIds: [ch] });
    expect(r.status).toBe(201);
    expect(r.body.data.active).toBe(true); // P6 activated backup_failed (backups.spec covers firing)
    expect(
      (await t.http.delete(`/api/v1/notification-channels/${ch}`).set(bearer(owner))).status,
    ).toBe(204);
    const after = await t.http.get(`/api/v1/alert-rules/${r.body.data.id}`).set(bearer(owner));
    expect(after.body.data.channelIds).toEqual([]);
  });
});
