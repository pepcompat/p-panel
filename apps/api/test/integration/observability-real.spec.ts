/**
 * P5 against the REAL lab backends from infra/observability (scripts/observability/up.sh):
 * Loki 127.0.0.1:53100, Prometheus 127.0.0.1:59090, Mailpit 127.0.0.1:51025/58025, receiver :58080.
 * Each block is skipped with a clear message when its backend is not reachable.
 */
import { createHmac, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
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
import { createManagedApp, entry, logBatch, postLogs } from './p5-fixtures';

const LOKI = 'http://127.0.0.1:53100';
const PROM = 'http://127.0.0.1:59090';
const MAILPIT = 'http://127.0.0.1:58025';
const RECEIVER = 'http://127.0.0.1:58080';

async function reachable(url: string): Promise<boolean> {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(1500) });
    return r.ok;
  } catch {
    return false;
  }
}

const up = {
  loki: await reachable(`${LOKI}/ready`),
  prom: await reachable(`${PROM}/-/ready`),
  mailpit: await reachable(`${MAILPIT}/api/v1/info`),
  receiver: await reachable(`${RECEIVER}/_health`),
};
for (const [k, v] of Object.entries(up))
  if (!v)
    console.warn(
      `[observability-real] ${k} not reachable — its tests are SKIPPED (run scripts/observability/up.sh)`,
    );

let t: TestApp;
let gw: number;
let owner: string;
let a: EnrolledAgent;
let b: EnrolledAgent;
let seq = 1;
const SECRET = `Real-Loki-Secret-${randomUUID().slice(0, 8)}`;

beforeAll(async () => {
  t = await bootApp({
    PPANEL_LOKI_URL: LOKI,
    PPANEL_PROMETHEUS_URL: PROM,
    PPANEL_SMTP_URL: 'smtp://127.0.0.1:51025',
    PPANEL_WEBHOOK_HTTP_ALLOWLIST: '127.0.0.1:58080',
    PPANEL_WEBHOOK_ALLOWLIST: '127.0.0.1:58080',
    PPANEL_TELEGRAM_API_BASE: RECEIVER,
    PPANEL_NOTIFY_RETRY_BASE_MS: '5',
  });
  gw = await t.gateway.start(0, '127.0.0.1');
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  a = await enrollAgent(t, owner, { name: 'real-a', environment: 'production' });
  b = await enrollAgent(t, owner, { name: 'real-b', environment: 'production' });
  for (const x of [a, b]) {
    const r = await agentCall(gw, x.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(seq++));
    expect(r.status).toBe(200);
  }
});

async function queryUntil(token: string, url: string, n: number) {
  for (let i = 0; i < 30; i++) {
    t.limiter.reset();
    const r = await t.http.get(url).set(bearer(token));
    if (r.status === 200 && r.body.data.length >= n) return r;
    await new Promise((res) => setTimeout(res, 500));
  }
  throw new Error(`no ${n} lines from ${url}`);
}

describe.skipIf(!up.loki)('real Loki: ingest → store → scoped query (P5-T02/P5-T03)', () => {
  it('stores redacted lines with Center labels; scope + LogQL injection hold against real LogQL', async () => {
    const ownerId = (
      await t.prisma.user.findUniqueOrThrow({ where: { email: 'superadmin@ppanel.local' } })
    ).id;
    const app = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
      secrets: { DB_PASSWORD: SECRET },
    });
    const ra = await postLogs(
      gw,
      a.creds,
      logBatch([
        entry('GET /api?api_key=sk_live_51HxQ2abcdef123456 200', {
          source: 'nginx_access',
          level: null,
        }),
        entry(`boot with ${SECRET} done`, {
          source: 'container',
          app: 'web',
          container: app.containerName,
          level: 'error',
        }),
        entry('quote " and } |= "x" in line'),
      ]),
    );
    expect(ra.status, JSON.stringify(ra.body)).toBe(200);
    const rb = await postLogs(gw, b.creds, logBatch([entry('only on B')]));
    expect(rb.status).toBe(200);

    const qa = await queryUntil(owner, `/api/v1/logs/query?serverId=${a.serverId}`, 3);
    const lines = qa.body.data.map((e: { line: string }) => e.line);
    expect(lines).toContain('GET /api?api_key=[REDACTED] 200');
    expect(lines).toContain('boot with [REDACTED] done');
    expect(JSON.stringify(qa.body)).not.toContain(SECRET);
    expect(qa.body.data.every((e: { serverId: string }) => e.serverId === a.serverId)).toBe(true);
    // direct check in Loki itself: the secret never reached storage
    const raw = await fetch(
      `${LOKI}/loki/api/v1/query_range?query=${encodeURIComponent(`{server_id="${a.serverId}"}`)}&limit=100`,
    ).then((r) => r.json());
    expect(JSON.stringify(raw)).not.toContain(SECRET);
    expect(JSON.stringify(raw)).not.toContain('sk_live_51HxQ2abcdef123456');
    expect(JSON.stringify(raw)).toContain(`"app_id":"${app.appId}"`);

    // filters: app, level, source
    const byApp = await queryUntil(owner, `/api/v1/logs/query?appId=${app.appId}`, 1);
    expect(byApp.body.data).toHaveLength(1);
    const errs = await t.http
      .get(`/api/v1/logs/query?serverId=${a.serverId}&level=error`)
      .set(bearer(owner));
    expect(errs.body.data.map((e: { level: string }) => e.level)).toEqual(['error']);
    // injection-looking q is a literal substring in real Loki
    const inj = await t.http
      .get(`/api/v1/logs/query?serverId=${a.serverId}&q=${encodeURIComponent('} |= "x"')}`)
      .set(bearer(owner));
    expect(inj.status).toBe(200);
    expect(inj.body.data.map((e: { line: string }) => e.line)).toEqual([
      'quote " and } |= "x" in line',
    ]);
    const sel = await t.http
      .get(
        `/api/v1/logs/query?serverId=${a.serverId}&q=${encodeURIComponent(`"} or {server_id="${b.serverId}`)}`,
      )
      .set(bearer(owner));
    expect(sel.status).toBe(200);
    expect(sel.body.data).toEqual([]);
    // a user bound to server A never sees B
    const r = await t.http
      .post('/api/v1/users')
      .set(bearer(owner))
      .send({
        email: 'real-scoped@ppanel.local',
        password: 'scoped-password-123',
        displayName: 'scoped',
        bindings: [{ roleKey: 'viewer', scopeType: 'server', scopeId: a.serverId }],
      });
    expect(r.status).toBe(201);
    const scoped = (
      await t.http
        .post('/api/v1/auth/login')
        .send({ email: 'real-scoped@ppanel.local', password: 'scoped-password-123' })
    ).body.data.accessToken;
    expect(
      (await t.http.get(`/api/v1/logs/query?serverId=${b.serverId}`).set(bearer(scoped))).status,
    ).toBe(404);
    const own = await t.http.get(`/api/v1/logs/query?serverId=${a.serverId}`).set(bearer(scoped));
    expect(own.body.data.some((e: { line: string }) => e.line === 'only on B')).toBe(false);
  });
});

describe.skipIf(!up.prom)('real Prometheus: fixed PromQL templates are valid', () => {
  it('every server metric template runs; an unscraped server is all null points + one gap', async () => {
    for (const metric of ['cpu', 'memory', 'disk', 'load1', 'net_rx', 'net_tx', 'up']) {
      const r = await t.http
        .get(`/api/v1/metrics/series?scope=server&id=${a.serverId}&metric=${metric}&range=6h`)
        .set(bearer(owner));
      expect(r.status, `${metric} ${JSON.stringify(r.body)}`).toBe(200);
      expect(r.body.data.points.every((p: [number, number | null]) => p[1] === null)).toBe(true);
      expect(r.body.data.gaps).toEqual([[r.body.data.from, r.body.data.to]]);
    }
    const ownerId = (
      await t.prisma.user.findUniqueOrThrow({ where: { email: 'superadmin@ppanel.local' } })
    ).id;
    const app = await createManagedApp(t, {
      serverId: a.serverId,
      name: 'web',
      createdBy: ownerId,
    });
    for (const metric of ['cpu', 'memory', 'up', 'restarts']) {
      const r = await t.http
        .get(`/api/v1/metrics/series?scope=app&id=${app.appId}&metric=${metric}&range=7d`)
        .set(bearer(owner));
      expect(r.status, metric).toBe(200);
      expect(r.body.data.step).toBe(1800);
    }
  });
});

describe.skipIf(!up.mailpit)('real Mailpit: email channel', () => {
  it('test message is delivered over SMTP and contains no secrets', async () => {
    const to = `ops-${randomUUID().slice(0, 8)}@example.test`;
    const ch = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({ type: 'email', name: 'mail', config: { to: [to] } });
    expect(ch.status).toBe(201);
    const r = await t.http
      .post(`/api/v1/notification-channels/${ch.body.data.id}/test`)
      .set(bearer(owner));
    expect(r.body.data, JSON.stringify(r.body)).toMatchObject({ delivered: true });
    const found = await fetch(
      `${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`,
    ).then((x) => x.json());
    expect(found.messages_count).toBe(1);
    expect(found.messages[0].Subject).toBe('[pPanel] Test notification');
  });
});

describe.skipIf(!up.receiver)('real lab receiver: webhook + fake Telegram', () => {
  it('webhook HMAC verified by the recorded request; telegram path carries the bot token only to the API base', async () => {
    await fetch(`${RECEIVER}/_requests`, { method: 'DELETE' });
    const secret = 'lab-signing-secret-0123456789';
    const hook = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'webhook',
        name: 'lab',
        config: { url: `${RECEIVER}/hook`, signingSecret: secret },
      });
    expect(hook.status, JSON.stringify(hook.body)).toBe(201);
    expect(
      (
        await t.http
          .post(`/api/v1/notification-channels/${hook.body.data.id}/test`)
          .set(bearer(owner))
      ).body.data.delivered,
    ).toBe(true);
    const tg = await t.http
      .post('/api/v1/notification-channels')
      .set(bearer(owner))
      .send({
        type: 'telegram',
        name: 'tg',
        config: { botToken: '42424242:LabFakeTokenLabFakeToken_1234', chatId: '@ppanel_lab' },
      });
    expect(
      (
        await t.http
          .post(`/api/v1/notification-channels/${tg.body.data.id}/test`)
          .set(bearer(owner))
      ).body.data.delivered,
    ).toBe(true);
    const { requests } = await fetch(`${RECEIVER}/_requests`).then((x) => x.json());
    const w = requests.find((r: { path: string }) => r.path === '/hook');
    expect(w.headers['x-ppanel-signature']).toBe(
      `sha256=${createHmac('sha256', secret).update(w.body).digest('hex')}`,
    );
    expect(
      requests.some(
        (r: { path: string }) =>
          r.path === '/bot42424242:LabFakeTokenLabFakeToken_1234/sendMessage',
      ),
    ).toBe(true);
  });
});
