/**
 * P4a Center side: container apps, secrets (fetch-once via the REAL mTLS gateway), deployments
 * (preflight, candidate, route switch, stop previous, retention, rollback, redeploy/restart),
 * approvals, managed routing, GitHub webhooks (fake registry), durability, RBAC, audit.
 * The agent is simulated through the gateway (lease → ack → result).
 */
import { createHash, createHmac } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { logger } from '../../src/common/logger';
import { SweeperService } from '../../src/jobs/sweeper.service';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  type EnrolledAgent,
  heartbeatBody,
  login,
  resetDb,
  stepUpToken,
  type TestApp,
} from './helpers';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const D1 = 'a'.repeat(64);
const D2 = 'b'.repeat(64);
const D3 = 'c'.repeat(64);
const D4 = 'd'.repeat(64);
const img = (d: string) => `lab-registry:5000/ppanel-test/web@sha256:${d}`;
const SECRET = 'S3cr3t-Value-For-P4T02-xyz';
const COMMIT = '1234567890abcdef1234567890abcdef12345678';
const COMMIT2 = 'fedcba0987654321fedcba0987654321fedcba09';
/** F-7 webhook storm commits */
const STORM = ['a1', 'b2', 'c3', 'd4', 'e5'].map((p) => p.repeat(20));
const HOOK_SECRET = 'webhook-secret-0123456789';

// ------------------------------------------------------------------ fake registry (HTTP API v2)

const REG_DIGESTS: Record<string, string> = {
  [`ppanel-test/web:sha-${COMMIT.slice(0, 7)}`]: `sha256:${'e'.repeat(64)}`,
  [`ppanel-test/web:sha-${COMMIT2.slice(0, 7)}`]: `sha256:${'f'.repeat(64)}`,
  [`private/app:sha-${COMMIT.slice(0, 7)}`]: `sha256:${'9'.repeat(64)}`,
  ...Object.fromEntries(
    STORM.map((c, i) => [
      `ppanel-test/web:sha-${c.slice(0, 7)}`,
      `sha256:${String(i + 1).repeat(64)}`,
    ]),
  ),
};
const registryHits: Array<{ method: string; url: string; accept?: string; auth?: string }> = [];
let registry: http.Server;
let regHost: string;

function startRegistry(): Promise<void> {
  registry = http.createServer((req, res) => {
    registryHits.push({
      method: req.method ?? '',
      url: req.url ?? '',
      accept: req.headers.accept,
      auth: req.headers.authorization,
    });
    const u = new URL(req.url ?? '/', 'http://x');
    if (u.pathname === '/token') {
      const basic = `Basic ${Buffer.from('reguser:regpass').toString('base64')}`;
      if (req.headers.authorization !== basic) return void res.writeHead(401).end();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return void res.end(JSON.stringify({ token: 'tok-123' }));
    }
    const m = /^\/v2\/(.+)\/manifests\/([^/]+)$/.exec(u.pathname);
    if (!m) return void res.writeHead(404).end();
    const [, name, tag] = m;
    if (name!.startsWith('private/') && req.headers.authorization !== 'Bearer tok-123') {
      res.writeHead(401, {
        'WWW-Authenticate': `Bearer realm="http://${regHost}/token",service="fake",scope="repository:${name}:pull"`,
      });
      return void res.end();
    }
    const digest = REG_DIGESTS[`${name}:${tag}`];
    if (!digest) return void res.writeHead(404).end();
    res.writeHead(200, {
      'Docker-Content-Digest': digest,
      'Content-Type': 'application/vnd.oci.image.index.v1+json',
    });
    res.end(req.method === 'HEAD' ? undefined : '{}');
  });
  return new Promise((r) =>
    registry.listen(0, '127.0.0.1', () => {
      regHost = `127.0.0.1:${(registry.address() as AddressInfo).port}`;
      r();
    }),
  );
}

// ------------------------------------------------------------------ app + users

let t: TestApp;
let port: number;
let owner: string; // superadmin
let admin: string; // ops_admin (approver)
let dev: string; // deployer
let viewer: string; // user1
let agent: EnrolledAgent;
let seq = 1;
const responses: unknown[] = []; // every API body seen in the secrets test

async function boot() {
  t = await bootApp({
    PPANEL_NGINX_READ_WAIT_MS: '5000',
    PPANEL_REGISTRY_ALLOWLIST: regHost,
    PPANEL_REGISTRY_INSECURE: regHost,
  });
  port = await t.gateway.start(0, '127.0.0.1');
}

beforeAll(async () => {
  await startRegistry();
  await boot();
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
  await new Promise((r) => registry.close(r));
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  dev = await login(t, 'dev');
  viewer = await login(t, 'user1');
  agent = await enrollAgent(t, owner);
  await heartbeat(agent);
  responses.length = 0;
  registryHits.length = 0;
});

async function heartbeat(a: EnrolledAgent, metrics: Record<string, number> = {}) {
  const r = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', {
    ...heartbeatBody(seq++),
    metrics: { cpuPct: 10, memPct: 30, diskPct: 50, load1: 0.2, uptimeSec: 100, ...metrics },
  });
  expect(r.status).toBe(200);
}

// ------------------------------------------------------------------ simulated agent

interface Grant {
  jobId: string;
  type: string;
  params: any;
  leaseToken: string;
}
type Reply = { status: 'succeeded' | 'failed'; output?: unknown; error?: unknown };
type Handler = (g: Grant) => Reply | Promise<Reply>;

const ok = (output: unknown): Reply => ({ status: 'succeeded', output });
const fail = (code: string, message = code, details?: unknown): Reply => ({
  status: 'failed',
  error: { code, message, ...(details ? { details } : {}) },
});

/** Default happy agent: fetches secrets for run_candidate, applies nginx, stops/starts/removes. */
function happy(a: EnrolledAgent = agent, overrides: Record<string, Handler> = {}): Handler {
  return async (g) => {
    if (overrides[g.type]) return overrides[g.type]!(g);
    switch (g.type) {
      case 'nginx.apply':
        return ok({
          applied: true,
          files: g.params.files.map((f: any) => ({
            path: f.path,
            sha256Before: f.expectedSha256Before,
            sha256After: sha(f.content),
          })),
          nginxTestOutput: 'syntax is ok',
          reloadMethod: 'nginx -s reload',
          postchecks: g.params.postchecks.map((p: any) => ({
            hostHeader: p.hostHeader,
            path: p.path,
            status: 200,
            ok: true,
          })),
          backupId: g.params.revisionId,
        });
      case 'container.run_candidate': {
        if (g.params.secretEnvKeys.length || g.params.registryAuth) {
          const s = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/secrets`, {
            leaseToken: g.leaseToken,
          });
          if (s.status !== 200) return fail('SECRETS_UNAVAILABLE', String(s.body?.error?.code));
        }
        return ok({
          containerId: 'c'.repeat(64),
          name: g.params.name,
          image: g.params.image,
          imageId: `sha256:${'1'.repeat(64)}`,
          hostPort: g.params.hostPort,
          health: { status: 'healthy', attempts: 2, elapsedMs: 1500, lastStatus: 200 },
        });
      }
      case 'container.start':
      case 'container.restart':
        return ok({
          name: g.params.name,
          health: { status: 'healthy', attempts: 1, elapsedMs: 300 },
        });
      case 'container.stop':
        return ok({ name: g.params.name, state: 'exited' });
      case 'container.remove':
        return ok({ name: g.params.name, state: 'removed' });
      case 'container.logs':
        return ok({ lines: ['booting', 'ready'], truncated: false });
      default:
        return fail('REJECTED_UNKNOWN_TYPE');
    }
  };
}

/** Serves tasks until the queue is empty; returns the grants handled (in order). */
async function drain(
  handler: Handler = happy(),
  a: EnrolledAgent = agent,
  max = 30,
): Promise<Grant[]> {
  const done: Grant[] = [];
  for (let i = 0; i < max; i++) {
    const r = await agentCall(port, a.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    expect(r.status).toBe(200);
    const tasks = r.body.data.tasks as Grant[];
    if (tasks.length === 0) return done;
    for (const g of tasks) {
      const ack = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
        leaseToken: g.leaseToken,
      });
      expect(ack.status).toBe(200);
      const reply = await handler(g);
      const res = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
        leaseToken: g.leaseToken,
        ...reply,
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      done.push(g);
    }
  }
  return done;
}

// ------------------------------------------------------------------ API helpers

async function api(
  method: 'get' | 'post' | 'put' | 'patch' | 'delete',
  url: string,
  token = owner,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  let req = t.http[method](`/api/v1${url}`).set(bearer(token));
  for (const [k, v] of Object.entries(headers)) req = req.set(k, v);
  const r = body === undefined ? await req : await req.send(body as object);
  responses.push(r.body, r.headers);
  return r;
}

async function enableRouting(a: EnrolledAgent = agent) {
  const r = await api('post', `/servers/${a.serverId}/managed-routing`);
  expect(r.status, JSON.stringify(r.body)).toBe(202);
  const g = await drain(happy(a), a);
  expect(g.map((x) => x.type)).toEqual(['nginx.apply']);
  expect(g[0]!.params.files).toEqual([
    {
      path: '/etc/nginx/conf.d/ppanel-managed.conf',
      expectedSha256Before: null,
      content: 'include /etc/nginx/ppanel-managed/*/*.conf;\n',
    },
  ]);
  const s = await api('get', `/servers/${a.serverId}/managed-routing`);
  expect(s.body.data).toMatchObject({ enabled: true, status: 'enabled' });
}

async function createApp(
  body: Record<string, unknown> = {},
  token = owner,
  a: EnrolledAgent = agent,
) {
  const r = await api('post', '/applications', token, {
    serverId: a.serverId,
    name: 'web',
    domains: ['web.example.lab'],
    containerPort: 8080,
    healthcheck: { path: '/healthz' },
    ...body,
  });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body.data;
}

async function deploy(
  appId: string,
  image = img(D1),
  token = owner,
  headers: Record<string, string> = {},
) {
  return api('post', `/applications/${appId}/deployments`, token, { image }, headers);
}

async function getDep(id: string, token = owner) {
  const r = await api('get', `/deployments/${id}`, token);
  expect(r.status).toBe(200);
  return r.body.data;
}

async function getApp(id: string, token = owner) {
  const r = await api('get', `/applications/${id}`, token);
  expect(r.status).toBe(200);
  return r.body.data;
}

/** Ready app on a routed server, with one succeeded deployment of `image`. */
async function deployedApp(image = img(D1), body: Record<string, unknown> = {}) {
  await enableRouting();
  const app = await createApp(body);
  const r = await deploy(app.id, image);
  expect(r.status, JSON.stringify(r.body)).toBe(202);
  await drain();
  const d = await getDep(r.body.data.deployment.id);
  expect(d.status, JSON.stringify(d)).toBe('succeeded');
  return { app, d };
}

const jobsOf = (types?: string[]) =>
  t.prisma.job.findMany({
    where: { serverId: agent.serverId, ...(types ? { type: { in: types } } : {}) },
    orderBy: { createdAt: 'asc' },
  });

// ================================================================== tests

describe('P4.04/P4.05 deployment happy path, retention, managed routing', () => {
  it('container app create → deploy → candidate → route switch → succeeded; route template + postchecks', async () => {
    await enableRouting();
    const app = await createApp({
      domains: ['web.example.lab', 'www.web.example.lab'],
      env: { NODE_ENV: 'production' },
    });
    expect(app).toMatchObject({
      kind: 'container',
      ownershipMode: 'managed',
      domains: ['web.example.lab', 'www.web.example.lab'],
    });
    expect(app.container).toMatchObject({
      containerPort: 8080,
      currentDeploymentId: null,
      rollbackAvailable: false,
      routePath: '/etc/nginx/ppanel-managed/web/route.conf',
    });
    expect(app.allowedActions).toEqual(expect.arrayContaining(['deploy', 'manage_secrets']));
    expect(app.allowedActions).not.toContain('rollback');

    const r = await deploy(app.id);
    expect(r.status).toBe(202);
    const dep = r.body.data.deployment;
    expect(dep).toMatchObject({ status: 'pulling', trigger: 'manual', number: 1, image: img(D1) });
    expect(dep.preflight.every((c: any) => c.ok)).toBe(true);
    expect(dep.preflight.map((c: any) => c.check)).toEqual([
      'agent_online',
      'managed_routing',
      'image_pinned',
      'secrets_present',
      'domain_conflict',
      'port_alloc',
      'disk',
      'lock',
    ]);
    expect(dep.planHash).toMatch(/^[a-f0-9]{64}$/);
    // a second deployment while one is active → 409
    const busy = await deploy(app.id, img(D2));
    expect(busy.status).toBe(409);
    expect(busy.body.error.code).toBe('DEPLOYMENT_IN_PROGRESS');

    const grants = await drain();
    expect(grants.map((g) => g.type)).toEqual(['container.run_candidate', 'nginx.apply']);
    const run = grants[0]!.params;
    expect(run).toMatchObject({
      deploymentId: dep.id,
      app: 'web',
      image: img(D1),
      containerPort: 8080,
      hostPort: 20000,
      env: { NODE_ENV: 'production' },
      secretEnvKeys: [],
      registryAuth: false,
    });
    expect(run.name).toMatch(/^ppanel-web-[a-f0-9]{8}$/);
    const apply = grants[1]!.params;
    expect(apply.revisionId).toBe(dep.id);
    expect(apply.files).toHaveLength(1);
    expect(apply.files[0].path).toBe('/etc/nginx/ppanel-managed/web/route.conf');
    expect(apply.files[0].expectedSha256Before).toBeNull();
    expect(apply.files[0].content).toContain(
      'upstream ppanel_web { server 127.0.0.1:20000; keepalive 16; }',
    );
    expect(apply.files[0].content).toContain('server_name web.example.lab www.web.example.lab;');
    expect(apply.postchecks).toEqual([
      { hostHeader: 'web.example.lab', path: '/healthz', scheme: 'http', expectStatus: [200] },
      { hostHeader: 'www.web.example.lab', path: '/healthz', scheme: 'http', expectStatus: [200] },
    ]);

    const d = await getDep(dep.id);
    expect(d.status).toBe('succeeded');
    // P8: display labels for lists/approvals
    expect(d.applicationName).toBe(app.name);
    expect(typeof d.createdByLabel).toBe('string');
    expect(d.container).toEqual({ name: run.name, hostPort: 20000 });
    expect(d.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['preflight', 'succeeded'],
      ['pull_start', 'succeeded'],
      ['health_check', 'succeeded'],
      ['route_switch', 'succeeded'],
    ]);
    const a2 = await getApp(app.id);
    expect(a2.container).toMatchObject({
      currentDeploymentId: dep.id,
      hostPort: 20000,
      containerName: run.name,
    });
    expect(a2.nginxFiles).toEqual([
      {
        path: '/etc/nginx/ppanel-managed/web/route.conf',
        lastKnownSha256: sha(apply.files[0].content),
      },
    ]);
    expect(a2.allowedActions).toEqual(
      expect.arrayContaining(['redeploy', 'restart', 'start', 'stop', 'view_logs']),
    );
  });

  it('second deploy stops previous; retention keeps current + 2 old containers; ports reused after removal', async () => {
    const { app, d: d1 } = await deployedApp(img(D1));
    const ids = [d1.id];
    const names = [d1.container.name];
    for (const digest of [D2, D3, D4]) {
      const r = await deploy(app.id, img(digest));
      expect(r.status).toBe(202);
      const g = await drain();
      const d = await getDep(r.body.data.deployment.id);
      expect(d.status).toBe('succeeded');
      ids.push(d.id);
      names.push(d.container.name);
      expect(g.find((x) => x.type === 'container.stop')!.params).toEqual({
        app: 'web',
        name: names[names.length - 2],
      });
      // on the 2nd deploy the route switch carries the previous route checksum (drift guard)
      expect(g.find((x) => x.type === 'nginx.apply')!.params.files[0].expectedSha256Before).toMatch(
        /^[a-f0-9]{64}$/,
      );
    }
    const removes = (await jobsOf(['container.remove'])).map((j) => (j.params as any).name);
    expect(removes).toEqual([names[0]]); // 4 containers → only the oldest pruned
    const last = await getDep(ids[3]!);
    expect(last.steps.map((s: any) => s.name)).toEqual([
      'preflight',
      'pull_start',
      'health_check',
      'route_switch',
      'stop_previous',
      'prune_remove',
    ]);
    const first = await t.prisma.deployment.findUniqueOrThrow({ where: { id: ids[0] } });
    expect(first.containerRemovedAt).not.toBeNull();
    const ports = (
      await t.prisma.hostPortAllocation.findMany({
        where: { serverId: agent.serverId },
        orderBy: { port: 'asc' },
      })
    ).map((p) => p.port);
    expect(ports).toEqual([20001, 20002, 20003]);
    const a = await getApp(app.id);
    expect(a.container).toMatchObject({
      currentDeploymentId: ids[3],
      previousDeploymentId: ids[2],
      rollbackAvailable: true,
    });
  });

  it('managed routing in production: requester ≠ approver, step-up, planHash bound', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    await heartbeat(prod);
    const ownerSu = await stepUpToken(t, owner);
    const noSu = await api('post', `/servers/${prod.serverId}/managed-routing`);
    expect(noSu.body.error.code).toBe('STEP_UP_REQUIRED');
    const r = await api('post', `/servers/${prod.serverId}/managed-routing`, owner, undefined, {
      'X-Step-Up': ownerSu,
    });
    expect(r.status).toBe(202);
    expect(r.body.data).toMatchObject({
      enabled: false,
      status: 'awaiting_approval',
      approval: { required: true },
    });
    expect(await drain(happy(prod), prod)).toEqual([]); // nothing sent before approval
    const self = await api(
      'post',
      `/servers/${prod.serverId}/managed-routing/approve`,
      owner,
      { planHash: r.body.data.planHash },
      { 'X-Step-Up': ownerSu },
    );
    expect(self.body.error.code).toBe('APPROVER_IS_CREATOR');
    const adminSu = await stepUpToken(t, admin);
    const wrong = await api(
      'post',
      `/servers/${prod.serverId}/managed-routing/approve`,
      admin,
      { planHash: 'f'.repeat(64) },
      { 'X-Step-Up': adminSu },
    );
    expect(wrong.body.error.code).toBe('PLAN_HASH_MISMATCH');
    const okr = await api(
      'post',
      `/servers/${prod.serverId}/managed-routing/approve`,
      admin,
      { planHash: r.body.data.planHash },
      { 'X-Step-Up': adminSu },
    );
    expect(okr.status).toBe(202);
    expect((await drain(happy(prod), prod)).map((g) => g.type)).toEqual(['nginx.apply']);
    const s = await api('get', `/servers/${prod.serverId}/managed-routing`);
    expect(s.body.data).toMatchObject({
      enabled: true,
      approval: { approvedBy: expect.any(String) },
    });
    const again = await api('post', `/servers/${prod.serverId}/managed-routing`, owner, undefined, {
      'X-Step-Up': ownerSu,
    });
    expect(again.body.error.code).toBe('MANAGED_ROUTING_ALREADY_ENABLED');
  });
});

describe('P4-T02 secrets: set → deploy → fetch-once via gateway → never exposed', () => {
  it('value absent from every API response, job params/results, deployment, audit rows, logs, container.logs', async () => {
    const captured: string[] = [];
    const l = logger as unknown as { sink: { write(s: string): void } };
    const origSink = l.sink;
    l.sink = { write: (s: string) => void captured.push(s) };
    logger.setLevel('debug');
    try {
      await enableRouting();
      const app = await createApp({ secretKeys: ['DB_PASSWORD'] });
      // missing declared secret → preflight blocks
      const pre = await api('post', `/applications/${app.id}/deployments/preflight`, owner, {
        image: img(D1),
      });
      expect(pre.body.data.ok).toBe(false);
      expect(pre.body.data.checks.find((c: any) => c.check === 'secrets_present')).toMatchObject({
        ok: false,
        code: 'SECRETS_MISSING',
        details: { missing: ['DB_PASSWORD'] },
      });

      const put = await api('put', `/applications/${app.id}/secrets/DB_PASSWORD`, owner, {
        value: SECRET,
      });
      expect(put.status).toBe(200);
      expect(put.body.data).toEqual({ key: 'DB_PASSWORD', set: true, version: 1 });
      const bad = await api('put', `/applications/${app.id}/secrets/bad-key`, owner, {
        value: 'x',
      });
      expect(bad.status).toBe(422);
      const reserved = await api(
        'put',
        `/applications/${app.id}/secrets/__REGISTRY_AUTH__`,
        owner,
        { value: 'x' },
      );
      expect(reserved.body.error.code).toBe('SECRET_KEY_RESERVED');
      const ra = await api('put', `/applications/${app.id}/registry-auth`, owner, {
        serveraddress: 'lab-registry:5000',
        username: 'puller',
        password: 'reg-pass-123456', // gitleaks:allow (test fixture, not a credential)
      });
      expect(ra.body.data).toEqual({
        serveraddress: 'lab-registry:5000',
        username: 'puller',
        set: true,
        version: 1,
      });
      const list = await api('get', `/applications/${app.id}/secrets`, viewer);
      expect(list.body.data).toEqual([
        { key: 'DB_PASSWORD', set: true, version: 1, updatedAt: expect.any(String) },
      ]);
      expect(
        (await api('get', `/applications/${app.id}/registry-auth`, viewer)).body.data,
      ).toMatchObject({ serveraddress: 'lab-registry:5000', username: 'puller', set: true });

      const r = await deploy(app.id);
      expect(r.status).toBe(202);
      let fetched: any = null;
      let second: any = null;
      await drain(
        happy(agent, {
          'container.run_candidate': async (g) => {
            expect(g.params.secretEnvKeys).toEqual(['DB_PASSWORD']);
            expect(g.params.registryAuth).toBe(true);
            expect(JSON.stringify(g.params)).not.toContain(SECRET);
            const s1 = await agentCall(
              port,
              agent.creds,
              'POST',
              `/agent/v1/tasks/${g.jobId}/secrets`,
              { leaseToken: g.leaseToken },
            );
            fetched = s1;
            second = await agentCall(
              port,
              agent.creds,
              'POST',
              `/agent/v1/tasks/${g.jobId}/secrets`,
              { leaseToken: g.leaseToken },
            );
            // a misbehaving agent echoing the secret is scrubbed by the Center
            return ok({
              containerId: 'c'.repeat(64),
              name: g.params.name,
              image: g.params.image,
              imageId: 'sha256:' + '1'.repeat(64),
              hostPort: g.params.hostPort,
              health: { status: 'healthy', attempts: 1, elapsedMs: 10 },
              debug: `DB_PASSWORD=${SECRET}`,
            });
          },
        }),
      );
      expect(fetched.status).toBe(200);
      expect(fetched.body.data).toEqual({
        env: { DB_PASSWORD: SECRET },
        registryAuth: {
          serveraddress: 'lab-registry:5000',
          username: 'puller',
          password: 'reg-pass-123456', // gitleaks:allow (test fixture, not a credential)
        },
      });
      expect(second.status).toBe(409);
      expect(second.body.error.code).toBe('SECRETS_ALREADY_FETCHED');
      const d = await getDep(r.body.data.deployment.id);
      expect(d.status).toBe('succeeded');

      // fetch for another (non run_candidate) job / wrong lease → refused
      const logs1 = t.http.get(`/api/v1/applications/${app.id}/logs?tail=10`).set(bearer(owner));
      const logsPromise = logs1.then((x) => x);
      let logsGrant: Grant | null = null;
      await new Promise((res) => setTimeout(res, 200));
      await drain(
        happy(agent, {
          'container.logs': async (g) => {
            logsGrant = g;
            const wrongType = await agentCall(
              port,
              agent.creds,
              'POST',
              `/agent/v1/tasks/${g.jobId}/secrets`,
              { leaseToken: g.leaseToken },
            );
            expect(wrongType.status).toBe(403);
            const wrongLease = await agentCall(
              port,
              agent.creds,
              'POST',
              `/agent/v1/tasks/${g.jobId}/secrets`,
              { leaseToken: 'x'.repeat(32) },
            );
            expect(wrongLease.status).toBe(409);
            return ok({
              lines: ['start', `connecting with password ${SECRET}`, 'registry reg-pass-123456 ok'],
              truncated: false,
            });
          },
        }),
      );
      const logs = await logsPromise;
      responses.push(logs.body);
      expect(logsGrant).not.toBeNull();
      expect(logs.status).toBe(200);
      expect(logs.body.data.lines).toEqual([
        'start',
        'connecting with password [REDACTED]',
        'registry [REDACTED] ok',
      ]);

      // more reads that must not leak
      responses.push((await api('get', `/applications/${app.id}`)).body);
      responses.push((await api('get', `/applications/${app.id}/deployments`)).body);
      responses.push((await api('get', `/deployments`)).body);
      responses.push((await api('get', `/servers/${agent.serverId}/jobs?limit=100`)).body);
      responses.push((await api('get', `/audit-events?limit=100`)).body);

      const needle = [SECRET, 'reg-pass-123456'];
      for (const n of needle) {
        expect(JSON.stringify(responses)).not.toContain(n);
        const jobs = await t.prisma.job.findMany();
        expect(JSON.stringify(jobs.map((j) => [j.params, j.result, j.error]))).not.toContain(n);
        const deps = await t.prisma.deployment.findMany({ include: { steps: true } });
        expect(JSON.stringify(deps)).not.toContain(n);
        const audit = await t.prisma.auditEvent.findMany();
        expect(JSON.stringify(audit)).not.toContain(n);
        expect(captured.join('\n')).not.toContain(n);
      }
      const secretRow = await t.prisma.secret.findFirstOrThrow({ where: { key: 'DB_PASSWORD' } });
      expect(secretRow.valueEncrypted).toMatch(/^v1\./);
      expect(secretRow.valueEncrypted).not.toContain(SECRET);
      const delivered = await t.prisma.auditEvent.findMany({
        where: { action: 'secrets.delivered' },
        orderBy: { createdAt: 'asc' },
      });
      expect(delivered.map((a) => a.result)).toEqual(['success', 'denied', 'denied', 'denied']);
      expect(delivered[0]!.metadata).toMatchObject({ keys: ['DB_PASSWORD'], registryAuth: true });
      expect(delivered[1]!.metadata).toMatchObject({ reason: 'already_fetched' });
    } finally {
      l.sink = origSink;
      logger.setLevel('fatal');
    }
  });

  it('production secret writes need step-up; deployer may set, viewer may not', async () => {
    await enableRouting();
    const app = await createApp();
    expect(
      (await api('put', `/applications/${app.id}/secrets/API_KEY`, viewer, { value: 'v1-value' }))
        .status,
    ).toBe(403);
    expect(
      (await api('put', `/applications/${app.id}/secrets/API_KEY`, dev, { value: 'v1-value' }))
        .status,
    ).toBe(200);
    expect(
      (await api('put', `/applications/${app.id}/secrets/API_KEY`, dev, { value: 'v2-value' })).body
        .data.version,
    ).toBe(2);
    expect((await api('delete', `/applications/${app.id}/secrets/API_KEY`, dev)).status).toBe(204);
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    const papp = await createApp({ name: 'papp', domains: ['papp.example.lab'] }, owner, prod);
    const r = await api('put', `/applications/${papp.id}/secrets/API_KEY`, owner, {
      value: 'v1-value',
    });
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
  });
});

describe('P4-T04 failure handling', () => {
  it('unhealthy candidate → failed; previous deployment still current; no route job; port released', async () => {
    const { app, d: d1 } = await deployedApp();
    const before = await jobsOf(['nginx.apply']);
    const r = await deploy(app.id, img(D2));
    const g = await drain(
      happy(agent, {
        'container.run_candidate': () =>
          fail('CANDIDATE_UNHEALTHY', 'health check failed', {
            logTail: ['Error: boom', 'exit 1'],
            attempts: 30,
            elapsedMs: 60000,
            reason: 'timeout',
            removed: true,
            exitCode: 1,
          }),
      }),
    );
    expect(g.map((x) => x.type)).toEqual(['container.run_candidate']);
    const d = await getDep(r.body.data.deployment.id);
    expect(d.status).toBe('failed');
    expect(d.error.code).toBe('CANDIDATE_UNHEALTHY');
    expect(d.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['preflight', 'succeeded'],
      ['pull_start', 'failed'],
      ['health_check', 'failed'],
    ]);
    expect(d.steps[2].logTail).toEqual(['Error: boom', 'exit 1']);
    expect(await jobsOf(['nginx.apply'])).toHaveLength(before.length);
    const a = await getApp(app.id);
    expect(a.container.currentDeploymentId).toBe(d1.id);
    expect(a.container.hostPort).toBe(20000);
    expect(await t.prisma.hostPortAllocation.count({ where: { serverId: agent.serverId } })).toBe(
      1,
    );
    expect((await getDep(d1.id)).status).toBe('succeeded');
  });

  it('route switch failure → failed, candidate stopped+removed, previous still serving', async () => {
    const { app, d: d1 } = await deployedApp();
    const r = await deploy(app.id, img(D2));
    const g = await drain(
      happy(agent, {
        'nginx.apply': () =>
          fail('POSTCHECK_FAILED_REVERTED', 'postcheck failed', {
            postchecks: [{ hostHeader: 'web.example.lab', status: 502, ok: false }],
          }),
      }),
    );
    expect(g.map((x) => x.type)).toEqual([
      'container.run_candidate',
      'nginx.apply',
      'container.stop',
      'container.remove',
    ]);
    const cand = g[0]!.params.name;
    expect(g[2]!.params.name).toBe(cand);
    expect(g[3]!.params.name).toBe(cand);
    const d = await getDep(r.body.data.deployment.id);
    expect(d.status).toBe('failed');
    expect(d.error.code).toBe('POSTCHECK_FAILED_REVERTED');
    expect(d.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['preflight', 'succeeded'],
      ['pull_start', 'succeeded'],
      ['health_check', 'succeeded'],
      ['route_switch', 'failed'],
      ['cleanup_stop', 'succeeded'],
      ['cleanup_remove', 'succeeded'],
    ]);
    const a = await getApp(app.id);
    expect(a.container.currentDeploymentId).toBe(d1.id);
    const row = await t.prisma.deployment.findUniqueOrThrow({ where: { id: d.id } });
    expect(row.containerRemovedAt).not.toBeNull();
    expect(await t.prisma.hostPortAllocation.count({ where: { serverId: agent.serverId } })).toBe(
      1,
    );
  });

  it('REVERT_FAILED_MANUAL_RECOVERY during route switch → requires_manual_recovery, drift flagged, nothing else touched', async () => {
    const { app } = await deployedApp();
    const r = await deploy(app.id, img(D2));
    const g = await drain(
      happy(agent, { 'nginx.apply': () => fail('REVERT_FAILED_MANUAL_RECOVERY') }),
    );
    expect(g.map((x) => x.type)).toEqual(['container.run_candidate', 'nginx.apply']);
    const d = await getDep(r.body.data.deployment.id);
    expect(d.status).toBe('requires_manual_recovery');
    const a = await getApp(app.id);
    expect(a.flags.driftDetected).toBe(true);
    expect(a.driftFiles[0]).toMatchObject({
      path: '/etc/nginx/ppanel-managed/web/route.conf',
      currentSha256: 'unknown',
    });
    // lock released (not active), next deploy is allowed but drift remains visible
    expect(a.allowedActions).toContain('deploy');
  });
});

describe('P4.07 rollback, redeploy vs restart, cancel', () => {
  it('rollback starts previous container, switches route, stops current; ROLLBACK_UNAVAILABLE when no previous or previous container removed', async () => {
    await enableRouting();
    const app = await createApp();
    const none = await api('post', `/applications/${app.id}/rollback`, owner, {});
    expect(none.body.error.code).toBe('ROLLBACK_UNAVAILABLE');
    const r1 = await deploy(app.id, img(D1));
    await drain();
    const r2 = await deploy(app.id, img(D2));
    await drain();
    const d1 = await getDep(r1.body.data.deployment.id);
    const d2 = await getDep(r2.body.data.deployment.id);

    const rb = await api('post', `/applications/${app.id}/rollback`, owner, {
      reason: 'bad release',
    });
    expect(rb.status).toBe(202);
    expect(rb.body.data.deployment).toMatchObject({
      trigger: 'rollback',
      status: 'starting',
      image: img(D1),
      rollbackOfDeploymentId: d1.id,
      container: d1.container,
    });
    const g = await drain();
    expect(g.map((x) => x.type)).toEqual(['container.start', 'nginx.apply', 'container.stop']);
    expect(g[0]!.params).toMatchObject({
      app: 'web',
      name: d1.container.name,
      hostPort: d1.container.hostPort,
    });
    expect(g[1]!.params.files[0].content).toContain(`server 127.0.0.1:${d1.container.hostPort};`);
    expect(g[2]!.params.name).toBe(d2.container.name);
    const rbd = await getDep(rb.body.data.deployment.id);
    expect(rbd.status).toBe('succeeded');
    expect(rbd.steps.map((s: any) => s.name)).toEqual([
      'preflight',
      'start_target',
      'health_check',
      'route_switch',
      'stop_previous',
    ]);
    expect((await getDep(d2.id)).status).toBe('rolled_back');
    const a = await getApp(app.id);
    expect(a.container).toMatchObject({
      currentDeploymentId: rbd.id,
      previousDeploymentId: d2.id,
      containerName: d1.container.name,
      rollbackAvailable: true,
    });

    // previous container removed → ROLLBACK_UNAVAILABLE
    await t.prisma.deployment.updateMany({
      where: { containerName: d2.container.name },
      data: { containerRemovedAt: new Date() },
    });
    const un = await api('post', `/applications/${app.id}/rollback`, owner, {});
    expect(un.status).toBe(409);
    expect(un.body.error).toMatchObject({
      code: 'ROLLBACK_UNAVAILABLE',
      details: { image: img(D2) },
    });
  });

  it('redeploy = new deployment of the same digest (fresh container); restart = container.restart, no deployment', async () => {
    const { app, d: d1 } = await deployedApp();
    const re = await api('post', `/applications/${app.id}/restart`, dev);
    expect(re.status).toBe(202);
    expect(re.body.data).toMatchObject({ operation: 'restart', container: d1.container.name });
    const g1 = await drain();
    expect(g1.map((x) => [x.type, x.params.name])).toEqual([
      ['container.restart', d1.container.name],
    ]);
    expect(await t.prisma.deployment.count()).toBe(1);

    const rd = await api('post', `/applications/${app.id}/redeploy`, dev, {});
    expect(rd.status).toBe(202);
    expect(rd.body.data.deployment).toMatchObject({
      trigger: 'redeploy',
      image: d1.image,
      number: 2,
    });
    const g2 = await drain();
    expect(g2.map((x) => x.type)).toEqual([
      'container.run_candidate',
      'nginx.apply',
      'container.stop',
    ]);
    expect(g2[0]!.params.name).not.toBe(d1.container.name);
    expect(await t.prisma.deployment.count()).toBe(2);

    for (const op of ['stop', 'start'] as const) {
      const x = await api('post', `/applications/${app.id}/${op}`, dev);
      expect(x.status).toBe(202);
      expect((await drain()).map((y) => y.type)).toEqual([`container.${op}`]);
    }
    const acts = await t.prisma.auditEvent.findMany({
      where: {
        action: {
          in: [
            'applications.restart',
            'applications.stop',
            'applications.start',
            'deployments.redeploy',
            'deployments.create',
          ],
        },
      },
    });
    expect(acts.map((a) => a.action).sort()).toEqual([
      'applications.restart',
      'applications.start',
      'applications.stop',
      'deployments.create',
      'deployments.create',
    ]);
  });

  it('cancel before route_switch cancels the queued job and frees the port; idempotency key replays', async () => {
    await enableRouting();
    const app = await createApp();
    const r = await deploy(app.id, img(D1), owner, { 'Idempotency-Key': 'deploy-key-0001' });
    expect(r.status).toBe(202);
    const replay = await deploy(app.id, img(D1), owner, { 'Idempotency-Key': 'deploy-key-0001' });
    expect(replay.status).toBe(200);
    expect(replay.body.data.deployment.id).toBe(r.body.data.deployment.id);
    const c = await api('post', `/deployments/${r.body.data.deployment.id}/cancel`, dev);
    expect(c.status).toBe(200);
    expect(c.body.data.status).toBe('cancelled');
    expect(await drain()).toEqual([]);
    expect((await jobsOf(['container.run_candidate']))[0]!.status).toBe('cancelled');
    expect(await t.prisma.hostPortAllocation.count()).toBe(0);
    const again = await api('post', `/deployments/${r.body.data.deployment.id}/cancel`);
    expect(again.body.error.code).toBe('DEPLOYMENT_STATE_INVALID');
  });

  it('cancel while the candidate is running → candidate removed when it reports', async () => {
    await enableRouting();
    const app = await createApp();
    const r = await deploy(app.id);
    const lease = await agentCall(port, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    const g = lease.body.data.tasks[0] as Grant;
    await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
      leaseToken: g.leaseToken,
    });
    expect(
      (await api('post', `/deployments/${r.body.data.deployment.id}/cancel`)).body.data.status,
    ).toBe('cancelled');
    await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      ...(await happy()(g)),
    });
    expect((await drain()).map((x) => x.type)).toEqual(['container.stop', 'container.remove']);
    expect((await getDep(r.body.data.deployment.id)).status).toBe('cancelled');
  });
});

describe('P4-T07 preflight blocks unsafe execution (no job sent)', () => {
  async function expectBlocked(appId: string, code: string, image = img(D1)) {
    const before = (await jobsOf()).length;
    const r = await deploy(appId, image);
    if (code === 'IMAGE_NOT_PINNED') {
      expect(r.status).toBe(422);
      expect(r.body.error.code).toBe('IMAGE_NOT_PINNED');
    } else {
      expect(r.status, JSON.stringify(r.body)).toBe(202);
      expect(r.body.data.deployment.status).toBe('failed');
      expect(r.body.data.deployment.error.code).toBe(code);
      expect(r.body.data.deployment.preflight.find((c: any) => c.code === code).ok).toBe(false);
    }
    expect((await jobsOf()).length).toBe(before);
  }

  it('managed routing disabled', async () => {
    const app = await createApp();
    await expectBlocked(app.id, 'MANAGED_ROUTING_DISABLED');
  });

  it('agent offline, disk ≥ 90, tag-only image, secrets missing', async () => {
    await enableRouting();
    const app = await createApp({ secretKeys: ['TOKEN_X'] });
    await expectBlocked(app.id, 'SECRETS_MISSING');
    await api('put', `/applications/${app.id}/secrets/TOKEN_X`, owner, { value: 'tok-value-1' });
    await expectBlocked(app.id, 'IMAGE_NOT_PINNED', 'lab-registry:5000/ppanel-test/web:v1');
    await heartbeat(agent, { diskPct: 92 });
    await expectBlocked(app.id, 'DISK_LOW');
    await heartbeat(agent, { diskPct: 40 });
    await t.prisma.server.update({
      where: { id: agent.serverId },
      data: { lastHeartbeatAt: new Date(Date.now() - 10 * 60_000) },
    });
    await expectBlocked(app.id, 'AGENT_OFFLINE');
    // the history keeps the failed attempts (no job)
    const list = await api('get', `/applications/${app.id}/deployments`);
    expect(list.body.paginate.total).toBe(3);
  });

  it('domain conflict: at create (other app) and at deploy (discovered legacy server_name)', async () => {
    await enableRouting();
    await createApp({ name: 'one', domains: ['one.example.lab'] });
    const dup = await api('post', '/applications', owner, {
      serverId: agent.serverId,
      name: 'two',
      domains: ['one.example.lab'],
      containerPort: 80,
    });
    expect(dup.status).toBe(409);
    expect(dup.body.error).toMatchObject({
      code: 'DOMAIN_CONFLICT',
      details: {
        conflicts: [{ domain: 'one.example.lab', with: { type: 'application', name: 'one' } }],
      },
    });
    const legacyApp = await createApp({ name: 'legacy', domains: ['api.example.lab'] });
    // a later discovery scan reveals a legacy nginx server_name api.example.lab on this server
    const FIXTURE = JSON.parse(
      readFileSync(path.join(__dirname, '../fixtures/discovery-scan-result.json'), 'utf8'),
    );
    const sc = await api('post', `/servers/${agent.serverId}/discovery-scans`, owner, {});
    expect(sc.status).toBe(202);
    await drain(happy(agent, { 'discovery.scan': () => ok(FIXTURE) }));
    expect((await api('get', `/discovery-scans/${sc.body.data.scanId}`)).body.data.status).toBe(
      'completed',
    );
    const r = await deploy(legacyApp.id);
    expect(r.body.data.deployment.status).toBe('failed');
    const chk = r.body.data.deployment.preflight.find((c: any) => c.check === 'domain_conflict');
    expect(chk).toMatchObject({ ok: false, code: 'DOMAIN_CONFLICT' });
    expect(chk.details.conflicts[0]).toMatchObject({
      domain: 'api.example.lab',
      with: { type: 'discovered_nginx_server' },
    });
    // wildcard legacy server_name *.php.example.lab also conflicts at creation
    const wc = await api('post', '/applications', owner, {
      serverId: agent.serverId,
      name: 'wc',
      domains: ['x.php.example.lab'],
      containerPort: 80,
    });
    expect(wc.body.error.code).toBe('DOMAIN_CONFLICT');
  });

  it('preflight endpoint does not create anything; unknown disk blocks in production only', async () => {
    await enableRouting();
    const app = await createApp();
    await t.prisma.server.update({
      where: { id: agent.serverId },
      data: { metricsSampledAt: new Date(Date.now() - 3600_000) },
    });
    const p = await api('post', `/applications/${app.id}/deployments/preflight`, owner, {
      image: img(D1),
    });
    expect(p.status).toBe(200);
    expect(p.body.data.checks.find((c: any) => c.check === 'disk')).toMatchObject({
      ok: true,
      code: 'DISK_UNKNOWN',
      warning: true,
    });
    expect(await t.prisma.deployment.count()).toBe(0);
  });
});

describe('approvals for production deployments (§14.6)', () => {
  async function prodApp() {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    await heartbeat(prod);
    await t.prisma.managedRouting.create({
      data: {
        serverId: prod.serverId,
        status: 'enabled',
        revisionId: '01900000-0000-7000-8000-000000000001',
        planHash: 'a'.repeat(64),
        approvalRequired: true,
        createdBy: (
          await t.prisma.user.findFirstOrThrow({ where: { email: 'superadmin@ppanel.local' } })
        ).id,
      },
    });
    const app = await createApp({ name: 'papi', domains: ['papi.example.lab'] }, dev, prod);
    return { prod, app };
  }

  it('awaiting_approval → creator cannot approve → planHash change invalidates → approve once → runs', async () => {
    const { prod, app } = await prodApp();
    const r = await deploy(app.id, img(D1), dev);
    expect(r.status).toBe(202);
    const dep = r.body.data.deployment;
    expect(dep).toMatchObject({
      status: 'awaiting_approval',
      approval: { required: true, approvedBy: null },
    });
    expect(dep.allowedActions).toEqual(['cancel']); // deployer: no approvals.decide
    expect(await drain(happy(prod), prod)).toEqual([]);
    const devApprove = await api('post', `/deployments/${dep.id}/approve`, dev, {
      planHash: dep.planHash,
    });
    expect(devApprove.status).toBe(403);

    const adminSu = await stepUpToken(t, admin);
    const noSu = await api('post', `/deployments/${dep.id}/approve`, admin, {
      planHash: dep.planHash,
    });
    expect(noSu.body.error.code).toBe('STEP_UP_REQUIRED');
    const wrong = await api(
      'post',
      `/deployments/${dep.id}/approve`,
      admin,
      { planHash: 'e'.repeat(64) },
      { 'X-Step-Up': adminSu },
    );
    expect(wrong.body.error.code).toBe('PLAN_HASH_MISMATCH');

    // config change after the request → plan changed → approval impossible for this deployment
    const patch = await api('patch', `/applications/${app.id}/container`, dev, {
      env: { FEATURE: 'on' },
    });
    expect(patch.status, JSON.stringify(patch.body)).toBe(200);
    const stale = await api(
      'post',
      `/deployments/${dep.id}/approve`,
      admin,
      { planHash: dep.planHash },
      { 'X-Step-Up': adminSu },
    );
    expect(stale.status).toBe(409);
    expect(stale.body.error).toMatchObject({
      code: 'PLAN_HASH_MISMATCH',
      details: { currentPlanHash: expect.any(String) },
    });
    expect((await api('post', `/deployments/${dep.id}/cancel`, dev)).body.data.status).toBe(
      'cancelled',
    );

    const r2 = await deploy(app.id, img(D1), dev);
    const dep2 = r2.body.data.deployment;
    expect(dep2.planHash).not.toBe(dep.planHash);
    const okA = await api(
      'post',
      `/deployments/${dep2.id}/approve`,
      admin,
      { planHash: dep2.planHash },
      { 'X-Step-Up': adminSu },
    );
    expect(okA.status, JSON.stringify(okA.body)).toBe(200);
    expect(okA.body.data).toMatchObject({
      status: 'pulling',
      approval: { approvedBy: expect.any(String) },
    });
    const twice = await api(
      'post',
      `/deployments/${dep2.id}/approve`,
      admin,
      { planHash: dep2.planHash },
      { 'X-Step-Up': adminSu },
    );
    expect(twice.body.error.code).toBe('DEPLOYMENT_STATE_INVALID');
    const ap = await t.prisma.operationApproval.findMany({ where: { subjectId: dep2.id } });
    expect(ap).toHaveLength(1);
    expect(ap[0]!.usedAt).not.toBeNull();
    expect(ap[0]!.usedByJobId).not.toBeNull();
    expect((await drain(happy(prod), prod)).map((g) => g.type)).toEqual([
      'container.run_candidate',
      'nginx.apply',
    ]);
    expect((await getDep(dep2.id)).status).toBe('succeeded');
    const audits = await t.prisma.auditEvent.findMany({
      where: { action: 'deployments.approve' },
      orderBy: { createdAt: 'asc' },
    });
    expect(audits.map((a) => a.result)).toEqual(['success']);
  });

  it('restart in production requires step-up', async () => {
    const { app } = await prodApp();
    const r = await api('post', `/applications/${app.id}/restart`, dev);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
  });
});

describe('P4-T06 GitHub webhooks', () => {
  async function setup(opts: { prod?: boolean; template?: string; branches?: string[] } = {}) {
    let a = agent;
    if (opts.prod) {
      a = await enrollAgent(t, owner, { environment: 'production' });
      await heartbeat(a);
      const ownerId = (
        await t.prisma.user.findFirstOrThrow({ where: { email: 'superadmin@ppanel.local' } })
      ).id;
      await t.prisma.managedRouting.create({
        data: {
          serverId: a.serverId,
          status: 'enabled',
          revisionId: '01900000-0000-7000-8000-000000000002',
          planHash: 'a'.repeat(64),
          approvalRequired: true,
          createdBy: ownerId,
        },
      });
    } else await enableRouting();
    const app = await createApp({}, owner, a);
    const integ = await api('post', '/integrations/github', owner, {
      name: 'org',
      webhookSecret: HOOK_SECRET,
    });
    expect(integ.status).toBe(201);
    expect(integ.body.data).toMatchObject({
      webhookUrl: `/api/v1/webhooks/github/${integ.body.data.id}`,
      webhookSecret: { set: true },
    });
    expect(JSON.stringify(integ.body)).not.toContain(HOOK_SECRET);
    const pol = await api('post', `/applications/${app.id}/auto-deploy`, owner, {
      integrationId: integ.body.data.id,
      repo: 'acme/web',
      branches: opts.branches ?? ['main', 'release/*'],
      imageTemplate: opts.template ?? `${regHost}/ppanel-test/web:sha-{sha7}`,
    });
    expect(pol.status, JSON.stringify(pol.body)).toBe(201);
    return { app, integrationId: integ.body.data.id as string, a };
  }

  function push(
    integrationId: string,
    opts: {
      delivery: string;
      ref?: string;
      after?: string;
      event?: string;
      secret?: string;
      repo?: string;
    },
  ) {
    const body = JSON.stringify({
      ref: opts.ref ?? 'refs/heads/main',
      after: opts.after ?? COMMIT,
      repository: { full_name: opts.repo ?? 'acme/web' },
      pusher: { name: 'x' },
    });
    const sig = `sha256=${createHmac('sha256', opts.secret ?? HOOK_SECRET)
      .update(body)
      .digest('hex')}`;
    return t.http
      .post(`/api/v1/webhooks/github/${integrationId}`)
      .set('Content-Type', 'application/json')
      .set('X-GitHub-Event', opts.event ?? 'push')
      .set('X-GitHub-Delivery', opts.delivery)
      .set('X-Hub-Signature-256', sig)
      .send(body);
  }

  it('valid push → one deployment pinned to the resolved digest; duplicate delivery → no second; same commit → already_deployed; wrong branch ignored; bad signature 401', async () => {
    const { app, integrationId } = await setup();
    const r1 = await push(integrationId, { delivery: 'd-1' });
    expect(r1.status, JSON.stringify(r1.body)).toBe(200);
    expect(r1.body.data).toMatchObject({
      duplicate: false,
      result: 'deployed',
      deploymentIds: [expect.any(String)],
    });
    const depId = r1.body.data.deploymentIds[0];
    const d = await getDep(depId);
    expect(d).toMatchObject({
      trigger: 'webhook',
      image: `${regHost}/ppanel-test/web@sha256:${'e'.repeat(64)}`,
      sourceRef: { repo: 'acme/web', commitSha: COMMIT, branch: 'main' },
      createdBy: null,
    });
    const head = registryHits.find((h) => h.method === 'HEAD')!;
    expect(head.url).toBe(`/v2/ppanel-test/web/manifests/sha-${COMMIT.slice(0, 7)}`);
    expect(head.accept).toContain('application/vnd.oci.image.index.v1+json');
    expect(head.accept).toContain('application/vnd.docker.distribution.manifest.v2+json');

    const dup = await push(integrationId, { delivery: 'd-1' });
    expect(dup.status).toBe(200);
    expect(dup.body.data).toEqual({ duplicate: true, deliveryId: 'd-1' });
    expect(await t.prisma.deployment.count()).toBe(1);

    await drain();
    expect((await getDep(depId)).status).toBe('succeeded');
    const same = await push(integrationId, { delivery: 'd-2' });
    expect(same.body.data).toMatchObject({
      result: 'ignored',
      reasons: ['already_deployed'],
      deploymentIds: [],
    });

    const wrongBranch = await push(integrationId, {
      delivery: 'd-3',
      ref: 'refs/heads/feature/x',
      after: COMMIT2,
    });
    expect(wrongBranch.body.data).toMatchObject({
      result: 'ignored',
      reasons: ['branch_not_allowed'],
    });
    const wrongRepo = await push(integrationId, {
      delivery: 'd-4',
      repo: 'acme/other',
      after: COMMIT2,
    });
    expect(wrongRepo.body.data).toMatchObject({
      result: 'ignored',
      reasons: ['no_matching_policy'],
    });
    const notPush = await push(integrationId, { delivery: 'd-5', event: 'issues' });
    expect(notPush.body.data).toMatchObject({
      result: 'ignored',
      reasons: ['event_not_supported'],
    });
    const bad = await push(integrationId, { delivery: 'd-6', secret: 'wrong-secret-0123456789' }); // gitleaks:allow (test fixture, not a credential)
    expect(bad.status).toBe(401);
    expect(bad.body.error.code).toBe('WEBHOOK_SIGNATURE_INVALID');
    const glob = await push(integrationId, {
      delivery: 'd-7',
      ref: 'refs/heads/release/1.0',
      after: COMMIT2,
    });
    expect(glob.body.data.result).toBe('deployed');

    expect(await t.prisma.deployment.count()).toBe(2);
    const hist = await api('get', `/integrations/github/${integrationId}/deliveries`);
    expect(hist.body.data.map((x: any) => x.deliveryId)).toEqual([
      'd-7',
      'd-5',
      'd-4',
      'd-3',
      'd-2',
      'd-1',
    ]); // bad signature not stored
    const deniedAudit = await t.prisma.auditEvent.findFirst({
      where: { action: 'webhooks.github', result: 'denied' },
    });
    expect(deniedAudit?.metadata).toMatchObject({ reason: 'signature_invalid' });
    expect(app.id).toBeTruthy();
  });

  it('production → awaiting_approval (never auto-applied); bearer-token registry with app registry-auth', async () => {
    const { app, integrationId, a } = await setup({
      prod: true,
      template: `${regHost}/private/app:sha-{sha7}`,
    });
    const ownerSu = await stepUpToken(t, owner);
    await api(
      'put',
      `/applications/${app.id}/registry-auth`,
      owner,
      { serveraddress: regHost, username: 'reguser', password: 'regpass' },
      { 'X-Step-Up': ownerSu },
    );
    const r = await push(integrationId, { delivery: 'p-1' });
    expect(r.body.data).toMatchObject({ result: 'awaiting_approval' });
    const d = await getDep(r.body.data.deploymentIds[0]);
    expect(d).toMatchObject({
      status: 'awaiting_approval',
      image: `${regHost}/private/app@sha256:${'9'.repeat(64)}`,
    });
    expect(await drain(happy(a), a)).toEqual([]);
    expect(registryHits.some((h) => h.url.startsWith('/token'))).toBe(true);
    expect(registryHits.filter((h) => h.auth === 'Bearer tok-123').length).toBeGreaterThan(0);
  });

  it('F-7: commits pushed during a deployment are coalesced (latest wins), deduped, and the latest deploys when the running one ends', async () => {
    const { app, integrationId } = await setup();
    const [c1, c2, c3] = STORM as [string, string, string];
    const r1 = await push(integrationId, { delivery: 'q-1', after: c1 });
    expect(r1.body.data).toMatchObject({ result: 'deployed' });
    const r2 = await push(integrationId, { delivery: 'q-2', after: c2 });
    expect(r2.body.data).toMatchObject({
      result: 'queued',
      reasons: ['queued_behind_deployment'],
      deploymentIds: [],
    });
    const r3 = await push(integrationId, { delivery: 'q-3', after: c3 });
    expect(r3.body.data).toMatchObject({ result: 'queued' });
    // same commit as the queued one / as the running one → ignored, never failed
    const dupQueued = await push(integrationId, { delivery: 'q-4', after: c3 });
    expect(dupQueued.body.data).toMatchObject({ result: 'ignored', reasons: ['already_queued'] });
    const dupRunning = await push(integrationId, { delivery: 'q-5', after: c1 });
    expect(dupRunning.body.data).toMatchObject({
      result: 'ignored',
      reasons: ['already_deployed'],
    });
    const hist = async () =>
      Object.fromEntries(
        (await api('get', `/integrations/github/${integrationId}/deliveries`)).body.data.map(
          (x: any) => [x.deliveryId, x],
        ),
      ) as Record<string, any>;
    let h = await hist();
    expect(h['q-2']).toMatchObject({
      result: 'superseded',
      reasons: expect.arrayContaining(['superseded_by:q-3']),
    });
    expect(h['q-3'].result).toBe('queued');
    expect(await t.prisma.pendingWebhookDeploy.findMany()).toMatchObject([
      { applicationId: app.id, commitSha: c3 },
    ]);
    // first deployment finishes → the pending commit starts automatically and also finishes
    await drain();
    const deps = await t.prisma.deployment.findMany({
      where: { applicationId: app.id },
      orderBy: { number: 'asc' },
    });
    expect(deps.map((d) => [d.commitSha, d.status])).toEqual([
      [c1, 'succeeded'],
      [c3, 'succeeded'],
    ]);
    expect(await t.prisma.pendingWebhookDeploy.count()).toBe(0);
    h = await hist();
    expect(h['q-3']).toMatchObject({
      result: 'deployed',
      deploymentIds: [deps[1]!.id],
      reasons: expect.arrayContaining(['queued_behind_deployment', 'dequeued']),
    });
    expect(h['q-2'].result).toBe('superseded');
    expect(Object.values(h).filter((x: any) => x.result === 'failed')).toEqual([]);
  });

  it('F-7: webhook storm (50 concurrent deliveries, 5 commits) → one deployment at a time, no failed deliveries, the queued commit deploys afterwards', async () => {
    const { app, integrationId } = await setup();
    const reqs = STORM.flatMap((c, i) =>
      Array.from({ length: 10 }, (_, j) => ({ delivery: `s-${i}-${j}`, after: c })),
    );
    const res = await Promise.all(reqs.map((r) => push(integrationId, r)));
    for (const r of res) expect(r.status, JSON.stringify(r.body)).toBe(200);
    const results = res.map((r) => r.body.data.result as string);
    expect(results.filter((x) => x === 'failed')).toEqual([]);
    expect(results.filter((x) => x === 'deployed')).toHaveLength(1);
    const first = await t.prisma.deployment.findMany({ where: { applicationId: app.id } });
    expect(first).toHaveLength(1);
    const pending = await t.prisma.pendingWebhookDeploy.findMany();
    expect(pending).toHaveLength(1);
    expect(pending[0]!.commitSha).not.toBe(first[0]!.commitSha);
    // per commit at most one delivery is queued/deployed; the rest are ignored or superseded
    const rows = await t.prisma.webhookDelivery.findMany({ where: { integrationId } });
    expect(rows.every((r) => !r.reasons.includes('processing'))).toBe(true);
    for (const c of STORM) {
      const live = rows.filter((r) => r.after === c && ['deployed', 'queued'].includes(r.result));
      expect(live.length).toBeLessThanOrEqual(1);
    }
    expect(rows.filter((r) => r.result === 'queued')).toHaveLength(1);
    await drain();
    const deps = await t.prisma.deployment.findMany({
      where: { applicationId: app.id },
      orderBy: { number: 'asc' },
    });
    expect(deps.map((d) => d.status)).toEqual(['succeeded', 'succeeded']);
    expect(deps[1]!.commitSha).toBe(pending[0]!.commitSha);
    expect(new Set(deps.map((d) => d.commitSha)).size).toBe(2);
    expect(await t.prisma.pendingWebhookDeploy.count()).toBe(0);
    const after = await t.prisma.webhookDelivery.findMany({ where: { integrationId } });
    expect(after.filter((r) => r.result === 'failed')).toEqual([]);
    expect(after.filter((r) => r.result === 'queued')).toEqual([]);
  });

  it('F-7: cancelling the running deployment starts the queued commit; a pending commit left behind (missed hook) is started by the reconcile pass', async () => {
    const { app, integrationId } = await setup();
    const [c1, c2, c3] = STORM as [string, string, string];
    const r1 = await push(integrationId, { delivery: 'k-1', after: c1 });
    await push(integrationId, { delivery: 'k-2', after: c2 });
    expect(await t.prisma.pendingWebhookDeploy.count()).toBe(1);
    const cancel = await api('post', `/deployments/${r1.body.data.deploymentIds[0]}/cancel`);
    expect(cancel.status, JSON.stringify(cancel.body)).toBe(200);
    let deps = await t.prisma.deployment.findMany({
      where: { applicationId: app.id },
      orderBy: { number: 'asc' },
    });
    expect(deps.map((d) => [d.commitSha, d.status])).toEqual([
      [c1, 'cancelled'],
      [c2, 'pulling'],
    ]);
    await drain();
    // simulate a crash between queueing and the settled hook: pending row, nothing active
    const policy = await t.prisma.autoDeployPolicy.findFirstOrThrow({
      where: { applicationId: app.id },
    });
    const k3 = await push(integrationId, {
      delivery: 'k-3',
      after: COMMIT2,
      ref: 'refs/heads/feature/no',
    });
    await t.prisma.pendingWebhookDeploy.create({
      data: {
        applicationId: app.id,
        policyId: policy.id,
        deliveryRowId: k3.body.data.id,
        repo: 'acme/web',
        branch: 'main',
        commitSha: c3,
      },
    });
    await t.app.get(SweeperService).tick();
    deps = await t.prisma.deployment.findMany({
      where: { applicationId: app.id },
      orderBy: { number: 'asc' },
    });
    expect(deps.map((d) => [d.commitSha, d.status])).toEqual([
      [c1, 'cancelled'],
      [c2, 'succeeded'],
      [c3, 'pulling'],
    ]);
    expect(await t.prisma.pendingWebhookDeploy.count()).toBe(0);
  });

  it('registry not allowlisted → policy rejected; unknown tag → delivery failed; GitHub App BLOCKED', async () => {
    await enableRouting();
    const app = await createApp();
    const integ = await api('post', '/integrations/github', owner, {
      name: 'org',
      webhookSecret: HOOK_SECRET,
    });
    const pol = await api('post', `/applications/${app.id}/auto-deploy`, owner, {
      integrationId: integ.body.data.id,
      repo: 'acme/web',
      branches: ['main'],
      imageTemplate: 'evil.example.com/x/y:{sha}',
    });
    expect(pol.body.error.code).toBe('REGISTRY_NOT_ALLOWED');
    await api('post', `/applications/${app.id}/auto-deploy`, owner, {
      integrationId: integ.body.data.id,
      repo: 'acme/web',
      branches: ['main'],
      imageTemplate: `${regHost}/ppanel-test/web:missing-{sha7}`,
    });
    const r = await push(integ.body.data.id, { delivery: 'm-1' });
    expect(r.body.data).toMatchObject({ result: 'failed', reasons: ['IMAGE_RESOLVE_FAILED'] });
    const gh = await api('get', '/integrations/github/app', viewer);
    expect(gh.body.data).toMatchObject({
      available: false,
      reason: expect.stringContaining('BLOCKED'),
    });
    // deployer cannot create integrations nor policies (policies.manage)
    expect(
      (await api('post', '/integrations/github', dev, { name: 'x', webhookSecret: HOOK_SECRET }))
        .status,
    ).toBe(403);
    expect(
      (
        await api('post', `/applications/${app.id}/auto-deploy`, dev, {
          integrationId: integ.body.data.id,
          repo: 'acme/x',
          branches: ['main'],
          imageTemplate: `${regHost}/a/b:{sha}`,
        })
      ).status,
    ).toBe(403);
  });
});

describe('durability across API restart', () => {
  it('a deployment resumes from the database after a restart (result posted to the new instance; missed hook reconciled)', async () => {
    await enableRouting();
    const app = await createApp();
    const r = await deploy(app.id);
    const lease = await agentCall(port, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    const g = lease.body.data.tasks[0] as Grant;
    await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
      leaseToken: g.leaseToken,
    });
    // restart the Center mid-deployment
    await t.gateway.stop();
    await t.close();
    await boot();
    const res = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      ...(await happy()(g)),
    });
    expect(res.status).toBe(200);
    // route switch job was created by the new instance; simulate a crash between commit and hook:
    const lease2 = await agentCall(port, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    const g2 = lease2.body.data.tasks[0] as Grant;
    expect(g2.type).toBe('nginx.apply');
    await t.prisma.job.update({
      where: { id: g2.jobId },
      data: {
        status: 'succeeded',
        finishedAt: new Date(),
        result: (await happy()(g2)).output as object,
      },
    });
    expect(
      (await t.prisma.deployment.findUniqueOrThrow({ where: { id: r.body.data.deployment.id } }))
        .status,
    ).toBe('routing');
    await t.app.get(SweeperService).tick();
    const d = await t.prisma.deployment.findUniqueOrThrow({
      where: { id: r.body.data.deployment.id },
    });
    expect(d.status).toBe('succeeded');
  });

  it('lease expiry of the candidate job → failed via the sweeper (never re-delivered); F-8: the possibly-started candidate is stopped + removed and its port released', async () => {
    await enableRouting();
    const app = await createApp();
    const r = await deploy(app.id);
    const lease = await agentCall(port, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    expect(lease.body.data.tasks).toHaveLength(1);
    const cand = (lease.body.data.tasks[0] as Grant).params.name as string;
    await t.prisma.job.updateMany({
      where: { type: 'container.run_candidate' },
      data: { leaseUntil: new Date(Date.now() - 1000) },
    });
    await t.app.get(SweeperService).tick();
    const d = await getDep(r.body.data.deployment.id);
    expect(d).toMatchObject({ status: 'failed', error: { code: 'LEASE_EXPIRED' } });
    expect(
      await t.prisma.hostPortAllocation.count({
        where: { serverId: agent.serverId, containerName: cand },
      }),
    ).toBe(1); // still reserved until the removal is confirmed
    // the agent finished the candidate while the Center was away: the late result is refused
    const late = await agentCall(
      port,
      agent.creds,
      'POST',
      `/agent/v1/tasks/${(lease.body.data.tasks[0] as Grant).jobId}/result`,
      {
        leaseToken: (lease.body.data.tasks[0] as Grant).leaseToken,
        status: 'succeeded',
        output: {},
      },
    );
    expect(late.status).toBe(409);
    // cleanup: stop + remove of the deterministic candidate name; run_candidate never re-delivered
    const g = await drain();
    expect(g.map((x) => [x.type, x.params.name])).toEqual([
      ['container.stop', cand],
      ['container.remove', cand],
    ]);
    const after = await getDep(r.body.data.deployment.id);
    expect(after.status).toBe('failed');
    expect(after.steps.map((s: any) => [s.name, s.status])).toEqual(
      expect.arrayContaining([
        ['cleanup_stop', 'succeeded'],
        ['cleanup_remove', 'succeeded'],
      ]),
    );
    expect(
      await t.prisma.hostPortAllocation.count({
        where: { serverId: agent.serverId, containerName: cand },
      }),
    ).toBe(0);
    // a second reconcile pass does not enqueue another cleanup
    await t.app.get(SweeperService).tick();
    expect(await drain()).toEqual([]);
  });

  it('F-8: candidate never created (TTL lapsed before delivery) → port released, no cleanup jobs', async () => {
    await enableRouting();
    const app = await createApp();
    const r = await deploy(app.id);
    await t.prisma.job.updateMany({
      where: { type: 'container.run_candidate' },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await t.app.get(SweeperService).tick();
    const d = await getDep(r.body.data.deployment.id);
    expect(d).toMatchObject({ status: 'failed', error: { code: 'TTL_EXPIRED' } });
    expect(await drain()).toEqual([]);
    expect(await t.prisma.hostPortAllocation.count({ where: { serverId: agent.serverId } })).toBe(
      0,
    );
  });
});

describe('RBAC + misc endpoints', () => {
  it('viewer read-only; deployer deploys but cannot approve/enable routing; direct container jobs restricted', async () => {
    await enableRouting();
    expect(
      (
        await api('post', '/applications', viewer, {
          serverId: agent.serverId,
          name: 'v',
          domains: ['v.example.lab'],
          containerPort: 80,
        })
      ).status,
    ).toBe(403);
    const app = await createApp({}, dev);
    expect(app.allowedActions).not.toContain('manage_auto_deploy');
    const v = await getApp(app.id, viewer);
    expect(v.allowedActions).not.toContain('deploy');
    expect(v.container.env).toEqual({});
    expect((await deploy(app.id, img(D1), viewer)).status).toBe(403);
    expect((await api('post', `/applications/${app.id}/restart`, viewer)).status).toBe(403);
    expect((await api('get', `/applications/${app.id}/deployments`, viewer)).status).toBe(200);
    expect((await api('post', `/servers/${agent.serverId}/managed-routing`, dev)).status).toBe(403);
    const r = await deploy(app.id, img(D1), dev);
    expect(r.status).toBe(202);
    for (const type of ['container.run_candidate', 'container.stop', 'container.logs']) {
      const j = await api('post', `/servers/${agent.serverId}/jobs`, owner, {
        type,
        params: { app: 'web', name: 'ppanel-web-12345678' },
      });
      expect(j.body.error.code).toBe('JOB_TYPE_RESTRICTED');
    }
    const ownership = await api('post', `/applications/${app.id}/ownership`, owner, {
      toMode: 'adopted',
      reason: 'try downgrade',
    });
    expect(ownership.body.error.code).toBe('OWNERSHIP_STEP_INVALID');
    const denied = await t.prisma.auditEvent.count({ where: { result: 'denied' } });
    expect(denied).toBeGreaterThan(0);
    const created = await t.prisma.auditEvent.findFirst({
      where: { action: 'applications.create' },
    });
    expect(created?.metadata).toMatchObject({ kind: 'container', name: 'web' });
  });

  it('compose validate + detect endpoints', async () => {
    const v = await api('post', '/deploy/compose/validate', dev, {
      yaml: 'services:\n  a:\n    image: x\n    privileged: true\n    network_mode: host\n',
    });
    expect(v.status).toBe(200);
    expect(v.body.data.valid).toBe(false);
    expect(v.body.data.violations.map((x: any) => x.rule).sort()).toEqual([
      'host_network',
      'privileged',
    ]);
    expect(
      (await api('post', '/deploy/compose/validate', viewer, { yaml: 'services: {}' })).status,
    ).toBe(403);
    const d = await api('post', '/deploy/detect', dev, {
      files: { 'package.json': '{"dependencies":{"@nestjs/core":"11"}}', 'nest-cli.json': '{}' },
    });
    expect(d.body.data).toMatchObject({ framework: 'nestjs', suggested: { containerPort: 3000 } });
  });

  it('application create validation: injection domain, env/secret overlap, environment mismatch, name taken', async () => {
    const base = { serverId: agent.serverId, name: 'web', containerPort: 80 };
    expect(
      (
        await api('post', '/applications', owner, {
          ...base,
          domains: ['a.com; include /etc/passwd'],
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await api('post', '/applications', owner, {
          ...base,
          domains: ['a.example.lab'],
          env: { K: 'v' },
          secretKeys: ['K'],
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await api('post', '/applications', owner, {
          ...base,
          domains: ['a.example.lab'],
          environment: 'production',
        })
      ).body.error.code,
    ).toBe('ENVIRONMENT_MISMATCH');
    await createApp();
    expect(
      (await api('post', '/applications', owner, { ...base, domains: ['b.example.lab'] })).body
        .error.code,
    ).toBe('APP_NAME_TAKEN');
  });
});
