/**
 * P4b Center side: build nodes, build config + git auth, builds (image.build through the REAL mTLS
 * gateway, fetch-once gitAuth/registryAuth), deploy-after, source inspection, build-mode webhooks,
 * Compose applications (validation, normalisation, digest resolution via the fake registry,
 * compose.apply, route switch only when the route service changed, rollback, stop/start), RBAC, audit.
 */
import { createHash, createHmac } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
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
  stepUpToken,
  type TestApp,
} from './helpers';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const COMMIT = '1111111111111111111111111111111111111111';
const COMMIT2 = '2222222222222222222222222222222222222222';
const COMMIT3 = '3333333333333333333333333333333333333333';
const GIT_TOKEN = 'ghp_SuperSecretGitToken_0123456789abcdef';
const REG_PASSWORD = 'RegistryPassw0rd-xyz-987';
const DB_PASSWORD = 'Db-Passw0rd-For-P4b-Compose'; // gitleaks:allow (fake value used to assert non-leakage)
const HOOK_SECRET = 'webhook-secret-0123456789';
const PG = `postgres@sha256:${'5'.repeat(64)}`;
const WORKER = `busybox@sha256:${'6'.repeat(64)}`;
const WORKER2 = `busybox@sha256:${'7'.repeat(64)}`;
const WEB10 = `sha256:${'a1'.repeat(32)}`;
const WEB11 = `sha256:${'b2'.repeat(32)}`;
const BUILT = `sha256:${'c3'.repeat(32)}`;
const BUILT2 = `sha256:${'d4'.repeat(32)}`;

// ------------------------------------------------------------------ fake registry (HTTP API v2)

const REG_DIGESTS: Record<string, string> = {
  'acme/web:1.0': WEB10,
  'acme/web:1.1': WEB11,
};
let registry: http.Server;
let regHost: string;

function startRegistry(): Promise<void> {
  registry = http.createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const m = /^\/v2\/(.+)\/manifests\/([^/]+)$/.exec(u.pathname);
    const digest = m ? REG_DIGESTS[`${m[1]}:${m[2]}`] : undefined;
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
let admin: string; // ops_admin
let dev: string; // deployer
let viewer: string; // user1
let agent: EnrolledAgent;
let seq = 1;
const responses: unknown[] = [];
const secretFetches: any[] = [];

beforeAll(async () => {
  await startRegistry();
  t = await bootApp({
    PPANEL_NGINX_READ_WAIT_MS: '3000',
    PPANEL_REGISTRY_ALLOWLIST: regHost,
    PPANEL_REGISTRY_INSECURE: regHost,
    PPANEL_GIT_HOST_ALLOWLIST: 'github.com',
  });
  port = await t.gateway.start(0, '127.0.0.1');
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
  await heartbeat(agent, ['docker', 'nginx', 'build']);
  responses.length = 0;
  secretFetches.length = 0;
  running.clear();
});

async function heartbeat(a: EnrolledAgent, capabilities = ['docker', 'nginx']) {
  const r = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', {
    ...heartbeatBody(seq++),
    capabilities,
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

/** Simulated compose state on the host: service → { name, specHash, running }. */
const running = new Map<string, { name: string; specHash: string; running: boolean }>();

/** agent currently draining (secrets are fetched with its own mTLS identity) */
let serving: EnrolledAgent;
async function fetchSecrets(g: Grant) {
  const s = await agentCall(port, serving.creds, 'POST', `/agent/v1/tasks/${g.jobId}/secrets`, {
    leaseToken: g.leaseToken,
  });
  secretFetches.push({ type: g.type, status: s.status, body: s.body });
  return s;
}

function composeApply(g: Grant, unhealthy?: string): Reply {
  const services: any[] = [];
  for (const s of g.params.services) {
    const cur = running.get(s.service);
    if (cur && cur.running && cur.specHash === s.specHash) {
      services.push({
        service: s.service,
        name: cur.name,
        action: 'unchanged',
        health: { status: 'running' },
        ...(s.hostPort ? { hostPort: (cur as any).hostPort } : {}),
      });
      continue;
    }
    if (unhealthy === s.service)
      return fail('COMPOSE_SERVICE_UNHEALTHY', `${s.service} did not become healthy`, {
        service: s.service,
        logTail: ['boot', 'crash'],
        services,
      });
    services.push({
      service: s.service,
      name: s.name,
      action: cur ? 'replaced' : 'created',
      previousName: cur?.name ?? null,
      health: { status: 'healthy', attempts: 1 },
      ...(s.hostPort ? { hostPort: s.hostPort } : {}),
    });
  }
  for (const r of services) {
    const p = g.params.services.find((x: any) => x.service === r.service);
    running.set(r.service, {
      name: r.name,
      specHash: p.specHash,
      running: true,
      ...(p.hostPort ? { hostPort: r.hostPort } : {}),
    } as any);
  }
  return ok({ services });
}

function happy(overrides: Record<string, Handler> = {}): Handler {
  return async (g) => {
    if (overrides[g.type]) return overrides[g.type]!(g);
    switch (g.type) {
      case 'image.build': {
        if (g.params.source.auth || g.params.registryAuth) {
          const s = await fetchSecrets(g);
          if (s.status !== 200) return fail('SOURCE_FETCH_FAILED', String(s.body?.error?.code));
        }
        const digest = g.params.source.commitSha === COMMIT ? BUILT : BUILT2;
        return ok({
          image: `${g.params.pushRepo}@${digest}`,
          tag: `build-${g.params.buildId.replace(/-/g, '').slice(0, 12)}`,
          commitSha: g.params.source.commitSha,
          durationMs: 4200,
          logTail: ['Step 1/3 : FROM node:22', 'Successfully built'],
          // a leaky build step echoing the credential — the Center must redact it
          log: [
            'Step 1/3 : FROM node:22',
            `\u001b[32mRUN echo ${GIT_TOKEN}\u001b[0m`,
            'Successfully built',
          ],
        });
      }
      case 'source.inspect':
        if (g.params.source.auth) await fetchSecrets(g);
        return ok({
          commitSha: g.params.source.commitSha,
          files: {
            'package.json': JSON.stringify({
              dependencies: { next: '15.0.0', react: '19.0.0' },
              scripts: { start: 'next start' },
            }),
            'next.config.js': 'module.exports = {}',
            'evil.txt': 'not allowlisted',
          },
          truncated: [],
        });
      case 'compose.apply': {
        const needs =
          g.params.registryAuth ||
          g.params.services.some((s: any) => Object.keys(s.secretEnv).length > 0);
        if (needs) {
          const s = await fetchSecrets(g);
          if (s.status !== 200) return fail('SECRETS_UNAVAILABLE');
        }
        return composeApply(g);
      }
      case 'compose.stop':
        for (const v of running.values()) v.running = false;
        return ok({ stopped: [...running.values()].map((v) => v.name) });
      case 'nginx.apply':
        return ok({
          applied: true,
          files: g.params.files.map((f: any) => ({
            path: f.path,
            sha256Before: f.expectedSha256Before,
            sha256After: sha(f.content),
          })),
          postchecks: (g.params.postchecks ?? []).map((p: any) => ({
            ...p,
            status: 200,
            ok: true,
          })),
        });
      case 'container.run_candidate':
        return ok({
          name: g.params.name,
          image: g.params.image,
          hostPort: g.params.hostPort,
          health: { status: 'healthy', attempts: 1, elapsedMs: 100 },
        });
      case 'container.stop':
        for (const v of running.values()) if (v.name === g.params.name) v.running = false;
        return ok({ name: g.params.name, state: 'exited' });
      case 'container.remove':
        return ok({ name: g.params.name, state: 'removed' });
      default:
        return fail('REJECTED_UNKNOWN_TYPE');
    }
  };
}

async function drain(
  handler: Handler = happy(),
  a: EnrolledAgent = agent,
  max = 30,
): Promise<Grant[]> {
  const done: Grant[] = [];
  serving = a;
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

async function enableRouting() {
  const r = await api('post', `/servers/${agent.serverId}/managed-routing`);
  expect(r.status, JSON.stringify(r.body)).toBe(202);
  await drain();
}

async function createContainerApp(token = owner) {
  const r = await api('post', '/applications', token, {
    serverId: agent.serverId,
    name: 'web',
    domains: ['web.example.lab'],
    containerPort: 3000,
  });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body.data;
}

async function buildNode() {
  const r = await api('patch', `/servers/${agent.serverId}`, owner, { buildNode: true });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  expect(r.body.data.buildNode).toBe(true);
}

const buildConfig = () => ({
  repoUrl: 'https://github.com/acme/web.git',
  template: 'nextjs',
  buildServerId: agent.serverId,
  pushRepo: `${regHost}/acme/web`,
  buildArgs: { NODE_ENV: 'production' },
});

async function buildableApp() {
  await enableRouting();
  await buildNode();
  const app = await createContainerApp();
  const c = await api('put', `/applications/${app.id}/build-config`, owner, buildConfig());
  expect(c.status, JSON.stringify(c.body)).toBe(200);
  const g = await api('put', `/applications/${app.id}/git-auth`, owner, { token: GIT_TOKEN });
  expect(g.status).toBe(200);
  const ra = await api('put', `/applications/${app.id}/registry-auth`, owner, {
    serveraddress: regHost,
    username: 'pusher',
    password: REG_PASSWORD,
  });
  expect(ra.status).toBe(200);
  return app;
}

async function getBuild(id: string, token = owner) {
  const r = await api('get', `/builds/${id}`, token);
  expect(r.status).toBe(200);
  return r.body.data;
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

const tokenB64 = Buffer.from(`x-access-token:${GIT_TOKEN}`).toString('base64');

async function assertNoSecretAnywhere(values: string[]) {
  const dump = JSON.stringify({
    responses,
    jobs: await t.prisma.job.findMany(),
    builds: await t.prisma.build.findMany(),
    deployments: await t.prisma.deployment.findMany({ include: { steps: true } }),
    audit: await t.prisma.auditEvent.findMany(),
    deliveries: await t.prisma.webhookDelivery.findMany(),
    versions: await t.prisma.composeAppVersion.findMany(),
  });
  for (const v of values) expect(dump.includes(v), `leaked ${v.slice(0, 6)}…`).toBe(false);
}

// ================================================================== builds

describe('P4.02 builds: build node, config, git auth, image.build, deploy-after', () => {
  it('happy path: build → digest → deployment pinned with sourceRef; git token only via the secrets call (gitAuth.header), never stored/returned', async () => {
    await enableRouting();
    const app = await createContainerApp();
    // build node designation needs policies.manage (deployer cannot)
    expect(
      (await api('patch', `/servers/${agent.serverId}`, dev, { buildNode: true })).status,
    ).toBe(403);
    await buildNode();
    // allowlists
    const badHost = await api('put', `/applications/${app.id}/build-config`, owner, {
      ...buildConfig(),
      repoUrl: 'https://evil.example.com/acme/web.git',
    });
    expect(badHost.status).toBe(422);
    expect(badHost.body.error.code).toBe('GIT_HOST_NOT_ALLOWED');
    const badReg = await api('put', `/applications/${app.id}/build-config`, owner, {
      ...buildConfig(),
      pushRepo: 'evil.example.com/acme/web',
    });
    expect(badReg.body.error.code).toBe('REGISTRY_NOT_ALLOWED');
    const both = await api('put', `/applications/${app.id}/build-config`, owner, {
      ...buildConfig(),
      dockerfile: 'Dockerfile',
    });
    expect(both.status).toBe(422);
    const noCfg = await api('post', `/applications/${app.id}/builds`, owner, { commitSha: COMMIT });
    expect(noCfg.body.error.code).toBe('BUILD_CONFIG_MISSING');
    const cfg = await api('put', `/applications/${app.id}/build-config`, owner, buildConfig());
    expect(cfg.status).toBe(200);
    expect(cfg.body.data).toMatchObject({
      repo: 'acme/web',
      template: 'nextjs',
      dockerfile: null,
      gitAuth: { set: false },
      limits: { memoryMb: 2048, cpus: 2, timeoutSec: 900 },
    });
    expect(
      (await api('put', `/applications/${app.id}/git-auth`, owner, { token: GIT_TOKEN })).body.data,
    ).toMatchObject({ set: true });
    expect((await api('get', `/applications/${app.id}/git-auth`)).body.data).toMatchObject({
      set: true,
    });
    const reserved = await api('put', `/applications/${app.id}/secrets/__GIT_TOKEN__`, owner, {
      value: 'x',
    });
    expect(reserved.body.error.code).toBe('SECRET_KEY_RESERVED');
    await api('put', `/applications/${app.id}/registry-auth`, owner, {
      serveraddress: regHost,
      username: 'pusher',
      password: REG_PASSWORD,
    });
    const view = await getApp(app.id);
    expect(view.allowedActions).toEqual(
      expect.arrayContaining(['build', 'inspect_source', 'manage_build_config']),
    );
    expect(view.build).toMatchObject({ config: { gitAuth: { set: true } }, lastBuild: null });
    expect((await api('get', `/applications/${app.id}/secrets`)).body.data).toEqual([]);

    const r = await api(
      'post',
      `/applications/${app.id}/builds`,
      owner,
      { commitSha: COMMIT, branch: 'main' },
      { 'Idempotency-Key': 'build-key-0001' },
    );
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    const b = r.body.data.build;
    expect(b).toMatchObject({
      status: 'queued',
      commitSha: COMMIT,
      trigger: 'manual',
      deployAfter: true,
      template: 'nextjs',
      image: null,
    });
    // idempotency replay
    const replay = await api(
      'post',
      `/applications/${app.id}/builds`,
      owner,
      { commitSha: COMMIT },
      { 'Idempotency-Key': 'build-key-0001' },
    );
    expect(replay.status).toBe(200);
    expect(replay.body.data.build.id).toBe(b.id);

    const grants = await drain();
    expect(grants.map((g) => g.type)).toEqual([
      'image.build',
      'container.run_candidate',
      'nginx.apply',
    ]);
    const p = grants[0]!.params;
    expect(p).toMatchObject({
      buildId: b.id,
      app: 'web',
      source: { url: 'https://github.com/acme/web.git', commitSha: COMMIT, subdir: '', auth: true },
      template: 'nextjs',
      buildArgs: { NODE_ENV: 'production' },
      pushRepo: `${regHost}/acme/web`,
      registryAuth: true,
      network: 'default',
    });
    // fetch-once: gitAuth header + registry credential
    expect(secretFetches[0]).toMatchObject({ type: 'image.build', status: 200 });
    expect(secretFetches[0].body.data.gitAuth).toEqual({
      header: `Authorization: Basic ${tokenB64}`,
    });
    expect(secretFetches[0].body.data.registryAuth).toMatchObject({
      username: 'pusher',
      password: REG_PASSWORD,
    });
    expect(secretFetches[0].body.data.env).toEqual({});
    const again = await agentCall(
      port,
      agent.creds,
      'POST',
      `/agent/v1/tasks/${grants[0]!.jobId}/secrets`,
      { leaseToken: grants[0]!.leaseToken },
    );
    expect(again.status).toBe(409);
    const ready = await getBuild(b.id);
    expect(ready).toMatchObject({
      status: 'succeeded',
      image: `${regHost}/acme/web@${BUILT}`,
      durationMs: 4200,
    });
    expect(ready.deploymentId).toBeTruthy();
    expect(ready.logTail).toEqual(['Step 1/3 : FROM node:22', 'Successfully built']);
    const log = await api('get', `/builds/${b.id}/log`);
    expect(log.body.data.lines).toEqual([
      'Step 1/3 : FROM node:22',
      'RUN echo [REDACTED]',
      'Successfully built',
    ]);
    const d = await getDep(ready.deploymentId);
    expect(d).toMatchObject({
      status: 'succeeded',
      trigger: 'manual',
      image: `${regHost}/acme/web@${BUILT}`,
      buildId: b.id,
      sourceRef: { repo: 'acme/web', commitSha: COMMIT, branch: 'main' },
      createdBy: expect.any(String),
    });
    expect(grants[1]!.params.image).toBe(`${regHost}/acme/web@${BUILT}`);

    // same commit → reused, no rebuild; force → rebuild
    const same = await api('post', `/applications/${app.id}/builds`, owner, { commitSha: COMMIT });
    expect(same.status).toBe(200);
    expect(same.body.data).toMatchObject({ reused: true, build: { id: b.id } });
    const forced = await api('post', `/applications/${app.id}/builds`, owner, {
      commitSha: COMMIT,
      force: true,
      deployAfter: false,
    });
    expect(forced.status).toBe(202);
    expect(forced.body.data.build.id).not.toBe(b.id);
    expect((await drain()).map((g) => g.type)).toEqual(['image.build']);
    expect((await getBuild(forced.body.data.build.id)).deploymentId).toBeNull();
    const list = await api('get', `/applications/${app.id}/builds`);
    expect(list.body.data).toHaveLength(2);
    expect(list.body.paginate).toMatchObject({ total: 2 });

    // the job row keeps no full log and no token
    const job = await t.prisma.job.findUniqueOrThrow({ where: { id: grants[0]!.jobId } });
    expect((job.result as any).log).toBeUndefined();
    await assertNoSecretAnywhere([GIT_TOKEN, tokenB64, REG_PASSWORD]);
    const audit = await t.prisma.auditEvent.findMany({
      where: {
        action: {
          in: [
            'builds.create',
            'builds.status',
            'secrets.delivered',
            'builds.config_set',
            'secrets.git_auth_set',
            'servers.build_node',
          ],
        },
      },
    });
    const actions = audit.map((a) => `${a.action}:${a.result}`);
    expect(actions).toEqual(
      expect.arrayContaining([
        'builds.create:success',
        'builds.status:success',
        'secrets.delivered:success',
        'builds.config_set:success',
        'secrets.git_auth_set:success',
      ]),
    );
    expect(
      await t.prisma.auditEvent.count({ where: { result: 'denied', actorId: { not: null } } }),
    ).toBeGreaterThan(0);
    const delivered = audit.find((a) => a.action === 'secrets.delivered' && a.result === 'success');
    expect(delivered?.metadata).toMatchObject({
      jobType: 'image.build',
      gitAuth: true,
      registryAuth: true,
      keys: [],
    });
  });

  it('BUILD_FAILED → build failed with log, no deployment; NO_BUILD_NODE without designation or capability; cancel', async () => {
    const app = await buildableApp();
    const r = await api('post', `/applications/${app.id}/builds`, owner, { commitSha: COMMIT });
    expect(r.status).toBe(202);
    await drain(
      happy({
        'image.build': async (g) => {
          await fetchSecrets(g);
          return fail('BUILD_FAILED', 'npm ERR! missing script: build', {
            logTail: ['npm run build', 'npm ERR! missing script: build'],
          });
        },
      }),
    );
    const b = await getBuild(r.body.data.build.id);
    expect(b).toMatchObject({
      status: 'failed',
      image: null,
      deploymentId: null,
      error: { code: 'BUILD_FAILED', message: 'npm ERR! missing script: build' },
      logTail: ['npm run build', 'npm ERR! missing script: build'],
    });
    expect(await t.prisma.deployment.count()).toBe(0);
    // failed build of a commit does not block a retry
    const retry = await api('post', `/applications/${app.id}/builds`, owner, { commitSha: COMMIT });
    expect(retry.status).toBe(202);
    const cancelled = await api('post', `/builds/${retry.body.data.build.id}/cancel`);
    expect(cancelled.body.data.status).toBe('cancelled');
    expect(
      (await t.prisma.job.findUniqueOrThrow({ where: { id: retry.body.data.build.jobId } })).status,
    ).toBe('cancelled');
    expect((await api('post', `/builds/${retry.body.data.build.id}/cancel`)).body.error.code).toBe(
      'BUILD_STATE_INVALID',
    );

    // capability missing → NO_BUILD_NODE
    await heartbeat(agent, ['docker', 'nginx']);
    const nc = await api('post', `/applications/${app.id}/builds`, owner, { commitSha: COMMIT2 });
    expect(nc.status).toBe(409);
    expect(nc.body.error).toMatchObject({
      code: 'NO_BUILD_NODE',
      details: { buildNode: true, capability: false },
    });
    // designation removed → NO_BUILD_NODE
    await heartbeat(agent, ['docker', 'nginx', 'build']);
    await api('patch', `/servers/${agent.serverId}`, owner, { buildNode: false });
    const nd = await api('post', `/applications/${app.id}/builds`, owner, { commitSha: COMMIT2 });
    expect(nd.body.error).toMatchObject({
      code: 'NO_BUILD_NODE',
      details: { buildNode: false, capability: true },
    });
    const insp = await api('post', `/applications/${app.id}/source/inspect`, owner, {
      commitSha: COMMIT2,
    });
    expect(insp.body.error.code).toBe('NO_BUILD_NODE');
  });

  it('source inspect → source.inspect on the build node → { files, detection } (allowlisted files only)', async () => {
    const app = await buildableApp();
    const pending = api('post', `/applications/${app.id}/source/inspect`, owner, {
      commitSha: COMMIT,
    });
    await new Promise((r) => setTimeout(r, 300));
    const g = await drain();
    expect(g.map((x) => x.type)).toEqual(['source.inspect']);
    expect(g[0]!.params).toEqual({
      source: { url: 'https://github.com/acme/web.git', commitSha: COMMIT, subdir: '', auth: true },
    });
    const r = await pending;
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data).toMatchObject({
      status: 'succeeded',
      commitSha: COMMIT,
      detection: { framework: 'nextjs' },
    });
    expect(Object.keys(r.body.data.files).sort()).toEqual(['next.config.js', 'package.json']);
    expect(secretFetches[0].body.data).toEqual({
      env: {},
      gitAuth: { header: `Authorization: Basic ${tokenB64}` },
    });
    const again = await api(
      'get',
      `/applications/${app.id}/source/inspect/${r.body.data.inspectionId}`,
    );
    expect(again.body.data.detection.framework).toBe('nextjs');
    await assertNoSecretAnywhere([GIT_TOKEN, tokenB64]);
  });
});

// ================================================================== webhook build mode

describe('P4.01 build-mode auto-deploy', () => {
  function push(
    integrationId: string,
    delivery: string,
    opts: { ref?: string; after?: string } = {},
  ) {
    const body = JSON.stringify({
      ref: opts.ref ?? 'refs/heads/main',
      after: opts.after ?? COMMIT,
      repository: { full_name: 'acme/web' },
    });
    const sig = `sha256=${createHmac('sha256', HOOK_SECRET).update(body).digest('hex')}`;
    return t.http
      .post(`/api/v1/webhooks/github/${integrationId}`)
      .set('Content-Type', 'application/json')
      .set('X-GitHub-Event', 'push')
      .set('X-GitHub-Delivery', delivery)
      .set('X-Hub-Signature-256', sig)
      .send(body);
  }

  it('push → one build per commit → deploy; duplicate delivery no-op; same commit already_built/already_deployed; wrong branch ignored', async () => {
    const app = await buildableApp();
    const integ = await api('post', '/integrations/github', owner, {
      name: 'org',
      webhookSecret: HOOK_SECRET,
    });
    const noTpl = await api('post', `/applications/${app.id}/auto-deploy`, owner, {
      integrationId: integ.body.data.id,
      repo: 'acme/web',
      branches: ['main'],
    });
    expect(noTpl.status).toBe(422);
    const pol = await api('post', `/applications/${app.id}/auto-deploy`, owner, {
      integrationId: integ.body.data.id,
      repo: 'acme/web',
      branches: ['main'],
      mode: 'build',
    });
    expect(pol.status, JSON.stringify(pol.body)).toBe(201);
    expect(pol.body.data).toMatchObject({ mode: 'build', imageTemplate: null });

    const r1 = await push(integ.body.data.id, 'b-1');
    expect(r1.status).toBe(200);
    expect(r1.body.data).toMatchObject({
      duplicate: false,
      result: 'building',
      buildIds: [expect.any(String)],
      deploymentIds: [],
    });
    const buildId = r1.body.data.buildIds[0];
    const dup = await push(integ.body.data.id, 'b-1');
    expect(dup.body.data).toMatchObject({ duplicate: true });
    const same = await push(integ.body.data.id, 'b-2');
    expect(same.body.data).toMatchObject({
      result: 'ignored',
      reasons: ['already_built'],
      buildIds: [],
    });
    const wrong = await push(integ.body.data.id, 'b-3', {
      ref: 'refs/heads/feature/x',
      after: COMMIT2,
    });
    expect(wrong.body.data).toMatchObject({ result: 'ignored', reasons: ['branch_not_allowed'] });
    expect(await t.prisma.build.count()).toBe(1);

    const grants = await drain();
    expect(grants.map((g) => g.type)).toEqual([
      'image.build',
      'container.run_candidate',
      'nginx.apply',
    ]);
    const b = await getBuild(buildId);
    expect(b).toMatchObject({ status: 'succeeded', trigger: 'webhook', branch: 'main' });
    const d = await getDep(b.deploymentId);
    expect(d).toMatchObject({
      trigger: 'webhook',
      status: 'succeeded',
      buildId,
      sourceRef: { commitSha: COMMIT, branch: 'main', repo: 'acme/web' },
    });
    const deliveries = await api('get', `/integrations/github/${integ.body.data.id}/deliveries`);
    const first = deliveries.body.data.find((x: any) => x.deliveryId === 'b-1');
    expect(first).toMatchObject({
      result: 'deployed',
      buildIds: [buildId],
      deploymentIds: [b.deploymentId],
    });
    const later = await push(integ.body.data.id, 'b-4');
    expect(later.body.data).toMatchObject({ result: 'ignored', reasons: ['already_deployed'] });
    await assertNoSecretAnywhere([GIT_TOKEN, tokenB64, REG_PASSWORD, HOOK_SECRET]);
  });
});

// ================================================================== compose

const composeYaml = (opts: { web?: string; worker?: string; extra?: string } = {}) => `
services:
  db:
    image: ${PG}
    environment:
      POSTGRES_PASSWORD: \${DB_PASSWORD}
      POSTGRES_DB: app
    volumes:
      - pgdata:/var/lib/postgresql/data
  worker:
    image: ${opts.worker ?? WORKER}
    command: ["sh", "-c", "sleep 3600"]
    depends_on: [db]
  web:
    image: ${opts.web ?? `${regHost}/acme/web:1.0`}
    ports:
      - "127.0.0.1:8080:3000"
    environment:
      DATABASE_HOST: db
      PRICE: "$$5"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped
${opts.extra ?? ''}
volumes:
  pgdata: {}
`;

async function createCompose(yaml = composeYaml(), token = owner) {
  return api('post', '/applications', token, {
    kind: 'compose',
    serverId: agent.serverId,
    name: 'shop',
    domains: ['shop.example.lab'],
    yaml,
    routeService: 'web',
    routePort: 3000,
    healthPath: '/healthz',
  });
}

async function deployCompose(appId: string, body: Record<string, unknown> = {}) {
  const r = await api('post', `/applications/${appId}/deployments`, owner, body);
  expect([200, 202]).toContain(r.status);
  return r.body.data.deployment;
}

describe('P4.02 compose applications', () => {
  it('validation rejects host binds, privileged, ports on a non-route service, cycles, missing secret placeholder (update), unresolvable tags', async () => {
    const cases: Array<[string, string]> = [
      [
        'host_bind',
        composeYaml({
          extra:
            '  evil:\n    image: busybox@sha256:' +
            '8'.repeat(64) +
            '\n    volumes:\n      - /etc:/host-etc\n',
        }),
      ],
      [
        'privileged',
        composeYaml({
          extra:
            '  evil:\n    image: busybox@sha256:' + '8'.repeat(64) + '\n    privileged: true\n',
        }),
      ],
      [
        'ports_not_route_service',
        composeYaml({
          extra:
            '  evil:\n    image: busybox@sha256:' +
            '8'.repeat(64) +
            '\n    ports: ["127.0.0.1:9000:9000"]\n',
        }),
      ],
      [
        'depends_on_cycle',
        `services:\n  web:\n    image: ${WORKER}\n    depends_on: [a]\n  a:\n    image: ${WORKER}\n    depends_on: [b]\n  b:\n    image: ${WORKER}\n    depends_on: [a]\n`,
      ],
      ['image_unresolvable', composeYaml({ web: `${regHost}/acme/web:missing` })],
      ['image_unresolvable', composeYaml({ web: 'nginx:latest' })],
      [
        'env_interpolation',
        composeYaml({
          extra: `  evil:\n    image: ${WORKER}\n    environment:\n      URL: "postgres://u:\${DB_PASSWORD}@db"\n`,
        }),
      ],
      ['build_unsupported', composeYaml({ extra: `  evil:\n    build: .\n` })],
      ['route_service_missing', `services:\n  api:\n    image: ${WORKER}\n`],
    ];
    for (const [rule, yaml] of cases) {
      const r = await createCompose(yaml);
      expect(r.status, `${rule}: ${JSON.stringify(r.body)}`).toBe(422);
      expect(r.body.error.code).toBe('COMPOSE_INVALID');
      expect(
        r.body.error.details.violations.map((v: any) => v.rule),
        rule,
      ).toContain(rule);
    }
    expect(await t.prisma.application.count()).toBe(0);

    await enableRouting();
    const ok1 = await createCompose();
    expect(ok1.status, JSON.stringify(ok1.body)).toBe(201);
    const appId = ok1.body.data.id;
    const missing = await api('put', `/applications/${appId}/compose`, owner, {
      yaml: composeYaml().replace('${DB_PASSWORD}', '${DB_PASS2}'),
      routeService: 'web',
      routePort: 3000,
    });
    expect(missing.status).toBe(422);
    expect(missing.body.error.details.violations).toEqual([
      expect.objectContaining({ rule: 'secret_missing', service: 'db' }),
    ]);
  });

  it('normalised plan (secretEnv, inferred health, order) → deploy: resolve_images → compose_apply → route_switch; secrets fetched once; unchanged redeploy skips the route; route switch only when the route service changed', async () => {
    await enableRouting();
    const c = await createCompose();
    expect(c.status, JSON.stringify(c.body)).toBe(201);
    const app = c.body.data;
    expect(app).toMatchObject({ kind: 'compose', ownershipMode: 'managed' });
    expect(app.container).toBeUndefined();
    expect(app.compose).toMatchObject({
      version: 1,
      routeService: 'web',
      routePort: 3000,
      healthPath: '/healthz',
      secretKeys: ['DB_PASSWORD'],
      rollback: { dataRestored: false },
      routePath: '/etc/nginx/ppanel-managed/shop/route.conf',
    });
    expect(app.compose.services.map((s: any) => s.service)).toEqual(['db', 'worker', 'web']);
    const [db, worker, web] = app.compose.services;
    expect(db).toMatchObject({
      image: PG,
      env: { POSTGRES_DB: 'app' },
      secretEnv: { POSTGRES_PASSWORD: 'DB_PASSWORD' },
      volumes: [{ name: 'pgdata', mountPath: '/var/lib/postgresql/data' }],
      health: { type: 'tcp', port: 5432 },
      dependsOn: [],
    });
    expect(worker).toMatchObject({
      health: { type: 'running' },
      command: ['sh', '-c', 'sleep 3600'],
      dependsOn: ['db'],
    });
    expect(web).toMatchObject({
      image: `${regHost}/acme/web:1.0`,
      env: { DATABASE_HOST: 'db', PRICE: '$5' },
      health: { type: 'http', port: 3000, path: '/healthz' },
      containerPort: 3000,
    });
    expect(app.compose.warnings.map((w: any) => w.rule)).toEqual(
      expect.arrayContaining(['key_ignored', 'image_not_pinned']),
    );
    expect(app.allowedActions).toEqual(
      expect.arrayContaining(['deploy', 'edit_compose', 'manage_secrets']),
    );
    expect(app.allowedActions).not.toContain('restart');

    // secret not set yet → preflight SECRETS_MISSING, no job
    const pre = await deployCompose(app.id);
    expect(pre).toMatchObject({ status: 'failed', error: { code: 'SECRETS_MISSING' } });
    expect(await t.prisma.job.count({ where: { type: 'compose.apply' } })).toBe(0);
    await api('put', `/applications/${app.id}/secrets/DB_PASSWORD`, owner, { value: DB_PASSWORD });

    const d1 = await deployCompose(app.id);
    expect(d1.status).toBe('pulling');
    expect(d1.image).toBe(`${regHost}/acme/web@${WEB10}`);
    expect(d1.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['preflight', 'succeeded'],
      ['resolve_images', 'succeeded'],
      ['compose_apply', 'running'],
    ]);
    expect(d1.compose.services.map((s: any) => [s.service, s.image, s.plannedAction])).toEqual([
      ['db', PG, 'replace'],
      ['worker', WORKER, 'replace'],
      ['web', `${regHost}/acme/web@${WEB10}`, 'replace'],
    ]);
    expect(d1.compose.dataRestored).toBe(false);
    const g1 = await drain();
    expect(g1.map((g) => g.type)).toEqual(['compose.apply', 'nginx.apply']);
    const ap = g1[0]!.params;
    expect(ap).toMatchObject({
      deploymentId: d1.id,
      app: 'shop',
      routeService: 'web',
      registryAuth: false,
    });
    expect(ap.services.map((s: any) => s.service)).toEqual(['db', 'worker', 'web']);
    expect(ap.services[2]).toMatchObject({
      image: `${regHost}/acme/web@${WEB10}`,
      hostPort: 20000,
      containerPort: 3000,
    });
    expect(ap.services[0].secretEnv).toEqual({ POSTGRES_PASSWORD: 'DB_PASSWORD' });
    expect(ap.services[0].name).toMatch(/^ppanel-shop-db-[a-f0-9]{8}$/);
    expect(ap.services[0].hostPort).toBeUndefined();
    expect(secretFetches).toHaveLength(1);
    expect(secretFetches[0].body.data.env).toEqual({ DB_PASSWORD });
    expect(g1[1]!.params.files[0].content).toContain('server 127.0.0.1:20000;');
    const s1 = await getDep(d1.id);
    expect(s1.status).toBe('succeeded');
    expect(s1.compose.services.map((s: any) => s.action)).toEqual([
      'created',
      'created',
      'created',
    ]);
    const a1 = await getApp(app.id);
    expect(a1.compose).toMatchObject({
      currentDeploymentId: d1.id,
      hostPort: 20000,
      containerName: ap.services[2].name,
    });

    // deploy again, nothing changed → all unchanged, no route switch, spare port released
    const d2 = await deployCompose(app.id);
    expect(d2.compose.services.every((s: any) => s.plannedAction === 'unchanged')).toBe(true);
    const g2 = await drain();
    expect(g2.map((g) => g.type)).toEqual(['compose.apply']);
    const s2 = await getDep(d2.id);
    expect(s2.status).toBe('succeeded');
    expect(s2.steps.find((s: any) => s.name === 'route_switch')).toMatchObject({
      status: 'skipped',
    });
    expect(s2.container).toEqual({ name: ap.services[2].name, hostPort: 20000 });
    expect(await t.prisma.hostPortAllocation.count()).toBe(1);
    expect((await getApp(app.id)).compose).toMatchObject({
      currentDeploymentId: d2.id,
      previousDeploymentId: d1.id,
    });

    // worker image changes → only the worker is replaced, route untouched
    const u1 = await api(
      'put',
      `/applications/${app.id}/compose`,
      owner,
      {
        yaml: composeYaml({ worker: WORKER2 }),
        routeService: 'web',
        routePort: 3000,
        healthPath: '/healthz',
      },
      { 'If-Match': String(a1.version) },
    );
    expect(u1.status, JSON.stringify(u1.body)).toBe(200);
    expect(u1.body.data.compose.version).toBe(2);
    const d3 = await deployCompose(app.id);
    expect(d3.compose.services.map((s: any) => s.plannedAction)).toEqual([
      'unchanged',
      'replace',
      'unchanged',
    ]);
    expect((await drain()).map((g) => g.type)).toEqual(['compose.apply']);
    const s3 = await getDep(d3.id);
    expect(s3.compose.services.map((s: any) => s.action)).toEqual([
      'unchanged',
      'replaced',
      'unchanged',
    ]);
    expect(s3.status).toBe('succeeded');

    // route service image changes → route switch to the new port + old route container stopped
    await api('put', `/applications/${app.id}/compose`, owner, {
      yaml: composeYaml({ worker: WORKER2, web: `${regHost}/acme/web:1.1` }),
      routeService: 'web',
      routePort: 3000,
      healthPath: '/healthz',
    });
    const d4 = await deployCompose(app.id);
    const g4 = await drain();
    expect(g4.map((g) => g.type)).toEqual(['compose.apply', 'nginx.apply', 'container.stop']);
    expect(g4[2]!.params.name).toBe(ap.services[2].name);
    const s4 = await getDep(d4.id);
    expect(s4.status).toBe('succeeded');
    expect(s4.image).toBe(`${regHost}/acme/web@${WEB11}`);
    expect(s4.steps.map((s: any) => s.name)).toEqual([
      'preflight',
      'resolve_images',
      'compose_apply',
      'health_check',
      'route_switch',
      'stop_previous',
    ]);
    expect(s4.container.hostPort).toBe(20001);
    await assertNoSecretAnywhere([DB_PASSWORD]);
    const audit = await t.prisma.auditEvent.findMany({
      where: {
        action: {
          in: ['applications.create', 'applications.compose_update', 'deployments.create'],
        },
      },
    });
    expect(audit.find((a) => a.action === 'applications.create')?.metadata).toMatchObject({
      kind: 'compose',
      composeVersion: 1,
      envPlaceholderKeys: ['DB_PASSWORD'],
    });
    expect(audit.filter((a) => a.action === 'applications.compose_update')).toHaveLength(2);
  });

  it('COMPOSE_SERVICE_UNHEALTHY → failed, previous plan stays current; rollback re-applies the previous plan (dataRestored false); stop/start', async () => {
    await enableRouting();
    const app = (await createCompose()).body.data;
    await api('put', `/applications/${app.id}/secrets/DB_PASSWORD`, owner, { value: DB_PASSWORD });
    const d1 = await deployCompose(app.id);
    await drain();
    expect((await getDep(d1.id)).status).toBe('succeeded');
    await api('put', `/applications/${app.id}/compose`, owner, {
      yaml: composeYaml({ web: `${regHost}/acme/web:1.1` }),
      routeService: 'web',
      routePort: 3000,
      healthPath: '/healthz',
    });

    const bad = await deployCompose(app.id);
    const gb = await drain(
      happy({
        'compose.apply': async (g) => {
          await fetchSecrets(g);
          return composeApply(g, 'web');
        },
      }),
    );
    expect(gb.map((g) => g.type)).toEqual(['compose.apply']);
    const sb = await getDep(bad.id);
    expect(sb).toMatchObject({ status: 'failed', error: { code: 'COMPOSE_SERVICE_UNHEALTHY' } });
    expect(sb.steps.find((s: any) => s.name === 'health_check')).toMatchObject({
      status: 'failed',
      errorCode: 'COMPOSE_SERVICE_UNHEALTHY',
      logTail: ['boot', 'crash'],
    });
    expect((await getApp(app.id)).compose.currentDeploymentId).toBe(d1.id);
    expect(await t.prisma.hostPortAllocation.count()).toBe(1);

    // successful v2, then roll back to v1's plan
    const d2 = await deployCompose(app.id);
    expect((await drain()).map((g) => g.type)).toEqual([
      'compose.apply',
      'nginx.apply',
      'container.stop',
    ]);
    expect((await getDep(d2.id)).status).toBe('succeeded');
    const a2 = await getApp(app.id);
    expect(a2.compose.rollbackAvailable).toBe(true);
    expect(a2.allowedActions).toContain('rollback');
    const rb = await api('post', `/applications/${app.id}/rollback`, owner, {
      reason: 'bad release',
    });
    expect(rb.status, JSON.stringify(rb.body)).toBe(202);
    expect(rb.body.data.rollback).toEqual({ dataRestored: false, rollbackOfDeploymentId: d1.id });
    const rd = rb.body.data.deployment;
    expect(rd).toMatchObject({
      trigger: 'rollback',
      rollbackOfDeploymentId: d1.id,
      image: `${regHost}/acme/web@${WEB10}`,
    });
    expect(rd.compose).toMatchObject({ version: 1, dataRestored: false });
    const gr = await drain();
    expect(gr.map((g) => g.type)).toEqual(['compose.apply', 'nginx.apply', 'container.stop']);
    expect(gr[0]!.params.services.find((s: any) => s.service === 'web').image).toBe(
      `${regHost}/acme/web@${WEB10}`,
    );
    expect((await getDep(rd.id)).status).toBe('succeeded');
    expect((await getDep(d2.id)).status).toBe('rolled_back');
    expect((await getApp(app.id)).compose.currentDeploymentId).toBe(rd.id);

    // stop → compose.stop; start → re-apply of the current plan (stopped services recreated)
    const stop = await api('post', `/applications/${app.id}/stop`);
    expect(stop.status).toBe(202);
    expect((await drain()).map((g) => [g.type, g.params])).toEqual([
      ['compose.stop', { app: 'shop' }],
    ]);
    const start = await api('post', `/applications/${app.id}/start`);
    expect(start.status).toBe(202);
    expect(start.body.data).toMatchObject({ operation: 'start', deploymentId: expect.any(String) });
    const gs = await drain();
    // + retention: route containers older than the last 2 are removed
    expect(gs.map((g) => g.type)).toEqual([
      'compose.apply',
      'nginx.apply',
      'container.stop',
      'container.remove',
    ]);
    expect((await getDep(start.body.data.deploymentId)).status).toBe('succeeded');
    const restart = await api('post', `/applications/${app.id}/restart`);
    expect(restart.body.error.code).toBe('OPERATION_NOT_SUPPORTED');
  });
});

// ================================================================== production approvals

describe('P4b production: approval rules unchanged for build and compose deployments', () => {
  async function prodServer() {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    const r = await agentCall(
      port,
      prod.creds,
      'POST',
      '/agent/v1/heartbeat',
      heartbeatBody(seq++),
    );
    expect(r.status).toBe(200);
    const ownerId = (
      await t.prisma.user.findFirstOrThrow({ where: { email: 'superadmin@ppanel.local' } })
    ).id;
    await t.prisma.managedRouting.create({
      data: {
        serverId: prod.serverId,
        status: 'enabled',
        revisionId: '01900000-0000-7000-8000-000000000009',
        planHash: 'a'.repeat(64),
        approvalRequired: true,
        createdBy: ownerId,
      },
    });
    return prod;
  }

  it('build on the (dev) build node → production deployment awaits approval; compose prod deploy approved by another user with step-up, planHash covers the plan', async () => {
    const prod = await prodServer();
    await buildNode();
    const ownerSu = await stepUpToken(t, owner);
    const app = (
      await api('post', '/applications', dev, {
        serverId: prod.serverId,
        name: 'pweb',
        domains: ['pweb.example.lab'],
        containerPort: 3000,
      })
    ).body.data;
    await api('put', `/applications/${app.id}/build-config`, dev, buildConfig());
    const b = await api('post', `/applications/${app.id}/builds`, dev, { commitSha: COMMIT3 });
    expect(b.status, JSON.stringify(b.body)).toBe(202);
    expect((await drain()).map((g) => g.type)).toEqual(['image.build']); // build runs on the build node only
    const built = await getBuild(b.body.data.build.id);
    const d = await getDep(built.deploymentId);
    expect(d).toMatchObject({
      status: 'awaiting_approval',
      approval: { required: true },
      buildId: built.id,
    });
    expect(await drain(happy(), prod)).toEqual([]);
    expect(
      (await api('post', `/deployments/${d.id}/approve`, dev, { planHash: d.planHash })).status,
    ).toBe(403);
    const ok1 = await api(
      'post',
      `/deployments/${d.id}/approve`,
      owner,
      { planHash: d.planHash },
      { 'X-Step-Up': ownerSu },
    );
    expect(ok1.status, JSON.stringify(ok1.body)).toBe(200);
    expect((await drain(happy(), prod)).map((g) => g.type)).toEqual([
      'container.run_candidate',
      'nginx.apply',
    ]);

    // compose in production (secret set with step-up) → awaiting_approval; secret rotation invalidates the plan
    const c = await api('post', '/applications', dev, {
      kind: 'compose',
      serverId: prod.serverId,
      name: 'pshop',
      domains: ['pshop.example.lab'],
      yaml: composeYaml(),
      routeService: 'web',
      routePort: 3000,
    });
    expect(c.status, JSON.stringify(c.body)).toBe(201);
    await api(
      'put',
      `/applications/${c.body.data.id}/secrets/DB_PASSWORD`,
      owner,
      { value: DB_PASSWORD },
      { 'X-Step-Up': ownerSu },
    );
    const cd = (await api('post', `/applications/${c.body.data.id}/deployments`, dev, {})).body.data
      .deployment;
    expect(cd).toMatchObject({ status: 'awaiting_approval', compose: { version: 1 } });
    expect(cd.steps.map((s: any) => s.name)).toEqual(['preflight', 'resolve_images']);
    await api(
      'put',
      `/applications/${c.body.data.id}/secrets/DB_PASSWORD`,
      owner,
      { value: `${DB_PASSWORD}-2` },
      { 'X-Step-Up': ownerSu },
    );
    const stale = await api(
      'post',
      `/deployments/${cd.id}/approve`,
      owner,
      { planHash: cd.planHash },
      { 'X-Step-Up': ownerSu },
    );
    expect(stale.body.error.code).toBe('PLAN_HASH_MISMATCH');
    await api('post', `/deployments/${cd.id}/cancel`, dev);
    const cd2 = (await api('post', `/applications/${c.body.data.id}/deployments`, dev, {})).body
      .data.deployment;
    const ok2 = await api(
      'post',
      `/deployments/${cd2.id}/approve`,
      owner,
      { planHash: cd2.planHash },
      { 'X-Step-Up': ownerSu },
    );
    expect(ok2.status, JSON.stringify(ok2.body)).toBe(200);
    const gp = await drain(happy(), prod);
    expect(
      gp.map((g) => g.type),
      JSON.stringify(await getDep(cd2.id)),
    ).toEqual(['compose.apply', 'nginx.apply']);
    expect((await getDep(cd2.id)).status).toBe('succeeded');
  });
});

// ================================================================== RBAC

describe('P4b RBAC + restricted job types', () => {
  it('viewer cannot create compose apps / builds / build config; deployer cannot designate build nodes; P4b job types restricted', async () => {
    const app = await buildableApp();
    expect((await createCompose(composeYaml(), viewer)).status).toBe(403);
    expect(
      (await api('post', `/applications/${app.id}/builds`, viewer, { commitSha: COMMIT })).status,
    ).toBe(403);
    expect(
      (await api('put', `/applications/${app.id}/build-config`, viewer, buildConfig())).status,
    ).toBe(403);
    expect(
      (await api('put', `/applications/${app.id}/git-auth`, viewer, { token: 'x' })).status,
    ).toBe(403);
    expect((await api('get', `/applications/${app.id}/build-config`, viewer)).status).toBe(200);
    expect(
      (await api('get', `/applications/${app.id}/build-config`, viewer)).body.data.gitAuth,
    ).toEqual({ set: true });
    const v = await getApp(app.id, viewer);
    expect(v.allowedActions).not.toContain('build');
    expect(
      (await api('patch', `/servers/${agent.serverId}`, dev, { buildNode: false })).status,
    ).toBe(403);
    expect(
      (await api('patch', `/servers/${agent.serverId}`, admin, { buildNode: false })).status,
    ).toBe(200);
    const b = await api('post', `/applications/${app.id}/builds`, dev, { commitSha: COMMIT });
    expect(b.body.error.code).toBe('NO_BUILD_NODE');
    for (const type of ['image.build', 'source.inspect', 'compose.apply', 'compose.stop']) {
      const j = await api('post', `/servers/${agent.serverId}/jobs`, owner, {
        type,
        params: { app: 'web' },
      });
      expect(j.body.error.code, type).toBe('JOB_TYPE_RESTRICTED');
    }
    // compose-only / container-only endpoints
    expect(
      (
        await api('put', `/applications/${app.id}/compose`, owner, {
          yaml: 'services: {}',
          routeService: 'web',
          routePort: 80,
        })
      ).body.error.code,
    ).toBe('NOT_COMPOSE_APP');
    const denied = await t.prisma.auditEvent.count({ where: { result: 'denied' } });
    expect(denied).toBeGreaterThan(0);
  });
});
