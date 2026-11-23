/**
 * P6 Center side (§10): repositories + access + recovery export + maintenance reports, policies +
 * validation + scheduler, runs (uploaded / BACKUP_PARTIAL / expired) with manifests, verification
 * levels, restores (plan → dry-run → approval → execute; in-place order; failure → manual recovery),
 * RBAC + audit (P6-T03), backup_failed alerts, secrets delivered once (never leaked).
 * The agent is simulated through the REAL mTLS gateway (lease → ack → secrets → result).
 */
import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { BackupSchedulerService } from '../../src/backup/backup-scheduler.service';
import { nextRunAfter } from '../../src/backup/backup-common';
import { uuidv7 } from '../../src/common/ids';
import { SweeperService } from '../../src/jobs/sweeper.service';
import { AlertEngineService } from '../../src/observability/alert-engine.service';
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
  totpNow,
} from './helpers';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const REPORT_TOKEN = 'report-token-0123456789abcdef0123456789abcdef';
const REST_PASSWORD = 'Rest-Server-Pass-P6-0001';
const DB_PASSWORD = 'Db-Pass-For-P6-Backups-77';
const IMG = `lab-registry:5000/ppanel-test/web@sha256:${'a'.repeat(64)}`;
const SNAP = (n: number) => n.toString(16).padStart(2, '0').repeat(32);

let t: TestApp;
let port: number;
let owner: string; // superadmin (platform_owner)
let admin: string; // ops_admin (approver)
let dev: string; // deployer (no backups.*)
let viewer: string; // viewer
let agent: EnrolledAgent;
let seq = 1;
const responses: unknown[] = [];
const secretFetches: Array<{ type: string; status: number; body: any }> = [];

beforeAll(async () => {
  t = await bootApp({
    PPANEL_BACKUP_REPORT_TOKEN: REPORT_TOKEN,
    PPANEL_NGINX_READ_WAIT_MS: '3000',
    LOG_LEVEL: 'error',
  });
  port = await t.gateway.start(0, '127.0.0.1');
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  await t.prisma.$executeRawUnsafe(
    'TRUNCATE "restore_steps", "restores", "backup_verifications", "backup_runs", "backup_policies", "backup_maintenance_reports", "backup_repo_access", "backup_repositories" CASCADE',
  );
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  dev = await login(t, 'dev');
  viewer = await login(t, 'user1');
  agent = await enrollAgent(t, owner, { environment: 'uat' });
  await heartbeat(agent);
  responses.length = 0;
  secretFetches.length = 0;
});

/** X-Step-Up for a user (enrols TOTP once per test, re-uses the secret afterwards). */
const totpUrls = new Map<string, string>();
async function stepUpToken(_t: TestApp, accessToken: string): Promise<string> {
  let url = totpUrls.get(accessToken);
  if (!url) {
    const setup = await t.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(accessToken));
    expect(setup.status).toBe(200);
    url = setup.body.data.otpauthUrl as string;
    const conf = await t.http
      .post('/api/v1/auth/mfa/totp/confirm')
      .set(bearer(accessToken))
      .send({ code: totpNow(url) });
    expect(conf.status).toBe(200);
    totpUrls.set(accessToken, url);
  }
  await t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
  const su = await t.http
    .post('/api/v1/auth/step-up')
    .set(bearer(accessToken))
    .send({ code: totpNow(url) });
  expect(su.status, JSON.stringify(su.body)).toBe(200);
  return su.body.data.stepUpToken as string;
}

async function heartbeat(a: EnrolledAgent) {
  const r = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(seq++));
  expect(r.status).toBe(200);
}

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

async function fetchSecrets(a: EnrolledAgent, g: Grant) {
  const s = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/secrets`, {
    leaseToken: g.leaseToken,
  });
  secretFetches.push({ type: g.type, status: s.status, body: s.body });
  return s;
}

let snapCounter = 1;
/** Agent-shaped manifest: one entry per target (files for paths/volume, dump facts for DB). */
function manifestFor(targets: any[], snaps: string[]) {
  return targets.map((tg, i) => {
    if (tg.type === 'paths') {
      const files = tg.paths.flatMap((p: string) => [
        { path: `${p}/a.txt`, size: 11, sha256: sha(`${p}a`) },
        { path: `${p}/b.txt`, size: 22, sha256: sha(`${p}b`) },
      ]);
      return {
        target: i,
        type: 'paths',
        snapshotId: snaps[i],
        paths: tg.paths,
        files,
        fileCount: files.length,
        truncated: false,
      };
    }
    if (tg.type === 'volume')
      return {
        target: i,
        type: 'volume',
        snapshotId: snaps[i],
        app: tg.app,
        volume: tg.volume,
        files: [{ path: `/backup/${tg.volume}/data.bin`, size: 4096, sha256: sha(tg.volume) }],
        fileCount: 1,
        truncated: false,
      };
    return {
      target: i,
      type: tg.type,
      snapshotId: snaps[i],
      database: tg.database,
      bytes: 9000,
      sha256: sha(tg.database),
      tables: [
        { name: 'orders', rows: 12 },
        { name: 'users', rows: 3 },
      ],
      fileCount: 0,
      truncated: false,
    };
  });
}

function happy(a: EnrolledAgent = agent, overrides: Record<string, Handler> = {}): Handler {
  return async (g) => {
    if (overrides[g.type]) return overrides[g.type]!(g);
    switch (g.type) {
      case 'backup.run': {
        const s = await fetchSecrets(a, g);
        if (s.status !== 200) return fail('SECRETS_UNAVAILABLE');
        const snaps = g.params.targets.map(() => SNAP(snapCounter++));
        return ok({
          snapshots: g.params.targets.map((tg: any, i: number) => ({
            target: i,
            type: tg.type,
            snapshotId: snaps[i],
            shortId: snaps[i].slice(0, 8),
            sizeBytes: 1234,
            filesNew: 2,
            filesChanged: 0,
            durationMs: 800,
          })),
          manifest: manifestFor(g.params.targets, snaps),
          resticVersion: '0.17.3',
        });
      }
      case 'backup.verify': {
        await fetchSecrets(a, g);
        return ok({
          repoCheckOk: true,
          filesCompared: g.params.manifest?.[0]?.files?.length ?? 0,
          mismatches: [],
          level: 'repository_checked',
        });
      }
      case 'restore.run': {
        await fetchSecrets(a, g);
        if (g.params.dryRun)
          return ok({ restored: [], dryRun: { files: ['/srv/data/a.txt', '/srv/data/b.txt'] } });
        return ok({
          restored: [{ target: g.params.target.type }],
          verify: { ok: true, compared: g.params.manifest?.length ?? 1, mismatches: [] },
          ...(g.params.target.mode === 'staging' && g.params.target.type === 'paths'
            ? { stagingPath: `/var/lib/ppanel-agent/restores/${g.params.restoreId}` }
            : {}),
          ...(g.params.target.mode === 'scratch' ? { scratch: { removed: true } } : {}),
        });
      }
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
          postchecks: g.params.postchecks.map((p: any) => ({ ...p, status: 200, ok: true })),
          backupId: g.params.revisionId,
        });
      case 'container.run_candidate':
        return ok({
          containerId: 'c'.repeat(64),
          name: g.params.name,
          image: g.params.image,
          imageId: `sha256:${'1'.repeat(64)}`,
          hostPort: g.params.hostPort,
          health: { status: 'healthy', attempts: 1, elapsedMs: 100, lastStatus: 200 },
        });
      case 'container.start':
        return ok({
          name: g.params.name,
          health: { status: 'healthy', attempts: 1, elapsedMs: 300 },
        });
      case 'container.stop':
        return ok({ name: g.params.name, state: 'exited' });
      case 'backup.snapshots':
        await fetchSecrets(a, g);
        return ok({
          snapshots: [
            {
              id: SNAP(200),
              shortId: SNAP(200).slice(0, 8),
              time: '2026-11-23T02:00:00Z',
              tags: ['ppanel'],
              paths: ['/srv/data'],
              hostname: 'lab-node',
            },
          ],
        });
      default:
        return fail('REJECTED_UNKNOWN_TYPE');
    }
  };
}

async function drain(
  handler: Handler = happy(),
  a: EnrolledAgent = agent,
  max = 40,
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

// ------------------------------------------------------------------ fixtures

async function repoWithAccess(a: EnrolledAgent = agent, initialized = true) {
  const r = await api('post', '/backup-repositories', owner, {
    name: `lab-${Math.random().toString(36).slice(2, 7)}`,
    baseUrl: 'http://backup.lab:8000',
  });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  const acc = await api(
    'put',
    `/backup-repositories/${r.body.data.id}/servers/${a.serverId}`,
    owner,
    {
      restUser: 'node-a',
      restPassword: REST_PASSWORD,
    },
  );
  expect(acc.status, JSON.stringify(acc.body)).toBe(200);
  if (initialized) {
    const i = await api(
      'post',
      `/backup-repositories/${r.body.data.id}/servers/${a.serverId}/initialized`,
      owner,
      {},
    );
    expect(i.status).toBe(200);
  }
  return r.body.data as { id: string };
}

async function policy(repoId: string, body: Record<string, unknown> = {}, token = owner) {
  return api('post', '/backup-policies', token, {
    name: 'nightly',
    serverId: agent.serverId,
    repositoryId: repoId,
    targets: [{ type: 'paths', paths: ['/srv/data'], excludes: ['*.tmp'] }],
    schedule: { cron: '0 2 * * *', timezone: 'Asia/Bangkok' },
    ...body,
  });
}

async function uploadedRun(repoId: string, body: Record<string, unknown> = {}) {
  const p = await policy(repoId, { verify: { afterBackup: 'none' }, ...body });
  expect(p.status, JSON.stringify(p.body)).toBe(201);
  const run = await api('post', `/backup-policies/${p.body.data.id}/run`);
  expect(run.status, JSON.stringify(run.body)).toBe(202);
  await drain();
  const got = await api('get', `/backup-runs/${run.body.data.run.id}`);
  expect(got.body.data.status).toBe('uploaded');
  return { policy: p.body.data, run: got.body.data };
}

async function repoPassword(repoId: string): Promise<string> {
  const su = await stepUpToken(t, owner);
  const r = await t.http
    .get(`/api/v1/backup-repositories/${repoId}/recovery-export`)
    .set(bearer(owner))
    .set('X-Step-Up', su);
  return r.body.data.servers[0].repoPassword;
}

/** Ready container app with a volume and a current (running) container. */
async function deployedVolumeApp() {
  const routing = await api('post', `/servers/${agent.serverId}/managed-routing`);
  expect(routing.status, JSON.stringify(routing.body)).toBe(202);
  await drain();
  const app = await api('post', '/applications', owner, {
    serverId: agent.serverId,
    name: 'web',
    domains: ['web.example.lab'],
    containerPort: 8080,
    healthcheck: { path: '/healthz' },
    volumes: [{ name: 'uploads', mountPath: '/data/uploads' }],
  });
  expect(app.status, JSON.stringify(app.body)).toBe(201);
  const d = await api('post', `/applications/${app.body.data.id}/deployments`, owner, {
    image: IMG,
  });
  expect(d.status, JSON.stringify(d.body)).toBe(202);
  await drain();
  const dep = await api('get', `/deployments/${d.body.data.deployment.id}`);
  expect(dep.body.data.status).toBe('succeeded');
  return {
    app: app.body.data,
    container: dep.body.data.container as { name: string; hostPort: number },
  };
}

/** Compose app row with a `db` service + DB_PASSWORD secret (inserted directly: no registry needed). */
async function composeDbApp() {
  const ownerId = (
    await t.prisma.user.findFirstOrThrow({ where: { email: 'superadmin@ppanel.local' } })
  ).id;
  const id = uuidv7();
  await t.prisma.application.create({
    data: {
      id,
      serverId: agent.serverId,
      name: 'shop',
      kind: 'compose',
      ownershipMode: 'managed',
      domains: ['shop.example.lab'],
      sourceFindingFingerprint: `managed:${id}`,
    },
  });
  await t.prisma.containerApp.create({
    data: {
      applicationId: id,
      containerPort: 3000,
      healthcheck: {},
      resources: {},
      createdBy: ownerId,
    },
  });
  await t.prisma.composeAppVersion.create({
    data: {
      id: uuidv7(),
      applicationId: id,
      version: 1,
      yaml: 'services: {}',
      yamlSha256: sha('x'),
      routeService: 'web',
      routePort: 3000,
      // stored shape is an ARRAY of normalised services (as compose-plan.ts persists it)
      plan: [
        {
          service: 'db',
          image: `docker.io/library/postgres@sha256:${'d'.repeat(64)}`,
          secretEnv: { POSTGRES_PASSWORD: 'DB_PASSWORD' },
          volumes: [{ name: 'pgdata', mountPath: '/var/lib/postgresql/data' }],
        },
        {
          service: 'web',
          image: `registry.lab/web@sha256:${'e'.repeat(64)}`,
          secretEnv: {},
          volumes: [],
        },
      ],
      secretKeys: ['DB_PASSWORD'],
      createdBy: ownerId,
    },
  });
  const s = await api('put', `/applications/${id}/secrets/DB_PASSWORD`, owner, {
    value: DB_PASSWORD,
  });
  expect(s.status, JSON.stringify(s.body)).toBe(200);
  return id;
}

async function assertNoSecretAnywhere(values: string[]) {
  const dump = JSON.stringify({
    responses,
    jobs: await t.prisma.job.findMany(),
    runs: await t.prisma.backupRun.findMany(),
    restores: await t.prisma.restore.findMany({ include: { steps: true } }),
    audit: await t.prisma.auditEvent.findMany(),
    policies: await t.prisma.backupPolicy.findMany(),
    reports: await t.prisma.backupMaintenanceReport.findMany(),
  });
  for (const v of values) expect(dump.includes(v), `leaked ${v.slice(0, 6)}…`).toBe(false);
}

// ================================================================== P6.01 repositories

describe('P6.01 repositories, access, initialised flag, recovery export, maintenance reports', () => {
  it('repo + access (generated repo password) never returns secrets; REPO_NOT_INITIALIZED preflight; recovery export needs step-up, is audited and no-store', async () => {
    const repo = await repoWithAccess(agent, false);
    const view = await api('get', `/backup-repositories/${repo.id}`, viewer);
    expect(view.status).toBe(200);
    expect(view.body.data.servers[0]).toMatchObject({
      serverId: agent.serverId,
      restUser: 'node-a',
      url: 'http://backup.lab:8000/node-a/',
      initialized: false,
      restPassword: { set: true },
      repoPassword: { set: true },
    });
    expect(view.body.data.allowedActions).toEqual([]);
    expect(JSON.stringify(view.body)).not.toContain(REST_PASSWORD);
    // deployer cannot create repositories (403, audited by the guard)
    const denied = await api('post', '/backup-repositories', dev, {
      name: 'x',
      baseUrl: 'http://b:8000',
    });
    expect(denied.status).toBe(403);
    // runs refused before the operator initialised the repo
    const p = await policy(repo.id);
    expect(p.status, JSON.stringify(p.body)).toBe(201);
    const run = await api('post', `/backup-policies/${p.body.data.id}/run`);
    expect(run.status).toBe(409);
    expect(run.body.error.code).toBe('REPO_NOT_INITIALIZED');
    expect(await t.prisma.job.count({ where: { type: 'backup.run' } })).toBe(0);
    // recovery export: step-up required
    const noSu = await api('get', `/backup-repositories/${repo.id}/recovery-export`);
    expect(noSu.status).toBe(403);
    expect(noSu.body.error.code).toBe('STEP_UP_REQUIRED');
    const viewerExport = await api(
      'get',
      `/backup-repositories/${repo.id}/recovery-export`,
      viewer,
    );
    expect(viewerExport.status).toBe(403);
    const su = await stepUpToken(t, owner);
    const exp = await api(
      'get',
      `/backup-repositories/${repo.id}/recovery-export`,
      owner,
      undefined,
      { 'X-Step-Up': su },
    );
    expect(exp.status).toBe(200);
    expect(exp.headers['cache-control']).toBe('no-store');
    const pw = exp.body.data.servers[0].repoPassword as string;
    expect(Buffer.from(pw, 'base64')).toHaveLength(32);
    const audits = await t.prisma.auditEvent.findMany({
      where: { action: 'backup_repositories.recovery_export' },
      orderBy: { createdAt: 'asc' },
    });
    expect(audits.map((a) => a.result)).toEqual(['denied', 'success']); // viewer stopped by the guard (403)
    expect(JSON.stringify(audits)).not.toContain(pw);
    // rotation keeps the repo password; changing the user resets initialised
    await api(
      'post',
      `/backup-repositories/${repo.id}/servers/${agent.serverId}/initialized`,
      owner,
      {},
    );
    await api('put', `/backup-repositories/${repo.id}/servers/${agent.serverId}`, owner, {
      restUser: 'node-a',
      restPassword: 'Another-Rest-Pass-1',
    });
    expect(await repoPassword(repo.id)).toBe(pw);
    const v2 = await api('get', `/backup-repositories/${repo.id}`);
    expect(v2.body.data.servers[0].initialized).toBe(true);
    // only the export endpoint ever returned the password
    responses.splice(responses.indexOf(exp.body), 1);
    await assertNoSecretAnywhere([pw, REST_PASSWORD, 'Another-Rest-Pass-1']);
  });

  it('maintenance report token: reports only; cannot read or delete anything; wrong token 401', async () => {
    const repo = await repoWithAccess();
    const body = {
      repositoryId: repo.id,
      serverUser: 'node-a',
      kind: 'prune',
      ok: true,
      finishedAt: '2026-11-23T03:00:00Z',
      detail: { removed: 4, password: 'should-be-redacted' },
    };
    const bad = await t.http
      .post('/api/v1/backup-maintenance/reports')
      .set(bearer('x'.repeat(40)))
      .send(body);
    expect(bad.status).toBe(401);
    const none = await t.http.post('/api/v1/backup-maintenance/reports').send(body);
    expect(none.status).toBe(401);
    const good = await t.http
      .post('/api/v1/backup-maintenance/reports')
      .set(bearer(REPORT_TOKEN))
      .send(body);
    expect(good.status, JSON.stringify(good.body)).toBe(201);
    await t.http
      .post('/api/v1/backup-maintenance/reports')
      .set(bearer(REPORT_TOKEN))
      .send({ ...body, kind: 'copy', ok: false, detail: { error: 'S3 503' } });
    const unknownUser = await t.http
      .post('/api/v1/backup-maintenance/reports')
      .set(bearer(REPORT_TOKEN))
      .send({ ...body, serverUser: 'nobody' });
    expect(unknownUser.status).toBe(404);
    const view = await api('get', `/backup-repositories/${repo.id}`);
    expect(view.body.data.servers[0].maintenance.map((m: any) => [m.kind, m.ok])).toEqual([
      ['prune', true],
      ['copy', false],
    ]);
    expect(JSON.stringify(view.body)).not.toContain('should-be-redacted');
    // the report token is not a user session: every other endpoint → 401
    const p = await policy(repo.id);
    for (const [m, url] of [
      ['get', '/backup-repositories'],
      ['get', `/backup-repositories/${repo.id}/recovery-export`],
      ['delete', `/backup-policies/${p.body.data.id}`],
      ['post', `/backup-policies/${p.body.data.id}/run`],
      ['get', '/backup-runs'],
      ['post', '/restores'],
      ['get', '/audit-events'],
    ] as const) {
      const r = await t.http[m](`/api/v1${url}`).set(bearer(REPORT_TOKEN)).send({});
      expect(r.status, `${m} ${url}`).toBe(401);
    }
    expect(
      (await t.prisma.backupPolicy.findUniqueOrThrow({ where: { id: p.body.data.id } })).deletedAt,
    ).toBeNull();
  });
});

// ================================================================== P6.03 policies + scheduler

describe('P6.03 policies: validation, scheduler (cron + IANA tz, missed slot once, one active run)', () => {
  it('rejects forbidden paths, non-canonical paths, bad cron / timezone, unknown volumes, DB targets without compose service or secret', async () => {
    const repo = await repoWithAccess();
    const cases: Array<[unknown[], string]> = [
      [[{ type: 'paths', paths: ['/proc/self'] }], 'BACKUP_TARGET_INVALID'],
      [[{ type: 'paths', paths: ['/'] }], 'BACKUP_TARGET_INVALID'],
      [[{ type: 'paths', paths: ['/var/lib/ppanel-agent/keys'] }], 'BACKUP_TARGET_INVALID'],
      [[{ type: 'paths', paths: ['/run/secrets'] }], 'BACKUP_TARGET_INVALID'],
      [[{ type: 'paths', paths: ['/sys'] }], 'BACKUP_TARGET_INVALID'],
      [[{ type: 'paths', paths: ['/srv/../etc'] }], 'VALIDATION_FAILED'],
      [[{ type: 'paths', paths: ['relative/path'] }], 'VALIDATION_FAILED'],
    ];
    for (const [targets, code] of cases) {
      const r = await policy(repo.id, { targets });
      expect([r.status, r.body.error?.code], JSON.stringify(targets)).toEqual([422, code]);
    }
    for (const schedule of [
      { cron: '0 0 2 * * *', timezone: 'UTC' },
      { cron: '0 2 1-31 *', timezone: 'UTC' },
      { cron: '0 2 * * *', timezone: 'Mars/Olympus' },
      { cron: '99 2 * * *', timezone: 'UTC' },
    ]) {
      const r = await policy(repo.id, { schedule });
      expect([r.status, r.body.error?.code], JSON.stringify(schedule)).toEqual([
        422,
        'SCHEDULE_INVALID',
      ]);
    }
    const shopId = await composeDbApp();
    const db = {
      type: 'postgres',
      applicationId: shopId,
      service: 'db',
      database: 'app',
      user: 'postgres',
      passwordSecretKey: 'DB_PASSWORD',
    };
    const badSvc = await policy(repo.id, { targets: [{ ...db, service: 'cache' }] });
    expect(badSvc.status).toBe(422);
    expect(badSvc.body.error.details[0].path).toBe('targets.0.service');
    const badKey = await policy(repo.id, { targets: [{ ...db, passwordSecretKey: 'NOPE' }] });
    expect(badKey.body.error.details[0].path).toBe('targets.0.passwordSecretKey');
    const badVol = await policy(repo.id, {
      targets: [{ type: 'volume', applicationId: shopId, volume: 'nope' }],
    });
    expect(badVol.status).toBe(422);
    const okp = await policy(repo.id, {
      targets: [
        db,
        { type: 'volume', applicationId: shopId, volume: 'pgdata' },
        { type: 'paths', paths: ['/srv/data', '/var/lib'] },
      ],
    });
    expect(okp.status, JSON.stringify(okp.body)).toBe(201);
    expect(okp.body.data.targets[0]).toMatchObject({
      type: 'postgres',
      app: 'shop',
      applicationId: shopId,
      service: 'db',
    });
    expect(okp.body.data.targets[2].excludes).toEqual(['/var/lib/ppanel-agent']); // parent of the agent state dir → auto-excluded
    expect(okp.body.data).toMatchObject({
      retentionAppliedBy: 'maintenance',
      retention: { keepDaily: 7, keepWeekly: 4, keepMonthly: 6 },
    });
    // deployer (no backups.create) → 403 audited; viewer can read
    const d = await policy(repo.id, {}, dev);
    expect(d.status).toBe(403);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'http.post', result: 'denied', actorId: { not: null } },
      }),
    ).toBeGreaterThan(0);
    expect((await api('get', `/backup-policies/${okp.body.data.id}`, viewer)).status).toBe(200);
    // If-Match on update
    const stale = await api(
      'patch',
      `/backup-policies/${okp.body.data.id}`,
      owner,
      { name: 'n2' },
      { 'If-Match': '99' },
    );
    expect(stale.status).toBe(409);
    const upd = await api(
      'patch',
      `/backup-policies/${okp.body.data.id}`,
      owner,
      { name: 'n2' },
      { 'If-Match': '1' },
    );
    expect(upd.body.data).toMatchObject({ name: 'n2', version: 2 });
  });

  it('computes the next run in the policy timezone; a Center down over 3 slots runs ONCE on the next tick; one active run per policy', async () => {
    const repo = await repoWithAccess();
    const p = await policy(repo.id);
    const pid = p.body.data.id;
    // 02:00 Asia/Bangkok = 19:00 UTC the previous day
    const next = new Date(p.body.data.nextRunAt);
    expect(next.getUTCHours()).toBe(19);
    expect(next.getUTCMinutes()).toBe(0);
    expect(
      nextRunAfter('0 2 * * *', 'Asia/Bangkok', new Date('2026-11-23T00:00:00Z'))!.toISOString(),
    ).toBe('2026-11-23T19:00:00.000Z');
    expect(
      nextRunAfter(
        '30 1 * * *',
        'America/New_York',
        new Date('2026-03-08T00:00:00Z'),
      )!.toISOString(),
    ).toBe('2026-03-08T06:30:00.000Z'); // EST
    expect(
      nextRunAfter(
        '30 1 * * *',
        'America/New_York',
        new Date('2026-03-09T00:00:00Z'),
      )!.toISOString(),
    ).toBe('2026-03-09T05:30:00.000Z'); // EDT
    // simulate: the slot was 3 days ago (Center was down)
    const slot = new Date('2026-11-20T19:00:00Z');
    await t.prisma.backupPolicy.update({ where: { id: pid }, data: { nextRunAt: slot } });
    const sched = t.app.get(BackupSchedulerService);
    const now = new Date('2026-11-23T20:10:00Z');
    const r1 = await sched.tick(now);
    expect(r1.started).toHaveLength(1);
    expect(r1.started[0]).toMatchObject({ policyId: pid, slot: slot.toISOString() });
    const pol = await t.prisma.backupPolicy.findUniqueOrThrow({ where: { id: pid } });
    expect(pol.nextRunAt!.toISOString()).toBe('2026-11-24T19:00:00.000Z');
    expect(pol.lastScheduledAt!.toISOString()).toBe(slot.toISOString());
    expect(await t.prisma.backupRun.count({ where: { policyId: pid } })).toBe(1);
    // repeated tick (or a second instance) → nothing new
    expect((await sched.tick(now)).started).toHaveLength(0);
    // next slot due while the first run is still queued → skipped (one active run), audited
    const later = new Date('2026-11-24T19:00:30Z');
    const r3 = await sched.tick(later);
    expect(r3.started).toHaveLength(0);
    expect(r3.skipped[0]).toMatchObject({ policyId: pid, reason: 'BACKUP_IN_PROGRESS' });
    expect(
      await t.prisma.auditEvent.count({ where: { action: 'backup_runs.schedule_skipped' } }),
    ).toBe(1);
    expect(await t.prisma.backupRun.count({ where: { policyId: pid } })).toBe(1);
    const manual = await api('post', `/backup-policies/${pid}/run`);
    expect([manual.status, manual.body.error?.code]).toEqual([409, 'BACKUP_IN_PROGRESS']);
    // the scheduled run executes; durable: a second app instance sees the same scheduler state
    const g = await drain();
    expect(g.map((x) => x.type)).toEqual(['backup.run', 'backup.verify']);
    expect(g[0]!.params.tags).toEqual(['trigger=schedule']);
    const t2 = await bootApp();
    try {
      const st = await t2.prisma.backupPolicy.findUniqueOrThrow({ where: { id: pid } });
      expect(st.nextRunAt!.toISOString()).toBe('2026-11-25T19:00:00.000Z');
      expect(
        (await t2.app.get(BackupSchedulerService).tick(new Date('2026-11-24T19:05:00Z'))).started,
      ).toHaveLength(0);
    } finally {
      await t2.close();
    }
    // disabling stops scheduling; re-enabling does not back-fill
    await api('patch', `/backup-policies/${pid}`, owner, { enabled: false });
    expect((await api('get', `/backup-policies/${pid}`)).body.data.nextRunAt).toBeNull();
  });
});

// ================================================================== P6.04 runs

describe('P6.04 runs: uploaded with manifest, BACKUP_PARTIAL / expired never uploaded (P6-T04), secrets once', () => {
  it('happy path: backup.run → uploaded with snapshots + manifest; restic creds + DB password delivered once via the secrets call; never in params/responses/audit', async () => {
    const repo = await repoWithAccess();
    const shopId = await composeDbApp();
    const p = await policy(repo.id, {
      targets: [
        { type: 'paths', paths: ['/srv/data', '/etc/myapp'] },
        {
          type: 'postgres',
          applicationId: shopId,
          service: 'db',
          database: 'app',
          user: 'postgres',
          passwordSecretKey: 'DB_PASSWORD',
        },
      ],
    });
    const run = await api('post', `/backup-policies/${p.body.data.id}/run`, owner, undefined, {
      'Idempotency-Key': 'manual-run-0001',
    });
    expect(run.status, JSON.stringify(run.body)).toBe(202);
    expect(run.body.data.run).toMatchObject({
      status: 'queued',
      trigger: 'manual',
      verification: 'none',
    });
    const replay = await api('post', `/backup-policies/${p.body.data.id}/run`, owner, undefined, {
      'Idempotency-Key': 'manual-run-0001',
    });
    expect(replay.status).toBe(200);
    expect(replay.body.data.run.id).toBe(run.body.data.run.id);
    // restricted: backup jobs cannot be created through POST /jobs
    const direct = await api('post', `/servers/${agent.serverId}/jobs`, owner, {
      type: 'backup.run',
      params: {},
    });
    expect(direct.body.error.code).toBe('JOB_TYPE_RESTRICTED');

    let secondFetch: any;
    const grants = await drain(
      happy(agent, {
        'backup.run': async (g) => {
          const res = await happy()(g);
          secondFetch = await fetchSecrets(agent, g);
          return res;
        },
      }),
    );
    expect(grants.map((g) => g.type)).toEqual(['backup.run', 'backup.verify', 'backup.verify']);
    const params = grants[0]!.params;
    expect(params).toMatchObject({
      runId: run.body.data.run.id,
      policyId: p.body.data.id,
      repo: { url: 'http://backup.lab:8000/node-a/', repositoryId: repo.id },
      tags: ['trigger=manual'],
    });
    expect(params.targets[1]).toEqual({
      type: 'postgres',
      app: 'shop',
      service: 'db',
      database: 'app',
      user: 'postgres',
      passwordSecretKey: 'DB_PASSWORD',
    });
    const first = secretFetches.find((s) => s.type === 'backup.run')!;
    expect(first.status).toBe(200);
    const pw = await repoPassword(repo.id);
    expect(first.body.data).toEqual({
      restic: { repoPassword: pw, restUser: 'node-a', restPassword: REST_PASSWORD },
      env: { DB_PASSWORD },
    });
    expect([secondFetch.status, secondFetch.body.error.code]).toEqual([
      409,
      'SECRETS_ALREADY_FETCHED',
    ]);

    const got = await api(
      'get',
      `/backup-runs/${run.body.data.run.id}?manifestLimit=2&manifestPage=2`,
      viewer,
    );
    expect(got.status).toBe(200);
    const d = got.body.data;
    expect(d).toMatchObject({
      status: 'uploaded',
      resticVersion: '0.17.3',
      error: null,
      verification: 'repository_checked',
    });
    expect(d.snapshots.map((s: any) => [s.target, s.targetType])).toEqual([
      [0, 'paths'],
      [1, 'postgres'],
    ]);
    expect(d.manifest).toEqual({ files: 4, bytes: 66 + 9000, databases: 1, truncated: false });
    expect(d.manifestPaginate).toEqual({ page: 2, limit: 2, total: 5 });
    expect(d.manifestEntries).toHaveLength(2);
    expect(d.allowedActions).toEqual([]); // viewer
    expect((await api('get', `/backup-runs/${d.id}`)).body.data.allowedActions).toEqual([
      'verify_check',
      'verify_restore_test',
      'restore',
    ]);
    // the post-backup check got the per-snapshot manifest
    expect(grants[1]!.params.manifest).toHaveLength(1);
    expect(grants[1]!.params.manifest[0]).toMatchObject({ target: 0, type: 'paths', fileCount: 4 });
    expect(grants[1]!.params.manifest[0].files).toHaveLength(4);
    expect(grants[2]!.params.manifest[0]).toMatchObject({ database: 'app' });
    const list = await api('get', `/backup-runs?policy_id=${p.body.data.id}&status=uploaded`);
    expect(list.body.paginate.total).toBe(1);
    // audit trail
    const acts = (await t.prisma.auditEvent.findMany({ orderBy: { createdAt: 'asc' } })).map(
      (a) => a.action,
    );
    expect(acts).toEqual(
      expect.arrayContaining([
        'backup_runs.create',
        'secrets.delivered',
        'backup_runs.finished',
        'backup_runs.verified',
      ]),
    );
    const delivered = await t.prisma.auditEvent.findFirstOrThrow({
      where: {
        action: 'secrets.delivered',
        result: 'success',
        metadata: { path: ['jobType'], equals: 'backup.run' },
      },
    });
    expect(delivered.metadata).toMatchObject({
      keys: ['DB_PASSWORD'],
      restic: true,
      restUser: 'node-a',
    });
    secretFetches.length = 0;
    responses.length = 0; // the recovery export response legitimately held the password
    await assertNoSecretAnywhere([pw, REST_PASSWORD, DB_PASSWORD]);
  });

  it('BACKUP_PARTIAL → failed (never uploaded); success without a snapshot per target → failed; backup_failed alert fires', async () => {
    const repo = await repoWithAccess();
    const p = await policy(repo.id, {
      targets: [
        { type: 'paths', paths: ['/srv/a'] },
        { type: 'paths', paths: ['/srv/b'] },
      ],
    });
    const pid = p.body.data.id;
    const rule = await api('post', '/alert-rules', owner, {
      name: 'backups',
      scopeType: 'server',
      scopeId: agent.serverId,
      kind: 'backup_failed',
      forSec: 0,
    });
    expect(rule.status, JSON.stringify(rule.body)).toBe(201);
    expect(rule.body.data.active).toBe(true);
    const engine = t.app.get(AlertEngineService);

    const r1 = await api('post', `/backup-policies/${pid}/run`);
    await drain(
      happy(agent, {
        'backup.run': () =>
          fail('BACKUP_PARTIAL', 'target 1 failed: permission denied', {
            completed: [{ target: 0, snapshotId: SNAP(90) }],
          }),
      }),
    );
    const f1 = (await api('get', `/backup-runs/${r1.body.data.run.id}`)).body.data;
    expect(f1).toMatchObject({
      status: 'failed',
      snapshots: [],
      error: { code: 'BACKUP_PARTIAL' },
    });
    expect(f1.error.details.completed).toHaveLength(1);
    expect(f1.allowedActions).toEqual([]);
    const notUploaded = await api('post', `/backup-runs/${f1.id}/verify`, owner, {
      level: 'check',
    });
    expect(notUploaded.body.error.code).toBe('RUN_NOT_UPLOADED');
    const restoreFromFailed = await api('post', '/restores', owner, {
      runId: f1.id,
      snapshotId: SNAP(90),
      target: { type: 'paths', include: [], mode: 'staging' },
    });
    expect(restoreFromFailed.body.error.code).toBe('RUN_NOT_UPLOADED');
    await engine.tick();
    const inc = await t.prisma.incident.findFirstOrThrow({ where: { kind: 'backup_failed' } });
    expect(inc).toMatchObject({ targetType: 'backup_policy', targetId: pid, status: 'firing' });

    // agent claims success but only one of two snapshots → never `uploaded`
    const r2 = await api('post', `/backup-policies/${pid}/run`);
    await drain(
      happy(agent, {
        'backup.run': () => ok({ snapshots: [{ target: 0, snapshotId: SNAP(91) }], manifest: [] }),
      }),
    );
    expect((await api('get', `/backup-runs/${r2.body.data.run.id}`)).body.data).toMatchObject({
      status: 'failed',
      error: { code: 'BACKUP_PARTIAL' },
    });
    // garbage result → failed too
    const r3 = await api('post', `/backup-policies/${pid}/run`);
    await drain(happy(agent, { 'backup.run': () => ok({ hello: 'world' }) }));
    expect((await api('get', `/backup-runs/${r3.body.data.run.id}`)).body.data.status).toBe(
      'failed',
    );
    // a good run resolves the incident
    await api('post', `/backup-policies/${pid}/run`);
    await drain();
    await engine.tick();
    expect((await t.prisma.incident.findUniqueOrThrow({ where: { id: inc.id } })).status).toBe(
      'resolved',
    );
    expect(await t.prisma.backupRun.count({ where: { status: 'uploaded' } })).toBe(1);
  });

  it('interrupted agent (lease lapses) → expired, never uploaded; a late success result is refused', async () => {
    const repo = await repoWithAccess();
    const p = await policy(repo.id);
    const r = await api('post', `/backup-policies/${p.body.data.id}/run`);
    const lease = await agentCall(port, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    const g = lease.body.data.tasks[0] as Grant;
    expect(g.type).toBe('backup.run');
    await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
      leaseToken: g.leaseToken,
    });
    expect((await api('get', `/backup-runs/${r.body.data.run.id}`)).body.data.status).toBe(
      'running',
    );
    await t.prisma.job.update({
      where: { id: g.jobId },
      data: { leaseUntil: new Date(Date.now() - 1000) },
    });
    await t.app.get(SweeperService).tick();
    const run = (await api('get', `/backup-runs/${r.body.data.run.id}`)).body.data;
    expect(run).toMatchObject({
      status: 'expired',
      error: { code: 'LEASE_EXPIRED' },
      snapshots: [],
    });
    const late = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      status: 'succeeded',
      output: { snapshots: [{ target: 0, snapshotId: SNAP(5) }], manifest: [] },
    });
    expect(late.status).toBe(409);
    expect((await api('get', `/backup-runs/${r.body.data.run.id}`)).body.data.status).toBe(
      'expired',
    );
    expect(await drain()).toEqual([]); // mutating job never re-delivered
  });

  it('verification levels: check → repository_checked; restore_test → restore_verified (never downgraded by a later check); mismatches / zero compared → verify_failed', async () => {
    const repo = await repoWithAccess();
    const { run } = await uploadedRun(repo.id);
    expect(run.verification).toBe('none');
    const v1 = await api('post', `/backup-runs/${run.id}/verify`, owner, { level: 'check' });
    expect(v1.status, JSON.stringify(v1.body)).toBe(202);
    const busy = await api('post', `/backup-runs/${run.id}/verify`, owner, { level: 'check' });
    expect(busy.body.error.code).toBe('VERIFY_IN_PROGRESS');
    await drain();
    expect((await api('get', `/backup-runs/${run.id}`)).body.data.verification).toBe(
      'repository_checked',
    );
    await api('post', `/backup-runs/${run.id}/verify`, owner, { level: 'restore_test' });
    const g = await drain();
    expect(g[0]!.params).toMatchObject({
      target: { type: 'paths', include: [], mode: 'staging' },
      dryRun: false,
      verify: true,
    });
    expect(g[0]!.params.manifest[0].files).toHaveLength(2);
    expect((await api('get', `/backup-runs/${run.id}`)).body.data.verification).toBe(
      'restore_verified',
    );
    await api('post', `/backup-runs/${run.id}/verify`, owner, { level: 'check' });
    await drain();
    expect((await api('get', `/backup-runs/${run.id}`)).body.data.verification).toBe(
      'restore_verified',
    );
    // restore test that compared nothing proves nothing
    await api('post', `/backup-runs/${run.id}/verify`, owner, { level: 'restore_test' });
    await drain(
      happy(agent, {
        'restore.run': () =>
          ok({ restored: [], verify: { ok: true, compared: 0, mismatches: [] } }),
      }),
    );
    const d = (await api('get', `/backup-runs/${run.id}`)).body.data;
    expect(d.verification).toBe('verify_failed');
    // check with a mismatch
    const { run: run2 } = await uploadedRun(repo.id, { name: 'second' });
    await api('post', `/backup-runs/${run2.id}/verify`, owner, { level: 'check' });
    await drain(
      happy(agent, {
        'backup.verify': () =>
          ok({ repoCheckOk: true, filesCompared: 2, mismatches: [{ path: '/srv/data/a.txt' }] }),
      }),
    );
    const d2 = (await api('get', `/backup-runs/${run2.id}`)).body.data;
    expect(d2.verification).toBe('verify_failed');
    expect(d2.verifications[0]).toMatchObject({ level: 'check', status: 'failed' });
    // deployer cannot verify
    expect(
      (await api('post', `/backup-runs/${run2.id}/verify`, dev, { level: 'check' })).status,
    ).toBe(403);
  });

  it('GET /servers/:id/snapshots → live backup.snapshots (read-only)', async () => {
    await repoWithAccess();
    const pending = api('get', `/servers/${agent.serverId}/snapshots`);
    await new Promise((r) => setTimeout(r, 300));
    await drain();
    const r = await pending;
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data.snapshots[0]).toMatchObject({ id: SNAP(200), paths: ['/srv/data'] });
    expect((await api('get', `/servers/${agent.serverId}/snapshots`, viewer)).status).toBe(403);
  });
});

// ================================================================== P6.05 restores

describe('P6.05 restores: plan → dry-run → approval → execute (P6-T03)', () => {
  it('staging restore in uat: planned (impact) → dry-run → impact_reviewed → executes WITHOUT approval → verified; run becomes restore_verified', async () => {
    const repo = await repoWithAccess();
    const { run } = await uploadedRun(repo.id);
    const snap = run.snapshots[0].snapshotId;
    const c = await api('post', '/restores', owner, {
      runId: run.id,
      snapshotId: snap.slice(0, 8),
      target: { type: 'paths', include: ['/srv/data/a.txt'], mode: 'staging' },
    });
    expect(c.status, JSON.stringify(c.body)).toBe(201);
    const r = c.body.data;
    expect(r).toMatchObject({
      status: 'planned',
      snapshotId: snap,
      approval: { required: false, reasons: [] },
    });
    expect(r.plan.impact.map((i: any) => i.effect)).toEqual(['create', 'note', 'note']);
    expect(r.plan.impact.at(-1).ref).toBe('config_vs_data');
    expect(r.allowedActions).toEqual(['dry_run', 'cancel']);
    const early = await api('post', `/restores/${r.id}/execute`);
    expect(early.status).toBe(409);
    const dry = await api('post', `/restores/${r.id}/dry-run`);
    expect(dry.status).toBe(202);
    const g = await drain();
    expect(g.map((x) => [x.type, x.params.dryRun])).toEqual([['restore.run', true]]);
    const reviewed = (await api('get', `/restores/${r.id}`)).body.data;
    expect(reviewed).toMatchObject({ status: 'impact_reviewed', plan: { dryRun: { ok: true } } });
    expect(reviewed.allowedActions).toEqual(['dry_run', 'execute', 'cancel']);
    const ex = await api('post', `/restores/${r.id}/execute`);
    expect(ex.status, JSON.stringify(ex.body)).toBe(202);
    expect(ex.body.data.status).toBe('running');
    const g2 = await drain();
    expect(g2.map((x) => [x.type, x.params.target.mode, x.params.verify])).toEqual([
      ['restore.run', 'staging', true],
    ]);
    expect(g2[0]!.params.manifest[0].files).toHaveLength(2);
    const done = (await api('get', `/restores/${r.id}`)).body.data;
    expect(done).toMatchObject({ status: 'verified', safetySnapshotRunId: null });
    expect(done.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['dry_run', 'succeeded'],
      ['restore', 'succeeded'],
    ]);
    expect((await api('get', `/backup-runs/${run.id}`)).body.data.verification).toBe(
      'restore_verified',
    );
    // target mismatch / unknown snapshot / forbidden include
    expect(
      (
        await api('post', '/restores', owner, {
          runId: run.id,
          snapshotId: SNAP(77),
          target: { type: 'paths', include: [], mode: 'staging' },
        })
      ).body.error.code,
    ).toBe('SNAPSHOT_NOT_IN_RUN');
    expect(
      (
        await api('post', '/restores', owner, {
          runId: run.id,
          snapshotId: snap,
          target: { type: 'paths', include: ['/etc/passwd'], mode: 'staging' },
        })
      ).body.error.code,
    ).toBe('RESTORE_TARGET_MISMATCH');
  });

  it('in_place volume restore: approval required (approver ≠ creator, step-up, planHash, single-use); order safety backup → stop → restore → start + healthcheck → verified', async () => {
    const repo = await repoWithAccess();
    const { app, container } = await deployedVolumeApp();
    const { run } = await uploadedRun(repo.id, {
      targets: [{ type: 'volume', applicationId: app.id, volume: 'uploads' }],
    });
    const c = await api('post', '/restores', owner, {
      runId: run.id,
      snapshotId: run.snapshots[0].snapshotId,
      target: { type: 'volume', app: 'web', volume: 'uploads', mode: 'in_place' },
    });
    expect(c.status, JSON.stringify(c.body)).toBe(201);
    const r = c.body.data;
    expect(r.approval).toMatchObject({ required: true, reasons: ['in_place'] });
    expect(r.plan.impact.map((i: any) => [i.effect, i.kind, i.ref])).toEqual([
      ['overwrite', 'volume', 'ppanel-web-uploads'],
      ['note', 'application', 'safety_backup'],
      ['downtime', 'application', 'web'],
      ['note', 'config', 'config_vs_data'],
    ]);
    await api('post', `/restores/${r.id}/dry-run`);
    await drain();
    const aw = (await api('get', `/restores/${r.id}`)).body.data;
    expect(aw.status).toBe('awaiting_approval');
    expect(aw.allowedActions).toEqual(['cancel']); // creator cannot approve
    // unapproved execute → 409 + audited denial
    // D4-B: in_place without an explicit impact confirmation is refused server-side and audited
    const unconfirmed = await api('post', `/restores/${r.id}/execute`);
    expect([unconfirmed.status, unconfirmed.body.error?.code]).toEqual([
      422,
      'IMPACT_CONFIRMATION_REQUIRED',
    ]);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'restores.execute', targetId: r.id, result: 'denied' },
      }),
    ).toBeGreaterThan(0);
    const unapproved = await api('post', `/restores/${r.id}/execute`, owner, {
      confirmImpact: true,
    });
    expect([unapproved.status, unapproved.body.error.code]).toEqual([409, 'APPROVAL_REQUIRED']);
    // creator cannot approve (403, audited)
    const suOwner = await stepUpToken(t, owner);
    const self = await api(
      'post',
      `/restores/${r.id}/approve`,
      owner,
      { planHash: r.planHash },
      { 'X-Step-Up': suOwner },
    );
    expect([self.status, self.body.error.code]).toEqual([403, 'APPROVER_IS_CREATOR']);
    // deployer / viewer lack approvals.decide
    expect(
      (await api('post', `/restores/${r.id}/approve`, dev, { planHash: r.planHash })).status,
    ).toBe(403);
    // approver without step-up → 403; wrong planHash → 409
    expect(
      (await api('post', `/restores/${r.id}/approve`, admin, { planHash: r.planHash })).body.error
        .code,
    ).toBe('STEP_UP_REQUIRED');
    const suAdmin = await stepUpToken(t, admin);
    const wrong = await api(
      'post',
      `/restores/${r.id}/approve`,
      admin,
      { planHash: 'f'.repeat(64) },
      { 'X-Step-Up': suAdmin },
    );
    expect(wrong.body.error.code).toBe('PLAN_HASH_MISMATCH');
    const ap = await api(
      'post',
      `/restores/${r.id}/approve`,
      admin,
      { planHash: r.planHash },
      { 'X-Step-Up': suAdmin },
    );
    expect(ap.status, JSON.stringify(ap.body)).toBe(200);
    expect(ap.body.data).toMatchObject({
      status: 'approved',
      approval: { approvedBy: expect.any(String), usedAt: null },
    });
    // deployer cannot execute (no backups.restore) → 403 audited
    expect((await api('post', `/restores/${r.id}/execute`, dev)).status).toBe(403);
    const ex = await api('post', `/restores/${r.id}/execute`, owner, { confirmImpact: true });
    expect(ex.status, JSON.stringify(ex.body)).toBe(202);
    expect(ex.body.data.approval.usedAt).not.toBeNull();
    const again = await api('post', `/restores/${r.id}/execute`, owner, { confirmImpact: true });
    expect(again.status).toBe(409); // single use
    const g = await drain();
    expect(g.map((x) => x.type)).toEqual([
      'backup.run',
      'container.stop',
      'restore.run',
      'container.start',
    ]);
    expect(g[0]!.params.tags).toEqual(['trigger=safety']);
    expect(g[0]!.params.targets).toEqual([{ type: 'volume', app: 'web', volume: 'uploads' }]);
    expect(g[1]!.params).toEqual({ app: 'web', name: container.name });
    expect(g[2]!.params).toMatchObject({
      restoreId: r.id,
      snapshotId: run.snapshots[0].snapshotId,
      target: { mode: 'in_place' },
      dryRun: false,
      verify: true,
    });
    expect(g[3]!.params).toMatchObject({
      app: 'web',
      name: container.name,
      hostPort: container.hostPort,
      healthcheck: { path: '/healthz' },
    });
    const done = (await api('get', `/restores/${r.id}`)).body.data;
    expect(done.status).toBe('verified');
    expect(done.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['dry_run', 'succeeded'],
      ['safety_backup', 'succeeded'],
      ['stop_app', 'succeeded'],
      ['restore', 'succeeded'],
      ['start_app', 'succeeded'],
    ]);
    expect(done.safetySnapshotIds).toHaveLength(1);
    const safety = (await api('get', `/backup-runs/${done.safetySnapshotRunId}`)).body.data;
    expect(safety).toMatchObject({
      trigger: 'safety',
      status: 'uploaded',
      restoreId: r.id,
      verification: 'none',
    });
    // full audit trail of the approved operation
    const trail = await t.prisma.auditEvent.findMany({
      where: { targetType: 'restore', targetId: r.id },
      orderBy: { createdAt: 'asc' },
    });
    expect(trail.map((a) => [a.action, a.result, (a.metadata as any)?.reason ?? null])).toEqual([
      ['restores.create', 'success', null],
      ['restores.dry_run', 'success', null],
      ['restores.dry_run_finished', 'success', null],
      ['restores.execute', 'denied', 'impact_not_confirmed'],
      ['restores.execute', 'denied', 'approval_required'],
      ['restores.approve', 'denied', 'approver_is_creator'],
      ['restores.approve', 'denied', 'step_up_required'],
      ['restores.approve', 'denied', 'plan_hash_mismatch'],
      ['restores.approve', 'success', null],
      ['restores.execute', 'success', null],
      ['restores.execute', 'denied', 'state_invalid'], // approval was single-use; restore already running
      ['restores.finished', 'success', null],
    ]);
    expect(
      trail.find((a) => a.action === 'restores.execute' && a.result === 'success')!.metadata,
    ).toMatchObject({ approvedBy: expect.any(String), safetyRunId: done.safetySnapshotRunId });
  });

  it('in_place failure → requires_manual_recovery with the safety snapshot id; app left stopped (no start); a failed safety backup aborts before stopping', async () => {
    const repo = await repoWithAccess();
    const { app } = await deployedVolumeApp();
    const { run } = await uploadedRun(repo.id, {
      targets: [{ type: 'volume', applicationId: app.id, volume: 'uploads' }],
    });
    const mk = async () => {
      const c = await api('post', '/restores', owner, {
        runId: run.id,
        snapshotId: run.snapshots[0].snapshotId,
        target: { type: 'volume', app: 'web', volume: 'uploads', mode: 'in_place' },
      });
      await api('post', `/restores/${c.body.data.id}/dry-run`);
      await drain();
      const su = await stepUpToken(t, admin);
      await api(
        'post',
        `/restores/${c.body.data.id}/approve`,
        admin,
        { planHash: c.body.data.planHash },
        { 'X-Step-Up': su },
      );
      const ex = await api('post', `/restores/${c.body.data.id}/execute`, owner, {
        confirmImpact: true,
      });
      expect(ex.status, JSON.stringify(ex.body)).toBe(202);
      return c.body.data.id as string;
    };
    const id1 = await mk();
    const g = await drain(
      happy(agent, {
        'restore.run': (gr) =>
          gr.params.dryRun ? ok({ restored: [] }) : fail('RESTORE_FAILED', 'disk full'),
      }),
    );
    expect(g.map((x) => x.type)).toEqual(['backup.run', 'container.stop', 'restore.run']);
    const r1 = (await api('get', `/restores/${id1}`)).body.data;
    expect(r1).toMatchObject({
      status: 'requires_manual_recovery',
      error: { code: 'RESTORE_FAILED' },
    });
    expect(r1.safetySnapshotIds).toHaveLength(1);
    expect(r1.safetySnapshotIds[0]).toMatch(/^[a-f0-9]{64}$/);
    expect(r1.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['dry_run', 'succeeded'],
      ['safety_backup', 'succeeded'],
      ['stop_app', 'succeeded'],
      ['restore', 'failed'],
    ]);
    // restore "succeeded" but verify not ok → also manual recovery
    const id2 = await mk();
    await drain(
      happy(agent, {
        'restore.run': (gr) =>
          ok(
            gr.params.dryRun
              ? { restored: [] }
              : { restored: [], verify: { ok: false, compared: 3, mismatches: [{ path: 'x' }] } },
          ),
      }),
    );
    expect((await api('get', `/restores/${id2}`)).body.data).toMatchObject({
      status: 'requires_manual_recovery',
      error: { code: 'VERIFY_FAILED' },
    });
    // start fails health → manual recovery
    const id3 = await mk();
    await drain(happy(agent, { 'container.start': () => fail('CANDIDATE_UNHEALTHY') }));
    expect((await api('get', `/restores/${id3}`)).body.data).toMatchObject({
      status: 'requires_manual_recovery',
      error: { code: 'APP_START_FAILED' },
    });
    // safety backup fails → failed, nothing stopped
    const id4 = await mk();
    const g4 = await drain(happy(agent, { 'backup.run': () => fail('REPO_LOCKED') }));
    expect(g4.map((x) => x.type)).toEqual(['backup.run']);
    expect((await api('get', `/restores/${id4}`)).body.data).toMatchObject({
      status: 'failed',
      error: { code: 'SAFETY_BACKUP_FAILED' },
    });
  });

  it('production: staging restore needs approval too (409 without); unauthorized users 403 + audited; cancel', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production', name: 'prod-1' });
    await agentCall(port, prod.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(seq++));
    const repo = await repoWithAccess(prod);
    const p = await api('post', '/backup-policies', owner, {
      name: 'prod',
      serverId: prod.serverId,
      repositoryId: repo.id,
      targets: [{ type: 'paths', paths: ['/srv/data'] }],
      schedule: { cron: '0 3 * * *', timezone: 'UTC' },
      verify: { afterBackup: 'none' },
    });
    expect(p.status, JSON.stringify(p.body)).toBe(201);
    await api('post', `/backup-policies/${p.body.data.id}/run`);
    await drain(happy(prod), prod);
    const run = (await api('get', `/backup-runs?policy_id=${p.body.data.id}`)).body.data[0];
    expect(run.status).toBe('uploaded');
    // unauthorized: viewer + deployer cannot even plan a restore → 403, audited
    for (const tok of [viewer, dev]) {
      const r = await api('post', '/restores', tok, {
        runId: run.id,
        snapshotId: run.snapshots[0].snapshotId,
        target: { type: 'paths', include: [], mode: 'staging' },
      });
      expect(r.status).toBe(403);
    }
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'http.post', targetId: '/api/v1/restores', result: 'denied' },
      }),
    ).toBe(2);
    const c = await api('post', '/restores', owner, {
      runId: run.id,
      snapshotId: run.snapshots[0].snapshotId,
      target: { type: 'paths', include: [], mode: 'staging' },
    });
    expect(c.body.data.approval).toMatchObject({ required: true, reasons: ['production'] });
    await api('post', `/restores/${c.body.data.id}/dry-run`);
    await drain(happy(prod), prod);
    expect((await api('get', `/restores/${c.body.data.id}`)).body.data.status).toBe(
      'awaiting_approval',
    );
    const ex = await api('post', `/restores/${c.body.data.id}/execute`);
    expect([ex.status, ex.body.error.code]).toEqual([409, 'APPROVAL_REQUIRED']);
    expect(
      await t.prisma.job.count({
        where: {
          serverId: prod.serverId,
          type: 'restore.run',
          params: { path: ['dryRun'], equals: false },
        },
      }),
    ).toBe(0);
    const denied = await t.prisma.auditEvent.findFirstOrThrow({
      where: { action: 'restores.execute', result: 'denied' },
    });
    expect(denied.metadata).toMatchObject({
      reason: 'approval_required',
      approvalReasons: ['production'],
    });
    // cancel before running; then nothing can be executed
    const cancel = await api('post', `/restores/${c.body.data.id}/cancel`);
    expect(cancel.body.data.status).toBe('cancelled');
    expect((await api('post', `/restores/${c.body.data.id}/execute`)).status).toBe(409);
    // restores list is scoped and paginated
    const list = await api('get', `/restores?server_id=${prod.serverId}`, viewer);
    expect(list.body.paginate.total).toBe(1);
    expect(list.body.data[0].allowedActions).toEqual([]);
  });
});

describe('P6.05 DB targets: scratch restore + in-place order for a compose DB service', () => {
  it('postgres scratch restore runs without approval in uat and gets the DB password via the secrets call; in_place keeps the DB up (stop skipped) and a compose start without a current plan → requires_manual_recovery', async () => {
    const repo = await repoWithAccess();
    const shopId = await composeDbApp();
    const db = {
      type: 'postgres',
      applicationId: shopId,
      service: 'db',
      database: 'app',
      user: 'postgres',
      passwordSecretKey: 'DB_PASSWORD',
    };
    const { run } = await uploadedRun(repo.id, { targets: [db] });
    const target = {
      type: 'postgres',
      app: 'shop',
      service: 'db',
      database: 'app',
      user: 'postgres',
      passwordSecretKey: 'DB_PASSWORD',
    };
    const c = await api('post', '/restores', owner, {
      runId: run.id,
      snapshotId: run.snapshots[0].snapshotId,
      target: { ...target, mode: 'scratch' },
    });
    expect(c.status, JSON.stringify(c.body)).toBe(201);
    expect(c.body.data.approval.required).toBe(false);
    await api('post', `/restores/${c.body.data.id}/dry-run`);
    await drain();
    secretFetches.length = 0;
    await api('post', `/restores/${c.body.data.id}/execute`);
    const g = await drain();
    expect(g.map((x) => [x.type, x.params.target.mode])).toEqual([['restore.run', 'scratch']]);
    expect(g[0]!.params.manifest[0]).toMatchObject({
      database: 'app',
      tables: [
        { name: 'orders', rows: 12 },
        { name: 'users', rows: 3 },
      ],
    });
    expect(secretFetches[0]!.body.data.env).toEqual({ DB_PASSWORD });
    expect((await api('get', `/restores/${c.body.data.id}`)).body.data.status).toBe('verified');

    const ip = await api('post', '/restores', owner, {
      runId: run.id,
      snapshotId: run.snapshots[0].snapshotId,
      target: { ...target, mode: 'in_place' },
    });
    expect(ip.body.data.plan.impact.map((i: any) => i.effect)).toEqual([
      'overwrite',
      'note',
      'downtime',
      'note',
    ]);
    await api('post', `/restores/${ip.body.data.id}/dry-run`);
    await drain();
    const su = await stepUpToken(t, admin);
    expect(
      (
        await api(
          'post',
          `/restores/${ip.body.data.id}/approve`,
          admin,
          { planHash: ip.body.data.planHash },
          { 'X-Step-Up': su },
        )
      ).status,
    ).toBe(200);
    expect(
      (await api('post', `/restores/${ip.body.data.id}/execute`, owner, { confirmImpact: true }))
        .status,
    ).toBe(202);
    const g2 = await drain();
    expect(g2.map((x) => x.type)).toEqual(['backup.run', 'restore.run']);
    const done = (await api('get', `/restores/${ip.body.data.id}`)).body.data;
    expect(done.steps.map((s: any) => [s.name, s.status])).toEqual([
      ['dry_run', 'succeeded'],
      ['safety_backup', 'succeeded'],
      ['stop_app', 'skipped'],
      ['restore', 'succeeded'],
      ['start_app', 'failed'],
    ]);
    expect(done).toMatchObject({
      status: 'requires_manual_recovery',
      error: { code: 'APP_START_FAILED' },
    });
    expect(done.safetySnapshotIds).toHaveLength(1);
    responses.length = 0;
    secretFetches.length = 0;
    await assertNoSecretAnywhere([DB_PASSWORD, REST_PASSWORD]);
  });
});
