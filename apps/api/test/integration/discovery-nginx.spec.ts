/**
 * P3 Center side: discovery scan ingest, import/ownership tiers, Nginx revisions, drift.
 * The agent is simulated through the REAL mTLS gateway (lease → ack → result), using the
 * captured lab discovery report as the scan output.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { DiscoveryService } from '../../src/discovery/discovery.service';
import { SweeperService } from '../../src/jobs/sweeper.service';
import { computePlanHash } from '../../src/nginx/nginx-plan';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  type EnrolledAgent,
  login,
  resetDb,
  stepUpToken,
  type TestApp,
} from './helpers';

const FIXTURE = JSON.parse(
  readFileSync(path.join(__dirname, '../fixtures/discovery-scan-result.json'), 'utf8'),
) as Record<string, any>;
const SECURE_FILE = '/etc/nginx/sites-enabled/04-tls-secure.conf';
const DUP_A_FILE = '/etc/nginx/sites-enabled/05-duplicate-a.conf';
const PHP_FILE = '/etc/nginx/sites-enabled/02-php-legacy.conf';
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

let t: TestApp;
let port: number;
let owner: string; // superadmin (platform_owner)
let admin: string; // ops_admin (approver)
let viewer: string; // user1
let agent: EnrolledAgent;

beforeAll(async () => {
  t = await bootApp({ PPANEL_NGINX_READ_WAIT_MS: '15000' });
  port = await t.gateway.start(0, '127.0.0.1');
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  viewer = await login(t, 'user1');
  agent = await enrollAgent(t, owner);
});

// ------------------------------------------------------------------ simulated agent

interface Grant {
  jobId: string;
  type: string;
  params: any;
  leaseToken: string;
}
type Reply = { status: 'succeeded' | 'failed'; output?: unknown; error?: unknown };

/** Polls the gateway until a task arrives, acks it and posts the handler's result. */
async function serve(a: EnrolledAgent, handler: (g: Grant) => Reply): Promise<Grant> {
  for (let i = 0; i < 20; i++) {
    const r = await agentCall(port, a.creds, 'GET', '/agent/v1/tasks?waitSec=2');
    expect(r.status).toBe(200);
    const tasks = r.body.data.tasks as Grant[];
    if (tasks.length === 0) continue;
    expect(tasks).toHaveLength(1);
    const g = tasks[0]!;
    const ack = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
      leaseToken: g.leaseToken,
    });
    expect(ack.status).toBe(200);
    const res = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      ...handler(g),
    });
    expect(res.status).toBe(200);
    return g;
  }
  throw new Error('no task delivered');
}

/** nginx.read_files reply from an in-memory "disk" (null = file absent). */
function readReply(disk: Record<string, string | null>) {
  return (g: Grant): Reply => {
    expect(g.type).toBe('nginx.read_files');
    return {
      status: 'succeeded',
      output: {
        files: (g.params.paths as string[]).map((p) => {
          const c = disk[p] ?? null;
          return c === null
            ? {
                path: p,
                exists: false,
                sha256: null,
                sizeBytes: 0,
                content: null,
                isSymlink: false,
                resolvedPath: p,
              }
            : {
                path: p,
                exists: true,
                sha256: sha(c),
                sizeBytes: c.length,
                content: c,
                isSymlink: false,
                resolvedPath: p,
              };
        }),
      },
    };
  };
}

function fixtureWith(fileSha: Record<string, string>) {
  const copy = structuredClone(FIXTURE);
  for (const f of copy.nginx.data.report.files) if (fileSha[f.path]) f.sha256 = fileSha[f.path];
  return copy;
}

async function scan(a: EnrolledAgent = agent, output: unknown = FIXTURE, token = owner) {
  const c = await t.http
    .post(`/api/v1/servers/${a.serverId}/discovery-scans`)
    .set(bearer(token))
    .send({});
  expect(c.status).toBe(202);
  expect(c.body.data).toEqual({ scanId: expect.any(String), jobId: expect.any(String) });
  const g = await serve(a, (grant) => {
    expect(grant.type).toBe('discovery.scan');
    expect(grant.params.sources).toEqual(['nginx', 'docker', 'systemd', 'php-fpm', 'ports']);
    return { status: 'succeeded', output };
  });
  expect(g.jobId).toBe(c.body.data.jobId);
  const s = await t.http.get(`/api/v1/discovery-scans/${c.body.data.scanId}`).set(bearer(token));
  expect(s.status).toBe(200);
  return s.body.data;
}

async function findings(scanId: string, qs = '', token = owner) {
  const r = await t.http
    .get(`/api/v1/discovery-scans/${scanId}/findings?limit=100${qs}`)
    .set(bearer(token));
  expect(r.status).toBe(200);
  return r.body;
}

async function findingFor(scanId: string, file: string, listen?: string) {
  const all = (await findings(scanId, '&kind=nginx_server')).data as any[];
  const f = all.find((x) => x.provenance.file === file && (!listen || x.listen.includes(listen)));
  expect(f, file).toBeTruthy();
  return f;
}

async function importOne(scanId: string, findingId: string, body: Record<string, unknown> = {}) {
  const r = await t.http
    .post(`/api/v1/discovery-scans/${scanId}/import`)
    .set(bearer(owner))
    .send({ findingIds: [findingId], ...body });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body.data.applications[0];
}

const own = (
  appId: string,
  toMode: string,
  opts: { token?: string; stepUp?: string; ack?: boolean } = {},
) => {
  const req = t.http
    .post(`/api/v1/applications/${appId}/ownership`)
    .set(bearer(opts.token ?? owner));
  if (opts.stepUp) req.set('X-Step-Up', opts.stepUp);
  return req.send({
    toMode,
    reason: `move to ${toMode} for test`,
    ...(opts.ack ? { acknowledgeReasons: true } : {}),
  });
};

/** Imports a finding and walks it up to `mode` one step at a time. */
async function appAt(
  scanId: string,
  file: string,
  mode: 'observed' | 'adopted' | 'managed',
  listen?: string,
  stepUp?: string,
) {
  const f = await findingFor(scanId, file, listen);
  const app = await importOne(scanId, f.id);
  for (const m of ['adopted', 'managed'] as const) {
    if (mode === 'observed' || (mode === 'adopted' && m === 'managed')) break;
    const r = await own(app.id, m, { ack: true, stepUp });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
  }
  return (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
}

async function createRevision(
  a: EnrolledAgent,
  appId: string,
  files: Array<{ path: string; content: string }>,
  disk: Record<string, string | null>,
  extra: Record<string, unknown> = {},
) {
  const pending = t.http
    .post(`/api/v1/applications/${appId}/nginx/revisions`)
    .set(bearer(owner))
    .send({ files, ...extra })
    .then((r) => r);
  await serve(a, readReply(disk));
  return pending;
}

const rev = async (id: string) =>
  (await t.http.get(`/api/v1/nginx-revisions/${id}`).set(bearer(owner))).body.data;
const post = (p: string, token = owner, stepUp?: string, body: unknown = {}) => {
  const req = t.http.post(`/api/v1${p}`).set(bearer(token));
  if (stepUp) req.set('X-Step-Up', stepUp);
  return req.send(body as object);
};

/** draft → validate → agent says valid. */
async function validated(a: EnrolledAgent, revId: string) {
  const v = await post(`/nginx-revisions/${revId}/validate`);
  expect(v.status, JSON.stringify(v.body)).toBe(202);
  await serve(a, (g) => {
    expect(g.type).toBe('nginx.validate');
    return {
      status: 'succeeded',
      output: { valid: true, nginxTestOutput: 'syntax is ok', filesChecked: [] },
    };
  });
  return rev(revId);
}

// ================================================================== P3.03 scans

describe('P3.03 discovery scan ingest', () => {
  it('scan → ingest → findings match the real report; re-ingest is idempotent; ownership untouched', async () => {
    const s = await scan();
    expect(s).toMatchObject({
      status: 'completed',
      serverId: agent.serverId,
      completedAt: expect.any(String),
      summary: {
        nginxServers: 9,
        duplicates: 1,
        manualReview: 5,
        upstreams: 1,
        phpFpmPools: 1,
        listeners: 3,
      },
      drift: [],
    });
    expect(s.configFiles).toHaveLength(16);
    expect(s.configFiles[0]).toEqual({
      path: '/etc/nginx/nginx.conf',
      sha256: 'ddd969a3c1588a33accc745b2f91a0448c528853b89d578fcc5cc5db98ba7955',
    });
    const nginx = await findings(s.id, '&kind=nginx_server');
    expect(nginx.paginate.total).toBe(9);
    const manual = await findings(s.id, '&kind=nginx_server&manual_review=true');
    expect(manual.paginate.total).toBe(5);
    const conflicts = (nginx.data as any[]).filter((f) => f.conflicts.length);
    expect(conflicts).toHaveLength(2);
    expect(conflicts[0].conflicts[0].with).toEqual([conflicts[1].id]);
    const total = (await findings(s.id)).paginate.total;
    expect(total).toBe(9 + 1 + 1 + 3); // servers + upstream + php pool + listeners
    expect(nginx.data[0]).toMatchObject({
      scanId: s.id,
      serverId: agent.serverId,
      fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
      externalId: expect.stringMatching(/^srv_/),
      applicationId: null,
      provenance: { file: expect.stringMatching(/^\/etc\/nginx\//), line: expect.any(Number) },
    });

    // re-ingest the same job (replay + direct hook call) → no duplicate findings
    const job = await t.prisma.job.findUniqueOrThrow({ where: { id: s.jobId } });
    await t.jobs.dispatchFinished(job);
    const row = await t.prisma.discoveryScan.findUniqueOrThrow({ where: { id: s.id } });
    expect(await t.app.get(DiscoveryService).ingest(row, FIXTURE)).toBe(false);
    expect(await t.prisma.discoveryFinding.count({ where: { scanId: s.id } })).toBe(total);

    // read-only: a scan never creates applications or changes ownership
    expect(await t.prisma.application.count()).toBe(0);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'discovery_scans.create', result: 'success' },
      }),
    ).toBe(1);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'discovery_scans.ingest', actorType: 'system' },
      }),
    ).toBe(1);

    // viewer may read scans/findings (nginx.read); list filter by server
    const list = await t.http
      .get(`/api/v1/discovery-scans?server_id=${agent.serverId}`)
      .set(bearer(viewer));
    expect(list.status).toBe(200);
    expect(list.body.paginate.total).toBe(1);
  });

  it('failed scan job → scan failed (no findings)', async () => {
    const c = await t.http
      .post(`/api/v1/servers/${agent.serverId}/discovery-scans`)
      .set(bearer(owner))
      .send({ sources: ['nginx'] });
    expect(c.status).toBe(202);
    await serve(agent, () => ({
      status: 'failed',
      error: { code: 'HANDLER_ERROR', message: 'boom' },
    }));
    const s = await t.http.get(`/api/v1/discovery-scans/${c.body.data.scanId}`).set(bearer(owner));
    expect(s.body.data).toMatchObject({
      status: 'failed',
      error: { code: 'HANDLER_ERROR' },
      sources: ['nginx'],
    });
    expect(await t.prisma.discoveryFinding.count()).toBe(0);
    const bad = await t.http
      .post(`/api/v1/servers/${agent.serverId}/discovery-scans`)
      .set(bearer(owner))
      .send({ sources: ['etc'] });
    expect(bad.status).toBe(422);
  });
});

// ================================================================== P3.04 import + ownership

describe('P3.04 import and ownership tiers (P3-T04 ownership part)', () => {
  it('import defaults to observed; adopted/managed rejected; re-import never changes ownership', async () => {
    const s = await scan();
    const f = await findingFor(s.id, SECURE_FILE, '443 ssl http2');
    const bad = await t.http
      .post(`/api/v1/discovery-scans/${s.id}/import`)
      .set(bearer(owner))
      .send({ findingIds: [f.id], mode: 'adopted' });
    expect(bad.status).toBe(422);
    expect(bad.body.error.code).toBe('IMPORT_MODE_NOT_ALLOWED');
    const bad2 = await t.http
      .post(`/api/v1/discovery-scans/${s.id}/import`)
      .set(bearer(owner))
      .send({ findingIds: [f.id], mode: 'managed' });
    expect(bad2.body.error.code).toBe('IMPORT_MODE_NOT_ALLOWED');
    const viewerImport = await t.http
      .post(`/api/v1/discovery-scans/${s.id}/import`)
      .set(bearer(viewer))
      .send({ findingIds: [f.id] });
    expect(viewerImport.status).toBe(403);

    const app = await importOne(s.id, f.id);
    expect(app).toMatchObject({
      serverId: agent.serverId,
      name: 'secure-example-lab',
      environment: 'development',
      kind: 'nginx_static',
      domains: ['secure.example.lab'],
      ownershipMode: 'observed',
      flags: { unsupported: false, conflict: false, manualReview: false, driftDetected: false },
      sourceFindingFingerprint: f.fingerprint,
      nginxFiles: [
        {
          path: SECURE_FILE,
          lastKnownSha256: 'f6538e4c5b1767f5658c5b978379bbd12455767259153aab3652ab48bc0c98a3',
        },
      ],
      lastScanId: s.id,
      version: 1,
    });
    expect(app.allowedActions).toEqual(expect.arrayContaining(['discover', 'adopt', 'read_files']));
    expect(app.allowedActions).not.toContain('create_revision');

    expect((await own(app.id, 'adopted')).status).toBe(200);
    const s2 = await scan();
    const f2 = await findingFor(s2.id, SECURE_FILE, '443 ssl http2');
    expect(f2.fingerprint).toBe(f.fingerprint);
    expect(f2.applicationId).toBe(app.id); // linked automatically on ingest
    const again = await importOne(s2.id, f2.id, { mode: 'discovered' });
    expect(again.id).toBe(app.id);
    expect(again.ownershipMode).toBe('adopted');
    expect(again.lastScanId).toBe(s2.id);
    // port-80 block of the same domain gets its own, non-colliding name
    const other = await importOne(s2.id, (await findingFor(s2.id, SECURE_FILE, '80')).id, {
      mode: 'discovered',
    });
    expect(other).toMatchObject({
      name: 'secure-example-lab-2',
      ownershipMode: 'discovered',
      kind: 'unknown',
    });
    expect(await t.prisma.auditEvent.count({ where: { action: 'applications.import' } })).toBe(2);
    expect(await t.prisma.auditEvent.count({ where: { action: 'applications.reimport' } })).toBe(1);
    const list = await t.http
      .get(`/api/v1/applications?ownership_mode=adopted&environment=development`)
      .set(bearer(viewer));
    expect(list.body.paginate.total).toBe(1);
  });

  it('ownership rules: one step, permissions, manual review ack, unsupported blocks managed, history', async () => {
    const s = await scan();
    const dup = await importOne(s.id, (await findingFor(s.id, DUP_A_FILE)).id);
    expect(dup.flags).toMatchObject({ conflict: true, manualReview: true, unsupported: false });

    const skip = await own(dup.id, 'managed');
    expect(skip.status).toBe(422);
    expect(skip.body.error.code).toBe('OWNERSHIP_STEP_INVALID');
    expect((await own(dup.id, 'adopted', { token: viewer })).status).toBe(403);
    const devUser = await login(t, 'dev'); // deployer: no servers.operate / nginx.write
    expect((await own(dup.id, 'observed', { token: devUser })).status).toBe(403);

    const noAck = await own(dup.id, 'adopted');
    expect(noAck.status).toBe(422);
    expect(noAck.body.error.code).toBe('MANUAL_REVIEW_REQUIRED');
    expect(noAck.body.error.details.reasons).toEqual([
      'duplicate server_name dup.example.lab on port 80',
    ]);
    const stale = await t.http
      .post(`/api/v1/applications/${dup.id}/ownership`)
      .set(bearer(owner))
      .set('If-Match', '99')
      .send({ toMode: 'adopted', reason: 'stale version', acknowledgeReasons: true });
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe('VERSION_CONFLICT');
    const ok = await own(dup.id, 'adopted', { ack: true });
    expect(ok.status).toBe(200);
    expect(ok.body.data.ownershipMode).toBe('adopted');
    expect(ok.body.data.allowedActions).toEqual(
      expect.arrayContaining(['observe', 'manage', 'create_revision']),
    );
    const managed = await own(dup.id, 'managed');
    expect(managed.status).toBe(200); // conflict/manual-review was acknowledged at adopt; not unsupported

    const php = await importOne(s.id, (await findingFor(s.id, PHP_FILE)).id);
    expect(php).toMatchObject({
      kind: 'nginx_php',
      flags: { unsupported: true },
      unsupportedDirectives: ['set'],
    });
    expect((await own(php.id, 'adopted', { ack: true })).status).toBe(200);
    const blocked = await own(php.id, 'managed');
    expect(blocked.status).toBe(422);
    expect(blocked.body.error.code).toBe('UNSUPPORTED_CONFIG');
    expect(blocked.body.error.details.unsupportedDirectives).toEqual(['set']);
    const phpView = (await t.http.get(`/api/v1/applications/${php.id}`).set(bearer(owner))).body
      .data;
    expect(phpView.allowedActions).not.toContain('manage');

    const hist = await t.http
      .get(`/api/v1/applications/${dup.id}/ownership-history`)
      .set(bearer(viewer));
    expect(hist.status).toBe(200);
    expect(hist.body.data.map((h: any) => `${h.fromMode}>${h.toMode}`)).toEqual([
      'adopted>managed',
      'observed>adopted',
    ]);
    expect(hist.body.data[1].acknowledgedReasons).toEqual([
      'duplicate server_name dup.example.lab on port 80',
    ]);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'applications.ownership', result: 'success' },
      }),
    ).toBe(3);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'http.post', result: 'denied', targetId: { contains: 'ownership' } },
      }),
    ).toBeGreaterThanOrEqual(1);
    // ownership changes never touch the host: no job was created besides the scan
    expect(await t.prisma.job.count({ where: { type: { not: 'discovery.scan' } } })).toBe(0);
  });

  it('production adopt requires step-up (403 STEP_UP_REQUIRED); downgrade cancels open drafts', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    const s = await scan(prod);
    const app = await importOne(s.id, (await findingFor(s.id, SECURE_FILE, '443 ssl http2')).id);
    const no = await own(app.id, 'adopted');
    expect(no.status).toBe(403);
    expect(no.body.error.code).toBe('STEP_UP_REQUIRED');
    const su = await stepUpToken(t, owner);
    expect((await own(app.id, 'adopted', { stepUp: su })).status).toBe(200);
    expect((await own(app.id, 'managed', { stepUp: su })).status).toBe(200);
    const hist = (
      await t.http.get(`/api/v1/applications/${app.id}/ownership-history`).set(bearer(owner))
    ).body.data;
    expect(hist[0].stepUp).toBe(true);

    const r = await createRevision(
      prod,
      app.id,
      [{ path: SECURE_FILE, content: 'server { listen 443 ssl; }\n' }],
      {
        [SECURE_FILE]: 'server { listen 443; }\n',
      },
    );
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const down = await own(app.id, 'adopted'); // downgrade: no step-up needed
    expect(down.status).toBe(200);
    expect((await rev(r.body.data.id)).status).toBe('cancelled');
    expect(
      await t.prisma.auditEvent.findFirst({
        where: { action: 'applications.ownership', targetId: app.id, result: 'success' },
        orderBy: { createdAt: 'desc' },
      }),
    ).toMatchObject({ metadata: expect.objectContaining({ revisionsCancelled: 1 }) });
  });
});

// ================================================================== P3.05 revisions

describe('P3.05 Nginx revisions (P3-T03/T04/T05 Center side)', () => {
  it('path policy: outside app files / traversal / other app managed dir → 422; observed app → 409', async () => {
    const s = await scan();
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2');
    const send = (p: string) =>
      t.http
        .post(`/api/v1/applications/${app.id}/nginx/revisions`)
        .set(bearer(owner))
        .send({ files: [{ path: p, content: 'x' }] });
    for (const p of [
      '/etc/nginx/nginx.conf',
      '/etc/nginx/ppanel-managed/other-app/a.conf',
      DUP_A_FILE,
    ]) {
      const r = await send(p);
      expect(r.status, p).toBe(422);
      expect(r.body.error.code).toBe('PATH_NOT_ALLOWED');
    }
    for (const p of [
      '/etc/nginx/../shadow',
      '/etc/passwd',
      '/etc/nginx/ppanel-managed/secure-example-lab/../x/a.conf',
    ]) {
      const r = await send(p);
      expect(r.status, p).toBe(422);
      expect(r.body.error.code).toBe('VALIDATION_FAILED');
    }
    expect(await t.prisma.job.count({ where: { type: 'nginx.read_files' } })).toBe(0); // rejected before touching the host
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'nginx_revisions.create', result: 'denied' },
      }),
    ).toBe(3);
    const obs = await appAt(s.id, DUP_A_FILE, 'observed');
    const r = await t.http
      .post(`/api/v1/applications/${obs.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: DUP_A_FILE, content: 'x' }] });
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('OWNERSHIP_REQUIRED');
    const viewerTry = await t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(viewer))
      .send({ files: [{ path: SECURE_FILE, content: 'x' }] });
    expect(viewerTry.status).toBe(403);
    const direct = await t.http
      .post(`/api/v1/servers/${agent.serverId}/jobs`)
      .set(bearer(owner))
      .send({
        type: 'nginx.apply',
        params: {
          revisionId: app.id,
          files: [{ path: SECURE_FILE, expectedSha256Before: null, content: 'x' }],
        },
      });
    expect(direct.status).toBe(422);
    expect(direct.body.error.code).toBe('JOB_TYPE_RESTRICTED');
  });

  it('draft diff + planHash; validate valid/invalid mapping; apply carries expectedSha256Before; NGINX_TEST_FAILED → apply_failed', async () => {
    const s = await scan();
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2');
    const before = 'server {\n  listen 443 ssl;\n  root /var/www/secure;\n}\n';
    const after = 'server {\n  listen 443 ssl;\n  root /var/www/secure2;\n}\n';
    const newFile = '/etc/nginx/ppanel-managed/secure-example-lab/headers.conf';
    const r = await createRevision(
      agent,
      app.id,
      [
        { path: SECURE_FILE, content: after },
        { path: newFile, content: 'add_header X-A 1;\n' },
      ],
      { [SECURE_FILE]: before, [newFile]: null },
      { postchecks: [{ hostHeader: 'secure.example.lab', path: '/', scheme: 'https' }] },
    );
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const d = r.body.data;
    expect(d).toMatchObject({
      status: 'draft',
      serverId: agent.serverId,
      applicationId: app.id,
      approval: { required: false, approvedBy: null },
      createdBy: expect.any(String),
      validation: null,
      postchecks: [
        { hostHeader: 'secure.example.lab', path: '/', scheme: 'https', expectStatus: [200] },
      ],
    });
    expect(d.allowedActions).toEqual(['validate', 'cancel']);
    const main = d.files.find((f: any) => f.path === SECURE_FILE);
    expect(main).toMatchObject({ beforeSha256: sha(before), afterSha256: sha(after) });
    expect(main.diff).toContain(`--- a${SECURE_FILE}`);
    expect(main.diff).toContain('-  root /var/www/secure;');
    expect(main.diff).toContain('+  root /var/www/secure2;');
    const created = d.files.find((f: any) => f.path === newFile);
    expect(created).toMatchObject({ beforeSha256: null, afterSha256: sha('add_header X-A 1;\n') });
    expect(created.diff).toContain('--- /dev/null');
    expect(d.planHash).toBe(computePlanHash(agent.serverId, d.files, d.postchecks));

    const second = await t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: SECURE_FILE, content: 'y' }] });
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('REVISION_IN_PROGRESS');

    // validate → agent says invalid (succeeded job with valid:false)
    expect((await post(`/nginx-revisions/${d.id}/apply`)).body.error.code).toBe(
      'REVISION_STATE_INVALID',
    );
    const v = await post(`/nginx-revisions/${d.id}/validate`);
    expect(v.status).toBe(202);
    expect((await rev(d.id)).status).toBe('validating');
    const vg = await serve(agent, (g) => {
      expect(g.type).toBe('nginx.validate');
      expect(g.params.revisionId).toBe(d.id);
      expect(g.params.files).toEqual(
        expect.arrayContaining([
          { path: SECURE_FILE, expectedSha256Before: sha(before), content: after },
          { path: newFile, expectedSha256Before: null, content: 'add_header X-A 1;\n' },
        ]),
      );
      return {
        status: 'succeeded',
        output: {
          valid: false,
          nginxTestOutput: 'nginx: [emerg] unknown directive',
          filesChecked: [],
        },
      };
    });
    const job = await t.prisma.job.findUniqueOrThrow({ where: { id: vg.jobId } });
    expect(job.resourceKey).toBe(`nginx:${agent.serverId}`);
    const inv = await rev(d.id);
    expect(inv).toMatchObject({
      status: 'invalid',
      validation: {
        jobId: vg.jobId,
        valid: false,
        nginxTestOutput: 'nginx: [emerg] unknown directive',
      },
    });

    // invalid is terminal → a new revision may be created; this one validates OK → valid (no approval: managed + dev)
    const r2 = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: after }], {
      [SECURE_FILE]: before,
    });
    expect(r2.status).toBe(201);
    const ok = await validated(agent, r2.body.data.id);
    expect(ok).toMatchObject({
      status: 'valid',
      validation: { valid: true, nginxTestOutput: 'syntax is ok' },
      approval: { required: false },
    });
    expect(ok.allowedActions).toEqual(['apply', 'cancel']);
    const a = await post(`/nginx-revisions/${ok.id}/apply`);
    expect(a.status, JSON.stringify(a.body)).toBe(202);
    expect(a.body.data).toMatchObject({
      jobId: expect.any(String),
      revision: { status: 'applying', applyJobId: a.body.data.jobId },
    });
    await serve(agent, (g) => {
      expect(g.type).toBe('nginx.apply');
      expect(g.params).toMatchObject({
        revisionId: ok.id,
        files: [{ path: SECURE_FILE, expectedSha256Before: sha(before), content: after }],
        postchecks: [],
      });
      return {
        status: 'failed',
        error: {
          code: 'NGINX_TEST_FAILED',
          message: 'nginx -t failed',
          details: { nginxTestOutput: 'emerg' },
        },
      };
    });
    const failed = await rev(ok.id);
    expect(failed).toMatchObject({
      status: 'apply_failed',
      result: {
        errorCode: 'NGINX_TEST_FAILED',
        operation: 'apply',
        details: { nginxTestOutput: 'emerg' },
      },
    });
    // baseline unchanged after a failed apply
    const appAfter = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body
      .data;
    expect(appAfter.nginxFiles[0].lastKnownSha256).toBe(app.nginxFiles[0].lastKnownSha256);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'nginx_revisions.status', actorType: 'system' },
      }),
    ).toBe(3);
  });

  it('approval: required for adopted, approver ≠ creator, step-up, planHash bound, expiry, single-use; apply → applied; revert → reverted', async () => {
    const s = await scan();
    const app = await appAt(s.id, DUP_A_FILE, 'adopted');
    const before = 'server { listen 80; server_name dup.example.lab; root /var/www/dup-a; }\n';
    const after = 'server { listen 80; server_name dup.example.lab; root /var/www/dup-a2; }\n';
    const r = await createRevision(agent, app.id, [{ path: DUP_A_FILE, content: after }], {
      [DUP_A_FILE]: before,
    });
    expect(r.status).toBe(201);
    const id = r.body.data.id;
    expect(r.body.data.approval.required).toBe(true);
    const v = await validated(agent, id);
    expect(v.status).toBe('awaiting_approval');

    const early = await post(`/nginx-revisions/${id}/apply`);
    expect(early.status).toBe(409);
    expect(early.body.error.code).toBe('APPROVAL_REQUIRED');
    const ownerSu = await stepUpToken(t, owner);
    const self = await post(`/nginx-revisions/${id}/approve`, owner, ownerSu, {
      planHash: v.planHash,
    });
    expect(self.status).toBe(403);
    expect(self.body.error.code).toBe('APPROVER_IS_CREATOR');
    const noSu = await post(`/nginx-revisions/${id}/approve`, admin, undefined, {
      planHash: v.planHash,
    });
    expect(noSu.status).toBe(403);
    expect(noSu.body.error.code).toBe('STEP_UP_REQUIRED');
    const adminSu = await stepUpToken(t, admin);
    const wrong = await post(`/nginx-revisions/${id}/approve`, admin, adminSu, {
      planHash: 'f'.repeat(64),
    });
    expect(wrong.status).toBe(409);
    expect(wrong.body.error.code).toBe('PLAN_HASH_MISMATCH');
    expect(
      (await post(`/nginx-revisions/${id}/approve`, viewer, undefined, { planHash: v.planHash }))
        .status,
    ).toBe(403);
    const ap = await post(`/nginx-revisions/${id}/approve`, admin, adminSu, {
      planHash: v.planHash,
    });
    expect(ap.status, JSON.stringify(ap.body)).toBe(200);
    const adminId = (await t.http.get('/api/v1/auth/me').set(bearer(admin))).body.data.user.id;
    expect(ap.body.data).toMatchObject({
      status: 'approved',
      approval: { required: true, approvedBy: adminId, expiresAt: expect.any(String) },
    });
    const exp =
      new Date(ap.body.data.approval.expiresAt).getTime() -
      new Date(ap.body.data.approval.approvedAt).getTime();
    expect(exp).toBe(60 * 60_000);

    // expired approval is rejected
    await t.prisma.nginxRevisionApproval.updateMany({
      where: { revisionId: id },
      data: {
        expiresAt: new Date(Date.now() - 1000),
        approvedAt: new Date(Date.now() - 3_601_000),
      },
    });
    const expired = await post(`/nginx-revisions/${id}/apply`);
    expect(expired.status).toBe(409);
    expect(expired.body.error.code).toBe('APPROVAL_EXPIRED');
    expect(
      (await post(`/nginx-revisions/${id}/approve`, admin, adminSu, { planHash: v.planHash }))
        .status,
    ).toBe(200);

    // plan changes after approval (consistent new planHash) → approval no longer matches
    const row = await t.prisma.nginxConfigRevision.findUniqueOrThrow({ where: { id } });
    const files = structuredClone(row.files) as any[];
    files[0].content = 'tampered';
    files[0].afterSha256 = sha('tampered');
    const newHash = computePlanHash(agent.serverId, files, []);
    await t.prisma.nginxConfigRevision.update({
      where: { id },
      data: { files, planHash: newHash },
    });
    const changed = await post(`/nginx-revisions/${id}/apply`);
    expect(changed.status).toBe(409);
    expect(changed.body.error.code).toBe('PLAN_HASH_MISMATCH');
    // tampering files without updating planHash is caught as well
    await t.prisma.nginxConfigRevision.update({ where: { id }, data: { planHash: row.planHash } });
    expect((await post(`/nginx-revisions/${id}/apply`)).body.error.code).toBe('PLAN_HASH_MISMATCH');
    await t.prisma.nginxConfigRevision.update({
      where: { id },
      data: { files: row.files as any, planHash: row.planHash },
    });

    const a = await post(`/nginx-revisions/${id}/apply`);
    expect(a.status, JSON.stringify(a.body)).toBe(202);
    const approvals = await t.prisma.nginxRevisionApproval.findMany({
      where: { revisionId: id },
      orderBy: { approvedAt: 'asc' },
    });
    expect(approvals).toHaveLength(2);
    expect(approvals[0]!.invalidatedAt).not.toBeNull(); // superseded by re-approval
    expect(approvals[1]).toMatchObject({
      usedByJobId: a.body.data.jobId,
      usedAt: expect.any(Date),
    }); // single-use
    await serve(agent, (g) => {
      expect(g.params.files[0]).toEqual({
        path: DUP_A_FILE,
        expectedSha256Before: sha(before),
        content: after,
      });
      return {
        status: 'succeeded',
        output: {
          applied: true,
          files: [{ path: DUP_A_FILE, sha256Before: sha(before), sha256After: sha(after) }],
          nginxTestOutput: 'ok',
          reloadMethod: 'systemctl',
          postchecks: [],
          backupId: id,
        },
      };
    });
    const applied = await rev(id);
    expect(applied).toMatchObject({
      status: 'applied',
      result: { applied: true, reloadMethod: 'systemctl' },
    });
    expect(applied.allowedActions).toEqual(['revert']);
    let appNow = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
    expect(appNow.nginxFiles).toEqual([{ path: DUP_A_FILE, lastKnownSha256: sha(after) }]);

    const rv = await post(`/nginx-revisions/${id}/revert`);
    expect(rv.status).toBe(202);
    await serve(agent, (g) => {
      expect(g.type).toBe('nginx.revert');
      expect(g.params).toEqual({
        revisionId: id,
        expectedCurrent: [{ path: DUP_A_FILE, sha256: sha(after) }],
      });
      return {
        status: 'succeeded',
        output: {
          reverted: true,
          files: [{ path: DUP_A_FILE, sha256Before: sha(after), sha256After: sha(before) }],
          nginxTestOutput: 'syntax is ok',
          reloadMethod: 'nginx -s reload',
          postchecks: [],
          backupId: id,
        },
      };
    });
    expect((await rev(id)).status).toBe('reverted');
    appNow = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
    expect(appNow.nginxFiles).toEqual([{ path: DUP_A_FILE, lastKnownSha256: sha(before) }]);
    for (const action of [
      'nginx_revisions.create',
      'nginx_revisions.validate',
      'nginx_revisions.approve',
      'nginx_revisions.apply',
      'nginx_revisions.revert',
    ])
      expect(
        await t.prisma.auditEvent.count({ where: { action, result: 'success', targetId: id } }),
        action,
      ).toBeGreaterThanOrEqual(1);
  });

  it('production: apply needs approval and step-up', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    const s = await scan(prod);
    const ownerSu = await stepUpToken(t, owner);
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2', ownerSu);
    const r = await createRevision(prod, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const id = r.body.data.id;
    expect(r.body.data.approval.required).toBe(true); // production, even when managed
    expect((await validated(prod, id)).status).toBe('awaiting_approval');
    expect((await post(`/nginx-revisions/${id}/apply`, owner, ownerSu)).body.error.code).toBe(
      'APPROVAL_REQUIRED',
    );
    const adminSu = await stepUpToken(t, admin);
    expect(
      (
        await post(`/nginx-revisions/${id}/approve`, admin, adminSu, {
          planHash: r.body.data.planHash,
        })
      ).status,
    ).toBe(200);
    const noSu = await post(`/nginx-revisions/${id}/apply`);
    expect(noSu.status).toBe(403);
    expect(noSu.body.error.code).toBe('STEP_UP_REQUIRED');
    expect((await post(`/nginx-revisions/${id}/apply`, owner, ownerSu)).status).toBe(202);
    await serve(prod, () => ({
      status: 'failed',
      error: { code: 'POSTCHECK_FAILED_REVERTED', details: { postchecks: [] } },
    }));
    expect(await rev(id)).toMatchObject({
      status: 'apply_failed',
      result: { errorCode: 'POSTCHECK_FAILED_REVERTED' },
    });
  });

  it('F-6: concurrent approvals of the same plan → exactly one 200 + one 409 APPROVAL_ALREADY_EXISTS, one approval row; re-approving an unexpired approval → 409', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    const s = await scan(prod);
    const ownerSu = await stepUpToken(t, owner);
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2', ownerSu);
    const r = await createRevision(prod, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const id = r.body.data.id;
    expect((await validated(prod, id)).status).toBe('awaiting_approval');
    const adminSu = await stepUpToken(t, admin);
    const body = { planHash: r.body.data.planHash };
    const res = await Promise.all(
      Array.from({ length: 4 }, () => post(`/nginx-revisions/${id}/approve`, admin, adminSu, body)),
    );
    expect(res.map((x) => x.status).sort()).toEqual([200, 409, 409, 409]);
    for (const x of res.filter((y) => y.status === 409))
      expect(x.body.error.code).toBe('APPROVAL_ALREADY_EXISTS');
    expect(await t.prisma.nginxRevisionApproval.count({ where: { revisionId: id } })).toBe(1);
    const again = await post(`/nginx-revisions/${id}/approve`, admin, adminSu, body);
    expect([again.status, again.body.error.code]).toEqual([409, 'APPROVAL_ALREADY_EXISTS']);
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'nginx_revisions.approve', result: 'success', targetId: id },
      }),
    ).toBe(1);
    // apply consumes the single approval
    expect((await post(`/nginx-revisions/${id}/apply`, owner, ownerSu)).status).toBe(202);
  });

  it('P7-T02 A: apply job TTL-expired before any agent saw it → revision back to awaiting_approval (needs a fresh approval), not apply_failed', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    const s = await scan(prod);
    const ownerSu = await stepUpToken(t, owner);
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2', ownerSu);
    const r = await createRevision(prod, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const id = r.body.data.id;
    expect((await validated(prod, id)).status).toBe('awaiting_approval');
    const adminSu = await stepUpToken(t, admin);
    const body = { planHash: r.body.data.planHash };
    expect((await post(`/nginx-revisions/${id}/approve`, admin, adminSu, body)).status).toBe(200);
    const a = await post(`/nginx-revisions/${id}/apply`, owner, ownerSu);
    expect(a.status).toBe(202);
    await t.prisma.job.update({
      where: { id: a.body.data.jobId },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await t.app.get(SweeperService).tick();
    expect(await rev(id)).toMatchObject({
      status: 'awaiting_approval',
      result: { errorCode: 'TTL_EXPIRED', operation: 'apply' },
    });
    // the consumed approval is not reusable: approve again, then apply works
    expect((await post(`/nginx-revisions/${id}/apply`, owner, ownerSu)).body.error.code).toBe(
      'APPROVAL_REQUIRED',
    );
    expect((await post(`/nginx-revisions/${id}/approve`, admin, adminSu, body)).status).toBe(200);
    expect((await post(`/nginx-revisions/${id}/apply`, owner, ownerSu)).status).toBe(202);
  });

  it('P7-T02 A: non-approval revision whose apply never ran → valid again', async () => {
    const s = await scan();
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2');
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: 'x\n' }], {
      [SECURE_FILE]: 'server {\n  listen 443 ssl;\n  root /var/www/secure;\n}\n',
    });
    const id = r.body.data.id;
    const v = await validated(agent, id);
    expect(v.status).toBe('valid');
    const a = await post(`/nginx-revisions/${id}/apply`);
    expect(a.status, JSON.stringify(a.body)).toBe(202);
    await t.prisma.job.update({
      where: { id: a.body.data.jobId },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await t.app.get(SweeperService).tick();
    expect(await rev(id)).toMatchObject({ status: 'valid', result: { errorCode: 'TTL_EXPIRED' } });
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
  });

  it('agent DRIFT_DETECTED → drift_blocked + app flagged; 409 until acknowledge', async () => {
    const s = await scan();
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2');
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const id = (await validated(agent, r.body.data.id)).id;
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'failed',
      error: {
        code: 'DRIFT_DETECTED',
        details: { files: [{ path: SECURE_FILE, expected: sha('a\n'), actual: 'c'.repeat(64) }] },
      },
    }));
    expect(await rev(id)).toMatchObject({
      status: 'drift_blocked',
      result: { errorCode: 'DRIFT_DETECTED' },
    });
    const flagged = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body
      .data;
    expect(flagged.flags.driftDetected).toBe(true);
    expect(flagged.driftFiles).toMatchObject([
      { path: SECURE_FILE, lastKnownSha256: sha('a\n'), currentSha256: 'c'.repeat(64) },
    ]);
    expect(flagged.allowedActions).toContain('acknowledge_drift');
    expect(flagged.allowedActions).not.toContain('create_revision');
    const blocked = await t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: SECURE_FILE, content: 'x' }] });
    expect(blocked.status).toBe(409);
    expect(blocked.body.error.code).toBe('DRIFT_REVIEW_REQUIRED');
    expect((await post(`/applications/${app.id}/drift/acknowledge`, viewer)).status).toBe(403);
    const ack = await post(`/applications/${app.id}/drift/acknowledge`);
    expect(ack.status).toBe(200);
    expect(ack.body.data).toMatchObject({
      flags: { driftDetected: false },
      driftFiles: [],
      nginxFiles: [{ path: SECURE_FILE, lastKnownSha256: 'c'.repeat(64) }],
    });
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'applications.drift_acknowledge', result: 'success' },
      }),
    ).toBe(1);
  });

  it('scan drift: external change flags app + blocks drafts until acknowledge; pPanel-applied change is not flagged', async () => {
    const s1 = await scan();
    const app = await appAt(s1.id, SECURE_FILE, 'managed', '443 ssl http2');
    const draft = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    expect(draft.status).toBe(201);

    // someone edits the file outside pPanel
    const s2 = await scan(agent, fixtureWith({ [SECURE_FILE]: 'e'.repeat(64) }));
    expect(s2.drift).toEqual([
      {
        path: SECURE_FILE,
        previousSha256: 'f6538e4c5b1767f5658c5b978379bbd12455767259153aab3652ab48bc0c98a3',
        currentSha256: 'e'.repeat(64),
        changedBy: 'external',
        revisionId: null,
      },
    ]);
    expect((await rev(draft.body.data.id)).status).toBe('drift_blocked');
    const flagged = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body
      .data;
    expect(flagged.flags.driftDetected).toBe(true);
    const c = await t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: SECURE_FILE, content: 'x' }] });
    expect(c.status).toBe(409);
    expect(c.body.error.code).toBe('DRIFT_REVIEW_REQUIRED');
    expect((await own(app.id, 'adopted')).status).toBe(200); // downgrade still allowed
    expect((await own(app.id, 'managed')).body.error.code).toBe('DRIFT_REVIEW_REQUIRED');
    const ack = await post(`/applications/${app.id}/drift/acknowledge`);
    expect(ack.body.data.nginxFiles[0].lastKnownSha256).toBe('e'.repeat(64));
    expect((await own(app.id, 'managed')).status).toBe(200);

    // pPanel applies a revision → next scan sees the new checksum but does not flag it
    const after = 'server { listen 443 ssl; root /srv/new; }\n';
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: after }], {
      [SECURE_FILE]: 'current\n',
    });
    const id = (await validated(agent, r.body.data.id)).id;
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'succeeded',
      output: {
        applied: true,
        files: [{ path: SECURE_FILE, sha256Before: sha('current\n'), sha256After: sha(after) }],
      },
    }));
    expect((await rev(id)).status).toBe('applied');
    const s3 = await scan(agent, fixtureWith({ [SECURE_FILE]: sha(after) }));
    expect(s3.drift).toEqual([
      {
        path: SECURE_FILE,
        previousSha256: 'e'.repeat(64),
        currentSha256: sha(after),
        changedBy: 'ppanel_revision',
        revisionId: id,
      },
    ]);
    const clean = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
    expect(clean.flags.driftDetected).toBe(false);
    expect(clean.lastScanId).toBe(s3.id);
    expect(
      await t.prisma.auditEvent.count({ where: { action: 'applications.drift_detected' } }),
    ).toBe(1);
  });

  it('cancel + nginx files read endpoint (200 with content)', async () => {
    const s = await scan();
    const app = await appAt(s.id, SECURE_FILE, 'managed', '443 ssl http2');
    const pending = t.http
      .get(`/api/v1/applications/${app.id}/nginx/files`)
      .set(bearer(viewer))
      .then((x) => x);
    await serve(agent, readReply({ [SECURE_FILE]: 'hello\n' }));
    const files = await pending;
    expect(files.status).toBe(200);
    expect(files.body.data).toMatchObject({
      status: 'succeeded',
      files: [
        {
          path: SECURE_FILE,
          sha256: sha('hello\n'),
          content: 'hello\n',
          exists: true,
          // regression (lab E2E 2026-11-23): UI needs the real path to edit symlinked sites
          isSymlink: false,
          resolvedPath: SECURE_FILE,
          truncated: false,
        },
      ],
    });
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const c = await post(`/nginx-revisions/${r.body.data.id}/cancel`);
    expect(c.status).toBe(200);
    expect(c.body.data.status).toBe('cancelled');
    expect((await post(`/nginx-revisions/${r.body.data.id}/cancel`)).body.error.code).toBe(
      'REVISION_STATE_INVALID',
    );
    const list = await t.http
      .get(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(viewer));
    expect(list.body.paginate.total).toBe(1);
    expect(await t.prisma.auditEvent.count({ where: { action: 'nginx_revisions.cancel' } })).toBe(
      1,
    );
  });

  it('symlinked sites-enabled file: edit is redirected to the resolved real path; scan does not flag pPanel change', async () => {
    const s1 = await scan();
    const app = await appAt(s1.id, DUP_A_FILE, 'managed');
    const real = '/etc/nginx/sites-available/05-duplicate-a.conf';
    const symReply =
      (content: string) =>
      (g: Grant): Reply => ({
        status: 'succeeded',
        output: {
          files: (g.params.paths as string[]).map((p) =>
            p === DUP_A_FILE
              ? {
                  path: p,
                  exists: true,
                  sha256: sha(content),
                  sizeBytes: content.length,
                  content,
                  isSymlink: true,
                  resolvedPath: real,
                }
              : {
                  path: p,
                  exists: true,
                  sha256: sha(content),
                  sizeBytes: content.length,
                  content,
                  isSymlink: false,
                  resolvedPath: p,
                },
          ),
        },
      });
    const pending = t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: DUP_A_FILE, content: 'new\n' }] })
      .then((x) => x);
    await serve(agent, symReply('old\n'));
    const r1 = await pending;
    expect(r1.status).toBe(422);
    expect(r1.body.error).toMatchObject({
      code: 'PATH_NOT_ALLOWED',
      details: { files: [{ path: DUP_A_FILE, resolvedPath: real, reason: 'symlink' }] },
    });
    const learned = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body
      .data;
    expect(learned.nginxFiles).toEqual([
      { path: DUP_A_FILE, lastKnownSha256: app.nginxFiles[0].lastKnownSha256, resolvedPath: real },
    ]);
    const p2 = t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: real, content: 'new\n' }] })
      .then((x) => x);
    await serve(agent, symReply('old\n'));
    const r2 = await p2;
    expect(r2.status, JSON.stringify(r2.body)).toBe(201);
    const id = (await validated(agent, r2.body.data.id)).id;
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, (g) => {
      expect(g.params.files[0].path).toBe(real);
      return {
        status: 'succeeded',
        output: {
          applied: true,
          files: [{ path: real, sha256Before: sha('old\n'), sha256After: sha('new\n') }],
          nginxTestOutput: 'ok',
          reloadMethod: 'systemctl',
          postchecks: [],
          backupId: id,
        },
      };
    });
    const after = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
    expect(after.nginxFiles).toEqual([
      { path: DUP_A_FILE, lastKnownSha256: sha('new\n'), resolvedPath: real },
    ]);
    const s2 = await scan(agent, fixtureWith({ [DUP_A_FILE]: sha('new\n') }));
    expect(s2.drift).toEqual([
      expect.objectContaining({ path: DUP_A_FILE, changedBy: 'ppanel_revision', revisionId: id }),
    ]);
    expect(
      (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data.flags
        .driftDetected,
    ).toBe(false);
  });

  it('REVERT_FAILED_MANUAL_RECOVERY → requires_manual_recovery; writes blocked until rescan + acknowledge', async () => {
    const s1 = await scan();
    const app = await appAt(s1.id, SECURE_FILE, 'managed', '443 ssl http2');
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const id = (await validated(agent, r.body.data.id)).id;
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'failed',
      error: {
        code: 'REVERT_FAILED_MANUAL_RECOVERY',
        message: 'restore failed',
        details: {
          backupDir: '/var/lib/ppanel/nginx-backups/x',
          problems: [{ path: SECURE_FILE, error: 'EIO' }],
        },
      },
    }));
    const v = await rev(id);
    expect(v).toMatchObject({
      status: 'requires_manual_recovery',
      result: {
        errorCode: 'REVERT_FAILED_MANUAL_RECOVERY',
        details: { backupDir: expect.any(String) },
      },
    });
    expect(v.allowedActions).toEqual([]);
    const a = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
    expect(a.flags.driftDetected).toBe(true);
    expect(a.driftFiles).toMatchObject([{ path: SECURE_FILE, currentSha256: 'unknown' }]);
    const blocked = await t.http
      .post(`/api/v1/applications/${app.id}/nginx/revisions`)
      .set(bearer(owner))
      .send({ files: [{ path: SECURE_FILE, content: 'x' }] });
    expect(blocked.body.error.code).toBe('DRIFT_REVIEW_REQUIRED');
    const early = await post(`/applications/${app.id}/drift/acknowledge`);
    expect(early.status).toBe(409);
    expect(early.body.error.details).toMatchObject({ rescanRequired: true, paths: [SECURE_FILE] });
    await scan(agent, fixtureWith({ [SECURE_FILE]: '9'.repeat(64) }));
    const ack = await post(`/applications/${app.id}/drift/acknowledge`);
    expect(ack.status, JSON.stringify(ack.body)).toBe(200);
    expect(ack.body.data.nginxFiles[0].lastKnownSha256).toBe('9'.repeat(64));
    expect(
      await t.prisma.auditEvent.count({
        where: { action: 'nginx_revisions.status', targetId: id, result: 'failure' },
      }),
    ).toBe(1);
  });

  it('F-4: REVERT_FAILED_MANUAL_RECOVERY with details.restored → drift flag carries the verified restored checksums', async () => {
    const s1 = await scan();
    const app = await appAt(s1.id, SECURE_FILE, 'managed', '443 ssl http2');
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: 'b\n' }], {
      [SECURE_FILE]: 'a\n',
    });
    const id = (await validated(agent, r.body.data.id)).id;
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'failed',
      error: {
        code: 'REVERT_FAILED_MANUAL_RECOVERY',
        message: 'files restored and verified, reload failed',
        details: {
          restored: true,
          restoredFiles: [{ path: SECURE_FILE, sha256: sha('a\n') }],
          revertNginxTestOk: false,
        },
      },
    }));
    expect((await rev(id)).status).toBe('requires_manual_recovery');
    const a = (await t.http.get(`/api/v1/applications/${app.id}`).set(bearer(owner))).body.data;
    expect(a.flags.driftDetected).toBe(true);
    expect(a.driftFiles).toMatchObject([{ path: SECURE_FILE, currentSha256: sha('a\n') }]);
  });

  it('AGENT_INTERRUPTED (agent crashed mid-job, rolled back from its journal on restart): apply → not applied (valid again), revert → still applied', async () => {
    const s1 = await scan();
    const app = await appAt(s1.id, SECURE_FILE, 'managed', '443 ssl http2');
    const before = 'a\n';
    const after = 'b\n';
    const r = await createRevision(agent, app.id, [{ path: SECURE_FILE, content: after }], {
      [SECURE_FILE]: before,
    });
    const id = (await validated(agent, r.body.data.id)).id;
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'failed',
      error: { code: 'AGENT_INTERRUPTED', message: 'the agent stopped while this job was running' },
    }));
    expect(await rev(id)).toMatchObject({
      status: 'valid',
      result: { errorCode: 'AGENT_INTERRUPTED', operation: 'apply' },
    });
    // apply again → applied; revert interrupted → still applied (revert can be retried)
    expect((await post(`/nginx-revisions/${id}/apply`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'succeeded',
      output: {
        applied: true,
        files: [{ path: SECURE_FILE, sha256Before: sha(before), sha256After: sha(after) }],
        nginxTestOutput: 'ok',
        reloadMethod: 'nginx -s reload',
        postchecks: [],
        backupId: id,
      },
    }));
    expect((await rev(id)).status).toBe('applied');
    expect((await post(`/nginx-revisions/${id}/revert`)).status).toBe(202);
    await serve(agent, () => ({
      status: 'failed',
      error: { code: 'AGENT_INTERRUPTED', message: 'the agent stopped while this job was running' },
    }));
    expect(await rev(id)).toMatchObject({
      status: 'applied',
      result: { errorCode: 'AGENT_INTERRUPTED', operation: 'revert' },
    });
    expect((await rev(id)).allowedActions).toContain('revert');
  });
});
