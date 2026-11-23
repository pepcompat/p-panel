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

let t: TestApp;
let port: number;
let owner: string;
let agent: EnrolledAgent;

beforeAll(async () => {
  t = await bootApp();
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
  agent = await enrollAgent(t, owner);
  await t.http
    .patch(`/api/v1/servers/${agent.serverId}`)
    .set(bearer(owner))
    .send({ ownedUnits: ['nginx.service', 'php8.3-fpm.service'] });
});

const poll = (waitSec = 0) =>
  agentCall(port, agent.creds, 'GET', `/agent/v1/tasks?waitSec=${waitSec}`);
const createJob = (body: Record<string, unknown>, key?: string, token = owner) => {
  const req = t.http.post(`/api/v1/servers/${agent.serverId}/jobs`).set(bearer(token));
  if (key) req.set('Idempotency-Key', key);
  return req.send(body);
};

describe('job creation (P2.01)', () => {
  it('P2-T01: same Idempotency-Key → one job (202 then 200), different payload → 409', async () => {
    const a = await createJob(
      { type: 'discovery.scan', params: { sources: ['nginx', 'docker'] } },
      'idem-key-0001',
    );
    expect(a.status).toBe(202);
    expect(a.body.data).toMatchObject({ jobId: expect.any(String), status: 'queued' });
    expect(a.body.data.job).toMatchObject({
      type: 'discovery.scan',
      idempotencyKey: 'idem-key-0001',
      attempt: 0,
      status: 'queued',
    });
    const b = await createJob(
      { type: 'discovery.scan', params: { sources: ['nginx', 'docker'] } },
      'idem-key-0001',
    );
    expect(b.status).toBe(200);
    expect(b.body.data.jobId).toBe(a.body.data.jobId);
    const parallel = await Promise.all(
      Array.from({ length: 5 }, () =>
        createJob({ type: 'inventory.collect', params: {} }, 'idem-key-0002'),
      ),
    );
    expect(new Set(parallel.map((p) => p.body.data.jobId)).size).toBe(1);
    expect(parallel.filter((p) => p.status === 202)).toHaveLength(1);
    expect(await t.prisma.job.count()).toBe(2);
    const conflict = await createJob({ type: 'inventory.collect', params: {} }, 'idem-key-0001');
    expect(conflict.status).toBe(409);
    // only one grant per job even with repeated polls
    const g = await poll();
    expect(g.body.data.tasks).toHaveLength(2);
    expect((await poll()).body.data.tasks).toHaveLength(0);
  });

  it('validates type allowlist and params with Zod; enforces owned-unit allowlist', async () => {
    const unknown = await createJob({ type: 'shell.exec', params: { cmd: 'rm -rf /' } });
    expect(unknown.status).toBe(422);
    expect(unknown.body.error.code).toBe('JOB_TYPE_UNKNOWN');
    const badParams = await createJob({
      type: 'discovery.scan',
      params: { sources: ['etc-passwd'] },
    });
    expect(badParams.status).toBe(422);
    expect(badParams.body.error.code).toBe('VALIDATION_FAILED');
    const extra = await createJob({ type: 'inventory.collect', params: { x: 1 } });
    expect(extra.status).toBe(422);
    const inject = await createJob({
      type: 'service.restart',
      params: { unit: 'nginx.service; reboot' },
    });
    expect(inject.status).toBe(422);
    const notOwned = await createJob({ type: 'service.restart', params: { unit: 'sshd.service' } });
    expect(notOwned.status).toBe(422);
    expect(notOwned.body.error.code).toBe('RESOURCE_NOT_OWNED');
    const ok = await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    expect(ok.status).toBe(202);
    const badKey = await createJob({ type: 'inventory.collect' }, 'short');
    expect(badKey.status).toBe(400);
    expect(
      await t.prisma.auditEvent.count({ where: { action: 'jobs.create', result: 'success' } }),
    ).toBe(1);
  });

  it('mutating job on a production server requires step-up', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    await t.http
      .patch(`/api/v1/servers/${prod.serverId}`)
      .set(bearer(owner))
      .send({ ownedUnits: ['nginx.service'] });
    const r = await t.http
      .post(`/api/v1/servers/${prod.serverId}/jobs`)
      .set(bearer(owner))
      .send({ type: 'service.restart', params: { unit: 'nginx.service' } });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    const ro = await t.http
      .post(`/api/v1/servers/${prod.serverId}/jobs`)
      .set(bearer(owner))
      .send({ type: 'inventory.collect' });
    expect(ro.status).toBe(202);
  });
});

describe('agent task lifecycle (long-poll, ack, result)', () => {
  it('lease → ack → result succeeded; result is idempotent; wrong token rejected', async () => {
    const c = await createJob({ type: 'inventory.collect', params: {} }, 'life-0001');
    const g = await poll();
    expect(g.status).toBe(200);
    const [grant] = g.body.data.tasks;
    expect(grant).toMatchObject({
      jobId: c.body.data.jobId,
      type: 'inventory.collect',
      params: {},
      idempotencyKey: 'life-0001',
      serverId: agent.serverId,
      leaseToken: expect.any(String),
      issuedAt: expect.any(String),
      expiresAt: expect.any(String),
    });
    const row = await t.prisma.job.findUniqueOrThrow({ where: { id: grant.jobId } });
    expect(row.status).toBe('leased');
    expect(row.leaseTokenHash).not.toBe(grant.leaseToken); // only the hash is stored
    expect(row.attempt).toBe(1);

    const wrong = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${grant.jobId}/ack`, {
      leaseToken: 'x'.repeat(43),
    });
    expect(wrong.status).toBe(409);
    expect(wrong.body.error.code).toBe('TASK_NOT_LEASED');
    const ack = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${grant.jobId}/ack`, {
      leaseToken: grant.leaseToken,
    });
    expect(ack.status).toBe(200);
    expect(ack.body.data).toEqual({ status: 'running' });
    const ack2 = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${grant.jobId}/ack`, {
      leaseToken: grant.leaseToken,
    });
    expect(ack2.status).toBe(200);

    // heartbeat renews the running lease
    const before = (await t.prisma.job.findUniqueOrThrow({ where: { id: grant.jobId } }))
      .leaseUntil!;
    await new Promise((r) => setTimeout(r, 20));
    await agentCall(
      port,
      agent.creds,
      'POST',
      '/agent/v1/heartbeat',
      heartbeatBody(1, { runningJobIds: [grant.jobId] }),
    );
    expect(
      (await t.prisma.job.findUniqueOrThrow({ where: { id: grant.jobId } })).leaseUntil!.getTime(),
    ).toBeGreaterThan(before.getTime());

    const res = await agentCall(
      port,
      agent.creds,
      'POST',
      `/agent/v1/tasks/${grant.jobId}/result`,
      {
        leaseToken: grant.leaseToken,
        status: 'succeeded',
        output: { packages: 3 },
      },
    );
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ accepted: true });
    const again = await agentCall(
      port,
      agent.creds,
      'POST',
      `/agent/v1/tasks/${grant.jobId}/result`,
      { leaseToken: grant.leaseToken, status: 'succeeded', output: {} },
    );
    expect(again.status).toBe(200);
    const job = await t.http
      .get(`/api/v1/servers/${agent.serverId}/jobs/${grant.jobId}`)
      .set(bearer(owner));
    expect(job.body.data).toMatchObject({ status: 'succeeded', result: { packages: 3 } });
    const list = await t.http
      .get(`/api/v1/servers/${agent.serverId}/jobs?status=succeeded`)
      .set(bearer(owner));
    expect(list.body.paginate.total).toBe(1);
  });

  it('long-poll wakes up when a job is created', async () => {
    const started = Date.now();
    const pending = poll(10);
    await new Promise((r) => setTimeout(r, 300));
    await createJob({ type: 'inventory.collect' });
    const g = await pending;
    expect(g.body.data.tasks).toHaveLength(1);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('long-poll returns an empty array on timeout', async () => {
    const g = await poll(1);
    expect(g.status).toBe(200);
    expect(g.body.data).toEqual({ tasks: [] });
  });

  it('concurrent pollers never receive the same job (FOR UPDATE SKIP LOCKED)', async () => {
    for (let i = 0; i < 8; i++) await createJob({ type: 'inventory.collect' });
    const grants = (
      await Promise.all(Array.from({ length: 6 }, () => t.jobs.lease(agent.serverId)))
    ).flat();
    expect(grants).toHaveLength(8);
    expect(new Set(grants.map((g) => g.jobId)).size).toBe(8);
  });

  it('per-server+resource lock: two restarts of the same unit never run concurrently', async () => {
    const a = await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    const b = await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    const other = await createJob({
      type: 'service.restart',
      params: { unit: 'php8.3-fpm.service' },
    });
    const first = (await poll()).body.data.tasks;
    expect(first.map((x: { jobId: string }) => x.jobId).sort()).toEqual(
      [a.body.data.jobId, other.body.data.jobId].sort(),
    );
    expect((await poll()).body.data.tasks).toHaveLength(0);
    const ga = first.find((x: { jobId: string }) => x.jobId === a.body.data.jobId);
    await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${ga.jobId}/result`, {
      leaseToken: ga.leaseToken,
      status: 'succeeded',
    });
    const second = (await poll()).body.data.tasks;
    expect(second.map((x: { jobId: string }) => x.jobId)).toEqual([b.body.data.jobId]);
  });

  it('agent rejection (REJECTED_EXPIRED) is recorded as failed', async () => {
    await createJob({ type: 'inventory.collect' });
    const [g] = (await poll()).body.data.tasks;
    const r = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      status: 'failed',
      error: { code: 'REJECTED_EXPIRED', message: 'grant expired' },
    });
    expect(r.status).toBe(200);
    const row = await t.prisma.job.findUniqueOrThrow({ where: { id: g.jobId } });
    expect(row.status).toBe('failed');
    expect(row.error).toEqual({ code: 'REJECTED_EXPIRED', message: 'grant expired' });
  });

  it('cancel a queued job; cancelled jobs are never leased', async () => {
    const c = await createJob({ type: 'inventory.collect' });
    const r = await t.http
      .post(`/api/v1/servers/${agent.serverId}/jobs/${c.body.data.jobId}/cancel`)
      .set(bearer(owner));
    expect(r.status).toBe(200);
    expect(r.body.data.status).toBe('cancelled');
    expect((await poll()).body.data.tasks).toHaveLength(0);
    const again = await t.http
      .post(`/api/v1/servers/${agent.serverId}/jobs/${c.body.data.jobId}/cancel`)
      .set(bearer(owner));
    expect(again.status).toBe(409);
  });
});

describe('P2-T02 expired mutating jobs are never re-delivered', () => {
  it('lease lapses while agent is disconnected → expired; reconnect gets nothing; late ack/result → 409 TASK_EXPIRED', async () => {
    const c = await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    const [grant] = (await poll()).body.data.tasks;
    expect(grant.jobId).toBe(c.body.data.jobId);
    // agent "disconnects"; lease runs out
    await t.prisma.job.update({
      where: { id: grant.jobId },
      data: { leaseUntil: new Date(Date.now() - 1000) },
    });
    // before the sweeper runs, a reconnecting agent still cannot get it (only `queued` rows are leasable)
    expect((await poll()).body.data.tasks).toHaveLength(0);
    const sweep = await t.jobs.sweep();
    expect(sweep.expiredMutating).toBe(1);
    const row = await t.prisma.job.findUniqueOrThrow({ where: { id: grant.jobId } });
    expect(row.status).toBe('expired');
    expect(row.error).toEqual({ code: 'LEASE_EXPIRED' });
    // reconnect → poll repeatedly → never re-leased
    for (let i = 0; i < 3; i++) expect((await poll()).body.data.tasks).toHaveLength(0);
    await t.jobs.sweep();
    expect((await t.prisma.job.findUniqueOrThrow({ where: { id: grant.jobId } })).status).toBe(
      'expired',
    );
    const ack = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${grant.jobId}/ack`, {
      leaseToken: grant.leaseToken,
    });
    expect(ack.status).toBe(409);
    expect(ack.body.error.code).toBe('TASK_EXPIRED');
    const res = await agentCall(
      port,
      agent.creds,
      'POST',
      `/agent/v1/tasks/${grant.jobId}/result`,
      { leaseToken: grant.leaseToken, status: 'succeeded' },
    );
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('TASK_EXPIRED');
  });

  it('ack after lease lapse (sweeper not yet run) → TASK_EXPIRED and job expired', async () => {
    await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    const [grant] = (await poll()).body.data.tasks;
    await t.prisma.job.update({
      where: { id: grant.jobId },
      data: { leaseUntil: new Date(Date.now() - 1) },
    });
    const ack = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${grant.jobId}/ack`, {
      leaseToken: grant.leaseToken,
    });
    expect(ack.status).toBe(409);
    expect(ack.body.error.code).toBe('TASK_EXPIRED');
    expect((await t.prisma.job.findUniqueOrThrow({ where: { id: grant.jobId } })).status).toBe(
      'expired',
    );
  });

  it('queued mutating job past its TTL is never leased (even before sweep) and sweeps to expired', async () => {
    const c = await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    await t.prisma.job.update({
      where: { id: c.body.data.jobId },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await poll()).body.data.tasks).toHaveLength(0);
    expect((await t.jobs.sweep()).expiredQueued).toBe(1);
    expect(
      (await t.prisma.job.findUniqueOrThrow({ where: { id: c.body.data.jobId } })).status,
    ).toBe('expired');
  });

  it('read-only job with lapsed lease IS re-leased (attempt 2) while TTL remains', async () => {
    const c = await createJob({ type: 'inventory.collect' });
    const [g1] = (await poll()).body.data.tasks;
    await t.prisma.job.update({
      where: { id: c.body.data.jobId },
      data: { leaseUntil: new Date(Date.now() - 1000) },
    });
    expect((await t.jobs.sweep()).requeued).toBe(1);
    const [g2] = (await poll()).body.data.tasks;
    expect(g2.jobId).toBe(g1.jobId);
    expect(g2.leaseToken).not.toBe(g1.leaseToken);
    expect((await t.prisma.job.findUniqueOrThrow({ where: { id: g1.jobId } })).attempt).toBe(2);
    // the stale lease token is useless now
    const stale = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g1.jobId}/ack`, {
      leaseToken: g1.leaseToken,
    });
    expect(stale.status).toBe(409);
  });

  it('revoking a server cancels its outstanding jobs', async () => {
    await createJob({ type: 'inventory.collect' });
    await createJob({ type: 'service.restart', params: { unit: 'nginx.service' } });
    await poll();
    await t.http.post(`/api/v1/servers/${agent.serverId}/revoke`).set(bearer(owner));
    const statuses = (await t.prisma.job.findMany()).map((j) => j.status);
    expect(statuses).toEqual(['cancelled', 'cancelled']);
  });
});

describe('P2-T03-lite durability across API restart', () => {
  it('queued/leased job state and lease survive a Center process restart; no duplicate delivery', async () => {
    const mutating = await createJob(
      { type: 'service.restart', params: { unit: 'nginx.service' } },
      'durable-0001',
    );
    const [grant] = (await poll()).body.data.tasks;
    const queued = await createJob({ type: 'inventory.collect' }, 'durable-0002');

    // simulate crash/restart: stop gateway + API, boot a brand-new instance on the same DB
    await t.gateway.stop();
    await t.close();
    t = await bootApp();
    port = await t.gateway.start(0, '127.0.0.1');

    const persisted = await t.prisma.job.findUniqueOrThrow({
      where: { id: mutating.body.data.jobId },
    });
    expect(persisted.status).toBe('leased');
    expect(persisted.attempt).toBe(1);
    // the new instance hands out only the queued read-only job, not the already-leased mutating one
    const tasks = (await poll()).body.data.tasks;
    expect(tasks.map((x: { jobId: string }) => x.jobId)).toEqual([queued.body.data.jobId]);
    // the lease issued by the old process is still honoured by the new one
    const ack = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${grant.jobId}/ack`, {
      leaseToken: grant.leaseToken,
    });
    expect(ack.status).toBe(200);
    // idempotent create after restart returns the same job
    const replay = await createJob(
      { type: 'service.restart', params: { unit: 'nginx.service' } },
      'durable-0001',
    );
    expect(replay.status).toBe(200);
    expect(replay.body.data.jobId).toBe(mutating.body.data.jobId);
    expect(await t.prisma.job.count()).toBe(2);
  });
});
