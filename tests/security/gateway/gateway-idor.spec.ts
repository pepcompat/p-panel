/**
 * P7.01 agent gateway (TB5): cross-agent job access through the real mTLS gateway, spoofed /
 * missing client certificates, revoked servers, log label spoofing.
 */
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  login,
  resetDb,
  spoofedAgentCert,
  type EnrolledAgent,
  type TestApp,
} from '../../../apps/api/test/integration/helpers';
import { entry, logBatch, postLogs } from '../../../apps/api/test/integration/p5-fixtures';

let t: TestApp;
let port: number;
let owner: string;
let a: EnrolledAgent;
let b: EnrolledAgent;

beforeAll(async () => {
  t = await bootApp({ PPANEL_GATEWAY_HOSTNAMES: 'localhost' });
  port = await t.gateway.start(0, '127.0.0.1');
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  a = await enrollAgent(t, owner, { name: 'gw-a' });
  b = await enrollAgent(t, owner, { name: 'gw-b' });
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
});

describe('cross-agent job access', () => {
  it("agent B can neither lease, ack, complete nor fetch secrets of agent A's job", async () => {
    const j = await t.http
      .post(`/api/v1/servers/${a.serverId}/jobs`)
      .set(bearer(owner))
      .send({ type: 'inventory.collect' });
    expect(j.status).toBe(202);
    // B polls first: must not see A's job
    const bPoll = await agentCall(port, b.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    expect(bPoll.body.data.tasks).toEqual([]);
    const [g] = (await agentCall(port, a.creds, 'GET', '/agent/v1/tasks?waitSec=0')).body.data
      .tasks;
    expect(g.jobId).toBeTruthy();
    for (const [method, path, body] of [
      ['POST', `/agent/v1/tasks/${g.jobId}/ack`, { leaseToken: g.leaseToken }],
      ['POST', `/agent/v1/tasks/${g.jobId}/secrets`, { leaseToken: g.leaseToken }],
      [
        'POST',
        `/agent/v1/tasks/${g.jobId}/result`,
        { leaseToken: g.leaseToken, status: 'succeeded', output: { pwned: true } },
      ],
    ] as const) {
      const r = await agentCall(port, b.creds, method, path, body);
      expect(r.status, path).toBe(409);
      expect(r.body.error.code).toBe('TASK_NOT_LEASED');
    }
    const row = await t.prisma.job.findUniqueOrThrow({ where: { id: g.jobId } });
    expect(row.status).toBe('leased');
    expect(row.result).toBeNull();
  });

  it('a wrong lease token from the right agent is refused too', async () => {
    const j = await t.http
      .post(`/api/v1/servers/${a.serverId}/jobs`)
      .set(bearer(owner))
      .set('Idempotency-Key', 'gw-idem-0002')
      .send({ type: 'inventory.collect' });
    expect(j.status).toBeLessThan(300);
    const tasks = (await agentCall(port, a.creds, 'GET', '/agent/v1/tasks?waitSec=0')).body.data
      .tasks;
    expect(tasks.length).toBeGreaterThan(0);
    for (const g of tasks) {
      const r = await agentCall(port, a.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
        leaseToken: 'x'.repeat(43),
      });
      expect(r.status).toBe(409);
    }
  });
});

describe('client identity', () => {
  it('no client cert / foreign-CA look-alike cert never reaches a handler', async () => {
    await expect(
      agentCall(port, { caPem: a.creds.caPem }, 'POST', '/agent/v1/heartbeat', {}),
    ).rejects.toThrow();
    const spoof = await spoofedAgentCert(a.serverId);
    await expect(
      agentCall(port, { ...spoof, caPem: a.creds.caPem }, 'GET', '/agent/v1/tasks?waitSec=0'),
    ).rejects.toThrow();
  });

  it("log batches cannot claim another server's identity via labels", async () => {
    const r = await postLogs(
      port,
      b.creds,
      logBatch([entry('spoofed', { serverId: a.serverId, server_id: a.serverId, app: 'x' })]),
    );
    expect(r.status).toBeLessThan(500);
    // everything B sends is attributed to B (the cert), never to A
    const telemetryA = await t.prisma.serverTelemetry.findUnique({
      where: { serverId: a.serverId },
    });
    expect(telemetryA?.acceptedTotal ?? 0n).toBe(0n);
  });

  it('a revoked server is cut off immediately', async () => {
    const rv = await t.http
      .post(`/api/v1/servers/${b.serverId}/revoke`)
      .set(bearer(owner))
      .send({ reason: 'security test' });
    expect(rv.status).toBeLessThan(300);
    const r = await agentCall(port, b.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    expect(r.status).toBe(401);
  });
});
