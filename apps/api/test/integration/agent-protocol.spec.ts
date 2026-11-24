/** Alignment with the finished Go agent (apps/agent) protocol behaviour. */
import { createPublicKey, X509Certificate } from 'node:crypto';
import https from 'node:https';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  type EnrolledAgent,
  heartbeatBody,
  login,
  newAgentKey,
  resetDb,
  type TestApp,
} from './helpers';

let t: TestApp;
let port: number;
let owner: string;
let agent: EnrolledAgent;

beforeAll(async () => {
  t = await bootApp({
    PPANEL_GATEWAY_HOSTNAMES: 'localhost,host.docker.internal',
    PPANEL_PUBLIC_GATEWAY_URL: 'https://host.docker.internal:4443',
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
  owner = await login(t, 'superadmin');
  agent = await enrollAgent(t, owner);
});

const createJob = (body: Record<string, unknown>) =>
  t.http.post(`/api/v1/servers/${agent.serverId}/jobs`).set(bearer(owner)).send(body);
const poll = () => agentCall(port, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');

describe('results without ack (rejections / cached replays)', () => {
  it.each([
    'REJECTED_EXPIRED',
    'REJECTED_UNKNOWN_TYPE',
    'REJECTED_WRONG_SERVER',
    'REJECTED_INVALID_PARAMS',
    'REJECTED_INVALID_GRANT',
    'REJECTED_NOT_OWNED',
    'HANDLER_FAILED',
    'HANDLER_TIMEOUT',
    'AGENT_INTERRUPTED',
    'AGENT_STATE_WRITE_FAILED',
  ])('leased (not acked) job + status rejected/%s → failed with that code', async (code) => {
    await createJob({ type: 'inventory.collect' });
    const [g] = (await poll()).body.data.tasks;
    const r = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      status: code.startsWith('REJECTED') ? 'rejected' : 'failed',
      output: null,
      error: { code, message: 'nope', details: { reason: 'test' } },
    });
    expect(r.status).toBe(200);
    expect(r.body.data).toEqual({ accepted: true });
    const row = await t.prisma.job.findUniqueOrThrow({ where: { id: g.jobId } });
    expect(row.status).toBe('failed');
    expect(row.startedAt).toBeNull(); // never acked
    expect(row.error).toEqual({ code, message: 'nope', details: { reason: 'test' } });
    // replay of the same result is idempotent
    const again = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      status: 'rejected',
      output: null,
      error: { code },
    });
    expect(again.status).toBe(200);
  });

  it('cached replay without ack: succeeded with truncated output marker', async () => {
    await createJob({ type: 'inventory.collect' });
    const [g] = (await poll()).body.data.tasks;
    const r = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      status: 'succeeded',
      output: { truncated: true, originalBytes: 20480 },
    });
    expect(r.status).toBe(200);
    const job = await t.http
      .get(`/api/v1/servers/${agent.serverId}/jobs/${g.jobId}`)
      .set(bearer(owner));
    expect(job.body.data).toMatchObject({
      status: 'succeeded',
      result: { truncated: true, originalBytes: 20480 },
    });
  });
});

describe('restarted agent reports AGENT_INTERRUPTED with the persisted lease token', () => {
  const leaseAndAck = async () => {
    await createJob({ type: 'inventory.collect' });
    const [g] = (await poll()).body.data.tasks;
    const ack = await agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/ack`, {
      leaseToken: g.leaseToken,
    });
    expect(ack.status).toBe(200);
    // mutating: never re-leased (the case that matters for interrupted jobs)
    await t.prisma.job.update({ where: { id: g.jobId }, data: { mutating: true } });
    return g as { jobId: string; leaseToken: string };
  };
  const interrupted = (g: { jobId: string; leaseToken: string }) =>
    // fresh TLS connection = a new agent process with the same identity and stored token
    agentCall(port, agent.creds, 'POST', `/agent/v1/tasks/${g.jobId}/result`, {
      leaseToken: g.leaseToken,
      status: 'failed',
      error: { code: 'AGENT_INTERRUPTED', message: 'the agent stopped while this job was running' },
    });

  it('running job, lease still valid → accepted as failed/AGENT_INTERRUPTED', async () => {
    const g = await leaseAndAck();
    const r = await interrupted(g);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(await t.prisma.job.findUniqueOrThrow({ where: { id: g.jobId } })).toMatchObject({
      status: 'failed',
      error: { code: 'AGENT_INTERRUPTED' },
    });
  });

  it('lease already lapsed (sweeper not run yet) → 409 TASK_EXPIRED, job expired LEASE_EXPIRED, nothing stored', async () => {
    const g = await leaseAndAck();
    await t.prisma.job.update({
      where: { id: g.jobId },
      data: { leaseUntil: new Date(Date.now() - 1000) },
    });
    const r = await interrupted(g);
    expect([r.status, r.body.error.code]).toEqual([409, 'TASK_EXPIRED']);
    const row = await t.prisma.job.findUniqueOrThrow({ where: { id: g.jobId } });
    expect(row).toMatchObject({ status: 'expired', error: { code: 'LEASE_EXPIRED' } });
    // and after the sweeper as well
    expect((await interrupted(g)).body.error.code).toBe('TASK_EXPIRED');
  });

  it('wrong lease token → 409 TASK_NOT_LEASED', async () => {
    const g = await leaseAndAck();
    const r = await interrupted({ ...g, leaseToken: 'x'.repeat(32) });
    expect([r.status, r.body.error.code]).toEqual([409, 'TASK_NOT_LEASED']);
  });
});

describe('heartbeat shape', () => {
  it('omitted metrics are stored/returned as null (never 0); addresses with source; serverTime present', async () => {
    const r = await agentCall(
      port,
      agent.creds,
      'POST',
      '/agent/v1/heartbeat',
      heartbeatBody(1, {
        metrics: { cpuPct: 5 },
        addresses: [
          {
            family: 'ipv4',
            scope: 'private',
            address: '10.0.0.5',
            interface: 'eth1',
            source: 'detected',
          },
        ],
        capabilities: ['docker', 'php-fpm'],
      }),
      { 'X-Request-ID': 'agent-req-0001', 'X-Client-Version': '0.1.0' },
    );
    expect(r.status).toBe(200);
    expect(r.body.meta.requestId).toBe('agent-req-0001');
    expect(Date.parse(r.body.data.serverTime)).not.toBeNaN();
    const s = (await t.http.get(`/api/v1/servers/${agent.serverId}`).set(bearer(owner))).body.data;
    expect(s.metrics).toMatchObject({
      cpuPct: 5,
      memPct: null,
      diskPct: null,
      load1: null,
      uptimeSec: null,
      stale: false,
    });
    expect(s.addresses).toEqual([
      expect.objectContaining({ address: '10.0.0.5', source: 'detected', scope: 'private' }),
    ]);
    expect(s.capabilities).toEqual(['docker', 'php-fpm']);
    const hb = await t.prisma.agentHeartbeat.findFirstOrThrow({
      where: { serverId: agent.serverId },
    });
    expect(hb.metrics).toMatchObject({ cpuPct: 5, memPct: null, diskPct: null });
  });

  it('heartbeat with no metrics object at all is accepted', async () => {
    const body = heartbeatBody(1) as Record<string, unknown>;
    delete body.metrics;
    expect((await agentCall(port, agent.creds, 'POST', '/agent/v1/heartbeat', body)).status).toBe(
      200,
    );
  });
});

describe('enrollment response', () => {
  it('accepts facts.os.name; cert chains to caPem, EKU clientAuth, matches CSR key; gatewayUrl https from config', async () => {
    const en = await t.http
      .post('/api/v1/enrollments')
      .set(bearer(owner))
      .send({ name: 'lab-a', environment: 'development' });
    expect(en.body.data.token).toMatch(/^ppe_[A-Za-z0-9_-]{16,128}$/);
    const key = await newAgentKey();
    const r = await t.http.post('/api/v1/agent/enroll').send({
      token: en.body.data.token,
      csrPem: key.csrPem,
      hostname: 'lab-a',
      facts: {
        os: {
          id: 'ubuntu',
          version: '24.04',
          arch: 'arm64',
          kernel: '6.8',
          name: 'Ubuntu 24.04.1 LTS',
        },
        agentVersion: '0.1.0',
      },
    });
    expect(r.status).toBe(201);
    expect(r.body.data.gatewayUrl).toBe('https://host.docker.internal:4443');
    const cert = new X509Certificate(r.body.data.certificatePem);
    const ca = new X509Certificate(r.body.data.caPem);
    expect(cert.verify(ca.publicKey)).toBe(true);
    expect(cert.keyUsage).toEqual(['1.3.6.1.5.5.7.3.2']); // node exposes EKU OIDs here: clientAuth only
    const csrKeyDer = createPublicKey(key.keyPem).export({ type: 'spki', format: 'der' });
    expect(cert.publicKey.export({ type: 'spki', format: 'der' }).equals(csrKeyDer)).toBe(true);
  });

  it('malformed token format → same uniform 401 as any other bad token', async () => {
    const r = await t.http
      .post('/api/v1/agent/enroll')
      .send({ token: 'garbage', csrPem: (await newAgentKey()).csrPem, hostname: 'x' });
    expect(r.status).toBe(401);
    expect(r.body.error.code).toBe('ENROLLMENT_TOKEN_INVALID');
  });
});

describe('gateway TLS identity', () => {
  it('server cert SAN includes host.docker.internal (lab containers)', async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port,
          servername: 'host.docker.internal',
          path: '/agent/v1/tasks?waitSec=0',
          key: agent.creds.keyPem,
          cert: agent.creds.certPem,
          ca: agent.creds.caPem,
          agent: false,
          headers: { 'X-Agent-Protocol': '1' },
          checkServerIdentity: (host, c) => {
            expect(c.subjectaltname).toContain('DNS:host.docker.internal');
            return https.globalAgent.options.checkServerIdentity?.(host, c) ?? undefined;
          },
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on('error', reject);
      req.end();
    });
    expect(status).toBe(200);
  });
});
