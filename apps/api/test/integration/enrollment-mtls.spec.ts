import { X509Certificate } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SweeperService } from '../../src/jobs/sweeper.service';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  heartbeatBody,
  login,
  newAgentKey,
  resetDb,
  spoofedAgentCert,
  type TestApp,
} from './helpers';

let t: TestApp;
let port: number;
let owner: string;

beforeAll(async () => {
  t = await bootApp({ PPANEL_HEARTBEAT_KEEP: '10' });
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
});

async function createEnrollment(environment = 'development', ttlMinutes = 15) {
  const res = await t.http.post('/api/v1/enrollments').set(bearer(owner)).send({ name: 'node-a', environment, tags: ['web'], ttlMinutes });
  expect(res.status).toBe(201);
  return res.body.data as { enrollmentId: string; token: string; expiresAt: string; installCommand: string };
}

describe('P1-T01 enrollment', () => {
  it('token shown once, stored as sha256, listing never returns it', async () => {
    const en = await createEnrollment();
    expect(en.token).toMatch(/^ppe_[A-Za-z0-9_-]{43}$/);
    expect(en.installCommand).toContain(en.token);
    const row = await t.prisma.agentEnrollment.findUniqueOrThrow({ where: { id: en.enrollmentId } });
    expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(row)).not.toContain(en.token);
    const list = await t.http.get('/api/v1/enrollments').set(bearer(owner));
    expect(list.status).toBe(200);
    expect(list.body.paginate.total).toBe(1);
    expect(JSON.stringify(list.body)).not.toContain(en.token);
    expect(list.body.data[0]).toMatchObject({ id: en.enrollmentId, status: 'pending' });
    const audit = await t.prisma.auditEvent.findFirstOrThrow({ where: { action: 'enrollments.create' } });
    expect(JSON.stringify(audit)).not.toContain(en.token);
  });

  it('valid enrollment registers exactly once; reused, expired and unknown tokens get the same error', async () => {
    const en = await createEnrollment();
    const key = await newAgentKey();
    const body = { token: en.token, csrPem: key.csrPem, hostname: 'node-a', facts: { os: { id: 'ubuntu', version: '24.04', arch: 'arm64' }, agentVersion: '0.1.0' } };
    const ok = await t.http.post('/api/v1/agent/enroll').send(body);
    expect(ok.status).toBe(201);
    expect(ok.body.data).toMatchObject({ serverId: expect.any(String), gatewayUrl: 'https://localhost:4443', heartbeatIntervalSec: 15 });
    const cert = new X509Certificate(ok.body.data.certificatePem);
    expect(cert.subject).toBe(`CN=agent:${ok.body.data.serverId}`);
    expect(cert.subjectAltName).toBe(`URI:ppanel://agent/${ok.body.data.serverId}`);
    expect(cert.checkIssued(new X509Certificate(ok.body.data.caPem))).toBe(true);
    expect(cert.verify(new X509Certificate(ok.body.data.caPem).publicKey)).toBe(true);
    const days = (new Date(cert.validTo).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);
    expect(days).toBeLessThan(7.1);
    expect(await t.prisma.server.count()).toBe(1);
    const server = await t.prisma.server.findFirstOrThrow();
    expect(server).toMatchObject({ name: 'node-a', environment: 'development', status: 'enrolling', hostname: 'node-a', tags: ['web'] });

    const reused = await t.http.post('/api/v1/agent/enroll').send({ ...body, csrPem: (await newAgentKey()).csrPem });
    expect(reused.status).toBe(401);
    expect(reused.body.error.code).toBe('ENROLLMENT_TOKEN_INVALID');

    const en2 = await createEnrollment();
    await t.prisma.agentEnrollment.update({ where: { id: en2.enrollmentId }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const expired = await t.http.post('/api/v1/agent/enroll').send({ ...body, token: en2.token });
    expect(expired.status).toBe(401);

    const unknown = await t.http.post('/api/v1/agent/enroll').send({ ...body, token: 'ppe_' + 'A'.repeat(43) });
    expect(unknown.status).toBe(401);

    // identical error (no oracle)
    expect(expired.body.error).toEqual(reused.body.error);
    expect(unknown.body.error).toEqual(reused.body.error);
    expect(await t.prisma.server.count()).toBe(1);
  });

  it('concurrent enrollments with one token → exactly one server', async () => {
    const en = await createEnrollment();
    const attempts = await Promise.all(
      Array.from({ length: 5 }, async () =>
        t.http.post('/api/v1/agent/enroll').send({ token: en.token, csrPem: (await newAgentKey()).csrPem, hostname: 'race' }),
      ),
    );
    expect(attempts.map((a) => a.status).sort()).toEqual([201, 401, 401, 401, 401]);
    expect(await t.prisma.server.count()).toBe(1);
    expect(await t.prisma.agentCertificate.count()).toBe(1);
  });

  it('invalid CSR (wrong curve) → 422 CSR_INVALID and token is NOT consumed', async () => {
    const en = await createEnrollment();
    const p384 = await newAgentKey('P-384');
    const bad = await t.http.post('/api/v1/agent/enroll').send({ token: en.token, csrPem: p384.csrPem, hostname: 'x' });
    expect(bad.status).toBe(422);
    expect(bad.body.error.code).toBe('CSR_INVALID');
    const garbage = await t.http.post('/api/v1/agent/enroll').send({ token: en.token, csrPem: '-----BEGIN CERTIFICATE REQUEST-----\n' + 'A'.repeat(200) + '\n-----END CERTIFICATE REQUEST-----', hostname: 'x' });
    expect(garbage.status).toBe(422);
    const ok = await t.http.post('/api/v1/agent/enroll').send({ token: en.token, csrPem: (await newAgentKey()).csrPem, hostname: 'x' });
    expect(ok.status).toBe(201);
  });

  it('CA private key is stored encrypted', async () => {
    const ca = await t.prisma.caKey.findFirstOrThrow({ where: { active: true } });
    expect(ca.privateKeyEnc.startsWith('v1.')).toBe(true);
    expect(ca.privateKeyEnc).not.toContain('PRIVATE KEY');
  });
});

describe('P1-T02 mTLS gateway', () => {
  it('heartbeat with a valid cert updates status, metrics, addresses, capabilities', async () => {
    const a = await enrollAgent(t, owner);
    const hb = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1));
    expect(hb.status).toBe(200);
    expect(hb.body.success).toBe(true);
    expect(hb.body.data).toMatchObject({ heartbeatIntervalSec: 15, serverTime: expect.any(String), certRenewAfter: expect.any(String) });
    const s = await t.http.get(`/api/v1/servers/${a.serverId}`).set(bearer(owner));
    expect(s.status).toBe(200);
    expect(s.body.data).toMatchObject({
      status: 'online',
      agentVersion: '0.1.0',
      capabilities: ['docker', 'nginx', 'systemd'],
      metrics: { cpuPct: 12.5, memPct: 40.1, diskPct: 63, stale: false },
      certificate: { serial: expect.any(String), notAfter: expect.any(String) },
      os: { id: 'ubuntu', version: '24.04', arch: 'arm64' },
    });
    expect(s.body.data.addresses).toHaveLength(2);
    expect(s.body.data.allowedActions).toContain('revoke');
    expect(s.headers.etag).toBe('"1"');
    const beats = await t.http.get(`/api/v1/servers/${a.serverId}/heartbeats?limit=5`).set(bearer(owner));
    expect(beats.body.data).toHaveLength(1);
  });

  it('rejects a client cert from a spoofed CA at the TLS layer, and connections without a cert', async () => {
    const a = await enrollAgent(t, owner);
    const spoof = await spoofedAgentCert(a.serverId);
    const TLS_REJECT = /alert|certificate|ECONNRESET|socket hang up/i;
    await expect(agentCall(port, { ...spoof, caPem: a.creds.caPem }, 'POST', '/agent/v1/heartbeat', heartbeatBody(1))).rejects.toThrow(TLS_REJECT);
    await expect(agentCall(port, { caPem: a.creds.caPem }, 'POST', '/agent/v1/heartbeat', heartbeatBody(1))).rejects.toThrow(TLS_REJECT);
    // positive control on the same gateway
    expect((await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1))).status).toBe(200);
    expect(await t.prisma.agentHeartbeat.count({ where: { serverId: a.serverId } })).toBe(1);
  });

  it('rotated cert is accepted; revoked certs are rejected with 401 AGENT_CERT_REVOKED', async () => {
    const a = await enrollAgent(t, owner);
    expect((await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1))).status).toBe(200);

    const nk = await newAgentKey();
    const rot = await agentCall(port, a.creds, 'POST', '/agent/v1/certificate/rotate', { csrPem: nk.csrPem });
    expect(rot.status).toBe(200);
    expect(rot.body.data).toEqual({ certificatePem: expect.stringContaining('BEGIN CERTIFICATE'), notAfter: expect.any(String) });
    const rotated = { keyPem: nk.keyPem, certPem: rot.body.data.certificatePem, caPem: a.creds.caPem };
    expect(new X509Certificate(rotated.certPem).subject).toBe(`CN=agent:${a.serverId}`);
    expect((await agentCall(port, rotated, 'POST', '/agent/v1/heartbeat', heartbeatBody(2))).status).toBe(200);
    // old cert stays valid until expiry unless revoked
    expect((await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(3))).status).toBe(200);

    // revoke a single certificate directly (e.g. compromised key) → that cert only is rejected
    await t.prisma.agentCertificate.updateMany({
      where: { certPem: a.creds.certPem },
      data: { revokedAt: new Date(), revokedReason: 'test' },
    });
    const r1 = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(4));
    expect(r1.status).toBe(401);
    expect(r1.body.error.code).toBe('AGENT_CERT_REVOKED');
    expect((await agentCall(port, rotated, 'POST', '/agent/v1/heartbeat', heartbeatBody(5))).status).toBe(200);

    // revoke the server through the API → every cert rejected
    const rv = await t.http.post(`/api/v1/servers/${a.serverId}/revoke`).set(bearer(owner));
    expect(rv.status).toBe(200);
    expect(rv.body.data.status).toBe('revoked');
    const r2 = await agentCall(port, rotated, 'GET', '/agent/v1/tasks?waitSec=0');
    expect(r2.status).toBe(401);
    expect(r2.body.error.code).toBe('AGENT_CERT_REVOKED');
    expect(await t.prisma.auditEvent.count({ where: { action: 'servers.revoke', result: 'success' } })).toBe(1);
  });

  it('expired agent cert is rejected', async () => {
    const a = await enrollAgent(t, owner);
    await t.prisma.agentCertificate.updateMany({ where: { serverId: a.serverId }, data: { notAfter: new Date(Date.now() - 1000) } });
    const r = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1));
    expect(r.status).toBe(401);
  });

  it('unsupported protocol major → 426', async () => {
    const a = await enrollAgent(t, owner);
    const r = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1), { 'X-Agent-Protocol': '2' });
    expect(r.status).toBe(426);
    expect(r.body.error.code).toBe('AGENT_PROTOCOL_UNSUPPORTED');
  });

  it('invalid heartbeat body → 422 envelope', async () => {
    const a = await enrollAgent(t, owner);
    const r = await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', { seq: -1 });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('VALIDATION_FAILED');
  });

  it('production revoke requires step-up', async () => {
    const a = await enrollAgent(t, owner, { environment: 'production' });
    const r = await t.http.post(`/api/v1/servers/${a.serverId}/revoke`).set(bearer(owner));
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
  });
});

describe('P2-T04-lite status derivation (stale/offline never zeroes metrics)', () => {
  it('derives stale and offline from last heartbeat, keeping last metrics flagged stale', async () => {
    const a = await enrollAgent(t, owner);
    await agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1));
    await t.prisma.server.update({ where: { id: a.serverId }, data: { lastHeartbeatAt: new Date(Date.now() - 60_000) } });
    let s = (await t.http.get(`/api/v1/servers/${a.serverId}`).set(bearer(owner))).body.data;
    expect(s.status).toBe('stale');
    expect(s.metrics).toMatchObject({ cpuPct: 12.5, memPct: 40.1, diskPct: 63, stale: true });

    await t.prisma.server.update({ where: { id: a.serverId }, data: { lastHeartbeatAt: new Date(Date.now() - 600_000) } });
    s = (await t.http.get(`/api/v1/servers/${a.serverId}`).set(bearer(owner))).body.data;
    expect(s.status).toBe('offline');
    expect(s.metrics).toMatchObject({ cpuPct: 12.5, stale: true });

    const offline = await t.http.get('/api/v1/servers?status=offline').set(bearer(owner));
    expect(offline.body.data.map((x: { id: string }) => x.id)).toEqual([a.serverId]);
    const online = await t.http.get('/api/v1/servers?status=online').set(bearer(owner));
    expect(online.body.data).toEqual([]);
  });
});

describe('heartbeat retention is bounded', () => {
  it('keeps only the newest PPANEL_HEARTBEAT_KEEP rows per server', async () => {
    const a = await enrollAgent(t, owner);
    const b = await enrollAgent(t, owner);
    const base = Date.now() - 3_600_000;
    for (const serverId of [a.serverId, b.serverId]) {
      await t.prisma.agentHeartbeat.createMany({
        data: Array.from({ length: 15 }, (_, i) => ({ serverId, seq: BigInt(i), receivedAt: new Date(base + i * 15_000) })),
      });
    }
    const deleted = await t.app.get(SweeperService).pruneHeartbeats();
    expect(deleted).toBe(10);
    const rows = await t.prisma.agentHeartbeat.findMany({ where: { serverId: a.serverId }, orderBy: { seq: 'asc' } });
    expect(rows.map((r) => Number(r.seq))).toEqual([5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  });
});
