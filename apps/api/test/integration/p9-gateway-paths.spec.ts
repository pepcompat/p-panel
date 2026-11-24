/**
 * P9 §1 management paths against TWO real mTLS listeners (public + private) of the agent gateway:
 * advertised endpoints, heartbeat `connection` directive + stored probe report, `/agent/v1/ping`,
 * fail-closed CONNECTION_PATH_NOT_ALLOWED (audited once per window) and the private_only guard.
 */
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
  stepUpToken,
  type TestApp,
} from './helpers';

let t: TestApp;
let pub: number;
let priv: number;
let owner: string;

beforeAll(async () => {
  t = await bootApp({
    PPANEL_PUBLIC_GATEWAY_URL: 'https://localhost:4443',
    PPANEL_PRIVATE_GATEWAY_URL: 'https://10.10.0.2:4444',
  });
  const ports = await t.gateway.startAll([
    { label: 'public', host: '127.0.0.1', port: 0 },
    { label: 'private', host: '127.0.0.1', port: 0 },
  ]);
  pub = ports.public!;
  priv = ports.private!;
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

const probe = (ok: boolean, checkedAt = new Date().toISOString()) => ({
  activePath: 'private',
  endpoints: [
    { path: 'public', url: 'https://localhost:4443', ok: true, latencyMs: 4, checkedAt },
    {
      path: 'private',
      url: 'https://10.10.0.2:4444',
      ok,
      latencyMs: ok ? 2 : null,
      checkedAt,
      ...(ok ? {} : { error: 'DIAL_TIMEOUT' }),
    },
  ],
});

async function hb(
  a: EnrolledAgent,
  port: number,
  seq: number,
  extra: Record<string, unknown> = {},
) {
  return agentCall(port, a.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(seq, extra));
}
const patch = (id: string, body: unknown, stepUp?: string) => {
  const r = t.http.patch(`/api/v1/servers/${id}`).set(bearer(owner));
  if (stepUp) r.set('X-Step-Up', stepUp);
  return r.send(body as object);
};

describe('P9-03 multiple gateway listeners', () => {
  it('enrollment advertises both endpoints; heartbeat answers with the connection directive on either path', async () => {
    expect(pub).not.toBe(priv);
    const a = await enrollAgent(t, owner);
    const enrollResp = await t.prisma.server.findUniqueOrThrow({ where: { id: a.serverId } });
    expect(enrollResp.connectionPolicy).toBe('auto');
    for (const [port, seq] of [
      [pub, 1],
      [priv, 2],
    ] as const) {
      const r = await hb(a, port, seq);
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      expect(r.body.data.connection).toEqual({
        policy: 'auto',
        endpoints: [
          { path: 'public', url: 'https://localhost:4443' },
          { path: 'private', url: 'https://10.10.0.2:4444' },
        ],
      });
    }
  });

  it('enroll response carries gatewayEndpoints (and keeps gatewayUrl)', async () => {
    const en = await t.http
      .post('/api/v1/enrollments')
      .set(bearer(owner))
      .send({ name: 'node-e', environment: 'development' });
    const key = await newAgentKey();
    const r = await t.http.post('/api/v1/agent/enroll').send({
      token: en.body.data.token,
      csrPem: key.csrPem,
      hostname: 'lab-node-e',
      facts: {
        agentVersion: '0.9.0',
        provider: {
          name: 'digitalocean',
          dropletId: 4242,
          region: 'lab1',
          interfaces: { private: ['10.10.0.7'], public: ['203.0.113.70'] },
        },
      },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.data.gatewayUrl).toBe('https://localhost:4443');
    expect(r.body.data.gatewayEndpoints).toEqual([
      { path: 'public', url: 'https://localhost:4443' },
      { path: 'private', url: 'https://10.10.0.2:4444' },
    ]);
    const inv = await t.prisma.serverNetworkInventory.findMany({
      where: { serverId: r.body.data.serverId },
    });
    expect(inv).toHaveLength(1);
    expect(inv[0]).toMatchObject({
      source: 'agent',
      dropletId: '4242',
      region: 'lab1',
      vpcUuid: null,
      privateIpv4: '10.10.0.7',
    });
  });

  it('ping answers on both paths without any DB write; probe report + provider facts are stored and shown', async () => {
    const a = await enrollAgent(t, owner);
    const before = {
      audit: await t.prisma.auditEvent.count(),
      hb: await t.prisma.agentHeartbeat.count(),
      srv: (await t.prisma.server.findUniqueOrThrow({ where: { id: a.serverId } })).updatedAt,
    };
    for (const [port, label] of [
      [pub, 'public'],
      [priv, 'private'],
    ] as const) {
      const r = await agentCall(port, a.creds, 'GET', '/agent/v1/ping');
      expect(r.status).toBe(200);
      expect(r.body.data).toMatchObject({
        path: label,
        policyAllows: true,
        serverTime: expect.any(String),
      });
    }
    expect(await t.prisma.auditEvent.count()).toBe(before.audit);
    expect(await t.prisma.agentHeartbeat.count()).toBe(before.hb);
    expect(
      (await t.prisma.server.findUniqueOrThrow({ where: { id: a.serverId } })).updatedAt,
    ).toEqual(before.srv);

    const r = await hb(a, priv, 1, {
      connection: probe(true),
      provider: {
        name: 'digitalocean',
        dropletId: '777',
        region: 'lab1',
        interfaces: { private: ['10.10.0.3'], public: [] },
      },
    });
    expect(r.status).toBe(200);
    const s = (await t.http.get(`/api/v1/servers/${a.serverId}`).set(bearer(owner))).body.data;
    expect(s.connection).toMatchObject({
      policy: 'auto',
      activePath: 'private',
      endpoints: [
        { path: 'public', ok: true, latencyMs: 4 },
        { path: 'private', ok: true, latencyMs: 2 },
      ],
      reportedAt: expect.any(String),
    });
    expect(s.provider).toEqual({
      name: 'digitalocean',
      region: 'lab1',
      dropletId: '777',
      vpcUuid: null,
    });
    expect(s.network).toEqual({ region: 'lab1', vpcUuid: null, vpcName: null, vpcSource: null });
    expect(s.privateIpv4).toBe('10.104.0.3'); // detected address wins over agent facts
    expect(s.publicIpv4).toBe('203.0.113.10');
    // provider null clears the facts (metadata gone)
    await hb(a, priv, 2, { provider: null });
    expect(await t.prisma.serverNetworkInventory.count({ where: { serverId: a.serverId } })).toBe(
      0,
    );
  });

  it('private_only: 422 without a fresh healthy private probe; then the public path is refused fail-closed (403, audited once)', async () => {
    const a = await enrollAgent(t, owner);
    let r = await patch(a.serverId, { connectionPolicy: 'private_only' });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('PRIVATE_PATH_UNVERIFIED');
    await hb(a, pub, 1, { connection: probe(false) });
    r = await patch(a.serverId, { connectionPolicy: 'private_only' });
    expect(r.body.error?.code).toBe('PRIVATE_PATH_UNVERIFIED');
    // a stale (6 min old) report does not count either
    await hb(a, pub, 2, { connection: probe(true) });
    await t.prisma.serverConnection.update({
      where: { serverId: a.serverId },
      data: { reportedAt: new Date(Date.now() - 6 * 60_000) },
    });
    r = await patch(a.serverId, { connectionPolicy: 'private_only' });
    expect(r.body.error?.code).toBe('PRIVATE_PATH_UNVERIFIED');
    await hb(a, priv, 3, { connection: probe(true) });
    r = await patch(a.serverId, { connectionPolicy: 'private_only' });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data.connection.policy).toBe('private_only');

    for (const [method, path] of [
      ['POST', '/agent/v1/heartbeat'],
      ['GET', '/agent/v1/tasks?waitSec=0'],
      ['POST', '/agent/v1/logs'],
    ] as const) {
      const res = await agentCall(
        pub,
        a.creds,
        method,
        path,
        method === 'POST' && path.endsWith('heartbeat') ? heartbeatBody(9) : undefined,
      );
      expect(res.status, path).toBe(403);
      expect(res.body.error.code).toBe('CONNECTION_PATH_NOT_ALLOWED');
      expect(res.body.error.details).toEqual({ path: 'public', policy: 'private_only' });
    }
    const denied = await t.prisma.auditEvent.findMany({
      where: { action: 'agent.connection_path_denied' },
    });
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({ actorType: 'agent', targetId: a.serverId, result: 'denied' });
    // ping still measures reachability and says the policy forbids it
    const ping = await agentCall(pub, a.creds, 'GET', '/agent/v1/ping');
    expect(ping.body.data).toMatchObject({ path: 'public', policyAllows: false });
    // the private path keeps working and carries the new policy
    const ok = await hb(a, priv, 10);
    expect(ok.status).toBe(200);
    expect(ok.body.data.connection.policy).toBe('private_only');
    const tasks = await agentCall(priv, a.creds, 'GET', '/agent/v1/tasks?waitSec=0');
    expect(tasks.status).toBe(200);

    // public_only is enforced the other way round
    r = await patch(a.serverId, { connectionPolicy: 'public_only' });
    expect(r.status).toBe(200);
    expect((await hb(a, priv, 11)).body.error.code).toBe('CONNECTION_PATH_NOT_ALLOWED');
    expect((await hb(a, pub, 12)).status).toBe(200);
  });

  it('production: a policy change needs step-up; listing filters by connection_policy', async () => {
    const a = await enrollAgent(t, owner, { environment: 'production' });
    await enrollAgent(t, owner);
    let r = await patch(a.serverId, { connectionPolicy: 'public_only' });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    // other fields stay step-up free
    expect((await patch(a.serverId, { tags: ['edge'] })).status).toBe(200);
    const su = await stepUpToken(t, owner);
    r = await patch(a.serverId, { connectionPolicy: 'public_only' }, su);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const list = await t.http
      .get('/api/v1/servers?connection_policy=public_only&tags[contains]=edge')
      .set(bearer(owner));
    expect(list.status).toBe(200);
    expect(list.body.data.map((s: { id: string }) => s.id)).toEqual([a.serverId]);
    const audit = await t.prisma.auditEvent.findFirstOrThrow({
      where: { action: 'servers.update', targetId: a.serverId, result: 'success' },
      orderBy: { createdAt: 'desc' },
    });
    expect(audit.diffHash).toMatch(/^[a-f0-9]{64}$/);
  });
});
