/**
 * P9 §2–§4 Center side: DigitalOcean provider integration against an in-process fake DO API,
 * user inventory, topology findings, server card fields + filters, server groups, diagnostics.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { decryptSecret } from '../../src/common/crypto';
import { uuidv7 } from '../../src/common/ids';
import { ProviderService } from '../../src/network/provider.service';
import { bearer, bootApp, login, resetDb, stepUpToken, type TestApp } from './helpers';

const DO_TOKEN = 'TEST_FAKE_DO_TOKEN_0123456789';

interface FakeDo {
  server: http.Server;
  base: string;
  methods: string[];
  paths: string[];
  fail: boolean;
  droplets: unknown[];
  vpcs: unknown[];
}
let fake: FakeDo;
let t: TestApp;
let owner: string;
let admin: string;
let viewer: string;

async function startFakeDo(): Promise<FakeDo> {
  const f = { methods: [], paths: [], fail: false, droplets: [], vpcs: [] } as unknown as FakeDo;
  f.server = http.createServer((req, res) => {
    f.methods.push(req.method ?? '');
    f.paths.push(req.url ?? '');
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.headers.authorization !== `Bearer ${DO_TOKEN}`)
      return send(401, { id: 'unauthorized' });
    if (f.fail) return send(500, { id: 'server_error' });
    const url = new URL(req.url ?? '/', 'http://x');
    const page = Number(url.searchParams.get('page') ?? 1);
    if (url.pathname === '/v2/account') return send(200, { account: { status: 'active' } });
    // one droplet per page → exercises pagination
    if (url.pathname === '/v2/droplets') {
      const items = f.droplets.slice(page - 1, page);
      return send(200, {
        droplets: items,
        links:
          page < f.droplets.length
            ? { pages: { next: `${f.base}/v2/droplets?page=${page + 1}` } }
            : {},
        meta: { total: f.droplets.length },
      });
    }
    if (url.pathname === '/v2/vpcs')
      return send(200, { vpcs: f.vpcs, links: {}, meta: { total: f.vpcs.length } });
    send(404, { id: 'not_found' });
  });
  await new Promise<void>((r) => f.server.listen(0, '127.0.0.1', () => r()));
  f.base = `http://127.0.0.1:${(f.server.address() as AddressInfo).port}`;
  return f;
}

beforeAll(async () => {
  fake = await startFakeDo();
  t = await bootApp({ PPANEL_DO_API_BASE: fake.base });
});
afterAll(async () => {
  await t.close();
  await new Promise<void>((r) => fake.server.close(() => r()));
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  viewer = await login(t, 'user1');
  fake.methods = [];
  fake.paths = [];
  fake.fail = false;
  fake.vpcs = [
    { id: 'vpc-a', name: 'lab-vpc-a', region: 'lab1' },
    { id: 'vpc-b', name: 'lab-vpc-b', region: 'lab1' },
  ];
  fake.droplets = [
    {
      id: 1001,
      name: 'node-a',
      region: { slug: 'lab1' },
      vpc_uuid: 'vpc-a',
      networks: {
        v4: [
          { ip_address: '10.10.0.11', type: 'private' },
          { ip_address: '198.51.100.11', type: 'public' },
        ],
      },
    },
    {
      id: 1002,
      name: 'node-b',
      region: { slug: 'lab1' },
      vpc_uuid: 'vpc-b',
      networks: { v4: [{ ip_address: '10.20.0.12', type: 'private' }] },
    },
    {
      id: 1003,
      name: 'stranger',
      region: { slug: 'lab1' },
      vpc_uuid: 'vpc-b',
      networks: { v4: [{ ip_address: '10.20.0.99', type: 'private' }] },
    },
  ];
});

async function server(
  name: string,
  opts: {
    privateIp?: string;
    dropletId?: string;
    env?: string;
    groupId?: string;
    tags?: string[];
  } = {},
) {
  const id = uuidv7();
  await t.prisma.server.create({
    data: {
      id,
      name,
      hostname: `${name}.lab`,
      environment: opts.env ?? 'development',
      status: 'online',
      lastHeartbeatAt: new Date(),
      agentVersion: '0.9.0',
      groupId: opts.groupId ?? null,
      tags: opts.tags ?? [],
      provider: opts.dropletId
        ? { name: 'digitalocean', dropletId: opts.dropletId, region: 'lab1', vpcUuid: null }
        : undefined,
    },
  });
  if (opts.privateIp)
    await t.prisma.serverAddress.create({
      data: {
        id: uuidv7(),
        serverId: id,
        family: 'ipv4',
        scope: 'private',
        address: opts.privateIp,
        source: 'detected',
      },
    });
  return id;
}

async function integration(token = owner) {
  const su = await stepUpToken(t, token);
  const r = await t.http
    .post('/api/v1/provider-integrations')
    .set(bearer(token))
    .set('X-Step-Up', su)
    .send({ provider: 'digitalocean', name: 'lab-do', token: DO_TOKEN, apiBase: fake.base });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body.data as { id: string };
}

async function sync(id: string) {
  const r = await t.http
    .post(`/api/v1/provider-integrations/${id}/sync`)
    .set(bearer(owner))
    .send({});
  expect(r.status, JSON.stringify(r.body)).toBe(202);
  await t.app.get(ProviderService).waitForSync(id);
}

const topology = async (token = owner) => {
  const r = await t.http.get('/api/v1/network/topology').set(bearer(token));
  expect(r.status).toBe(200);
  return r.body.data as {
    regions: Array<{
      region: string | null;
      vpcs: Array<{ vpcUuid: string; vpcName: string | null; source: string; servers: string[] }>;
      unknownVpc: string[];
    }>;
    findings: Array<{ code: string; serverIds: string[] }>;
  };
};

describe('P9-01 provider integration (fake DigitalOcean API)', () => {
  it('create: step-up, token validated with GET /v2/account, encrypted, never returned; allowlist enforced', async () => {
    const base = { provider: 'digitalocean', name: 'lab-do', token: DO_TOKEN, apiBase: fake.base };
    let r = await t.http.post('/api/v1/provider-integrations').set(bearer(owner)).send(base);
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    const su = await stepUpToken(t, owner);
    const post = (body: unknown) =>
      t.http
        .post('/api/v1/provider-integrations')
        .set(bearer(owner))
        .set('X-Step-Up', su)
        .send(body as object);
    r = await post({ ...base, token: 'TEST_FAKE_WRONG_TOKEN' });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('PROVIDER_AUTH_FAILED');
    for (const apiBase of [
      'http://169.254.169.254',
      'http://127.0.0.1:1',
      'https://api.digitalocean.com.evil.test',
    ]) {
      r = await post({ ...base, apiBase });
      expect(r.status, apiBase).toBe(422);
      expect(r.body.error.code).toBe('PROVIDER_API_NOT_ALLOWED');
    }
    r = await post(base);
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.data).toMatchObject({
      provider: 'digitalocean',
      name: 'lab-do',
      apiBase: fake.base,
      status: 'ok',
      lastSyncAt: null,
    });
    expect(JSON.stringify(r.body)).not.toContain(DO_TOKEN);
    const row = await t.prisma.providerIntegration.findUniqueOrThrow({
      where: { id: r.body.data.id },
    });
    expect(row.tokenEnc).not.toContain(DO_TOKEN);
    expect(
      decryptSecret(t.config.masterKey, row.tokenEnc, `provider_integration:${row.id}`).toString(),
    ).toBe(DO_TOKEN);
    const list = await t.http.get('/api/v1/provider-integrations').set(bearer(owner));
    expect(list.status).toBe(200);
    expect(JSON.stringify(list.body)).not.toContain(DO_TOKEN);
    expect((await t.http.get('/api/v1/provider-integrations').set(bearer(viewer))).status).toBe(
      403,
    );
    expect(new Set(fake.methods)).toEqual(new Set(['GET']));
    const audits = await t.prisma.auditEvent.findMany({
      where: { action: 'provider_integrations.create' },
    });
    expect(audits.map((a) => a.result).sort()).toEqual([
      'denied',
      'denied',
      'denied',
      'failure',
      'success',
    ]);
    expect(JSON.stringify(audits)).not.toContain(DO_TOKEN);
  });

  it('sync (paginated, GET only) matches by droplet id then private IPv4 → provider rows; topology: same region, different VPC', async () => {
    const a = await server('node-a', { dropletId: '1001', privateIp: '10.99.0.1' });
    const b = await server('node-b', { privateIp: '10.20.0.12' });
    const c = await server('node-c', { privateIp: '10.30.0.13' });
    const i = await integration();
    await sync(i.id);
    expect(new Set(fake.methods)).toEqual(new Set(['GET']));
    expect(fake.paths.filter((p) => p.startsWith('/v2/droplets'))).toEqual([
      '/v2/droplets?page=1&per_page=200',
      '/v2/droplets?page=2&per_page=200',
      '/v2/droplets?page=3&per_page=200',
    ]);
    const rows = await t.prisma.serverNetworkInventory.findMany({
      where: { source: 'provider' },
      orderBy: { dropletId: 'asc' },
    });
    expect(rows.map((r) => [r.serverId, r.dropletId, r.vpcUuid, r.vpcName, r.privateIpv4])).toEqual(
      [
        [a, '1001', 'vpc-a', 'lab-vpc-a', '10.10.0.11'],
        [b, '1002', 'vpc-b', 'lab-vpc-b', '10.20.0.12'],
      ],
    );
    const view = (await t.http.get('/api/v1/provider-integrations').set(bearer(owner))).body
      .data[0];
    expect(view).toMatchObject({
      status: 'ok',
      lastError: null,
      syncInProgress: false,
      lastSyncSummary: { droplets: 3, vpcs: 2, matched: 2, unmatched: 1 },
    });
    const topo = await topology();
    expect(topo.regions).toEqual([
      {
        region: 'lab1',
        vpcs: [
          { vpcUuid: 'vpc-a', vpcName: 'lab-vpc-a', source: 'provider', servers: [a] },
          { vpcUuid: 'vpc-b', vpcName: 'lab-vpc-b', source: 'provider', servers: [b] },
        ],
        unknownVpc: [],
      },
      { region: null, vpcs: [], unknownVpc: [c] },
    ]);
    expect(topo.findings.map((f) => [f.code, f.serverIds])).toEqual([
      ['VPC_UNKNOWN', [c]],
      ['SAME_REGION_DIFFERENT_VPC', [a, b].sort()],
    ]);
    // server cards show the provider-verified addresses and network
    const sa = (await t.http.get(`/api/v1/servers/${a}`).set(bearer(owner))).body.data;
    expect(sa).toMatchObject({
      privateIpv4: '10.10.0.11',
      publicIpv4: '198.51.100.11',
      network: { region: 'lab1', vpcUuid: 'vpc-a', vpcName: 'lab-vpc-a', vpcSource: 'provider' },
    });
    // stale provider data
    await t.prisma.serverNetworkInventory.updateMany({
      where: { serverId: a, source: 'provider' },
      data: { observedAt: new Date(Date.now() - 25 * 3_600_000) },
    });
    expect((await topology()).findings.find((f) => f.code === 'PROVIDER_STALE')?.serverIds).toEqual(
      [a],
    );
  });

  it('sync failure is recorded (status error, lastError), delete → 204', async () => {
    const i = await integration();
    fake.fail = true;
    await sync(i.id);
    const view = (await t.http.get('/api/v1/provider-integrations').set(bearer(owner))).body
      .data[0];
    expect(view).toMatchObject({ status: 'error', lastError: { code: 'PROVIDER_UNAVAILABLE' } });
    expect(
      (await t.http.post(`/api/v1/provider-integrations/${i.id}/sync`).set(bearer(admin)).send({}))
        .status,
    ).toBe(202);
    await t.app.get(ProviderService).waitForSync(i.id);
    expect(
      (await t.http.delete(`/api/v1/provider-integrations/${i.id}`).set(bearer(viewer))).status,
    ).toBe(403);
    expect(
      (await t.http.delete(`/api/v1/provider-integrations/${i.id}`).set(bearer(owner))).status,
    ).toBe(204);
    expect(await t.prisma.providerIntegration.count()).toBe(0);
  });
});

describe('P9-01 user inventory', () => {
  it('rows by serverId / hostname, all-or-nothing, mismatch with provider, RBAC', async () => {
    const a = await server('node-a', { dropletId: '1001' });
    const c = await server('node-c');
    let r = await t.http
      .post('/api/v1/network/inventory')
      .set(bearer(owner))
      .send({
        rows: [
          {
            hostname: 'node-c.lab',
            region: 'lab1',
            vpcUuid: 'vpc-c',
            vpcName: 'manual',
            privateIpv4: '10.30.0.13',
          },
          { hostname: 'ghost' },
        ],
      });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('INVENTORY_SERVER_UNRESOLVED');
    expect(r.body.error.details).toEqual([{ index: 1, reason: 'server_not_found' }]);
    expect(await t.prisma.serverNetworkInventory.count()).toBe(0);
    r = await t.http
      .post('/api/v1/network/inventory')
      .set(bearer(owner))
      .send([
        {
          hostname: 'node-c',
          region: 'lab1',
          vpcUuid: 'vpc-c',
          vpcName: 'manual',
          privateIpv4: '10.30.0.13',
        },
        { serverId: a, region: 'lab1', vpcUuid: 'vpc-zzz', dropletId: 1001 },
      ]);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data.upserted).toBe(2);
    expect(r.body.data.rows[0]).toMatchObject({
      serverId: c,
      source: 'inventory',
      vpcUuid: 'vpc-c',
    });
    let topo = await topology();
    expect(topo.regions[0]!.vpcs.map((v) => [v.vpcUuid, v.source])).toEqual([
      ['vpc-c', 'inventory'],
      ['vpc-zzz', 'inventory'],
    ]);
    const i = await integration();
    await sync(i.id);
    topo = await topology();
    expect(topo.findings.find((f) => f.code === 'INVENTORY_MISMATCH')?.serverIds).toEqual([a]);
    // provider wins for the VPC shown
    expect(topo.regions[0]!.vpcs.find((v) => v.servers.includes(a))?.vpcUuid).toBe('vpc-a');
    // duplicates and RBAC
    r = await t.http
      .post('/api/v1/network/inventory')
      .set(bearer(owner))
      .send({ rows: [{ serverId: c }, { hostname: 'node-c' }] });
    expect(r.body.error.details).toEqual([{ index: 1, reason: 'duplicate_of_row_0' }]);
    r = await t.http
      .post('/api/v1/network/inventory')
      .set(bearer(viewer))
      .send({ rows: [{ serverId: c }] });
    expect(r.status).toBe(403);
    r = await t.http
      .post('/api/v1/network/inventory')
      .set(bearer(owner))
      .send({ rows: [{ serverId: c, extra: 1 }] });
    expect(r.status).toBe(422);
  });
});

describe('P9-02 server cards, filters and groups', () => {
  it('groups: GET one, PATCH, DELETE (409 GROUP_NOT_EMPTY unless empty); groupName + filters on /servers', async () => {
    const g = await t.http
      .post('/api/v1/server-groups')
      .set(bearer(owner))
      .send({ name: 'web', environment: 'development' });
    expect(g.status).toBe(201);
    const gid = g.body.data.id as string;
    const s1 = await server('web-1', { groupId: gid, tags: ['edge', 'web'] });
    await server('db-1', { tags: ['db'], env: 'uat' });
    let r = await t.http.get(`/api/v1/server-groups/${gid}`).set(bearer(viewer));
    expect(r.status).toBe(200);
    expect(r.body.data).toMatchObject({ id: gid, name: 'web', serverCount: 1 });
    expect(
      (await t.http.patch(`/api/v1/server-groups/${gid}`).set(bearer(viewer)).send({ name: 'x' }))
        .status,
    ).toBe(403);
    r = await t.http
      .patch(`/api/v1/server-groups/${gid}`)
      .set(bearer(owner))
      .send({ name: 'web-tier', description: null });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data).toMatchObject({
      name: 'web-tier',
      description: null,
      environment: 'development',
    });
    const list = async (qs: string) => {
      const res = await t.http.get(`/api/v1/servers?${qs}`).set(bearer(owner));
      expect(res.status, `${qs} ${JSON.stringify(res.body)}`).toBe(200);
      return res.body.data as Array<{ id: string; name: string; groupName: string | null }>;
    };
    expect((await list(`group_id=${gid}`)).map((s) => [s.id, s.groupName])).toEqual([
      [s1, 'web-tier'],
    ]);
    expect((await list('tags[contains]=edge')).map((s) => s.name)).toEqual(['web-1']);
    expect((await list('tags[in]=db,edge&sort=name&order=asc')).map((s) => s.name)).toEqual([
      'db-1',
      'web-1',
    ]);
    expect((await list('environment=uat&status=online')).map((s) => s.name)).toEqual(['db-1']);
    expect((await list('connection_policy=auto')).length).toBe(2);
    expect((await t.http.get('/api/v1/servers?tags[gt]=a').set(bearer(owner))).status).toBe(400);
    r = await t.http.delete(`/api/v1/server-groups/${gid}`).set(bearer(owner));
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('GROUP_NOT_EMPTY');
    await t.http.patch(`/api/v1/servers/${s1}`).set(bearer(owner)).send({ groupId: null });
    expect((await t.http.delete(`/api/v1/server-groups/${gid}`).set(bearer(owner))).status).toBe(
      204,
    );
    expect((await t.http.get(`/api/v1/server-groups/${gid}`).set(bearer(owner))).status).toBe(404);
    const actions = (
      await t.prisma.auditEvent.findMany({
        where: { action: { startsWith: 'server_groups.' }, result: 'success' },
      })
    ).map((a) => a.action);
    expect(actions.sort()).toEqual([
      'server_groups.create',
      'server_groups.delete',
      'server_groups.update',
    ]);
  });
});

describe('P9-04 network diagnostics', () => {
  async function runJob(
    serverId: string,
    output: unknown,
    status: 'succeeded' | 'failed' = 'succeeded',
  ) {
    const [g] = await t.jobs.lease(serverId);
    expect(g?.type).toBe('network.diagnose');
    await t.jobs.ack(serverId, g!.jobId, g!.leaseToken);
    await t.jobs.result(serverId, g!.jobId, {
      leaseToken: g!.leaseToken,
      status,
      output,
      ...(status === 'failed' ? { error: { code: 'HANDLER_FAILED' } } : {}),
    });
    return g!;
  }

  it('diagnose: target policy, typed read-only job, result stored; POST /jobs cannot create it', async () => {
    const s = await server('node-a', { privateIp: '10.10.0.11' });
    let r = await t.http
      .post(`/api/v1/servers/${s}/network-diagnostics`)
      .set(bearer(owner))
      .send({
        tcp: [
          { host: '8.8.8.8', port: 53 },
          { host: '10.10.0.12', port: 8080 },
        ],
      });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('DIAGNOSE_TARGET_NOT_ALLOWED');
    expect(r.body.error.details.tcp.map((x: { reason: string }) => x.reason)).toEqual([
      'host_not_private',
      'port_not_allowed',
    ]);
    expect(
      (await t.http.post(`/api/v1/servers/${s}/network-diagnostics`).set(bearer(viewer)).send({}))
        .status,
    ).toBe(403);
    r = await t.http
      .post(`/api/v1/servers/${s}/network-diagnostics`)
      .set(bearer(owner))
      .send({
        resolve: ['node-b.lab.internal'],
        tcp: [{ host: '10.10.0.12', port: 5432 }],
        includeRoutes: true,
      });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    const { testId, jobId } = r.body.data;
    const job = await t.prisma.job.findUniqueOrThrow({ where: { id: jobId } });
    expect(job).toMatchObject({ type: 'network.diagnose', mutating: false });
    expect(job.params).toEqual({
      resolve: ['node-b.lab.internal'],
      tcp: [{ host: '10.10.0.12', port: 5432 }],
      includeRoutes: true,
      allowedPorts: [],
    });
    let v = await t.http.get(`/api/v1/network-diagnostics/${testId}`).set(bearer(viewer));
    expect(v.body.data).toMatchObject({ status: 'queued', kind: 'diagnose', result: null });
    const output = {
      interfaces: [{ name: 'eth1', mtu: 1500, up: true, addresses: ['10.10.0.11/16'] }],
      routes: [{ dst: '10.10.0.0/16', gateway: '0.0.0.0', iface: 'eth1', metric: 0 }],
      dns: [{ host: 'node-b.lab.internal', addresses: [], error: 'NXDOMAIN' }],
      tcp: [{ host: '10.10.0.12', port: 5432, ok: true, latencyMs: 1 }],
      centerEndpoints: [],
    };
    await runJob(s, output);
    v = await t.http.get(`/api/v1/network-diagnostics/${testId}`).set(bearer(viewer));
    expect(v.body.data).toMatchObject({
      status: 'succeeded',
      result: output,
      finishedAt: expect.any(String),
      reachable: null,
    });
    const list = await t.http.get(`/api/v1/servers/${s}/network-diagnostics`).set(bearer(owner));
    expect(list.body.paginate.total).toBe(1);
    r = await t.http
      .post(`/api/v1/servers/${s}/jobs`)
      .set(bearer(owner))
      .send({ type: 'network.diagnose', params: { tcp: [{ host: '1.1.1.1', port: 22 }] } });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('JOB_TYPE_RESTRICTED');
    r = await t.http
      .post(`/api/v1/servers/${s}/jobs`)
      .set(bearer(owner))
      .send({ type: 'http.probe', params: { url: 'http://a.example/', resolveTo: '1.1.1.1' } });
    expect(r.body.error.code).toBe('JOB_TYPE_RESTRICTED');
  });

  it('pair test dials the target private IPv4; NO_PRIVATE_ADDRESS when unknown; fails across VPCs, passes within', async () => {
    const a = await server('node-a', { privateIp: '10.10.0.11' });
    const b = await server('node-b', { privateIp: '10.20.0.12' });
    const nop = await server('node-x');
    let r = await t.http
      .post('/api/v1/network/connectivity-tests')
      .set(bearer(owner))
      .send({ fromServerId: a, toServerId: nop, port: 80 });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('NO_PRIVATE_ADDRESS');
    r = await t.http
      .post('/api/v1/network/connectivity-tests')
      .set(bearer(owner))
      .send({ fromServerId: a, toServerId: b, port: 9999 });
    expect(r.body.error.code).toBe('DIAGNOSE_TARGET_NOT_ALLOWED');
    // an allocated app host port on the target is allowed (listed in allowedPorts)
    await t.prisma.hostPortAllocation.create({ data: { serverId: b, port: 20001 } });
    r = await t.http
      .post('/api/v1/network/connectivity-tests')
      .set(bearer(owner))
      .send({ fromServerId: a, toServerId: b, port: 20001 });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    const job = await t.prisma.job.findUniqueOrThrow({ where: { id: r.body.data.jobId } });
    expect(job.params).toMatchObject({
      tcp: [{ host: '10.20.0.12', port: 20001 }],
      allowedPorts: [20001],
    });
    await runJob(a, {
      interfaces: [],
      routes: [],
      dns: [],
      tcp: [{ host: '10.20.0.12', port: 20001, ok: false, latencyMs: null, error: 'DIAL_TIMEOUT' }],
      centerEndpoints: [],
    });
    let v = await t.http
      .get(`/api/v1/network-diagnostics/${r.body.data.testId}`)
      .set(bearer(owner));
    expect(v.body.data).toMatchObject({
      kind: 'pair',
      serverId: a,
      targetServerId: b,
      status: 'succeeded',
      reachable: false,
    });
    r = await t.http
      .post('/api/v1/network/connectivity-tests')
      .set(bearer(owner))
      .send({ fromServerId: a, toServerId: b, port: 22 });
    await runJob(a, {
      interfaces: [],
      routes: [],
      dns: [],
      tcp: [{ host: '10.20.0.12', port: 22, ok: true, latencyMs: 2 }],
      centerEndpoints: [],
    });
    v = await t.http.get(`/api/v1/network-diagnostics/${r.body.data.testId}`).set(bearer(owner));
    expect(v.body.data.reachable).toBe(true);
    // failed job → failed test with the agent code
    r = await t.http
      .post('/api/v1/network/connectivity-tests')
      .set(bearer(owner))
      .send({ fromServerId: b, toServerId: a, port: 22 });
    await runJob(b, undefined, 'failed');
    v = await t.http.get(`/api/v1/network-diagnostics/${r.body.data.testId}`).set(bearer(owner));
    expect(v.body.data).toMatchObject({
      status: 'failed',
      error: { code: 'HANDLER_FAILED' },
      reachable: false,
    });
    expect(
      (await t.http.get(`/api/v1/servers/${b}/network-diagnostics`).set(bearer(owner))).body
        .paginate.total,
    ).toBe(3);
  });
});
