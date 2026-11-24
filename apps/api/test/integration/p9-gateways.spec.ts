/**
 * P9 §5 Gateway routing, Center side: gateways, routes (strict validation), plans rendered into
 * /etc/nginx/ppanel-gateway/ and driven through the P3 nginx revision service (read → validate →
 * apply → revert), http.probe shadow tests (direct vs gateway), production approval (second person +
 * step-up, planHash bound to shadow results) and the DNS cutover block. The agent is simulated.
 */
import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { uuidv7 } from '../../src/common/ids';
import { bearer, bootApp, login, resetDb, stepUpToken, type TestApp } from './helpers';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const BODY = 'a'.repeat(64);

let t: TestApp;
let owner: string;
let admin: string;
let viewer: string;
let disk: Record<string, string>;

beforeAll(async () => {
  t = await bootApp({ PPANEL_NGINX_READ_WAIT_MS: '10000' });
});
afterAll(async () => t.close());
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  viewer = await login(t, 'user1');
  disk = {};
  leased.clear();
});

async function server(name: string, env: string, priv: string, pub: string) {
  const id = uuidv7();
  await t.prisma.server.create({
    data: {
      id,
      name,
      hostname: `${name}.lab`,
      environment: env,
      status: 'online',
      lastHeartbeatAt: new Date(),
      agentVersion: '0.9.0',
      addresses: {
        create: [
          { id: uuidv7(), family: 'ipv4', scope: 'private', address: priv, source: 'detected' },
          { id: uuidv7(), family: 'ipv4', scope: 'public', address: pub, source: 'detected' },
        ],
      },
    },
  });
  return id;
}

type Grant = { jobId: string; type: string; params: any; leaseToken: string };
type ProbeReply = (g: Grant) => { status: number; bodySha256: string };

/** Simulated agent: one task, handled against the in-memory /etc/nginx "disk". */
const leased = new Map<string, Grant[]>();
async function serve(serverId: string, probe?: ProbeReply): Promise<Grant> {
  for (let i = 0; i < 100; i++) {
    // one lease call may grant several tasks: keep the rest for the next serve()
    const queue = leased.get(serverId) ?? [];
    if (queue.length === 0) queue.push(...((await t.jobs.lease(serverId)) as Grant[]));
    leased.set(serverId, queue);
    const g = queue.shift();
    if (!g) {
      await new Promise((r) => setTimeout(r, 50));
      continue;
    }
    await t.jobs.ack(serverId, g.jobId, g.leaseToken);
    const p = g.params as any;
    let output: unknown;
    switch (g.type) {
      case 'nginx.read_files':
        output = {
          files: (p.paths as string[]).map((path) =>
            disk[path] === undefined
              ? {
                  path,
                  exists: false,
                  sha256: null,
                  sizeBytes: 0,
                  content: null,
                  isSymlink: false,
                  resolvedPath: path,
                }
              : {
                  path,
                  exists: true,
                  sha256: sha(disk[path]!),
                  sizeBytes: disk[path]!.length,
                  content: disk[path],
                  isSymlink: false,
                  resolvedPath: path,
                },
          ),
        };
        break;
      case 'nginx.validate':
        output = {
          valid: true,
          nginxTestOutput: 'nginx: configuration file test is successful',
          filesChecked: [],
        };
        break;
      case 'nginx.apply':
        for (const f of p.files) disk[f.path] = f.content;
        output = {
          applied: true,
          files: p.files.map((f: any) => ({ path: f.path, sha256After: sha(f.content) })),
        };
        break;
      case 'nginx.revert':
        for (const f of p.expectedCurrent) delete disk[f.path];
        output = {
          reverted: true,
          files: p.expectedCurrent.map((f: any) => ({ path: f.path, sha256After: null })),
        };
        break;
      case 'http.probe': {
        const r = probe ? probe(g as Grant) : { status: 200, bodySha256: BODY };
        output = { ...r, latencyMs: 3, bytesRead: 12, truncated: false };
        break;
      }
      default:
        throw new Error(`unexpected job ${g.type}`);
    }
    await t.jobs.result(serverId, g.jobId, {
      leaseToken: g.leaseToken,
      status: 'succeeded',
      output,
    });
    return g as Grant;
  }
  throw new Error('no task');
}

const api = (
  method: 'get' | 'post' | 'patch' | 'delete',
  path: string,
  token = owner,
  body?: unknown,
  stepUp?: string,
) => {
  const r = t.http[method](`/api/v1${path}`).set(bearer(token));
  if (stepUp) r.set('X-Step-Up', stepUp);
  return body === undefined ? r : r.send(body as object);
};

async function setup(env = 'development') {
  const gwServer = await server('gw-1', env, '10.10.0.2', '203.0.113.2');
  const backend = await server('app-1', env, '10.10.0.11', '198.51.100.11');
  const g = await api('post', '/gateways', owner, { serverId: gwServer, name: 'gw-lab' });
  expect(g.status, JSON.stringify(g.body)).toBe(201);
  return { gw: g.body.data, gwServer, backend };
}

async function plan(gwId: string, gwServer: string) {
  const pending = api('post', `/gateways/${gwId}/plans`, owner, {}).then((r) => r);
  const read = await serve(gwServer);
  expect(read.type).toBe('nginx.read_files');
  const r = await pending;
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  const v = await serve(gwServer);
  expect(v.type).toBe('nginx.validate');
  const p = await api('get', `/gateway-plans/${r.body.data.id}`);
  return { plan: p.body.data, validate: v };
}

describe('P9-05 gateways and routes', () => {
  it('create gateway (one per server), strict route validation, backend addresses must be known', async () => {
    const { gw, gwServer, backend } = await setup();
    expect(gw).toMatchObject({
      serverId: gwServer,
      name: 'gw-lab',
      routeCount: 0,
      addresses: { privateIpv4: '10.10.0.2', publicIpv4: '203.0.113.2' },
    });
    expect(
      (await api('post', '/gateways', owner, { serverId: gwServer, name: 'other' })).body.error
        .code,
    ).toBe('GATEWAY_EXISTS');
    expect((await api('post', '/gateways', viewer, { serverId: backend, name: 'v' })).status).toBe(
      403,
    );
    const app = await t.prisma.application.findUniqueOrThrow({
      where: {
        id: (await t.prisma.gateway.findUniqueOrThrow({ where: { id: gw.id } })).applicationId,
      },
    });
    expect(app).toMatchObject({
      kind: 'gateway',
      ownershipMode: 'managed',
      name: 'ppanel-gateway',
    });
    const route = (body: Record<string, unknown>) =>
      api('post', `/gateways/${gw.id}/routes`, owner, body);
    for (const domain of [
      'shop.example.lab;}',
      'shop example.lab',
      '*.example.lab',
      '10.0.0.1',
      'shop',
    ])
      expect(
        (await route({ domain, backends: [{ serverId: backend, port: 8080 }] })).status,
        domain,
      ).toBe(422);
    expect(
      (
        await route({
          domain: 'shop.example.lab',
          backends: [{ serverId: backend, port: 8080 }],
          healthPath: '/h;x',
        })
      ).status,
    ).toBe(422);
    let r = await route({
      domain: 'shop.example.lab',
      backends: [{ serverId: backend, address: '10.99.9.9', port: 8080 }],
    });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('BACKEND_ADDRESS_UNKNOWN');
    r = await route({ domain: 'shop.example.lab', backends: [{ serverId: uuidv7(), port: 8080 }] });
    expect(r.body.error.code).toBe('BACKEND_ADDRESS_UNKNOWN');
    r = await route({
      domain: 'Shop.Example.Lab',
      backends: [{ serverId: backend, port: 8080 }],
      healthPath: '/healthz',
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.data).toMatchObject({
      domain: 'shop.example.lab',
      mode: 'hybrid',
      backends: [{ serverId: backend, address: '10.10.0.11', port: 8080 }],
    });
    expect(
      (await route({ domain: 'shop.example.lab', backends: [{ serverId: backend, port: 80 }] }))
        .body.error.code,
    ).toBe('ROUTE_DOMAIN_TAKEN');
    const rid = r.body.data.id;
    r = await api('patch', `/gateways/${gw.id}/routes/${rid}`, owner, {
      mode: 'gateway',
      backends: [{ serverId: backend, address: '198.51.100.11', port: 80 }],
    });
    expect(r.status).toBe(200);
    expect(r.body.data).toMatchObject({ mode: 'gateway', version: 2 });
    expect((await api('get', `/gateways/${gw.id}/routes`, viewer)).body.paginate.total).toBe(1);
    expect((await api('delete', `/gateways/${gw.id}`)).body.error.code).toBe('GATEWAY_NOT_EMPTY');
    expect((await api('delete', `/gateways/${gw.id}/routes/${rid}`)).status).toBe(204);
    expect((await api('delete', `/gateways/${gw.id}`)).status).toBe(204);
    // re-create on the same server reuses the gateway application (revision history survives)
    const again = await api('post', '/gateways', owner, { serverId: gwServer, name: 'gw-lab' });
    expect(again.status).toBe(201);
    expect(await t.prisma.application.count({ where: { kind: 'gateway' } })).toBe(1);
    const actions = (
      await t.prisma.auditEvent.findMany({
        where: { action: { startsWith: 'gateway' }, result: 'success' },
      })
    ).map((a) => a.action);
    expect(new Set(actions)).toEqual(
      new Set([
        'gateways.create',
        'gateway_routes.create',
        'gateway_routes.update',
        'gateway_routes.delete',
        'gateways.delete',
      ]),
    );
  });
});

describe('P9-T4 gateway plan flow (development: no approval)', () => {
  it('plan → validate → shadow test (direct vs gateway) → apply → verify → rollback; generic revision endpoints refused', async () => {
    const { gw, gwServer, backend } = await setup();
    await api('post', `/gateways/${gw.id}/routes`, owner, {
      domain: 'shop.example.lab',
      backends: [{ serverId: backend, port: 8080 }],
      healthPath: '/healthz',
    });
    const { plan: p, validate } = await plan(gw.id, gwServer);
    expect(p.status).toBe('validated');
    expect(p.rendered.map((f: any) => f.path)).toEqual([
      '/etc/nginx/conf.d/ppanel-gateway.conf',
      '/etc/nginx/ppanel-gateway/shop.example.lab.conf',
    ]);
    const conf = p.rendered[1].content as string;
    expect(conf).toContain('server_name shop.example.lab;');
    expect(conf).toContain('server 10.10.0.11:8080');
    expect(validate.params.files.map((f: any) => [f.path, f.expectedSha256Before])).toEqual([
      ['/etc/nginx/conf.d/ppanel-gateway.conf', null],
      ['/etc/nginx/ppanel-gateway/shop.example.lab.conf', null],
    ]);
    expect(p.validation).toMatchObject({ valid: true });
    expect(p.approval).toEqual({
      required: false,
      approvedBy: null,
      approvedByLabel: null,
      approvedAt: null,
    });
    expect(p.cutover.dnsChanges).toEqual([
      {
        domain: 'shop.example.lab',
        mode: 'hybrid',
        recordType: 'A',
        target: '198.51.100.11',
        directTarget: '198.51.100.11',
        action: 'none',
      },
    ]);
    expect(p.allowedActions).toEqual(expect.arrayContaining(['shadow_test', 'apply', 'cancel']));
    // a second plan while one is open is refused
    expect((await api('post', `/gateways/${gw.id}/plans`, owner, {})).body.error.code).toBe(
      'GATEWAY_PLAN_STATE_INVALID',
    );
    // the gateway's revision cannot be driven through the generic P3 endpoints
    let r = await api('post', `/nginx-revisions/${p.nginxRevisionId}/apply`, owner, {});
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('OWNERSHIP_REQUIRED');
    const appId = (await t.prisma.gateway.findUniqueOrThrow({ where: { id: gw.id } }))
      .applicationId;
    r = await api('post', `/applications/${appId}/nginx/revisions`, owner, {
      files: [{ path: '/etc/nginx/ppanel-gateway/x.example.lab.conf', content: 'evil' }],
    });
    expect(r.body.error.code).toBe('OWNERSHIP_REQUIRED');

    // shadow test: viewer refused; probes run on the gateway itself
    expect((await api('post', `/gateway-plans/${p.id}/shadow-test`, viewer, {})).status).toBe(403);
    r = await api('post', `/gateway-plans/${p.id}/shadow-test`, owner, {});
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    expect(r.body.data.status).toBe('shadow_testing');
    const probes = [await serve(gwServer), await serve(gwServer)];
    expect(probes.map((g) => [g.type, g.params.url, g.params.resolveTo, g.params.port])).toEqual([
      ['http.probe', 'http://shop.example.lab/healthz', '10.10.0.2', 80],
      ['http.probe', 'http://shop.example.lab/healthz', '10.10.0.11', 8080],
    ]);
    let cur = (await api('get', `/gateway-plans/${p.id}`)).body.data;
    expect(cur.status).toBe('shadow_tested');
    expect(cur.shadowResults).toEqual([
      {
        domain: 'shop.example.lab',
        url: 'http://shop.example.lab/healthz',
        viaGateway: { status: 200, latencyMs: 3, bodySha256: BODY },
        direct: { status: 200, latencyMs: 3, bodySha256: BODY },
        match: true,
      },
    ]);
    expect(cur.planHash).not.toBe(p.planHash);

    // apply (dev: no approval) → nginx.apply with postchecks → applied
    r = await api('post', `/gateway-plans/${p.id}/apply`, owner, {});
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    expect(r.body.data.status).toBe('applying');
    const apply = await serve(gwServer);
    expect(apply.type).toBe('nginx.apply');
    expect(apply.params.postchecks).toEqual([
      {
        hostHeader: 'shop.example.lab',
        path: '/healthz',
        scheme: 'http',
        expectStatus: [200, 204],
      },
    ]);
    cur = (await api('get', `/gateway-plans/${p.id}`)).body.data;
    expect(cur).toMatchObject({ status: 'applied', nginxRevisionStatus: 'applied' });
    expect(disk['/etc/nginx/ppanel-gateway/shop.example.lab.conf']).toBe(conf);

    // post-apply verification (mismatching body is reported, plan stays applied, hash unchanged)
    r = await api('post', `/gateway-plans/${p.id}/shadow-test`, owner, {});
    expect(r.status).toBe(202);
    await serve(gwServer, () => ({ status: 200, bodySha256: BODY }));
    await serve(gwServer, () => ({ status: 502, bodySha256: 'b'.repeat(64) }));
    cur = (await api('get', `/gateway-plans/${p.id}`)).body.data;
    expect(cur.status).toBe('applied');
    expect(cur.verification[0].match).toBe(false);
    expect(cur.allowedActions).toContain('rollback');

    // a later plan without the route writes a stub for the removed domain (revisions cannot delete)
    const route = (await api('get', `/gateways/${gw.id}/routes`)).body.data[0];
    await api('delete', `/gateways/${gw.id}/routes/${route.id}`);
    const second = await plan(gw.id, gwServer);
    expect(second.plan.rendered.map((f: any) => f.path)).toEqual([
      '/etc/nginx/conf.d/ppanel-gateway.conf',
      '/etc/nginx/ppanel-gateway/shop.example.lab.conf',
    ]);
    expect(second.plan.rendered[1].content).toMatch(/no longer routed/);
    expect(second.validate.params.files[1].expectedSha256Before).toBe(sha(conf));
    r = await api('post', `/gateway-plans/${second.plan.id}/cancel`, owner, {});
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data.status).toBe('cancelled');

    // rollback of the applied plan → nginx.revert → rolled_back
    r = await api('post', `/gateway-plans/${p.id}/rollback`, owner, {});
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    expect((await serve(gwServer)).type).toBe('nginx.revert');
    cur = (await api('get', `/gateway-plans/${p.id}`)).body.data;
    expect(cur.status).toBe('rolled_back');
    expect(disk['/etc/nginx/ppanel-gateway/shop.example.lab.conf']).toBeUndefined();
    const plans = await api('get', `/gateways/${gw.id}/plans`, viewer);
    expect(plans.body.paginate.total).toBe(2);
    const actions = (
      await t.prisma.auditEvent.findMany({ where: { action: { startsWith: 'gateway_plans.' } } })
    ).map((a) => `${a.action}:${a.result}`);
    expect(actions).toEqual(
      expect.arrayContaining([
        'gateway_plans.create:success',
        'gateway_plans.shadow_test:success',
        'gateway_plans.apply:success',
        'gateway_plans.rollback:success',
        'gateway_plans.cancel:success',
        'gateway_plans.status:success',
      ]),
    );
  });
});

describe('P9-T4 production gateway: second-person approval with step-up, bound to the shadow results', () => {
  it('approve needs shadow test, another user, step-up and the current planHash; apply needs step-up', async () => {
    const { gw, gwServer, backend } = await setup('production');
    await api('post', `/gateways/${gw.id}/routes`, owner, {
      domain: 'shop.example.lab',
      mode: 'gateway',
      backends: [{ serverId: backend, port: 8080 }],
    });
    const { plan: p } = await plan(gw.id, gwServer);
    expect(p).toMatchObject({ status: 'validated', approval: { required: true } });
    expect(p.cutover.dnsChanges[0]).toMatchObject({
      action: 'point_to_gateway',
      target: '203.0.113.2',
      directTarget: '198.51.100.11',
    });
    const suOwner = await stepUpToken(t, owner);
    const suAdmin = await stepUpToken(t, admin);
    let r = await api('post', `/gateway-plans/${p.id}/apply`, owner, {}, suOwner);
    expect(r.body.error.code).toBe('GATEWAY_PLAN_STATE_INVALID');
    r = await api(
      'post',
      `/gateway-plans/${p.id}/approve`,
      admin,
      { planHash: p.planHash },
      suAdmin,
    );
    expect(r.body.error.code).toBe('SHADOW_TEST_REQUIRED');
    await api('post', `/gateway-plans/${p.id}/shadow-test`, owner, {});
    await serve(gwServer);
    await serve(gwServer);
    let cur = (await api('get', `/gateway-plans/${p.id}`)).body.data;
    expect(cur.status).toBe('awaiting_approval');
    r = await api(
      'post',
      `/gateway-plans/${p.id}/approve`,
      owner,
      { planHash: cur.planHash },
      suOwner,
    );
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('APPROVER_IS_CREATOR');
    r = await api('post', `/gateway-plans/${p.id}/approve`, admin, { planHash: cur.planHash });
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    r = await api(
      'post',
      `/gateway-plans/${p.id}/approve`,
      admin,
      { planHash: p.planHash },
      suAdmin,
    );
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('PLAN_HASH_MISMATCH');
    r = await api(
      'post',
      `/gateway-plans/${p.id}/approve`,
      admin,
      { planHash: cur.planHash },
      suAdmin,
    );
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.data.approval).toMatchObject({ required: true, approvedBy: expect.any(String) });
    expect(r.body.data.nginxRevisionStatus).toBe('approved');
    // approved plan cannot be re-shadow-tested (would change the bound hash)
    expect(
      (await api('post', `/gateway-plans/${p.id}/shadow-test`, owner, {})).body.error.code,
    ).toBe('GATEWAY_PLAN_STATE_INVALID');
    r = await api('post', `/gateway-plans/${p.id}/apply`, owner, {});
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    r = await api('post', `/gateway-plans/${p.id}/apply`, owner, {}, suOwner);
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    await serve(gwServer);
    cur = (await api('get', `/gateway-plans/${p.id}`)).body.data;
    expect(cur.status).toBe('applied');
    r = await api('post', `/gateway-plans/${p.id}/rollback`, owner, {});
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    // tampering with a stored plan after the shadow test is detected (hash recomputed on approve)
    const p2route = await api('post', `/gateways/${gw.id}/routes`, owner, {
      domain: 'b.example.lab',
      backends: [{ serverId: backend, port: 8080 }],
    });
    expect(p2route.status).toBe(201);
    const second = await plan(gw.id, gwServer);
    await api('post', `/gateway-plans/${second.plan.id}/shadow-test`, owner, {});
    for (let k = 0; k < 4; k++) await serve(gwServer);
    const ready = (await api('get', `/gateway-plans/${second.plan.id}`)).body.data;
    expect(ready.status).toBe('awaiting_approval');
    await t.prisma.gatewayChangePlan.update({
      where: { id: second.plan.id },
      data: {
        routesSnapshot: [
          {
            ...ready.routesSnapshot[0],
            backends: [{ serverId: backend, address: '10.66.6.6', port: 1 }],
          },
        ],
      },
    });
    r = await api(
      'post',
      `/gateway-plans/${second.plan.id}/approve`,
      admin,
      { planHash: ready.planHash },
      suAdmin,
    );
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('PLAN_HASH_MISMATCH');
  });
});
