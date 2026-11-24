import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Server } from '@ppanel/shared-contracts';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import { isApiError } from '@/lib/api/errors';
import type { LoginSuccess } from '@/lib/api/types';
import type {
  Gateway,
  GatewayChangePlan,
  NetworkConnectivityTest,
  ProviderIntegration,
  ServerGroup,
  TestAccepted,
  Topology,
} from '@/lib/api/p9-types';

let offset = 0;
const realNow = Date.now.bind(Date);
const advance = (ms: number) => (offset += ms);

function client() {
  let tok: string | null = null;
  const c = createApiClient({
    baseUrl: 'http://mock/api/v1',
    clientVersion: 't',
    fetch: mockFetch as typeof fetch,
    tokenStore: { get: () => tok, set: (t) => (tok = t) },
  });
  return {
    c,
    async login(email: string) {
      const r = await c.post<LoginSuccess | { mfaRequired: true; mfaToken: string }>(
        '/auth/login',
        { email, password: 'password' },
        { auth: false },
      );
      if ('mfaToken' in r) {
        const v = await c.post<LoginSuccess>(
          '/auth/mfa/verify',
          { mfaToken: r.mfaToken, code: '123456' },
          { auth: false },
        );
        tok = v.accessToken;
      } else tok = r.accessToken;
    },
    async stepUp() {
      return (await c.post<{ stepUpToken: string }>('/auth/step-up', { code: '123456' }))
        .stepUpToken;
    },
  };
}
const fail = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => (isApiError(e) ? e : null),
  );

beforeEach(() => {
  resetMockState();
  offset = 0;
  vi.spyOn(Date, 'now').mockImplementation(() => realNow() + offset);
});
afterEach(() => vi.restoreAllMocks());

type C = ReturnType<typeof client>['c'];
const servers = async (c: C) => (await c.list<Server>('/servers', { query: { limit: 100 } })).items;
const byName = async (c: C, name: string) => (await servers(c)).find((s) => s.name === name)!;

describe('mock P9 (docs/P9_NETWORK_CONTRACT.md)', () => {
  it('server view: connection probes, fail-closed private_only, VPC only from provider/inventory', async () => {
    const { c, login } = client();
    await login('admin');
    const all = await servers(c);
    const db = all.find((s) => s.name === 'db-prod-01')!;
    expect(db.connectionPolicy).toBe('private_only');
    expect(db.connection.activePath).toBeNull();
    expect(db.connection.endpoints.find((e) => e.path === 'private')).toMatchObject({
      ok: false,
      error: 'DIAL_TIMEOUT',
    });
    expect(db.connection.endpoints.find((e) => e.path === 'public')!.ok).toBe(true);
    const app = all.find((s) => s.name === 'app-prod-01')!;
    expect(app.connection.activePath).toBe('private');
    expect(app.network).toMatchObject({ vpcName: 'prod-sgp1', vpcSource: 'provider' });
    expect(app.groupName).toBe('storefront');
    // dev servers only have agent facts (seed provider.vpcUuid is set) → still unknown
    const dev = all.find((s) => s.name === 'dev-01')!;
    expect(dev.provider?.vpcUuid).toBeTruthy();
    expect(dev.network.vpcUuid).toBeNull();
    expect(dev.network.vpcSource).toBeNull();
    expect(all.find((s) => s.name === 'app-uat-01')!.network.vpcSource).toBe('inventory');
    // filters
    const pol = await c.list<Server>('/servers', { query: { connection_policy: 'private_only' } });
    expect(pol.items.every((s) => s.connectionPolicy === 'private_only')).toBe(true);
    const tag = await c.list<Server>('/servers', { query: { 'tags[contains]': 'legacy' } });
    expect(tag.items.map((s) => s.name)).toEqual(['web-legacy-02']);
  });

  it('topology: two VPCs in one region, unknown VPCs and provider/inventory mismatch', async () => {
    const { c, login } = client();
    await login('user1');
    const topo = await c.get<Topology>('/network/topology');
    const sgp1 = topo.regions.find((r) => r.region === 'sgp1')!;
    expect(sgp1.vpcs.map((v) => v.vpcName).sort()).toEqual([
      'default-sgp1',
      'prod-sgp1',
      'uat-sgp1',
    ]);
    expect(sgp1.unknownVpc).toHaveLength(2);
    const codes = topo.findings.map((f) => f.code);
    expect(codes).toEqual(
      expect.arrayContaining(['VPC_UNKNOWN', 'SAME_REGION_DIFFERENT_VPC', 'INVENTORY_MISMATCH']),
    );
  });

  it('policy change: step-up in production, 422 PRIVATE_PATH_UNVERIFIED, non-prod without step-up', async () => {
    const { c, login, stepUp } = client();
    await login('superadmin');
    const legacy = await byName(c, 'web-legacy-02');
    const headers = { 'If-Match': String(legacy.version) };
    const noStep = await fail(
      c.patch(`/servers/${legacy.id}`, { connectionPolicy: 'private_only' }, { headers }),
    );
    expect(noStep).toMatchObject({ status: 403, code: 'STEP_UP_REQUIRED' });
    const unverified = await fail(
      c.patch(
        `/servers/${legacy.id}`,
        { connectionPolicy: 'private_only' },
        { headers: { ...headers, 'X-Step-Up': await stepUp() } },
      ),
    );
    expect(unverified).toMatchObject({ status: 422, code: 'PRIVATE_PATH_UNVERIFIED' });
    expect((unverified!.details as { lastPrivateProbe: { ok: boolean } }).lastPrivateProbe.ok).toBe(
      false,
    );
    const sandbox = await byName(c, 'dev-sandbox-02');
    const ok = await c.patch<Server>(
      `/servers/${sandbox.id}`,
      { connectionPolicy: 'private_only' },
      { headers: { 'If-Match': String(sandbox.version) } },
    );
    expect(ok.connectionPolicy).toBe('private_only');
    expect(ok.connection.activePath).toBe('private');
  });

  it('groups: create, assign, 409 GROUP_NOT_EMPTY, unassign with groupId null, delete', async () => {
    const { c, login } = client();
    await login('superadmin');
    const g = await c.post<ServerGroup>('/server-groups', {
      name: 'edge',
      environment: 'development',
    });
    expect(g.serverCount).toBe(0);
    const dup = await fail(c.post('/server-groups', { name: 'Edge' }));
    expect(dup?.status).toBe(422);
    const dev = await byName(c, 'dev-01');
    await c.patch(
      `/servers/${dev.id}`,
      { groupId: g.id },
      { headers: { 'If-Match': String(dev.version) } },
    );
    expect((await byName(c, 'dev-01')).groupName).toBe('edge');
    const filtered = await c.list<Server>('/servers', { query: { group_id: g.id } });
    expect(filtered.items.map((s) => s.name)).toEqual(['dev-01']);
    const notEmpty = await fail(c.del(`/server-groups/${g.id}`));
    expect(notEmpty).toMatchObject({ status: 409, code: 'GROUP_NOT_EMPTY' });
    const fresh = await byName(c, 'dev-01');
    await c.request('PATCH', `/servers/${dev.id}`, {
      body: { groupId: null },
      keepNulls: true,
      headers: { 'If-Match': String(fresh.version) },
    });
    expect((await byName(c, 'dev-01')).groupId).toBeNull();
    await c.patch<ServerGroup>(`/server-groups/${g.id}`, { description: 'renamed' });
    await c.del(`/server-groups/${g.id}`);
    expect((await c.list<ServerGroup>('/server-groups')).items.some((x) => x.id === g.id)).toBe(
      false,
    );
  });

  it('inventory import sets a VPC with source inventory; strict rows', async () => {
    const { c, login } = client();
    await login('superadmin');
    const bad = await fail(
      c.post('/network/inventory', { rows: [{ hostname: 'dev-01', colour: 'x' }] }),
    );
    expect(bad?.status).toBe(422);
    const unresolved = await fail(
      c.post('/network/inventory', { rows: [{ hostname: 'nope-01' }] }),
    );
    expect(unresolved?.code).toBe('INVENTORY_SERVER_UNRESOLVED');
    await c.post('/network/inventory', {
      rows: [
        {
          hostname: 'dev-01',
          region: 'sgp1',
          vpcUuid: '9e7a6b54-1c2d-4e3f-8a9b-0c1d2e3f4a5b',
          vpcName: 'dev-sgp1',
        },
      ],
    });
    const dev = await byName(c, 'dev-01');
    expect(dev.network).toMatchObject({ vpcName: 'dev-sgp1', vpcSource: 'inventory' });
  });

  it('provider integration: step-up, token validated and never returned, sync 202', async () => {
    const { c, login, stepUp } = client();
    await login('superadmin');
    const body = { provider: 'digitalocean', name: 'do-lab', token: 'dop_v1_0123456789abcdef0123' };
    expect(await fail(c.post('/provider-integrations', body))).toMatchObject({
      code: 'STEP_UP_REQUIRED',
    });
    const bad = await fail(
      c.post(
        '/provider-integrations',
        { ...body, token: 'dop_v1_bad_token_000000' },
        { headers: { 'X-Step-Up': await stepUp() } },
      ),
    );
    expect(bad?.code).toBe('PROVIDER_AUTH_FAILED');
    const created = await c.post<ProviderIntegration>('/provider-integrations', body, {
      headers: { 'X-Step-Up': await stepUp() },
    });
    expect(JSON.stringify(created)).not.toContain(body.token);
    const list = (await c.list<ProviderIntegration>('/provider-integrations')).items;
    expect(JSON.stringify(list)).not.toContain(body.token);
    await c.post(`/provider-integrations/${created.id}/sync`);
    expect(await fail(c.post(`/provider-integrations/${created.id}/sync`))).toMatchObject({
      code: 'PROVIDER_SYNC_IN_PROGRESS',
    });
    advance(2000);
    const after = (await c.list<ProviderIntegration>('/provider-integrations')).items.find(
      (i) => i.id === created.id,
    )!;
    expect(after.syncInProgress).toBe(false);
    expect(after.lastSyncAt).not.toBeNull();
  });

  it('diagnostics and pair tests: same VPC reachable, cross-VPC not, public targets refused', async () => {
    const { c, login } = client();
    await login('superadmin');
    const app = await byName(c, 'app-prod-01');
    const refused = await fail(
      c.post(`/servers/${app.id}/network-diagnostics`, { tcp: [{ host: '8.8.8.8', port: 443 }] }),
    );
    expect(refused?.code).toBe('DIAGNOSE_TARGET_NOT_ALLOWED');
    const r = await c.post<TestAccepted>(`/servers/${app.id}/network-diagnostics`, {
      resolve: ['center.ppanel.internal'],
      tcp: [
        { host: '10.104.0.12', port: 5432 },
        { host: '10.130.0.20', port: 80 },
      ],
      includeRoutes: true,
    });
    advance(2000);
    const t = await c.get<NetworkConnectivityTest>(`/network-diagnostics/${r.testId}`);
    expect(t.status).toBe('succeeded');
    expect(t.result!.tcp.map((x) => x.ok)).toEqual([true, false]);
    expect(t.result!.routes.length).toBeGreaterThan(0);
    expect(t.result!.centerEndpoints.map((e) => e.path).sort()).toEqual(['private', 'public']);

    const dev = await byName(c, 'dev-01');
    const sandbox = await byName(c, 'dev-sandbox-02');
    const legacy = await byName(c, 'web-legacy-02');
    const same = await c.post<TestAccepted>('/network/connectivity-tests', {
      fromServerId: dev.id,
      toServerId: sandbox.id,
      port: 22,
    });
    const cross = await c.post<TestAccepted>('/network/connectivity-tests', {
      fromServerId: app.id,
      toServerId: legacy.id,
      port: 80,
    });
    advance(2000);
    expect(
      (await c.get<NetworkConnectivityTest>(`/network-diagnostics/${same.testId}`)).reachable,
    ).toBe(true);
    expect(
      (await c.get<NetworkConnectivityTest>(`/network-diagnostics/${cross.testId}`)).reachable,
    ).toBe(false);
    const list = await c.list<NetworkConnectivityTest>(`/servers/${app.id}/network-diagnostics`);
    expect(list.items.length).toBe(2);
  });

  it('gateway plan: validate → shadow (mismatch shown) → approval by another person → apply → rollback', async () => {
    const admin = client();
    await admin.login('admin');
    const gws = (await admin.c.list<Gateway>('/gateways')).items;
    const prod = gws.find((g) => g.environment === 'production')!;
    expect(prod.routeCount).toBe(3);
    const created = await admin.c.post<GatewayChangePlan>(`/gateways/${prod.id}/plans`);
    expect(created.status).toBe('draft');
    expect(created.rendered.map((f) => f.path)).toEqual(
      expect.arrayContaining([
        '/etc/nginx/ppanel-gateway/shop.w3.co.conf',
        '/etc/nginx/conf.d/ppanel-gateway.conf',
      ]),
    );
    expect(created.rendered.some((f) => f.path.includes('api.w3.co'))).toBe(false); // direct
    advance(1500);
    expect((await admin.c.get<GatewayChangePlan>(`/gateway-plans/${created.id}`)).status).toBe(
      'validated',
    );
    const early = await fail(admin.c.post(`/gateway-plans/${created.id}/apply`));
    expect(early?.code).toBe('SHADOW_TEST_REQUIRED');
    await admin.c.post(`/gateway-plans/${created.id}/shadow-test`);
    advance(1500);
    const shadowed = await admin.c.get<GatewayChangePlan>(`/gateway-plans/${created.id}`);
    expect(shadowed.status).toBe('awaiting_approval');
    expect(shadowed.approval.required).toBe(true);
    const byDomain = Object.fromEntries(shadowed.shadowResults!.map((r) => [r.domain, r.match]));
    expect(byDomain).toEqual({ 'shop.w3.co': true, 'legacy.w3.co': false });
    expect(
      shadowed.cutover.dnsChanges.every(
        (d) => d.mode !== 'gateway' || d.action === 'point_to_gateway',
      ),
    ).toBe(true);
    expect(shadowed.cutover.rollback.length).toBeGreaterThan(0);
    // requester cannot approve their own plan
    const own = await fail(
      admin.c.post(`/gateway-plans/${created.id}/approve`, { planHash: shadowed.planHash }),
    );
    expect(own?.code).toBe('APPROVER_IS_CREATOR');
    expect(await fail(admin.c.post(`/gateway-plans/${created.id}/apply`))).toMatchObject({
      code: 'APPROVAL_REQUIRED',
    });

    const owner = client();
    await owner.login('superadmin');
    const stale = await fail(
      owner.c.post(
        `/gateway-plans/${created.id}/approve`,
        { planHash: 'f'.repeat(64) },
        { headers: { 'X-Step-Up': await owner.stepUp() } },
      ),
    );
    expect(stale?.code).toBe('PLAN_HASH_MISMATCH');
    const approved = await owner.c.post<GatewayChangePlan>(
      `/gateway-plans/${created.id}/approve`,
      { planHash: shadowed.planHash },
      { headers: { 'X-Step-Up': await owner.stepUp() } },
    );
    expect(approved.approval.approvedBy).toBeTruthy();
    expect(await fail(owner.c.post(`/gateway-plans/${created.id}/apply`))).toMatchObject({
      code: 'STEP_UP_REQUIRED',
    });
    await owner.c.post(`/gateway-plans/${created.id}/apply`, undefined, {
      headers: { 'X-Step-Up': await owner.stepUp() },
    });
    advance(1500);
    const applied = await owner.c.get<GatewayChangePlan>(`/gateway-plans/${created.id}`);
    expect(applied.status).toBe('applied');
    expect(applied.verification).not.toBeNull();
    await owner.c.post(`/gateway-plans/${created.id}/rollback`, undefined, {
      headers: { 'X-Step-Up': await owner.stepUp() },
    });
    advance(1500);
    expect((await owner.c.get<GatewayChangePlan>(`/gateway-plans/${created.id}`)).status).toBe(
      'rolled_back',
    );
  });

  it('gateway routes: domain taken, delete needs an empty gateway; dev gateway needs no approval', async () => {
    const { c, login } = client();
    await login('superadmin');
    const gws = (await c.list<Gateway>('/gateways')).items;
    const dev = gws.find((g) => g.environment === 'development')!;
    const devSrv = await byName(c, 'dev-01');
    const taken = await fail(
      c.post(`/gateways/${dev.id}/routes`, {
        domain: 'shop.w3.co',
        mode: 'hybrid',
        backends: [{ serverId: devSrv.id, port: 80 }],
      }),
    );
    expect(taken?.code).toBe('ROUTE_DOMAIN_TAKEN');
    expect(await fail(c.del(`/gateways/${dev.id}`))).toMatchObject({ code: 'GATEWAY_NOT_EMPTY' });
    const p = await c.post<GatewayChangePlan>(`/gateways/${dev.id}/plans`);
    advance(1500);
    await c.post(`/gateway-plans/${p.id}/shadow-test`);
    advance(1500);
    const done = await c.get<GatewayChangePlan>(`/gateway-plans/${p.id}`);
    expect(done.status).toBe('shadow_tested');
    expect(done.approval.required).toBe(false);
    expect(done.allowedActions).toContain('apply');
  });
});
