import {
  agentEnrollSchema,
  createGatewayRouteSchema,
  dialOrder,
  heartbeatSchema,
  type GatewayRoute,
  isDiagnosePrivateAddress,
  JOB_TYPES,
  networkInventoryInputSchema,
  policyAllowsPath,
} from '@ppanel/shared-contracts';
import { describe, expect, it } from 'vitest';
import { loadConfig, normalizeApiBase, parseGatewayListeners } from '../../src/config/config';
import {
  checkDiagnoseTargets,
  centerEndpointAddresses,
} from '../../src/network/diagnostics.service';
import { checkApiBase, DoClient, normalizeDroplet } from '../../src/network/do-client';
import {
  buildCutover,
  computeGatewayPlanHash,
  renderPlanFiles,
  renderRouteConf,
} from '../../src/network/gateway-render';
import {
  hasHealthyPrivateProbe,
  networkView,
  preferredIpv4,
} from '../../src/network/network-common';
import { matchDroplets } from '../../src/network/provider.service';
import { computeTopology } from '../../src/network/topology';
import { isGatewayPath } from '../../src/nginx/nginx-revisions.service';

const testableConfig = (o: Record<string, string>) =>
  loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://x',
    PPANEL_MASTER_KEY: Buffer.alloc(32, 1).toString('base64'),
    JWT_ACCESS_SECRET: 'j'.repeat(40),
    AGENT_GATEWAY_HOST: '0.0.0.0',
    AGENT_GATEWAY_PORT: '4443',
    PPANEL_PUBLIC_GATEWAY_URL: 'https://localhost:4443',
    PPANEL_GATEWAY_LISTENERS: '',
    PPANEL_PRIVATE_GATEWAY_URL: '',
    PPANEL_DO_API_BASE: '',
    ...o,
  });

const inv = (source: string, extra: Record<string, unknown> = {}) => ({
  source,
  region: null,
  vpcUuid: null,
  vpcName: null,
  dropletId: null,
  privateIpv4: null,
  publicIpv4: null,
  observedAt: new Date(),
  ...extra,
});

describe('P9 §1 management paths', () => {
  it('parses listener labels; default is one public listener', () => {
    expect(parseGatewayListeners('public=0.0.0.0:4443,private=[::]:4444')).toEqual([
      { label: 'public', host: '0.0.0.0', port: 4443 },
      { label: 'private', host: '::', port: 4444 },
    ]);
    for (const bad of [
      'vpn=0.0.0.0:1',
      'public=0.0.0.0',
      'public=a:1,public=b:2',
      'public=h:99999',
      '',
    ])
      expect(() => parseGatewayListeners(bad), bad).toThrow(/PPANEL_GATEWAY_LISTENERS/);
    const c = testableConfig({});
    expect(c.gatewayListeners).toEqual([{ label: 'public', host: '0.0.0.0', port: 4443 }]);
    expect(c.gatewayEndpoints).toEqual([{ path: 'public', url: 'https://localhost:4443' }]);
    const p = testableConfig({ PPANEL_PRIVATE_GATEWAY_URL: 'https://10.0.0.2:4444' });
    expect(p.gatewayEndpoints[1]).toEqual({ path: 'private', url: 'https://10.0.0.2:4444' });
    expect(() => testableConfig({ PPANEL_PRIVATE_GATEWAY_URL: 'http://10.0.0.2:4444' })).toThrow();
  });

  it('dial order per policy; private_only never dials public; enforcement fails closed', () => {
    expect(dialOrder('private_only', false)).toEqual(['private']);
    expect(dialOrder('public_only', true)).toEqual(['public']);
    expect(dialOrder('private_preferred', true)).toEqual(['private', 'public']);
    expect(dialOrder('public_preferred', true)).toEqual(['public', 'private']);
    expect(dialOrder('auto', true)).toEqual(['private', 'public']);
    expect(dialOrder('auto', false)).toEqual(['public']);
    expect(policyAllowsPath('private_only', 'public')).toBe(false);
    expect(policyAllowsPath('private_only', 'private')).toBe(true);
    expect(policyAllowsPath('public_only', 'private')).toBe(false);
    expect(policyAllowsPath('auto', 'public')).toBe(true);
    expect(policyAllowsPath('garbage', 'private')).toBe(true);
  });

  it('heartbeat P9 blocks are tolerant: agent shapes parse, malformed blocks are dropped, never a 422', () => {
    const base = { seq: 1, sentAt: new Date().toISOString(), agentVersion: '0.9.0' };
    const hb = heartbeatSchema.parse({
      ...base,
      connection: {
        policy: 'auto',
        activePath: null,
        endpoints: [
          {
            path: 'private',
            url: 'https://10.0.0.2:4444',
            ok: false,
            latencyMs: null,
            checkedAt: '2026-11-24T00:00:00.123456789Z',
            error: 'HTTP_502',
          },
        ],
      },
      provider: {
        name: 'digitalocean',
        dropletId: 123,
        region: '',
        interfaces: { private: null, public: ['203.0.113.1'] },
      },
    });
    expect(hb.connection?.endpoints[0]).toMatchObject({ ok: false, error: 'HTTP_502' });
    expect(hb.provider).toEqual({
      name: 'digitalocean',
      dropletId: '123',
      region: null,
      interfaces: { private: [], public: ['203.0.113.1'] },
    });
    const bad = heartbeatSchema.parse({
      ...base,
      connection: { endpoints: 'x' },
      provider: { name: 'aws' },
    });
    expect(bad.connection).toBeUndefined();
    expect(bad.provider).toBeUndefined();
    expect(heartbeatSchema.parse({ ...base, provider: null }).provider).toBeNull();
    const en = agentEnrollSchema.parse({
      token: 't',
      csrPem: 'x'.repeat(100),
      hostname: 'h',
      facts: { provider: { name: 'x' } },
    });
    expect(en.facts?.provider).toBeNull();
  });

  it('a healthy private probe must be ≤ 5 min old (Center clock) and ok', () => {
    const now = Date.now();
    const ep = (ok: boolean, path = 'private', checkedAt = new Date(now).toISOString()) => ({
      path,
      url: 'https://x',
      ok,
      latencyMs: 3,
      checkedAt,
    });
    expect(hasHealthyPrivateProbe(null)).toBe(false);
    expect(hasHealthyPrivateProbe({ endpoints: [ep(true)], reportedAt: new Date(now) }, now)).toBe(
      true,
    );
    expect(hasHealthyPrivateProbe({ endpoints: [ep(false)], reportedAt: new Date(now) }, now)).toBe(
      false,
    );
    expect(
      hasHealthyPrivateProbe({ endpoints: [ep(true, 'public')], reportedAt: new Date(now) }, now),
    ).toBe(false);
    expect(
      hasHealthyPrivateProbe(
        { endpoints: [ep(true)], reportedAt: new Date(now - 6 * 60_000) },
        now,
      ),
    ).toBe(false);
    expect(
      hasHealthyPrivateProbe(
        {
          endpoints: [ep(true, 'private', new Date(now - 10 * 60_000).toISOString())],
          reportedAt: new Date(now),
        },
        now,
      ),
    ).toBe(false);
  });
});

describe('P9 §2 provider inventory', () => {
  it('api_base allowlist: official default, lab base only when listed, http never in production', () => {
    const list = ['https://api.digitalocean.com', 'http://lab-do-fake:8080'];
    expect(checkApiBase(undefined, list, false)).toBe('https://api.digitalocean.com');
    expect(checkApiBase('http://lab-do-fake:8080/', list, false)).toBe('http://lab-do-fake:8080');
    for (const bad of [
      'http://169.254.169.254',
      'https://evil.example',
      'https://u:p@api.digitalocean.com',
      'ftp://x',
    ])
      expect(() => checkApiBase(bad, list, false), bad).toThrow(/not allowed/);
    expect(() => checkApiBase('http://lab-do-fake:8080', list, true)).toThrow(/not allowed/);
    expect(normalizeApiBase('https://api.digitalocean.com/?x=1')).toBeNull();
    expect(() =>
      testableConfig({ NODE_ENV: 'production', PPANEL_DO_API_BASE: 'http://x:1' }),
    ).toThrow();
  });

  it('client refuses every non-GET method and SSRF targets before any socket', async () => {
    const c = new DoClient({
      apiBase: 'https://api.digitalocean.com',
      token: 'TEST_FAKE_TOKEN',
      timeoutMs: 1000,
      allowPrivate: false,
      resolver: async () => [{ address: '10.0.0.1', family: 4 }],
    });
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'])
      await expect(c.request(m, '/v2/droplets')).rejects.toMatchObject({
        code: 'PROVIDER_API_NOT_ALLOWED',
      });
    await expect(c.get('/v2/account')).rejects.toMatchObject({ code: 'PROVIDER_API_NOT_ALLOWED' });
    await expect(c.get('/../x')).rejects.toMatchObject({ code: 'PROVIDER_API_NOT_ALLOWED' });
    const meta = new DoClient({
      apiBase: 'http://lab-do-fake:8080',
      token: 'x',
      timeoutMs: 1000,
      allowPrivate: true,
      resolver: async () => [{ address: '169.254.169.254', family: 4 }],
    });
    await expect(meta.get('/v2/account')).rejects.toMatchObject({
      code: 'PROVIDER_API_NOT_ALLOWED',
    });
  });

  it('droplets match servers by droplet id first, then by a unique private IPv4', () => {
    const droplets = [
      {
        id: 101,
        region: { slug: 'sgp1' },
        vpc_uuid: 'vpc-a',
        networks: { v4: [{ ip_address: '10.0.0.9', type: 'private' }] },
      },
      {
        id: 102,
        region: { slug: 'sgp1' },
        vpc_uuid: 'vpc-b',
        networks: {
          v4: [
            { ip_address: '10.1.0.5', type: 'private' },
            { ip_address: '203.0.113.7', type: 'public' },
          ],
        },
      },
      {
        id: 103,
        region: { slug: 'sgp1' },
        vpc_uuid: 'vpc-b',
        networks: { v4: [{ ip_address: '10.9.9.9', type: 'private' }] },
      },
      { id: 104, networks: { v4: [{ ip_address: '10.2.0.1', type: 'private' }] } },
      { id: 'bad id' },
    ];
    const r = matchDroplets(
      droplets,
      [{ id: 'vpc-b', name: 'lab-b' }],
      [
        { id: 's1', dropletId: '101', privateIpv4s: ['10.5.5.5'] },
        { id: 's2', dropletId: null, privateIpv4s: ['10.1.0.5'] },
        { id: 's3', dropletId: null, privateIpv4s: ['10.2.0.1'] },
        { id: 's4', dropletId: null, privateIpv4s: ['10.2.0.1'] },
      ],
    );
    expect(r.matches.map((m) => [m.serverId, m.dropletId, m.matchedBy])).toEqual([
      ['s1', '101', 'droplet_id'],
      ['s2', '102', 'private_ipv4'],
    ]);
    expect(r.matches[1]).toMatchObject({
      vpcUuid: 'vpc-b',
      vpcName: 'lab-b',
      publicIpv4: '203.0.113.7',
    });
    expect(r.unmatched).toBe(3); // 103 no server, 104 ambiguous, bad id
    expect(normalizeDroplet({ id: 1, region: { slug: 'X;Y' }, vpc_uuid: 'a b' })).toMatchObject({
      region: null,
      vpcUuid: null,
    });
  });

  it('VPC comes only from provider/inventory; agent facts never set it', () => {
    expect(networkView([inv('agent', { region: 'sgp1', vpcUuid: 'should-not-happen' })])).toEqual({
      region: 'sgp1',
      vpcUuid: null,
      vpcName: null,
      vpcSource: null,
    });
    expect(
      networkView([
        inv('inventory', { vpcUuid: 'v-i' }),
        inv('provider', { vpcUuid: 'v-p', region: 'r' }),
      ]),
    ).toMatchObject({ vpcUuid: 'v-p', vpcSource: 'provider', region: 'r' });
    expect(
      preferredIpv4(
        [{ family: 'ipv4', scope: 'private', address: '10.0.0.3', source: 'detected' }],
        [inv('inventory', { privateIpv4: '10.0.0.4' })],
        'private',
      ),
    ).toBe('10.0.0.4');
  });

  it('topology groups by region/VPC and emits every finding code', () => {
    const old = new Date(Date.now() - 25 * 3_600_000);
    const t = computeTopology([
      {
        id: 'a',
        name: 'a',
        addresses: [],
        inventory: [
          inv('provider', {
            region: 'lab1',
            vpcUuid: 'vpc-a',
            vpcName: 'A',
            privateIpv4: '10.0.0.1',
          }),
        ],
      },
      {
        id: 'b',
        name: 'b',
        addresses: [],
        inventory: [
          inv('provider', {
            region: 'lab1',
            vpcUuid: 'vpc-b',
            privateIpv4: '10.0.0.1',
            observedAt: old,
          }),
        ],
      },
      { id: 'c', name: 'c', addresses: [], inventory: [inv('agent', { region: 'lab1' })] },
      {
        id: 'd',
        name: 'd',
        addresses: [],
        inventory: [
          inv('provider', { region: 'lab2', vpcUuid: 'vpc-x' }),
          inv('inventory', { region: 'lab2', vpcUuid: 'vpc-y' }),
        ],
      },
      { id: 'e', name: 'e', addresses: [], inventory: [] },
    ]);
    const lab1 = t.regions.find((r) => r.region === 'lab1')!;
    expect(lab1.vpcs.map((v) => [v.vpcUuid, v.servers])).toEqual([
      ['vpc-a', ['a']],
      ['vpc-b', ['b']],
    ]);
    expect(lab1.unknownVpc).toEqual(['c']);
    expect(t.regions.at(-1)).toMatchObject({ region: null, unknownVpc: ['e'] });
    const codes = Object.fromEntries(t.findings.map((f) => [f.code, f.serverIds]));
    expect(codes).toEqual({
      VPC_UNKNOWN: ['c', 'e'],
      SAME_REGION_DIFFERENT_VPC: ['a', 'b'],
      PRIVATE_IP_CONFLICT: ['a', 'b'],
      PROVIDER_STALE: ['b'],
      INVENTORY_MISMATCH: ['d'],
    });
  });

  it('inventory body: strict rows, ≤ 500, exactly one of serverId/hostname, bare array accepted', () => {
    const ok = networkInventoryInputSchema.safeParse([
      { hostname: 'node-a', vpcUuid: 'v-1', privateIpv4: '10.0.0.2' },
    ]);
    expect(ok.success).toBe(true);
    for (const bad of [
      { rows: [] },
      { rows: [{ hostname: 'a', serverId: '0190a6b8-0000-7000-8000-000000000000' }] },
      { rows: [{ hostname: 'a', extra: 1 }] },
      { rows: [{ hostname: 'a', privateIpv4: '10.0.0.300' }] },
      { rows: Array.from({ length: 501 }, () => ({ hostname: 'a' })) },
    ])
      expect(networkInventoryInputSchema.safeParse(bad).success).toBe(false);
  });
});

describe('P9 §4 diagnostics', () => {
  it('targets: private ranges or a Center endpoint IP, allowed ports only', () => {
    expect(
      ['10.1.2.3', '172.20.0.1', '192.168.1.1', '100.64.0.9', 'fd12::1'].every(
        isDiagnosePrivateAddress,
      ),
    ).toBe(true);
    expect(
      ['8.8.8.8', '127.0.0.1', '169.254.169.254', '172.32.0.1', '::1', 'fe80::1'].some(
        isDiagnosePrivateAddress,
      ),
    ).toBe(false);
    const center = centerEndpointAddresses({
      gatewayEndpoints: [
        { path: 'public', url: 'https://203.0.113.5:4443' },
        { path: 'private', url: 'https://center.internal:4444' },
      ],
    });
    expect([...center]).toEqual(['203.0.113.5']);
    const bad = checkDiagnoseTargets(
      {
        tcp: [
          { host: '10.0.0.5', port: 5432 },
          { host: '203.0.113.5', port: 4443 },
          { host: '8.8.8.8', port: 53 },
          { host: '10.0.0.5', port: 8080 },
          { host: '10.0.0.6', port: 20001 },
        ],
        allowedPorts: [20001],
      },
      center,
    );
    expect(bad.map((b) => [b.index, b.reason])).toEqual([
      [2, 'host_not_private'],
      [3, 'port_not_allowed'],
    ]);
  });

  it('job params are strict; network.diagnose + http.probe are read-only typed jobs', () => {
    expect(JOB_TYPES['network.diagnose'].mutating).toBe(false);
    expect(JOB_TYPES['http.probe'].mutating).toBe(false);
    const d = JOB_TYPES['network.diagnose'].params;
    expect(d.parse({})).toEqual({ resolve: [], tcp: [], includeRoutes: false, allowedPorts: [] });
    expect(d.safeParse({ tcp: [{ host: 'example.com', port: 1 }] }).success).toBe(false);
    expect(d.safeParse({ resolve: Array(11).fill('a.example') }).success).toBe(false);
    expect(d.safeParse({ resolve: ['a;b'] }).success).toBe(false);
    const h = JOB_TYPES['http.probe'].params;
    expect(
      h.parse({ url: 'http://shop.example.lab/healthz', resolveTo: '10.0.0.2' }),
    ).toMatchObject({
      method: 'GET',
      timeoutSec: 10,
    });
    for (const url of [
      'http://shop.example.lab:8080/',
      'http://user@shop.example.lab/',
      'file:///etc/passwd',
      'http://10.0.0.1/',
      'http://a.example/ x',
    ])
      expect(h.safeParse({ url, resolveTo: '10.0.0.2' }).success, url).toBe(false);
    expect(
      h.safeParse({ url: 'http://a.example/', resolveTo: '10.0.0.2', method: 'POST' }).success,
    ).toBe(false);
    expect(
      h.safeParse({ url: 'http://a.example/', resolveTo: '10.0.0.2', timeoutSec: 11 }).success,
    ).toBe(false);
  });
});

describe('P9 §5 gateway rendering', () => {
  const route = (over: Partial<GatewayRoute> = {}): GatewayRoute => ({
    id: '0190a6b8-1111-7000-8000-00000000abcd',
    gatewayId: 'g',
    domain: 'shop.example.lab',
    mode: 'hybrid',
    backends: [{ serverId: 's', address: '10.110.0.11', port: 8080 }],
    healthPath: '/healthz',
    createdAt: '',
    updatedAt: '',
    version: 1,
    ...over,
  });

  it('renders upstream-by-private-address server blocks and nothing user-controlled', () => {
    const conf = renderRouteConf('gw-1', route());
    expect(conf).toContain('server_name shop.example.lab;');
    expect(conf).toContain('server 10.110.0.11:8080 max_fails=3 fail_timeout=10s;');
    expect(conf).toMatch(/proxy_pass http:\/\/ppanel_gw_shop_example_lab_[0-9a-f]{8};/);
    for (const domain of [
      'a.example;\n}',
      'evil.example lua',
      '*.example.com',
      '$host.example',
      'x',
    ])
      expect(() => renderRouteConf('g', route({ domain })), domain).toThrow();
    expect(() =>
      renderRouteConf('g', route({ backends: [{ serverId: 's', address: '10.0.0.1;', port: 1 }] })),
    ).toThrow();
    for (const domain of ['a.example;}', 'EXAMPLE..com', 'a b.com', 'ex ample.com', '1.2.3.4'])
      expect(
        createGatewayRouteSchema.safeParse({
          domain,
          backends: [{ serverId: '0190a6b8-1111-7000-8000-00000000abcd', port: 80 }],
        }).success,
        domain,
      ).toBe(false);
    expect(
      createGatewayRouteSchema.safeParse({
        domain: 'shop.example.lab',
        backends: [{ serverId: '0190a6b8-1111-7000-8000-00000000abcd', port: 80 }],
        healthPath: '/x;rewrite',
      }).success,
    ).toBe(false);
  });

  it('plan files: include + one file per hybrid/gateway route + stubs for removed domains', () => {
    const files = renderPlanFiles(
      'gw',
      [
        route(),
        route({
          id: '0190a6b8-1111-7000-8000-00000000abce',
          domain: 'direct.example.lab',
          mode: 'direct',
        }),
      ],
      [
        { path: '/etc/nginx/ppanel-gateway/old.example.lab.conf', lastKnownSha256: 'a'.repeat(64) },
        { path: '/etc/nginx/ppanel-gateway/gone.example.lab.conf', lastKnownSha256: null },
      ],
    );
    expect(files.map((f) => f.path)).toEqual([
      '/etc/nginx/conf.d/ppanel-gateway.conf',
      '/etc/nginx/ppanel-gateway/shop.example.lab.conf',
      '/etc/nginx/ppanel-gateway/old.example.lab.conf',
    ]);
    expect(files[2]!.content).toMatch(/no longer routed/);
    expect(files.every((f) => isGatewayPath(f.path))).toBe(true);
    expect(isGatewayPath('/etc/nginx/ppanel-gateway/a/b.conf')).toBe(false);
    expect(isGatewayPath('/etc/nginx/ppanel-gateway/../nginx.conf')).toBe(false);
    expect(isGatewayPath('/etc/nginx/conf.d/other.conf')).toBe(false);
  });

  it('plan hash binds routes, rendered files, revision plan and shadow results', () => {
    const base = {
      gatewayId: 'g',
      routes: [route()],
      rendered: [{ path: '/x', sha256: 'a' }],
      revisionPlanHash: 'r',
      shadowResults: null,
    };
    const h = computeGatewayPlanHash(base);
    expect(computeGatewayPlanHash({ ...base })).toBe(h);
    expect(computeGatewayPlanHash({ ...base, routes: [route({ mode: 'gateway' })] })).not.toBe(h);
    expect(computeGatewayPlanHash({ ...base, rendered: [{ path: '/x', sha256: 'b' }] })).not.toBe(
      h,
    );
    expect(computeGatewayPlanHash({ ...base, revisionPlanHash: 's' })).not.toBe(h);
    const shadow = [
      {
        domain: 'd',
        url: 'u',
        match: true,
        viaGateway: { status: 200, latencyMs: 1, bodySha256: 'x' },
        direct: { status: 200, latencyMs: 1, bodySha256: 'x' },
      },
    ];
    expect(computeGatewayPlanHash({ ...base, shadowResults: shadow })).not.toBe(h);
  });

  it('cutover: DNS instructions + rollback, never an edit', () => {
    const c = buildCutover(
      'plan-1',
      [route({ mode: 'gateway' }), route({ domain: 'b.example.lab' })],
      { publicIpv4: '203.0.113.9', privateIpv4: '10.0.0.9' },
      () => '198.51.100.3',
    );
    expect(c.dnsChanges).toEqual([
      {
        domain: 'b.example.lab',
        mode: 'hybrid',
        recordType: 'A',
        target: '198.51.100.3',
        directTarget: '198.51.100.3',
        action: 'none',
      },
      {
        domain: 'shop.example.lab',
        mode: 'gateway',
        recordType: 'A',
        target: '203.0.113.9',
        directTarget: '198.51.100.3',
        action: 'point_to_gateway',
      },
    ]);
    expect(c.rollback.join(' ')).toMatch(/gateway-plans\/plan-1\/rollback/);
    expect(c.note).toMatch(/never edits DNS/);
    expect(c.verification[0]).toContain('--resolve b.example.lab:80:203.0.113.9');
  });
});
