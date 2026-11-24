/**
 * Mock routes for docs/P9_NETWORK_CONTRACT.md, shaped like @ppanel/shared-contracts network.ts:
 * server groups, P9 server fields (connection probes, network view), provider integrations,
 * inventory import, topology + findings, network diagnostics, pair connectivity tests, gateways,
 * routes and change plans (validate → shadow test → approval → apply → rollback, cutover block).
 *
 * Fixtures (region sgp1):
 * - the provider (DigitalOcean) knows VPC prod-sgp1 (app-prod-01/02, db-prod-01) and default-sgp1
 *   (web-legacy-02): two VPCs in one region → SAME_REGION_DIFFERENT_VPC.
 * - the inventory import knows uat-sgp1 (worker-uat-01, app-uat-01) and claims web-legacy-02 is in
 *   prod-sgp1 → INVENTORY_MISMATCH. Dev servers only have agent facts → VPC_UNKNOWN.
 * - db-prod-01 is private_only and its private path is down (DIAL_TIMEOUT); public answers but is
 *   never dialed (fail closed). web-legacy-02's private path is down → switching it to private_only
 *   returns 422 PRIVATE_PATH_UNVERIFIED.
 * - gateways: edge-prod-sgp1 on app-prod-02 (production: approval + step-up) with shop.w3.co
 *   (hybrid, reachable), legacy.w3.co (hybrid → web-legacy-02's private address in another VPC:
 *   shadow-test mismatch) and api.w3.co (direct); edge-dev on dev-sandbox-02 (no approval).
 * Test hooks: a provider token containing "bad" → 422 PROVIDER_AUTH_FAILED; a route domain containing
 * "invalid" → nginx -t fails during plan validation.
 */
import { CONNECTION_POLICIES, type ConnectionPolicy, type Server } from '@ppanel/shared-contracts';
import { isHostname, isIpLiteral, isIpv4, isPrivateIp } from '@/lib/p9-gates';
import {
  DIAG_MAX_RESOLVE,
  DIAG_MAX_TCP,
  DIAG_PORTS,
  HEALTH_PATH_RE,
  ROUTE_MODES,
  dialOrder,
  type DiagnoseResult,
  type Gateway,
  type GatewayChangePlan,
  type GatewayCutover,
  type GatewayRoute,
  type MgmtPath,
  type NetworkConnectivityTest,
  type ProviderIntegration,
  type RouteBackend,
  type ServerGroup,
  type ServerNetworkInventory,
  type ServerView,
  type ShadowResult,
  type Topology,
  type TopologyFinding,
} from '@/lib/api/p9-types';
import type { P3Ctx } from './p3-routes';

const KEY = 'ppanel.mock.p9';
const TEST_MS = 1400;
const VALIDATE_MS = 900;
const SHADOW_MS = 1200;
const APPLY_MS = 1200;
const SYNC_MS = 1200;
const APPROVAL_TTL_MS = 60 * 60e3;
const CENTER_PRIVATE = '10.104.0.5';
const CENTER_PUBLIC = '159.89.200.5';

type DiagParams = {
  resolve: string[];
  tcp: Array<{ host: string; port: number }>;
  includeRoutes: boolean;
  port?: number;
};
type Probe = DiagnoseResult['centerEndpoints'][number];
interface U {
  id: string;
  displayName: string;
}
type GroupRec = Omit<ServerGroup, 'serverCount'>;
type IntegrationRec = Omit<ProviderIntegration, 'syncInProgress' | 'allowedActions'> & {
  syncUntil: number | null;
};
type TestRec = Omit<NetworkConnectivityTest, 'params'> & { params: DiagParams; doneAt: number };
type GwRec = Pick<Gateway, 'id' | 'serverId' | 'name' | 'status' | 'createdAt' | 'updatedAt'>;
type Running = 'shadow_testing' | 'applying' | 'rolling_back' | 'draft';
type PlanRec = Omit<GatewayChangePlan, 'cutover' | 'allowedActions' | 'approval'> & {
  approvedBy: string | null;
  approvedAt: string | null;
  approvalExpiresAt: string | null;
  pending: { status: Running; until: number } | null;
  /** route domain hook: nginx -t fails */
  nginxFails?: boolean;
  error?: { code: string; message: string } | null;
};
interface P9State {
  groups: GroupRec[];
  membership: Record<string, string>;
  policies: Record<string, ConnectionPolicy>;
  inventory: ServerNetworkInventory[];
  integrations: IntegrationRec[];
  tests: TestRec[];
  gateways: GwRec[];
  routes: GatewayRoute[];
  plans: PlanRec[];
}

let st: P9State | null = null;
let ctx: P3Ctx;

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}
function save() {
  try {
    storage()?.setItem(KEY, JSON.stringify(st));
  } catch {
    /* memory only */
  }
}
export function resetP9State() {
  st = null;
  storage()?.removeItem(KEY);
}

const iso = (ms: number) => new Date(ms).toISOString();
const ago = (sec: number) => iso(Date.now() - sec * 1000);
const rid = () => ctx.rid();
const byName = (n: string) => ctx.servers().find((x) => x.name === n);
const srvOf = (id: string) => ctx.servers().find((x) => x.id === id);
const userLabel = (id: string | null) => ctx.users().find((x) => x.id === id)?.displayName ?? null;
const userByName = (n: string) => ctx.users().find((x) => x.displayName === n);
const need = (u: U, perm: Parameters<P3Ctx['requirePerm']>[1], srv?: Server) =>
  ctx.requirePerm(u as never, perm, srv);
const can = (u: U, perm: Parameters<P3Ctx['hasPermFor']>[1], srv?: Server) =>
  ctx.hasPermFor(u as never, perm, srv);
const err = (status: number, code: string, message: string, details?: unknown) =>
  new ctx.HttpError(status, code, message, details);
const invalid = (details: Array<{ field: string; message: string }>) =>
  err(422, 'VALIDATION_FAILED', 'Validation failed', details);

/** Deterministic hex (FNV-1a + xorshift). */
function hex(seed: string, n = 64): string {
  let x = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    x ^= seed.charCodeAt(i);
    x = Math.imul(x, 16777619) >>> 0;
  }
  let out = '';
  while (out.length < n) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out += x.toString(16).padStart(8, '0');
  }
  return out.slice(0, n);
}

const addr = (s: Server, scope: 'public' | 'private') =>
  s.addresses.find((a) => a.scope === scope && a.family === 'ipv4');

// ---------------------------------------------------------------- seed

const VPC = {
  prod: { uuid: '5f1c2a9e-7b3d-4c11-9a0e-2d6b8f3e1c40', name: 'prod-sgp1' },
  legacy: { uuid: 'a07e44d1-90c2-4f6b-8e15-77c3d2b0f9aa', name: 'default-sgp1' },
  uat: { uuid: 'c3d90b12-5e7a-4a0f-b6d1-0e4f8a2c7b55', name: 'uat-sgp1' },
};

function invRow(
  s: Server,
  source: ServerNetworkInventory['source'],
  vpc: { uuid: string; name: string } | null,
  observedSecAgo: number,
): ServerNetworkInventory {
  return {
    serverId: s.id,
    source,
    region: 'sgp1',
    vpcUuid: vpc?.uuid ?? null,
    vpcName: vpc?.name ?? null,
    dropletId: source === 'inventory' ? null : (s.provider?.dropletId ?? null),
    privateIpv4: addr(s, 'private')?.address ?? null,
    publicIpv4: addr(s, 'public')?.address ?? null,
    observedAt: ago(observedSecAgo),
  };
}

function route(
  gatewayId: string,
  domain: string,
  mode: GatewayRoute['mode'],
  backends: RouteBackend[],
  healthPath: string,
  createdSecAgo: number,
): GatewayRoute {
  return {
    id: `01935f00-0000-7000-8000-${hex(domain, 12)}`,
    gatewayId,
    domain,
    mode,
    backends,
    healthPath,
    createdAt: ago(createdSecAgo),
    updatedAt: ago(createdSecAgo),
    version: 1,
  };
}

const backendOf = (srv: Server | undefined, port: number): RouteBackend[] =>
  srv ? [{ serverId: srv.id, address: addr(srv, 'private')?.address ?? '', port }] : [];

function seed() {
  const owner = userByName('Super Admin');
  const ops = userByName('Ops Admin');
  const inventory: ServerNetworkInventory[] = [];
  for (const s of ctx.servers()) inventory.push(invRow(s, 'agent', null, 20));
  const prov: Array<[string, typeof VPC.prod]> = [
    ['app-prod-01', VPC.prod],
    ['app-prod-02', VPC.prod],
    ['db-prod-01', VPC.prod],
    ['web-legacy-02', VPC.legacy],
  ];
  for (const [n, v] of prov) {
    const s = byName(n);
    if (s) inventory.push(invRow(s, 'provider', v, 7200));
  }
  const inv: Array<[string, typeof VPC.prod]> = [
    ['worker-uat-01', VPC.uat],
    ['app-uat-01', VPC.uat],
    ['web-legacy-02', VPC.prod], // disagrees with the provider → INVENTORY_MISMATCH
  ];
  for (const [n, v] of inv) {
    const s = byName(n);
    if (s) inventory.push(invRow(s, 'inventory', v, 86400 * 3));
  }

  const groups: GroupRec[] = [
    {
      id: '01935a00-0000-7000-8000-000000000001',
      name: 'storefront',
      description: 'Customer-facing web tier',
      environment: 'production',
      createdAt: ago(86400 * 20),
      updatedAt: ago(86400 * 2),
    },
    {
      id: '01935a00-0000-7000-8000-000000000002',
      name: 'data',
      description: 'Databases and caches',
      environment: 'production',
      createdAt: ago(86400 * 19),
      updatedAt: ago(86400 * 19),
    },
    {
      id: '01935a00-0000-7000-8000-000000000003',
      name: 'sandbox',
      description: null,
      environment: null,
      createdAt: ago(86400 * 5),
      updatedAt: ago(86400 * 5),
    },
  ];
  const membership: Record<string, string> = {};
  const put = (n: string, g: number) => {
    const s = byName(n);
    if (s) membership[s.id] = groups[g]!.id;
  };
  put('app-prod-01', 0);
  put('app-prod-02', 0);
  put('web-legacy-02', 0);
  put('db-prod-01', 1);

  const gateways: GwRec[] = [];
  const routes: GatewayRoute[] = [];
  const plans: PlanRec[] = [];
  const gwProd = byName('app-prod-02');
  if (gwProd) {
    const g: GwRec = {
      id: '01935b00-0000-7000-8000-000000000001',
      serverId: gwProd.id,
      name: 'edge-prod-sgp1',
      status: 'active',
      createdAt: ago(86400 * 6),
      updatedAt: ago(86400 * 6),
    };
    gateways.push(g);
    const a = byName('app-prod-01');
    routes.push(route(g.id, 'shop.w3.co', 'hybrid', backendOf(a, 8080), '/healthz', 86400 * 5));
    routes.push(
      route(g.id, 'legacy.w3.co', 'hybrid', backendOf(byName('web-legacy-02'), 80), '/', 86400 * 4),
    );
    routes.push(route(g.id, 'api.w3.co', 'direct', backendOf(a, 8081), '/healthz', 86400 * 4));
    // an earlier plan (applied two days ago) so the history is not empty
    const snap = routes.filter((r) => r.domain === 'shop.w3.co');
    const rendered = renderFiles(snap);
    const p: PlanRec = {
      id: '01935c00-0000-7000-8000-000000000001',
      gatewayId: g.id,
      status: 'applied',
      routesSnapshot: snap,
      rendered,
      planHash: '',
      nginxRevisionId: '01935d00-0000-7000-8000-000000000001',
      nginxRevisionStatus: 'applied',
      validation: { valid: true, nginxTestOutput: 'nginx: configuration file test is successful' },
      shadowResults: [
        {
          domain: 'shop.w3.co',
          url: 'http://shop.w3.co/healthz',
          viaGateway: { status: 200, latencyMs: 41, bodySha256: hex('shop.w3.co-body') },
          direct: { status: 200, latencyMs: 37, bodySha256: hex('shop.w3.co-body') },
          match: true,
        },
      ],
      verification: null,
      createdBy: ops?.id ?? '',
      approvedBy: owner?.id ?? null,
      approvedAt: ago(86400 * 2 + 600),
      approvalExpiresAt: ago(86400 * 2 - 3000),
      createdAt: ago(86400 * 2 + 1800),
      updatedAt: ago(86400 * 2),
      pending: null,
    };
    p.planHash = hashOf(p);
    plans.push(p);
  }
  const gwDev = byName('dev-sandbox-02');
  if (gwDev) {
    const g: GwRec = {
      id: '01935b00-0000-7000-8000-000000000002',
      serverId: gwDev.id,
      name: 'edge-dev',
      status: 'active',
      createdAt: ago(86400 * 3),
      updatedAt: ago(86400 * 3),
    };
    gateways.push(g);
    routes.push(
      route(g.id, 'preview.dev.w3.co', 'hybrid', backendOf(byName('dev-01'), 3000), '/', 86400 * 2),
    );
  }

  st = {
    groups,
    membership,
    policies: {},
    inventory,
    integrations: [
      {
        id: '01935e00-0000-7000-8000-000000000001',
        provider: 'digitalocean',
        name: 'do-main',
        apiBase: 'https://api.digitalocean.com',
        status: 'ok',
        lastSyncAt: ago(7200),
        lastError: null,
        lastSyncSummary: { droplets: 5, vpcs: 2, matched: 4, unmatched: 1 },
        createdBy: owner?.id ?? null,
        createdAt: ago(86400 * 10),
        updatedAt: ago(7200),
        syncUntil: null,
      },
    ],
    tests: [],
    gateways,
    routes,
    plans,
  };
}

function s(): P9State {
  if (!st) {
    const raw = storage()?.getItem(KEY);
    if (raw)
      try {
        st = JSON.parse(raw) as P9State;
      } catch {
        st = null;
      }
    if (!st) {
      seed();
      save();
    }
  }
  tick();
  return st!;
}

// ---------------------------------------------------------------- derived server fields

/** Ground truth for reachability in the mock world: the seed's real VPC (what DO would report). */
const realVpc = (srv: Server) => srv.provider?.vpcUuid ?? null;
const live = (srv: Server) => srv.status === 'online' || srv.status === 'degraded';

/** Probe fixture per server (what the agent last reported). */
function probes(srv: Server): Probe[] {
  const privAddr = addr(srv, 'private');
  const offline = srv.status === 'offline';
  const checked = offline ? ago(1080) : srv.status === 'stale' ? ago(40) : ago(18);
  const privDown = !privAddr?.verifiedAt || srv.name === 'db-prod-01' || offline;
  return [
    {
      path: 'private',
      url: `https://${CENTER_PRIVATE}:4444`,
      ok: !privDown,
      latencyMs: privDown ? null : 2 + (srv.name.length % 4),
      checkedAt: checked,
      ...(privDown ? { error: offline ? 'REFUSED' : 'DIAL_TIMEOUT' } : {}),
    },
    {
      path: 'public',
      url: `https://${CENTER_PUBLIC}:4443`,
      ok: !offline,
      latencyMs: offline ? null : 18 + (srv.name.length % 9),
      checkedAt: checked,
      ...(offline ? { error: 'DIAL_TIMEOUT' } : {}),
    },
  ];
}

function policyOf(srv: Server): ConnectionPolicy {
  return s().policies[srv.id] ?? srv.connectionPolicy;
}

function activePath(srv: Server, eps: Probe[]): MgmtPath | null {
  if (srv.status === 'offline' || srv.status === 'revoked' || srv.status === 'enrolling')
    return null;
  const order = dialOrder(
    policyOf(srv),
    eps.some((e) => e.path === 'private'),
  );
  return order.find((p) => eps.find((e) => e.path === p)?.ok) ?? null;
}

function bestInventory(serverId: string): ServerNetworkInventory | null {
  const rows = s().inventory.filter((r) => r.serverId === serverId);
  return (
    rows.find((r) => r.source === 'provider' && r.vpcUuid) ??
    rows.find((r) => r.source === 'inventory' && r.vpcUuid) ??
    rows.find((r) => r.source === 'provider') ??
    rows[0] ??
    null
  );
}

/** Adds the P9 fields to the server read model (called by the adapter for every server). */
export function decorateP9(srv: Server): ServerView {
  const state = s();
  const groupId = state.membership[srv.id] ?? null;
  const eps = probes(srv);
  const inv = bestInventory(srv.id);
  const known = !!inv?.vpcUuid && (inv.source === 'provider' || inv.source === 'inventory');
  const privAddr = addr(srv, 'private');
  return {
    ...srv,
    connectionPolicy: policyOf(srv),
    groupId,
    groupName: state.groups.find((g) => g.id === groupId)?.name ?? null,
    publicIpv4: addr(srv, 'public')?.address ?? null,
    privateIpv4: privAddr?.address ?? null,
    connection: {
      policy: policyOf(srv),
      activePath: activePath(srv, eps),
      endpoints: eps.map(({ url: _u, ...e }) => e),
      reportedAt: eps[0]?.checkedAt ?? null,
    },
    network: {
      region: inv?.region ?? srv.provider?.region ?? null,
      vpcUuid: known ? inv!.vpcUuid : null,
      vpcName: known ? inv!.vpcName : null,
      vpcSource: known ? (inv!.source as 'provider' | 'inventory') : null,
    },
  };
}

/** GET /servers extra filters (§3): group_id, connection_policy, tags[contains]. */
export function filterP9(items: ServerView[], url: URL): ServerView[] {
  const g = url.searchParams.get('group_id');
  const pol = url.searchParams.get('connection_policy');
  const tag = url.searchParams.get('tags[contains]');
  return items
    .filter((x) => !g || x.groupId === g)
    .filter((x) => !pol || x.connectionPolicy === pol)
    .filter((x) => !tag || x.tags.includes(tag));
}

/**
 * PATCH /servers/:id additions: a policy change needs step-up in production and a healthy private
 * probe from the last 5 min for private_only (422 PRIVATE_PATH_UNVERIFIED); groupId → membership.
 */
export function beforeServerPatch(
  u: U,
  srv: Server,
  body: Record<string, unknown>,
  req: Request,
  requestId: string,
) {
  const state = s();
  if (body.connectionPolicy !== undefined && body.connectionPolicy !== policyOf(srv)) {
    const pol = body.connectionPolicy as ConnectionPolicy;
    if (!CONNECTION_POLICIES.includes(pol))
      throw invalid([{ field: 'connectionPolicy', message: 'Unknown policy' }]);
    if (srv.environment === 'production' && !ctx.checkStepUp(req, u as never)) {
      ctx.audit(u as never, 'server.connection_policy', srv, 'denied', requestId);
      throw err(
        403,
        'STEP_UP_REQUIRED',
        'Changing the connection policy of a production server requires a fresh 2FA confirmation',
      );
    }
    if (pol === 'private_only') {
      const p = probes(srv).find((e) => e.path === 'private');
      const fresh = !!p?.ok && Date.now() - Date.parse(p.checkedAt) <= 5 * 60e3;
      if (!fresh)
        throw err(
          422,
          'PRIVATE_PATH_UNVERIFIED',
          'No healthy private-path probe was reported in the last 5 minutes.',
          { lastPrivateProbe: p ?? null },
        );
    }
    state.policies[srv.id] = pol;
  }
  if ('groupId' in body) {
    const gid = body.groupId as string | null;
    if (gid !== null && !state.groups.some((g) => g.id === gid))
      throw invalid([{ field: 'groupId', message: 'Unknown group' }]);
    if (gid === null) delete state.membership[srv.id];
    else state.membership[srv.id] = gid;
  }
  save();
}

// ---------------------------------------------------------------- topology

function topology(): Topology {
  const servers = ctx.servers();
  type Vpc = Topology['regions'][number]['vpcs'][number];
  const regions = new Map<string | null, { vpcs: Map<string, Vpc>; unknown: string[] }>();
  const findings: TopologyFinding[] = [];
  const nameOf = (id: string) => srvOf(id)?.name ?? id.slice(0, 8);
  const views = servers.map(decorateP9);
  for (const v of views) {
    const n = v.network;
    const r = regions.get(n.region) ?? { vpcs: new Map<string, Vpc>(), unknown: [] };
    regions.set(n.region, r);
    if (n.vpcUuid && n.vpcSource) {
      const vpc = r.vpcs.get(n.vpcUuid) ?? {
        vpcUuid: n.vpcUuid,
        vpcName: n.vpcName,
        source: n.vpcSource,
        servers: [],
      };
      vpc.servers.push(v.id);
      r.vpcs.set(n.vpcUuid, vpc);
    } else r.unknown.push(v.id);
  }
  for (const [region, r] of regions) {
    if (r.unknown.length)
      findings.push({
        code: 'VPC_UNKNOWN',
        serverIds: r.unknown,
        message: `${r.unknown.map(nameOf).join(', ')}: no provider or inventory data, so the VPC is unknown. Private connectivity is not assumed.`,
      });
    if (r.vpcs.size > 1) {
      const vpcs = [...r.vpcs.values()];
      findings.push({
        code: 'SAME_REGION_DIFFERENT_VPC',
        serverIds: vpcs.flatMap((v) => v.servers),
        message: `Region ${region ?? '?'} has ${vpcs.length} VPCs (${vpcs.map((v) => v.vpcName ?? v.vpcUuid.slice(0, 8)).join(', ')}). Servers in different VPCs cannot reach each other's private addresses, even in the same region.`,
      });
    }
  }
  for (const srv of servers) {
    const rows = s().inventory.filter((x) => x.serverId === srv.id);
    const p = rows.find((x) => x.source === 'provider' && x.vpcUuid);
    const i = rows.find((x) => x.source === 'inventory' && x.vpcUuid);
    if (p && i && p.vpcUuid !== i.vpcUuid)
      findings.push({
        code: 'INVENTORY_MISMATCH',
        serverIds: [srv.id],
        message: `${srv.name}: the provider says VPC ${p.vpcName ?? p.vpcUuid}, the inventory says ${i.vpcName ?? i.vpcUuid}. The provider value is used; correct the inventory.`,
      });
  }
  const seen = new Map<string, string[]>();
  for (const v of views) {
    if (!v.privateIpv4) continue;
    const k = `${v.network.vpcUuid ?? '?'}|${v.privateIpv4}`;
    seen.set(k, [...(seen.get(k) ?? []), v.id]);
  }
  for (const [k, ids] of seen)
    if (ids.length > 1)
      findings.push({
        code: 'PRIVATE_IP_CONFLICT',
        serverIds: ids,
        message: `${ids.map(nameOf).join(', ')} report the same private address ${k.split('|')[1]}.`,
      });
  for (const i of s().integrations)
    if (i.lastSyncAt && Date.now() - Date.parse(i.lastSyncAt) > 24 * 3600e3)
      findings.push({
        code: 'PROVIDER_STALE',
        serverIds: [],
        message: `${i.name}: the last provider sync is older than 24 h; VPC data may be outdated.`,
      });
  return {
    regions: [...regions.entries()].map(([region, r]) => ({
      region,
      vpcs: [...r.vpcs.values()],
      unknownVpc: r.unknown,
    })),
    findings,
  };
}

// ---------------------------------------------------------------- diagnostics

function canReach(from: Server, host: string): { ok: boolean; error?: string } {
  if (host === CENTER_PRIVATE)
    return probes(from).find((e) => e.path === 'private')?.ok
      ? { ok: true }
      : { ok: false, error: 'DIAL_TIMEOUT' };
  if (host === CENTER_PUBLIC) return { ok: live(from) };
  const target = ctx.servers().find((x) => x.addresses.some((a) => a.address === host));
  if (!target) return { ok: false, error: 'REFUSED' };
  if (addr(target, 'private')?.address !== host) return { ok: true };
  if (target.status === 'offline') return { ok: false, error: 'DIAL_TIMEOUT' };
  return realVpc(target) && realVpc(target) === realVpc(from)
    ? { ok: true }
    : { ok: false, error: 'DIAL_TIMEOUT' };
}

function diagResult(srv: Server, params: DiagParams): DiagnoseResult {
  const pub = addr(srv, 'public')?.address;
  const priv = addr(srv, 'private')?.address;
  const net = (ip: string) => ip.split('.').slice(0, 2).join('.');
  return {
    interfaces: [
      { name: 'lo', mtu: 65536, up: true, addresses: ['127.0.0.1/8', '::1/128'] },
      ...(pub ? [{ name: 'eth0', mtu: 1500, up: true, addresses: [`${pub}/20`] }] : []),
      ...(priv
        ? [{ name: 'eth1', mtu: 1500, up: srv.name !== 'db-prod-01', addresses: [`${priv}/20`] }]
        : []),
    ],
    routes: params.includeRoutes
      ? [
          ...(pub
            ? [
                {
                  dst: '0.0.0.0/0',
                  gateway: pub.replace(/\.\d+$/, '.1'),
                  iface: 'eth0',
                  metric: 0,
                },
              ]
            : []),
          ...(priv
            ? [{ dst: `${net(priv)}.0.0/20`, gateway: '0.0.0.0', iface: 'eth1', metric: 0 }]
            : []),
        ]
      : [],
    dns: params.resolve.map((host) => {
      if (host === 'center.ppanel.internal') return { host, addresses: [CENTER_PRIVATE] };
      const target = ctx.servers().find((x) => `${x.hostname}.internal` === host);
      if (target)
        return { host, addresses: [addr(target, 'private')?.address ?? ''].filter(Boolean) };
      if (host.endsWith('w3.co'))
        return { host, addresses: [addr(byName('app-prod-01')!, 'public')!.address] };
      return { host, addresses: [], error: 'NXDOMAIN' };
    }),
    tcp: params.tcp.map((t) => {
      const r = canReach(srv, t.host);
      return {
        host: t.host,
        port: t.port,
        ok: r.ok,
        latencyMs: r.ok ? 1 + (t.port % 5) : null,
        ...(r.ok ? {} : { error: r.error ?? 'DIAL_TIMEOUT' }),
      };
    }),
    centerEndpoints: probes(srv),
  };
}

function validateDiag(raw: Record<string, unknown>): DiagParams {
  const details: Array<{ field: string; message: string }> = [];
  const resolve = Array.isArray(raw.resolve) ? raw.resolve.map(String) : [];
  const tcp = Array.isArray(raw.tcp) ? (raw.tcp as Array<{ host?: unknown; port?: unknown }>) : [];
  if (resolve.length > DIAG_MAX_RESOLVE)
    details.push({ field: 'resolve', message: `At most ${DIAG_MAX_RESOLVE} hostnames` });
  if (resolve.some((h) => !isHostname(h)))
    details.push({ field: 'resolve', message: 'Hostnames only' });
  if (tcp.length > DIAG_MAX_TCP)
    details.push({ field: 'tcp', message: `At most ${DIAG_MAX_TCP} checks` });
  if (details.length) throw invalid(details);
  const center = [CENTER_PRIVATE, CENTER_PUBLIC];
  for (const t of tcp) {
    const host = String(t.host ?? '');
    const port = Number(t.port);
    if (!isIpLiteral(host) || (!isPrivateIp(host) && !center.includes(host)))
      throw err(
        422,
        'DIAGNOSE_TARGET_NOT_ALLOWED',
        `${host} is not a private address or a Center endpoint`,
      );
    if (!(DIAG_PORTS as readonly number[]).includes(port))
      throw err(
        422,
        'DIAGNOSE_TARGET_NOT_ALLOWED',
        `Port ${port} is not allowed (${DIAG_PORTS.join(', ')} or an app host port)`,
      );
  }
  return {
    resolve,
    tcp: tcp.map((t) => ({ host: String(t.host), port: Number(t.port) })),
    includeRoutes: raw.includeRoutes === true,
  };
}

function newTest(
  u: U,
  srv: Server,
  kind: TestRec['kind'],
  params: DiagParams,
  target: Server | null,
): TestRec {
  const t: TestRec = {
    id: rid(),
    serverId: srv.id,
    targetServerId: target?.id ?? null,
    kind,
    params,
    result: null,
    reachable: null,
    status: 'queued',
    jobId: rid(),
    requestedBy: u.id,
    error: null,
    createdAt: iso(Date.now()),
    finishedAt: null,
    doneAt: Date.now() + TEST_MS,
  };
  s().tests.unshift(t);
  s().tests = s().tests.slice(0, 200);
  save();
  return t;
}

function viewTest(t: TestRec): NetworkConnectivityTest {
  const { doneAt: _d, ...rest } = t;
  return { ...rest, params: { ...t.params } };
}

// ---------------------------------------------------------------- gateways + plans

function gatewayView(u: U, g: GwRec): Gateway {
  const srv = srvOf(g.serverId);
  const manage = !!srv && can(u, 'policies.manage', srv);
  return {
    ...g,
    serverName: srv?.name ?? '—',
    environment: srv?.environment ?? 'development',
    addresses: {
      privateIpv4: srv ? (addr(srv, 'private')?.address ?? null) : null,
      publicIpv4: srv ? (addr(srv, 'public')?.address ?? null) : null,
    },
    routeCount: s().routes.filter((r) => r.gatewayId === g.id).length,
    allowedActions: manage ? ['manage_routes', 'plan', 'delete'] : [],
  };
}
function findGateway(id: string) {
  const g = s().gateways.find((x) => x.id === id);
  if (!g) throw err(404, 'NOT_FOUND', 'Gateway not found');
  return g;
}
const gwServer = (g: GwRec) => {
  const srv = srvOf(g.serverId);
  if (!srv) throw err(404, 'NOT_FOUND', 'Gateway server not found');
  return srv;
};

function renderFiles(routes: GatewayRoute[]): GatewayChangePlan['rendered'] {
  const files: GatewayChangePlan['rendered'] = routes
    .filter((r) => r.mode !== 'direct')
    .map((r) => {
      const up = r.domain.replace(/[^a-z0-9]/gi, '_');
      const content = [
        '# Managed by pPanel (P9 gateway routing). Do not edit.',
        `upstream ${up} {`,
        ...r.backends.map((b) => `    server ${b.address}:${b.port} max_fails=2 fail_timeout=10s;`),
        '}',
        'server {',
        '    listen 80;',
        `    server_name ${r.domain};`,
        '    location / {',
        `        proxy_pass http://${up};`,
        '        proxy_set_header Host $host;',
        '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
        '        proxy_set_header X-Forwarded-Proto $scheme;',
        '    }',
        '}',
        '',
      ].join('\n');
      return {
        path: `/etc/nginx/ppanel-gateway/${r.domain}.conf`,
        content,
        sha256: hex(content),
        domain: r.domain,
      };
    });
  const inc =
    '# Managed by pPanel (P9 gateway routing). Do not edit.\ninclude /etc/nginx/ppanel-gateway/*.conf;\n';
  return [
    { path: '/etc/nginx/conf.d/ppanel-gateway.conf', content: inc, sha256: hex(inc), domain: null },
    ...files,
  ];
}

function cutover(g: GwRec, p: PlanRec): GatewayCutover {
  const srv = srvOf(g.serverId);
  const gwIp = srv ? (addr(srv, 'public')?.address ?? null) : null;
  const origin = (r: GatewayRoute) => {
    const b = srvOf(r.backends[0]?.serverId ?? '');
    return b ? (addr(b, 'public')?.address ?? null) : null;
  };
  const rs = p.routesSnapshot;
  return {
    dnsChanges: rs.map((r) => ({
      domain: r.domain,
      mode: r.mode,
      recordType: 'A',
      target: r.mode === 'gateway' ? gwIp : origin(r),
      directTarget: origin(r),
      action: r.mode === 'gateway' ? 'point_to_gateway' : 'none',
    })),
    ttlAdvice:
      'Lower the TTL of each record to 60 s at least one full current-TTL period (often 24 h) before changing it, and raise it again after 24 h of stable traffic. DNS changes are never instant and do not guarantee zero downtime.',
    verification: rs
      .filter((r) => r.mode !== 'direct')
      .flatMap((r) => [
        `curl -sS -o /dev/null -w '%{http_code}\\n' --resolve ${r.domain}:80:${gwIp ?? '<gateway-ip>'} http://${r.domain}${r.healthPath}`,
        `dig +short ${r.domain} A`,
      ]),
    rollback: [
      ...rs
        .filter((r) => r.mode === 'gateway')
        .map(
          (r) =>
            `At your DNS provider, set A ${r.domain} back to ${origin(r) ?? 'the direct origin'}.`,
        ),
      'Keep the direct origin serving until at least two TTL periods have passed; do not stop the app on the origin.',
      'Roll back this plan in pPanel to remove the gateway configuration (DNS is not touched).',
    ],
    note: 'pPanel never edits DNS. Hybrid routes are served by the gateway while DNS still points at the app server, so they can be shadow-tested without any DNS change.',
  };
}

function planView(
  u: U,
  p: PlanRec,
): GatewayChangePlan & {
  createdByLabel: string | null;
  approvedByLabel: string | null;
  approvalExpiresAt: string | null;
  error: { code: string; message: string } | null;
} {
  const g = s().gateways.find((x) => x.id === p.gatewayId)!;
  const srv = srvOf(g.serverId);
  const prod = srv?.environment === 'production';
  const { pending: _p, nginxFails: _n, approvedBy, approvedAt, approvalExpiresAt, ...rest } = p;
  const manage = !!srv && can(u, 'policies.manage', srv);
  const actions: GatewayChangePlan['allowedActions'] = [];
  if (manage && ['validated', 'shadow_tested', 'awaiting_approval'].includes(p.status))
    actions.push('shadow_test');
  if (
    prod &&
    p.status === 'awaiting_approval' &&
    !approvedBy &&
    srv &&
    can(u, 'approvals.decide', srv)
  )
    actions.push('approve');
  if (
    manage &&
    (p.status === 'shadow_tested' || p.status === 'awaiting_approval') &&
    (!prod || approvedBy)
  )
    actions.push('apply');
  if (manage && (p.status === 'applied' || p.status === 'failed')) actions.push('rollback');
  return {
    ...rest,
    approval: { required: prod, approvedBy, approvedAt },
    cutover: cutover(g, p),
    allowedActions: actions,
    createdByLabel: userLabel(p.createdBy),
    approvedByLabel: userLabel(approvedBy),
    approvalExpiresAt,
    error: p.error ?? null,
  };
}
function findPlan(id: string) {
  const p = s().plans.find((x) => x.id === id);
  if (!p) throw err(404, 'NOT_FOUND', 'Plan not found');
  return p;
}

function shadowResults(g: GwRec, p: PlanRec): ShadowResult[] {
  const gw = gwServer(g);
  return p.routesSnapshot
    .filter((r) => r.mode !== 'direct')
    .map((r) => {
      const body = hex(`${r.domain}-body`);
      const reach = r.backends.every((b) => canReach(gw, b.address).ok);
      return {
        domain: r.domain,
        url: `http://${r.domain}${r.healthPath}`,
        viaGateway: reach
          ? { status: 200, latencyMs: 38 + (r.domain.length % 11), bodySha256: body }
          : {
              status: 502,
              latencyMs: 10_000,
              bodySha256: hex('nginx-502'),
              error: 'UPSTREAM_TIMEOUT',
            },
        direct: { status: 200, latencyMs: 31 + (r.domain.length % 7), bodySha256: body },
        match: reach,
      };
    });
}

function hashOf(p: Pick<PlanRec, 'routesSnapshot' | 'rendered' | 'shadowResults'>) {
  return hex(
    JSON.stringify({
      r: p.routesSnapshot.map((x) => [x.domain, x.mode, x.backends]),
      f: p.rendered.map((f) => f.sha256),
      s: p.shadowResults,
    }),
  );
}

/** Advance time-based plan / test / integration progress. */
function tick() {
  if (!st) return;
  const now = Date.now();
  let dirty = false;
  for (const t of st.tests) {
    if (t.status === 'queued' && now > t.doneAt - TEST_MS / 2) {
      t.status = 'running';
      dirty = true;
    }
    if ((t.status === 'queued' || t.status === 'running') && now >= t.doneAt) {
      const srv = srvOf(t.serverId);
      if (!srv || !live(srv)) {
        t.status = 'expired';
        t.error = {
          code: 'AGENT_OFFLINE',
          message: 'The agent did not pick up the job (offline or stale). Nothing was run.',
        };
      } else {
        t.status = 'succeeded';
        t.result = diagResult(srv, t.params);
        if (t.kind === 'pair') t.reachable = t.result.tcp.every((x) => x.ok);
      }
      t.finishedAt = iso(now);
      dirty = true;
    }
  }
  for (const i of st.integrations)
    if (i.syncUntil && now >= i.syncUntil) {
      i.syncUntil = null;
      i.lastSyncAt = iso(now);
      i.updatedAt = iso(now);
      i.status = 'ok';
      i.lastError = null;
      for (const r of st.inventory) if (r.source === 'provider') r.observedAt = iso(now);
      dirty = true;
    }
  for (const p of st.plans) {
    if (!p.pending || now < p.pending.until) continue;
    const g = st.gateways.find((x) => x.id === p.gatewayId);
    const was = p.pending.status;
    p.pending = null;
    p.updatedAt = iso(now);
    dirty = true;
    if (was === 'draft') {
      if (p.nginxFails) {
        p.status = 'failed';
        p.validation = {
          valid: false,
          nginxTestOutput:
            'nginx: [emerg] invalid server name or wildcard in /etc/nginx/ppanel-gateway/*.conf\nnginx: configuration file /etc/nginx/nginx.conf test failed',
        };
        p.nginxRevisionStatus = 'invalid';
      } else {
        p.status = 'validated';
        p.validation = {
          valid: true,
          nginxTestOutput:
            'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful',
        };
        p.nginxRevisionStatus = 'validated';
      }
    } else if (was === 'shadow_testing' && g) {
      p.shadowResults = shadowResults(g, p);
      p.planHash = hashOf(p);
      p.approvedBy = null;
      p.approvedAt = null;
      p.approvalExpiresAt = null;
      p.status =
        srvOf(g.serverId)?.environment === 'production' ? 'awaiting_approval' : 'shadow_tested';
    } else if (was === 'applying') {
      p.status = 'applied';
      p.nginxRevisionStatus = 'applied';
      if (g) p.verification = shadowResults(g, p);
    } else if (was === 'rolling_back') {
      p.status = 'rolled_back';
      p.nginxRevisionStatus = 'reverted';
    }
  }
  if (dirty) save();
}

// ---------------------------------------------------------------- routes

export function registerP9Routes(c: P3Ctx) {
  ctx = c;
  const { on, ok } = c;
  const noContent = (requestId: string) =>
    new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });

  // ---------- groups ----------
  const groupView = (g: GroupRec): ServerGroup => ({
    ...g,
    serverCount: Object.values(s().membership).filter((x) => x === g.id).length,
  });
  const findGroup = (id: string) => {
    const g = s().groups.find((x) => x.id === id);
    if (!g) throw err(404, 'NOT_FOUND', 'Group not found');
    return g;
  };
  const validateGroup = (body: Record<string, unknown>, partial: boolean, selfId?: string) => {
    const details: Array<{ field: string; message: string }> = [];
    const name = typeof body.name === 'string' ? body.name.trim() : undefined;
    if (!partial || body.name !== undefined) {
      if (!name || name.length > 63)
        details.push({ field: 'name', message: 'Required, at most 63 characters' });
      else if (
        s().groups.some((g) => g.name.toLowerCase() === name.toLowerCase() && g.id !== selfId)
      )
        details.push({ field: 'name', message: 'A group with this name already exists' });
    }
    if (typeof body.description === 'string' && body.description.length > 500)
      details.push({ field: 'description', message: 'At most 500 characters' });
    if (
      body.environment !== undefined &&
      body.environment !== null &&
      !['production', 'uat', 'development'].includes(String(body.environment))
    )
      details.push({ field: 'environment', message: 'Unknown environment' });
    if (details.length) throw invalid(details);
    return name;
  };
  on('GET', '/server-groups', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const items = s()
      .groups.map(groupView)
      .sort((a, b) => a.name.localeCompare(b.name));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('GET', '/server-groups/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    return ok(requestId, groupView(findGroup(params[0]!)));
  });
  on('POST', '/server-groups', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    const name = validateGroup(body, false)!;
    const g: GroupRec = {
      id: rid(),
      name,
      description:
        typeof body.description === 'string' && body.description.trim()
          ? body.description.trim()
          : null,
      environment: (body.environment as GroupRec['environment']) ?? null,
      createdAt: iso(Date.now()),
      updatedAt: iso(Date.now()),
    };
    s().groups.push(g);
    save();
    return ok(requestId, groupView(g), 201);
  });
  on('PATCH', '/server-groups/:id', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    const g = findGroup(params[0]!);
    const name = validateGroup(body, true, g.id);
    if (name) g.name = name;
    if (body.description !== undefined)
      g.description =
        typeof body.description === 'string' && body.description.trim()
          ? body.description.trim()
          : null;
    if (body.environment !== undefined)
      g.environment = (body.environment as GroupRec['environment']) ?? null;
    g.updatedAt = iso(Date.now());
    save();
    return ok(requestId, groupView(g));
  });
  on('DELETE', '/server-groups/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    const g = findGroup(params[0]!);
    const count = Object.values(s().membership).filter((x) => x === g.id).length;
    if (count > 0)
      throw err(
        409,
        'GROUP_NOT_EMPTY',
        `Group "${g.name}" still has ${count} server(s). Move them out first.`,
        { serverCount: count },
      );
    s().groups = s().groups.filter((x) => x.id !== g.id);
    save();
    return noContent(requestId);
  });

  // ---------- topology + inventory ----------
  on('GET', '/network/topology', ({ req, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    return ok(requestId, topology());
  });
  on('POST', '/network/inventory', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'servers.operate');
    const rows = Array.isArray(body.rows) ? (body.rows as Array<Record<string, unknown>>) : null;
    if (!rows || rows.length === 0 || rows.length > 500)
      throw invalid([{ field: 'rows', message: '1–500 rows required' }]);
    const allowed = [
      'serverId',
      'hostname',
      'region',
      'vpcUuid',
      'vpcName',
      'dropletId',
      'privateIpv4',
      'publicIpv4',
    ];
    const details: Array<{ field: string; message: string }> = [];
    const resolved: Array<[Server, Record<string, unknown>]> = [];
    rows.forEach((r, i) => {
      const extra = Object.keys(r).filter((k) => !allowed.includes(k));
      if (extra.length)
        details.push({ field: `rows.${i}`, message: `Unknown field(s): ${extra.join(', ')}` });
      for (const k of ['privateIpv4', 'publicIpv4'])
        if (r[k] !== undefined && !isIpv4(String(r[k])))
          details.push({ field: `rows.${i}.${k}`, message: 'Invalid IPv4' });
    });
    if (details.length) throw invalid(details);
    rows.forEach((r, i) => {
      const srv = ctx
        .servers()
        .find((x) => x.id === r.serverId || (r.hostname && x.hostname === r.hostname));
      if (!srv)
        throw err(
          422,
          'INVENTORY_SERVER_UNRESOLVED',
          `Row ${i + 1}: no server matches ${String(r.serverId ?? r.hostname)}`,
          [{ field: `rows.${i}`, message: 'No server matches serverId/hostname' }],
        );
      resolved.push([srv, r]);
    });
    const out: ServerNetworkInventory[] = [];
    for (const [srv, r] of resolved) {
      s().inventory = s().inventory.filter(
        (x) => !(x.serverId === srv.id && x.source === 'inventory'),
      );
      const row: ServerNetworkInventory = {
        serverId: srv.id,
        source: 'inventory',
        region: (r.region as string) ?? null,
        vpcUuid: (r.vpcUuid as string) ?? null,
        vpcName: (r.vpcName as string) ?? null,
        dropletId: r.dropletId !== undefined ? String(r.dropletId) : null,
        privateIpv4: (r.privateIpv4 as string) ?? null,
        publicIpv4: (r.publicIpv4 as string) ?? null,
        observedAt: iso(Date.now()),
      };
      s().inventory.push(row);
      out.push(row);
    }
    save();
    c.audit(u as never, 'network.inventory.import', resolved[0]![0], 'success', requestId);
    return ok(requestId, { upserted: out.length, rows: out }, 200);
  });

  // ---------- provider integrations ----------
  const integrationView = (u: U, i: IntegrationRec): ProviderIntegration => {
    const { syncUntil, ...rest } = i;
    const manage = can(u, 'policies.manage');
    return {
      ...rest,
      syncInProgress: !!syncUntil,
      allowedActions: manage ? ['sync', 'delete'] : [],
    };
  };
  const findIntegration = (id: string) => {
    const i = s().integrations.find((x) => x.id === id);
    if (!i) throw err(404, 'NOT_FOUND', 'Integration not found');
    return i;
  };
  on('GET', '/provider-integrations', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const { slice, paginate } = c.paginate(
      s().integrations.map((i) => integrationView(u, i)),
      url,
    );
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/provider-integrations', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    if (!c.checkStepUp(req, u))
      throw err(
        403,
        'STEP_UP_REQUIRED',
        'Adding a provider token requires a fresh 2FA confirmation',
      );
    const details: Array<{ field: string; message: string }> = [];
    if (body.provider !== 'digitalocean')
      details.push({ field: 'provider', message: 'Only digitalocean is supported' });
    if (
      typeof body.name !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(body.name.trim()) ||
      body.name.length > 63
    )
      details.push({ field: 'name', message: 'Letters, digits, space, dot, dash; max 63' });
    if (
      typeof body.token !== 'string' ||
      body.token.length < 8 ||
      !/^[\x21-\x7e]+$/.test(body.token)
    )
      details.push({ field: 'token', message: 'Paste a DigitalOcean read-only token' });
    if (details.length) throw invalid(details);
    if (body.apiBase !== undefined && body.apiBase !== 'https://api.digitalocean.com')
      throw err(
        422,
        'PROVIDER_API_NOT_ALLOWED',
        'This API base is not in the PPANEL_DO_API_BASE allowlist',
      );
    if (String(body.token).includes('bad'))
      throw err(
        422,
        'PROVIDER_AUTH_FAILED',
        'DigitalOcean rejected the token (GET /v2/account answered 401). Nothing was saved.',
      );
    const i: IntegrationRec = {
      id: rid(),
      provider: 'digitalocean',
      name: String(body.name).trim(),
      apiBase: 'https://api.digitalocean.com',
      status: 'ok',
      lastSyncAt: null,
      lastError: null,
      lastSyncSummary: null,
      createdBy: u.id,
      createdAt: iso(Date.now()),
      updatedAt: iso(Date.now()),
      syncUntil: null,
    };
    s().integrations.push(i);
    save();
    return ok(requestId, integrationView(u, i), 201);
  });
  on('DELETE', '/provider-integrations/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    const i = findIntegration(params[0]!);
    s().integrations = s().integrations.filter((x) => x.id !== i.id);
    save();
    return noContent(requestId);
  });
  on('POST', '/provider-integrations/:id/sync', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    const i = findIntegration(params[0]!);
    if (i.syncUntil)
      throw err(409, 'PROVIDER_SYNC_IN_PROGRESS', 'A sync of this integration is already running');
    i.syncUntil = Date.now() + SYNC_MS;
    i.lastSyncSummary = { droplets: 5, vpcs: 2, matched: 4, unmatched: 1 };
    save();
    return ok(requestId, integrationView(u, i), 202);
  });

  // ---------- diagnostics ----------
  const findSrv = (id: string) => {
    const srv = srvOf(id);
    if (!srv) throw err(404, 'NOT_FOUND', 'Server not found');
    return srv;
  };
  on('POST', '/servers/:id/network-diagnostics', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const srv = findSrv(params[0]!);
    need(u, 'servers.operate', srv);
    const t = newTest(u, srv, 'diagnose', validateDiag(body), null);
    return ok(requestId, { testId: t.id, jobId: t.jobId }, 202);
  });
  on('GET', '/servers/:id/network-diagnostics', ({ req, url, params, requestId }) => {
    const u = c.currentUser(req);
    const srv = findSrv(params[0]!);
    need(u, 'fleet.read', srv);
    const items = s()
      .tests.filter((t) => t.serverId === srv.id)
      .map(viewTest);
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('GET', '/network-diagnostics/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const t = s().tests.find((x) => x.id === params[0]);
    if (!t) throw err(404, 'NOT_FOUND', 'Test not found');
    need(u, 'fleet.read', srvOf(t.serverId));
    return ok(requestId, viewTest(t));
  });
  on('POST', '/network/connectivity-tests', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    const from = findSrv(String(body.fromServerId ?? ''));
    const to = findSrv(String(body.toServerId ?? ''));
    need(u, 'servers.operate', from);
    const port = Number(body.port);
    if (from.id === to.id)
      throw invalid([{ field: 'toServerId', message: 'fromServerId and toServerId must differ' }]);
    if (!(port >= 1 && port <= 65535)) throw invalid([{ field: 'port', message: '1–65535' }]);
    if (!(DIAG_PORTS as readonly number[]).includes(port))
      throw err(
        422,
        'DIAGNOSE_TARGET_NOT_ALLOWED',
        `Port ${port} is not allowed (${DIAG_PORTS.join(', ')} or an app host port)`,
      );
    const host = addr(to, 'private')?.address;
    if (!host) throw err(422, 'NO_PRIVATE_ADDRESS', `${to.name} has no known private IPv4`);
    const t = newTest(
      u,
      from,
      'pair',
      { resolve: [], tcp: [{ host, port }], includeRoutes: false, port },
      to,
    );
    return ok(requestId, { testId: t.id, jobId: t.jobId }, 202);
  });

  // ---------- gateways ----------
  on('GET', '/gateways', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const { slice, paginate } = c.paginate(
      s().gateways.map((g) => gatewayView(u, g)),
      url,
    );
    return ok(requestId, slice, 200, paginate);
  });
  on('GET', '/gateways/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    return ok(requestId, gatewayView(u, findGateway(params[0]!)));
  });
  on('POST', '/gateways', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    const srv = findSrv(String(body.serverId ?? ''));
    need(u, 'policies.manage', srv);
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(name))
      throw invalid([{ field: 'name', message: 'Lowercase letters, digits and dashes' }]);
    if (s().gateways.some((g) => g.serverId === srv.id || g.name === name))
      throw err(409, 'GATEWAY_EXISTS', `${srv.name} is already a gateway, or the name is taken`);
    const now = iso(Date.now());
    const g: GwRec = {
      id: rid(),
      serverId: srv.id,
      name,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    s().gateways.push(g);
    save();
    c.audit(u as never, 'gateway.create', srv, 'success', requestId);
    return ok(requestId, gatewayView(u, g), 201);
  });
  on('DELETE', '/gateways/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const g = findGateway(params[0]!);
    need(u, 'policies.manage', gwServer(g));
    if (s().routes.some((r) => r.gatewayId === g.id))
      throw err(409, 'GATEWAY_NOT_EMPTY', 'Delete the gateway’s routes first');
    s().gateways = s().gateways.filter((x) => x.id !== g.id);
    save();
    return noContent(requestId);
  });

  // ---------- routes ----------
  const validateBackends = (raw: unknown) => {
    const backends = Array.isArray(raw) ? (raw as Array<Record<string, unknown>>) : [];
    const details: Array<{ field: string; message: string }> = [];
    if (backends.length === 0 || backends.length > 10)
      details.push({ field: 'backends', message: '1–10 backends' });
    const out: RouteBackend[] = [];
    backends.forEach((b, i) => {
      const srv = srvOf(String(b.serverId));
      const port = Number(b.port);
      if (!srv) {
        details.push({ field: `backends.${i}.serverId`, message: 'Unknown server' });
        return;
      }
      if (!(port >= 1 && port <= 65535))
        details.push({ field: `backends.${i}.port`, message: '1–65535' });
      const address = b.address ? String(b.address) : (addr(srv, 'private')?.address ?? '');
      if (b.address && !srv.addresses.some((a) => a.address === address))
        throw err(
          422,
          'BACKEND_ADDRESS_UNKNOWN',
          `${address} is not one of ${srv.name}'s known addresses`,
        );
      out.push({ serverId: srv.id, address, port });
    });
    if (details.length) throw invalid(details);
    return out;
  };
  const findRoute = (g: GwRec, id: string) => {
    const r = s().routes.find((x) => x.id === id && x.gatewayId === g.id);
    if (!r) throw err(404, 'NOT_FOUND', 'Route not found');
    return r;
  };
  on('GET', '/gateways/:id/routes', ({ req, url, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const g = findGateway(params[0]!);
    const items = s()
      .routes.filter((r) => r.gatewayId === g.id)
      .sort((a, b) => a.domain.localeCompare(b.domain));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/gateways/:id/routes', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const g = findGateway(params[0]!);
    need(u, 'policies.manage', gwServer(g));
    const domain = typeof body.domain === 'string' ? body.domain.trim().toLowerCase() : '';
    const details: Array<{ field: string; message: string }> = [];
    if (!isHostname(domain) || !domain.includes('.'))
      details.push({ field: 'domain', message: 'Enter a domain such as shop.example.com' });
    if (body.mode !== undefined && !ROUTE_MODES.includes(body.mode as never))
      details.push({ field: 'mode', message: 'direct, hybrid or gateway' });
    const healthPath = typeof body.healthPath === 'string' ? body.healthPath : '/';
    if (!HEALTH_PATH_RE.test(healthPath))
      details.push({ field: 'healthPath', message: 'Path starting with /' });
    if (details.length) throw invalid(details);
    if (s().routes.some((r) => r.domain === domain))
      throw err(409, 'ROUTE_DOMAIN_TAKEN', `${domain} is already routed by a gateway`);
    const now = iso(Date.now());
    const r: GatewayRoute = {
      id: rid(),
      gatewayId: g.id,
      domain,
      mode: (body.mode as GatewayRoute['mode']) ?? 'hybrid',
      backends: validateBackends(body.backends),
      healthPath,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };
    s().routes.push(r);
    save();
    return ok(requestId, r, 201);
  });
  on('PATCH', '/gateways/:id/routes/:routeId', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const g = findGateway(params[0]!);
    need(u, 'policies.manage', gwServer(g));
    const r = findRoute(g, params[1]!);
    const ifMatch = req.headers.get('If-Match');
    if (ifMatch && Number(ifMatch) !== r.version)
      throw err(409, 'VERSION_CONFLICT', 'This route was changed by someone else. Reload.', {
        currentVersion: r.version,
      });
    const extra = Object.keys(body).filter((k) => !['mode', 'backends', 'healthPath'].includes(k));
    if (extra.length)
      throw invalid([
        { field: extra[0]!, message: 'Only mode, backends and healthPath can change' },
      ]);
    if (body.mode !== undefined && !ROUTE_MODES.includes(body.mode as never))
      throw invalid([{ field: 'mode', message: 'direct, hybrid or gateway' }]);
    if (body.healthPath !== undefined && !HEALTH_PATH_RE.test(String(body.healthPath)))
      throw invalid([{ field: 'healthPath', message: 'Path starting with /' }]);
    if (body.backends !== undefined) r.backends = validateBackends(body.backends);
    if (body.mode !== undefined) r.mode = body.mode as GatewayRoute['mode'];
    if (body.healthPath !== undefined) r.healthPath = String(body.healthPath);
    r.version += 1;
    r.updatedAt = iso(Date.now());
    save();
    return ok(requestId, r);
  });
  on('DELETE', '/gateways/:id/routes/:routeId', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const g = findGateway(params[0]!);
    need(u, 'policies.manage', gwServer(g));
    const r = findRoute(g, params[1]!);
    s().routes = s().routes.filter((x) => x.id !== r.id);
    save();
    return noContent(requestId);
  });

  // ---------- change plans ----------
  on('GET', '/gateways/:id/plans', ({ req, url, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const g = findGateway(params[0]!);
    const items = s()
      .plans.filter((p) => p.gatewayId === g.id)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((p) => planView(u, p));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/gateways/:id/plans', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const g = findGateway(params[0]!);
    const srv = gwServer(g);
    need(u, 'policies.manage', srv);
    const snap = s()
      .routes.filter((r) => r.gatewayId === g.id)
      .map((r) => ({ ...r, backends: r.backends.map((b) => ({ ...b })) }));
    if (!snap.some((r) => r.mode !== 'direct'))
      throw err(
        422,
        'GATEWAY_PLAN_STATE_INVALID',
        'Every route is Direct, so there is nothing for the gateway to serve. Set a route to Hybrid or Gateway first.',
      );
    if (s().plans.some((p) => p.gatewayId === g.id && p.pending))
      throw err(
        409,
        'GATEWAY_PLAN_STATE_INVALID',
        'Another plan for this gateway is running a job',
      );
    const rendered = renderFiles(snap);
    const p: PlanRec = {
      id: rid(),
      gatewayId: g.id,
      status: 'draft',
      routesSnapshot: snap,
      rendered,
      planHash: '',
      nginxRevisionId: rid(),
      nginxRevisionStatus: 'validating',
      validation: { valid: null, nginxTestOutput: null },
      shadowResults: null,
      verification: null,
      createdBy: u.id,
      approvedBy: null,
      approvedAt: null,
      approvalExpiresAt: null,
      createdAt: iso(Date.now()),
      updatedAt: iso(Date.now()),
      pending: { status: 'draft', until: Date.now() + VALIDATE_MS },
      nginxFails: snap.some((r) => r.domain.includes('invalid')),
    };
    p.planHash = hashOf(p);
    s().plans.push(p);
    save();
    c.audit(u as never, 'gateway.plan.create', srv, 'success', requestId);
    return ok(requestId, planView(u, p), 201);
  });
  on('GET', '/gateway-plans/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    return ok(requestId, planView(u, findPlan(params[0]!)));
  });
  const stateErr = (p: PlanRec, what: string) =>
    err(409, 'GATEWAY_PLAN_STATE_INVALID', `Cannot ${what} a plan in status ${p.status}`);
  on('POST', '/gateway-plans/:id/shadow-test', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const p = findPlan(params[0]!);
    need(u, 'policies.manage', gwServer(findGateway(p.gatewayId)));
    if (p.pending || !['validated', 'shadow_tested', 'awaiting_approval'].includes(p.status))
      throw stateErr(p, 'shadow-test');
    p.status = 'shadow_testing';
    p.pending = { status: 'shadow_testing', until: Date.now() + SHADOW_MS };
    save();
    return ok(requestId, planView(u, p), 202);
  });
  on('POST', '/gateway-plans/:id/approve', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const p = findPlan(params[0]!);
    const srv = gwServer(findGateway(p.gatewayId));
    need(u, 'approvals.decide', srv);
    if (srv.environment !== 'production')
      throw err(409, 'APPROVAL_NOT_REQUIRED', 'Only production gateway plans need approval');
    if (p.createdBy === u.id) {
      c.audit(u as never, 'gateway.plan.approve', srv, 'denied', requestId);
      throw err(409, 'APPROVER_IS_CREATOR', 'A different person must approve this plan');
    }
    if (!c.checkStepUp(req, u))
      throw err(
        403,
        'STEP_UP_REQUIRED',
        'Approving a production plan requires a fresh 2FA confirmation',
      );
    if (!p.shadowResults) throw err(409, 'SHADOW_TEST_REQUIRED', 'Run the shadow test first');
    if (p.status !== 'awaiting_approval') throw stateErr(p, 'approve');
    if (body.planHash !== p.planHash)
      throw err(
        409,
        'PLAN_HASH_MISMATCH',
        'The plan changed since you reviewed it. Reload and review again.',
      );
    p.approvedBy = u.id;
    p.approvedAt = iso(Date.now());
    p.approvalExpiresAt = iso(Date.now() + APPROVAL_TTL_MS);
    p.updatedAt = iso(Date.now());
    save();
    c.audit(u as never, 'gateway.plan.approve', srv, 'success', requestId);
    return ok(requestId, planView(u, p));
  });
  on('POST', '/gateway-plans/:id/apply', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const p = findPlan(params[0]!);
    const srv = gwServer(findGateway(p.gatewayId));
    need(u, 'policies.manage', srv);
    const prod = srv.environment === 'production';
    if (p.pending || !['shadow_tested', 'awaiting_approval'].includes(p.status))
      throw err(409, 'SHADOW_TEST_REQUIRED', 'Run the shadow test before applying');
    if (prod && !p.approvedBy)
      throw err(409, 'APPROVAL_REQUIRED', 'A second person must approve this production plan');
    if (prod && p.approvalExpiresAt && Date.parse(p.approvalExpiresAt) < Date.now())
      throw err(409, 'APPROVAL_EXPIRED', 'The approval expired. Run the shadow test again.');
    if (prod && !c.checkStepUp(req, u))
      throw err(
        403,
        'STEP_UP_REQUIRED',
        'Applying a production plan requires a fresh 2FA confirmation',
      );
    p.status = 'applying';
    p.pending = { status: 'applying', until: Date.now() + APPLY_MS };
    save();
    c.audit(u as never, 'gateway.plan.apply', srv, 'success', requestId);
    return ok(requestId, planView(u, p), 202);
  });
  on('POST', '/gateway-plans/:id/rollback', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const p = findPlan(params[0]!);
    const srv = gwServer(findGateway(p.gatewayId));
    need(u, 'policies.manage', srv);
    if (p.pending || (p.status !== 'applied' && p.status !== 'failed'))
      throw stateErr(p, 'roll back');
    if (srv.environment === 'production' && !c.checkStepUp(req, u))
      throw err(
        403,
        'STEP_UP_REQUIRED',
        'Rolling back a production plan requires a fresh 2FA confirmation',
      );
    p.status = 'rolling_back';
    p.pending = { status: 'rolling_back', until: Date.now() + APPLY_MS };
    save();
    c.audit(u as never, 'gateway.plan.rollback', srv, 'success', requestId);
    return ok(requestId, planView(u, p), 202);
  });
}
