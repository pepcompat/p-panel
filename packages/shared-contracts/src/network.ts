// P9 — management paths, provider inventory, topology, diagnostics, Gateway routing.
// Source of truth: docs/P9_NETWORK_CONTRACT.md and docs/API_CONTRACTS.md §11.
import { z } from 'zod';
import { domainSchema } from './deploy';
import { networkDiagnoseParams } from './jobs';
import type { ConnectionPolicy, Environment } from './server';

// ---------------------------------------------------------------- §1 management paths

export const CONNECTION_PATHS = ['public', 'private'] as const;
export type ConnectionPath = (typeof CONNECTION_PATHS)[number];

export interface GatewayEndpoint {
  path: ConnectionPath;
  url: string;
}

/** Short error codes the agent reports per probed endpoint. */
export const CONNECTION_PROBE_ERRORS = [
  'DIAL_TIMEOUT',
  'TLS_FAILED',
  'REFUSED',
  'DNS_FAILED',
  /** the Center answered 403 CONNECTION_PATH_NOT_ALLOWED on this path */
  'PATH_FORBIDDEN',
] as const;

/** Paths a policy lets the agent use, in dial order (`auto` depends on a private endpoint existing). */
export function dialOrder(policy: ConnectionPolicy, hasPrivate: boolean): ConnectionPath[] {
  switch (policy) {
    case 'private_only':
      return ['private'];
    case 'public_only':
      return ['public'];
    case 'private_preferred':
      return ['private', 'public'];
    case 'public_preferred':
      return ['public', 'private'];
    default:
      return hasPrivate ? ['private', 'public'] : ['public'];
  }
}

/** Center enforcement: may a request of this server arrive on `path`? (fail closed for *_only). */
export function policyAllowsPath(policy: string, path: ConnectionPath): boolean {
  if (policy === 'private_only') return path === 'private';
  if (policy === 'public_only') return path === 'public';
  return true;
}

const isoTime = z.string().datetime({ offset: true });

export const heartbeatConnectionEndpointSchema = z
  .object({
    path: z.enum(CONNECTION_PATHS),
    url: z.string().max(300),
    ok: z.boolean(),
    latencyMs: z.number().int().min(0).max(600_000).nullish(),
    checkedAt: isoTime,
    error: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]{0,63}$/)
      .nullish(),
  })
  .strip();

/** Heartbeat body `connection` (agent probe results, every 60 s). */
export const heartbeatConnectionSchema = z
  .object({
    activePath: z.enum(CONNECTION_PATHS).nullish(),
    endpoints: z.preprocess(
      (v) => (v === null ? [] : v),
      z.array(heartbeatConnectionEndpointSchema).max(8).default([]),
    ),
  })
  .strip();
export type HeartbeatConnection = z.infer<typeof heartbeatConnectionSchema>;

/** Heartbeat response `connection` — the agent persists it (`<stateDir>/connection.json`). */
export interface HeartbeatConnectionDirective {
  policy: ConnectionPolicy;
  endpoints: GatewayEndpoint[];
}

/** Agent `provider` facts from the DigitalOcean metadata service (absent → null). */
export const agentProviderFactsSchema = z
  .object({
    name: z.literal('digitalocean'),
    dropletId: z
      .union([z.string().regex(/^\d{1,20}$/), z.number().int().nonnegative()])
      .transform(String),
    region: z.preprocess(
      (v) => (v === '' ? null : v),
      z
        .string()
        .regex(/^[a-z0-9-]{1,32}$/)
        .nullish(),
    ),
    interfaces: z
      .object({
        private: z.preprocess(
          (v) => (v === null ? [] : v),
          z
            .array(z.string().ip({ version: 'v4' }))
            .max(8)
            .default([]),
        ),
        public: z.preprocess(
          (v) => (v === null ? [] : v),
          z
            .array(z.string().ip({ version: 'v4' }))
            .max(8)
            .default([]),
        ),
      })
      .strip()
      .default({}),
  })
  .strip();
export type AgentProviderFacts = z.infer<typeof agentProviderFactsSchema>;

/** Server view (`GET /servers`) additions. */
export interface ServerConnectionView {
  policy: ConnectionPolicy;
  activePath: ConnectionPath | null;
  endpoints: Array<{
    path: ConnectionPath;
    ok: boolean;
    latencyMs: number | null;
    checkedAt: string;
    error?: string;
  }>;
  /** when the Center last received a probe report (null = never) */
  reportedAt: string | null;
}

export const NETWORK_SOURCES = ['agent', 'provider', 'inventory'] as const;
export type NetworkSource = (typeof NETWORK_SOURCES)[number];

export interface ServerNetworkView {
  region: string | null;
  vpcUuid: string | null;
  vpcName: string | null;
  /** a VPC is known only from the provider API or the user inventory, never from agent facts */
  vpcSource: 'provider' | 'inventory' | null;
}

// ---------------------------------------------------------------- §2 provider inventory

export const PROVIDERS = ['digitalocean'] as const;
export const PROVIDER_STATUSES = ['ok', 'error', 'unverified'] as const;
export type ProviderStatus = (typeof PROVIDER_STATUSES)[number];
export const DEFAULT_DO_API_BASE = 'https://api.digitalocean.com';

export const createProviderIntegrationSchema = z
  .object({
    provider: z.enum(PROVIDERS),
    name: z
      .string()
      .trim()
      .min(1)
      .max(63)
      .regex(/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/),
    /** Read-only DigitalOcean API token (stored AES-256-GCM, never returned). */
    token: z
      .string()
      .min(8)
      .max(512)
      .regex(/^[\x21-\x7e]+$/, 'token must be printable ASCII without spaces'),
    /** Defaults to https://api.digitalocean.com; anything else must be in PPANEL_DO_API_BASE. */
    apiBase: z.string().max(300).optional(),
  })
  .strict();
export type CreateProviderIntegrationInput = z.infer<typeof createProviderIntegrationSchema>;

export interface ProviderIntegration {
  id: string;
  provider: (typeof PROVIDERS)[number];
  name: string;
  apiBase: string;
  status: ProviderStatus;
  lastSyncAt: string | null;
  lastError: { code: string; message: string } | null;
  syncInProgress: boolean;
  /** summary of the last sync */
  lastSyncSummary: {
    droplets: number;
    vpcs: number;
    matched: number;
    unmatched: number;
  } | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  allowedActions: Array<'sync' | 'delete'>;
}

const ipv4 = z.string().ip({ version: 'v4' });
export const networkInventoryRowSchema = z
  .object({
    serverId: z.string().uuid().optional(),
    hostname: z.string().trim().min(1).max(253).optional(),
    region: z
      .string()
      .regex(/^[a-z0-9-]{1,32}$/)
      .optional(),
    vpcUuid: z
      .string()
      .regex(/^[A-Za-z0-9-]{1,64}$/)
      .optional(),
    vpcName: z.string().trim().min(1).max(100).optional(),
    dropletId: z
      .union([z.string().regex(/^\d{1,20}$/), z.number().int().nonnegative()])
      .transform(String)
      .optional(),
    privateIpv4: ipv4.optional(),
    publicIpv4: ipv4.optional(),
  })
  .strict()
  .refine((r) => (r.serverId ? !r.hostname : !!r.hostname), {
    message: 'exactly one of serverId or hostname is required',
  });
export type NetworkInventoryRow = z.infer<typeof networkInventoryRowSchema>;
export const NETWORK_INVENTORY_MAX_ROWS = 500;
/** `POST /network/inventory` body: `{ rows: [...] }` (a bare array is accepted too). */
export const networkInventoryInputSchema = z.preprocess(
  (v) => (Array.isArray(v) ? { rows: v } : v),
  z
    .object({ rows: z.array(networkInventoryRowSchema).min(1).max(NETWORK_INVENTORY_MAX_ROWS) })
    .strict(),
);
export type NetworkInventoryInput = z.infer<typeof networkInventoryInputSchema>;

export interface NetworkInventoryEntry {
  serverId: string;
  source: NetworkSource;
  region: string | null;
  vpcUuid: string | null;
  vpcName: string | null;
  dropletId: string | null;
  privateIpv4: string | null;
  publicIpv4: string | null;
  observedAt: string;
}

export const TOPOLOGY_FINDING_CODES = [
  'VPC_UNKNOWN',
  'SAME_REGION_DIFFERENT_VPC',
  'PRIVATE_IP_CONFLICT',
  'PROVIDER_STALE',
  'INVENTORY_MISMATCH',
] as const;
export type TopologyFindingCode = (typeof TOPOLOGY_FINDING_CODES)[number];
/** Provider rows older than this raise PROVIDER_STALE. */
export const PROVIDER_STALE_AFTER_HOURS = 24;

export interface NetworkTopology {
  regions: Array<{
    /** null = region unknown for these servers */
    region: string | null;
    vpcs: Array<{
      vpcUuid: string;
      vpcName: string | null;
      source: 'provider' | 'inventory';
      servers: string[];
    }>;
    unknownVpc: string[];
  }>;
  findings: Array<{ code: TopologyFindingCode; serverIds: string[]; message: string }>;
}

// ---------------------------------------------------------------- §3 groups

export const updateServerGroupSchema = z
  .object({
    name: z.string().trim().min(1).max(63).optional(),
    description: z.string().trim().max(500).nullable().optional(),
    environment: z.enum(['production', 'uat', 'development']).nullable().optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, { message: 'at least one field is required' });
export type UpdateServerGroupInput = z.infer<typeof updateServerGroupSchema>;

// ---------------------------------------------------------------- §4 diagnostics

/** `POST /servers/:id/network-diagnostics` body (all optional; same limits as the job). */
export const createNetworkDiagnosticsSchema = networkDiagnoseParams
  .omit({ allowedPorts: true })
  .strict();
export type CreateNetworkDiagnosticsInput = z.infer<typeof createNetworkDiagnosticsSchema>;

export const createConnectivityTestSchema = z
  .object({
    fromServerId: z.string().uuid(),
    toServerId: z.string().uuid(),
    port: z.number().int().min(1).max(65535),
  })
  .strict()
  .refine((v) => v.fromServerId !== v.toServerId, {
    message: 'fromServerId and toServerId must differ',
  });
export type CreateConnectivityTestInput = z.infer<typeof createConnectivityTestSchema>;

export const CONNECTIVITY_TEST_STATUSES = [
  'queued',
  'running',
  'succeeded',
  'failed',
  'expired',
  'cancelled',
] as const;
export type ConnectivityTestStatus = (typeof CONNECTIVITY_TEST_STATUSES)[number];

export interface NetworkDiagnoseResult {
  interfaces: Array<{ name: string; mtu: number; up: boolean; addresses: string[] }>;
  routes: Array<{ dst: string; gateway: string; iface: string; metric: number }>;
  dns: Array<{ host: string; addresses: string[]; error?: string }>;
  tcp: Array<{ host: string; port: number; ok: boolean; latencyMs: number | null; error?: string }>;
  centerEndpoints: Array<{
    path: ConnectionPath;
    url: string;
    ok: boolean;
    latencyMs: number | null;
    checkedAt: string;
    error?: string;
  }>;
}

export interface NetworkConnectivityTest {
  id: string;
  serverId: string;
  targetServerId: string | null;
  kind: 'diagnose' | 'pair';
  params: Record<string, unknown>;
  status: ConnectivityTestStatus;
  jobId: string | null;
  /** pair tests: did the TCP connect to the target's private IPv4 succeed (null until finished) */
  reachable: boolean | null;
  result: NetworkDiagnoseResult | null;
  error: { code: string; message?: string } | null;
  requestedBy: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface NetworkDiagnosticsCreated {
  testId: string;
  jobId: string;
}

// ---------------------------------------------------------------- §5 gateways

export const GATEWAY_STATUSES = ['active', 'disabled'] as const;
export const GATEWAY_ROUTE_MODES = ['direct', 'hybrid', 'gateway'] as const;
export type GatewayRouteMode = (typeof GATEWAY_ROUTE_MODES)[number];
/** Max routes rendered into one plan (one nginx revision holds ≤ 20 files incl. the include file). */
export const GATEWAY_MAX_ROUTES = 19;

export const createGatewaySchema = z
  .object({
    serverId: z.string().uuid(),
    name: z
      .string()
      .trim()
      .min(1)
      .max(63)
      .regex(/^[a-z0-9][a-z0-9-]*$/),
  })
  .strict();
export type CreateGatewayInput = z.infer<typeof createGatewaySchema>;

export interface Gateway {
  id: string;
  serverId: string;
  serverName: string;
  environment: Environment;
  name: string;
  status: (typeof GATEWAY_STATUSES)[number];
  /** addresses probes and DNS instructions may use (private first) */
  addresses: { privateIpv4: string | null; publicIpv4: string | null };
  routeCount: number;
  createdAt: string;
  updatedAt: string;
  allowedActions: Array<'manage_routes' | 'plan' | 'delete'>;
}

export const HEALTH_PATH_RE = /^\/[A-Za-z0-9._~\/?=&%-]{0,200}$/;
export const gatewayBackendSchema = z
  .object({
    serverId: z.string().uuid(),
    /** must be one of the server's known addresses; default = its preferred private IPv4 */
    address: z.string().ip({ version: 'v4' }).optional(),
    port: z.number().int().min(1).max(65535),
  })
  .strict();

export const createGatewayRouteSchema = z
  .object({
    domain: domainSchema,
    mode: z.enum(GATEWAY_ROUTE_MODES).default('hybrid'),
    backends: z
      .array(gatewayBackendSchema)
      .min(1)
      .max(10)
      .refine((a) => new Set(a.map((b) => `${b.serverId}:${b.port}`)).size === a.length, {
        message: 'backends must be unique',
      }),
    healthPath: z.string().regex(HEALTH_PATH_RE).default('/'),
  })
  .strict();
export type CreateGatewayRouteInput = z.infer<typeof createGatewayRouteSchema>;

export const updateGatewayRouteSchema = z
  .object({
    mode: z.enum(GATEWAY_ROUTE_MODES).optional(),
    backends: createGatewayRouteSchema.shape.backends.optional(),
    healthPath: z.string().regex(HEALTH_PATH_RE).optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, { message: 'at least one field is required' });
export type UpdateGatewayRouteInput = z.infer<typeof updateGatewayRouteSchema>;

export interface GatewayBackend {
  serverId: string;
  address: string;
  port: number;
}

export interface GatewayRoute {
  id: string;
  gatewayId: string;
  domain: string;
  mode: GatewayRouteMode;
  backends: GatewayBackend[];
  healthPath: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export const GATEWAY_PLAN_STATUSES = [
  'draft',
  'validated',
  'shadow_testing',
  'shadow_tested',
  'awaiting_approval',
  'applying',
  'applied',
  'rolling_back',
  'rolled_back',
  'failed',
  'cancelled',
] as const;
export type GatewayPlanStatus = (typeof GATEWAY_PLAN_STATUSES)[number];

export interface ShadowProbe {
  status: number | null;
  latencyMs: number | null;
  bodySha256: string | null;
  error?: string;
}
export interface ShadowResult {
  domain: string;
  url: string;
  viaGateway: ShadowProbe;
  direct: ShadowProbe;
  /** same status and same body hash */
  match: boolean;
}

export interface GatewayCutover {
  dnsChanges: Array<{
    domain: string;
    mode: GatewayRouteMode;
    recordType: 'A';
    /** what DNS should point at once this plan is applied */
    target: string | null;
    /** what DNS points at while the route is direct / hybrid (the app server) */
    directTarget: string | null;
    action: 'none' | 'point_to_gateway' | 'point_to_direct';
  }>;
  ttlAdvice: string;
  verification: string[];
  rollback: string[];
  note: string;
}

export interface GatewayChangePlan {
  id: string;
  gatewayId: string;
  status: GatewayPlanStatus;
  routesSnapshot: GatewayRoute[];
  rendered: Array<{ path: string; sha256: string; content: string; domain: string | null }>;
  planHash: string;
  nginxRevisionId: string | null;
  nginxRevisionStatus: string | null;
  validation: { valid: boolean | null; nginxTestOutput: string | null } | null;
  shadowResults: ShadowResult[] | null;
  /** post-apply re-run of the shadow test (not part of planHash) */
  verification: ShadowResult[] | null;
  approval: {
    required: boolean;
    approvedBy: string | null;
    /** display label of the approver */
    approvedByLabel?: string | null;
    approvedAt: string | null;
  };
  cutover: GatewayCutover;
  createdBy: string;
  /** display label of the creator */
  createdByLabel?: string | null;
  createdAt: string;
  updatedAt: string;
  allowedActions: Array<'shadow_test' | 'approve' | 'apply' | 'rollback' | 'cancel'>;
}

export const shadowTestSchema = z
  .object({
    /** server that runs the probes (default: the gateway itself) */
    probeServerId: z.string().uuid().optional(),
    /** request path (default: each route's healthPath) */
    path: z.string().regex(HEALTH_PATH_RE).optional(),
    expectStatus: z.array(z.number().int().min(100).max(599)).min(1).max(10).optional(),
  })
  .strict();
export type ShadowTestInput = z.infer<typeof shadowTestSchema>;

export const approveGatewayPlanSchema = z
  .object({ planHash: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();
