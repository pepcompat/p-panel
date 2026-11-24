import { z } from 'zod';
import {
  agentProviderFactsSchema,
  type GatewayEndpoint,
  heartbeatConnectionSchema,
  type HeartbeatConnectionDirective,
} from './network';
import { agentSshFactsSchema } from './ssh';

export const AGENT_PROTOCOL_VERSION = '1';

/** P8: `GET /api/v1/version` (public). Single product version (root VERSION file, SemVer). */
export interface CenterVersionInfo {
  version: string;
  commit: string;
  /** ISO 8601 UTC build time, null for an unstamped dev build */
  buildDate: string | null;
  agentProtocol: typeof AGENT_PROTOCOL_VERSION;
  /** agents older than this are `agentOutdated` and get 409 AGENT_OUTDATED for mutating jobs */
  minAgentVersion: string;
  /** name of the latest applied Prisma migration, null when the DB is unreachable */
  schemaVersion: string | null;
}
export const AGENT_PROTOCOL_HEADER = 'X-Agent-Protocol';

const osFacts = z
  .object({
    id: z.string().max(64),
    version: z.string().max(64),
    arch: z.string().max(32),
    kernel: z.string().max(128).optional(),
    name: z.string().max(128).optional(),
  })
  .strip();

/** Agent token shape (informational: the Center answers any non-matching token with the uniform 401). */
export const ENROLLMENT_TOKEN_RE = /^ppe_[A-Za-z0-9_-]{16,128}$/;

export const agentEnrollSchema = z.object({
  token: z.string().min(1).max(256),
  csrPem: z.string().min(100).max(16_384),
  hostname: z.string().trim().min(1).max(253),
  facts: z
    .object({
      os: osFacts.optional(),
      agentVersion: z.string().max(64).optional(),
      /** P9: DigitalOcean metadata facts (null/absent = not a DO droplet or metadata unreachable) */
      provider: agentProviderFactsSchema.nullish().catch(null),
      /** P10: sshd host key fingerprints + port (null = none readable) */
      ssh: agentSshFactsSchema.nullish().catch(null),
    })
    .strip()
    .optional(),
});
export type AgentEnrollInput = z.infer<typeof agentEnrollSchema>;

export interface AgentEnrollResponse {
  serverId: string;
  certificatePem: string;
  caPem: string;
  gatewayUrl: string;
  /** P9: every advertised management path (public always; private when configured) */
  gatewayEndpoints: GatewayEndpoint[];
  heartbeatIntervalSec: number;
}

export const heartbeatAddressSchema = z
  .object({
    family: z.enum(['ipv4', 'ipv6']),
    scope: z.enum(['public', 'private']),
    address: z.string().ip(),
    interface: z.string().max(64).optional(),
    source: z.literal('detected').optional(),
  })
  .strip();

const pct = z.number().min(0).max(100);
/** Go encodes empty slices as null; treat null as an empty list. */
const nullAsEmpty = (v: unknown) => (v === null ? undefined : v);
const byteCount = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);

export const CONTAINER_STATES = [
  'running',
  'exited',
  'restarting',
  'paused',
  'created',
  'dead',
  'removing',
] as const;
export type ContainerState = (typeof CONTAINER_STATES)[number];
export const CONTAINER_HEALTHS = ['healthy', 'unhealthy', 'starting', 'none'] as const;
export type ContainerHealth = (typeof CONTAINER_HEALTHS)[number];

/** P5 heartbeat `containers[]` entry (agent reports only containers carrying the ownership labels). */
export const heartbeatContainerSchema = z
  .object({
    name: z.string().regex(/^ppanel-[a-z0-9][a-z0-9_.-]{0,120}$/),
    app: z.string().min(1).max(64),
    service: z.string().max(64).nullish(),
    deploymentId: z.string().uuid().nullish(),
    state: z.enum(CONTAINER_STATES),
    health: z.enum(CONTAINER_HEALTHS).nullish(),
    restartCount: z.number().int().nonnegative().max(1_000_000_000).nullish(),
    cpuPct: z.number().nonnegative().max(100_000).nullish(),
    memBytes: byteCount.nullish(),
    memLimitBytes: byteCount.nullish(),
  })
  .strip();
export type HeartbeatContainer = z.infer<typeof heartbeatContainerSchema>;

export const heartbeatLogShippingSchema = z
  .object({
    bufferedBytes: byteCount.default(0),
    bufferCapBytes: byteCount.nullish(),
    droppedEntries: byteCount.default(0),
    lastShippedAt: z.string().datetime({ offset: true }).nullish(),
  })
  .strip();
export type HeartbeatLogShipping = z.infer<typeof heartbeatLogShippingSchema>;
export const heartbeatSchema = z.object({
  seq: z.number().int().nonnegative(),
  sentAt: z.string().datetime({ offset: true }),
  agentVersion: z.string().max(64),
  metrics: z
    // Unknown metrics are OMITTED by the agent (never sent as 0); the Center stores them as null.
    .object({
      cpuPct: pct.optional(),
      memPct: pct.optional(),
      diskPct: pct.optional(),
      load1: z.number().nonnegative().optional(),
      uptimeSec: z.number().nonnegative().transform(Math.floor).optional(),
      // P5 extension (omitted when unknown, never 0-as-unknown)
      memTotalBytes: byteCount.optional(),
      memAvailableBytes: byteCount.optional(),
      diskTotalBytes: byteCount.optional(),
      diskFreeBytes: byteCount.optional(),
      netRxBytes: byteCount.optional(),
      netTxBytes: byteCount.optional(),
    })
    .strip()
    .default({}),
  /** P5: latest sample of pPanel-managed containers only (≤ 50). */
  // absent = agent does not report containers (pre-P5); null/[] = it reports none
  containers: z
    .preprocess((v) => (v === null ? [] : v), z.array(heartbeatContainerSchema).max(50))
    .optional(),
  /** P5: agent log shipping state. */
  logShipping: heartbeatLogShippingSchema.optional(),
  addresses: z.preprocess(nullAsEmpty, z.array(heartbeatAddressSchema).max(64).default([])),
  capabilities: z.preprocess(
    nullAsEmpty,
    z
      .array(z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/))
      .max(64)
      .default([]),
  ),
  runningJobIds: z.preprocess(nullAsEmpty, z.array(z.string().uuid()).max(100).default([])),
  os: osFacts.optional(),
  /** P9: per-endpoint probe results (absent = agent does not probe yet) */
  // a malformed P9 block is ignored (never fails the heartbeat → the server would look offline)
  connection: heartbeatConnectionSchema.optional().catch(undefined),
  /** P9: DigitalOcean metadata facts (null = metadata absent; undefined = not reported) */
  provider: agentProviderFactsSchema.nullish().catch(undefined),
  /** P10: sshd host key fingerprints + port (null = absent; undefined = not reported → kept) */
  ssh: agentSshFactsSchema.nullish().catch(undefined),
});
export type HeartbeatInput = z.infer<typeof heartbeatSchema>;

export interface HeartbeatResponse {
  serverTime: string;
  heartbeatIntervalSec: number;
  /** ISO time after which the agent should call /agent/v1/certificate/rotate. */
  certRenewAfter: string;
  /** P9: connection policy + advertised endpoints (agent persists it as connection.json, 0600) */
  connection: HeartbeatConnectionDirective;
}

export const certificateRotateSchema = z
  .object({ csrPem: z.string().min(100).max(16_384) })
  .strict();

export const taskAckSchema = z.object({ leaseToken: z.string().min(16).max(128) }).strict();
/** Error codes the Go agent reports in `result.error.code`. */
export const AGENT_RESULT_ERROR_CODES = [
  'REJECTED_EXPIRED',
  'REJECTED_UNKNOWN_TYPE',
  'REJECTED_WRONG_SERVER',
  'REJECTED_INVALID_PARAMS',
  'REJECTED_INVALID_GRANT',
  'REJECTED_NOT_OWNED',
  'HANDLER_FAILED',
  'HANDLER_TIMEOUT',
  'AGENT_INTERRUPTED',
  /** acked, but the agent could not persist "started" (state dir unwritable/full): NOT executed */
  'AGENT_STATE_WRITE_FAILED',
] as const;
export type AgentResultErrorCode = (typeof AGENT_RESULT_ERROR_CODES)[number];

export const taskResultErrorSchema = z
  .object({
    code: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/),
    message: z.string().max(4096).optional(),
    details: z.unknown().optional(),
  })
  .strip();

/**
 * Result may be posted for a job that is `leased` (not acked: rejections, cached replays) or `running`.
 * `rejected` is accepted as an alias of `failed` (stored as status `failed` with error.code REJECTED_*).
 * Replayed outputs > 8 KiB arrive as `{ truncated: true, originalBytes: N }`.
 */
export const taskResultSchema = z
  .object({
    leaseToken: z.string().min(16).max(128),
    status: z.enum(['succeeded', 'failed', 'rejected']),
    output: z.unknown().optional(),
    error: z
      .union([z.string().max(4096), taskResultErrorSchema])
      .nullable()
      .optional(),
  })
  .strict();
export type TaskResultInput = z.infer<typeof taskResultSchema>;
