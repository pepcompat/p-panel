import { z } from 'zod';

export const AGENT_PROTOCOL_VERSION = '1';
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
    })
    .strip()
    .default({}),
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
});
export type HeartbeatInput = z.infer<typeof heartbeatSchema>;

export interface HeartbeatResponse {
  serverTime: string;
  heartbeatIntervalSec: number;
  /** ISO time after which the agent should call /agent/v1/certificate/rotate. */
  certRenewAfter: string;
}

export const certificateRotateSchema = z.object({ csrPem: z.string().min(100).max(16_384) }).strict();

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
    error: z.union([z.string().max(4096), taskResultErrorSchema]).nullable().optional(),
  })
  .strict();
export type TaskResultInput = z.infer<typeof taskResultSchema>;
