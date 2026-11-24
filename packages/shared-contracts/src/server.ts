import { z } from 'zod';
import { systemdUnitSchema } from './jobs';

export const ENVIRONMENTS = ['production', 'uat', 'development'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

export const SERVER_STATUSES = [
  'enrolling',
  'online',
  'degraded',
  'offline',
  'stale',
  'revoked',
] as const;
export type ServerStatus = (typeof SERVER_STATUSES)[number];

export const CONNECTION_POLICIES = [
  'auto',
  'private_preferred',
  'private_only',
  'public_preferred',
  'public_only',
] as const;
export type ConnectionPolicy = (typeof CONNECTION_POLICIES)[number];

export interface ServerAddress {
  family: 'ipv4' | 'ipv6';
  scope: 'public' | 'private';
  address: string;
  interface?: string;
  source: 'detected' | 'override';
  verifiedAt: string | null;
}

/** Unknown/unsampled metrics are `null` — never reported as 0. */
export interface ServerMetrics {
  cpuPct: number | null;
  memPct: number | null;
  diskPct: number | null;
  load1?: number | null;
  uptimeSec?: number | null;
  sampledAt: string;
  stale: boolean;
}

export interface Server {
  id: string;
  name: string;
  hostname: string;
  environment: Environment;
  groupId: string | null;
  tags: string[];
  status: ServerStatus;
  lastHeartbeatAt: string | null;
  agentVersion: string | null;
  /**
   * P8: true when `agentVersion` is older than the Center's `minAgentVersion` (GET /version). Outdated
   * agents keep running workloads; new mutating jobs are refused with 409 AGENT_OUTDATED.
   */
  agentOutdated?: boolean;
  os: { id: string; version: string; arch: string; kernel?: string } | null;
  provider: {
    name: string | null;
    region: string | null;
    dropletId: string | null;
    vpcUuid: string | null;
  } | null;
  addresses: ServerAddress[];
  connectionPolicy: ConnectionPolicy;
  metrics: ServerMetrics | null;
  capabilities: string[];
  /** P4b: Center-side build node designation (builds also need the agent's `build` capability). */
  buildNode: boolean;
  certificate: { serial: string; notAfter: string } | null;
  allowedActions: string[];
  createdAt: string;
  updatedAt: string;
  version: number;
}

export const HEARTBEAT_INTERVAL_SEC = 15;
export const STALE_AFTER_SEC = 45;
export const OFFLINE_AFTER_SEC = 120;

export const createEnrollmentSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1)
    .max(63)
    .regex(/^[a-z0-9][a-z0-9-]*$/),
  environment: z.enum(ENVIRONMENTS),
  tags: z.array(z.string().trim().min(1).max(32)).max(20).optional(),
  ttlMinutes: z.number().int().min(5).max(60).default(15),
});
export type CreateEnrollmentInput = z.infer<typeof createEnrollmentSchema>;

export interface EnrollmentCreated {
  enrollmentId: string;
  token: string;
  expiresAt: string;
  /** P8: downloads + verifies install-agent.sh from the release, installs the agent and enrolls */
  installCommand: string;
  /** enroll only (agent binary already installed): `sudo ppanel-agent enroll --center … --token …` */
  enrollCommand?: string;
}

// ---- additions (Center API P1.06) ----

export const updateServerSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1)
      .max(63)
      .regex(/^[a-z0-9][a-z0-9-]*$/)
      .optional(),
    environment: z.enum(ENVIRONMENTS).optional(),
    tags: z.array(z.string().trim().min(1).max(32)).max(20).optional(),
    groupId: z.string().uuid().nullable().optional(),
    connectionPolicy: z.enum(CONNECTION_POLICIES).optional(),
    /** systemd units allowlisted for typed jobs such as service.restart (owned-resource allowlist). */
    ownedUnits: z.array(systemdUnitSchema).max(100).optional(),
    /** P4b: designate as build node (needs `policies.manage`). */
    buildNode: z.boolean().optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, { message: 'at least one field is required' });
export type UpdateServerInput = z.infer<typeof updateServerSchema>;

export const createServerGroupSchema = z
  .object({
    name: z.string().trim().min(1).max(63),
    description: z.string().trim().max(500).optional(),
    environment: z.enum(ENVIRONMENTS).optional(),
  })
  .strict();
export type CreateServerGroupInput = z.infer<typeof createServerGroupSchema>;

export interface ServerGroup {
  id: string;
  name: string;
  description: string | null;
  environment: Environment | null;
  serverCount: number;
  createdAt: string;
  updatedAt: string;
}

export type EnrollmentStatus = 'pending' | 'used' | 'expired';
export interface Enrollment {
  id: string;
  name: string;
  environment: Environment;
  tags: string[];
  status: EnrollmentStatus;
  expiresAt: string;
  usedAt: string | null;
  serverId: string | null;
  createdById: string | null;
  createdAt: string;
}

export interface Heartbeat {
  id: string;
  seq: number;
  sentAt: string | null;
  receivedAt: string;
  agentVersion: string | null;
  metrics: Record<string, number> | null;
}
