import { z } from 'zod';

/** systemd unit name accepted by typed jobs (no path traversal, must start alphanumeric). */
export const SYSTEMD_UNIT_RE = /^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,127}\.service$/;
export const systemdUnitSchema = z
  .string()
  .regex(SYSTEMD_UNIT_RE)
  .refine((u) => !u.includes('..'), { message: "unit must not contain '..'" });

export const DISCOVERY_SOURCES = ['nginx', 'docker', 'systemd', 'php-fpm', 'ports'] as const;

export const JOB_STATUSES = [
  'queued',
  'leased',
  'running',
  'succeeded',
  'failed',
  'expired',
  'cancelled',
] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

/** Typed job allowlist. `mutating` jobs are never re-leased after lease expiry. */
export const JOB_TYPES = {
  'inventory.collect': { mutating: false, params: z.object({}).strict() },
  'discovery.scan': {
    mutating: false,
    params: z
      .object({
        sources: z
          .array(z.enum(DISCOVERY_SOURCES))
          .min(1)
          .refine((a) => new Set(a).size === a.length, { message: 'sources must be unique' }),
      })
      .strict(),
  },
  'service.restart': {
    mutating: true,
    params: z.object({ unit: systemdUnitSchema }).strict(),
  },
} as const;
export type JobType = keyof typeof JOB_TYPES;

export interface Job {
  id: string;
  serverId: string;
  type: JobType;
  params: Record<string, unknown>;
  status: JobStatus;
  idempotencyKey: string;
  expiresAt: string;
  leaseUntil: string | null;
  attempt: number;
  desiredVersion: number | null;
  actorId: string | null;
  correlationId: string;
  result: unknown;
  createdAt: string;
  updatedAt: string;
}

export interface TaskGrant {
  jobId: string;
  type: JobType;
  params: Record<string, unknown>;
  idempotencyKey: string;
  issuedAt: string;
  expiresAt: string;
  leaseToken: string;
  desiredVersion: number | null;
  serverId: string;
}

// ---- additions (Center API P2.01) ----

export const createJobSchema = z
  .object({
    type: z.string().min(1).max(64),
    params: z.record(z.unknown()).default({}),
    /** Absolute expiry window for the job; after it the job is never delivered. */
    ttlSec: z.number().int().min(30).max(86_400).default(600),
    desiredVersion: z.number().int().nonnegative().optional(),
  })
  .strict();
export type CreateJobInput = z.infer<typeof createJobSchema>;

export interface JobCreated {
  jobId: string;
  status: JobStatus;
  job: Job;
}

export function isJobType(t: string): t is JobType {
  return Object.prototype.hasOwnProperty.call(JOB_TYPES, t);
}
