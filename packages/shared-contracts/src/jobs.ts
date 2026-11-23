import { z } from 'zod';

/** systemd unit name accepted by typed jobs (no path traversal, must start alphanumeric). */
export const SYSTEMD_UNIT_RE = /^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,127}\.service$/;
export const systemdUnitSchema = z
  .string()
  .regex(SYSTEMD_UNIT_RE)
  .refine((u) => !u.includes('..'), { message: "unit must not contain '..'" });

// ---- P3: Nginx typed jobs (see docs/AGENT_PROTOCOL.md §Nginx) ----

/** Absolute nginx config path under /etc/nginx; no traversal, no NUL/newline, no glob. */
export const NGINX_PATH_RE = /^\/etc\/nginx\/[A-Za-z0-9._\/-]{1,200}$/;
export const nginxPathSchema = z
  .string()
  .regex(NGINX_PATH_RE)
  .refine((p) => !p.split('/').includes('..') && !p.includes('//'), {
    message: 'path must be canonical (no .. or //)',
  });
/** Files pPanel may create (never pre-existing operator files). */
export const NGINX_MANAGED_DIR = '/etc/nginx/ppanel-managed/';
export const NGINX_MAX_FILE_BYTES = 262144;
export const sha256HexSchema = z.string().regex(/^[a-f0-9]{64}$/);

export const nginxFileChangeSchema = z
  .object({
    path: nginxPathSchema,
    /** sha256 of current content; null = file must NOT exist yet (create, only under NGINX_MANAGED_DIR). */
    expectedSha256Before: sha256HexSchema.nullable(),
    /** Full new content (UTF-8). */
    content: z.string().max(NGINX_MAX_FILE_BYTES),
  })
  .strict();

/** Loopback-only HTTP probe run by the agent after reload (SSRF-safe: host is fixed to 127.0.0.1). */
export const nginxPostcheckSchema = z
  .object({
    hostHeader: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/),
    path: z
      .string()
      .regex(/^\/[A-Za-z0-9._~\/?=&%-]{0,200}$/)
      .default('/'),
    scheme: z.enum(['http', 'https']).default('http'),
    port: z.number().int().min(1).max(65535).optional(),
    expectStatus: z.array(z.number().int().min(100).max(599)).min(1).max(10).default([200]),
  })
  .strict();

const nginxRevisionParams = z
  .object({
    revisionId: z.string().uuid(),
    files: z
      .array(nginxFileChangeSchema)
      .min(1)
      .max(20)
      .refine((a) => new Set(a.map((f) => f.path)).size === a.length, {
        message: 'paths must be unique',
      }),
  })
  .strict();

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
  /** Read-only: return content + sha256 of files under /etc/nginx (for diff/preview). */
  'nginx.read_files': {
    mutating: false,
    params: z.object({ paths: z.array(nginxPathSchema).min(1).max(20) }).strict(),
  },
  /** Dry-run: preflight + backup + write + `nginx -t`, then ALWAYS restore originals. Never reloads. */
  'nginx.validate': { mutating: true, params: nginxRevisionParams },
  /** Preflight → backup → atomic write → nginx -t → reload → postcheck → auto-revert on failure. */
  'nginx.apply': {
    mutating: true,
    params: nginxRevisionParams

      .extend({ postchecks: z.array(nginxPostcheckSchema).max(10).default([]) })
      .strict(),
  },
  /** Restore the backup taken by a previous apply of `revisionId`, then nginx -t + reload. */
  'nginx.revert': {
    mutating: true,
    params: z
      .object({
        revisionId: z.string().uuid(),
        /** sha256 the agent must currently see for each file (the revision's after-state) — drift guard. */
        expectedCurrent: z
          .array(z.object({ path: nginxPathSchema, sha256: sha256HexSchema.nullable() }).strict())
          .min(1)
          .max(20),
      })
      .strict(),
  },
} as const;

/** Agent result error codes added in P3. */
export const NGINX_ERROR_CODES = [
  'PATH_NOT_ALLOWED',
  'DRIFT_DETECTED',
  'NGINX_TEST_FAILED',
  'RELOAD_FAILED_REVERTED',
  'POSTCHECK_FAILED_REVERTED',
  'REVERT_FAILED_MANUAL_RECOVERY',
  'BACKUP_NOT_FOUND',
  'NGINX_NOT_PRESENT',
] as const;
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
