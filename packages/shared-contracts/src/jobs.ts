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

// ---- P4: container typed jobs (see docs/AGENT_PROTOCOL.md §Containers) ----

/** Application slug used in container/network/route names. */
export const APP_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
export const appSlugSchema = z.string().regex(APP_SLUG_RE);
/** Image reference pinned by digest: `registry/repo@sha256:<64 hex>` (tags alone are refused). */
export const IMAGE_DIGEST_REF_RE =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$/;
export const imageDigestRefSchema = z.string().max(400).regex(IMAGE_DIGEST_REF_RE);
/** Managed container name: ppanel-<app>-<8 hex deployment short id>. */
export const MANAGED_CONTAINER_RE = /^ppanel-[a-z0-9][a-z0-9-]{0,40}-[a-f0-9]{8}$/;
export const managedContainerSchema = z.string().regex(MANAGED_CONTAINER_RE);
export const ENV_KEY_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;
/** Host ports pPanel may bind; always on 127.0.0.1 only (nginx proxies to it). */
export const MANAGED_PORT_MIN = 20000;
export const MANAGED_PORT_MAX = 29999;

export const containerHealthcheckSchema = z
  .object({
    path: z
      .string()
      .regex(/^\/[A-Za-z0-9._~\/?=&%-]{0,200}$/)
      .default('/'),
    expectStatus: z.array(z.number().int().min(100).max(599)).min(1).max(10).default([200]),
    intervalSec: z.number().int().min(1).max(30).default(2),
    timeoutSec: z.number().int().min(1).max(30).default(3),
    /** Total time the candidate has to become healthy. */
    startPeriodSec: z.number().int().min(1).max(600).default(60),
  })
  .strict();

export const containerResourcesSchema = z
  .object({
    memoryMb: z.number().int().min(32).max(65536).default(512),
    cpus: z.number().min(0.1).max(64).default(1),
    pids: z.number().int().min(16).max(32768).default(512),
  })
  .strict();

export const containerRunCandidateParams = z
  .object({
    deploymentId: z.string().uuid(),
    app: appSlugSchema,
    name: managedContainerSchema,
    image: imageDigestRefSchema,
    containerPort: z.number().int().min(1).max(65535),
    hostPort: z.number().int().min(MANAGED_PORT_MIN).max(MANAGED_PORT_MAX),
    /** Non-secret env, plain values. */
    env: z.record(z.string().regex(ENV_KEY_RE), z.string().max(4096)).default({}),
    /** Secret env keys; values are fetched once via POST /agent/v1/tasks/:jobId/secrets. */
    secretEnvKeys: z.array(z.string().regex(ENV_KEY_RE)).max(100).default([]),
    /** True when a registry credential must be fetched with the secrets call. */
    registryAuth: z.boolean().default(false),
    /** Named volumes only (`ppanel-<app>-<name>`), never host paths. */
    volumes: z
      .array(
        z
          .object({
            name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,40}$/),
            mountPath: z.string().regex(/^\/[A-Za-z0-9._\/-]{1,200}$/),
          })
          .strict(),
      )
      .max(10)
      .default([]),
    resources: containerResourcesSchema.default({}),
    healthcheck: containerHealthcheckSchema.default({}),
    command: z.array(z.string().max(1024)).max(64).optional(),
    user: z
      .string()
      .regex(/^[A-Za-z0-9_.-]{1,64}(:[A-Za-z0-9_.-]{1,64})?$/)
      .optional(),
    readOnlyRootfs: z.boolean().default(false),
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
  /** Pull by digest, create hardened container on 127.0.0.1:<hostPort>, wait healthy; remove on failure. */
  'container.run_candidate': { mutating: true, params: containerRunCandidateParams },
  /** Stop (not remove) a managed container — keeps it for rollback. */
  'container.stop': {
    mutating: true,
    params: z.object({ app: appSlugSchema, name: managedContainerSchema }).strict(),
  },
  /** Start a stopped managed container and wait for health (rollback / start). */
  'container.start': {
    mutating: true,
    params: z
      .object({
        app: appSlugSchema,
        name: managedContainerSchema,
        hostPort: z.number().int().min(MANAGED_PORT_MIN).max(MANAGED_PORT_MAX),
        healthcheck: containerHealthcheckSchema.default({}),
      })
      .strict(),
  },
  'container.restart': {
    mutating: true,
    params: z
      .object({
        app: appSlugSchema,
        name: managedContainerSchema,
        hostPort: z.number().int().min(MANAGED_PORT_MIN).max(MANAGED_PORT_MAX),
        healthcheck: containerHealthcheckSchema.default({}),
      })
      .strict(),
  },
  'container.remove': {
    mutating: true,
    params: z.object({ app: appSlugSchema, name: managedContainerSchema }).strict(),
  },
  /** Read-only: managed containers of an app (or all managed when app omitted). */
  'container.list': {
    mutating: false,
    params: z.object({ app: appSlugSchema.optional() }).strict(),
  },
  /** Read-only: bounded, redacted container logs. */
  'container.logs': {
    mutating: false,
    params: z
      .object({
        app: appSlugSchema,
        name: managedContainerSchema,
        tailLines: z.number().int().min(1).max(1000).default(200),
        sinceSec: z.number().int().min(1).max(86400).optional(),
      })
      .strict(),
  },
} as const;

/** Agent result error codes added in P3. */
/** Agent result error codes added in P4. */
export const CONTAINER_ERROR_CODES = [
  'DOCKER_UNAVAILABLE',
  'IMAGE_PULL_FAILED',
  'PORT_IN_USE',
  'CONTAINER_EXISTS',
  'CONTAINER_NOT_MANAGED',
  'CONTAINER_NOT_FOUND',
  'CANDIDATE_UNHEALTHY',
  'SECRETS_UNAVAILABLE',
] as const;

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
