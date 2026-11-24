// P4b — build nodes, builds from source, source inspection, Compose applications (Center read models).
// Source of truth: docs/API_CONTRACTS.md §8 (job params live in ./jobs).
import { z } from 'zod';
import type { DetectResult } from './detect';
import { containerTlsSchema, domainSchema } from './deploy';
import {
  APP_SLUG_RE,
  COMMIT_SHA_RE,
  DOCKERFILE_TEMPLATES,
  ENV_KEY_RE,
  GIT_URL_RE,
  IMAGE_REPO_RE,
  isRepoRelPath,
} from './jobs';
import { ENVIRONMENTS } from './server';

// ---------------------------------------------------------------- build config + git auth (§8.1)

/** Reserved secret key holding the git token (never an env secret, never returned). */
export const GIT_TOKEN_SECRET_KEY = '__GIT_TOKEN__';
/** Secret keys managed through dedicated endpoints (not usable as env secrets). */
export const RESERVED_SECRET_KEYS = ['__REGISTRY_AUTH__', GIT_TOKEN_SECRET_KEY] as const;

const relPath = (max: number) =>
  z
    .string()
    .regex(new RegExp(`^[A-Za-z0-9._\\/-]{1,${max}}$`))
    .refine((p) => !p.split('/').includes('..') && !p.startsWith('/'), 'path must be relative');

export const buildLimitsSchema = z
  .object({
    memoryMb: z.number().int().min(256).max(32768).default(2048),
    cpus: z.number().min(0.5).max(32).default(2),
    timeoutSec: z.number().int().min(60).max(3600).default(900),
  })
  .strict();

const buildConfigBase = z
  .object({
    /** https (or git:// in dev) URL without credentials; host must be in PPANEL_GIT_HOST_ALLOWLIST. */
    repoUrl: z.string().trim().max(600).regex(GIT_URL_RE, 'repoUrl must be https://host/path'),
    subdir: z
      .string()
      .regex(/^[A-Za-z0-9._\/-]{0,200}$/)
      .refine(
        isRepoRelPath,
        'subdir must be a relative path inside the repository (no .., no .git)',
      )
      .default(''),
    dockerfile: relPath(200).optional(),
    template: z.enum(DOCKERFILE_TEMPLATES).optional(),
    buildArgs: z
      .record(z.string().regex(ENV_KEY_RE), z.string().max(1024))
      .refine((r) => Object.keys(r).length <= 50, 'at most 50 build args')
      .default({}),
    target: z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,64}$/)
      .optional(),
    buildServerId: z.string().uuid(),
    /** registry[:port]/path (no tag); registry must be allowlisted (PPANEL_REGISTRY_ALLOWLIST). */
    pushRepo: z.string().max(300).regex(IMAGE_REPO_RE, 'pushRepo must be registry/repository'),
    network: z.enum(['default', 'none']).default('default'),
    limits: buildLimitsSchema.default({}),
  })
  .strict();

export const buildConfigSchema = buildConfigBase.refine(
  (p) => (p.dockerfile ? !p.template : !!p.template),
  { message: 'exactly one of dockerfile or template is required', path: ['dockerfile'] },
);
export type BuildConfigInput = z.infer<typeof buildConfigSchema>;

export interface BuildConfig {
  repoUrl: string;
  /** `org/name` derived from the URL path when it has exactly two segments (for sourceRef). */
  repo: string | null;
  subdir: string;
  dockerfile: string | null;
  template: (typeof DOCKERFILE_TEMPLATES)[number] | null;
  buildArgs: Record<string, string>;
  target: string | null;
  buildServerId: string;
  pushRepo: string;
  network: 'default' | 'none';
  limits: z.infer<typeof buildLimitsSchema>;
  gitAuth: { set: boolean };
  updatedAt: string;
  version: number;
}

/** `Application.build` summary (config + last build). */
export interface ApplicationBuildSummary {
  config: BuildConfig;
  lastBuild: {
    id: string;
    status: BuildStatus;
    commitSha: string;
    image: string | null;
    finishedAt: string | null;
  } | null;
}

export const gitAuthSchema = z.object({ token: z.string().min(1).max(4096) }).strict();

// ---------------------------------------------------------------- builds (§8.2)

export const BUILD_STATUSES = [
  'queued',
  'fetching',
  'building',
  'pushing',
  'succeeded',
  'failed',
  'cancelled',
  'expired',
] as const;
export type BuildStatus = (typeof BUILD_STATUSES)[number];
/** At most one build per (application, commit) may be in one of these states (DB partial unique index). */
export const BUILD_ACTIVE_STATUSES = [
  'queued',
  'fetching',
  'building',
  'pushing',
] as const satisfies readonly BuildStatus[];
export const BUILD_TRIGGERS = ['manual', 'webhook'] as const;
export type BuildTrigger = (typeof BUILD_TRIGGERS)[number];

export const createBuildSchema = z
  .object({
    commitSha: z.string().regex(COMMIT_SHA_RE, 'commitSha must be 40 lowercase hex'),
    branch: z
      .string()
      .regex(/^[A-Za-z0-9._\/-]{1,255}$/)
      .optional(),
    /** On success, create a deployment pinned to the produced digest (default true). */
    deployAfter: z.boolean().default(true),
    /** Rebuild even when a succeeded build of the same commit exists. */
    force: z.boolean().default(false),
  })
  .strict();
export type CreateBuildInput = z.infer<typeof createBuildSchema>;

export const BUILD_ACTIONS = ['cancel', 'view_log'] as const;
export type BuildAction = (typeof BUILD_ACTIONS)[number];

export interface Build {
  id: string;
  applicationId: string;
  buildServerId: string;
  status: BuildStatus;
  commitSha: string;
  branch: string | null;
  trigger: BuildTrigger;
  /** `<pushRepo>@sha256:…` once pushed */
  image: string | null;
  template: string | null;
  dockerfile: string | null;
  pushRepo: string;
  deployAfter: boolean;
  logTail: string[];
  error: { code: string; message: string; details?: unknown } | null;
  durationMs: number | null;
  jobId: string | null;
  deploymentId: string | null;
  /** set when deployAfter could not create the deployment (e.g. DEPLOYMENT_IN_PROGRESS) */
  deployError: { code: string; message: string } | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
  allowedActions: BuildAction[];
}

export interface BuildLog {
  buildId: string;
  status: BuildStatus;
  lines: string[];
  truncated: boolean;
}

/** Bounded build log stored by the Center (agent sends ≤ 2000 lines / 512 KiB). */
export const BUILD_LOG_MAX_LINES = 2000;
export const BUILD_LOG_MAX_BYTES = 524_288;

// ---------------------------------------------------------------- source inspection (§8.2)

export const sourceInspectSchema = z
  .object({ commitSha: z.string().regex(COMMIT_SHA_RE, 'commitSha must be 40 lowercase hex') })
  .strict();

export interface SourceInspection {
  inspectionId: string;
  jobId: string;
  status: 'pending' | 'succeeded' | 'failed';
  commitSha: string;
  files: Record<string, string>;
  truncated: string[];
  detection: DetectResult | null;
  error: { code: string; message: string } | null;
}

// ---------------------------------------------------------------- compose applications (§8.3)

export const COMPOSE_SERVICE_NAME_RE = /^[a-z0-9][a-z0-9-]{0,30}$/;
const healthPathSchema = z
  .string()
  .regex(/^\/[A-Za-z0-9._~\/?=&%-]{0,200}$/)
  .default('/');

export const createComposeAppSchema = z
  .object({
    kind: z.literal('compose'),
    serverId: z.string().uuid(),
    name: z.string().regex(APP_SLUG_RE, 'name must be a lowercase slug (a-z0-9-, ≤ 41 chars)'),
    environment: z.enum(ENVIRONMENTS).optional(),
    domains: z
      .array(domainSchema)
      .min(1)
      .max(10)
      .refine((a) => new Set(a).size === a.length, 'domains must be unique'),
    yaml: z.string().min(1).max(262_144),
    routeService: z.string().regex(COMPOSE_SERVICE_NAME_RE),
    routePort: z.number().int().min(1).max(65535),
    healthPath: healthPathSchema.optional(),
    tls: containerTlsSchema.optional(),
  })
  .strict();
export type CreateComposeAppInput = z.infer<typeof createComposeAppSchema>;

export const updateComposeSchema = z
  .object({
    yaml: z.string().min(1).max(262_144),
    routeService: z.string().regex(COMPOSE_SERVICE_NAME_RE),
    routePort: z.number().int().min(1).max(65535),
    healthPath: healthPathSchema.optional(),
  })
  .strict();
export type UpdateComposeInput = z.infer<typeof updateComposeSchema>;

export type ComposeHealth =
  | {
      type: 'http';
      port: number;
      path: string;
      expectStatus: number[];
      intervalSec: number;
      timeoutSec: number;
      startPeriodSec: number;
    }
  | { type: 'tcp'; port: number; startPeriodSec: number }
  | { type: 'running'; startPeriodSec: number };

/** Normalised service as stored in a compose version (image as written; digests are per deployment). */
export interface ComposePlanService {
  service: string;
  image: string;
  env: Record<string, string>;
  /** VAR → application secret key */
  secretEnv: Record<string, string>;
  command?: string[];
  volumes: Array<{ name: string; mountPath: string }>;
  dependsOn: string[];
  health: ComposeHealth;
  /** route service only */
  containerPort?: number;
}

export interface ComposeAppConfig {
  version: number;
  versionId: string;
  routeService: string;
  routePort: number;
  healthPath: string;
  /** services in dependency order */
  services: ComposePlanService[];
  /** `${VAR}` placeholders → required app secrets */
  secretKeys: string[];
  warnings: Array<{ service: string | null; rule: string; path: string; message: string }>;
  currentDeploymentId: string | null;
  previousDeploymentId: string | null;
  /** route container currently serving */
  containerName: string | null;
  hostPort: number | null;
  routePath: string;
  tls: { certPath: string; keyPath: string } | null;
  rollbackAvailable: boolean;
  /** Rollback re-applies the previous plan; it never restores volumes or database data. */
  rollback: { dataRestored: false };
  createdAt: string;
}

export const COMPOSE_SERVICE_ACTIONS = ['unchanged', 'created', 'replaced'] as const;
export type ComposeServiceAction = (typeof COMPOSE_SERVICE_ACTIONS)[number];

/** Per-deployment compose plan (digests resolved) + per-service results. */
export interface DeploymentCompose {
  versionId: string;
  version: number;
  routeService: string;
  services: Array<{
    service: string;
    image: string;
    /** image as written in the YAML (tag or digest) */
    sourceImage: string;
    specHash: string;
    name: string;
    /** predicted from the current plan before execution, then the agent's reported action */
    plannedAction: 'unchanged' | 'replace';
    action: ComposeServiceAction | null;
    previousName: string | null;
    hostPort: number | null;
    health: string | null;
  }>;
  /** Rollback re-applies a previous plan; volumes / database data are never restored. */
  dataRestored: false;
}

export const BUILD_SECRET_HEADER_PREFIX = 'Authorization: Basic ';
/** `Authorization: Basic base64(x-access-token:<token>)` — the header the agent passes to git. */
export function gitAuthHeader(token: string, encode: (s: string) => string): string {
  return `${BUILD_SECRET_HEADER_PREFIX}${encode(`x-access-token:${token}`)}`;
}
