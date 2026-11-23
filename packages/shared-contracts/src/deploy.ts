// P4a — container applications, secrets, deployments, managed routing, GitHub webhooks.
// Source of truth: docs/API_CONTRACTS.md §7.
import { z } from 'zod';
import {
  APP_SLUG_RE,
  containerHealthcheckSchema,
  containerResourcesSchema,
  ENV_KEY_RE,
  IMAGE_DIGEST_REF_RE,
} from './jobs';
import { ENVIRONMENTS } from './server';

// ---------------------------------------------------------------- hostnames / domains

/**
 * Strict DNS hostname used for route `server_name` and postcheck `Host` headers: lowercase LDH labels
 * (1–63 chars, no leading/trailing hyphen), ≥ 2 labels, alphabetic TLD (no bare IPs), ≤ 253 chars.
 * Anything else (spaces, `;`, `{`, `$`, `*`, quotes, newlines …) is rejected — the route template
 * interpolates domains verbatim, so this regex is the injection boundary.
 */
export const HOSTNAME_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function isValidHostname(value: unknown): value is string {
  return typeof value === 'string' && HOSTNAME_RE.test(value);
}

export const domainSchema = z
  .string()
  .trim()
  .toLowerCase()
  .refine(isValidHostname, { message: 'must be a valid DNS hostname (e.g. app.example.com)' });

const uniqueStrings = (a: string[]) => new Set(a).size === a.length;

/** Operator-provided certificate paths that already exist on the host (ACME issuance is P4 BLOCKED). */
export const TLS_PATH_RE = /^\/etc\/(?:ssl|letsencrypt\/live)\/[A-Za-z0-9._\/-]{1,200}$/;
const tlsPathSchema = z
  .string()
  .regex(TLS_PATH_RE)
  .refine((p) => !p.split('/').includes('..') && !p.includes('//'), {
    message: 'path must be canonical (no .. or //)',
  });
export const containerTlsSchema = z
  .object({ certPath: tlsPathSchema, keyPath: tlsPathSchema })
  .strict();

export const containerVolumeSchema = z
  .object({
    name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,40}$/),
    mountPath: z
      .string()
      .regex(/^\/[A-Za-z0-9._\/-]{1,200}$/)
      .refine((p) => !p.split('/').includes('..'), { message: 'mountPath must be canonical' }),
  })
  .strict();

const envRecordSchema = z
  .record(z.string().regex(ENV_KEY_RE), z.string().max(4096))
  .refine((r) => Object.keys(r).length <= 100, { message: 'at most 100 env keys' });

// ---------------------------------------------------------------- container applications (§7.1)

export const createContainerAppSchema = z
  .object({
    serverId: z.string().uuid(),
    name: z.string().regex(APP_SLUG_RE, 'name must be a lowercase slug (a-z0-9-, ≤ 41 chars)'),
    /** Optional; must equal the target server's environment when given. */
    environment: z.enum(ENVIRONMENTS).optional(),
    domains: z.array(domainSchema).min(1).max(10).refine(uniqueStrings, 'domains must be unique'),
    containerPort: z.number().int().min(1).max(65535),
    healthcheck: containerHealthcheckSchema.optional(),
    resources: containerResourcesSchema.optional(),
    /** Plain, non-secret env. Secret values go through PUT /applications/:id/secrets/:key. */
    env: envRecordSchema.optional(),
    /** Declared secret keys; preflight `secrets_present` requires all of them to be set. */
    secretKeys: z
      .array(z.string().regex(ENV_KEY_RE))
      .max(100)
      .refine(uniqueStrings, 'secretKeys must be unique')
      .optional(),
    volumes: z.array(containerVolumeSchema).max(10).optional(),
    tls: containerTlsSchema.optional(),
  })
  .strict();
export type CreateContainerAppInput = z.infer<typeof createContainerAppSchema>;

/** PATCH /applications/:id/container (extension) — changes invalidate pending approvals (planHash). */
export const updateContainerAppSchema = z
  .object({
    domains: z
      .array(domainSchema)
      .min(1)
      .max(10)
      .refine(uniqueStrings, 'domains must be unique')
      .optional(),
    containerPort: z.number().int().min(1).max(65535).optional(),
    healthcheck: containerHealthcheckSchema.optional(),
    resources: containerResourcesSchema.optional(),
    env: envRecordSchema.optional(),
    secretKeys: z
      .array(z.string().regex(ENV_KEY_RE))
      .max(100)
      .refine(uniqueStrings, 'secretKeys must be unique')
      .optional(),
    volumes: z.array(containerVolumeSchema).max(10).optional(),
    tls: containerTlsSchema.nullable().optional(),
  })
  .strict();
export type UpdateContainerAppInput = z.infer<typeof updateContainerAppSchema>;

export interface ContainerAppConfig {
  containerPort: number;
  healthcheck: z.infer<typeof containerHealthcheckSchema>;
  resources: z.infer<typeof containerResourcesSchema>;
  /** plain env (non-secret) */
  env: Record<string, string>;
  secretKeys: string[];
  volumes: Array<z.infer<typeof containerVolumeSchema>>;
  tls: z.infer<typeof containerTlsSchema> | null;
  currentDeploymentId: string | null;
  previousDeploymentId: string | null;
  /** host port of the currently serving container (127.0.0.1 only) */
  hostPort: number | null;
  /** container name currently serving */
  containerName: string | null;
  /** nginx route file managed by pPanel */
  routePath: string;
  /** `true` when the previous container still exists (rollback possible) */
  rollbackAvailable: boolean;
}

// ---------------------------------------------------------------- secrets (§7.2)

/** Reserved secret key holding the registry credential JSON. */
export const REGISTRY_AUTH_SECRET_KEY = '__REGISTRY_AUTH__';

export const putSecretSchema = z.object({ value: z.string().min(1).max(32_768) }).strict();

export const registryAuthSchema = z
  .object({
    serveraddress: z
      .string()
      .trim()
      .toLowerCase()
      .regex(/^[a-z0-9.-]{1,253}(?::[0-9]{1,5})?$/, 'serveraddress must be host[:port]'),
    username: z.string().min(1).max(256),
    password: z.string().min(1).max(4096),
  })
  .strict();
export type RegistryAuthInput = z.infer<typeof registryAuthSchema>;

export interface SecretSummary {
  key: string;
  set: true;
  version: number;
  updatedAt: string;
}

export interface RegistryAuthView {
  serveraddress: string | null;
  username: string | null;
  set: boolean;
  version?: number;
  updatedAt?: string;
}

/** Response of the agent's fetch-once call (mTLS gateway). */
export interface AgentSecretsResponse {
  env: Record<string, string>;
  registryAuth?: { username: string; password: string; serveraddress: string };
}

// ---------------------------------------------------------------- deployments (§7.3)

export const DEPLOYMENT_STATUSES = [
  'queued',
  'preflight',
  'pulling',
  'starting',
  'health_check',
  'routing',
  'succeeded',
  'failed',
  'rollback_pending',
  'rolled_back',
  'requires_manual_recovery',
  'cancelled',
  'expired',
  'awaiting_approval',
] as const;
export type DeploymentStatus = (typeof DEPLOYMENT_STATUSES)[number];

/** At most one deployment per application may be in one of these states (DB partial unique index). */
export const DEPLOYMENT_ACTIVE_STATUSES = [
  'queued',
  'preflight',
  'pulling',
  'starting',
  'health_check',
  'routing',
  'rollback_pending',
  'awaiting_approval',
] as const satisfies readonly DeploymentStatus[];

/** Cancel is allowed only before route_switch. */
export const DEPLOYMENT_CANCELLABLE_STATUSES = [
  'awaiting_approval',
  'queued',
  'preflight',
  'pulling',
  'starting',
] as const satisfies readonly DeploymentStatus[];

export const DEPLOYMENT_TRIGGERS = ['manual', 'webhook', 'rollback', 'redeploy'] as const;
export type DeploymentTrigger = (typeof DEPLOYMENT_TRIGGERS)[number];

/**
 * `preflight|pull_start|health_check|route_switch|stop_previous` from the contract, plus:
 * `start_target` (rollback: container.start of the previous container),
 * `cleanup_stop`/`cleanup_remove` (candidate removal after a failed route switch / cancel),
 * `prune_remove` (retention: remove containers older than the last 2).
 */
export const DEPLOYMENT_STEP_NAMES = [
  'preflight',
  'pull_start',
  'start_target',
  'health_check',
  'route_switch',
  'stop_previous',
  'cleanup_stop',
  'cleanup_remove',
  'prune_remove',
] as const;
export type DeploymentStepName = (typeof DEPLOYMENT_STEP_NAMES)[number];
export const DEPLOYMENT_STEP_STATUSES = [
  'pending',
  'running',
  'succeeded',
  'failed',
  'skipped',
] as const;
export type DeploymentStepStatus = (typeof DEPLOYMENT_STEP_STATUSES)[number];

export const PREFLIGHT_CHECKS = [
  'agent_online',
  'managed_routing',
  'image_pinned',
  'secrets_present',
  'domain_conflict',
  'port_alloc',
  'disk',
  'lock',
] as const;
export type PreflightCheckName = (typeof PREFLIGHT_CHECKS)[number];

export interface PreflightCheck {
  check: PreflightCheckName;
  ok: boolean;
  code?: string;
  message: string;
  /** non-blocking warning (e.g. DISK_UNKNOWN outside production) */
  warning?: boolean;
  details?: unknown;
}

export const sourceRefSchema = z
  .object({
    repo: z
      .string()
      .regex(/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/)
      .optional(),
    commitSha: z
      .string()
      .regex(/^[a-f0-9]{40}$/)
      .optional(),
    branch: z
      .string()
      .regex(/^[A-Za-z0-9._\/-]{1,255}$/)
      .optional(),
    tag: z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,128}$/)
      .optional(),
  })
  .strict();
export type SourceRef = z.infer<typeof sourceRefSchema>;

export const createDeploymentSchema = z
  .object({
    /** Must be pinned by digest (`registry/repo@sha256:…`) → else 422 IMAGE_NOT_PINNED. */
    image: z.string().trim().min(1).max(400),
    sourceRef: sourceRefSchema.optional(),
    reason: z.string().trim().max(500).optional(),
  })
  .strict();
export type CreateDeploymentInput = z.infer<typeof createDeploymentSchema>;

export const deploymentPreflightSchema = z
  .object({ image: z.string().trim().min(1).max(400).optional() })
  .strict();

export const approveDeploymentSchema = z
  .object({ planHash: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();

export const rollbackSchema = z.object({ reason: z.string().trim().max(500).optional() }).strict();

export function isDigestPinned(image: string): boolean {
  return IMAGE_DIGEST_REF_RE.test(image);
}

export interface DeploymentStep {
  name: DeploymentStepName;
  status: DeploymentStepStatus;
  jobId: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  message: string | null;
  logTail: string[];
  /** agent error code when the step failed */
  errorCode?: string | null;
}

export const DEPLOYMENT_ACTIONS = ['approve', 'cancel'] as const;
export type DeploymentAction = (typeof DEPLOYMENT_ACTIONS)[number];

export interface Deployment {
  id: string;
  applicationId: string;
  serverId: string;
  number: number;
  trigger: DeploymentTrigger;
  image: string;
  sourceRef: SourceRef | null;
  reason: string | null;
  status: DeploymentStatus;
  preflight: PreflightCheck[];
  steps: DeploymentStep[];
  container: { name: string; hostPort: number } | null;
  previousDeploymentId: string | null;
  /** rollback only: the deployment whose container is being restored */
  rollbackOfDeploymentId: string | null;
  planHash: string;
  approval: {
    required: boolean;
    approvedBy: string | null;
    approvedAt: string | null;
    expiresAt: string | null;
  };
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
  error: { code: string; message: string; details?: unknown } | null;
  allowedActions: DeploymentAction[];
  version: number;
}

/** POST /applications/:id/restart|start|stop → 202 */
export interface ContainerOperationAccepted {
  jobId: string;
  operation: 'restart' | 'start' | 'stop';
  container: string;
}

export interface ContainerLogs {
  jobId: string;
  status: 'succeeded' | 'pending';
  lines: string[];
  truncated: boolean;
  container: string | null;
}

// ---------------------------------------------------------------- managed routing

export const MANAGED_ROUTING_CONF_PATH = '/etc/nginx/conf.d/ppanel-managed.conf';
export const MANAGED_ROUTING_CONF_CONTENT = 'include /etc/nginx/ppanel-managed/*/*.conf;\n';
export const MANAGED_ROUTING_STATUSES = [
  'awaiting_approval',
  'applying',
  'enabled',
  'failed',
  'requires_manual_recovery',
] as const;
export type ManagedRoutingStatus = (typeof MANAGED_ROUTING_STATUSES)[number];

export interface ManagedRouting {
  serverId: string;
  enabled: boolean;
  status: ManagedRoutingStatus | 'disabled';
  revisionId: string | null;
  planHash: string | null;
  path: string;
  applyJobId: string | null;
  approval: {
    required: boolean;
    approvedBy: string | null;
    approvedAt: string | null;
    expiresAt: string | null;
  };
  error: { code?: string; message?: string } | null;
  createdBy: string | null;
  allowedActions: Array<'enable' | 'approve'>;
  updatedAt: string | null;
}

// ---------------------------------------------------------------- GitHub integrations / auto-deploy (§7.5)

export const createGithubIntegrationSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    webhookSecret: z.string().min(16).max(256),
  })
  .strict();

export interface Integration {
  id: string;
  kind: 'github';
  name: string;
  webhookUrl: string;
  webhookSecret: { set: true };
  enabled: boolean;
  createdBy: string;
  createdAt: string;
}

export const BRANCH_PATTERN_RE = /^[A-Za-z0-9._\/*-]{1,255}$/;
/**
 * `registry-host[:port]/repo[/…]:<tag template>`; placeholders `{sha}` (40 hex), `{sha7}`, `{branch}`
 * (`/` → `-`). The registry host must be explicit so digest resolution never guesses a registry.
 */
export const IMAGE_TEMPLATE_RE =
  /^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+:(?:[A-Za-z0-9_.-]|\{sha\}|\{sha7\}|\{branch\}){1,128}$/;

export const autoDeployPolicySchema = z
  .object({
    integrationId: z.string().uuid(),
    repo: z.string().regex(/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/),
    branches: z
      .array(z.string().regex(BRANCH_PATTERN_RE))
      .min(1)
      .max(20)
      .refine(uniqueStrings, 'branches must be unique'),
    imageTemplate: z
      .string()
      .max(300)
      .regex(IMAGE_TEMPLATE_RE, 'imageTemplate must be registry-host/repo:tag-template')
      .refine((s) => /\{sha7?\}/.test(s), 'imageTemplate must contain {sha} or {sha7}'),
    enabled: z.boolean().default(true),
  })
  .strict();
export type AutoDeployPolicyInput = z.infer<typeof autoDeployPolicySchema>;
export const updateAutoDeployPolicySchema = autoDeployPolicySchema
  .omit({ integrationId: true })
  .partial()
  .strict();

export interface AutoDeployPolicy {
  id: string;
  applicationId: string;
  integrationId: string;
  repo: string;
  branches: string[];
  imageTemplate: string;
  enabled: boolean;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export const WEBHOOK_DELIVERY_RESULTS = [
  'deployed',
  'awaiting_approval',
  'ignored',
  'failed',
] as const;
export type WebhookDeliveryResult = (typeof WEBHOOK_DELIVERY_RESULTS)[number];

export interface WebhookDelivery {
  id: string;
  integrationId: string;
  deliveryId: string;
  event: string;
  repo: string | null;
  ref: string | null;
  after: string | null;
  signatureOk: boolean;
  result: WebhookDeliveryResult;
  /** e.g. `not_push`, `no_matching_policy`, `already_deployed`, `deployment_in_progress`, `IMAGE_RESOLVE_FAILED` */
  reasons: string[];
  deploymentIds: string[];
  receivedAt: string;
}

/** Exact match, or `*` glob (matches any run of characters, including `/`). */
export function branchMatches(pattern: string, branch: string): boolean {
  if (!pattern.includes('*')) return pattern === branch;
  const re = new RegExp(
    '^' +
      pattern
        .split('*')
        .map((p) => p.replace(/[.+?^${}()|[\]\\/-]/g, '\\$&'))
        .join('.*') +
      '$',
  );
  return re.test(branch);
}

/** Expand an image template for a commit. Branch `/` become `-` (tags cannot contain `/`). */
export function renderImageTemplate(template: string, sha: string, branch: string): string {
  return template
    .replace(/\{sha\}/g, sha)
    .replace(/\{sha7\}/g, sha.slice(0, 7))
    .replace(/\{branch\}/g, branch.replace(/[^A-Za-z0-9_.-]/g, '-'));
}

// ---------------------------------------------------------------- compose / detect requests (§7.6)

export const COMPOSE_MAX_BYTES = 262_144;
export const composeValidateSchema = z
  .object({
    yaml: z.string().max(COMPOSE_MAX_BYTES),
    environment: z.enum(ENVIRONMENTS).optional(),
  })
  .strict();

export const DETECT_MAX_FILE_BYTES = 65_536;
export const detectSchema = z
  .object({
    files: z
      .record(z.string().regex(/^[A-Za-z0-9._\/-]{1,200}$/), z.string().max(DETECT_MAX_FILE_BYTES))
      .refine((r) => Object.keys(r).length <= 50, 'at most 50 files'),
  })
  .strict();
