// P3 — discovery scans, findings, applications (ownership tiers), Nginx config revisions.
// Source of truth: docs/API_CONTRACTS.md §6.
import { z } from 'zod';
import type { ApplicationBuildSummary, ComposeAppConfig } from './build';
import type { ContainerAppConfig } from './deploy';
import {
  DISCOVERY_SOURCES,
  nginxPathSchema,
  nginxPostcheckSchema,
  NGINX_MAX_FILE_BYTES,
} from './jobs';

export type DiscoverySource = (typeof DISCOVERY_SOURCES)[number];

// ---------------------------------------------------------------- scans

export const DISCOVERY_SCAN_STATUSES = ['running', 'completed', 'failed', 'expired'] as const;
export type DiscoveryScanStatus = (typeof DISCOVERY_SCAN_STATUSES)[number];

export const createDiscoveryScanSchema = z
  .object({
    sources: z
      .array(z.enum(DISCOVERY_SOURCES))
      .min(1)
      .max(DISCOVERY_SOURCES.length)
      .refine((a) => new Set(a).size === a.length, { message: 'sources must be unique' })
      .optional(),
  })
  .strict();
export type CreateDiscoveryScanInput = z.infer<typeof createDiscoveryScanSchema>;

export interface DiscoveryScanSummary {
  nginxServers: number;
  upstreams: number;
  duplicates: number;
  manualReview: number;
  phpFpmPools: number;
  listeners: number;
  containers: number;
  systemdUnits: number;
  /** per requested source: ok | unavailable | error | missing */
  sourceStatus: Record<string, string>;
}

export interface DiscoveryDriftEntry {
  path: string;
  previousSha256: string | null;
  currentSha256: string;
  changedBy: 'external' | 'ppanel_revision';
  revisionId: string | null;
}

export interface DiscoveryScan {
  id: string;
  serverId: string;
  jobId: string;
  status: DiscoveryScanStatus;
  sources: DiscoverySource[];
  requestedBy: string | null;
  startedAt: string;
  completedAt: string | null;
  summary: DiscoveryScanSummary | null;
  configFiles: Array<{ path: string; sha256: string }>;
  drift: DiscoveryDriftEntry[];
  error: { code?: string; message?: string } | null;
}

export interface DiscoveryScanCreated {
  scanId: string;
  jobId: string;
}

// ---------------------------------------------------------------- findings

export const FINDING_KINDS = [
  'nginx_server',
  'php_fpm_pool',
  'listener',
  'container',
  'systemd_unit',
  'upstream',
] as const;
export type FindingKind = (typeof FINDING_KINDS)[number];
export type FindingConfidence = 'high' | 'medium' | 'low';

export interface DiscoveryFinding {
  id: string;
  scanId: string;
  serverId: string;
  kind: FindingKind;
  /** sha256 of stable identity (kind + file + sorted serverNames + sorted listen). Stable across scans. */
  fingerprint: string;
  /** Agent-side id (e.g. `srv_…`) — only stable within one scan. */
  externalId: string | null;
  title: string;
  domains: string[];
  listen: string[];
  provenance: {
    file: string | null;
    line: number | null;
    /** first include site (`file:line`), null when top-level */
    includedFrom: string | null;
    includeChain: string[];
  } | null;
  confidence: FindingConfidence;
  manualReviewRequired: boolean;
  reasons: string[];
  unsupportedDirectives: string[];
  conflicts: Array<{ type: 'duplicate_server_name'; with: string[]; name?: string; port?: number }>;
  links: {
    upstream: string | null;
    fastcgiPass: string | null;
    root: string | null;
    proxyPass: string | null;
    processes: unknown[];
  };
  applicationId: string | null;
  data: Record<string, unknown>;
}

// ---------------------------------------------------------------- applications & ownership

export const OWNERSHIP_MODES = ['discovered', 'observed', 'adopted', 'managed'] as const;
export type OwnershipMode = (typeof OWNERSHIP_MODES)[number];
export const APPLICATION_KINDS = [
  'nginx_static',
  'nginx_php',
  'nginx_proxy',
  'unknown',
  /** P4a: managed container application (source of truth = pPanel). */
  'container',
  /** P4b: managed Compose application (normalised plan executed by compose.apply). */
  'compose',
] as const;
export type ApplicationKind = (typeof APPLICATION_KINDS)[number];

/** Per-application action names returned in `allowedActions` (UI derives button state from these). */
export const APPLICATION_ACTIONS = [
  'discover', // downgrade to discovered
  'observe',
  'adopt',
  'manage',
  'read_files',
  'create_revision',
  'acknowledge_drift',
  // P4a container applications
  'deploy',
  'redeploy',
  'rollback',
  'restart',
  'start',
  'stop',
  'manage_secrets',
  'view_logs',
  'edit_container',
  'manage_auto_deploy',
  // P4b builds / compose
  'build',
  'inspect_source',
  'manage_build_config',
  'edit_compose',
] as const;
export type ApplicationAction = (typeof APPLICATION_ACTIONS)[number];

export interface Application {
  id: string;
  serverId: string;
  name: string;
  environment: 'production' | 'uat' | 'development';
  kind: ApplicationKind;
  domains: string[];
  ownershipMode: OwnershipMode;
  flags: { unsupported: boolean; conflict: boolean; manualReview: boolean; driftDetected: boolean };
  /** Why manual review / conflict / unsupported was flagged (copied from the source finding). */
  reasons: string[];
  unsupportedDirectives: string[];
  sourceFindingFingerprint: string;
  /**
   * `path` = path as nginx includes it (display / drift key). When the agent reported it is a symlink
   * (typical sites-enabled → sites-available), `resolvedPath` is the real file: revisions must target it.
   */
  nginxFiles: Array<{ path: string; lastKnownSha256: string | null; resolvedPath?: string }>;
  /** Files whose on-host checksum differs from lastKnownSha256 (non-empty iff flags.driftDetected). */
  driftFiles: Array<{
    path: string;
    lastKnownSha256: string | null;
    /** 'unknown' when the agent could not tell (file missing / manual recovery) → rescan before acknowledge */
    currentSha256: string;
    detectedAt?: string;
  }>;
  lastScanId: string | null;
  /** Present iff kind === 'container' (§7.1). */
  container?: ContainerAppConfig;
  /** P4b: present iff kind === 'compose' (§8.3). */
  compose?: ComposeAppConfig;
  /** P4b: container apps with a build config (§8.1); null when none is configured. */
  build?: ApplicationBuildSummary | null;
  allowedActions: ApplicationAction[];
  version: number;
  createdAt: string;
  updatedAt: string;
}

export const importFindingsSchema = z
  .object({
    findingIds: z.array(z.string().uuid()).min(1).max(200),
    /** adopted/managed are rejected with 422 IMPORT_MODE_NOT_ALLOWED (import never grants write tiers). */
    mode: z.string().default('observed'),
  })
  .strict();
export type ImportFindingsInput = z.infer<typeof importFindingsSchema>;

export const changeOwnershipSchema = z
  .object({
    toMode: z.enum(OWNERSHIP_MODES),
    reason: z.string().trim().min(3).max(500),
    acknowledgeReasons: z.boolean().optional(),
  })
  .strict();
export type ChangeOwnershipInput = z.infer<typeof changeOwnershipSchema>;

export interface AdoptionReview {
  id: string;
  applicationId: string;
  fromMode: OwnershipMode;
  toMode: OwnershipMode;
  actorId: string;
  reason: string;
  acknowledgedReasons: string[];
  stepUp: boolean;
  createdAt: string;
}

// ---------------------------------------------------------------- nginx revisions

export const NGINX_REVISION_STATUSES = [
  'draft',
  'validating',
  'valid',
  'invalid',
  'awaiting_approval',
  'approved',
  'applying',
  'applied',
  'apply_failed',
  'reverting',
  'reverted',
  'drift_blocked',
  'superseded',
  'cancelled',
  /** agent reported REVERT_FAILED_MANUAL_RECOVERY: host state unknown, operator must restore from backup. */
  'requires_manual_recovery',
] as const;
export type NginxRevisionStatus = (typeof NGINX_REVISION_STATUSES)[number];
/** At most one revision per application may be in one of these states. */
export const NGINX_REVISION_OPEN_STATUSES = [
  'draft',
  'validating',
  'valid',
  'awaiting_approval',
  'approved',
  'applying',
  'reverting',
] as const satisfies readonly NginxRevisionStatus[];

export const APPROVAL_TTL_MINUTES = 60;

export const createNginxRevisionSchema = z
  .object({
    files: z
      .array(
        z
          .object({
            path: nginxPathSchema,
            content: z
              .string()
              .max(NGINX_MAX_FILE_BYTES)
              .refine((c) => !c.includes('\u0000'), { message: 'content must not contain NUL' }),
          })
          .strict(),
      )
      .min(1)
      .max(20)
      .refine((a) => new Set(a.map((f) => f.path)).size === a.length, {
        message: 'paths must be unique',
      }),
    postchecks: z.array(nginxPostcheckSchema).max(10).optional(),
  })
  .strict();
export type CreateNginxRevisionInput = z.infer<typeof createNginxRevisionSchema>;

export const approveNginxRevisionSchema = z
  .object({ planHash: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();

export interface NginxRevisionFile {
  path: string;
  beforeSha256: string | null;
  afterSha256: string;
  diff: string;
}

export interface NginxRevision {
  id: string;
  serverId: string;
  applicationId: string;
  status: NginxRevisionStatus;
  files: NginxRevisionFile[];
  planHash: string;
  postchecks: Array<z.infer<typeof nginxPostcheckSchema>>;
  validation: {
    jobId: string;
    valid: boolean | null;
    nginxTestOutput: string | null;
    error: { code?: string; message?: string } | null;
  } | null;
  approval: {
    required: boolean;
    approvedBy: string | null;
    approvedAt: string | null;
    expiresAt: string | null;
  };
  validateJobId: string | null;
  applyJobId: string | null;
  revertJobId: string | null;
  /** Last agent output/error for apply/revert (`errorCode` = agent error code e.g. NGINX_TEST_FAILED). */
  result: { errorCode?: string; [k: string]: unknown } | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface NginxFilesRead {
  jobId: string;
  status: 'succeeded' | 'pending';
  files: Array<{
    path: string;
    sha256: string | null;
    content: string | null;
    exists: boolean;
    /** true when `path` is a symlink (e.g. sites-enabled); revisions must target `resolvedPath`. */
    isSymlink: boolean;
    /** Real file path to edit (equals `path` when not a symlink). */
    resolvedPath: string;
    truncated: boolean;
  }>;
}
