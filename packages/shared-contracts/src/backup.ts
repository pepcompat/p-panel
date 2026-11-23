/**
 * P6 backups and restores — Center read models, request schemas and agent result schemas
 * (docs/API_CONTRACTS.md §10, docs/AGENT_PROTOCOL.md "Backups and restores (P6)", ADR-0009).
 */
import { z } from 'zod';
import {
  ENV_KEY_RE,
  hostPathSchema,
  imageDigestRefSchema,
  RESTIC_SNAPSHOT_RE,
  restoreTargetSchema,
  sha256HexSchema,
} from './jobs';

// ---------------------------------------------------------------- vocabularies

export const BACKUP_RUN_STATUSES = [
  'queued',
  'running',
  'uploaded',
  'failed',
  'expired',
  'cancelled',
] as const;
export type BackupRunStatus = (typeof BACKUP_RUN_STATUSES)[number];
/** Non-terminal run states (at most one per policy — DB partial unique index). */
export const BACKUP_RUN_ACTIVE_STATUSES: readonly BackupRunStatus[] = ['queued', 'running'];

/**
 * Verification level of a run. `repository_checked` = `restic check` + manifest re-hash passed;
 * `restore_verified` ONLY after an actual isolated restore (staging/scratch) compared OK.
 */
export const BACKUP_VERIFICATION_LEVELS = [
  'none',
  'repository_checked',
  'restore_verified',
  'verify_failed',
] as const;
export type BackupVerification = (typeof BACKUP_VERIFICATION_LEVELS)[number];
export const BACKUP_RUN_TRIGGERS = ['schedule', 'manual', 'safety'] as const;
export type BackupRunTrigger = (typeof BACKUP_RUN_TRIGGERS)[number];
export const BACKUP_VERIFY_LEVELS = ['check', 'restore_test'] as const;
export type BackupVerifyLevel = (typeof BACKUP_VERIFY_LEVELS)[number];

export const RESTORE_STATUSES = [
  'planned',
  'impact_reviewed',
  'awaiting_approval',
  'approved',
  'running',
  'verified',
  'failed',
  'requires_manual_recovery',
  'cancelled',
] as const;
export type RestoreStatus = (typeof RESTORE_STATUSES)[number];
/** Restores can be cancelled only before execution starts. */
export const RESTORE_CANCELLABLE: readonly RestoreStatus[] = [
  'planned',
  'impact_reviewed',
  'awaiting_approval',
  'approved',
];
/** in_place execution order: safety_backup → stop_app → restore → start_app (incl. healthcheck). */
export const RESTORE_STEP_NAMES = [
  'dry_run',
  'safety_backup',
  'stop_app',
  'restore',
  'start_app',
] as const;
export type RestoreStepName = (typeof RESTORE_STEP_NAMES)[number];
export const RESTORE_STEP_STATUSES = ['running', 'succeeded', 'failed', 'skipped'] as const;

export const MAINTENANCE_KINDS = ['prune', 'copy', 'check', 'unlock'] as const;
export type MaintenanceKind = (typeof MAINTENANCE_KINDS)[number];

/** Host paths a policy may never back up (or contain): kernel pseudo-fs + the agent's own state. */
export const BACKUP_FORBIDDEN_PATHS = [
  '/proc',
  '/sys',
  '/dev',
  '/run',
  '/var/lib/ppanel-agent',
  '/etc/ppanel-agent',
] as const;

/** Center-side error codes added in P6 (agent result codes: BACKUP_ERROR_CODES in jobs.ts). */
export const BACKUP_CENTER_ERROR_CODES = {
  /** policy run / verify / restore against a repo the operator has not initialised (409) */
  REPO_NOT_INITIALIZED: 'REPO_NOT_INITIALIZED',
  /** the server has no access row in this repository (409) */
  REPO_ACCESS_MISSING: 'REPO_ACCESS_MISSING',
  /** a run of this policy is already queued/running (409) */
  BACKUP_IN_PROGRESS: 'BACKUP_IN_PROGRESS',
  /** target invalid: forbidden path, unknown app/volume/DB service, missing secret key (422) */
  BACKUP_TARGET_INVALID: 'BACKUP_TARGET_INVALID',
  /** cron must be 5 fields / timezone must be IANA (422) */
  SCHEDULE_INVALID: 'SCHEDULE_INVALID',
  /** run is not `uploaded` (verify / restore from it) (409) */
  RUN_NOT_UPLOADED: 'RUN_NOT_UPLOADED',
  /** snapshotId is not one of the run's snapshots (422) */
  SNAPSHOT_NOT_IN_RUN: 'SNAPSHOT_NOT_IN_RUN',
  /** restore target does not match the snapshot's backup target (422) */
  RESTORE_TARGET_MISMATCH: 'RESTORE_TARGET_MISMATCH',
  /** restore transition not allowed from the current status (409) */
  RESTORE_STATE_INVALID: 'RESTORE_STATE_INVALID',
  /** a verification of this run is already running (409) */
  VERIFY_IN_PROGRESS: 'VERIFY_IN_PROGRESS',
} as const;

// ---------------------------------------------------------------- repositories (§10.1)

const restUserSchema = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,62}$/);
/** rest-server base URL without credentials and without the per-server path. */
export const backupBaseUrlSchema = z
  .string()
  .trim()
  .max(300)
  .regex(
    /^https?:\/\/[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?\/?$/,
    'baseUrl must be http(s)://host[:port]/',
  );

export const backupOffsiteSchema = z
  .object({
    kind: z.literal('s3'),
    endpoint: z.string().trim().url().max(300),
    bucket: z.string().regex(/^[a-z0-9][a-z0-9.-]{1,62}$/),
  })
  .strict();

export const createBackupRepositorySchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    kind: z.literal('rest').default('rest'),
    baseUrl: backupBaseUrlSchema,
    offsite: backupOffsiteSchema.nullable().default(null),
  })
  .strict();
export type CreateBackupRepositoryInput = z.infer<typeof createBackupRepositorySchema>;

export const updateBackupRepositorySchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    baseUrl: backupBaseUrlSchema.optional(),
    offsite: backupOffsiteSchema.nullable().optional(),
  })
  .strict();

/** PUT /backup-repositories/:id/servers/:serverId — per-server rest-server user + restic password. */
export const putBackupRepoAccessSchema = z
  .object({
    /** rest-server user = private repo path `/<restUser>/` */
    restUser: restUserSchema,
    restPassword: z.string().min(12).max(256),
    /** omitted → the Center generates 32 random bytes (base64); kept when the row already exists */
    repoPassword: z.string().min(16).max(256).optional(),
  })
  .strict();
export type PutBackupRepoAccessInput = z.infer<typeof putBackupRepoAccessSchema>;

export const markInitializedSchema = z
  .object({ initialized: z.boolean().default(true) })
  .strict()
  .default({});

export interface MaintenanceStatus {
  kind: MaintenanceKind;
  serverUser: string;
  ok: boolean;
  finishedAt: string;
  receivedAt: string;
  detail: Record<string, unknown>;
}

export interface BackupRepoAccessView {
  serverId: string;
  serverName: string;
  restUser: string;
  /** rest-server URL of this server's private repo (no credentials) */
  url: string;
  initialized: boolean;
  initializedAt: string | null;
  restPassword: { set: true };
  repoPassword: { set: true };
  /** latest report per maintenance kind for this server user */
  maintenance: MaintenanceStatus[];
}

export type BackupRepositoryAction =
  'edit' | 'manage_access' | 'mark_initialized' | 'recovery_export';

export interface BackupRepository {
  id: string;
  name: string;
  kind: 'rest';
  baseUrl: string;
  offsite: z.infer<typeof backupOffsiteSchema> | null;
  /** retention (`forget --prune`) and offsite copy run from the maintenance identity, never from the UI */
  maintenanceNote: string;
  servers: BackupRepoAccessView[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  allowedActions: BackupRepositoryAction[];
}

/** GET /backup-repositories/:id/recovery-export — offline escrow (step-up, audited, Cache-Control: no-store). */
export interface BackupRecoveryExport {
  repositoryId: string;
  name: string;
  baseUrl: string;
  exportedAt: string;
  servers: Array<{
    serverId: string;
    serverName: string;
    restUser: string;
    url: string;
    repoPassword: string;
  }>;
  note: string;
}

/** POST /backup-maintenance/reports (Authorization: Bearer PPANEL_BACKUP_REPORT_TOKEN). */
export const maintenanceReportSchema = z
  .object({
    repositoryId: z.string().uuid(),
    serverUser: restUserSchema,
    kind: z.enum(MAINTENANCE_KINDS),
    ok: z.boolean(),
    finishedAt: z.string().datetime({ offset: true }),
    detail: z.record(z.unknown()).default({}),
  })
  .strict();
export type MaintenanceReportInput = z.infer<typeof maintenanceReportSchema>;

// ---------------------------------------------------------------- policies (§10.2)

const svcRe = /^[a-z0-9][a-z0-9-]{0,30}$/;
const dbIdentRe = /^[A-Za-z0-9_-]{1,63}$/;

/** Policy targets as written by the client: app targets reference `applicationId` (resolved to slug). */
export const backupPolicyTargetInputSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('paths'),
      paths: z.array(hostPathSchema).min(1).max(50),
      excludes: z
        .array(z.string().regex(/^[A-Za-z0-9._*?\/\[\]-]{1,200}$/))
        .max(100)
        .default([]),
    })
    .strict(),
  z
    .object({
      type: z.literal('volume'),
      applicationId: z.string().uuid(),
      volume: z.string().regex(/^[a-z0-9][a-z0-9-]{0,40}$/),
    })
    .strict(),
  z
    .object({
      type: z.enum(['postgres', 'mysql']),
      applicationId: z.string().uuid(),
      service: z.string().regex(svcRe),
      database: z.string().regex(dbIdentRe),
      user: z.string().regex(dbIdentRe),
      passwordSecretKey: z.string().regex(ENV_KEY_RE),
      port: z.number().int().min(1).max(65535).optional(),
    })
    .strict(),
]);
export type BackupPolicyTargetInput = z.infer<typeof backupPolicyTargetInputSchema>;

/** Stored/returned target: the `backupTargetSchema` job shape + `applicationId` for app targets. */
export type BackupPolicyTarget =
  | { type: 'paths'; paths: string[]; excludes: string[] }
  | { type: 'volume'; applicationId: string; app: string; volume: string }
  | {
      type: 'postgres' | 'mysql';
      applicationId: string;
      app: string;
      service: string;
      database: string;
      user: string;
      passwordSecretKey: string;
      port?: number;
    };

export const backupScheduleSchema = z
  .object({
    /** 5-field cron (minute hour day-of-month month day-of-week) */
    cron: z.string().trim().min(9).max(120),
    /** IANA timezone, e.g. Asia/Bangkok */
    timezone: z.string().trim().min(1).max(64),
  })
  .strict();

export const backupRetentionSchema = z
  .object({
    keepDaily: z.number().int().min(0).max(3650).default(7),
    keepWeekly: z.number().int().min(0).max(520).default(4),
    keepMonthly: z.number().int().min(0).max(240).default(6),
  })
  .strict();

export const backupVerifyPolicySchema = z
  .object({
    afterBackup: z.enum(['none', 'check', 'restore_test']).default('check'),
    restoreTestEvery: z.enum(['never', 'weekly', 'monthly']).default('never'),
  })
  .strict();

export const createBackupPolicySchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    serverId: z.string().uuid(),
    repositoryId: z.string().uuid(),
    targets: z.array(backupPolicyTargetInputSchema).min(1).max(20),
    schedule: backupScheduleSchema,
    retention: backupRetentionSchema.default({}),
    verify: backupVerifyPolicySchema.default({}),
    enabled: z.boolean().default(true),
    /** helper image (restic + DB tools) for volume / DB targets; must match the agent's backup.helperImage */
    helperImage: imageDigestRefSchema.optional(),
  })
  .strict();
export type CreateBackupPolicyInput = z.infer<typeof createBackupPolicySchema>;

export const updateBackupPolicySchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    repositoryId: z.string().uuid().optional(),
    targets: z.array(backupPolicyTargetInputSchema).min(1).max(20).optional(),
    schedule: backupScheduleSchema.optional(),
    retention: backupRetentionSchema.optional(),
    verify: backupVerifyPolicySchema.optional(),
    enabled: z.boolean().optional(),
    helperImage: imageDigestRefSchema.nullable().optional(),
  })
  .strict();
export type UpdateBackupPolicyInput = z.infer<typeof updateBackupPolicySchema>;

export type BackupPolicyAction = 'edit' | 'delete' | 'run';

export interface BackupPolicy {
  id: string;
  name: string;
  serverId: string;
  repositoryId: string;
  targets: BackupPolicyTarget[];
  schedule: { cron: string; timezone: string };
  retention: z.infer<typeof backupRetentionSchema>;
  /** retention is applied by the maintenance identity (scripts/backup/maintenance.sh), not the agent */
  retentionAppliedBy: 'maintenance';
  verify: z.infer<typeof backupVerifyPolicySchema>;
  helperImage: string | null;
  enabled: boolean;
  /** next scheduled slot (UTC ISO); null when disabled */
  nextRunAt: string | null;
  lastScheduledAt: string | null;
  lastRun: {
    id: string;
    status: BackupRunStatus;
    verification: BackupVerification;
    finishedAt: string | null;
  } | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  version: number;
  allowedActions: BackupPolicyAction[];
}

// ---------------------------------------------------------------- runs (§10.3)

export interface BackupSnapshotRef {
  /** index into the run's targets */
  target: number;
  targetType: BackupPolicyTarget['type'];
  snapshotId: string;
  shortId: string | null;
  sizeBytes: number | null;
  filesNew: number | null;
  filesChanged: number | null;
  durationMs: number | null;
}

export interface BackupManifestSummary {
  /** hashed files (sum of `fileCount` of paths / volume entries) */
  files: number;
  /** bytes of hashed files + DB dump bytes */
  bytes: number;
  databases: number;
  truncated: boolean;
}

/** One row of GET /backup-runs/:id `manifestEntries` (the per-target manifest, flattened + paginated). */
export type BackupManifestRow =
  | { kind: 'file'; target: number; snapshotId: string; path: string; size: number; sha256: string }
  | {
      kind: 'database';
      target: number;
      snapshotId: string;
      database: string;
      bytes: number;
      sha256: string | null;
      tables: Array<{ name: string; rows: number }>;
    };

export type BackupRunAction = 'verify_check' | 'verify_restore_test' | 'restore';

export interface BackupVerificationView {
  id: string;
  level: BackupVerifyLevel;
  status: 'running' | 'passed' | 'failed';
  jobIds: string[];
  result: Record<string, unknown> | null;
  error: { code: string; message: string } | null;
  createdBy: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface BackupRun {
  id: string;
  policyId: string;
  policyName: string;
  serverId: string;
  repositoryId: string;
  trigger: BackupRunTrigger;
  status: BackupRunStatus;
  verification: BackupVerification;
  verifiedAt: string | null;
  targets: BackupPolicyTarget[];
  snapshots: BackupSnapshotRef[];
  manifest: BackupManifestSummary;
  error: { code: string; message: string; details?: unknown } | null;
  scheduledFor: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  jobId: string | null;
  resticVersion: string | null;
  /** set on safety runs taken before an in-place restore */
  restoreId: string | null;
  createdBy: string | null;
  createdAt: string;
  allowedActions: BackupRunAction[];
}

/** GET /backup-runs/:id — run + paginated manifest entries (`manifestPage`, `manifestLimit`). */
export interface BackupRunDetail extends BackupRun {
  manifestEntries: BackupManifestRow[];
  manifestPaginate: { page: number; limit: number; total: number };
  verifications: BackupVerificationView[];
}

export const verifyBackupRunSchema = z.object({ level: z.enum(BACKUP_VERIFY_LEVELS) }).strict();

// ---------------------------------------------------------------- restores (§10.4)

export const createRestoreSchema = z
  .object({
    runId: z.string().uuid(),
    snapshotId: z.string().regex(RESTIC_SNAPSHOT_RE),
    target: restoreTargetSchema,
  })
  .strict();
export type CreateRestoreInput = z.infer<typeof createRestoreSchema>;

export const approveRestoreSchema = z.object({ planHash: sha256HexSchema }).strict();

/**
 * Execute body. `confirmImpact: true` is REQUIRED for `in_place` targets (design D4-B: a destructive
 * restore cannot run without an explicit impact confirmation — enforced server-side, not only in the UI).
 */
export const executeRestoreSchema = z
  .object({ confirmImpact: z.boolean().optional() })
  .strict()
  .default({});
export type ExecuteRestoreInput = z.infer<typeof executeRestoreSchema>;

export interface RestoreImpactItem {
  /** overwrite = data replaced in place; create = new isolated location; downtime = app stopped */
  effect: 'overwrite' | 'create' | 'downtime' | 'note';
  kind: 'path' | 'volume' | 'database' | 'application' | 'config';
  ref: string;
  detail: string;
}

export interface RestoreStep {
  name: RestoreStepName;
  status: (typeof RESTORE_STEP_STATUSES)[number];
  jobId: string | null;
  backupRunId: string | null;
  deploymentId: string | null;
  startedAt: string;
  finishedAt: string | null;
  message: string | null;
  errorCode: string | null;
}

export type RestoreAction = 'dry_run' | 'approve' | 'execute' | 'cancel';

export interface Restore {
  id: string;
  runId: string;
  snapshotId: string;
  serverId: string;
  applicationId: string | null;
  target: z.infer<typeof restoreTargetSchema>;
  status: RestoreStatus;
  plan: {
    impact: RestoreImpactItem[];
    dryRun: { jobId: string | null; ok: boolean | null; listing: unknown; error: unknown } | null;
  };
  planHash: string;
  approval: {
    required: boolean;
    reasons: Array<'in_place' | 'production'>;
    approvedBy: string | null;
    approvedAt: string | null;
    expiresAt: string | null;
    usedAt: string | null;
  };
  steps: RestoreStep[];
  safetySnapshotRunId: string | null;
  /** snapshot ids of the safety run (shown for manual rollback) */
  safetySnapshotIds: string[];
  result: Record<string, unknown> | null;
  error: { code: string; message: string } | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
  version: number;
  allowedActions: RestoreAction[];
}

// ---------------------------------------------------------------- agent results (parsed leniently)

const nonNegInt = z.number().int().min(0);
export const backupRunResultSchema = z
  .object({
    snapshots: z
      .array(
        z
          .object({
            /** index into params.targets (preferred) — or the target object echoed back */
            target: z.union([z.number().int().min(0), z.record(z.unknown())]).optional(),
            snapshotId: z.string().regex(RESTIC_SNAPSHOT_RE),
            shortId: z.string().max(16).optional(),
            sizeBytes: nonNegInt.optional(),
            filesNew: nonNegInt.optional(),
            filesChanged: nonNegInt.optional(),
            durationMs: nonNegInt.optional(),
          })
          .passthrough(),
      )
      .max(20),
    manifest: z.array(z.unknown()).default([]),
    truncated: z.boolean().optional(),
    resticVersion: z.string().max(64).optional(),
  })
  .passthrough();

export const backupVerifyResultSchema = z
  .object({
    repoCheckOk: z.boolean(),
    filesCompared: nonNegInt.default(0),
    mismatches: z.array(z.unknown()).default([]),
    level: z.enum(['repository_checked', 'restore_verified']).optional(),
  })
  .passthrough();

export const restoreRunResultSchema = z
  .object({
    restored: z.array(z.unknown()).default([]),
    verify: z
      .object({
        ok: z.boolean(),
        compared: nonNegInt.default(0),
        mismatches: z.array(z.unknown()).default([]),
      })
      .passthrough()
      .optional(),
    stagingPath: z.string().max(4096).optional(),
    volume: z.string().max(200).optional(),
    scratch: z.object({ removed: z.boolean() }).passthrough().optional(),
  })
  .passthrough();

/** Live `backup.snapshots` result (GET /servers/:id/snapshots). */
export interface ServerSnapshots {
  repositoryId: string;
  jobId: string;
  pending: boolean;
  snapshots: Array<{
    id: string;
    shortId: string | null;
    time: string | null;
    tags: string[];
    paths: string[];
    hostname: string | null;
    sizeBytes: number | null;
  }>;
}
