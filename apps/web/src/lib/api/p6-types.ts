/**
 * P6 read models — the shared contracts (`@ppanel/shared-contracts` backup.ts, docs/API_CONTRACTS.md
 * §10 + §10.6) plus a few optional "web-requested" display fields the UI tolerates being absent.
 */
import type { z } from 'zod';
import type {
  BackupPolicy as SharedBackupPolicy,
  BackupPolicyTargetInput,
  BackupRecoveryExport,
  BackupRepository as SharedBackupRepository,
  BackupRun as SharedBackupRun,
  BackupRunDetail as SharedBackupRunDetail,
  BackupSnapshotRef,
  BackupVerification,
  BackupRunStatus,
  Environment,
  Restore as SharedRestore,
  RestoreStatus,
  RestoreStepName,
  ServerSnapshots,
  restoreTargetSchema,
} from '@ppanel/shared-contracts';

export {
  BACKUP_RUN_STATUSES as RUN_STATUSES,
  BACKUP_RUN_ACTIVE_STATUSES as RUN_ACTIVE,
  BACKUP_VERIFICATION_LEVELS as VERIFICATION_LEVELS,
  MAINTENANCE_KINDS,
  RESTORE_STATUSES,
  RESTORE_STEP_NAMES,
  RESTORE_CANCELLABLE,
} from '@ppanel/shared-contracts';
export type {
  BackupManifestRow,
  BackupPolicyTarget,
  BackupVerificationView,
  MaintenanceKind,
  MaintenanceStatus,
  RestoreImpactItem,
  RestoreStep,
  RestoreStepName,
} from '@ppanel/shared-contracts';

export type RunStatus = BackupRunStatus;
export type VerificationLevel = BackupVerification;
export type { RestoreStatus };
export const RESTORE_TERMINAL: readonly RestoreStatus[] = [
  'verified',
  'failed',
  'requires_manual_recovery',
  'cancelled',
];

/** Policy target as the client writes it (app targets by applicationId). */
export type BackupTargetInput = BackupPolicyTargetInput;
export type DbTarget = Extract<BackupPolicyTargetInput, { applicationId: string; service: string }>;
export type RunSnapshot = BackupSnapshotRef;
export type RecoveryExport = BackupRecoveryExport;
export type RestoreTargetInput = z.input<typeof restoreTargetSchema>;
export type RestoreMode = 'staging' | 'scratch' | 'in_place';

export const VERIFY_AFTER = ['none', 'check', 'restore_test'] as const;
export const RESTORE_TEST_EVERY = ['never', 'weekly', 'monthly'] as const;

interface Display {
  /** web-requested */
  serverName?: string;
  environment?: Environment;
}

export type BackupRepository = SharedBackupRepository & {
  /** web-requested: last recovery export (the values are never stored client-side) */
  lastRecoveryExportAt?: string | null;
};

export interface BackupPolicyInput {
  name: string;
  serverId: string;
  repositoryId: string;
  targets: BackupTargetInput[];
  schedule: { cron: string; timezone: string };
  retention: { keepDaily: number; keepWeekly: number; keepMonthly: number };
  verify: {
    afterBackup: (typeof VERIFY_AFTER)[number];
    restoreTestEvery: (typeof RESTORE_TEST_EVERY)[number];
  };
  enabled: boolean;
}

export type BackupPolicy = SharedBackupPolicy & Display & { repositoryName?: string };

export type BackupRun = SharedBackupRun &
  Display & {
    /** web-requested: a verification in flight (else derived from detail.verifications) */
    verifying?: { level: 'check' | 'restore_test'; startedAt: string } | null;
  };

export type BackupRunDetail = SharedBackupRunDetail &
  Display & {
    verifying?: BackupRun['verifying'];
    /** web-requested: job log lines (else only the job id is shown) */
    logs?: string[];
  };

export type SnapshotList = ServerSnapshots & { pending?: boolean };
export type LiveSnapshot = ServerSnapshots['snapshots'][number] & { runId?: string | null };

export type Restore = SharedRestore &
  Display & {
    /** web-requested */
    createdByLabel?: string | null;
    approvedByLabel?: string | null;
  };

export interface CreateRestoreInput {
  runId: string;
  snapshotId: string;
  target: RestoreTargetInput;
}

/** Display order of steps per restore kind (the API lists steps as they start). */
export function expectedSteps(t: RestoreTargetInput): RestoreStepName[] {
  if (t.mode !== 'in_place') return ['dry_run', 'restore'];
  if (t.type === 'paths') return ['dry_run', 'safety_backup', 'restore'];
  return ['dry_run', 'safety_backup', 'stop_app', 'restore', 'start_app'];
}
