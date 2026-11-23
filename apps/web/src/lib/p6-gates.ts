/**
 * P6 pure UI rules: honest verification wording, restore approval/impact gating, policy validation.
 * The Center enforces all of this (P6-T03/T04); these functions only decide what the UI shows.
 */
import type { Environment } from '@ppanel/shared-contracts';
import type { MessageKey } from '@/i18n/en';
import type { Tone } from '@/components/ui/badge';
import { evaluateGate, type GateResult } from './permissions';
import { isValidTimeZone, parseCron } from './cron';
import type {
  BackupPolicyInput,
  BackupPolicyTarget,
  BackupRun,
  BackupRunDetail,
  BackupTargetInput,
  Restore,
  RestoreMode,
  RestoreStatus,
} from './api/p6-types';

// ---------------------------------------------------------------- verification badge (D4-C)

export interface VerificationBadgeSpec {
  tone: Tone;
  key: MessageKey;
  vars?: Record<string, string>;
  /** The run produced a usable snapshot (uploaded). */
  success: boolean;
  /** data-testid value for tests */
  level: string;
}

/**
 * Maps a run to its one honest badge:
 *  - failed / partial / expired / cancelled → never success, whatever `verification` says
 *  - uploaded + none → "Snapshot uploaded — not verified"
 *  - uploaded + repository_checked → "Repository checked" (structure ok, data not restored)
 *  - uploaded + restore_verified → "Restore verified on <date>" (an actual isolated restore compared)
 *  - uploaded + verify_failed → "Verification failed"
 */
export function verificationBadge(
  run: Pick<BackupRun, 'status' | 'verification' | 'verifiedAt' | 'error'>,
  formatDate: (iso: string) => string = (s) => s,
): VerificationBadgeSpec {
  switch (run.status) {
    case 'queued':
    case 'running':
      return { tone: 'info', key: 'bk.ver.inProgress', success: false, level: 'in_progress' };
    case 'failed':
      return {
        tone: 'crit',
        key: run.error?.code === 'BACKUP_PARTIAL' ? 'bk.ver.partial' : 'bk.ver.backupFailed',
        success: false,
        level: run.error?.code === 'BACKUP_PARTIAL' ? 'partial' : 'failed',
      };
    case 'expired':
      return { tone: 'off', key: 'bk.ver.expired', success: false, level: 'expired' };
    case 'cancelled':
      return { tone: 'off', key: 'bk.ver.cancelled', success: false, level: 'cancelled' };
    case 'uploaded':
      break;
  }
  switch (run.verification) {
    case 'restore_verified':
      return run.verifiedAt
        ? {
            tone: 'ok',
            key: 'bk.ver.restoreVerifiedOn',
            vars: { date: formatDate(run.verifiedAt) },
            success: true,
            level: 'restore_verified',
          }
        : { tone: 'ok', key: 'bk.ver.restoreVerified', success: true, level: 'restore_verified' };
    case 'repository_checked':
      return {
        tone: 'info',
        key: 'bk.ver.repoChecked',
        success: true,
        level: 'repository_checked',
      };
    case 'verify_failed':
      return { tone: 'crit', key: 'bk.ver.verifyFailed', success: true, level: 'verify_failed' };
    case 'none':
    default:
      return { tone: 'stale', key: 'bk.ver.notVerified', success: true, level: 'none' };
  }
}

/** Only an uploaded run has snapshots that can be verified or restored. */
export const runIsRestorable = (r: Pick<BackupRun, 'status' | 'snapshots'>) =>
  r.status === 'uploaded' && r.snapshots.length > 0;

// ---------------------------------------------------------------- gates

const block = (key: MessageKey, vars?: Record<string, string>): GateResult => ({
  allowed: false,
  reason: { key, vars },
});

export type RunAction = 'verify_check' | 'verify_restore_test' | 'restore';
export function runGate(
  action: RunAction,
  run: Pick<BackupRun, 'status' | 'snapshots' | 'verifying' | 'allowedActions'>,
  permissions: readonly string[] | undefined,
): GateResult {
  const p = evaluateGate({
    permissions,
    perm: action === 'restore' ? 'backups.restore' : 'backups.create',
  });
  if (!p.allowed) return p;
  if (!runIsRestorable(run)) return block('bk.reason.notUploaded');
  if (action !== 'restore' && run.verifying) return block('bk.reason.verifying');
  if (run.allowedActions && !run.allowedActions.includes(action))
    return block('perm.actionNotAllowed', { action });
  return { allowed: true };
}

// ---------------------------------------------------------------- restore rules (P6-T03, D4-B)

/** in_place anywhere, or any production target → approval by another user with 2FA. */
export function restoreNeedsApproval(mode: RestoreMode, env: Environment | undefined): boolean {
  return mode === 'in_place' || env === 'production';
}

/** Destructive restore: the explicit impact checkbox is required before it can continue. */
export function impactGate(mode: RestoreMode, confirmed: boolean): GateResult {
  if (mode === 'in_place' && !confirmed) return block('rs.reason.confirmImpact');
  return { allowed: true };
}

export const defaultModeFor = (t: BackupTargetInput['type']): RestoreMode =>
  t === 'postgres' || t === 'mysql' ? 'scratch' : 'staging';

export type WizardStep =
  'snapshot' | 'target' | 'impact' | 'dryrun' | 'approval' | 'execute' | 'result';
export const WIZARD_STEPS: WizardStep[] = [
  'snapshot',
  'target',
  'impact',
  'dryrun',
  'approval',
  'execute',
  'result',
];

/** Which step an existing restore record belongs on. */
export function stepForStatus(s: RestoreStatus): WizardStep {
  switch (s) {
    case 'planned':
      return 'impact';
    case 'impact_reviewed':
      return 'dryrun';
    case 'awaiting_approval':
    case 'approved':
      return 'approval';
    case 'running':
      return 'execute';
    default:
      return 'result';
  }
}

export function restoreGate(
  action: 'approve' | 'execute' | 'cancel',
  r: Pick<Restore, 'status' | 'createdBy' | 'approval' | 'allowedActions'>,
  permissions: readonly string[] | undefined,
  userId: string | undefined,
  impactConfirmed = true,
  mode: RestoreMode = 'staging',
): GateResult {
  let g: GateResult;
  if (action === 'approve') {
    const p = evaluateGate({ permissions, perm: 'approvals.decide' });
    if (!p.allowed) return p;
    if (!r.approval.required) return block('rs.reason.noApproval');
    if (r.createdBy === userId) return block('rs.reason.selfApproval');
    g = r.status === 'awaiting_approval' ? { allowed: true } : block('rs.reason.state');
  } else if (action === 'execute') {
    const p = evaluateGate({ permissions, perm: 'backups.restore' });
    if (!p.allowed) return p;
    const im = impactGate(mode, impactConfirmed);
    if (!im.allowed) return im;
    if (r.approval.required && r.status !== 'approved') g = block('rs.reason.needsApproval');
    else if (!r.approval.required && r.status !== 'impact_reviewed' && r.status !== 'approved')
      g = block('rs.reason.needsDryRun');
    else if (r.approval.expiresAt && Date.parse(r.approval.expiresAt) < Date.now())
      g = block('rs.reason.approvalExpired');
    else g = { allowed: true };
  } else {
    const p = evaluateGate({ permissions, perm: 'backups.restore' });
    if (!p.allowed) return p;
    g = ['planned', 'impact_reviewed', 'awaiting_approval', 'approved'].includes(r.status)
      ? { allowed: true }
      : block('rs.reason.state');
  }
  if (g.allowed && r.allowedActions && !r.allowedActions.includes(action))
    return { allowed: false, reason: { key: 'perm.actionNotAllowed', vars: { action } } };
  return g;
}

// ---------------------------------------------------------------- policy validation

const HOST_PATH_RE = /^\/[A-Za-z0-9._@+/-]{0,400}$/;
const EXCLUDE_RE = /^[A-Za-z0-9._*?/[\]-]{1,200}$/;
const FORBIDDEN_ROOTS = ['/proc', '/sys', '/dev', '/var/lib/ppanel-agent'];

/** Same rule as the shared hostPathSchema + the Center's forbidden roots. */
export function hostPathError(p: string): MessageKey | null {
  if (!HOST_PATH_RE.test(p)) return 'bk.err.pathFormat';
  if (p.split('/').includes('..') || p.includes('//') || (p.length > 1 && p.endsWith('/')))
    return 'bk.err.pathCanonical';
  if (p === '/') return 'bk.err.pathRoot';
  if (FORBIDDEN_ROOTS.some((r) => p === r || p.startsWith(`${r}/`))) return 'bk.err.pathForbidden';
  return null;
}

export interface PolicyErrors {
  [field: string]: MessageKey;
}
export function validatePolicy(p: BackupPolicyInput): PolicyErrors {
  const e: PolicyErrors = {};
  if (!p.name.trim()) e.name = 'bk.err.required';
  else if (p.name.trim().length > 80) e.name = 'bk.err.tooLong';
  if (!p.serverId) e.serverId = 'bk.err.required';
  if (!p.repositoryId) e.repositoryId = 'bk.err.required';
  if (p.targets.length === 0) e.targets = 'bk.err.noTargets';
  p.targets.forEach((t, i) => {
    if (t.type === 'paths') {
      if (t.paths.length === 0) e[`targets.${i}.paths`] = 'bk.err.required';
      t.paths.forEach((x, j) => {
        const err = hostPathError(x);
        if (err) e[`targets.${i}.paths.${j}`] = err;
      });
      t.excludes.forEach((x, j) => {
        if (!EXCLUDE_RE.test(x)) e[`targets.${i}.excludes.${j}`] = 'bk.err.excludeFormat';
      });
    } else if (t.type === 'volume') {
      if (!t.applicationId) e[`targets.${i}.app`] = 'bk.err.required';
      if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(t.volume)) e[`targets.${i}.volume`] = 'bk.err.required';
    } else {
      if (!t.applicationId) e[`targets.${i}.app`] = 'bk.err.required';
      if (!t.service) e[`targets.${i}.service`] = 'bk.err.dbService';
      if (!/^[A-Za-z0-9_-]{1,63}$/.test(t.database)) e[`targets.${i}.database`] = 'bk.err.ident';
      if (!/^[A-Za-z0-9_-]{1,63}$/.test(t.user)) e[`targets.${i}.user`] = 'bk.err.ident';
      if (!t.passwordSecretKey) e[`targets.${i}.passwordSecretKey`] = 'bk.err.secretKey';
    }
  });
  if (!parseCron(p.schedule.cron).ok) e.cron = 'bk.err.cron';
  if (!isValidTimeZone(p.schedule.timezone)) e.timezone = 'bk.err.timezone';
  for (const k of ['keepDaily', 'keepWeekly', 'keepMonthly'] as const) {
    const v = p.retention[k];
    if (!Number.isInteger(v) || v < 0 || v > 1000) e[`retention.${k}`] = 'bk.err.retention';
  }
  if (p.retention.keepDaily + p.retention.keepWeekly + p.retention.keepMonthly === 0)
    e['retention.keepDaily'] = 'bk.err.retentionZero';
  return e;
}

export function targetLabel(t: BackupTargetInput | BackupPolicyTarget, appName?: string): string {
  if (t.type === 'paths') return t.paths.join(', ');
  const app = appName ?? ('app' in t ? t.app : t.applicationId.slice(0, 8));
  if (t.type === 'volume') return `${app}/${t.volume}`;
  return `${app}/${t.service}/${t.database}`;
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(v >= 10 ? 0 : 1)} ${u[i]}`;
}

// ---------------------------------------------------------------- tolerant parsing of `unknown` result blobs

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};

export interface DryListing {
  files: number | null;
  bytes: number | null;
  entries: Array<{ path: string; action: 'overwrite' | 'create' | 'skip' }>;
  tables: Array<{ name: string; rows: number }>;
  warnings: string[];
}
/** `plan.dryRun.listing` is agent-defined (`unknown` in the contract): accept an array of entries or an object. */
export function parseDryListing(listing: unknown, inPlace: boolean): DryListing {
  const o = obj(listing);
  const raw = Array.isArray(listing) ? listing : arr(o.entries ?? o.restored ?? o.files);
  const entries = raw
    .map((e) => {
      if (typeof e === 'string')
        return { path: e, action: inPlace ? 'overwrite' : 'create' } as const;
      const x = obj(e);
      const path = String(x.path ?? x.ref ?? x.name ?? '');
      const a = String(x.action ?? x.effect ?? (inPlace ? 'overwrite' : 'create'));
      const action = a === 'overwrite' || a === 'skip' ? a : 'create';
      return path ? { path, action } : null;
    })
    .filter((x): x is DryListing['entries'][number] => !!x);
  return {
    files: num(o.files) ?? num(o.count) ?? (entries.length || null),
    bytes: num(o.bytes) ?? num(o.totalBytes),
    entries,
    tables: arr(o.tables)
      .map((t) => obj(t))
      .filter((t) => typeof t.name === 'string')
      .map((t) => ({ name: String(t.name), rows: num(t.rows) ?? 0 })),
    warnings: arr(o.warnings).map(String),
  };
}

export interface RestoreResultView {
  ok: boolean | null;
  compared: number | null;
  mismatches: number;
  location: string | null;
  tables: Array<{ name: string; expected: number; actual: number }>;
}
/** `restore.result` is the agent's restoreRunResult (verify {ok, compared, mismatches[]}, stagingPath, volume). */
export function parseRestoreResult(result: unknown): RestoreResultView {
  const o = obj(result);
  const v = obj(o.verify);
  return {
    ok: typeof v.ok === 'boolean' ? v.ok : null,
    compared: num(v.compared),
    mismatches: arr(v.mismatches).length,
    location:
      typeof o.stagingPath === 'string'
        ? o.stagingPath
        : typeof o.volume === 'string'
          ? o.volume
          : null,
    tables: arr(o.tables)
      .map((t) => obj(t))
      .filter((t) => typeof t.name === 'string')
      .map((t) => ({
        name: String(t.name),
        expected: num(t.expected) ?? 0,
        actual: num(t.actual) ?? 0,
      })),
  };
}

/** A verification in flight: web-requested `verifying`, else derived from detail.verifications. */
export function verifyingOf(
  r: Pick<BackupRunDetail, 'verifying'> & { verifications?: BackupRunDetail['verifications'] },
) {
  if (r.verifying) return r.verifying;
  const v = (r.verifications ?? []).find((x) => x.status === 'running');
  return v ? { level: v.level, startedAt: v.createdAt } : null;
}

/** Latest finished verification error (for verify_failed). */
export function lastVerifyError(r: { verifications?: BackupRunDetail['verifications'] }) {
  return (r.verifications ?? []).find((x) => x.status === 'failed')?.error ?? null;
}
