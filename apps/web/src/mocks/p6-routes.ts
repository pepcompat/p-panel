/**
 * Mock routes for API_CONTRACTS §10 / §10.6 (P6), shaped like `@ppanel/shared-contracts` backup.ts:
 * repositories (append-only, init by the operator, per-server maintenance reports, step-up recovery
 * export), policies (If-Match, BACKUP_TARGET_INVALID, soft delete, run now), runs (queued → running →
 * uploaded / failed / expired, verification levels, flattened manifest rows), live snapshots
 * (202 pending → 200), restores (planned → dry-run → impact_reviewed | awaiting_approval →
 * approved → running → verified / failed / requires_manual_recovery; safety backup before in_place).
 *
 * Fixtures: app-prod-02 has repo access but is NOT initialized (runs → REPO_NOT_INITIALIZED);
 * worker-uat-01 is offline (runs expire, live snapshots unavailable); db-prod-01 reports a failed
 * offsite copy. Test hooks: a backup path containing "partial" → BACKUP_PARTIAL; a restore target
 * whose ref contains "fail" → restore step fails (staging → failed, in_place →
 * requires_manual_recovery); storefront's older run failed its test restore.
 */
import type { Server } from '@ppanel/shared-contracts';
import type { Application } from '@/lib/api/p3-types';
import { hostPathError, validatePolicy } from '@/lib/p6-gates';
import { nextRuns } from '@/lib/cron';
import type {
  BackupManifestRow,
  BackupPolicy,
  BackupPolicyInput,
  BackupPolicyTarget,
  BackupRepository,
  BackupRun,
  BackupTargetInput,
  BackupVerificationView,
  MaintenanceStatus,
  Restore,
  RestoreImpactItem,
  RestoreStep,
  RestoreStepName,
  RestoreTargetInput,
  RunSnapshot,
} from '@/lib/api/p6-types';
import { p3Internals, type P3Ctx } from './p3-routes';
import { p4Internals } from './p4-routes';

const KEY = 'ppanel.mock.p6';
const APPROVAL_TTL_MS = 60 * 60e3;
const RUN_START_MS = 700;
const RUN_UPLOAD_MS = 2600;
const VERIFY_CHECK_MS = 1500;
const VERIFY_RESTORE_MS = 2600;
const SNAPSHOT_PENDING_MS = 900;
const STEP_MS: Record<RestoreStepName, number> = {
  dry_run: 900,
  safety_backup: 1500,
  stop_app: 700,
  restore: 1400,
  start_app: 1200,
};

interface U {
  id: string;
  displayName: string;
}
type AccessRec = BackupRepository['servers'][number] & { password: string };
type RepoRec = Omit<BackupRepository, 'servers' | 'allowedActions'> & { servers: AccessRec[] };
type PolicyRec = Omit<BackupPolicy, 'allowedActions' | 'nextRunAt' | 'lastRun'> & {
  deletedAt?: string | null;
};
type RunRec = Omit<BackupRun, 'allowedActions'> & {
  t0: number;
  outcome: 'uploaded' | 'failed' | 'expired';
  outcomeError?: { code: string; message: string } | null;
  verifying: { level: 'check' | 'restore_test'; startedAt: string } | null;
  verifyDoneAt?: number | null;
  verifyFails?: boolean;
  verifications: BackupVerificationView[];
  logs: string[];
};
type RestoreRec = Omit<Restore, 'allowedActions'> & {
  dryRunDoneAt?: number | null;
  execStartedAt?: number | null;
  failAt?: RestoreStepName | null;
};
interface P6State {
  repos: RepoRec[];
  policies: PolicyRec[];
  runs: RunRec[];
  restores: RestoreRec[];
  snapPending: Record<string, number>;
}

let st: P6State | null = null;
let ctx: P3Ctx;

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}
function save() {
  try {
    storage()?.setItem(KEY, JSON.stringify(st));
  } catch {
    /* memory only */
  }
}
export function resetP6State() {
  st = null;
  storage()?.removeItem(KEY);
}
function s(): P6State {
  p4Internals.state();
  if (!st) {
    const raw = storage()?.getItem(KEY);
    if (raw)
      try {
        st = JSON.parse(raw) as P6State;
      } catch {
        st = null;
      }
    if (!st) {
      seed();
      save();
    }
  }
  return st!;
}

const iso = (ms: number) => new Date(ms).toISOString();
const apps = (): Application[] => p3Internals.state().apps;
const appById = (id: string) => apps().find((a) => a.id === id);
const appByName = (n: string) => apps().find((a) => a.name === n);
const can = (u: U, perm: Parameters<P3Ctx['hasPermFor']>[1], srv?: Server) =>
  ctx.hasPermFor(u as never, perm, srv);
const need = (u: U, perm: Parameters<P3Ctx['requirePerm']>[1], srv?: Server) =>
  ctx.requirePerm(u as never, perm, srv);
const srvOf = (id: string) => ctx.servers().find((x) => x.id === id);
const byName = (n: string) => ctx.servers().find((x) => x.name === n);
const userLabel = (id: string | null) => ctx.users().find((x) => x.id === id)?.displayName ?? null;

/** Deterministic hex: FNV-1a over the whole seed, then an xorshift stream. */
function hex(seed: string, n = 64): string {
  let x = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    x ^= seed.charCodeAt(i);
    x = Math.imul(x, 16777619) >>> 0;
  }
  let out = '';
  while (out.length < n) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    if (x === 0) x = 0x9e3779b9;
    out += x.toString(16).padStart(8, '0');
  }
  return out.slice(0, n);
}
const b64 = (h: string) =>
  btoa(String.fromCharCode(...(h.match(/../g) ?? []).map((x) => parseInt(x, 16))));
/** Seeded ids: unique 8-char prefix (the UI shows short ids). */
const uid = (n: number) => `${hex(`p6-${n}`, 8)}-b600-7000-8000-${String(n).padStart(12, '0')}`;

function serverOr404(id: string): Server {
  const srv = srvOf(id);
  if (!srv) throw new ctx.HttpError(404, 'NOT_FOUND', 'Server not found');
  return srv;
}

// ---------------------------------------------------------------- manifests / snapshots

const TABLES = ['accounts', 'contacts', 'deals', 'activities', 'notes', 'users', 'audit_log'];

function manifestFor(runId: string, targets: BackupPolicyTarget[], snaps: RunSnapshot[]) {
  const rows: BackupManifestRow[] = [];
  targets.forEach((t, ti) => {
    const snapshotId = snaps.find((x) => x.target === ti)?.snapshotId ?? '';
    if (t.type === 'paths') {
      for (const p of t.paths) {
        const n = 40 + (parseInt(hex(runId + p, 2), 16) % 60);
        for (let i = 0; i < n; i++) {
          const name =
            i % 7 === 0 ? `img-${i}.webp` : i % 5 === 0 ? `doc-${i}.pdf` : `file-${i}.json`;
          rows.push({
            kind: 'file',
            target: ti,
            snapshotId,
            path: `${p}/${i % 3 === 0 ? '2026/11/' : ''}${name}`,
            size: 512 + (parseInt(hex(runId + p + i, 6), 16) % 2_000_000),
            sha256: hex(`${runId}${p}${i}`),
          });
        }
      }
    } else if (t.type === 'volume') {
      for (let i = 0; i < 12; i++)
        rows.push({
          kind: 'file',
          target: ti,
          snapshotId,
          path: `/var/lib/docker/volumes/${t.app}_${t.volume}/_data/base/${16384 + i}`,
          size: 8192 * (i + 1) * 97,
          sha256: hex(`${runId}${t.volume}${i}`),
        });
    } else {
      rows.push({
        kind: 'database',
        target: ti,
        snapshotId,
        database: t.database,
        bytes: 18_400_000 + (parseInt(hex(runId, 5), 16) % 9_000_000),
        sha256: hex(`${runId}dump`),
        tables: TABLES.map((name, i) => ({
          name,
          rows: 120 + (parseInt(hex(runId + name, 5), 16) % 90_000) * (i + 1),
        })),
      });
    }
  });
  return rows;
}

function snapshotsFor(runId: string, targets: BackupPolicyTarget[]): RunSnapshot[] {
  return targets.map((t, i) => {
    const id = hex(`${runId}snap${i}`, 64);
    const db = t.type === 'postgres' || t.type === 'mysql';
    return {
      target: i,
      targetType: t.type,
      snapshotId: id,
      shortId: id.slice(0, 8),
      sizeBytes: t.type === 'paths' ? 240_000_000 + i * 1_000_000 : db ? 21_000_000 : 1_900_000_000,
      filesNew: db ? 1 : 37,
      filesChanged: db ? 0 : 5,
      durationMs: 4200 + i * 900,
    };
  });
}

function summary(rows: BackupManifestRow[]): BackupRun['manifest'] {
  return {
    files: rows.filter((r) => r.kind === 'file').length,
    bytes: rows.reduce((a, r) => a + (r.kind === 'file' ? r.size : r.bytes), 0),
    databases: rows.filter((r) => r.kind === 'database').length,
    truncated: false,
  };
}

/** Input targets (applicationId) → stored targets (+ resolved app slug). */
function resolveTargets(targets: BackupTargetInput[]): BackupPolicyTarget[] {
  return targets.map((t) => {
    if (t.type === 'paths') return { type: 'paths', paths: t.paths, excludes: t.excludes ?? [] };
    const app = appById(t.applicationId)?.name ?? t.applicationId.slice(0, 8);
    return { ...t, app } as BackupPolicyTarget;
  });
}
const toInput = (t: BackupPolicyTarget): BackupTargetInput => {
  if (t.type === 'paths') return t;
  const { app: _a, ...rest } = t;
  return rest as BackupTargetInput;
};

function makeRun(
  p: PolicyRec,
  trigger: BackupRun['trigger'],
  createdAt: number,
  final: {
    status: BackupRun['status'];
    verification?: BackupRun['verification'];
    verifiedAt?: number;
    error?: { code: string; message: string } | null;
    verifyFails?: boolean;
  } | null,
  n: number,
): RunRec {
  const id = n > 0 ? uid(1000 + n) : ctx.rid();
  const uploaded = final?.status === 'uploaded';
  const snaps = uploaded ? snapshotsFor(id, p.targets) : [];
  const rows = uploaded ? manifestFor(id, p.targets, snaps) : [];
  const srv = srvOf(p.serverId);
  const run: RunRec = {
    id,
    policyId: p.id,
    policyName: p.name,
    serverId: p.serverId,
    repositoryId: p.repositoryId,
    trigger,
    status: final ? final.status : 'queued',
    verification: final?.verification ?? 'none',
    verifiedAt: final?.verifiedAt ? iso(final.verifiedAt) : null,
    targets: p.targets,
    snapshots: snaps,
    manifest: uploaded ? summary(rows) : { files: 0, bytes: 0, databases: 0, truncated: false },
    error: final?.error ?? null,
    scheduledFor: trigger === 'schedule' ? iso(createdAt) : null,
    startedAt: final && final.status !== 'expired' ? iso(createdAt + RUN_START_MS) : null,
    finishedAt: final ? iso(createdAt + 4 * 60e3) : null,
    jobId: ctx.rid(),
    resticVersion: '0.17.3',
    restoreId: null,
    createdBy: null,
    createdAt: iso(createdAt),
    serverName: srv?.name,
    environment: srv?.environment,
    t0: createdAt,
    outcome: 'uploaded',
    outcomeError: null,
    verifying: null,
    verifyFails: final?.verifyFails ?? false,
    verifications: [],
    logs: [],
  };
  if (final?.verification && final.verification !== 'none') {
    const failed = final.verification === 'verify_failed';
    run.verifications.push({
      id: ctx.rid(),
      level: final.verification === 'repository_checked' ? 'check' : 'restore_test',
      status: failed ? 'failed' : 'passed',
      jobIds: [ctx.rid()],
      result: { filesCompared: 1240, mismatches: failed ? 2 : 0 },
      error: failed
        ? {
            code: 'VERIFY_FAILED',
            message: 'Test restore: 2 of 1240 files did not match the manifest sha256.',
          }
        : null,
      createdBy: null,
      createdAt: run.verifiedAt ?? run.createdAt,
      finishedAt: run.verifiedAt,
    });
  }
  run.logs = runLogs(run);
  return run;
}

function runLogs(run: RunRec): string[] {
  const t = Date.parse(run.createdAt);
  const at = (ms: number) => iso(t + ms).replace('.000Z', 'Z');
  const lines = [`${at(0)} info  job backup.run queued (run ${run.id.slice(0, 8)})`];
  if (run.status === 'expired')
    return [...lines, `${at(600e3)} warn  job expired: agent did not pick it up within the TTL`];
  if (run.status === 'queued') return lines;
  lines.push(`${at(700)} info  preflight: restic 0.17.3, repo reachable, append-only`);
  run.targets.forEach((x, i) => {
    const label =
      x.type === 'paths'
        ? x.paths.join(' ')
        : x.type === 'volume'
          ? `volume ${x.volume}`
          : `${x.type} ${x.service}/${x.database}`;
    lines.push(`${at(1000 + i * 500)} info  target ${i + 1}/${run.targets.length}: ${label}`);
  });
  if (run.status === 'failed')
    lines.push(
      `${at(3000)} error ${run.error?.code ?? 'BACKUP_FAILED'}: ${run.error?.message ?? ''}`,
    );
  if (run.status === 'uploaded') {
    run.snapshots.forEach((x) =>
      lines.push(`${at(2500)} info  snapshot ${x.shortId} saved (target ${x.target + 1})`),
    );
    lines.push(`${at(2600)} info  manifest written · no prune (append-only)`);
  }
  return lines;
}

// ---------------------------------------------------------------- seed

function seed() {
  const now = Date.now();
  const H = 3600e3;
  const [owner, admin] = [ctx.users()[0]!, ctx.users()[1]!];
  const crm = appByName('crm-suite');
  const store = appByName('storefront');
  const repoId = uid(1);
  const report = (
    serverUser: string,
    kind: MaintenanceStatus['kind'],
    ok: boolean,
    agoH: number,
    detail: Record<string, unknown>,
  ): MaintenanceStatus => ({
    kind,
    serverUser,
    ok,
    finishedAt: iso(now - agoH * H),
    receivedAt: iso(now - agoH * H + 30e3),
    detail,
  });
  const access = (name: string, initialized: boolean, ageD: number): AccessRec | null => {
    const srv = byName(name);
    if (!srv) return null;
    const user = srv.name;
    return {
      serverId: srv.id,
      serverName: srv.name,
      restUser: user,
      url: `https://backup.lab.internal:8000/${user}/`,
      initialized,
      initializedAt: initialized ? iso(now - ageD * 864e5) : null,
      restPassword: { set: true },
      repoPassword: { set: true },
      maintenance: initialized
        ? [
            report(user, 'prune', true, 20, { removed: 2 }),
            user === 'db-prod-01'
              ? report(user, 'copy', false, 19, {
                  message:
                    's3: AccessDenied writing to object-locked bucket (check the offsite bucket policy)',
                })
              : report(user, 'copy', true, 19, { copied: 1 }),
            report(user, 'check', true, 48, { message: 'no errors were found' }),
          ]
        : [],
      password: b64(hex(`pw${srv.name}`, 64)),
    };
  };
  const servers = [
    access('app-prod-01', true, 30),
    access('app-prod-02', false, 0),
    access('app-uat-01', true, 20),
    access('db-prod-01', true, 30),
    access('worker-uat-01', true, 12),
    access('dev-01', true, 9),
  ].filter((x): x is AccessRec => !!x);
  const repo: RepoRec = {
    id: repoId,
    name: 'lab-backup',
    kind: 'rest',
    baseUrl: 'https://backup.lab.internal:8000/',
    offsite: { kind: 's3', endpoint: 'https://s3.lab.internal', bucket: 'ppanel-offsite' },
    maintenanceNote:
      'Retention (forget --prune) and the offsite copy run from the maintenance identity (scripts/backup/maintenance.sh), never from the Center.',
    servers,
    createdBy: owner.id,
    createdAt: iso(now - 30 * 864e5),
    updatedAt: iso(now - 30 * 864e5),
    version: 1,
    lastRecoveryExportAt: null,
  };
  const policies: PolicyRec[] = [];
  const runs: RunRec[] = [];
  const restores: RestoreRec[] = [];
  // Helpers below (impactFor / dryListing) read the state: expose it before building restores.
  st = { repos: [repo], policies, runs, restores, snapPending: {} };

  const mk = (n: number, input: BackupPolicyInput, by: U, ageD: number): PolicyRec => ({
    id: uid(100 + n),
    name: input.name,
    serverId: input.serverId,
    repositoryId: input.repositoryId,
    targets: resolveTargets(input.targets),
    schedule: input.schedule,
    retention: input.retention,
    retentionAppliedBy: 'maintenance',
    verify: input.verify,
    helperImage: null,
    enabled: input.enabled,
    lastScheduledAt: iso(now - 864e5),
    version: 1,
    createdBy: by.id,
    createdAt: iso(now - ageD * 864e5),
    updatedAt: iso(now - ageD * 864e5),
  });

  if (crm) {
    const p = mk(
      1,
      {
        name: 'crm-suite nightly',
        serverId: crm.serverId,
        repositoryId: repoId,
        targets: [
          { type: 'paths', paths: ['/srv/crm-suite/storage'], excludes: ['*.tmp', 'cache/*'] },
          {
            type: 'postgres',
            applicationId: crm.id,
            service: 'db',
            database: 'crm',
            user: 'crm',
            passwordSecretKey: 'DB_PASSWORD',
          },
        ],
        schedule: { cron: '0 2 * * *', timezone: 'Asia/Bangkok' },
        retention: { keepDaily: 7, keepWeekly: 4, keepMonthly: 6 },
        verify: { afterBackup: 'check', restoreTestEvery: 'weekly' },
        enabled: true,
      },
      admin,
      14,
    );
    policies.push(p);
    runs.push(
      makeRun(
        p,
        'schedule',
        now - 4 * 864e5,
        { status: 'uploaded', verification: 'restore_verified', verifiedAt: now - 4 * 864e5 + H },
        1,
      ),
      makeRun(
        p,
        'schedule',
        now - 3 * 864e5,
        {
          status: 'failed',
          error: {
            code: 'BACKUP_PARTIAL',
            message:
              '1 of 2 targets failed: DUMP_FAILED (pg_dump: connection refused). No usable snapshot for this run.',
          },
        },
        2,
      ),
      makeRun(
        p,
        'schedule',
        now - 2 * 864e5,
        {
          status: 'uploaded',
          verification: 'repository_checked',
          verifiedAt: now - 2 * 864e5 + H / 4,
        },
        3,
      ),
      makeRun(
        p,
        'schedule',
        now - 864e5,
        {
          status: 'expired',
          error: {
            code: 'JOB_EXPIRED',
            message: 'The agent did not pick the job up before it expired.',
          },
        },
        4,
      ),
      makeRun(p, 'manual', now - 3 * H, { status: 'uploaded', verification: 'none' }, 5),
    );
    // A past in-place DB restore that could not bring the app back → requires_manual_recovery.
    const src = runs[0]!;
    const safety = makeRun(p, 'safety', now - 6 * H, { status: 'uploaded' }, 6);
    safety.restoreId = uid(301);
    runs.push(safety);
    const target: RestoreTargetInput = {
      type: 'postgres',
      app: crm.name,
      service: 'db',
      database: 'crm',
      user: 'crm',
      passwordSecretKey: 'DB_PASSWORD',
      mode: 'in_place',
    };
    const r = newRestoreRec(
      admin,
      src,
      src.snapshots[1]!.snapshotId,
      target,
      now - 6 * H - 20 * 60e3,
      uid(301),
    );
    r.status = 'requires_manual_recovery';
    r.approval = {
      ...r.approval,
      approvedBy: owner.id,
      approvedAt: iso(now - 6 * H - 10 * 60e3),
      expiresAt: iso(now - 6 * H + 50 * 60e3),
      usedAt: iso(now - 6 * H),
    };
    r.approvedByLabel = owner.displayName;
    r.plan.dryRun = { jobId: ctx.rid(), ok: true, listing: dryListing(r), error: null };
    r.safetySnapshotRunId = safety.id;
    r.safetySnapshotIds = safety.snapshots.map((x) => x.snapshotId);
    const t0 = now - 6 * H;
    const step = (
      name: RestoreStepName,
      i: number,
      status: RestoreStep['status'],
      message: string | null = null,
      errorCode: string | null = null,
    ): RestoreStep => ({
      name,
      status,
      jobId: ctx.rid(),
      backupRunId: name === 'safety_backup' ? safety.id : null,
      deploymentId: null,
      startedAt: iso(t0 + i * 60e3),
      finishedAt: iso(t0 + i * 60e3 + 50e3),
      message,
      errorCode,
    });
    r.steps = [
      step('dry_run', -2, 'succeeded'),
      step('safety_backup', 0, 'succeeded'),
      step('stop_app', 1, 'skipped', 'DB restore: the database service keeps running'),
      step('restore', 2, 'succeeded'),
      step(
        'start_app',
        3,
        'failed',
        'crm-suite: GET / → 502 after 90s (12 attempts)',
        'HEALTHCHECK_FAILED',
      ),
    ];
    r.error = {
      code: 'HEALTHCHECK_FAILED',
      message: 'The database was restored in place but crm-suite did not become healthy.',
    };
    r.finishedAt = iso(t0 + 4 * 60e3);
    restores.push(r);
  }
  if (store) {
    const p = mk(
      2,
      {
        name: 'storefront uploads',
        serverId: store.serverId,
        repositoryId: repoId,
        targets: [
          {
            type: 'paths',
            paths: ['/srv/storefront/uploads', '/srv/storefront/config'],
            excludes: ['*.log'],
          },
        ],
        schedule: { cron: '30 1 * * *', timezone: 'Asia/Bangkok' },
        retention: { keepDaily: 14, keepWeekly: 8, keepMonthly: 12 },
        verify: { afterBackup: 'none', restoreTestEvery: 'monthly' },
        enabled: true,
      },
      admin,
      20,
    );
    policies.push(p);
    runs.push(
      makeRun(
        p,
        'schedule',
        now - 2 * 864e5,
        {
          status: 'uploaded',
          verification: 'verify_failed',
          verifiedAt: now - 2 * 864e5 + H,
          verifyFails: true,
        },
        11,
      ),
      makeRun(p, 'schedule', now - 5 * H, { status: 'uploaded', verification: 'none' }, 12),
    );
  }
  const worker = byName('worker-uat-01');
  if (worker)
    policies.push(
      mk(
        3,
        {
          name: 'queue-worker spool',
          serverId: worker.id,
          repositoryId: repoId,
          targets: [{ type: 'paths', paths: ['/srv/queue-worker/spool'], excludes: [] }],
          schedule: { cron: '0 */6 * * *', timezone: 'UTC' },
          retention: { keepDaily: 3, keepWeekly: 0, keepMonthly: 0 },
          verify: { afterBackup: 'none', restoreTestEvery: 'never' },
          enabled: true,
        },
        admin,
        6,
      ),
    );
}

// ---------------------------------------------------------------- tick (time-based progress)

function startVerify(r: RunRec, level: 'check' | 'restore_test', now: number) {
  r.verifying = { level, startedAt: iso(now) };
  r.verifyDoneAt = now + (level === 'check' ? VERIFY_CHECK_MS : VERIFY_RESTORE_MS);
  r.verifications.unshift({
    id: ctx.rid(),
    level,
    status: 'running',
    jobIds: [ctx.rid()],
    result: null,
    error: null,
    createdBy: null,
    createdAt: iso(now),
    finishedAt: null,
  });
  r.logs.push(
    `${iso(now)} info  verify ${level} started (${level === 'check' ? 'backup.verify' : 'restore.run → scratch, verify=true'})`,
  );
}

function finishVerify(r: RunRec, now: number) {
  const lvl = r.verifying!.level;
  const v = r.verifications.find((x) => x.status === 'running');
  let err: { code: string; message: string } | null = null;
  if (r.verifyFails) {
    r.verification = 'verify_failed';
    err =
      lvl === 'check'
        ? { code: 'VERIFY_FAILED', message: 'restic check: pack 3f1a… is damaged.' }
        : {
            code: 'VERIFY_FAILED',
            message: 'Test restore: 2 of 1240 files did not match the manifest sha256.',
          };
  } else if (lvl === 'restore_test') r.verification = 'restore_verified';
  else if (r.verification !== 'restore_verified') r.verification = 'repository_checked';
  r.verifiedAt = iso(now);
  if (v) {
    v.status = err ? 'failed' : 'passed';
    v.error = err;
    v.finishedAt = iso(now);
    v.result = { filesCompared: r.manifest.files || 1, mismatches: err ? 2 : 0 };
  }
  r.logs.push(`${iso(now)} ${err ? 'error' : 'info '} verify ${lvl}: ${r.verification}`);
  r.verifying = null;
  r.verifyDoneAt = null;
}

function tick() {
  const now = Date.now();
  let dirty = false;
  for (const r of s().runs) {
    if (r.status === 'queued' && r.outcome === 'expired') {
      if (now - r.t0 >= RUN_UPLOAD_MS + 1500) {
        r.status = 'expired';
        r.error = r.outcomeError ?? { code: 'JOB_EXPIRED', message: 'Job expired' };
        r.finishedAt = iso(now);
        r.logs.push(`${iso(now)} warn  job expired: the agent is offline`);
        dirty = true;
      }
      continue;
    }
    if (r.status === 'queued' && now - r.t0 >= RUN_START_MS) {
      r.status = 'running';
      r.startedAt = iso(r.t0 + RUN_START_MS);
      r.logs.push(`${r.startedAt} info  agent accepted job · preflight ok`);
      dirty = true;
    }
    if (r.status === 'running' && now - r.t0 >= RUN_UPLOAD_MS) {
      const p = s().policies.find((x) => x.id === r.policyId);
      r.finishedAt = iso(r.t0 + RUN_UPLOAD_MS);
      if (r.outcome === 'failed') {
        r.status = 'failed';
        r.error = r.outcomeError ?? { code: 'BACKUP_FAILED', message: 'Backup failed' };
        r.logs.push(`${r.finishedAt} error ${r.error.code}: ${r.error.message}`);
      } else {
        r.status = 'uploaded';
        r.snapshots = snapshotsFor(r.id, r.targets);
        r.manifest = summary(manifestFor(r.id, r.targets, r.snapshots));
        r.snapshots.forEach((x) =>
          r.logs.push(`${r.finishedAt} info  snapshot ${x.shortId} saved (target ${x.target + 1})`),
        );
        r.logs.push(`${r.finishedAt} info  manifest written · no prune (append-only)`);
        if (p && p.verify.afterBackup !== 'none' && r.trigger !== 'safety')
          startVerify(r, p.verify.afterBackup === 'check' ? 'check' : 'restore_test', now);
      }
      dirty = true;
    }
    if (r.verifying && r.verifyDoneAt && now >= r.verifyDoneAt) {
      finishVerify(r, now);
      dirty = true;
    }
  }
  for (const r of s().restores) {
    if (r.status === 'planned' && r.dryRunDoneAt && now >= r.dryRunDoneAt) {
      const step = r.steps.find((x) => x.name === 'dry_run')!;
      step.status = 'succeeded';
      step.finishedAt = iso(r.dryRunDoneAt);
      r.plan.dryRun = { jobId: step.jobId, ok: true, listing: dryListing(r), error: null };
      r.status = r.approval.required ? 'awaiting_approval' : 'impact_reviewed';
      r.dryRunDoneAt = null;
      r.updatedAt = iso(now);
      dirty = true;
    }
    if (r.status !== 'running' || !r.execStartedAt) continue;
    const plan = expectedExec(r.target);
    let t = r.execStartedAt;
    let failed: RestoreStepName | null = null;
    for (const name of plan) {
      const dur = STEP_MS[name];
      if (now < t) break;
      let step = r.steps.find((x) => x.name === name);
      if (!step) {
        step = {
          name,
          status: 'running',
          jobId: ctx.rid(),
          backupRunId: null,
          deploymentId: null,
          startedAt: iso(t),
          finishedAt: null,
          message: null,
          errorCode: null,
        };
        r.steps.push(step);
        dirty = true;
      }
      if (now >= t + dur && step.status === 'running') {
        step.finishedAt = iso(t + dur);
        if (r.failAt === name) {
          step.status = 'failed';
          step.errorCode = name === 'restore' ? 'RESTORE_FAILED' : 'HEALTHCHECK_FAILED';
          step.message =
            name === 'restore'
              ? 'restic restore: input/output error while writing target'
              : 'GET / → 502 after 90s';
        } else {
          step.status = 'succeeded';
          if (name === 'safety_backup' && !r.safetySnapshotRunId) {
            createSafetyRun(r, t + dur);
            step.backupRunId = r.safetySnapshotRunId;
          }
          if (name === 'restore' && r.target.mode !== 'in_place')
            step.message = `→ ${stagingLocation(r)}`;
        }
        dirty = true;
      }
      if (step.status === 'failed') {
        failed = name;
        break;
      }
      if (step.status !== 'succeeded') break;
      t += dur;
    }
    const allDone = plan.every((n) => r.steps.find((x) => x.name === n)?.status === 'succeeded');
    if (failed) {
      r.status = r.target.mode === 'in_place' ? 'requires_manual_recovery' : 'failed';
      r.error =
        failed === 'restore'
          ? {
              code: 'RESTORE_FAILED',
              message:
                r.target.mode === 'in_place'
                  ? 'The restore failed part-way; the target may be partially overwritten.'
                  : 'The restore into the isolated target failed. Nothing live was touched.',
            }
          : {
              code: 'HEALTHCHECK_FAILED',
              message: 'The app did not become healthy after the restore.',
            };
      r.finishedAt = iso(now);
      dirty = true;
    } else if (allDone) {
      r.status = 'verified';
      r.result = verifyResultFor(r);
      r.finishedAt = iso(now);
      dirty = true;
    }
  }
  if (dirty) save();
}

function createSafetyRun(r: RestoreRec, at: number) {
  const p = s().policies.find((x) => x.id === s().runs.find((y) => y.id === r.runId)?.policyId);
  if (!p) return;
  const run = makeRun(p, 'safety', at - STEP_MS.safety_backup, { status: 'uploaded' }, 0);
  run.restoreId = r.id;
  run.finishedAt = iso(at);
  s().runs.push(run);
  r.safetySnapshotRunId = run.id;
  r.safetySnapshotIds = run.snapshots.map((x) => x.snapshotId);
}

// ---------------------------------------------------------------- restores

function srcRows(r: Pick<Restore, 'runId' | 'snapshotId'>) {
  const run = s().runs.find((x) => x.id === r.runId);
  if (!run) return [];
  return manifestFor(run.id, run.targets, run.snapshots).filter(
    (x) => x.snapshotId === r.snapshotId,
  );
}

const stagingLocation = (r: Pick<Restore, 'id' | 'target'>) => {
  const short = hex(r.id, 8);
  const t = r.target;
  return t.type === 'paths'
    ? `/var/lib/ppanel-agent/restore/${short}`
    : t.type === 'volume'
      ? `ppanel-${t.app}-restore-${short}`
      : `ppanel-restore-${short}/${t.database}`;
};

function verifyResultFor(r: RestoreRec): Restore['result'] {
  const rows = srcRows(r);
  const db = rows.find((x) => x.kind === 'database');
  const files = rows.filter((x) => x.kind === 'file').length;
  return {
    verify: { ok: true, compared: db ? db.tables.length : files, mismatches: [] },
    ...(db
      ? { tables: db.tables.map((x) => ({ name: x.name, expected: x.rows, actual: x.rows })) }
      : {}),
    ...(r.target.mode !== 'in_place' ? { stagingPath: stagingLocation(r) } : {}),
  };
}

function targetRef(t: RestoreTargetInput): string {
  if (t.type === 'paths') return (t.include ?? []).length ? t.include!.join(', ') : '*';
  if (t.type === 'volume') return `${t.app}/${t.volume}`;
  return `${t.app}/${t.service}/${t.database}`;
}

function impactFor(
  r: Pick<Restore, 'id' | 'runId' | 'snapshotId'> & { target: RestoreTargetInput },
): RestoreImpactItem[] {
  const t = r.target;
  const inPlace = t.mode === 'in_place';
  const run = s().runs.find((x) => x.id === r.runId);
  const snap = run?.snapshots.find((x) => x.snapshotId === r.snapshotId);
  const src = snap ? run!.targets[snap.target] : undefined;
  const loc = stagingLocation(r as Pick<Restore, 'id' | 'target'>);
  const out: RestoreImpactItem[] = [];
  if (t.type === 'paths') {
    const paths = (t.include ?? []).length ? t.include! : src?.type === 'paths' ? src.paths : [];
    for (const p of paths)
      out.push(
        inPlace
          ? {
              effect: 'overwrite',
              kind: 'path',
              ref: p,
              detail: 'existing files are replaced; files added since the snapshot are kept',
            }
          : { effect: 'create', kind: 'path', ref: `${loc}${p}`, detail: `staging copy of ${p}` },
      );
  } else if (t.type === 'volume') {
    out.push(
      inPlace
        ? {
            effect: 'overwrite',
            kind: 'volume',
            ref: t.volume,
            detail: `named volume of ${t.app} is replaced`,
          }
        : { effect: 'create', kind: 'volume', ref: loc, detail: 'new isolated volume' },
    );
    if (inPlace)
      out.push({
        effect: 'downtime',
        kind: 'application',
        ref: t.app,
        detail: 'the app is stopped during the restore (~90 s)',
      });
  } else {
    out.push(
      inPlace
        ? {
            effect: 'overwrite',
            kind: 'database',
            ref: `${t.service}/${t.database}`,
            detail:
              'tables are dropped and re-created from the dump; data written after the snapshot is lost',
          }
        : { effect: 'create', kind: 'database', ref: loc, detail: 'isolated scratch DB container' },
    );
    if (inPlace)
      out.push({
        effect: 'downtime',
        kind: 'application',
        ref: t.app,
        detail: 'app containers using the DB are restarted',
      });
  }
  out.push({
    effect: 'note',
    kind: 'config',
    ref: 'config_vs_data',
    detail:
      'A config/app rollback never restores data, and a data restore never rolls back config or app versions.',
  });
  return out;
}

function dryListing(r: Pick<Restore, 'runId' | 'snapshotId' | 'target'>) {
  const rows = srcRows(r);
  const t = r.target;
  const inPlace = t.mode === 'in_place';
  const db = rows.find(
    (x): x is Extract<BackupManifestRow, { kind: 'database' }> => x.kind === 'database',
  );
  if (db)
    return {
      files: 1,
      bytes: db.bytes,
      entries: [{ path: `${db.database}.dump`, action: inPlace ? 'overwrite' : 'create' }],
      tables: db.tables,
      warnings: inPlace ? ['Connections to the database are closed during the restore.'] : [],
    };
  const files = rows.filter(
    (x): x is Extract<BackupManifestRow, { kind: 'file' }> => x.kind === 'file',
  );
  const inc = t.type === 'paths' ? (t.include ?? []) : [];
  const pick = inc.length ? files.filter((e) => inc.some((i) => e.path.startsWith(i))) : files;
  return {
    files: pick.length,
    bytes: pick.reduce((a, e) => a + e.size, 0),
    entries: pick.slice(0, 50).map((e, i) => ({
      path: e.path,
      action: inPlace ? (i % 9 === 0 ? 'create' : 'overwrite') : 'create',
    })),
    warnings:
      inPlace && t.type === 'paths' ? ['Files created after the snapshot are not deleted.'] : [],
  };
}

const expectedExec = (t: RestoreTargetInput): RestoreStepName[] =>
  t.mode !== 'in_place'
    ? ['restore']
    : t.type === 'paths'
      ? ['safety_backup', 'restore']
      : ['safety_backup', 'stop_app', 'restore', 'start_app'];

function newRestoreRec(
  u: U,
  run: RunRec,
  snapshotId: string,
  target: RestoreTargetInput,
  at: number,
  id = ctx.rid(),
): RestoreRec {
  const srv = srvOf(run.serverId);
  const reasons: Array<'in_place' | 'production'> = [];
  if (target.mode === 'in_place') reasons.push('in_place');
  if (srv?.environment === 'production') reasons.push('production');
  const impact = impactFor({ id, target, runId: run.id, snapshotId });
  return {
    id,
    runId: run.id,
    snapshotId,
    serverId: run.serverId,
    applicationId: target.type === 'paths' ? null : (appByName(target.app)?.id ?? null),
    target: target as Restore['target'],
    status: 'planned',
    plan: { impact, dryRun: null },
    planHash: hex(JSON.stringify([snapshotId, target, impact])),
    approval: {
      required: reasons.length > 0,
      reasons,
      approvedBy: null,
      approvedAt: null,
      expiresAt: null,
      usedAt: null,
    },
    steps: [],
    safetySnapshotRunId: null,
    safetySnapshotIds: [],
    result: null,
    error: null,
    createdBy: u.id,
    createdAt: iso(at),
    updatedAt: iso(at),
    finishedAt: null,
    version: 1,
    serverName: srv?.name,
    environment: srv?.environment,
    createdByLabel: userLabel(u.id),
    approvedByLabel: null,
    failAt: targetRef(target).includes('fail')
      ? 'restore'
      : target.mode === 'in_place' && target.type !== 'paths' && target.app === 'storefront'
        ? 'start_app'
        : null,
  };
}

function publicRestore(u: U, r: RestoreRec): Restore {
  const { dryRunDoneAt: _d, execStartedAt: _e, failAt: _f, ...rest } = r;
  const srv = srvOf(r.serverId);
  const actions: Restore['allowedActions'] = [];
  if (can(u, 'backups.restore', srv)) {
    if (['planned', 'impact_reviewed', 'awaiting_approval', 'approved'].includes(r.status))
      actions.push('cancel');
    if (r.status === 'planned' && !r.dryRunDoneAt) actions.push('dry_run');
    if ((r.status === 'impact_reviewed' && !r.approval.required) || r.status === 'approved')
      actions.push('execute');
  }
  if (r.status === 'awaiting_approval' && can(u, 'approvals.decide', srv) && r.createdBy !== u.id)
    actions.push('approve');
  return { ...rest, allowedActions: actions };
}

// ---------------------------------------------------------------- public views

function publicRun(u: U, r: RunRec): BackupRun {
  const {
    t0: _t,
    outcome: _o,
    outcomeError: _oe,
    verifyDoneAt: _v,
    verifyFails: _vf,
    logs: _l,
    verifications: _vs,
    ...rest
  } = r;
  const srv = srvOf(r.serverId);
  const actions: BackupRun['allowedActions'] = [];
  if (r.status === 'uploaded' && r.snapshots.length) {
    if (can(u, 'backups.create', srv) && !r.verifying)
      actions.push('verify_check', 'verify_restore_test');
    if (can(u, 'backups.restore', srv)) actions.push('restore');
  }
  const p = s().policies.find((x) => x.id === r.policyId);
  return {
    ...rest,
    policyName: p?.name ?? rest.policyName,
    serverName: srv?.name,
    environment: srv?.environment,
    allowedActions: actions,
  };
}

function publicPolicy(u: U, p: PolicyRec): BackupPolicy {
  const srv = srvOf(p.serverId);
  const last = s()
    .runs.filter((r) => r.policyId === p.id && r.trigger !== 'safety')
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  const { deletedAt: _d, ...rest } = p;
  return {
    ...rest,
    serverName: srv?.name,
    environment: srv?.environment,
    repositoryName: s().repos.find((x) => x.id === p.repositoryId)?.name,
    nextRunAt: p.enabled
      ? (nextRuns(p.schedule.cron, p.schedule.timezone, Date.now(), 1).map(iso)[0] ?? null)
      : null,
    lastRun: last
      ? {
          id: last.id,
          status: last.status,
          verification: last.verification,
          finishedAt: last.finishedAt,
        }
      : null,
    allowedActions: can(u, 'backups.create', srv) ? ['edit', 'delete', 'run'] : [],
  };
}

function publicRepo(u: U, r: RepoRec): BackupRepository {
  return {
    ...r,
    servers: r.servers
      .filter((a) => can(u, 'fleet.read', srvOf(a.serverId)))
      .map(({ password: _p, ...a }) => a),
    allowedActions: can(u, 'policies.manage')
      ? ['edit', 'manage_access', 'mark_initialized', 'recovery_export']
      : [],
  };
}

function targetInvalid(errs: Record<string, string>) {
  return new ctx.HttpError(
    422,
    'BACKUP_TARGET_INVALID',
    'Backup policy is invalid',
    Object.entries(errs).map(([path, message]) => ({ path, message })),
  );
}

function checkPolicyBody(b: BackupPolicyInput, srv: Server) {
  const errs: Record<string, string> = { ...validatePolicy(b) };
  if (!s().repos.some((x) => x.id === b.repositoryId)) errs.repositoryId = 'Unknown repository';
  b.targets.forEach((t, i) => {
    // createBackupPolicySchema is strict: stored targets carry `app`, inputs must not.
    if ((t as { app?: unknown }).app !== undefined) errs[`targets.${i}`] = 'Unrecognized key: app';
    if (t.type === 'paths') {
      t.paths.forEach((p, j) => {
        if (hostPathError(p))
          errs[`targets.${i}.paths.${j}`] =
            'Path must be canonical and not under /proc, /sys, /dev or the agent state dir';
      });
      return;
    }
    const app = appById(t.applicationId);
    if (!app || app.serverId !== srv.id) {
      errs[`targets.${i}.app`] = 'App not found on this server';
      return;
    }
    if (t.type === 'postgres' || t.type === 'mysql') {
      if (!app.compose?.services.some((x) => x.service === t.service))
        errs[`targets.${i}.service`] = 'Not a compose DB service of this app';
      const keys = app.compose?.secretKeys ?? app.container?.secretKeys ?? [];
      if (!keys.includes(t.passwordSecretKey))
        errs[`targets.${i}.passwordSecretKey`] = 'Secret key does not exist on this app';
    }
  });
  return errs;
}

function startRun(u: U, p: PolicyRec, trigger: BackupRun['trigger'], requestId: string): RunRec {
  const srv = serverOr404(p.serverId);
  const active = s().runs.find(
    (r) => r.policyId === p.id && (r.status === 'queued' || r.status === 'running'),
  );
  if (active)
    throw new ctx.HttpError(
      409,
      'BACKUP_IN_PROGRESS',
      'A run of this policy is already in progress.',
      {
        runId: active.id,
      },
    );
  const access = s()
    .repos.find((x) => x.id === p.repositoryId)
    ?.servers.find((a) => a.serverId === p.serverId);
  if (!access)
    throw new ctx.HttpError(
      409,
      'REPO_ACCESS_MISSING',
      `${srv.name} has no access to this repository.`,
    );
  const run = makeRun(p, trigger, Date.now(), null, 0);
  run.createdBy = u.id;
  if (!access.initialized) {
    run.status = 'failed';
    run.error = {
      code: 'REPO_NOT_INITIALIZED',
      message: `Repository not initialized for ${srv.name}. The operator runs scripts/backup/maintenance.sh init ${access.restUser}.`,
    };
    run.finishedAt = run.createdAt;
    run.logs.push(`${run.createdAt} error preflight REPO_NOT_INITIALIZED`);
  } else if (srv.status === 'offline' || srv.status === 'revoked') {
    run.outcome = 'expired';
    run.outcomeError = {
      code: 'JOB_EXPIRED',
      message: 'The agent is offline; the job expired before it was picked up.',
    };
  } else if (
    p.targets.some((t) => t.type === 'paths' && t.paths.some((x) => x.includes('partial')))
  ) {
    run.outcome = 'failed';
    run.outcomeError = {
      code: 'BACKUP_PARTIAL',
      message: '1 target could not be read (permission denied). No usable snapshot for this run.',
    };
  }
  s().runs.push(run);
  ctx.audit(u, 'backup.run', srv, 'success', requestId);
  save();
  return run;
}

// ---------------------------------------------------------------- routes

export function registerP6Routes(c: P3Ctx) {
  ctx = c;
  const { on, ok, HttpError } = c;
  const stepUp = (req: Request, u: U, srv: Server, action: string, rid: string) => {
    if (!c.checkStepUp(req, u)) {
      c.audit(u, action, srv, 'denied', rid);
      throw new HttpError(
        403,
        'STEP_UP_REQUIRED',
        'This action requires a fresh 2FA confirmation (X-Step-Up).',
      );
    }
  };
  const policyOr404 = (u: U, id: string) => {
    const p = s().policies.find((x) => x.id === id && !x.deletedAt);
    if (!p || !can(u, 'fleet.read', srvOf(p.serverId)))
      throw new HttpError(404, 'NOT_FOUND', 'Policy not found');
    return p;
  };
  const runOr404 = (u: U, id: string) => {
    const r = s().runs.find((x) => x.id === id);
    if (!r || !can(u, 'fleet.read', srvOf(r.serverId)))
      throw new HttpError(404, 'NOT_FOUND', 'Backup run not found');
    return r;
  };
  const restoreOr404 = (u: U, id: string) => {
    const r = s().restores.find((x) => x.id === id);
    if (!r || !can(u, 'fleet.read', srvOf(r.serverId)))
      throw new HttpError(404, 'NOT_FOUND', 'Restore not found');
    return r;
  };

  // ----- repositories
  on('GET', '/backup-repositories', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const { slice, paginate } = c.paginate(
      s().repos.map((r) => publicRepo(u, r)),
      url,
    );
    return ok(requestId, slice, 200, paginate);
  });
  on(
    'POST',
    '/backup-repositories/:id/servers/:sid/initialized',
    ({ req, params, body, requestId }) => {
      const u = c.currentUser(req);
      const repo = s().repos.find((x) => x.id === params[0]);
      if (!repo) throw new HttpError(404, 'NOT_FOUND', 'Repository not found');
      const srv = serverOr404(params[1]!);
      need(u, 'policies.manage', srv);
      const a = repo.servers.find((x) => x.serverId === srv.id);
      if (!a)
        throw new HttpError(
          409,
          'REPO_ACCESS_MISSING',
          'This server has no access to the repository',
        );
      const flag = body.initialized !== false;
      a.initialized = flag;
      a.initializedAt = flag ? (a.initializedAt ?? iso(Date.now())) : null;
      c.audit(u, 'backup.repository.initialized', srv, 'success', requestId);
      save();
      return ok(requestId, publicRepo(u, repo));
    },
  );
  on('GET', '/backup-repositories/:id/recovery-export', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const repo = s().repos.find((x) => x.id === params[0]);
    if (!repo) throw new HttpError(404, 'NOT_FOUND', 'Repository not found');
    need(u, 'policies.manage');
    const anySrv = srvOf(repo.servers[0]?.serverId ?? '') ?? ctx.servers()[0]!;
    stepUp(req, u, anySrv, 'backup.recovery_export', requestId);
    repo.lastRecoveryExportAt = iso(Date.now());
    c.audit(u, 'backup.recovery_export', anySrv, 'success', requestId);
    save();
    return ok(requestId, {
      repositoryId: repo.id,
      name: repo.name,
      baseUrl: repo.baseUrl,
      exportedAt: repo.lastRecoveryExportAt,
      servers: repo.servers.map((a) => ({
        serverId: a.serverId,
        serverName: a.serverName,
        restUser: a.restUser,
        url: a.url,
        repoPassword: a.password,
      })),
      note: 'Store offline (printed and sealed, or age-encrypted). rest-server passwords are reset on the backup host.',
    });
  });

  // ----- policies
  on('GET', '/backup-policies', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const sid = url.searchParams.get('server_id');
    const items = s()
      .policies.filter((p) => !p.deletedAt && can(u, 'fleet.read', srvOf(p.serverId)))
      .filter((p) => !sid || p.serverId === sid)
      .map((p) => publicPolicy(u, p));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('GET', '/backup-policies/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    return ok(requestId, publicPolicy(u, policyOr404(u, params[0]!)));
  });
  on('POST', '/backup-policies', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    const b = body as unknown as BackupPolicyInput;
    const srv = srvOf(String(b.serverId ?? ''));
    if (!srv) throw targetInvalid({ serverId: 'Unknown server' });
    need(u, 'backups.create', srv);
    const input: BackupPolicyInput = {
      name: String(b.name ?? '').trim(),
      serverId: srv.id,
      repositoryId: String(b.repositoryId ?? ''),
      targets: Array.isArray(b.targets) ? b.targets : [],
      schedule: {
        cron: String(b.schedule?.cron ?? ''),
        timezone: String(b.schedule?.timezone ?? ''),
      },
      retention: {
        keepDaily: Number(b.retention?.keepDaily ?? 7),
        keepWeekly: Number(b.retention?.keepWeekly ?? 4),
        keepMonthly: Number(b.retention?.keepMonthly ?? 6),
      },
      verify: {
        afterBackup: b.verify?.afterBackup ?? 'check',
        restoreTestEvery: b.verify?.restoreTestEvery ?? 'never',
      },
      enabled: b.enabled !== false,
    };
    const errs = checkPolicyBody(input, srv);
    if (errs.cron || errs.timezone)
      throw new HttpError(
        422,
        'SCHEDULE_INVALID',
        'cron must be 5 fields and timezone an IANA name',
      );
    if (Object.keys(errs).length) throw targetInvalid(errs);
    if (
      !s()
        .repos.find((x) => x.id === input.repositoryId)
        ?.servers.some((a) => a.serverId === srv.id)
    )
      throw new HttpError(
        409,
        'REPO_ACCESS_MISSING',
        `${srv.name} has no access to this repository.`,
      );
    const now = iso(Date.now());
    const p: PolicyRec = {
      id: c.rid(),
      name: input.name,
      serverId: srv.id,
      repositoryId: input.repositoryId,
      targets: resolveTargets(input.targets),
      schedule: input.schedule,
      retention: input.retention,
      retentionAppliedBy: 'maintenance',
      verify: input.verify,
      helperImage: null,
      enabled: input.enabled,
      lastScheduledAt: null,
      version: 1,
      createdBy: u.id,
      createdAt: now,
      updatedAt: now,
    };
    s().policies.push(p);
    c.audit(u, 'backup.policy.create', srv, 'success', requestId);
    save();
    return ok(requestId, publicPolicy(u, p), 201);
  });
  on('PATCH', '/backup-policies/:id', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const p = policyOr404(u, params[0]!);
    const srv = serverOr404(p.serverId);
    need(u, 'backups.create', srv);
    if (Number(req.headers.get('If-Match')) !== p.version)
      throw new HttpError(
        409,
        'VERSION_CONFLICT',
        'This policy was changed by someone else. Reload and try again.',
        {
          currentVersion: p.version,
        },
      );
    const b = body as Partial<BackupPolicyInput>;
    if ('serverId' in b)
      throw new HttpError(400, 'VALIDATION_FAILED', 'Unrecognized key: serverId');
    const next: BackupPolicyInput = {
      name: b.name !== undefined ? String(b.name).trim() : p.name,
      serverId: p.serverId,
      repositoryId: b.repositoryId ?? p.repositoryId,
      targets: b.targets ?? p.targets.map(toInput),
      schedule: b.schedule ?? p.schedule,
      retention: b.retention ?? p.retention,
      verify: b.verify ?? p.verify,
      enabled: b.enabled ?? p.enabled,
    };
    const errs = checkPolicyBody(next, srv);
    if (Object.keys(errs).length) throw targetInvalid(errs);
    Object.assign(p, {
      ...next,
      targets: resolveTargets(next.targets),
      version: p.version + 1,
      updatedAt: iso(Date.now()),
    });
    c.audit(u, 'backup.policy.update', srv, 'success', requestId);
    save();
    return ok(requestId, publicPolicy(u, p));
  });
  on('DELETE', '/backup-policies/:id', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const p = policyOr404(u, params[0]!);
    const srv = serverOr404(p.serverId);
    need(u, 'backups.create', srv);
    if (Number(req.headers.get('If-Match')) !== p.version)
      throw new HttpError(409, 'VERSION_CONFLICT', 'This policy was changed by someone else.', {
        currentVersion: p.version,
      });
    p.deletedAt = iso(Date.now()); // soft delete: runs stay restorable
    c.audit(u, 'backup.policy.delete', srv, 'success', requestId);
    save();
    return new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });
  });
  on('POST', '/backup-policies/:id/run', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const p = policyOr404(u, params[0]!);
    need(u, 'backups.create', srvOf(p.serverId));
    const run = startRun(u, p, 'manual', requestId);
    return ok(requestId, { run: publicRun(u, run), reused: false }, 202);
  });

  // ----- runs
  on('GET', '/backup-runs', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const q = url.searchParams;
    const items = s()
      .runs.filter((r) => can(u, 'fleet.read', srvOf(r.serverId)))
      .filter((r) => !q.get('policy_id') || r.policyId === q.get('policy_id'))
      .filter((r) => !q.get('status') || r.status === q.get('status'))
      .filter((r) => !q.get('server_id') || r.serverId === q.get('server_id'))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((r) => publicRun(u, r));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('GET', '/backup-runs/:id', ({ req, url, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = runOr404(u, params[0]!);
    const rows = r.status === 'uploaded' ? manifestFor(r.id, r.targets, r.snapshots) : [];
    const page = Math.max(1, Number(url.searchParams.get('manifestPage') ?? 1) || 1);
    const limit = Math.min(
      1000,
      Math.max(1, Number(url.searchParams.get('manifestLimit') ?? 100) || 100),
    );
    return ok(requestId, {
      ...publicRun(u, r),
      manifestEntries: rows.slice((page - 1) * limit, page * limit),
      manifestPaginate: { page, limit, total: rows.length },
      verifications: r.verifications,
      logs: r.logs,
    });
  });
  on('POST', '/backup-runs/:id/verify', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = runOr404(u, params[0]!);
    const srv = serverOr404(r.serverId);
    need(u, 'backups.create', srv);
    const level =
      body.level === 'restore_test' ? 'restore_test' : body.level === 'check' ? 'check' : null;
    if (!level)
      throw new HttpError(400, 'VALIDATION_FAILED', 'level must be check or restore_test');
    if (r.status !== 'uploaded' || !r.snapshots.length)
      throw new HttpError(409, 'RUN_NOT_UPLOADED', 'Only an uploaded run has snapshots to verify.');
    if (r.verifying)
      throw new HttpError(
        409,
        'VERIFY_IN_PROGRESS',
        'A verification of this run is already running.',
      );
    if (srv.status === 'offline')
      throw new HttpError(409, 'AGENT_OFFLINE', 'The agent is offline.');
    startVerify(r, level, Date.now());
    c.audit(u, `backup.verify.${level}`, srv, 'success', requestId);
    save();
    return ok(requestId, publicRun(u, r), 202);
  });

  // ----- live snapshots (backups.create; 202 pending first, like a slow agent)
  on('GET', '/servers/:id/snapshots', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const srv = serverOr404(params[0]!);
    need(u, 'backups.create', srv);
    const repo = s().repos.find((r) => r.servers.some((a) => a.serverId === srv.id));
    const access = repo?.servers.find((a) => a.serverId === srv.id);
    if (!repo || !access)
      throw new HttpError(
        409,
        'REPO_ACCESS_MISSING',
        'No backup repository is configured for this server.',
      );
    if (!access.initialized)
      throw new HttpError(
        409,
        'REPO_NOT_INITIALIZED',
        `Repository not initialized for ${srv.name}.`,
      );
    if (srv.status === 'offline' || srv.status === 'revoked')
      throw new HttpError(
        409,
        'AGENT_OFFLINE',
        'The agent is offline; the live snapshot list needs the agent (backup.snapshots).',
      );
    const now = Date.now();
    const until = s().snapPending[srv.id];
    if (!until || now - until > 30_000) {
      s().snapPending[srv.id] = now + SNAPSHOT_PENDING_MS;
      save();
    }
    const jobId = hex(`${srv.id}${s().snapPending[srv.id]}`, 8);
    if (now < s().snapPending[srv.id]!) return ok(requestId, { pending: true, jobId }, 202);
    const snapshots = s()
      .runs.filter((r) => r.serverId === srv.id && r.status === 'uploaded')
      .flatMap((r) =>
        r.snapshots.map((x) => {
          const t = r.targets[x.target];
          return {
            id: x.snapshotId,
            shortId: x.shortId,
            time: r.finishedAt ?? r.createdAt,
            tags: [
              `policy=${r.policyId}`,
              `run=${r.id}`,
              ...(r.trigger === 'safety' ? ['safety'] : []),
            ],
            paths: t?.type === 'paths' ? t.paths : t ? [`${t.type}:${t.app}`] : [],
            hostname: srv.hostname,
            sizeBytes: x.sizeBytes,
          };
        }),
      )
      .sort((a, b) => b.time.localeCompare(a.time));
    return ok(requestId, { repositoryId: repo.id, jobId, pending: false, snapshots });
  });

  // ----- restores
  on('GET', '/restores', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const q = url.searchParams;
    const items = s()
      .restores.filter((r) => can(u, 'fleet.read', srvOf(r.serverId)))
      .filter((r) => !q.get('status') || r.status === q.get('status'))
      .filter((r) => !q.get('server_id') || r.serverId === q.get('server_id'))
      .filter((r) => !q.get('run_id') || r.runId === q.get('run_id'))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((r) => publicRestore(u, r));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('GET', '/restores/:id', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    return ok(requestId, publicRestore(u, restoreOr404(u, params[0]!)));
  });
  on('POST', '/restores', ({ req, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const run = runOr404(u, String(body.runId ?? ''));
    const srv = serverOr404(run.serverId);
    need(u, 'backups.restore', srv);
    if (run.status !== 'uploaded')
      throw new HttpError(409, 'RUN_NOT_UPLOADED', 'Only an uploaded run can be restored.');
    const snap = run.snapshots.find((x) => x.snapshotId === body.snapshotId);
    if (!snap)
      throw new HttpError(
        422,
        'SNAPSHOT_NOT_IN_RUN',
        'snapshotId is not one of the run’s snapshots.',
      );
    const t = body.target as RestoreTargetInput | undefined;
    if (t && (t as { applicationId?: unknown }).applicationId !== undefined)
      throw new HttpError(400, 'VALIDATION_FAILED', 'Unrecognized key: applicationId');
    const src = run.targets[snap.target];
    const badMode = !t
      ? true
      : t.type === 'postgres' || t.type === 'mysql'
        ? t.mode !== 'scratch' && t.mode !== 'in_place'
        : t.mode !== 'staging' && t.mode !== 'in_place';
    const mismatch =
      !t ||
      !src ||
      badMode ||
      t.type !== src.type ||
      (t.type !== 'paths' && src.type !== 'paths' && t.app !== src.app);
    if (mismatch)
      throw new HttpError(
        422,
        'RESTORE_TARGET_MISMATCH',
        'The restore target does not match the snapshot’s backup target.',
      );
    const target = (
      t!.type === 'paths' ? { ...t!, include: t!.include ?? [] } : t!
    ) as RestoreTargetInput;
    if (target.type === 'paths' && (target.include ?? []).some((p) => hostPathError(p)))
      throw new HttpError(400, 'VALIDATION_FAILED', 'include paths must be canonical');
    const r = newRestoreRec(u, run, snap.snapshotId, target, Date.now());
    s().restores.push(r);
    c.audit(u, 'restore.create', srv, 'success', requestId);
    save();
    return ok(requestId, publicRestore(u, r), 201);
  });
  on('POST', '/restores/:id/dry-run', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const r = restoreOr404(u, params[0]!);
    const srv = serverOr404(r.serverId);
    need(u, 'backups.restore', srv);
    if (r.status !== 'planned' || r.dryRunDoneAt)
      throw new HttpError(409, 'RESTORE_STATE_INVALID', `Cannot dry-run a ${r.status} restore.`);
    if (srv.status === 'offline')
      throw new HttpError(409, 'AGENT_OFFLINE', 'The agent is offline.');
    const now = Date.now();
    r.dryRunDoneAt = now + STEP_MS.dry_run;
    r.steps = r.steps.filter((x) => x.name !== 'dry_run');
    r.steps.push({
      name: 'dry_run',
      status: 'running',
      jobId: c.rid(),
      backupRunId: null,
      deploymentId: null,
      startedAt: iso(now),
      finishedAt: null,
      message: null,
      errorCode: null,
    });
    r.version += 1;
    c.audit(u, 'restore.dry_run', srv, 'success', requestId);
    save();
    return ok(requestId, publicRestore(u, r), 202);
  });
  on('POST', '/restores/:id/approve', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = restoreOr404(u, params[0]!);
    const srv = serverOr404(r.serverId);
    need(u, 'approvals.decide', srv);
    if (r.createdBy === u.id) {
      c.audit(u, 'restores.approve', srv, 'denied', requestId);
      throw new HttpError(
        403,
        'APPROVER_IS_CREATOR',
        'The creator of a restore cannot approve it. Ask another approver.',
      );
    }
    stepUp(req, u, srv, 'restores.approve', requestId);
    if (r.status !== 'awaiting_approval')
      throw new HttpError(409, 'RESTORE_STATE_INVALID', `Cannot approve a ${r.status} restore.`);
    if (body.planHash !== r.planHash)
      throw new HttpError(409, 'PLAN_HASH_MISMATCH', 'The plan changed since you reviewed it.');
    const now = Date.now();
    r.status = 'approved';
    r.approval = {
      ...r.approval,
      approvedBy: u.id,
      approvedAt: iso(now),
      expiresAt: iso(now + APPROVAL_TTL_MS),
    };
    r.approvedByLabel = u.displayName;
    r.version += 1;
    c.audit(u, 'restores.approve', srv, 'success', requestId);
    save();
    return ok(requestId, publicRestore(u, r));
  });
  on('POST', '/restores/:id/execute', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = restoreOr404(u, params[0]!);
    const srv = serverOr404(r.serverId);
    need(u, 'backups.restore', srv);
    if (r.approval.required) {
      if (r.status !== 'approved') {
        c.audit(u, 'restores.execute', srv, 'denied', requestId);
        throw new HttpError(
          409,
          'APPROVAL_REQUIRED',
          'This restore needs approval by another user before it can run.',
        );
      }
      if (r.approval.expiresAt && Date.parse(r.approval.expiresAt) < Date.now())
        throw new HttpError(
          409,
          'APPROVAL_EXPIRED',
          'The approval expired. Request a new approval.',
        );
      r.approval.usedAt = iso(Date.now());
    } else if (r.status !== 'impact_reviewed') {
      throw new HttpError(409, 'RESTORE_STATE_INVALID', 'Run the dry-run first.');
    }
    r.status = 'running';
    r.execStartedAt = Date.now();
    r.version += 1;
    c.audit(u, 'restores.execute', srv, 'success', requestId);
    save();
    tick();
    return ok(requestId, publicRestore(u, r), 202);
  });
  on('POST', '/restores/:id/cancel', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const r = restoreOr404(u, params[0]!);
    const srv = serverOr404(r.serverId);
    need(u, 'backups.restore', srv);
    if (!['planned', 'impact_reviewed', 'awaiting_approval', 'approved'].includes(r.status))
      throw new HttpError(
        409,
        'RESTORE_STATE_INVALID',
        'Only a restore that has not started can be cancelled.',
      );
    r.status = 'cancelled';
    r.dryRunDoneAt = null;
    r.version += 1;
    r.finishedAt = iso(Date.now());
    c.audit(u, 'restore.cancel', srv, 'success', requestId);
    save();
    return ok(requestId, publicRestore(u, r));
  });
}

export const p6Debug = { state: () => s(), tick: () => tick() };
