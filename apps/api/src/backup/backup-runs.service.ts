import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  BACKUP_RUN_ACTIVE_STATUSES,
  type BackupManifestEntry,
  type BackupPolicyTarget,
  type BackupRun as BackupRunView,
  type BackupRunAction,
  type BackupRunDetail,
  type BackupRunStatus,
  type BackupRunTrigger,
  type BackupSnapshotRef,
  type BackupVerification,
  type BackupVerificationView,
  type BackupVerifyLevel,
  backupVerifyResultSchema,
  ERROR_CODES,
  restoreRunResultSchema,
  type ServerSnapshots,
} from '@ppanel/shared-contracts';
import type {
  BackupPolicy as PolicyRow,
  BackupRun as RunRow,
  BackupVerification as VerificationRow,
  Prisma,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { serverScope } from '../discovery/p3-common';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import {
  boundJson,
  boundManifest,
  jobTarget,
  manifestFor,
  manifestRows,
  mapSnapshots,
} from './backup-common';
import { BackupCredentialsService, repoUrl } from './backup-credentials.service';

const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_.:-]{8,128}$/;
const TERMINAL_RUN: BackupRunStatus[] = ['uploaded', 'failed', 'expired', 'cancelled'];

export type RunFinishedListener = (run: RunRow) => Promise<void>;

export function jobErr(job: Pick<FinishedJob, 'status' | 'error'>): {
  code: string;
  message: string;
  details?: unknown;
} {
  const e = (job.error ?? {}) as { code?: unknown; message?: unknown; details?: unknown };
  const code =
    typeof e.code === 'string'
      ? e.code
      : job.status === 'expired'
        ? 'LEASE_EXPIRED'
        : job.status === 'cancelled'
          ? 'CANCELLED'
          : 'FAILED';
  return {
    code,
    message: typeof e.message === 'string' ? e.message.slice(0, 1000) : `job ${job.status}`,
    ...(e.details !== undefined ? { details: boundJson(e.details, 16_384) } : {}),
  };
}

export function targetsOf(row: { targets: unknown }): BackupPolicyTarget[] {
  return Array.isArray(row.targets) ? (row.targets as BackupPolicyTarget[]) : [];
}
export function snapshotsOf(row: { snapshots: unknown }): BackupSnapshotRef[] {
  return Array.isArray(row.snapshots) ? (row.snapshots as BackupSnapshotRef[]) : [];
}
export function manifestOf(row: { manifest: unknown }): BackupManifestEntry[] {
  return Array.isArray(row.manifest) ? (row.manifest as BackupManifestEntry[]) : [];
}

/** Restore target used by a restore test (isolated: staging dir / new volume / scratch DB). */
export function isolatedRestoreTarget(t: BackupPolicyTarget): Record<string, unknown> {
  if (t.type === 'paths') return { type: 'paths', include: [], mode: 'staging' };
  if (t.type === 'volume') return { type: 'volume', app: t.app, volume: t.volume, mode: 'staging' };
  return {
    type: t.type,
    app: t.app,
    service: t.service,
    database: t.database,
    user: t.user,
    passwordSecretKey: t.passwordSecretKey,
    mode: 'scratch',
  };
}

interface VerifyResultEntry {
  jobId: string;
  snapshotId: string;
  target: number;
  status: 'running' | 'succeeded' | 'failed' | 'expired' | 'cancelled';
  ok: boolean | null;
  result?: unknown;
  error?: unknown;
}

/**
 * §10.3 runs, manifests and verification. `uploaded` only when the agent reported a snapshot for
 * EVERY target; a failed / partial (BACKUP_PARTIAL) / expired job is never `uploaded` (P6-T04).
 * `restore_verified` only after an isolated restore compared OK.
 */
@Injectable()
export class BackupRunsService implements OnModuleInit {
  private readonly listeners: RunFinishedListener[] = [];

  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly creds: BackupCredentialsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    this.hooks.register('backup.run', (j) => this.onBackupJob(j));
    this.hooks.register('backup.verify', (j) => this.onVerifyJob(j));
    this.hooks.register('restore.run', (j) => this.onVerifyJob(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  /** Restores listen for their safety runs. */
  onRunFinished(fn: RunFinishedListener): void {
    this.listeners.push(fn);
  }

  // ---------------------------------------------------------------- dispatch

  /** Preflight shared by runs, verifications and restores (409 REPO_ACCESS_MISSING / REPO_NOT_INITIALIZED). */
  async repoRef(repositoryId: string, serverId: string) {
    const access = await this.creds.access(repositoryId, serverId);
    if (!access)
      throw AppError.conflict(
        'This server has no access configured in the backup repository',
        ERROR_CODES.REPO_ACCESS_MISSING,
        { repositoryId, serverId },
      );
    if (!access.initializedAt)
      throw AppError.conflict(
        'The repository is not initialised for this server (operator: scripts/backup/maintenance.sh init, then mark it initialised)',
        ERROR_CODES.REPO_NOT_INITIALIZED,
        { repositoryId, serverId, restUser: access.restUser },
      );
    return { url: repoUrl(access.repository.baseUrl, access.restUser), repositoryId };
  }

  /**
   * Creates a run + its `backup.run` job (one active run per policy: partial unique index →
   * BACKUP_IN_PROGRESS). Returns `{ created: false }` for an idempotent replay.
   */
  async startRun(input: {
    policy: PolicyRow;
    trigger: BackupRunTrigger;
    actorId: string | null;
    idempotencyKey?: string;
    scheduledFor?: Date;
    targets?: BackupPolicyTarget[];
    restoreId?: string;
    tx?: Tx;
  }): Promise<{ run: RunRow; created: boolean }> {
    const { policy } = input;
    if (input.idempotencyKey !== undefined) {
      if (!IDEMPOTENCY_KEY_RE.test(input.idempotencyKey))
        throw AppError.badRequest('Idempotency-Key must be 8-128 chars of [A-Za-z0-9_.:-]');
      const existing = await this.prisma.backupRun.findUnique({
        where: {
          policyId_idempotencyKey: { policyId: policy.id, idempotencyKey: input.idempotencyKey },
        },
      });
      if (existing) return { run: existing, created: false };
    }
    const server = await this.prisma.server.findUniqueOrThrow({ where: { id: policy.serverId } });
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const repo = await this.repoRef(policy.repositoryId, policy.serverId);
    const targets = input.targets ?? targetsOf(policy);
    const id = uuidv7();
    const work = async (tx: Tx) => {
      await tx.backupRun.create({
        data: {
          id,
          policyId: policy.id,
          serverId: policy.serverId,
          repositoryId: policy.repositoryId,
          trigger: input.trigger,
          status: 'queued',
          targets: targets as unknown as Prisma.InputJsonValue,
          idempotencyKey: input.idempotencyKey ?? null,
          scheduledFor: input.scheduledFor ?? null,
          restoreId: input.restoreId ?? null,
          createdBy: input.actorId,
        },
      });
      const job = await this.jobs.createInternal(tx, {
        serverId: policy.serverId,
        type: 'backup.run',
        params: {
          runId: id,
          policyId: policy.id,
          repo,
          targets: targets.map(jobTarget),
          tags: [`trigger=${input.trigger}`],
          ...(policy.helperImage ? { helperImage: policy.helperImage } : {}),
          limits: { timeoutSec: Math.min(this.config.PPANEL_BACKUP_JOB_TTL_SEC, 86_400) },
        },
        actorId: input.actorId,
        ttlSec: this.config.PPANEL_BACKUP_JOB_TTL_SEC,
        metadata: { backupRunId: id, policyId: policy.id, trigger: input.trigger },
      });
      const run = await tx.backupRun.update({ where: { id }, data: { jobId: job.id } });
      await this.audit.record(
        {
          actorId: input.actorId,
          ...(input.actorId ? {} : { actorType: 'system' as const }),
          action: 'backup_runs.create',
          targetType: 'backup_run',
          targetId: id,
          result: 'success',
          metadata: {
            policyId: policy.id,
            serverId: policy.serverId,
            trigger: input.trigger,
            jobId: job.id,
            targets: targets.length,
            ...(input.restoreId ? { restoreId: input.restoreId } : {}),
            ...(input.scheduledFor ? { scheduledFor: input.scheduledFor.toISOString() } : {}),
          },
        },
        tx,
      );
      return run;
    };
    try {
      const run = input.tx ? await work(input.tx) : await this.prisma.$transaction(work);
      if (!input.tx) this.jobs.notify(policy.serverId);
      return { run, created: true };
    } catch (e) {
      if (!isUniqueViolation(e)) throw e;
      if (input.idempotencyKey) {
        const raced = await this.prisma.backupRun.findUnique({
          where: {
            policyId_idempotencyKey: { policyId: policy.id, idempotencyKey: input.idempotencyKey },
          },
        });
        if (raced) return { run: raced, created: false };
      }
      const active = await this.prisma.backupRun.findFirst({
        where: { policyId: policy.id, status: { in: [...BACKUP_RUN_ACTIVE_STATUSES] } },
        select: { id: true },
      });
      throw AppError.conflict(
        'A run of this policy is already queued or running',
        ERROR_CODES.BACKUP_IN_PROGRESS,
        { runId: active?.id ?? null },
      );
    }
  }

  // ---------------------------------------------------------------- completion

  private async onBackupJob(job: FinishedJob): Promise<void> {
    const run = await this.prisma.backupRun.findUnique({ where: { jobId: job.id } });
    if (!run || TERMINAL_RUN.includes(run.status as BackupRunStatus)) return;
    const now = new Date();
    const targets = targetsOf(run);
    let data: Prisma.BackupRunUpdateInput;
    if (job.status === 'succeeded') {
      const mapped = mapSnapshots(targets, job.result);
      if (!mapped) {
        data = {
          status: 'failed',
          error: {
            code: 'BACKUP_PARTIAL',
            message:
              'The agent reported success without a snapshot for every target — treated as a failure',
            details: boundJson(job.result, 16_384) as Prisma.InputJsonValue,
          },
        };
      } else {
        const m = boundManifest(mapped.manifest, mapped.truncated);
        data = {
          status: 'uploaded',
          snapshots: mapped.snapshots as unknown as Prisma.InputJsonValue,
          manifest: m.entries as unknown as Prisma.InputJsonValue,
          manifestSummary: m.summary as unknown as Prisma.InputJsonValue,
          resticVersion: mapped.resticVersion,
          error: m.invalid
            ? { code: 'MANIFEST_ENTRIES_INVALID', message: `${m.invalid} manifest entries dropped` }
            : undefined,
        };
      }
    } else {
      data = {
        status:
          job.status === 'expired'
            ? 'expired'
            : job.status === 'cancelled'
              ? 'cancelled'
              : 'failed',
        error: jobErr(job) as Prisma.InputJsonValue,
      };
    }
    const jobRow = await this.prisma.job.findUnique({
      where: { id: job.id },
      select: { startedAt: true },
    });
    const r = await this.prisma.backupRun.updateMany({
      where: { id: run.id, status: { in: [...BACKUP_RUN_ACTIVE_STATUSES] } },
      data: {
        ...(data as Prisma.BackupRunUpdateManyMutationInput),
        finishedAt: now,
        startedAt: run.startedAt ?? jobRow?.startedAt ?? null,
      },
    });
    if (r.count !== 1) return;
    const fresh = await this.prisma.backupRun.findUniqueOrThrow({ where: { id: run.id } });
    await this.audit.record({
      actorType: 'system',
      action: 'backup_runs.finished',
      targetType: 'backup_run',
      targetId: run.id,
      result: fresh.status === 'uploaded' ? 'success' : 'failure',
      metadata: {
        policyId: run.policyId,
        status: fresh.status,
        jobId: job.id,
        jobStatus: job.status,
        ...(fresh.error ? { errorCode: (fresh.error as { code?: string }).code } : {}),
        snapshots: snapshotsOf(fresh).map((s) => s.shortId),
      },
    });
    for (const l of this.listeners) {
      try {
        await l(fresh);
      } catch (err) {
        logger.emit('error', 'backup run listener failed', { runId: run.id, err });
      }
    }
    if (fresh.status === 'uploaded' && fresh.trigger !== 'safety') {
      const policy = await this.prisma.backupPolicy.findUnique({ where: { id: run.policyId } });
      const after = (policy?.verify as { afterBackup?: string } | null)?.afterBackup ?? 'none';
      if (after === 'check' || after === 'restore_test') {
        try {
          await this.startVerification(fresh, after, null);
        } catch (err) {
          logger.emit('warn', 'post-backup verification not started', { runId: run.id, err });
        }
      }
    }
  }

  // ---------------------------------------------------------------- verification

  /** Creates one verification (one job per snapshot). check → backup.verify; restore_test → restore.run isolated. */
  async startVerification(
    run: RunRow,
    level: BackupVerifyLevel,
    actorId: string | null,
  ): Promise<VerificationRow> {
    if (run.status !== 'uploaded')
      throw AppError.conflict(`Run is ${run.status}`, ERROR_CODES.RUN_NOT_UPLOADED, {
        status: run.status,
      });
    const repo = await this.repoRef(run.repositoryId, run.serverId);
    const policy = await this.prisma.backupPolicy.findUniqueOrThrow({
      where: { id: run.policyId },
    });
    const targets = targetsOf(run);
    const manifest = manifestOf(run);
    const snaps = snapshotsOf(run);
    const id = uuidv7();
    try {
      const v = await this.prisma.$transaction(async (tx) => {
        await tx.backupVerification.create({
          data: { id, runId: run.id, level, status: 'running', createdBy: actorId },
        });
        const entries: VerifyResultEntry[] = [];
        for (const s of snaps) {
          const m = manifestFor(manifest, targets, s.target, s.snapshotId);
          const job =
            level === 'check'
              ? await this.jobs.createInternal(tx, {
                  serverId: run.serverId,
                  type: 'backup.verify',
                  params: {
                    repo,
                    snapshotId: s.snapshotId,
                    readDataSubsetPct: 5,
                    ...(m.length ? { manifest: m } : {}),
                  },
                  actorId,
                  ttlSec: this.config.PPANEL_BACKUP_JOB_TTL_SEC,
                  metadata: { backupRunId: run.id, verificationId: id, level },
                })
              : await this.jobs.createInternal(tx, {
                  serverId: run.serverId,
                  type: 'restore.run',
                  params: {
                    restoreId: uuidv7(),
                    repo,
                    snapshotId: s.snapshotId,
                    target: isolatedRestoreTarget(targets[s.target]!),
                    dryRun: false,
                    verify: true,
                    ...(m.length ? { manifest: m } : {}),
                    ...(policy.helperImage ? { helperImage: policy.helperImage } : {}),
                    timeoutSec: Math.min(this.config.PPANEL_BACKUP_JOB_TTL_SEC, 86_400),
                  },
                  actorId,
                  ttlSec: this.config.PPANEL_BACKUP_JOB_TTL_SEC,
                  metadata: { backupRunId: run.id, verificationId: id, level },
                });
          entries.push({
            jobId: job.id,
            snapshotId: s.snapshotId,
            target: s.target,
            status: 'running',
            ok: null,
          });
        }
        const row = await tx.backupVerification.update({
          where: { id },
          data: {
            jobIds: entries.map((e) => e.jobId),
            results: entries as unknown as Prisma.InputJsonValue,
          },
        });
        await this.audit.record(
          {
            actorId,
            ...(actorId ? {} : { actorType: 'system' as const }),
            action: 'backup_runs.verify',
            targetType: 'backup_run',
            targetId: run.id,
            result: 'success',
            metadata: { verificationId: id, level, jobIds: entries.map((e) => e.jobId) },
          },
          tx,
        );
        return row;
      });
      this.jobs.notify(run.serverId);
      return v;
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'A verification of this run is already running',
          ERROR_CODES.VERIFY_IN_PROGRESS,
        );
      throw e;
    }
  }

  private entryOk(
    level: string,
    job: FinishedJob,
  ): { ok: boolean; result?: unknown; error?: unknown } {
    if (job.status !== 'succeeded') return { ok: false, error: jobErr(job) };
    if (level === 'check') {
      const p = backupVerifyResultSchema.safeParse(job.result);
      if (!p.success)
        return {
          ok: false,
          error: { code: 'VERIFY_RESULT_INVALID', message: 'unparseable backup.verify result' },
        };
      return {
        ok: p.data.repoCheckOk && p.data.mismatches.length === 0,
        result: boundJson(p.data, 16_384),
      };
    }
    const p = restoreRunResultSchema.safeParse(job.result);
    if (!p.success || !p.data.verify)
      return {
        ok: false,
        error: {
          code: 'VERIFY_RESULT_INVALID',
          message: 'restore.run result has no verify section',
        },
      };
    // an isolated restore that compared zero items proves nothing
    const ok =
      p.data.verify.ok && p.data.verify.mismatches.length === 0 && p.data.verify.compared > 0;
    return { ok, result: boundJson(p.data, 16_384) };
  }

  private async onVerifyJob(job: FinishedJob): Promise<void> {
    const v = await this.prisma.backupVerification.findFirst({
      where: { jobIds: { has: job.id } },
    });
    if (!v || v.status !== 'running') return;
    const outcome = this.entryOk(v.level, job);
    const finished = await this.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM backup_verifications WHERE id = ${v.id}::uuid FOR UPDATE`;
      const cur = await tx.backupVerification.findUniqueOrThrow({ where: { id: v.id } });
      if (cur.status !== 'running') return null;
      const entries = (cur.results as unknown as VerifyResultEntry[]).map((e) =>
        e.jobId === job.id && e.status === 'running'
          ? { ...e, status: job.status as VerifyResultEntry['status'], ...outcome }
          : e,
      );
      const done = entries.every((e) => e.status !== 'running');
      const passed = done && entries.every((e) => e.ok === true);
      const firstErr = entries.find((e) => e.ok === false);
      await tx.backupVerification.update({
        where: { id: v.id },
        data: {
          results: entries as unknown as Prisma.InputJsonValue,
          ...(done
            ? {
                status: passed ? 'passed' : 'failed',
                finishedAt: new Date(),
                error: passed
                  ? undefined
                  : ((firstErr?.error as Prisma.InputJsonValue | undefined) ?? {
                      code: 'VERIFY_FAILED',
                      message: 'Verification found mismatches',
                    }),
              }
            : {}),
        },
      });
      if (!done) return null;
      const run = await tx.backupRun.findUniqueOrThrow({ where: { id: v.runId } });
      const level: BackupVerification = !passed
        ? 'verify_failed'
        : v.level === 'restore_test'
          ? 'restore_verified'
          : run.verification === 'restore_verified'
            ? 'restore_verified' // a passed repo check never downgrades a proven restore
            : 'repository_checked';
      await tx.backupRun.update({
        where: { id: run.id },
        data: { verification: level, verifiedAt: new Date() },
      });
      if (passed && v.level === 'restore_test')
        await tx.backupPolicy.update({
          where: { id: run.policyId },
          data: { lastRestoreTestAt: new Date() },
        });
      await this.audit.record(
        {
          actorType: 'system',
          action: 'backup_runs.verified',
          targetType: 'backup_run',
          targetId: run.id,
          result: passed ? 'success' : 'failure',
          metadata: { verificationId: v.id, level: v.level, verification: level },
        },
        tx,
      );
      return level;
    });
    if (finished)
      logger.emit('info', 'backup verification finished', { verificationId: v.id, finished });
  }

  /** Repairs runs/verifications whose job finished while hooks did not run (sweeper expiry, restart). */
  async reconcile(): Promise<void> {
    const active = await this.prisma.backupRun.findMany({
      where: { status: { in: [...BACKUP_RUN_ACTIVE_STATUSES] }, jobId: { not: null } },
      take: 200,
    });
    for (const run of active) {
      const job = await this.prisma.job.findUnique({ where: { id: run.jobId! } });
      if (!job) continue;
      if (this.jobs.isTerminal(job.status)) await this.onBackupJob(job);
      else if (job.status === 'running' && run.status === 'queued')
        await this.prisma.backupRun.updateMany({
          where: { id: run.id, status: 'queued' },
          data: { status: 'running', startedAt: job.startedAt ?? new Date() },
        });
    }
    const verifs = await this.prisma.backupVerification.findMany({
      where: { status: 'running' },
      take: 200,
    });
    for (const v of verifs) {
      const jobs = await this.prisma.job.findMany({ where: { id: { in: v.jobIds } } });
      const entries = v.results as unknown as VerifyResultEntry[];
      for (const j of jobs)
        if (
          this.jobs.isTerminal(j.status) &&
          entries.find((e) => e.jobId === j.id)?.status === 'running'
        )
          await this.onVerifyJob(j);
    }
  }

  // ---------------------------------------------------------------- views

  private allowedActions(
    user: AuthUser,
    r: RunRow,
    server: { id: string; environment: string; status: string },
  ): BackupRunAction[] {
    if (r.status !== 'uploaded' || server.status === 'revoked') return [];
    const scope = serverScope(server);
    const out: BackupRunAction[] = [];
    if (this.authz.can(user, 'backups.create', scope))
      out.push('verify_check', 'verify_restore_test');
    if (this.authz.can(user, 'backups.restore', scope)) out.push('restore');
    return out;
  }

  toView(
    user: AuthUser,
    r: RunRow,
    ctx: { policyName: string; server: { id: string; environment: string; status: string } },
  ): BackupRunView {
    const summary = (r.manifestSummary ?? {}) as Partial<BackupRunView['manifest']>;
    return {
      id: r.id,
      policyId: r.policyId,
      policyName: ctx.policyName,
      serverId: r.serverId,
      repositoryId: r.repositoryId,
      trigger: r.trigger as BackupRunTrigger,
      status: r.status as BackupRunStatus,
      verification: r.verification as BackupVerification,
      verifiedAt: r.verifiedAt?.toISOString() ?? null,
      targets: targetsOf(r),
      snapshots: snapshotsOf(r),
      manifest: {
        files: summary.files ?? 0,
        bytes: summary.bytes ?? 0,
        databases: summary.databases ?? 0,
        truncated: summary.truncated ?? false,
      },
      error: (r.error as BackupRunView['error']) ?? null,
      scheduledFor: r.scheduledFor?.toISOString() ?? null,
      startedAt: r.startedAt?.toISOString() ?? null,
      finishedAt: r.finishedAt?.toISOString() ?? null,
      jobId: r.jobId,
      resticVersion: r.resticVersion,
      restoreId: r.restoreId,
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
      allowedActions: this.allowedActions(user, r, ctx.server),
    };
  }

  private async ctxFor(runs: RunRow[]) {
    const policies = await this.prisma.backupPolicy.findMany({
      where: { id: { in: [...new Set(runs.map((r) => r.policyId))] } },
      select: { id: true, name: true },
    });
    const servers = await this.prisma.server.findMany({
      where: { id: { in: [...new Set(runs.map((r) => r.serverId))] } },
      select: { id: true, environment: true, status: true },
    });
    const pn = new Map(policies.map((p) => [p.id, p.name]));
    const sv = new Map(servers.map((s) => [s.id, s]));
    return (r: RunRow) => ({ policyName: pn.get(r.policyId) ?? '', server: sv.get(r.serverId)! });
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) return new Paginated([], paginate(pq, 0));
    const where: Prisma.BackupRunWhereInput = {
      AND: [
        {
          serverId: {
            in: (await this.prisma.server.findMany({ where: visible, select: { id: true } })).map(
              (s) => s.id,
            ),
          },
        },
        buildWhere(pq, {
          policy_id: { prop: 'policyId', type: 'uuid' },
          server_id: { prop: 'serverId', type: 'uuid' },
          status: { prop: 'status', type: 'string' },
          verification: { prop: 'verification', type: 'string' },
          trigger: { prop: 'trigger', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }) as Prisma.BackupRunWhereInput,
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.backupRun.count({ where }),
      this.prisma.backupRun.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    const ctx = await this.ctxFor(rows);
    return new Paginated(
      rows.map((r) => this.toView(user, r, ctx(r))),
      paginate(pq, total),
    );
  }

  /** Visible run (404 outside the user's scope). */
  async load(
    user: AuthUser,
    id: string,
  ): Promise<{
    run: RunRow;
    server: { id: string; environment: string; status: string; name: string };
  }> {
    const run = await this.prisma.backupRun.findUnique({ where: { id } });
    const server = run
      ? await this.prisma.server.findUnique({
          where: { id: run.serverId },
          select: { id: true, environment: true, status: true, name: true },
        })
      : null;
    if (!run || !server || !this.authz.can(user, 'fleet.read', serverScope(server)))
      throw AppError.notFound('Backup run');
    return { run, server };
  }

  async get(
    user: AuthUser,
    id: string,
    manifestPage = 1,
    manifestLimit = 100,
  ): Promise<BackupRunDetail> {
    let { run } = await this.load(user, id);
    if (run.jobId && BACKUP_RUN_ACTIVE_STATUSES.includes(run.status as BackupRunStatus)) {
      await this.reconcileRun(run);
      ({ run } = await this.load(user, id));
    }
    const ctx = await this.ctxFor([run]);
    const all = manifestRows(manifestOf(run));
    const verifs = await this.prisma.backupVerification.findMany({
      where: { runId: run.id },
      orderBy: { createdAt: 'desc' },
      take: 20,
    });
    return {
      ...this.toView(user, run, ctx(run)),
      manifestEntries: all.slice((manifestPage - 1) * manifestLimit, manifestPage * manifestLimit),
      manifestPaginate: { page: manifestPage, limit: manifestLimit, total: all.length },
      verifications: verifs.map((v) => this.verificationView(v)),
    };
  }

  private async reconcileRun(run: RunRow): Promise<void> {
    const job = await this.prisma.job.findUnique({ where: { id: run.jobId! } });
    if (!job) return;
    if (this.jobs.isTerminal(job.status)) await this.onBackupJob(job);
    else if (job.status === 'running' && run.status === 'queued')
      await this.prisma.backupRun.updateMany({
        where: { id: run.id, status: 'queued' },
        data: { status: 'running', startedAt: job.startedAt ?? new Date() },
      });
  }

  verificationView(v: VerificationRow): BackupVerificationView {
    return {
      id: v.id,
      level: v.level as BackupVerifyLevel,
      status: v.status as BackupVerificationView['status'],
      jobIds: v.jobIds,
      result: { entries: v.results },
      error: (v.error as BackupVerificationView['error']) ?? null,
      createdBy: v.createdBy,
      createdAt: v.createdAt.toISOString(),
      finishedAt: v.finishedAt?.toISOString() ?? null,
    };
  }

  async verify(
    user: AuthUser,
    id: string,
    level: BackupVerifyLevel,
  ): Promise<{ verification: BackupVerificationView; run: BackupRunView }> {
    const { run, server } = await this.load(user, id);
    await this.authz.enforce(user, 'backups.create', serverScope(server), {
      action: 'backup_runs.verify',
      targetType: 'backup_run',
      targetId: id,
    });
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const v = await this.startVerification(run, level, user.id);
    const fresh = await this.prisma.backupRun.findUniqueOrThrow({ where: { id } });
    const ctx = await this.ctxFor([fresh]);
    return { verification: this.verificationView(v), run: this.toView(user, fresh, ctx(fresh)) };
  }

  // ---------------------------------------------------------------- live snapshots (read-only)

  async snapshots(
    user: AuthUser,
    serverId: string,
    repositoryId: string | undefined,
    tag: string | undefined,
  ): Promise<{ pending: boolean; body: ServerSnapshots }> {
    const server = await this.prisma.server.findUnique({ where: { id: serverId } });
    if (!server || !this.authz.can(user, 'fleet.read', serverScope(server)))
      throw AppError.notFound('Server');
    await this.authz.enforce(user, 'backups.create', serverScope(server), {
      action: 'backup_snapshots.list',
      targetType: 'server',
      targetId: serverId,
    });
    let repoId = repositoryId;
    if (!repoId) {
      const rows = await this.prisma.backupRepoAccess.findMany({
        where: { serverId },
        select: { repositoryId: true },
      });
      if (rows.length !== 1)
        throw AppError.badRequest(
          rows.length === 0
            ? 'This server has no backup repository access'
            : 'repository_id is required (the server has several repositories)',
        );
      repoId = rows[0]!.repositoryId;
    }
    const repo = await this.repoRef(repoId, serverId);
    const job = await this.prisma.$transaction((tx) =>
      this.jobs.createInternal(tx, {
        serverId,
        type: 'backup.snapshots',
        params: { repo, ...(tag ? { tag } : {}) },
        actorId: user.id,
        ttlSec: 300,
        metadata: { repositoryId: repoId },
      }),
    );
    this.jobs.notify(serverId);
    const deadline = Date.now() + this.config.PPANEL_NGINX_READ_WAIT_MS;
    let j = job;
    while (!this.jobs.isTerminal(j.status) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
      j = await this.prisma.job.findUniqueOrThrow({ where: { id: job.id } });
    }
    if (!this.jobs.isTerminal(j.status))
      return {
        pending: true,
        body: { repositoryId: repoId, jobId: job.id, pending: true, snapshots: [] },
      };
    if (j.status !== 'succeeded') {
      const e = jobErr(j);
      throw new AppError(502, e.code, e.message);
    }
    const raw = ((j.result as { snapshots?: unknown[] } | null)?.snapshots ?? []).slice(0, 1000);
    return {
      pending: false,
      body: {
        repositoryId: repoId,
        jobId: job.id,
        pending: false,
        snapshots: raw.map((s) => {
          const o = (s ?? {}) as Record<string, unknown>;
          const str = (v: unknown) => (typeof v === 'string' ? v : null);
          return {
            id: String(o.id ?? ''),
            shortId: str(o.shortId) ?? str(o.short_id),
            time: str(o.time),
            tags: Array.isArray(o.tags) ? o.tags.map(String) : [],
            paths: Array.isArray(o.paths) ? o.paths.map(String) : [],
            hostname: str(o.hostname),
            sizeBytes: typeof o.sizeBytes === 'number' ? o.sizeBytes : null,
          };
        }),
      },
    };
  }
}
