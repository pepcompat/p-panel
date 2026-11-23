import { planServices } from './backup-policies.service';
import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  type CreateRestoreInput,
  ERROR_CODES,
  RESTORE_CANCELLABLE,
  type Restore as RestoreView,
  type RestoreAction,
  type RestoreImpactItem,
  restoreRunResultSchema,
  type RestoreStatus,
  type RestoreStepName,
} from '@ppanel/shared-contracts';
import type {
  BackupRun as RunRow,
  OperationApproval,
  Prisma,
  Restore as RestoreRow,
  RestoreStepRow,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ComposeAppsService } from '../deploy/compose-apps.service';
import { healthcheckOf } from '../deploy/container-common';
import { serverScope } from '../discovery/p3-common';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import {
  approvalReasons,
  boundJson,
  computeImpact,
  manifestFor,
  pathViolation,
  restorePlanHash,
  type RestoreTarget,
  restoreTargetMismatch,
} from './backup-common';
import {
  BackupRunsService,
  jobErr,
  manifestOf,
  snapshotsOf,
  targetsOf,
} from './backup-runs.service';

const APPROVAL_TTL_MINUTES = 60;
const OP_TTL_SEC = 900;
const STEP_JOB_TYPES = ['restore.run', 'container.stop', 'container.start', 'compose.stop'];
const DEPLOYMENT_OK = ['succeeded'];
const DEPLOYMENT_BAD = [
  'failed',
  'rolled_back',
  'requires_manual_recovery',
  'cancelled',
  'expired',
  'awaiting_approval',
];

type ServerRef = { id: string; environment: string; status: string };

/**
 * §10.4 restores (P6-T03): plan + impact → dry-run → approval (in_place anywhere / any production
 * target: approver ≠ creator, approvals.decide, step-up, planHash-bound, single-use, 60 min) →
 * execute. in_place order: safety backup (must be `uploaded`) → stop app → restore.run in place with
 * verify → start app + healthcheck → verified | failed | requires_manual_recovery (safety snapshot
 * shown for manual rollback). Every transition is a CAS on Postgres rows driven by job hooks and the
 * sweeper's reconcile pass (durable across restarts). Everything is audited.
 */
@Injectable()
export class RestoresService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly runs: BackupRunsService,
    private readonly composeApps: ComposeAppsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    for (const t of STEP_JOB_TYPES) this.hooks.register(t, (j) => this.onJob(j));
    this.runs.onRunFinished((r) => this.onSafetyRun(r));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  // ---------------------------------------------------------------- views

  private target(r: RestoreRow): RestoreTarget {
    return r.target as unknown as RestoreTarget;
  }

  private allowedActions(user: AuthUser, r: RestoreRow, server: ServerRef): RestoreAction[] {
    if (server.status === 'revoked') return [];
    const scope = serverScope(server);
    const canRestore = this.authz.can(user, 'backups.restore', scope);
    const out: RestoreAction[] = [];
    if (canRestore && (r.status === 'planned' || r.status === 'impact_reviewed'))
      out.push('dry_run');
    if (
      r.status === 'awaiting_approval' &&
      r.createdBy !== user.id &&
      this.authz.can(user, 'approvals.decide', scope)
    )
      out.push('approve');
    if (
      canRestore &&
      ((r.approvalRequired && r.status === 'approved') ||
        (!r.approvalRequired && r.status === 'impact_reviewed'))
    )
      out.push('execute');
    if (canRestore && RESTORE_CANCELLABLE.includes(r.status as RestoreStatus)) out.push('cancel');
    return out;
  }

  private async toView(
    user: AuthUser,
    r: RestoreRow & { steps: RestoreStepRow[] },
    server: ServerRef,
  ): Promise<RestoreView> {
    const approvals = await this.prisma.operationApproval.findMany({
      where: { subjectType: 'restore', subjectId: r.id, invalidatedAt: null },
      orderBy: { approvedAt: 'desc' },
      take: 1,
    });
    const a: OperationApproval | undefined = approvals[0];
    const safety = r.safetySnapshotRunId
      ? await this.prisma.backupRun.findUnique({ where: { id: r.safetySnapshotRunId } })
      : null;
    const dry = (r.dryRun ?? null) as RestoreView['plan']['dryRun'];
    return {
      id: r.id,
      runId: r.runId,
      snapshotId: r.snapshotId,
      serverId: r.serverId,
      applicationId: r.applicationId,
      target: this.target(r),
      status: r.status as RestoreStatus,
      plan: { impact: r.impact as unknown as RestoreImpactItem[], dryRun: dry },
      planHash: r.planHash,
      approval: {
        required: r.approvalRequired,
        reasons: r.approvalReasons as RestoreView['approval']['reasons'],
        approvedBy: a?.approverId ?? null,
        approvedAt: a?.approvedAt.toISOString() ?? null,
        expiresAt: a?.expiresAt.toISOString() ?? null,
        usedAt: a?.usedAt?.toISOString() ?? null,
      },
      steps: [...r.steps]
        .sort((x, y) => x.seq - y.seq)
        .map((s) => ({
          name: s.name as RestoreStepName,
          status: s.status as RestoreView['steps'][number]['status'],
          jobId: s.jobId,
          backupRunId: s.backupRunId,
          deploymentId: s.deploymentId,
          startedAt: s.startedAt.toISOString(),
          finishedAt: s.finishedAt?.toISOString() ?? null,
          message: s.message,
          errorCode: s.errorCode,
        })),
      safetySnapshotRunId: r.safetySnapshotRunId,
      safetySnapshotIds: safety ? snapshotsOf(safety).map((s) => s.snapshotId) : [],
      result: (r.result as Record<string, unknown> | null) ?? null,
      error: (r.error as RestoreView['error']) ?? null,
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      finishedAt: r.finishedAt?.toISOString() ?? null,
      version: r.version,
      allowedActions: this.allowedActions(user, r, server),
    };
  }

  private async load(user: AuthUser, id: string) {
    const r = await this.prisma.restore.findUnique({ where: { id }, include: { steps: true } });
    const server = r
      ? await this.prisma.server.findUnique({
          where: { id: r.serverId },
          select: { id: true, environment: true, status: true },
        })
      : null;
    if (!r || !server || !this.authz.can(user, 'fleet.read', serverScope(server)))
      throw AppError.notFound('Restore');
    return { r, server };
  }

  async get(user: AuthUser, id: string): Promise<RestoreView> {
    let { r, server } = await this.load(user, id);
    if (r.status === 'running' || r.steps.some((s) => s.status === 'running')) {
      await this.reconcileOne(r.id);
      ({ r, server } = await this.load(user, id));
    }
    return this.toView(user, r, server);
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) return new Paginated([], paginate(pq, 0));
    const servers = await this.prisma.server.findMany({
      where: visible,
      select: { id: true, environment: true, status: true },
    });
    const byId = new Map(servers.map((s) => [s.id, s]));
    const where: Prisma.RestoreWhereInput = {
      AND: [
        { serverId: { in: [...byId.keys()] } },
        buildWhere(pq, {
          server_id: { prop: 'serverId', type: 'uuid' },
          run_id: { prop: 'runId', type: 'uuid' },
          status: { prop: 'status', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }) as Prisma.RestoreWhereInput,
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.restore.count({ where }),
      this.prisma.restore.findMany({
        where,
        include: { steps: true },
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(
      await Promise.all(rows.map((r) => this.toView(user, r, byId.get(r.serverId)!))),
      paginate(pq, total),
    );
  }

  private stateError(r: { status: string }, allowed: string[]) {
    return AppError.conflict(`Restore is ${r.status}`, ERROR_CODES.RESTORE_STATE_INVALID, {
      status: r.status,
      allowed,
    });
  }

  private async enforceRestore(
    user: AuthUser,
    server: ServerRef,
    action: string,
    id: string | null,
  ) {
    await this.authz.enforce(user, 'backups.restore', serverScope(server), {
      action,
      targetType: 'restore',
      targetId: id,
    });
  }

  // ---------------------------------------------------------------- 1. plan

  async create(user: AuthUser, input: CreateRestoreInput): Promise<RestoreView> {
    const { run, server } = await this.runs.load(user, input.runId);
    await this.enforceRestore(user, server, 'restores.create', null);
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (run.status !== 'uploaded')
      throw AppError.conflict(`Run is ${run.status}`, ERROR_CODES.RUN_NOT_UPLOADED, {
        status: run.status,
      });
    const snap = snapshotsOf(run).find(
      (s) => s.snapshotId === input.snapshotId || s.shortId === input.snapshotId,
    );
    if (!snap)
      throw new AppError(
        422,
        ERROR_CODES.SNAPSHOT_NOT_IN_RUN,
        'snapshotId is not a snapshot of this run',
        {
          snapshots: snapshotsOf(run).map((s) => s.snapshotId),
        },
      );
    const targets = targetsOf(run);
    const source = targets[snap.target]!;
    let target = input.target;
    const mismatch = restoreTargetMismatch(source, target);
    if (mismatch)
      throw new AppError(422, ERROR_CODES.RESTORE_TARGET_MISMATCH, mismatch, { source });
    if (target.type === 'paths')
      for (const p of target.include) {
        const v = pathViolation(p);
        if (v) throw new AppError(422, ERROR_CODES.PATH_NOT_ALLOWED, v, { path: p });
      }
    let applicationId: string | null = null;
    let appKind: string | null = null;
    if (target.type !== 'paths') {
      const app = await this.prisma.application.findUnique({
        where: { serverId_name: { serverId: run.serverId, name: target.app } },
        select: { id: true, kind: true },
      });
      if (!app)
        throw new AppError(
          422,
          ERROR_CODES.RESTORE_TARGET_MISMATCH,
          `application ${target.app} no longer exists`,
        );
      applicationId = app.id;
      appKind = app.kind;
      // Scratch DB restores default to the SOURCE service's own image: a dump made by a newer
      // server minor can contain settings an older server rejects (lab E2E: pg 16.16 → 16.10 failed).
      if (
        (target.type === 'postgres' || target.type === 'mysql') &&
        target.mode === 'scratch' &&
        !target.scratchImage
      ) {
        const image = await this.sourceServiceImage(app.id, target.service);
        if (!image)
          throw new AppError(
            422,
            ERROR_CODES.RESTORE_TARGET_MISMATCH,
            `cannot determine the image of service ${target.service}; pass target.scratchImage`,
          );
        target = { ...target, scratchImage: image };
      }
    }
    const id = uuidv7();
    const impact = computeImpact(source, target, {
      snapshotId: snap.snapshotId,
      restoreId: id,
      appKind,
      manifestFiles: manifestFor(manifestOf(run), targets, snap.target, snap.snapshotId).reduce(
        (n, e) => n + Math.max(e.fileCount, e.files?.length ?? 0),
        0,
      ),
    });
    const reasons = approvalReasons(target, server.environment);
    const planHash = restorePlanHash({
      runId: run.id,
      snapshotId: snap.snapshotId,
      serverId: run.serverId,
      target,
      impact,
    });
    await this.prisma.$transaction(async (tx) => {
      await tx.restore.create({
        data: {
          id,
          runId: run.id,
          snapshotId: snap.snapshotId,
          serverId: run.serverId,
          repositoryId: run.repositoryId,
          applicationId,
          target: target as unknown as Prisma.InputJsonValue,
          targetIndex: snap.target,
          status: 'planned',
          impact: impact as unknown as Prisma.InputJsonValue,
          planHash,
          approvalRequired: reasons.length > 0,
          approvalReasons: reasons,
          createdBy: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'restores.create',
          targetType: 'restore',
          targetId: id,
          result: 'success',
          diff: { planHash },
          metadata: {
            runId: run.id,
            snapshotId: snap.snapshotId,
            serverId: run.serverId,
            mode: target.mode,
            type: target.type,
            approvalRequired: reasons.length > 0,
            reasons,
            planHash,
          },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- 2. dry-run

  private async restoreParams(r: RestoreRow, dryRun: boolean) {
    const run = await this.prisma.backupRun.findUniqueOrThrow({ where: { id: r.runId } });
    const policy = await this.prisma.backupPolicy.findUniqueOrThrow({
      where: { id: run.policyId },
    });
    const repo = await this.runs.repoRef(r.repositoryId, r.serverId);
    const m = manifestFor(manifestOf(run), targetsOf(run), r.targetIndex, r.snapshotId);
    return {
      restoreId: r.id,
      repo,
      snapshotId: r.snapshotId,
      target: r.target as Record<string, unknown>,
      dryRun,
      verify: !dryRun,
      ...(!dryRun && m.length ? { manifest: m } : {}),
      ...(policy.helperImage ? { helperImage: policy.helperImage } : {}),
      timeoutSec: Math.min(this.config.PPANEL_BACKUP_JOB_TTL_SEC, 86_400),
    };
  }

  async dryRun(user: AuthUser, id: string): Promise<RestoreView> {
    const { r, server } = await this.load(user, id);
    await this.enforceRestore(user, server, 'restores.dry_run', id);
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (r.status !== 'planned' && r.status !== 'impact_reviewed')
      throw this.stateError(r, ['planned', 'impact_reviewed']);
    if (r.steps.some((s) => s.name === 'dry_run' && s.status === 'running'))
      throw AppError.conflict('A dry-run is already running', ERROR_CODES.RESTORE_STATE_INVALID);
    const params = await this.restoreParams(r, true);
    await this.prisma.$transaction(async (tx) => {
      const job = await this.jobs.createInternal(tx, {
        serverId: r.serverId,
        type: 'restore.run',
        params,
        actorId: user.id,
        ttlSec: this.config.PPANEL_BACKUP_JOB_TTL_SEC,
        metadata: { restoreId: id, dryRun: true },
      });
      await this.addStep(tx, id, 'dry_run', 'running', {
        jobId: job.id,
        message: 'restic restore --dry-run',
      });
      await tx.restore.update({
        where: { id },
        data: {
          status: 'planned',
          dryRun: { jobId: job.id, ok: null, listing: null, error: null },
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'restores.dry_run',
          targetType: 'restore',
          targetId: id,
          result: 'success',
          metadata: { jobId: job.id },
        },
        tx,
      );
    });
    this.jobs.notify(r.serverId);
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- 3. approval

  async approve(user: AuthUser, id: string, planHash: string, stepUp: string | undefined) {
    const { r, server } = await this.load(user, id);
    const audit = { action: 'restores.approve', targetType: 'restore', targetId: id };
    await this.authz.enforce(user, 'approvals.decide', serverScope(server), audit);
    if (r.createdBy === user.id) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason: 'approver_is_creator' },
      });
      throw AppError.forbidden(
        'The creator of a restore cannot approve it',
        ERROR_CODES.APPROVER_IS_CREATOR,
      );
    }
    try {
      this.auth.assertStepUp(user, stepUp);
    } catch (e) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason: 'step_up_required' },
      });
      throw e;
    }
    if (!r.approvalRequired)
      throw AppError.conflict(
        'This restore does not require approval',
        ERROR_CODES.APPROVAL_NOT_REQUIRED,
      );
    if (r.status !== 'awaiting_approval') throw this.stateError(r, ['awaiting_approval']);
    if (planHash !== r.planHash) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason: 'plan_hash_mismatch' },
      });
      throw AppError.conflict(
        'planHash does not match the current plan',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        {
          planHash: r.planHash,
        },
      );
    }
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const moved = await tx.restore.updateMany({
        where: { id, status: 'awaiting_approval', planHash },
        data: { status: 'approved', version: { increment: 1 } },
      });
      if (moved.count !== 1) throw this.stateError(r, ['awaiting_approval']);
      await tx.operationApproval.updateMany({
        where: { subjectType: 'restore', subjectId: id, usedAt: null, invalidatedAt: null },
        data: { invalidatedAt: now },
      });
      const approval = await tx.operationApproval.create({
        data: {
          id: uuidv7(),
          subjectType: 'restore',
          subjectId: id,
          approverId: user.id,
          planHash,
          approvedAt: now,
          expiresAt: new Date(now.getTime() + APPROVAL_TTL_MINUTES * 60_000),
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          ...audit,
          result: 'success',
          diff: { planHash },
          metadata: { planHash, approvalId: approval.id, reasons: r.approvalReasons },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- 4. execute

  async execute(user: AuthUser, id: string, confirmImpact = false): Promise<RestoreView> {
    const { r, server } = await this.load(user, id);
    const audit = { action: 'restores.execute', targetType: 'restore', targetId: id };
    await this.enforceRestore(user, server, 'restores.execute', id);
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const deny = async (reason: string, err: AppError) => {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason, status: r.status, approvalReasons: r.approvalReasons },
      });
      return err;
    };
    const now = new Date();
    let approval: OperationApproval | null = null;
    if (!['planned', 'impact_reviewed', 'awaiting_approval', 'approved'].includes(r.status))
      throw await deny(
        'state_invalid',
        this.stateError(r, r.approvalRequired ? ['approved'] : ['impact_reviewed']),
      );
    // D4-B: destructive (in_place) restores need an explicit impact confirmation on execute.
    if ((r.target as { mode?: string }).mode === 'in_place' && !confirmImpact)
      throw await deny(
        'impact_not_confirmed',
        new AppError(
          422,
          ERROR_CODES.IMPACT_CONFIRMATION_REQUIRED,
          'In-place restore overwrites live data: confirm the impact (confirmImpact: true) to execute',
          { impact: r.impact },
        ),
      );
    if (r.approvalRequired) {
      if (r.status !== 'approved')
        throw await deny(
          'approval_required',
          AppError.conflict(
            `This restore requires an approval (${r.approvalReasons.join(', ')}) before execution`,
            ERROR_CODES.APPROVAL_REQUIRED,
            { status: r.status, reasons: r.approvalReasons },
          ),
        );
      approval = await this.prisma.operationApproval.findFirst({
        where: { subjectType: 'restore', subjectId: id, usedAt: null, invalidatedAt: null },
        orderBy: { approvedAt: 'desc' },
      });
      if (!approval || approval.planHash !== r.planHash)
        throw await deny(
          'approval_missing',
          AppError.conflict('No valid approval', ERROR_CODES.APPROVAL_REQUIRED),
        );
      if (approval.expiresAt <= now) {
        await this.prisma.$transaction(async (tx) => {
          await tx.operationApproval.update({
            where: { id: approval!.id },
            data: { invalidatedAt: now },
          });
          await tx.restore.updateMany({
            where: { id, status: 'approved' },
            data: { status: 'awaiting_approval' },
          });
        });
        throw await deny(
          'approval_expired',
          AppError.conflict('The approval expired; approve again', ERROR_CODES.APPROVAL_EXPIRED),
        );
      }
    } else if (r.status !== 'impact_reviewed') {
      throw await deny(
        'dry_run_required',
        r.status === 'planned'
          ? AppError.conflict('Run the dry-run first', ERROR_CODES.RESTORE_STATE_INVALID, {
              status: r.status,
            })
          : this.stateError(r, ['impact_reviewed']),
      );
    }
    const target = this.target(r);
    const inPlace = target.mode === 'in_place';
    const run = await this.prisma.backupRun.findUniqueOrThrow({ where: { id: r.runId } });
    const policy = await this.prisma.backupPolicy.findUniqueOrThrow({
      where: { id: run.policyId },
    });
    await this.runs.repoRef(r.repositoryId, r.serverId); // preflight: access + initialised
    const restoreParams = inPlace ? null : await this.restoreParams(r, false);
    let safetyRunId: string | null = null;
    try {
      await this.prisma.$transaction(async (tx) => {
        const moved = await tx.restore.updateMany({
          where: { id, status: r.status, version: r.version },
          data: { status: 'running', version: { increment: 1 } },
        });
        if (moved.count !== 1) throw this.stateError(r, [r.status]);
        if (approval) {
          const used = await tx.operationApproval.updateMany({
            where: {
              id: approval.id,
              usedAt: null,
              invalidatedAt: null,
              planHash: r.planHash,
              expiresAt: { gt: now },
            },
            data: { usedAt: now },
          });
          if (used.count !== 1)
            throw AppError.conflict('Approval is no longer valid', ERROR_CODES.APPROVAL_REQUIRED);
        }
        if (inPlace) {
          // (a) safety backup of the current state of the same target — must be `uploaded`
          const targets = targetsOf(run);
          const { run: safety } = await this.runs.startRun({
            policy,
            trigger: 'safety',
            actorId: user.id,
            targets: [targets[r.targetIndex]!],
            restoreId: id,
            tx,
          });
          safetyRunId = safety.id;
          await tx.restore.update({ where: { id }, data: { safetySnapshotRunId: safety.id } });
          await this.addStep(tx, id, 'safety_backup', 'running', {
            jobId: safety.jobId,
            backupRunId: safety.id,
            message: 'Safety backup of the current state before overwriting',
          });
        } else {
          const job = await this.jobs.createInternal(tx, {
            serverId: r.serverId,
            type: 'restore.run',
            params: restoreParams!,
            actorId: user.id,
            ttlSec: this.config.PPANEL_BACKUP_JOB_TTL_SEC,
            metadata: { restoreId: id },
          });
          await this.addStep(tx, id, 'restore', 'running', {
            jobId: job.id,
            message: `Restore into an isolated ${target.mode} target with verification`,
          });
        }
        await this.audit.record(
          {
            actorId: user.id,
            ...audit,
            result: 'success',
            diff: { planHash: r.planHash },
            metadata: {
              planHash: r.planHash,
              mode: target.mode,
              approvalId: approval?.id ?? null,
              approvedBy: approval?.approverId ?? null,
              safetyRunId,
            },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'Another restore is running on this server, or a backup of this policy is active',
          ERROR_CODES.BACKUP_IN_PROGRESS,
        );
      throw e;
    }
    this.jobs.notify(r.serverId);
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- cancel

  async cancel(user: AuthUser, id: string): Promise<RestoreView> {
    const { r, server } = await this.load(user, id);
    await this.enforceRestore(user, server, 'restores.cancel', id);
    if (!RESTORE_CANCELLABLE.includes(r.status as RestoreStatus))
      throw this.stateError(r, [...RESTORE_CANCELLABLE]);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const moved = await tx.restore.updateMany({
        where: { id, status: { in: [...RESTORE_CANCELLABLE] } },
        data: {
          status: 'cancelled',
          finishedAt: now,
          error: { code: 'CANCELLED', message: `Cancelled by ${user.email}` },
          version: { increment: 1 },
        },
      });
      if (moved.count !== 1) throw this.stateError(r, [...RESTORE_CANCELLABLE]);
      await tx.operationApproval.updateMany({
        where: { subjectType: 'restore', subjectId: id, usedAt: null, invalidatedAt: null },
        data: { invalidatedAt: now },
      });
      for (const s of r.steps.filter((x) => x.status === 'running' && x.jobId)) {
        await tx.job.updateMany({
          where: { id: s.jobId!, status: { in: ['queued', 'leased'] } },
          data: {
            status: 'cancelled',
            finishedAt: now,
            leaseTokenHash: null,
            error: { code: 'CANCELLED' },
          },
        });
        await tx.restoreStepRow.update({
          where: { id: s.id },
          data: { status: 'skipped', finishedAt: now, message: 'Cancelled' },
        });
      }
      await this.audit.record(
        {
          actorId: user.id,
          action: 'restores.cancel',
          targetType: 'restore',
          targetId: id,
          result: 'success',
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- pipeline

  private async addStep(
    tx: Tx,
    restoreId: string,
    name: RestoreStepName,
    status: 'running' | 'succeeded' | 'failed' | 'skipped',
    extra: {
      jobId?: string | null;
      backupRunId?: string | null;
      deploymentId?: string | null;
      message?: string | null;
      errorCode?: string | null;
    } = {},
  ): Promise<RestoreStepRow> {
    const agg = await tx.restoreStepRow.aggregate({ where: { restoreId }, _max: { seq: true } });
    const now = new Date();
    return tx.restoreStepRow.create({
      data: {
        id: uuidv7(),
        restoreId,
        seq: (agg._max.seq ?? 0) + 1,
        name,
        status,
        jobId: extra.jobId ?? null,
        backupRunId: extra.backupRunId ?? null,
        deploymentId: extra.deploymentId ?? null,
        message: extra.message ?? null,
        errorCode: extra.errorCode ?? null,
        startedAt: now,
        finishedAt: status === 'running' ? null : now,
      },
    });
  }

  /** CAS a running step to its outcome; false when another handler already did it. */
  private async finishStep(
    tx: Tx,
    step: RestoreStepRow,
    ok: boolean,
    extra: { message?: string; errorCode?: string | null } = {},
  ): Promise<boolean> {
    const r = await tx.restoreStepRow.updateMany({
      where: { id: step.id, status: 'running' },
      data: {
        status: ok ? 'succeeded' : 'failed',
        finishedAt: new Date(),
        ...(extra.message !== undefined ? { message: extra.message.slice(0, 2000) } : {}),
        ...(extra.errorCode !== undefined ? { errorCode: extra.errorCode } : {}),
      },
    });
    return r.count === 1;
  }

  private async finish(
    tx: Tx,
    restoreId: string,
    status: 'verified' | 'failed' | 'requires_manual_recovery',
    extra: { error?: { code: string; message: string }; result?: unknown } = {},
  ) {
    const r = await tx.restore.updateMany({
      where: { id: restoreId, status: 'running' },
      data: {
        status,
        finishedAt: new Date(),
        ...(extra.error ? { error: extra.error } : {}),
        ...(extra.result !== undefined
          ? { result: boundJson(extra.result, 32_768) as Prisma.InputJsonValue }
          : {}),
        version: { increment: 1 },
      },
    });
    if (r.count !== 1) return;
    const row = await tx.restore.findUniqueOrThrow({ where: { id: restoreId } });
    await this.audit.record(
      {
        actorType: 'system',
        action: 'restores.finished',
        targetType: 'restore',
        targetId: restoreId,
        result: status === 'verified' ? 'success' : 'failure',
        metadata: {
          status,
          ...(extra.error ? { errorCode: extra.error.code } : {}),
          safetySnapshotRunId: row.safetySnapshotRunId,
        },
      },
      tx,
    );
  }

  /** Current container of a container app (for stop/start), or null when nothing is deployed. */
  private async currentContainer(appId: string) {
    const ca = await this.prisma.containerApp.findUnique({ where: { applicationId: appId } });
    const d = ca?.currentDeploymentId
      ? await this.prisma.deployment.findUnique({ where: { id: ca.currentDeploymentId } })
      : null;
    if (!ca || !d?.containerName || !d.hostPort || d.containerRemovedAt) return null;
    return { name: d.containerName, hostPort: d.hostPort, healthcheck: healthcheckOf(ca) };
  }

  /** (b) stop the app — or skip (paths / DB targets / nothing running) straight to (c). */
  private async stepStop(tx: Tx, r: RestoreRow): Promise<void> {
    const target = this.target(r);
    const app = r.applicationId
      ? await tx.application.findUnique({ where: { id: r.applicationId } })
      : null;
    if (target.type === 'volume' && app) {
      if (app.kind === 'compose') {
        const job = await this.jobs.createInternal(tx, {
          serverId: r.serverId,
          type: 'compose.stop',
          params: { app: app.name },
          actorId: r.createdBy,
          ttlSec: OP_TTL_SEC,
          metadata: { restoreId: r.id, applicationId: app.id },
        });
        await this.addStep(tx, r.id, 'stop_app', 'running', {
          jobId: job.id,
          message: `Stopping ${app.name} (compose, volumes kept)`,
        });
        return;
      }
      const c = await this.currentContainer(app.id);
      if (c) {
        const job = await this.jobs.createInternal(tx, {
          serverId: r.serverId,
          type: 'container.stop',
          params: { app: app.name, name: c.name },
          actorId: r.createdBy,
          ttlSec: OP_TTL_SEC,
          metadata: { restoreId: r.id, applicationId: app.id },
        });
        await this.addStep(tx, r.id, 'stop_app', 'running', {
          jobId: job.id,
          message: `Stopping ${c.name}`,
        });
        return;
      }
      await this.addStep(tx, r.id, 'stop_app', 'skipped', { message: 'No running container' });
    } else if (target.type !== 'paths') {
      await this.addStep(tx, r.id, 'stop_app', 'skipped', {
        message: 'The DB service must stay up for an in-place DB restore',
      });
    }
    await this.stepRestore(tx, r);
  }

  /** (c) restore.run (in place or isolated) with verify. */
  private async stepRestore(tx: Tx, r: RestoreRow): Promise<void> {
    const params = await this.restoreParams(r, false);
    const job = await this.jobs.createInternal(tx, {
      serverId: r.serverId,
      type: 'restore.run',
      params,
      actorId: r.createdBy,
      ttlSec: this.config.PPANEL_BACKUP_JOB_TTL_SEC,
      metadata: { restoreId: r.id },
    });
    await this.addStep(tx, r.id, 'restore', 'running', {
      jobId: job.id,
      message: `restic restore ${r.snapshotId.slice(0, 8)} (${this.target(r).mode}) with verification`,
    });
  }

  /** (d) start the app + healthcheck; nothing to start for paths. */
  private async stepStart(tx: Tx, r: RestoreRow): Promise<'started' | 'none'> {
    const target = this.target(r);
    if (target.type === 'paths' || !r.applicationId) return 'none';
    const app = await tx.application.findUnique({ where: { id: r.applicationId } });
    if (!app) return 'none';
    if (app.kind === 'container') {
      const c = await this.currentContainer(app.id);
      if (!c) return 'none';
      const job = await this.jobs.createInternal(tx, {
        serverId: r.serverId,
        type: 'container.start',
        params: { app: app.name, name: c.name, hostPort: c.hostPort, healthcheck: c.healthcheck },
        actorId: r.createdBy,
        ttlSec: OP_TTL_SEC,
        metadata: { restoreId: r.id, applicationId: app.id },
      });
      await this.addStep(tx, r.id, 'start_app', 'running', {
        jobId: job.id,
        message: `Starting ${c.name} and waiting for its healthcheck`,
      });
      return 'started';
    }
    // compose: re-apply the current plan as a deployment pre-approved by this restore (outside tx)
    await this.addStep(tx, r.id, 'start_app', 'running', {
      message: `Re-applying the current compose plan of ${app.name} (health-checked deployment)`,
    });
    return 'started';
  }

  /** compose start_app: create the redeploy after the step row committed. */
  private async startComposeIfNeeded(restoreId: string): Promise<void> {
    const step = await this.prisma.restoreStepRow.findFirst({
      where: { restoreId, name: 'start_app', status: 'running', jobId: null, deploymentId: null },
    });
    if (!step) return;
    const r = await this.prisma.restore.findUniqueOrThrow({ where: { id: restoreId } });
    try {
      const d = await this.composeApps.startForRestore(r.applicationId!, r.createdBy, r.id);
      if (!d) throw new Error('no current compose plan');
      await this.prisma.restoreStepRow.update({
        where: { id: step.id },
        data: { deploymentId: d.deploymentId },
      });
      await this.onDeploymentState(restoreId);
    } catch (err) {
      await this.prisma.$transaction(async (tx) => {
        if (
          await this.finishStep(tx, step, false, {
            message: `Start failed: ${(err as Error).message}`.slice(0, 500),
            errorCode: err instanceof AppError ? err.code : 'START_FAILED',
          })
        )
          await this.finish(tx, restoreId, 'requires_manual_recovery', {
            error: {
              code: 'APP_START_FAILED',
              message:
                'Data was restored but the application could not be started; see the safety snapshot for manual rollback',
            },
          });
      });
    }
  }

  private async onDeploymentState(restoreId: string): Promise<void> {
    const step = await this.prisma.restoreStepRow.findFirst({
      where: { restoreId, name: 'start_app', status: 'running', deploymentId: { not: null } },
    });
    if (!step) return;
    const d = await this.prisma.deployment.findUnique({ where: { id: step.deploymentId! } });
    if (!d) return;
    if (!DEPLOYMENT_OK.includes(d.status) && !DEPLOYMENT_BAD.includes(d.status)) return;
    const ok = DEPLOYMENT_OK.includes(d.status);
    await this.prisma.$transaction(async (tx) => {
      if (
        !(await this.finishStep(tx, step, ok, {
          message: `Deployment #${d.number} ${d.status}`,
          errorCode: ok ? null : ((d.error as { code?: string } | null)?.code ?? d.status),
        }))
      )
        return;
      if (ok) await this.finish(tx, restoreId, 'verified', { result: { deploymentId: d.id } });
      else
        await this.finish(tx, restoreId, 'requires_manual_recovery', {
          error: {
            code: 'APP_START_FAILED',
            message: `Data restored; application start deployment ${d.status}. Use the safety snapshot for manual rollback.`,
          },
        });
    });
  }

  private async onSafetyRun(run: RunRow): Promise<void> {
    if (!run.restoreId) return;
    const step = await this.prisma.restoreStepRow.findFirst({
      where: {
        restoreId: run.restoreId,
        backupRunId: run.id,
        name: 'safety_backup',
        status: 'running',
      },
    });
    if (!step) return;
    const ok = run.status === 'uploaded';
    await this.prisma.$transaction(async (tx) => {
      const err = (run.error ?? {}) as { code?: string; message?: string };
      if (
        !(await this.finishStep(tx, step, ok, {
          message: ok
            ? `Safety snapshot ${snapshotsOf(run)
                .map((s) => s.shortId)
                .join(', ')}`
            : `Safety backup ${run.status}: ${err.message ?? ''}`.trim(),
          errorCode: ok ? null : (err.code ?? run.status.toUpperCase()),
        }))
      )
        return;
      const r = await tx.restore.findUniqueOrThrow({ where: { id: run.restoreId! } });
      if (r.status !== 'running') return;
      if (!ok) {
        await this.finish(tx, r.id, 'failed', {
          error: {
            code: 'SAFETY_BACKUP_FAILED',
            message: 'The safety backup did not upload; nothing was stopped or overwritten',
          },
        });
        return;
      }
      await this.stepStop(tx, r);
    });
    this.jobs.notify(run.serverId);
  }

  private async onJob(job: FinishedJob): Promise<void> {
    const step = await this.prisma.restoreStepRow.findFirst({
      where: { jobId: job.id, status: 'running' },
    });
    if (!step) return;
    const r = await this.prisma.restore.findUniqueOrThrow({ where: { id: step.restoreId } });
    const target = this.target(r);
    const inPlace = target.mode === 'in_place';
    let composeStart = false;
    await this.prisma.$transaction(async (tx) => {
      const e = jobErr(job);
      if (step.name === 'dry_run') {
        const ok = job.status === 'succeeded';
        if (
          !(await this.finishStep(tx, step, ok, {
            message: ok ? 'Dry-run listing stored' : e.message,
            errorCode: ok ? null : e.code,
          }))
        )
          return;
        const cur = await tx.restore.findUniqueOrThrow({ where: { id: r.id } });
        await tx.restore.update({
          where: { id: r.id },
          data: {
            dryRun: {
              jobId: job.id,
              ok,
              listing: ok ? (boundJson(job.result, 65_536) as Prisma.InputJsonValue) : null,
              error: ok ? null : (e as unknown as Prisma.InputJsonValue),
            },
            ...(ok && cur.status === 'planned'
              ? {
                  status: cur.approvalRequired ? 'awaiting_approval' : 'impact_reviewed',
                  version: { increment: 1 },
                }
              : {}),
          },
        });
        await this.audit.record(
          {
            actorType: 'system',
            action: 'restores.dry_run_finished',
            targetType: 'restore',
            targetId: r.id,
            result: ok ? 'success' : 'failure',
            metadata: { jobId: job.id, ...(ok ? {} : { errorCode: e.code }) },
          },
          tx,
        );
        return;
      }
      if (r.status !== 'running') {
        await this.finishStep(tx, step, job.status === 'succeeded');
        return;
      }
      if (step.name === 'stop_app') {
        const ok = job.status === 'succeeded';
        if (
          !(await this.finishStep(tx, step, ok, {
            message: ok ? 'Application stopped' : e.message,
            errorCode: ok ? null : e.code,
          }))
        )
          return;
        if (!ok) {
          const compose = job.type === 'compose.stop';
          await this.finish(tx, r.id, compose ? 'requires_manual_recovery' : 'failed', {
            error: {
              code: 'APP_STOP_FAILED',
              message: compose
                ? 'Stopping the compose application failed; services may be partially stopped. Nothing was restored.'
                : 'Stopping the application failed; nothing was restored.',
            },
          });
          return;
        }
        await this.stepRestore(tx, r);
        return;
      }
      if (step.name === 'restore') {
        const parsed =
          job.status === 'succeeded' ? restoreRunResultSchema.safeParse(job.result) : null;
        const verify = parsed?.success ? parsed.data.verify : undefined;
        const ok =
          job.status === 'succeeded' &&
          !!parsed?.success &&
          verify?.ok === true &&
          (verify.mismatches?.length ?? 0) === 0;
        const msg = ok
          ? `Restored and verified (${verify?.compared ?? 0} items compared)`
          : job.status === 'succeeded'
            ? 'Restore finished but verification failed'
            : e.message;
        if (
          !(await this.finishStep(tx, step, ok, {
            message: msg,
            errorCode: ok ? null : job.status === 'succeeded' ? 'VERIFY_FAILED' : e.code,
          }))
        )
          return;
        const result = parsed?.success ? parsed.data : job.result;
        if (!ok) {
          await this.finish(tx, r.id, inPlace ? 'requires_manual_recovery' : 'failed', {
            error: {
              code: job.status === 'succeeded' ? 'VERIFY_FAILED' : e.code,
              message: inPlace
                ? 'In-place restore failed or did not verify; the application was left stopped. Restore the safety snapshot manually.'
                : msg,
            },
            result,
          });
          return;
        }
        if (!inPlace) {
          await this.finish(tx, r.id, 'verified', { result });
          // an isolated restore that compared OK is the evidence for `restore_verified`
          if ((verify?.compared ?? 0) > 0)
            await tx.backupRun.update({
              where: { id: r.runId },
              data: { verification: 'restore_verified', verifiedAt: new Date() },
            });
          return;
        }
        await tx.restore.update({
          where: { id: r.id },
          data: { result: boundJson(result, 32_768) as Prisma.InputJsonValue },
        });
        const started = await this.stepStart(tx, r);
        if (started === 'none') await this.finish(tx, r.id, 'verified', { result });
        else {
          const app = r.applicationId
            ? await tx.application.findUnique({ where: { id: r.applicationId } })
            : null;
          composeStart = app?.kind === 'compose';
        }
        return;
      }
      if (step.name === 'start_app') {
        const ok = job.status === 'succeeded';
        if (
          !(await this.finishStep(tx, step, ok, {
            message: ok ? 'Application started and healthy' : e.message,
            errorCode: ok ? null : e.code,
          }))
        )
          return;
        if (ok) await this.finish(tx, r.id, 'verified');
        else
          await this.finish(tx, r.id, 'requires_manual_recovery', {
            error: {
              code: 'APP_START_FAILED',
              message:
                'Data was restored but the application did not start healthy; use the safety snapshot for manual rollback',
            },
          });
      }
    });
    if (composeStart) await this.startComposeIfNeeded(r.id);
    this.jobs.notify(r.serverId);
  }

  // ---------------------------------------------------------------- reconcile

  private async reconcileOne(restoreId: string): Promise<void> {
    const steps = await this.prisma.restoreStepRow.findMany({
      where: { restoreId, status: 'running' },
    });
    for (const s of steps) {
      if (s.jobId) {
        const job = await this.prisma.job.findUnique({ where: { id: s.jobId } });
        if (job && this.jobs.isTerminal(job.status)) {
          if (s.name === 'safety_backup' && s.backupRunId) await this.runs.reconcile();
          else await this.onJob(job);
        }
      }
      if (s.name === 'safety_backup' && s.backupRunId) {
        const run = await this.prisma.backupRun.findUnique({ where: { id: s.backupRunId } });
        if (run && !['queued', 'running'].includes(run.status)) await this.onSafetyRun(run);
      }
      if (s.name === 'start_app' && !s.jobId) {
        if (s.deploymentId) await this.onDeploymentState(restoreId);
        else await this.startComposeIfNeeded(restoreId);
      }
    }
  }

  async reconcile(): Promise<void> {
    const rows = await this.prisma.restoreStepRow.findMany({
      where: { status: 'running' },
      select: { restoreId: true },
      distinct: ['restoreId'],
      take: 100,
    });
    for (const r of rows) {
      try {
        await this.reconcileOne(r.restoreId);
      } catch (err) {
        logger.emit('error', 'restore reconcile failed', { restoreId: r.restoreId, err });
      }
    }
  }

  /** Digest-pinned image of a compose service from the app's latest normalised plan. */
  private async sourceServiceImage(applicationId: string, service: string): Promise<string | null> {
    const latest = await this.prisma.composeAppVersion.findFirst({
      where: { applicationId },
      orderBy: { version: 'desc' },
      select: { plan: true },
    });
    const svc = planServices(latest?.plan).find((s) => s.service === service) as
      { image?: unknown } | undefined;
    return typeof svc?.image === 'string' && svc.image.includes('@sha256:') ? svc.image : null;
  }
}
