import { Injectable, type OnModuleInit } from '@nestjs/common';
import {
  APPROVAL_TTL_MINUTES,
  ERROR_CODES,
  MANAGED_ROUTING_CONF_CONTENT,
  MANAGED_ROUTING_CONF_PATH,
  type ManagedRouting,
  type ManagedRoutingStatus,
} from '@ppanel/shared-contracts';
import type { ManagedRouting as RoutingRow, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { serverScope } from '../discovery/p3-common';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import { computePlanHash, contentSha256 } from '../nginx/nginx-plan';

const APPLY_TTL_SEC = 600;

function planHashFor(serverId: string): string {
  return computePlanHash(
    serverId,
    [
      {
        path: MANAGED_ROUTING_CONF_PATH,
        beforeSha256: null,
        afterSha256: contentSha256(MANAGED_ROUTING_CONF_CONTENT),
      },
    ],
    [],
  );
}

/**
 * "Enable managed routing" per server: one approval-gated `nginx.apply` that creates
 * `/etc/nginx/conf.d/ppanel-managed.conf` (include of `/etc/nginx/ppanel-managed/*\/*.conf`).
 * Approval rules as nginx revisions: production requires approval (approver ≠ requester, X-Step-Up,
 * planHash-bound, single-use, 60 min); the approval starts the apply.
 */
@Injectable()
export class ManagedRoutingService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
  ) {}

  onModuleInit(): void {
    this.hooks.register('nginx.apply', (j) => this.onApplyFinished(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  private async server(user: AuthUser, serverId: string) {
    const s = await this.prisma.server.findUnique({ where: { id: serverId } });
    if (!s || !this.authz.can(user, 'nginx.read', serverScope(s)))
      throw AppError.notFound('Server');
    return s;
  }

  private async view(
    user: AuthUser,
    serverId: string,
    env: string,
    row: RoutingRow | null,
  ): Promise<ManagedRouting> {
    const approvals = row
      ? await this.prisma.operationApproval.findMany({
          where: { subjectType: 'managed_routing', subjectId: row.revisionId, invalidatedAt: null },
          orderBy: { approvedAt: 'desc' },
          take: 1,
        })
      : [];
    const scope = { serverId, environment: env };
    const actions: ManagedRouting['allowedActions'] = [];
    if ((!row || row.status === 'failed') && this.authz.can(user, 'nginx.write', scope))
      actions.push('enable');
    if (
      row?.status === 'awaiting_approval' &&
      this.authz.can(user, 'approvals.decide', scope) &&
      row.createdBy !== user.id
    )
      actions.push('approve');
    const a = approvals[0];
    return {
      serverId,
      enabled: row?.status === 'enabled',
      status: (row?.status as ManagedRoutingStatus | undefined) ?? 'disabled',
      revisionId: row?.revisionId ?? null,
      planHash: row?.planHash ?? null,
      path: MANAGED_ROUTING_CONF_PATH,
      applyJobId: row?.applyJobId ?? null,
      approval: {
        required: row?.approvalRequired ?? env === 'production',
        approvedBy: a?.approverId ?? null,
        approvedAt: a?.approvedAt.toISOString() ?? null,
        expiresAt: a?.expiresAt.toISOString() ?? null,
      },
      error: (row?.error as ManagedRouting['error']) ?? null,
      createdBy: row?.createdBy ?? null,
      allowedActions: actions,
      updatedAt: row?.updatedAt.toISOString() ?? null,
    };
  }

  async get(user: AuthUser, serverId: string): Promise<ManagedRouting> {
    const s = await this.server(user, serverId);
    let row = await this.prisma.managedRouting.findUnique({ where: { serverId } });
    if (row?.status === 'applying' && row.applyJobId) {
      const job = await this.prisma.job.findUnique({ where: { id: row.applyJobId } });
      if (job && this.jobs.isTerminal(job.status)) {
        await this.jobs.dispatchFinished(job);
        row = await this.prisma.managedRouting.findUnique({ where: { serverId } });
      }
    }
    return this.view(user, serverId, s.environment, row);
  }

  private async startApply(tx: Tx, row: { serverId: string; revisionId: string }, actorId: string) {
    const job = await this.jobs.createInternal(tx, {
      serverId: row.serverId,
      type: 'nginx.apply',
      params: {
        revisionId: row.revisionId,
        files: [
          {
            path: MANAGED_ROUTING_CONF_PATH,
            expectedSha256Before: null,
            content: MANAGED_ROUTING_CONF_CONTENT,
          },
        ],
        postchecks: [],
      },
      actorId,
      ttlSec: APPLY_TTL_SEC,
      metadata: { managedRouting: true, revisionId: row.revisionId },
    });
    return job;
  }

  async enable(
    user: AuthUser,
    serverId: string,
    stepUp: string | undefined,
  ): Promise<ManagedRouting> {
    const s = await this.server(user, serverId);
    await this.authz.enforce(user, 'nginx.write', serverScope(s), {
      action: 'managed_routing.enable',
      targetType: 'server',
      targetId: serverId,
    });
    if (s.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (s.environment === 'production') this.auth.assertStepUp(user, stepUp);
    const existing = await this.prisma.managedRouting.findUnique({ where: { serverId } });
    if (existing?.status === 'enabled')
      throw AppError.conflict(
        'Managed routing is already enabled',
        ERROR_CODES.MANAGED_ROUTING_ALREADY_ENABLED,
      );
    if (existing && existing.status !== 'failed')
      throw AppError.conflict(
        `Managed routing is ${existing.status}`,
        ERROR_CODES.MANAGED_ROUTING_IN_PROGRESS,
        {
          status: existing.status,
        },
      );
    const approvalRequired = s.environment === 'production';
    const revisionId = uuidv7();
    const planHash = planHashFor(serverId);
    try {
      await this.prisma.$transaction(async (tx) => {
        if (existing) {
          const r = await tx.managedRouting.deleteMany({ where: { serverId, status: 'failed' } });
          if (r.count !== 1)
            throw AppError.conflict(
              'Managed routing changed concurrently',
              ERROR_CODES.MANAGED_ROUTING_IN_PROGRESS,
            );
        }
        await tx.managedRouting.create({
          data: {
            serverId,
            status: approvalRequired ? 'awaiting_approval' : 'applying',
            revisionId,
            planHash,
            approvalRequired,
            createdBy: user.id,
          },
        });
        let jobId: string | null = null;
        if (!approvalRequired) {
          const job = await this.startApply(tx, { serverId, revisionId }, user.id);
          jobId = job.id;
          await tx.managedRouting.update({ where: { serverId }, data: { applyJobId: job.id } });
        }
        await this.audit.record(
          {
            actorId: user.id,
            action: 'managed_routing.enable',
            targetType: 'server',
            targetId: serverId,
            result: 'success',
            diff: { planHash },
            metadata: { revisionId, planHash, approvalRequired, jobId },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'Managed routing changed concurrently',
          ERROR_CODES.MANAGED_ROUTING_IN_PROGRESS,
        );
      throw e;
    }
    this.jobs.notify(serverId);
    return this.get(user, serverId);
  }

  async approve(
    user: AuthUser,
    serverId: string,
    planHash: string,
    stepUp: string | undefined,
  ): Promise<ManagedRouting> {
    const s = await this.server(user, serverId);
    const audit = { action: 'managed_routing.approve', targetType: 'server', targetId: serverId };
    await this.authz.enforce(user, 'approvals.decide', serverScope(s), audit);
    const row = await this.prisma.managedRouting.findUnique({ where: { serverId } });
    if (!row) throw AppError.notFound('Managed routing request');
    if (row.createdBy === user.id) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason: 'approver_is_creator' },
      });
      throw AppError.forbidden('The requester cannot approve it', ERROR_CODES.APPROVER_IS_CREATOR);
    }
    this.auth.assertStepUp(user, stepUp);
    if (row.status !== 'awaiting_approval')
      throw AppError.conflict(
        `Managed routing is ${row.status}`,
        ERROR_CODES.REVISION_STATE_INVALID,
        {
          status: row.status,
        },
      );
    if (planHash !== row.planHash || planHashFor(serverId) !== row.planHash)
      throw AppError.conflict(
        'planHash does not match the current plan',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        {
          planHash: row.planHash,
        },
      );
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const approval = await tx.operationApproval.create({
        data: {
          id: uuidv7(),
          subjectType: 'managed_routing',
          subjectId: row.revisionId,
          approverId: user.id,
          planHash,
          approvedAt: now,
          expiresAt: new Date(now.getTime() + APPROVAL_TTL_MINUTES * 60_000),
        },
      });
      const job = await this.startApply(tx, row, user.id);
      const moved = await tx.managedRouting.updateMany({
        where: { serverId, status: 'awaiting_approval', version: row.version },
        data: { status: 'applying', applyJobId: job.id, version: { increment: 1 } },
      });
      if (moved.count !== 1)
        throw AppError.conflict(
          'Managed routing changed concurrently',
          ERROR_CODES.REVISION_STATE_INVALID,
        );
      await tx.operationApproval.update({
        where: { id: approval.id },
        data: { usedAt: now, usedByJobId: job.id },
      });
      await this.audit.record(
        {
          actorId: user.id,
          ...audit,
          result: 'success',
          diff: { planHash },
          metadata: { planHash, jobId: job.id },
        },
        tx,
      );
    });
    this.jobs.notify(serverId);
    return this.get(user, serverId);
  }

  private async onApplyFinished(job: FinishedJob): Promise<void> {
    const row = await this.prisma.managedRouting.findFirst({
      where: { applyJobId: job.id, status: 'applying' },
    });
    if (!row) return;
    const e = (job.error ?? {}) as { code?: string; message?: string };
    const code =
      typeof e.code === 'string' ? e.code : job.status === 'expired' ? 'LEASE_EXPIRED' : 'FAILED';
    const status =
      job.status === 'succeeded'
        ? 'enabled'
        : code === 'REVERT_FAILED_MANUAL_RECOVERY'
          ? 'requires_manual_recovery'
          : 'failed';
    if (status === 'requires_manual_recovery')
      logger.emit('fatal', 'managed routing apply: manual recovery required', {
        serverId: row.serverId,
        jobId: job.id,
      });
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.managedRouting.updateMany({
        where: { serverId: row.serverId, status: 'applying', applyJobId: job.id },
        data: {
          status,
          error:
            status === 'enabled'
              ? undefined
              : ({ code, ...(e.message ? { message: e.message } : {}) } as Prisma.InputJsonValue),
          version: { increment: 1 },
        },
      });
      if (r.count !== 1) return;
      await this.audit.record(
        {
          actorType: 'system',
          action: 'managed_routing.status',
          targetType: 'server',
          targetId: row.serverId,
          result: status === 'enabled' ? 'success' : 'failure',
          metadata: {
            to: status,
            jobId: job.id,
            ...(status !== 'enabled' ? { errorCode: code } : {}),
          },
        },
        tx,
      );
    });
  }

  async reconcile(): Promise<void> {
    const rows = await this.prisma.managedRouting.findMany({
      where: { status: 'applying', applyJobId: { not: null } },
      take: 50,
    });
    for (const r of rows) {
      const job = await this.prisma.job.findUnique({ where: { id: r.applyJobId! } });
      if (job && this.jobs.isTerminal(job.status)) await this.jobs.dispatchFinished(job);
    }
  }
}
