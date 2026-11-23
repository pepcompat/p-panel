import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  APPROVAL_TTL_MINUTES,
  type CreateNginxRevisionInput,
  ERROR_CODES,
  type NginxFilesRead,
  type NginxRevision,
  NGINX_REVISION_OPEN_STATUSES,
  type NginxRevisionStatus,
} from '@ppanel/shared-contracts';
import type {
  Job as JobRow,
  NginxConfigRevision as RevisionRow,
  NginxRevisionApproval as ApprovalRow,
  Prisma,
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
import { ApplicationsService } from '../discovery/applications.service';
import { DiscoveryService } from '../discovery/discovery.service';
import {
  type AppWithServer,
  driftFilesOf,
  nginxFilesOf,
  serverScope,
} from '../discovery/p3-common';
import type { FinishedJob } from '../jobs/job-hooks';
import { JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import {
  checkRevisionPath,
  computePlanHash,
  contentSha256,
  type NginxFileEntry,
  unifiedDiff,
} from './nginx-plan';

const OPEN = [...NGINX_REVISION_OPEN_STATUSES] as string[];
const READ_TTL_SEC = 120;
const MUTATE_TTL_SEC = 600;

interface StoredFile {
  path: string;
  beforeSha256: string | null;
  afterSha256: string;
  diff: string;
  content: string;
}
interface ReadFile {
  path: string;
  exists: boolean;
  sha256: string | null;
  content: string | null;
  isSymlink?: boolean;
  resolvedPath?: string | null;
  truncated?: boolean;
}
type RevisionWithApp = RevisionRow & { application: AppWithServer; approvals: ApprovalRow[] };

const revisionInclude = {
  application: { include: { server: { select: { id: true, environment: true, status: true } } } },
  approvals: { orderBy: { approvedAt: 'desc' as const } },
};

function filesOf(r: { files: unknown }): StoredFile[] {
  return r.files as StoredFile[];
}

function approvalRequired(app: AppWithServer): boolean {
  return app.server.environment === 'production' || app.ownershipMode === 'adopted';
}

function errCode(job: FinishedJob): string {
  const e = job.error as { code?: unknown } | null;
  if (e && typeof e.code === 'string') return e.code;
  return job.status === 'expired'
    ? 'LEASE_EXPIRED'
    : job.status === 'cancelled'
      ? 'CANCELLED'
      : 'FAILED';
}

@Injectable()
export class NginxRevisionsService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly apps: ApplicationsService,
    private readonly discovery: DiscoveryService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    this.hooks.register('nginx.validate', (j) => this.onValidateFinished(j));
    this.hooks.register('nginx.apply', (j) => this.onApplyFinished(j));
    this.hooks.register('nginx.revert', (j) => this.onRevertFinished(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  // ---------------------------------------------------------------- views

  allowedActions(user: AuthUser, r: RevisionWithApp): string[] {
    const scope = serverScope(r.application.server);
    if (r.application.server.status === 'revoked') return [];
    const write = this.authz.can(user, 'nginx.write', scope);
    const out: string[] = [];
    const s = r.status as NginxRevisionStatus;
    if (write && s === 'draft') out.push('validate');
    if (
      (s === 'awaiting_approval' || s === 'approved') &&
      this.authz.can(user, 'approvals.decide', scope) &&
      user.id !== r.createdBy
    )
      out.push('approve');
    const required = r.approvalRequired || approvalRequired(r.application);
    if (write && ((s === 'valid' && !required) || s === 'approved')) out.push('apply');
    if (write && s === 'applied') out.push('revert');
    if (write && ['draft', 'valid', 'awaiting_approval', 'approved'].includes(s))
      out.push('cancel');
    return out;
  }

  toView(user: AuthUser, r: RevisionWithApp): NginxRevision & { allowedActions: string[] } {
    const latest = r.approvals.find((a) => !a.invalidatedAt) ?? null;
    const v = r.validation as NginxRevision['validation'];
    return {
      id: r.id,
      serverId: r.serverId,
      applicationId: r.applicationId,
      status: r.status as NginxRevisionStatus,
      files: filesOf(r).map((f) => ({
        path: f.path,
        beforeSha256: f.beforeSha256,
        afterSha256: f.afterSha256,
        diff: f.diff,
      })),
      planHash: r.planHash,
      postchecks: r.postchecks as NginxRevision['postchecks'],
      validation: v ?? null,
      approval: {
        required: r.approvalRequired || approvalRequired(r.application),
        approvedBy: latest?.approverId ?? null,
        approvedAt: latest?.approvedAt.toISOString() ?? null,
        expiresAt: latest?.expiresAt.toISOString() ?? null,
      },
      validateJobId: r.validateJobId,
      applyJobId: r.applyJobId,
      revertJobId: r.revertJobId,
      result: (r.result as NginxRevision['result']) ?? null,
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      version: r.version,
      allowedActions: this.allowedActions(user, r),
    };
  }

  private async loadRevision(user: AuthUser, id: string): Promise<RevisionWithApp> {
    const r = await this.prisma.nginxConfigRevision.findUnique({
      where: { id },
      include: revisionInclude,
    });
    if (!r || !this.authz.can(user, 'nginx.read', serverScope(r.application.server)))
      throw AppError.notFound('Nginx revision');
    return r;
  }

  async get(user: AuthUser, id: string) {
    let r = await this.loadRevision(user, id);
    if (['validating', 'applying', 'reverting'].includes(r.status)) {
      await this.reconcileOne(r);
      r = await this.loadRevision(user, id);
    }
    return this.toView(user, r);
  }

  async list(user: AuthUser, appId: string, pq: ParsedQuery) {
    await this.apps.load(user, appId, 'nginx.read');
    const where: Prisma.NginxConfigRevisionWhereInput = {
      AND: [
        { applicationId: appId },
        buildWhere(pq, {
          status: { prop: 'status', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }) as Prisma.NginxConfigRevisionWhereInput,
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.nginxConfigRevision.count({ where }),
      this.prisma.nginxConfigRevision.findMany({
        where,
        include: revisionInclude,
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(
      rows.map((r) => this.toView(user, r)),
      paginate(pq, total),
    );
  }

  // ---------------------------------------------------------------- read files

  private async waitForJob(jobId: string): Promise<JobRow> {
    const deadline = Date.now() + this.config.PPANEL_NGINX_READ_WAIT_MS;
    for (;;) {
      const j = await this.prisma.job.findUniqueOrThrow({ where: { id: jobId } });
      if (this.jobs.isTerminal(j.status) || Date.now() >= deadline) return j;
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  private async startRead(user: AuthUser, app: AppWithServer, paths: string[]): Promise<JobRow> {
    if (app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const job = await this.prisma.$transaction((tx) =>
      this.jobs.createInternal(tx, {
        serverId: app.serverId,
        type: 'nginx.read_files',
        params: { paths },
        actorId: user.id,
        ttlSec: READ_TTL_SEC,
        metadata: { applicationId: app.id },
      }),
    );
    this.jobs.notify(app.serverId);
    return job;
  }

  private readOutput(job: JobRow): ReadFile[] {
    const out = job.result as { files?: ReadFile[] } | null;
    return Array.isArray(out?.files) ? out.files : [];
  }

  /** GET /applications/:id/nginx/files — read-only; waits ≤ PPANEL_NGINX_READ_WAIT_MS, else 202 pending. */
  async readFiles(
    user: AuthUser,
    appId: string,
    jobIdQuery: string | undefined,
  ): Promise<{ pending: boolean; body: NginxFilesRead }> {
    const app = await this.apps.load(user, appId, 'nginx.read');
    let job: JobRow;
    if (jobIdQuery) {
      const j = await this.prisma.job.findFirst({
        where: { id: jobIdQuery, serverId: app.serverId, type: 'nginx.read_files' },
      });
      const paths = new Set(nginxFilesOf(app).flatMap((f) => [f.path, f.resolvedPath ?? f.path]));
      const ok = j && ((j.params as { paths?: string[] }).paths ?? []).every((p) => paths.has(p));
      if (!j || !ok) throw AppError.notFound('Read job');
      job = j;
    } else {
      const paths = nginxFilesOf(app)
        .map((f) => f.path)
        .slice(0, 20);
      if (paths.length === 0)
        throw AppError.conflict('Application has no attributed nginx files', ERROR_CODES.CONFLICT);
      await this.audit.record({
        actorId: user.id,
        action: 'applications.nginx_files_read',
        targetType: 'application',
        targetId: appId,
        result: 'success',
        metadata: { paths },
      });
      job = await this.waitForJob((await this.startRead(user, app, paths)).id);
    }
    if (job.status === 'succeeded') {
      const files = this.readOutput(job);
      await this.learnSymlinks(app, files);
      return {
        pending: false,
        body: {
          jobId: job.id,
          status: 'succeeded',
          files: files.map((f) => ({
            path: f.path,
            sha256: f.sha256,
            content: f.content,
            exists: f.exists,
            isSymlink: f.isSymlink ?? false,
            resolvedPath: f.resolvedPath ?? f.path,
            truncated: f.truncated ?? false,
          })),
        },
      };
    }
    if (this.jobs.isTerminal(job.status))
      throw new AppError(502, ERROR_CODES.NGINX_READ_FAILED, `nginx.read_files job ${job.status}`, {
        jobId: job.id,
        error: job.error,
      });
    return { pending: true, body: { jobId: job.id, status: 'pending', files: [] } };
  }

  /** Remember symlink targets so a retry can edit the real file (agent refuses writing through symlinks). */
  private async learnSymlinks(app: AppWithServer, files: ReadFile[]): Promise<void> {
    const entries = nginxFilesOf(app);
    let changed = false;
    const next = entries.map((e) => {
      const f = files.find((x) => x.path === e.path);
      if (
        f?.isSymlink &&
        f.resolvedPath &&
        f.resolvedPath !== e.resolvedPath &&
        checkRevisionPath(f.resolvedPath, app.name, []) !==
          'path is not a canonical /etc/nginx path'
      ) {
        changed = true;
        return { ...e, resolvedPath: f.resolvedPath };
      }
      return e;
    });
    if (changed)
      await this.prisma.application.update({
        where: { id: app.id },
        data: { nginxFiles: next as unknown as Prisma.InputJsonValue },
      });
  }

  // ---------------------------------------------------------------- create draft

  private assertWritable(app: AppWithServer): void {
    if (app.kind === 'container')
      throw AppError.conflict(
        'Routes of container applications are generated by deployments',
        ERROR_CODES.OWNERSHIP_REQUIRED,
        { kind: app.kind },
      );
    if (app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (app.ownershipMode !== 'adopted' && app.ownershipMode !== 'managed')
      throw AppError.conflict(
        'Application must be adopted or managed',
        ERROR_CODES.OWNERSHIP_REQUIRED,
        {
          ownershipMode: app.ownershipMode,
        },
      );
    if (app.flagDriftDetected)
      throw AppError.conflict(
        'Configuration drift must be acknowledged first',
        ERROR_CODES.DRIFT_REVIEW_REQUIRED,
        {
          driftFiles: driftFilesOf(app),
        },
      );
  }

  async create(user: AuthUser, appId: string, input: CreateNginxRevisionInput) {
    const app = await this.apps.load(user, appId, 'nginx.read');
    const audit = { action: 'nginx_revisions.create', targetType: 'application', targetId: appId };
    await this.authz.enforce(user, 'nginx.write', serverScope(app.server), audit);
    this.assertWritable(app);
    const entries = nginxFilesOf(app);
    const rejected = input.files
      .map((f) => ({ path: f.path, reason: checkRevisionPath(f.path, app.name, entries) }))
      .filter((x) => x.reason !== null);
    if (rejected.length) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { rejected },
      });
      throw new AppError(
        422,
        ERROR_CODES.PATH_NOT_ALLOWED,
        'Revision path not allowed for this application',
        {
          files: rejected,
        },
      );
    }
    const open = await this.prisma.nginxConfigRevision.findFirst({
      where: { applicationId: appId, status: { in: OPEN } },
      select: { id: true, status: true },
    });
    if (open)
      throw AppError.conflict('Another revision is in progress', ERROR_CODES.REVISION_IN_PROGRESS, {
        revisionId: open.id,
        status: open.status,
      });

    // current content (source of beforeSha256) comes from the host, never from the client
    const job = await this.waitForJob(
      (
        await this.startRead(
          user,
          app,
          input.files.map((f) => f.path),
        )
      ).id,
    );
    if (job.status !== 'succeeded') {
      const pending = !this.jobs.isTerminal(job.status);
      throw new AppError(
        pending ? 504 : 502,
        ERROR_CODES.NGINX_READ_FAILED,
        pending ? 'Timed out reading current nginx files' : `nginx.read_files job ${job.status}`,
        {
          jobId: job.id,
          ...(pending ? { pending: true } : { error: job.error }),
        },
      );
    }
    const read = this.readOutput(job);
    await this.learnSymlinks(app, read);
    const files: StoredFile[] = [];
    for (const f of input.files) {
      const cur = read.find((x) => x.path === f.path);
      if (!cur)
        throw new AppError(502, ERROR_CODES.NGINX_READ_FAILED, `Agent did not return ${f.path}`, {
          jobId: job.id,
        });
      if (cur.isSymlink)
        throw new AppError(
          422,
          ERROR_CODES.PATH_NOT_ALLOWED,
          'Path is a symlink; edit its real path instead',
          {
            files: [{ path: f.path, resolvedPath: cur.resolvedPath ?? null, reason: 'symlink' }],
          },
        );
      if (cur.exists && (cur.content === null || cur.truncated))
        throw new AppError(422, ERROR_CODES.PATH_NOT_ALLOWED, 'File too large to edit', {
          files: [{ path: f.path }],
        });
      if (!cur.exists && !f.path.startsWith(`/etc/nginx/ppanel-managed/${app.name}/`))
        throw new AppError(
          422,
          ERROR_CODES.PATH_NOT_ALLOWED,
          'New files may only be created in the managed directory',
          {
            files: [{ path: f.path, reason: 'does not exist' }],
          },
        );
      const beforeSha = cur.exists ? (cur.sha256 ?? contentSha256(cur.content ?? '')) : null;
      files.push({
        path: f.path,
        beforeSha256: beforeSha,
        afterSha256: contentSha256(f.content),
        diff: unifiedDiff(f.path, cur.exists ? (cur.content ?? '') : null, f.content),
        content: f.content,
      });
    }
    const postchecks = input.postchecks ?? [];
    const planHash = computePlanHash(app.serverId, files, postchecks);
    const id = uuidv7();
    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.nginxConfigRevision.create({
          data: {
            id,
            serverId: app.serverId,
            applicationId: appId,
            status: 'draft',
            files: files as unknown as Prisma.InputJsonValue,
            planHash,
            postchecks: postchecks as unknown as Prisma.InputJsonValue,
            approvalRequired: approvalRequired(app),
            createdBy: user.id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'nginx_revisions.create',
            targetType: 'nginx_revision',
            targetId: id,
            result: 'success',
            diff: { planHash },
            metadata: {
              applicationId: appId,
              planHash,
              paths: files.map((f) => f.path),
              readJobId: job.id,
            },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'Another revision is in progress',
          ERROR_CODES.REVISION_IN_PROGRESS,
        );
      throw e;
    }
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- transitions

  private async transition(
    user: AuthUser,
    id: string,
    action: string,
    perm: 'nginx.write' | 'approvals.decide',
  ): Promise<RevisionWithApp> {
    const r = await this.loadRevision(user, id);
    await this.authz.enforce(user, perm, serverScope(r.application.server), {
      action,
      targetType: 'nginx_revision',
      targetId: id,
    });
    return r;
  }

  private stateError(r: { status: string }, allowed: string[]): AppError {
    return AppError.conflict(`Revision is ${r.status}`, ERROR_CODES.REVISION_STATE_INVALID, {
      status: r.status,
      allowed,
    });
  }

  private assertPlanIntact(r: RevisionWithApp): void {
    const recomputed = computePlanHash(r.serverId, filesOf(r), r.postchecks as unknown[]);
    if (recomputed !== r.planHash)
      throw AppError.conflict(
        'Revision plan changed since it was created',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        {
          planHash: r.planHash,
        },
      );
  }

  private jobFiles(r: RevisionRow) {
    return filesOf(r).map((f) => ({
      path: f.path,
      expectedSha256Before: f.beforeSha256,
      content: f.content,
    }));
  }

  async validate(user: AuthUser, id: string) {
    const r = await this.transition(user, id, 'nginx_revisions.validate', 'nginx.write');
    if (r.status !== 'draft') throw this.stateError(r, ['draft']);
    this.assertWritable(r.application);
    this.assertPlanIntact(r);
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId: r.serverId,
        type: 'nginx.validate',
        params: { revisionId: r.id, files: this.jobFiles(r) },
        actorId: user.id,
        ttlSec: MUTATE_TTL_SEC,
        metadata: { revisionId: r.id },
      });
      await this.move(tx, r.id, ['draft'], {
        status: 'validating',
        validateJobId: j.id,
        validation: { jobId: j.id, valid: null, nginxTestOutput: null, error: null },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'nginx_revisions.validate',
          targetType: 'nginx_revision',
          targetId: r.id,
          result: 'success',
          metadata: { jobId: j.id },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(r.serverId);
    return { jobId: job.id, revision: await this.get(user, id) };
  }

  async approve(user: AuthUser, id: string, planHash: string, stepUpHeader: string | undefined) {
    const r = await this.transition(user, id, 'nginx_revisions.approve', 'approvals.decide');
    if (r.createdBy === user.id) {
      await this.audit.record({
        actorId: user.id,
        action: 'nginx_revisions.approve',
        targetType: 'nginx_revision',
        targetId: id,
        result: 'denied',
        metadata: { reason: 'approver_is_creator' },
      });
      throw AppError.forbidden(
        'The creator of a revision cannot approve it',
        ERROR_CODES.APPROVER_IS_CREATOR,
      );
    }
    this.auth.assertStepUp(user, stepUpHeader);
    if (r.status !== 'awaiting_approval' && r.status !== 'approved')
      throw this.stateError(r, ['awaiting_approval', 'approved']);
    if (!(r.approvalRequired || approvalRequired(r.application)))
      throw AppError.conflict(
        'This revision does not require approval',
        ERROR_CODES.APPROVAL_NOT_REQUIRED,
      );
    this.assertPlanIntact(r);
    if (planHash !== r.planHash)
      throw AppError.conflict(
        'planHash does not match the current plan',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        {
          planHash: r.planHash,
        },
      );
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      // a new approval supersedes any earlier unused one
      await tx.nginxRevisionApproval.updateMany({
        where: { revisionId: id, usedAt: null, invalidatedAt: null },
        data: { invalidatedAt: now },
      });
      await tx.nginxRevisionApproval.create({
        data: {
          id: uuidv7(),
          revisionId: id,
          approverId: user.id,
          planHash,
          approvedAt: now,
          expiresAt: new Date(now.getTime() + APPROVAL_TTL_MINUTES * 60_000),
        },
      });
      await this.move(tx, id, ['awaiting_approval', 'approved'], { status: 'approved' });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'nginx_revisions.approve',
          targetType: 'nginx_revision',
          targetId: id,
          result: 'success',
          diff: { planHash },
          metadata: { planHash },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  async apply(user: AuthUser, id: string, stepUpHeader: string | undefined) {
    const r = await this.transition(user, id, 'nginx_revisions.apply', 'nginx.write');
    this.assertWritable(r.application);
    if (r.application.server.environment === 'production')
      this.auth.assertStepUp(user, stepUpHeader);
    const required = r.approvalRequired || approvalRequired(r.application);
    if (required && r.status === 'awaiting_approval')
      throw AppError.conflict('Approval required before apply', ERROR_CODES.APPROVAL_REQUIRED);
    const allowed = required ? ['approved'] : ['valid', 'approved'];
    if (!allowed.includes(r.status)) throw this.stateError(r, allowed);
    this.assertPlanIntact(r);
    const now = new Date();
    let approval: ApprovalRow | null = null;
    if (required) {
      approval = r.approvals.find((a) => !a.invalidatedAt && !a.usedAt) ?? null;
      if (!approval)
        throw AppError.conflict('Approval required before apply', ERROR_CODES.APPROVAL_REQUIRED);
      if (approval.planHash !== r.planHash)
        throw AppError.conflict(
          'Approval was given for a different plan',
          ERROR_CODES.PLAN_HASH_MISMATCH,
          {
            planHash: r.planHash,
          },
        );
      if (approval.expiresAt <= now)
        throw AppError.conflict(
          'Approval expired; request a new approval',
          ERROR_CODES.APPROVAL_EXPIRED,
          {
            expiredAt: approval.expiresAt.toISOString(),
          },
        );
    }
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId: r.serverId,
        type: 'nginx.apply',
        params: { revisionId: r.id, files: this.jobFiles(r), postchecks: r.postchecks },
        actorId: user.id,
        ttlSec: MUTATE_TTL_SEC,
        metadata: { revisionId: r.id, approvalId: approval?.id },
      });
      if (approval) {
        // single use: consume atomically (fails if already used / expired / re-planned meanwhile)
        const used = await tx.nginxRevisionApproval.updateMany({
          where: {
            id: approval.id,
            usedAt: null,
            invalidatedAt: null,
            planHash: r.planHash,
            expiresAt: { gt: now },
          },
          data: { usedAt: now, usedByJobId: j.id },
        });
        if (used.count !== 1)
          throw AppError.conflict('Approval is no longer valid', ERROR_CODES.APPROVAL_REQUIRED);
      }
      await this.move(tx, r.id, allowed, { status: 'applying', applyJobId: j.id });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'nginx_revisions.apply',
          targetType: 'nginx_revision',
          targetId: r.id,
          result: 'success',
          diff: { planHash: r.planHash },
          metadata: { jobId: j.id, approvalId: approval?.id ?? null, planHash: r.planHash },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(r.serverId);
    return { jobId: job.id, revision: await this.get(user, id) };
  }

  async revert(user: AuthUser, id: string, stepUpHeader: string | undefined) {
    const r = await this.transition(user, id, 'nginx_revisions.revert', 'nginx.write');
    if (r.application.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (r.application.server.environment === 'production')
      this.auth.assertStepUp(user, stepUpHeader);
    if (r.status !== 'applied') throw this.stateError(r, ['applied']);
    if (r.application.flagDriftDetected)
      throw AppError.conflict(
        'Configuration drift must be acknowledged first',
        ERROR_CODES.DRIFT_REVIEW_REQUIRED,
        {
          driftFiles: driftFilesOf(r.application),
        },
      );
    try {
      const job = await this.prisma.$transaction(async (tx) => {
        const j = await this.jobs.createInternal(tx, {
          serverId: r.serverId,
          type: 'nginx.revert',
          params: {
            revisionId: r.id,
            expectedCurrent: filesOf(r).map((f) => ({ path: f.path, sha256: f.afterSha256 })),
          },
          actorId: user.id,
          ttlSec: MUTATE_TTL_SEC,
          metadata: { revisionId: r.id },
        });
        await this.move(tx, r.id, ['applied'], { status: 'reverting', revertJobId: j.id });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'nginx_revisions.revert',
            targetType: 'nginx_revision',
            targetId: r.id,
            result: 'success',
            metadata: { jobId: j.id },
          },
          tx,
        );
        return j;
      });
      this.jobs.notify(r.serverId);
      return { jobId: job.id, revision: await this.get(user, id) };
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'Another revision is in progress',
          ERROR_CODES.REVISION_IN_PROGRESS,
        );
      throw e;
    }
  }

  async cancel(user: AuthUser, id: string) {
    const r = await this.transition(user, id, 'nginx_revisions.cancel', 'nginx.write');
    const allowed = ['draft', 'valid', 'awaiting_approval', 'approved'];
    if (!allowed.includes(r.status)) throw this.stateError(r, allowed);
    await this.prisma.$transaction(async (tx) => {
      await this.move(tx, id, allowed, { status: 'cancelled' });
      await tx.nginxRevisionApproval.updateMany({
        where: { revisionId: id, usedAt: null, invalidatedAt: null },
        data: { invalidatedAt: new Date() },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'nginx_revisions.cancel',
          targetType: 'nginx_revision',
          targetId: id,
          result: 'success',
          metadata: { from: r.status },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  /** Compare-and-set status transition (optimistic: concurrent transitions → 409). */
  private async move(
    tx: Tx,
    id: string,
    from: string[],
    data: Prisma.NginxConfigRevisionUpdateManyMutationInput,
  ): Promise<void> {
    const r = await tx.nginxConfigRevision.updateMany({
      where: { id, status: { in: from } },
      data: { ...data, version: { increment: 1 } },
    });
    if (r.count !== 1)
      throw AppError.conflict('Revision changed concurrently', ERROR_CODES.REVISION_STATE_INVALID);
  }

  // ---------------------------------------------------------------- job results (hooks, idempotent)

  private async systemMove(
    tx: Tx,
    r: RevisionRow,
    from: string,
    data: Prisma.NginxConfigRevisionUpdateManyMutationInput,
    job: FinishedJob,
  ): Promise<boolean> {
    const u = await tx.nginxConfigRevision.updateMany({
      where: { id: r.id, status: from },
      data: { ...data, version: { increment: 1 } },
    });
    if (u.count !== 1) return false;
    await this.audit.record(
      {
        actorType: 'system',
        action: 'nginx_revisions.status',
        targetType: 'nginx_revision',
        targetId: r.id,
        result:
          data.status === 'applied' ||
          data.status === 'reverted' ||
          data.status === 'valid' ||
          data.status === 'awaiting_approval'
            ? 'success'
            : 'failure',
        metadata: {
          from,
          to: data.status,
          jobId: job.id,
          jobType: job.type,
          jobStatus: job.status,
          ...(job.status !== 'succeeded' ? { errorCode: errCode(job) } : {}),
        },
      },
      tx,
    );
    return true;
  }

  private async driftFromAgent(tx: Tx, r: RevisionRow, job: FinishedJob): Promise<void> {
    const details = (
      job.error as {
        details?: {
          files?: Array<{ path: string; expected: string | null; actual: string | null }>;
        };
      } | null
    )?.details;
    const files = (details?.files ?? []).filter((f) => typeof f.path === 'string');
    // actual null = file missing on host → checksum unknown until the next scan
    const drifted = files.map((f) => ({
      path: f.path,
      lastKnownSha256: f.expected ?? null,
      currentSha256: typeof f.actual === 'string' ? f.actual : 'unknown',
    }));
    if (drifted.length === 0)
      // agent did not say which file — flag every file in the revision with unknown current checksum
      for (const f of filesOf(r))
        drifted.push({ path: f.path, lastKnownSha256: f.beforeSha256, currentSha256: 'unknown' });
    await this.discovery.flagDrift(tx, r.applicationId, drifted, {
      source: 'agent',
      jobId: job.id,
      revisionId: r.id,
    });
  }

  /**
   * Shared failure mapping: DRIFT_DETECTED → drift_blocked (+ app drift flag);
   * REVERT_FAILED_MANUAL_RECOVERY → requires_manual_recovery (+ app drift flag with unknown checksums,
   * so nothing more can be written until an operator recovers, rescans and acknowledges);
   * anything else → `fallback`.
   */
  private async failTo(
    tx: Tx,
    r: RevisionRow,
    from: string,
    fallback: string,
    data: Prisma.NginxConfigRevisionUpdateManyMutationInput,
    job: FinishedJob,
  ): Promise<void> {
    const code = errCode(job);
    if (code === 'DRIFT_DETECTED') {
      if (await this.systemMove(tx, r, from, { ...data, status: 'drift_blocked' }, job))
        await this.driftFromAgent(tx, r, job);
      return;
    }
    if (code === 'REVERT_FAILED_MANUAL_RECOVERY') {
      logger.emit('fatal', 'nginx revert failed: manual recovery required', {
        revisionId: r.id,
        serverId: r.serverId,
        jobId: job.id,
      });
      if (await this.systemMove(tx, r, from, { ...data, status: 'requires_manual_recovery' }, job))
        await this.discovery.flagDrift(
          tx,
          r.applicationId,
          filesOf(r).map((f) => ({
            path: f.path,
            lastKnownSha256: f.beforeSha256,
            currentSha256: 'unknown',
          })),
          { source: 'agent', jobId: job.id, revisionId: r.id, errorCode: code },
        );
      return;
    }
    await this.systemMove(tx, r, from, { ...data, status: fallback }, job);
  }

  private failureResult(job: FinishedJob, operation: string): Prisma.InputJsonValue {
    const e = (job.error ?? {}) as { message?: string; details?: unknown };
    return {
      errorCode: errCode(job),
      operation,
      ...(e.message ? { message: e.message } : {}),
      ...(e.details ? { details: e.details } : {}),
    } as Prisma.InputJsonValue;
  }

  private async onValidateFinished(job: FinishedJob): Promise<void> {
    const r = await this.prisma.nginxConfigRevision.findFirst({
      where: { validateJobId: job.id, status: 'validating' },
      include: revisionInclude,
    });
    if (!r) return;
    await this.prisma.$transaction(async (tx) => {
      if (job.status === 'succeeded') {
        const out = (job.result ?? {}) as {
          valid?: unknown;
          nginxTestOutput?: unknown;
          filesChecked?: unknown;
        };
        const valid = out.valid === true;
        const required = r.approvalRequired || approvalRequired(r.application);
        await this.systemMove(
          tx,
          r,
          'validating',
          {
            status: valid ? (required ? 'awaiting_approval' : 'valid') : 'invalid',
            approvalRequired: required,
            validation: {
              jobId: job.id,
              valid,
              nginxTestOutput: typeof out.nginxTestOutput === 'string' ? out.nginxTestOutput : null,
              filesChecked: Array.isArray(out.filesChecked) ? out.filesChecked : [],
              error: null,
            } as Prisma.InputJsonValue,
          },
          job,
        );
        return;
      }
      const code = errCode(job);
      const e = (job.error ?? {}) as { message?: string; details?: unknown };
      const error = {
        code,
        ...(e.message ? { message: e.message } : {}),
        ...(e.details ? { details: e.details } : {}),
      };
      // lease lapse / cancel before a verdict: back to draft so it can be re-validated
      const failed = job.status === 'failed';
      await this.failTo(
        tx,
        r,
        'validating',
        failed ? 'invalid' : 'draft',
        {
          validation: {
            jobId: job.id,
            valid: failed ? false : null,
            nginxTestOutput: null,
            error,
          } as Prisma.InputJsonValue,
          result: this.failureResult(job, 'validate'),
        },
        job,
      );
    });
  }

  private async onApplyFinished(job: FinishedJob): Promise<void> {
    const r = await this.prisma.nginxConfigRevision.findFirst({
      where: { applyJobId: job.id, status: 'applying' },
    });
    if (!r) return;
    await this.prisma.$transaction(async (tx) => {
      if (job.status === 'succeeded') {
        const out = (job.result ?? {}) as { files?: Array<{ path: string; sha256After?: string }> };
        if (
          !(await this.systemMove(
            tx,
            r,
            'applying',
            { status: 'applied', result: (job.result ?? {}) as Prisma.InputJsonValue },
            job,
          ))
        )
          return;
        const after = new Map(
          filesOf(r).map((f) => [
            f.path,
            out.files?.find((x) => x.path === f.path)?.sha256After ?? f.afterSha256,
          ]),
        );
        await this.updateBaseline(tx, r.applicationId, after);
        // older applied revisions of this app can no longer be reverted safely
        await tx.nginxConfigRevision.updateMany({
          where: { applicationId: r.applicationId, status: 'applied', id: { not: r.id } },
          data: { status: 'superseded', version: { increment: 1 } },
        });
        return;
      }
      await this.failTo(
        tx,
        r,
        'applying',
        'apply_failed',
        { result: this.failureResult(job, 'apply') },
        job,
      );
    });
  }

  private async onRevertFinished(job: FinishedJob): Promise<void> {
    const r = await this.prisma.nginxConfigRevision.findFirst({
      where: { revertJobId: job.id, status: 'reverting' },
    });
    if (!r) return;
    await this.prisma.$transaction(async (tx) => {
      if (job.status === 'succeeded') {
        if (
          !(await this.systemMove(
            tx,
            r,
            'reverting',
            {
              status: 'reverted',
              result: { ...(job.result as object), operation: 'revert' } as Prisma.InputJsonValue,
            },
            job,
          ))
        )
          return;
        const out = (job.result ?? {}) as {
          files?: Array<{ path: string; sha256After?: string | null }>;
        };
        await this.updateBaseline(
          tx,
          r.applicationId,
          new Map(
            filesOf(r).map((f) => {
              const reported = out.files?.find((x) => x.path === f.path);
              return [
                f.path,
                reported && reported.sha256After !== undefined
                  ? reported.sha256After
                  : f.beforeSha256,
              ];
            }),
          ),
        );
        return;
      }
      // contract: a failed revert is `apply_failed` (result.operation = 'revert'); the host keeps the applied content
      await this.failTo(
        tx,
        r,
        'reverting',
        'apply_failed',
        { result: this.failureResult(job, 'revert') },
        job,
      );
    });
  }

  /** After applied/reverted: the host now has pPanel's checksums, so the next scan must not flag them as drift. */
  private async updateBaseline(
    tx: Tx,
    applicationId: string,
    sha: Map<string, string | null>,
  ): Promise<void> {
    const app = await tx.application.findUniqueOrThrow({ where: { id: applicationId } });
    const entries: NginxFileEntry[] = nginxFilesOf(app).map((e) => ({ ...e }));
    for (const [path, value] of sha) {
      const matches = entries.filter((e) => e.path === path || e.resolvedPath === path);
      if (matches.length) for (const m of matches) m.lastKnownSha256 = value;
      else if (value !== null) entries.push({ path, lastKnownSha256: value });
    }
    // a created file that was reverted no longer exists → forget it
    const next = entries.filter(
      (e) =>
        !(
          e.lastKnownSha256 === null &&
          sha.has(e.path) &&
          e.path.startsWith('/etc/nginx/ppanel-managed/')
        ),
    );
    await tx.application.update({
      where: { id: applicationId },
      data: { nginxFiles: next as unknown as Prisma.InputJsonValue, version: { increment: 1 } },
    });
  }

  // ---------------------------------------------------------------- reconcile

  private async reconcileOne(r: RevisionRow): Promise<void> {
    const jobId =
      r.status === 'validating'
        ? r.validateJobId
        : r.status === 'applying'
          ? r.applyJobId
          : r.revertJobId;
    if (!jobId) return;
    const job = await this.prisma.job.findUnique({ where: { id: jobId } });
    if (job && this.jobs.isTerminal(job.status)) await this.jobs.dispatchFinished(job);
  }

  async reconcile(): Promise<void> {
    const rows = await this.prisma.nginxConfigRevision.findMany({
      where: { status: { in: ['validating', 'applying', 'reverting'] } },
      take: 50,
      orderBy: { updatedAt: 'asc' },
    });
    for (const r of rows) await this.reconcileOne(r);
  }
}
