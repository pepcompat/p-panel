import { Injectable } from '@nestjs/common';
import {
  type BackupPolicy as BackupPolicyView,
  type BackupPolicyAction,
  type BackupPolicyTarget,
  type BackupPolicyTargetInput,
  type BackupRunStatus,
  type BackupVerification,
  type CreateBackupPolicyInput,
  ERROR_CODES,
  type UpdateBackupPolicyInput,
} from '@ppanel/shared-contracts';
import type { BackupPolicy as PolicyRow, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { serverScope } from '../discovery/p3-common';
import { agentExcludes, nextRunAfter, pathViolation, scheduleError } from './backup-common';
import { BackupRunsService, targetsOf } from './backup-runs.service';

interface Issue {
  path: string;
  message: string;
}

export interface PlanService {
  service: string;
  image?: string;
  volumes?: Array<{ name: string }>;
  secretEnv?: Record<string, string>;
}

/**
 * Compose app versions store the normalised plan as an ARRAY of services (P4b); older/other
 * call sites wrap it as `{ services: [...] }`. Accept both (regression from the P6 lab E2E).
 */
export function planServices(plan: unknown): PlanService[] {
  if (Array.isArray(plan)) return plan as PlanService[];
  const wrapped = (plan as { services?: unknown } | null)?.services;
  return Array.isArray(wrapped) ? (wrapped as PlanService[]) : [];
}

function volumesOfPlan(plan: unknown): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const s of planServices(plan))
    out.set(
      s.service,
      (s.volumes ?? []).map((v) => v.name),
    );
  return out;
}

/** §10.2 policies: CRUD (If-Match), target validation, manual run. Scheduling lives in BackupSchedulerService. */
@Injectable()
export class BackupPoliciesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly runs: BackupRunsService,
  ) {}

  // ---------------------------------------------------------------- validation

  /** Resolves client targets to stored targets; 422 BACKUP_TARGET_INVALID with every issue. */
  async resolveTargets(
    serverId: string,
    input: BackupPolicyTargetInput[],
  ): Promise<BackupPolicyTarget[]> {
    const issues: Issue[] = [];
    const out: BackupPolicyTarget[] = [];
    for (const [i, t] of input.entries()) {
      const at = `targets.${i}`;
      if (t.type === 'paths') {
        t.paths.forEach((p, j) => {
          const v = pathViolation(p);
          if (v) issues.push({ path: `${at}.paths.${j}`, message: v });
        });
        out.push({
          type: 'paths',
          paths: t.paths,
          excludes: [...new Set([...t.excludes, ...agentExcludes(t.paths)])],
        });
        continue;
      }
      const app = await this.prisma.application.findUnique({
        where: { id: t.applicationId },
        include: { container: true },
      });
      if (!app || app.serverId !== serverId) {
        issues.push({
          path: `${at}.applicationId`,
          message: 'application not found on this server',
        });
        continue;
      }
      if (app.kind !== 'container' && app.kind !== 'compose') {
        issues.push({
          path: `${at}.applicationId`,
          message: 'only managed (container / compose) applications have volumes or DB services',
        });
        continue;
      }
      const latest =
        app.kind === 'compose'
          ? await this.prisma.composeAppVersion.findFirst({
              where: { applicationId: app.id },
              orderBy: { version: 'desc' },
            })
          : null;
      if (t.type === 'volume') {
        const names =
          app.kind === 'container'
            ? ((app.container?.volumes as Array<{ name: string }> | null) ?? []).map((v) => v.name)
            : [...volumesOfPlan(latest?.plan).values()].flat();
        if (!names.includes(t.volume))
          issues.push({
            path: `${at}.volume`,
            message: `application ${app.name} has no volume ${t.volume} (known: ${names.join(', ') || 'none'})`,
          });
        out.push({ type: 'volume', applicationId: app.id, app: app.name, volume: t.volume });
        continue;
      }
      // postgres / mysql: a compose DB service + an existing secret key holding its password
      if (app.kind !== 'compose' || !latest) {
        issues.push({
          path: `${at}.applicationId`,
          message: 'DB targets must reference a compose application with a DB service',
        });
        continue;
      }
      const services = planServices(latest.plan);
      const svc = services.find((s) => s.service === t.service);
      if (!svc)
        issues.push({
          path: `${at}.service`,
          message: `compose service ${t.service} not found (known: ${services.map((s) => s.service).join(', ') || 'none'})`,
        });
      const secret = await this.prisma.secret.findUnique({
        where: { applicationId_key: { applicationId: app.id, key: t.passwordSecretKey } },
        select: { id: true },
      });
      if (!secret)
        issues.push({
          path: `${at}.passwordSecretKey`,
          message: `application ${app.name} has no secret ${t.passwordSecretKey}`,
        });
      out.push({
        type: t.type,
        applicationId: app.id,
        app: app.name,
        service: t.service,
        database: t.database,
        user: t.user,
        passwordSecretKey: t.passwordSecretKey,
        ...(t.port ? { port: t.port } : {}),
      });
    }
    if (issues.length)
      throw new AppError(422, ERROR_CODES.BACKUP_TARGET_INVALID, 'Invalid backup targets', issues);
    return out;
  }

  private assertSchedule(cron: string, timezone: string): void {
    const err = scheduleError(cron, timezone);
    if (err)
      throw new AppError(422, ERROR_CODES.SCHEDULE_INVALID, err, [
        { path: 'schedule', message: err },
      ]);
  }

  // ---------------------------------------------------------------- access

  private async serverFor(user: AuthUser, serverId: string) {
    const s = await this.prisma.server.findUnique({ where: { id: serverId } });
    if (!s || !this.authz.can(user, 'fleet.read', serverScope(s)))
      throw AppError.notFound('Server');
    return s;
  }

  async load(user: AuthUser, id: string) {
    const p = await this.prisma.backupPolicy.findUnique({ where: { id } });
    const server = p
      ? await this.prisma.server.findUnique({
          where: { id: p.serverId },
          select: { id: true, environment: true, status: true },
        })
      : null;
    if (!p || p.deletedAt || !server || !this.authz.can(user, 'fleet.read', serverScope(server)))
      throw AppError.notFound('Backup policy');
    return { policy: p, server };
  }

  private async enforceWrite(
    user: AuthUser,
    server: { id: string; environment: string },
    action: string,
    targetId: string | null,
  ) {
    await this.authz.enforce(user, 'backups.create', serverScope(server), {
      action,
      targetType: 'backup_policy',
      targetId,
    });
  }

  // ---------------------------------------------------------------- views

  private async view(
    user: AuthUser,
    p: PolicyRow,
    server: { id: string; environment: string; status: string },
  ): Promise<BackupPolicyView> {
    const last = await this.prisma.backupRun.findFirst({
      where: { policyId: p.id, trigger: { not: 'safety' } },
      orderBy: { createdAt: 'desc' },
      select: { id: true, status: true, verification: true, finishedAt: true },
    });
    const can =
      server.status !== 'revoked' && this.authz.can(user, 'backups.create', serverScope(server));
    return {
      id: p.id,
      name: p.name,
      serverId: p.serverId,
      repositoryId: p.repositoryId,
      targets: targetsOf(p),
      schedule: { cron: p.scheduleCron, timezone: p.timezone },
      retention: p.retention as BackupPolicyView['retention'],
      retentionAppliedBy: 'maintenance',
      verify: p.verify as BackupPolicyView['verify'],
      helperImage: p.helperImage,
      enabled: p.enabled,
      nextRunAt: p.enabled ? (p.nextRunAt?.toISOString() ?? null) : null,
      lastScheduledAt: p.lastScheduledAt?.toISOString() ?? null,
      lastRun: last
        ? {
            id: last.id,
            status: last.status as BackupRunStatus,
            verification: last.verification as BackupVerification,
            finishedAt: last.finishedAt?.toISOString() ?? null,
          }
        : null,
      createdBy: p.createdBy,
      createdAt: p.createdAt.toISOString(),
      updatedAt: p.updatedAt.toISOString(),
      version: p.version,
      allowedActions: can ? (['edit', 'delete', 'run'] satisfies BackupPolicyAction[]) : [],
    };
  }

  async get(user: AuthUser, id: string): Promise<BackupPolicyView> {
    const { policy, server } = await this.load(user, id);
    return this.view(user, policy, server);
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) return new Paginated([], paginate(pq, 0));
    const servers = await this.prisma.server.findMany({
      where: visible,
      select: { id: true, environment: true, status: true },
    });
    const byId = new Map(servers.map((s) => [s.id, s]));
    const where: Prisma.BackupPolicyWhereInput = {
      AND: [
        { deletedAt: null, serverId: { in: [...byId.keys()] } },
        buildWhere(pq, {
          server_id: { prop: 'serverId', type: 'uuid' },
          repository_id: { prop: 'repositoryId', type: 'uuid' },
          enabled: { prop: 'enabled', type: 'boolean' },
          name: { prop: 'name', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }) as Prisma.BackupPolicyWhereInput,
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.backupPolicy.count({ where }),
      this.prisma.backupPolicy.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(
      await Promise.all(rows.map((r) => this.view(user, r, byId.get(r.serverId)!))),
      paginate(pq, total),
    );
  }

  // ---------------------------------------------------------------- CRUD

  async create(user: AuthUser, input: CreateBackupPolicyInput): Promise<BackupPolicyView> {
    const server = await this.serverFor(user, input.serverId);
    await this.enforceWrite(user, server, 'backup_policies.create', null);
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const repo = await this.prisma.backupRepository.findUnique({
      where: { id: input.repositoryId },
    });
    if (!repo) throw AppError.validation([{ path: 'repositoryId', message: 'unknown repository' }]);
    this.assertSchedule(input.schedule.cron, input.schedule.timezone);
    const targets = await this.resolveTargets(input.serverId, input.targets);
    const id = uuidv7();
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await tx.backupPolicy.create({
        data: {
          id,
          name: input.name,
          serverId: input.serverId,
          repositoryId: input.repositoryId,
          targets: targets as unknown as Prisma.InputJsonValue,
          scheduleCron: input.schedule.cron.trim().split(/\s+/).join(' '),
          timezone: input.schedule.timezone,
          retention: input.retention as Prisma.InputJsonValue,
          verify: input.verify as Prisma.InputJsonValue,
          helperImage: input.helperImage ?? null,
          enabled: input.enabled,
          nextRunAt: nextRunAfter(input.schedule.cron, input.schedule.timezone, now),
          createdBy: user.id,
          updatedBy: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'backup_policies.create',
          targetType: 'backup_policy',
          targetId: id,
          result: 'success',
          diff: { ...input, targets },
          metadata: {
            serverId: input.serverId,
            repositoryId: input.repositoryId,
            schedule: input.schedule,
            targets: targets.map((t) => t.type),
          },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  async update(
    user: AuthUser,
    id: string,
    input: UpdateBackupPolicyInput,
    ifMatch: number | undefined,
  ): Promise<BackupPolicyView> {
    const { policy, server } = await this.load(user, id);
    await this.enforceWrite(user, server, 'backup_policies.update', id);
    if (ifMatch !== undefined && ifMatch !== policy.version)
      throw AppError.conflict('Version mismatch', ERROR_CODES.VERSION_CONFLICT, {
        version: policy.version,
      });
    const cron = input.schedule?.cron ?? policy.scheduleCron;
    const tz = input.schedule?.timezone ?? policy.timezone;
    if (input.schedule) this.assertSchedule(cron, tz);
    if (input.repositoryId) {
      const repo = await this.prisma.backupRepository.findUnique({
        where: { id: input.repositoryId },
      });
      if (!repo)
        throw AppError.validation([{ path: 'repositoryId', message: 'unknown repository' }]);
    }
    const targets = input.targets
      ? await this.resolveTargets(policy.serverId, input.targets)
      : null;
    const reschedule = !!input.schedule || (input.enabled === true && !policy.enabled);
    const r = await this.prisma.$transaction(async (tx) => {
      const u = await tx.backupPolicy.updateMany({
        where: { id, version: policy.version, deletedAt: null },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.repositoryId !== undefined ? { repositoryId: input.repositoryId } : {}),
          ...(targets ? { targets: targets as unknown as Prisma.InputJsonValue } : {}),
          ...(input.schedule
            ? { scheduleCron: cron.trim().split(/\s+/).join(' '), timezone: tz }
            : {}),
          ...(input.retention ? { retention: input.retention as Prisma.InputJsonValue } : {}),
          ...(input.verify ? { verify: input.verify as Prisma.InputJsonValue } : {}),
          ...(input.helperImage !== undefined ? { helperImage: input.helperImage } : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          // re-enabling or re-scheduling never back-fills the slots it missed meanwhile
          ...(reschedule ? { nextRunAt: nextRunAfter(cron, tz, new Date()) } : {}),
          updatedBy: user.id,
          version: { increment: 1 },
        },
      });
      if (u.count === 1)
        await this.audit.record(
          {
            actorId: user.id,
            action: 'backup_policies.update',
            targetType: 'backup_policy',
            targetId: id,
            result: 'success',
            diff: input,
            metadata: { fields: Object.keys(input) },
          },
          tx,
        );
      return u.count;
    });
    if (r !== 1) throw AppError.conflict('Version mismatch', ERROR_CODES.VERSION_CONFLICT);
    return this.get(user, id);
  }

  /** Soft delete (runs + manifests are kept for restores); refused while a run is active. */
  async remove(user: AuthUser, id: string, ifMatch: number | undefined): Promise<void> {
    const { policy, server } = await this.load(user, id);
    await this.enforceWrite(user, server, 'backup_policies.delete', id);
    if (ifMatch !== undefined && ifMatch !== policy.version)
      throw AppError.conflict('Version mismatch', ERROR_CODES.VERSION_CONFLICT, {
        version: policy.version,
      });
    const active = await this.prisma.backupRun.findFirst({
      where: { policyId: id, status: { in: ['queued', 'running'] } },
      select: { id: true },
    });
    if (active)
      throw AppError.conflict('A run of this policy is active', ERROR_CODES.BACKUP_IN_PROGRESS, {
        runId: active.id,
      });
    await this.prisma.backupPolicy.update({
      where: { id },
      data: { deletedAt: new Date(), enabled: false, nextRunAt: null, version: { increment: 1 } },
    });
    await this.audit.record({
      actorId: user.id,
      action: 'backup_policies.delete',
      targetType: 'backup_policy',
      targetId: id,
      result: 'success',
    });
  }

  async runNow(user: AuthUser, id: string, idempotencyKey: string | undefined) {
    const { policy, server } = await this.load(user, id);
    await this.enforceWrite(user, server, 'backup_policies.run', id);
    const { run, created } = await this.runs.startRun({
      policy,
      trigger: 'manual',
      actorId: user.id,
      ...(idempotencyKey ? { idempotencyKey } : {}),
    });
    const detail = await this.runs.get(user, run.id);
    const { manifestEntries: _m, manifestPaginate: _p, verifications: _v, ...view } = detail;
    void _m;
    void _p;
    void _v;
    return { created, run: view };
  }
}
