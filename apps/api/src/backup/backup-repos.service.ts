import { Inject, Injectable } from '@nestjs/common';
import {
  type BackupRecoveryExport,
  type BackupRepository as BackupRepositoryView,
  type BackupRepositoryAction,
  type CreateBackupRepositoryInput,
  ERROR_CODES,
  type MaintenanceKind,
  type MaintenanceReportInput,
  MAINTENANCE_KINDS,
  type MaintenanceStatus,
  type PutBackupRepoAccessInput,
  type updateBackupRepositorySchema,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import type { z } from 'zod';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { safeEqual } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { redact } from '../common/logger';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { serverScope } from '../discovery/p3-common';
import { boundJson } from './backup-common';
import { BackupCredentialsService, repoUrl } from './backup-credentials.service';

const MAINTENANCE_NOTE =
  'Retention (restic forget --prune) and the offsite copy run from the separate maintenance identity ' +
  '(scripts/backup/maintenance.sh). Agents and the Center are append-only and cannot delete snapshots.';

type RepoRow = Prisma.BackupRepositoryGetPayload<{
  include: {
    access: { include: { server: { select: { id: true; name: true; environment: true } } } };
  };
}>;

/**
 * §10.1 repositories + per-server access. Passwords are never returned except by the step-up
 * recovery export (offline escrow, audited, `Cache-Control: no-store`).
 */
@Injectable()
export class BackupReposService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly creds: BackupCredentialsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  private actions(user: AuthUser): BackupRepositoryAction[] {
    return this.authz.can(user, 'policies.manage')
      ? ['edit', 'manage_access', 'mark_initialized', 'recovery_export']
      : [];
  }

  private async latestReports(repoId: string): Promise<Map<string, MaintenanceStatus[]>> {
    const rows = await this.prisma.$queryRaw<
      Array<{
        server_user: string;
        kind: string;
        ok: boolean;
        finished_at: Date;
        received_at: Date;
        detail: unknown;
      }>
    >`SELECT DISTINCT ON (server_user, kind) server_user, kind, ok, finished_at, received_at, detail
        FROM backup_maintenance_reports
       WHERE repository_id = ${repoId}::uuid
       ORDER BY server_user, kind, finished_at DESC, received_at DESC`;
    const out = new Map<string, MaintenanceStatus[]>();
    for (const r of rows) {
      const list = out.get(r.server_user) ?? [];
      list.push({
        kind: r.kind as MaintenanceKind,
        serverUser: r.server_user,
        ok: r.ok,
        finishedAt: r.finished_at.toISOString(),
        receivedAt: r.received_at.toISOString(),
        detail: (r.detail ?? {}) as Record<string, unknown>,
      });
      out.set(r.server_user, list);
    }
    return out;
  }

  private async view(user: AuthUser, r: RepoRow): Promise<BackupRepositoryView> {
    const reports = await this.latestReports(r.id);
    const visible = r.access.filter((a) =>
      this.authz.can(user, 'fleet.read', serverScope(a.server)),
    );
    return {
      id: r.id,
      name: r.name,
      kind: 'rest',
      baseUrl: r.baseUrl,
      offsite: (r.offsite as BackupRepositoryView['offsite']) ?? null,
      maintenanceNote: MAINTENANCE_NOTE,
      servers: visible.map((a) => ({
        serverId: a.serverId,
        serverName: a.server.name,
        restUser: a.restUser,
        url: repoUrl(r.baseUrl, a.restUser),
        initialized: !!a.initializedAt,
        initializedAt: a.initializedAt?.toISOString() ?? null,
        restPassword: { set: true },
        repoPassword: { set: true },
        maintenance: (reports.get(a.restUser) ?? []).sort(
          (x, y) => MAINTENANCE_KINDS.indexOf(x.kind) - MAINTENANCE_KINDS.indexOf(y.kind),
        ),
      })),
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      version: r.version,
      allowedActions: this.actions(user),
    };
  }

  private include = {
    access: {
      include: { server: { select: { id: true, name: true, environment: true } } },
      orderBy: { createdAt: 'asc' as const },
    },
  };

  async load(id: string): Promise<RepoRow> {
    const r = await this.prisma.backupRepository.findUnique({
      where: { id },
      include: this.include,
    });
    if (!r) throw AppError.notFound('Backup repository');
    return r;
  }

  async list(user: AuthUser): Promise<BackupRepositoryView[]> {
    const rows = await this.prisma.backupRepository.findMany({
      include: this.include,
      orderBy: { createdAt: 'asc' },
    });
    return Promise.all(rows.map((r) => this.view(user, r)));
  }

  async get(user: AuthUser, id: string): Promise<BackupRepositoryView> {
    return this.view(user, await this.load(id));
  }

  private async manage(user: AuthUser, action: string, targetId: string | null) {
    await this.authz.enforce(user, 'policies.manage', undefined, {
      action,
      targetType: 'backup_repository',
      targetId,
    });
  }

  async create(user: AuthUser, input: CreateBackupRepositoryInput): Promise<BackupRepositoryView> {
    await this.manage(user, 'backup_repositories.create', null);
    this.assertHttps(input.baseUrl);
    const id = uuidv7();
    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.backupRepository.create({
          data: {
            id,
            name: input.name,
            kind: 'rest',
            baseUrl: input.baseUrl.replace(/\/+$/, ''),
            offsite: (input.offsite ?? undefined) as Prisma.InputJsonValue | undefined,
            createdBy: user.id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'backup_repositories.create',
            targetType: 'backup_repository',
            targetId: id,
            result: 'success',
            diff: input,
            metadata: { name: input.name, baseUrl: input.baseUrl, offsite: !!input.offsite },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e)) throw AppError.conflict('Repository name already exists');
      throw e;
    }
    return this.get(user, id);
  }

  private assertHttps(baseUrl: string): void {
    if (this.config.isProduction && !baseUrl.startsWith('https://'))
      throw AppError.validation(
        [{ path: 'baseUrl', message: 'rest-server must be https:// in production' }],
        'Invalid repository',
      );
  }

  async update(
    user: AuthUser,
    id: string,
    input: z.infer<typeof updateBackupRepositorySchema>,
    ifMatch: number | undefined,
  ): Promise<BackupRepositoryView> {
    await this.manage(user, 'backup_repositories.update', id);
    const cur = await this.load(id);
    if (ifMatch !== undefined && ifMatch !== cur.version)
      throw AppError.conflict('Version mismatch', ERROR_CODES.VERSION_CONFLICT, {
        version: cur.version,
      });
    if (input.baseUrl) this.assertHttps(input.baseUrl);
    const r = await this.prisma.backupRepository.updateMany({
      where: { id, version: cur.version },
      data: {
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.baseUrl !== undefined ? { baseUrl: input.baseUrl.replace(/\/+$/, '') } : {}),
        ...(input.offsite !== undefined
          ? { offsite: (input.offsite ?? null) as Prisma.InputJsonValue }
          : {}),
        version: { increment: 1 },
      },
    });
    if (r.count !== 1) throw AppError.conflict('Version mismatch', ERROR_CODES.VERSION_CONFLICT);
    await this.audit.record({
      actorId: user.id,
      action: 'backup_repositories.update',
      targetType: 'backup_repository',
      targetId: id,
      result: 'success',
      diff: input,
      metadata: { fields: Object.keys(input) },
    });
    return this.get(user, id);
  }

  private async serverFor(user: AuthUser, serverId: string) {
    const s = await this.prisma.server.findUnique({ where: { id: serverId } });
    if (!s || !this.authz.can(user, 'fleet.read', serverScope(s)))
      throw AppError.notFound('Server');
    return s;
  }

  /** Create/rotate a server's rest-server credentials (repo password generated unless given; kept on rotation). */
  async putAccess(
    user: AuthUser,
    id: string,
    serverId: string,
    input: PutBackupRepoAccessInput,
  ): Promise<BackupRepositoryView> {
    await this.manage(user, 'backup_repositories.access_set', id);
    await this.load(id);
    const server = await this.serverFor(user, serverId);
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const existing = await this.creds.access(id, serverId);
    const repoPassword = input.repoPassword ?? null;
    const restEnc = this.creds.encrypt(id, serverId, 'rest', input.restPassword);
    const repoEnc =
      repoPassword !== null
        ? this.creds.encrypt(id, serverId, 'repo', repoPassword)
        : (existing?.repoPasswordEnc ??
          this.creds.encrypt(id, serverId, 'repo', this.creds.generateRepoPassword()));
    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.backupRepoAccess.upsert({
          where: { repositoryId_serverId: { repositoryId: id, serverId } },
          create: {
            repositoryId: id,
            serverId,
            restUser: input.restUser,
            restPasswordEnc: restEnc,
            repoPasswordEnc: repoEnc,
            createdBy: user.id,
          },
          update: {
            restUser: input.restUser,
            restPasswordEnc: restEnc,
            repoPasswordEnc: repoEnc,
            // a new user/password pair means a different private repo path → must be initialised again
            ...(existing && existing.restUser !== input.restUser
              ? { initializedAt: null, initializedBy: null }
              : {}),
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'backup_repositories.access_set',
            targetType: 'backup_repository',
            targetId: id,
            result: 'success',
            metadata: {
              serverId,
              restUser: input.restUser,
              repoPasswordSource:
                repoPassword !== null ? 'operator' : existing ? 'kept' : 'generated',
              rotated: !!existing,
            },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict('restUser is already used by another server in this repository');
      throw e;
    }
    return this.get(user, id);
  }

  async markInitialized(
    user: AuthUser,
    id: string,
    serverId: string,
    initialized: boolean,
  ): Promise<BackupRepositoryView> {
    await this.manage(user, 'backup_repositories.initialized', id);
    await this.serverFor(user, serverId);
    const r = await this.prisma.backupRepoAccess.updateMany({
      where: { repositoryId: id, serverId },
      data: initialized
        ? { initializedAt: new Date(), initializedBy: user.id }
        : { initializedAt: null, initializedBy: null },
    });
    if (r.count !== 1) throw AppError.notFound('Repository access');
    await this.audit.record({
      actorId: user.id,
      action: 'backup_repositories.initialized',
      targetType: 'backup_repository',
      targetId: id,
      result: 'success',
      metadata: { serverId, initialized },
    });
    return this.get(user, id);
  }

  /** The only API that returns repo passwords: policies.manage (global) + step-up, audited, never logged. */
  async recoveryExport(
    user: AuthUser,
    id: string,
    stepUp: string | undefined,
  ): Promise<BackupRecoveryExport> {
    await this.manage(user, 'backup_repositories.recovery_export', id);
    try {
      this.auth.assertStepUp(user, stepUp);
    } catch (e) {
      await this.audit.record({
        actorId: user.id,
        action: 'backup_repositories.recovery_export',
        targetType: 'backup_repository',
        targetId: id,
        result: 'denied',
        metadata: { reason: 'step_up_required' },
      });
      throw e;
    }
    const r = await this.load(id);
    const servers: BackupRecoveryExport['servers'] = [];
    for (const a of r.access) {
      servers.push({
        serverId: a.serverId,
        serverName: a.server.name,
        restUser: a.restUser,
        url: repoUrl(r.baseUrl, a.restUser),
        repoPassword: this.creds.decrypt(a, 'repo'),
      });
    }
    await this.audit.record({
      actorId: user.id,
      action: 'backup_repositories.recovery_export',
      targetType: 'backup_repository',
      targetId: id,
      result: 'success',
      metadata: { servers: servers.map((s) => s.serverId), count: servers.length },
    });
    return {
      repositoryId: r.id,
      name: r.name,
      baseUrl: r.baseUrl,
      exportedAt: new Date().toISOString(),
      servers,
      note: 'Store offline (sealed / age-encrypted to an operator key). Without these passwords the snapshots cannot be decrypted. The rest-server credentials can be reset on the backup host and are not included.',
    };
  }

  // ---------------------------------------------------------------- maintenance reports (report token)

  /** Constant-time bearer check; 404 when the token is not configured (endpoint disabled). */
  assertReportToken(authorization: string | undefined): void {
    const expected = this.config.backupReportToken;
    if (!expected) throw AppError.notFound('Route');
    const m = /^Bearer\s+(\S+)$/i.exec(authorization ?? '');
    if (!m || !safeEqual(m[1]!, expected)) throw AppError.unauthenticated();
  }

  async report(input: MaintenanceReportInput): Promise<{ id: string; accepted: true }> {
    const repo = await this.prisma.backupRepository.findUnique({
      where: { id: input.repositoryId },
      include: { access: { select: { restUser: true } } },
    });
    if (!repo) throw AppError.notFound('Backup repository');
    // the maintenance identity may also report on the Center's own repo user (`center`)
    if (input.serverUser !== 'center' && !repo.access.some((a) => a.restUser === input.serverUser))
      throw AppError.notFound('Repository server user');
    const id = uuidv7();
    await this.prisma.backupMaintenanceReport.create({
      data: {
        id,
        repositoryId: input.repositoryId,
        serverUser: input.serverUser,
        kind: input.kind,
        ok: input.ok,
        finishedAt: new Date(input.finishedAt),
        detail: boundJson(redact(input.detail), 8192) as Prisma.InputJsonValue,
      },
    });
    await this.audit.record({
      actorType: 'system',
      action: 'backup_maintenance.report',
      targetType: 'backup_repository',
      targetId: input.repositoryId,
      result: input.ok ? 'success' : 'failure',
      metadata: { serverUser: input.serverUser, kind: input.kind, ok: input.ok },
    });
    return { id, accepted: true };
  }
}
