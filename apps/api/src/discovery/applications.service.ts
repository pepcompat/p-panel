import { Injectable } from '@nestjs/common';
import {
  type AdoptionReview,
  type Application,
  type ApplicationBuildSummary,
  type BuildStatus,
  type ComposeAppConfig,
  type ComposePlanService,
  GIT_TOKEN_SECRET_KEY,
  type ChangeOwnershipInput,
  DEPLOYMENT_ACTIVE_STATUSES,
  ERROR_CODES,
  NGINX_REVISION_OPEN_STATUSES,
  type OwnershipMode,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import { toBuildConfig } from '../deploy/build-common';
import {
  composeActions,
  containerActions,
  type ContainerRuntimeState,
  toContainerConfig,
  tlsOf,
} from '../deploy/container-common';
import { routePath } from '../deploy/route-template';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import {
  allowedActionsFor,
  appInclude,
  type AppWithServer,
  driftFilesOf,
  enforceOnServer,
  modeIndex,
  nginxFilesOf,
  ownershipPermission,
  serverScope,
  toApplication,
} from './p3-common';

const OPEN = [...NGINX_REVISION_OPEN_STATUSES] as string[];
/** Open revisions cancelled by an ownership downgrade (in-flight validating/applying/reverting jobs are left to finish). */
const CANCEL_ON_DOWNGRADE = ['draft', 'valid', 'awaiting_approval', 'approved'];

@Injectable()
export class ApplicationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
  ) {}

  async views(user: AuthUser, rows: AppWithServer[]): Promise<Application[]> {
    if (rows.length === 0) return [];
    const open = await this.prisma.nginxConfigRevision.findMany({
      where: { applicationId: { in: rows.map((r) => r.id) }, status: { in: OPEN } },
      select: { applicationId: true },
    });
    const withOpen = new Set(open.map((o) => o.applicationId));
    const managed = rows.filter((r) => r.kind === 'container' || r.kind === 'compose');
    const containers = await this.containerContext(managed);
    const builds = await this.buildContext(rows.filter((r) => r.kind === 'container'));
    const composes = await this.composeContext(rows.filter((r) => r.kind === 'compose'));
    return rows.map((r) => {
      const c = containers.get(r.id);
      if (!c) return toApplication(r, allowedActionsFor(this.authz, user, r, withOpen.has(r.id)));
      if (r.kind === 'compose') {
        const v = composes.get(r.id);
        const state = { ...c.state, rollbackAvailable: v?.rollbackAvailable ?? false };
        return {
          ...toApplication(r, composeActions(this.authz, user, r, state)),
          compose: v
            ? {
                version: v.row.version,
                versionId: v.row.id,
                routeService: v.row.routeService,
                routePort: v.row.routePort,
                healthPath: v.row.healthPath,
                services: v.row.plan as unknown as ComposePlanService[],
                secretKeys: v.row.secretKeys,
                warnings: v.row.warnings as unknown as ComposeAppConfig['warnings'],
                currentDeploymentId: c.row.currentDeploymentId,
                previousDeploymentId: c.row.previousDeploymentId,
                containerName: c.state.current?.containerName ?? null,
                hostPort: c.state.current?.hostPort ?? null,
                routePath: routePath(r.name),
                tls: tlsOf(c.row),
                rollbackAvailable: v.rollbackAvailable,
                rollback: { dataRestored: false as const },
                createdAt: v.row.createdAt.toISOString(),
              }
            : undefined,
        };
      }
      const b = builds.get(r.id) ?? null;
      return {
        ...toApplication(r, containerActions(this.authz, user, r, c.state, { configured: !!b })),
        container: toContainerConfig(r.name, c.row, c.state),
        build: b,
      };
    });
  }

  /** P4b: build config + last build of container apps. */
  private async buildContext(rows: AppWithServer[]) {
    const out = new Map<string, ApplicationBuildSummary>();
    if (rows.length === 0) return out;
    const ids = rows.map((r) => r.id);
    const cfgs = await this.prisma.buildConfig.findMany({ where: { applicationId: { in: ids } } });
    if (cfgs.length === 0) return out;
    const git = new Set(
      (
        await this.prisma.secret.findMany({
          where: { applicationId: { in: ids }, key: GIT_TOKEN_SECRET_KEY },
          select: { applicationId: true },
        })
      ).map((x) => x.applicationId),
    );
    for (const c of cfgs) {
      const last = await this.prisma.build.findFirst({
        where: { applicationId: c.applicationId },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      });
      out.set(c.applicationId, {
        config: toBuildConfig(c, git.has(c.applicationId)),
        lastBuild: last
          ? {
              id: last.id,
              status: last.status as BuildStatus,
              commitSha: last.commitSha,
              image: last.image,
              finishedAt: last.finishedAt?.toISOString() ?? null,
            }
          : null,
      });
    }
    return out;
  }

  /** P4b: latest compose version + whether a previous successful plan exists (rollback). */
  private async composeContext(rows: AppWithServer[]) {
    const out = new Map<
      string,
      {
        row: NonNullable<Awaited<ReturnType<PrismaService['composeAppVersion']['findFirst']>>>;
        rollbackAvailable: boolean;
      }
    >();
    for (const r of rows) {
      const v = await this.prisma.composeAppVersion.findFirst({
        where: { applicationId: r.id },
        orderBy: { version: 'desc' },
      });
      if (!v) continue;
      const c = await this.prisma.containerApp.findUnique({ where: { applicationId: r.id } });
      const prev = c?.previousDeploymentId
        ? await this.prisma.deployment.findUnique({
            where: { id: c.previousDeploymentId },
            select: { status: true, plan: true },
          })
        : null;
      out.set(r.id, {
        row: v,
        rollbackAvailable:
          !!prev && prev.plan !== null && ['succeeded', 'rolled_back'].includes(prev.status),
      });
    }
    return out;
  }

  /** P4a: container config + runtime state (current container, rollback availability, deploy lock). */
  private async containerContext(rows: AppWithServer[]) {
    const out = new Map<
      string,
      {
        row: NonNullable<Awaited<ReturnType<PrismaService['containerApp']['findUnique']>>>;
        state: ContainerRuntimeState;
      }
    >();
    if (rows.length === 0) return out;
    const ids = rows.map((r) => r.id);
    const cs = await this.prisma.containerApp.findMany({ where: { applicationId: { in: ids } } });
    const depIds = cs.flatMap((c) =>
      [c.currentDeploymentId, c.previousDeploymentId].filter((x): x is string => !!x),
    );
    const deps = new Map(
      (
        await this.prisma.deployment.findMany({
          where: { id: { in: depIds } },
          select: { id: true, containerName: true, hostPort: true, containerRemovedAt: true },
        })
      ).map((d) => [d.id, d]),
    );
    const active = new Set(
      (
        await this.prisma.deployment.findMany({
          where: { applicationId: { in: ids }, status: { in: [...DEPLOYMENT_ACTIVE_STATUSES] } },
          select: { applicationId: true },
        })
      ).map((d) => d.applicationId),
    );
    for (const c of cs) {
      const cur = c.currentDeploymentId ? deps.get(c.currentDeploymentId) : undefined;
      const prev = c.previousDeploymentId ? deps.get(c.previousDeploymentId) : undefined;
      const current =
        cur && !cur.containerRemovedAt
          ? { containerName: cur.containerName, hostPort: cur.hostPort }
          : null;
      out.set(c.applicationId, {
        row: c,
        state: {
          current,
          rollbackAvailable:
            !!prev?.containerName &&
            !prev.containerRemovedAt &&
            prev.containerName !== current?.containerName,
          hasActiveDeployment: active.has(c.applicationId),
        },
      });
    }
    return out;
  }

  async view(user: AuthUser, row: AppWithServer): Promise<Application> {
    return (await this.views(user, [row]))[0]!;
  }

  /** Loads an application visible to the user (apps.read on its server scope), else 404. */
  async load(
    user: AuthUser,
    id: string,
    visibility: 'apps.read' | 'nginx.read' = 'apps.read',
  ): Promise<AppWithServer> {
    const row = await this.prisma.application.findUnique({ where: { id }, include: appInclude });
    if (!row || !this.authz.can(user, visibility, serverScope(row.server)))
      throw AppError.notFound('Application');
    return row;
  }

  async get(user: AuthUser, id: string): Promise<Application> {
    return this.view(user, await this.load(user, id));
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const scope = this.authz.serverWhere(user, 'apps.read');
    if (!scope) throw AppError.forbidden();
    const and: Prisma.ApplicationWhereInput[] = [
      { server: scope },
      buildWhere(
        pq,
        {
          server_id: { prop: 'serverId', type: 'uuid' },
          ownership_mode: { prop: 'ownershipMode', type: 'string' },
          kind: { prop: 'kind', type: 'string' },
          name: { prop: 'name', type: 'string' },
          flag_drift_detected: { prop: 'flagDriftDetected', type: 'boolean' },
          flag_manual_review: { prop: 'flagManualReview', type: 'boolean' },
          created_at: { prop: 'createdAt', type: 'date' },
        },
        ['environment'],
      ) as Prisma.ApplicationWhereInput,
    ];
    for (const f of pq.filters.filter((x) => x.field === 'environment')) {
      if (f.op !== 'eq' && f.op !== 'in')
        throw AppError.badRequest('environment supports eq and in');
      and.push({ server: { environment: { in: f.value.split(',').map((v) => v.trim()) } } });
    }
    if (pq.q)
      and.push({
        OR: [
          { name: { contains: pq.q, mode: 'insensitive' } },
          { domains: { has: pq.q.toLowerCase() } },
        ],
      });
    const where: Prisma.ApplicationWhereInput = { AND: and };
    const [total, rows] = await Promise.all([
      this.prisma.application.count({ where }),
      this.prisma.application.findMany({
        where,
        include: appInclude,
        orderBy: [{ [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(await this.views(user, rows), paginate(pq, total));
  }

  // ---------------------------------------------------------------- ownership (§6.2)

  async changeOwnership(
    user: AuthUser,
    id: string,
    input: ChangeOwnershipInput,
    ifMatch: number | undefined,
    stepUpHeader: string | undefined,
  ): Promise<Application> {
    const app = await this.load(user, id);
    if (app.kind === 'container' || app.kind === 'compose' || app.kind === 'gateway')
      throw AppError.conflict(
        'Container and gateway applications are always managed by pPanel',
        ERROR_CODES.OWNERSHIP_STEP_INVALID,
      );
    const from = app.ownershipMode as OwnershipMode;
    const to = input.toMode;
    const audit = { action: 'applications.ownership', targetType: 'application', targetId: id };
    if (to !== from)
      await this.authz.enforce(user, ownershipPermission(from, to), serverScope(app.server), audit);
    const step = modeIndex(to) - modeIndex(from);
    if (Math.abs(step) !== 1)
      throw new AppError(
        422,
        ERROR_CODES.OWNERSHIP_STEP_INVALID,
        'Ownership changes move exactly one tier at a time (discovered ↔ observed ↔ adopted ↔ managed)',
        { from, to },
      );
    if (app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const upgrade = step > 0;
    const writeTier = upgrade && (to === 'adopted' || to === 'managed');
    let stepUp = false;
    if (writeTier && app.server.environment === 'production') {
      this.auth.assertStepUp(user, stepUpHeader);
      stepUp = true;
    }
    if (writeTier && app.flagDriftDetected)
      throw AppError.conflict(
        'Configuration drift must be acknowledged before raising ownership',
        ERROR_CODES.DRIFT_REVIEW_REQUIRED,
        { driftFiles: driftFilesOf(app) },
      );
    let acknowledged: string[] = [];
    if (upgrade && to === 'adopted' && (app.flagManualReview || app.flagConflict)) {
      if (input.acknowledgeReasons !== true)
        throw new AppError(
          422,
          ERROR_CODES.MANUAL_REVIEW_REQUIRED,
          'This application needs manual review; resend with acknowledgeReasons: true after reviewing',
          {
            reasons: app.reasons,
            flags: { manualReview: app.flagManualReview, conflict: app.flagConflict },
          },
        );
      acknowledged = app.reasons.length ? app.reasons : ['conflict'];
    }
    if (upgrade && to === 'managed' && app.flagUnsupported)
      throw new AppError(
        422,
        ERROR_CODES.UNSUPPORTED_CONFIG,
        'Unsupported Nginx directives block the managed tier; keep adopted and migrate manually',
        { unsupportedDirectives: app.unsupportedDirectives },
      );

    const updated = await this.prisma.$transaction(async (tx) => {
      const r = await tx.application.updateMany({
        where: { id, ownershipMode: from, ...(ifMatch !== undefined ? { version: ifMatch } : {}) },
        data: { ownershipMode: to, version: { increment: 1 } },
      });
      if (r.count !== 1) {
        const cur = await tx.application.findUnique({ where: { id }, select: { version: true } });
        throw AppError.conflict(
          'Application was modified by someone else',
          ERROR_CODES.VERSION_CONFLICT,
          {
            currentVersion: cur?.version,
          },
        );
      }
      let cancelled = 0;
      if (!upgrade) {
        const c = await tx.nginxConfigRevision.updateMany({
          where: { applicationId: id, status: { in: CANCEL_ON_DOWNGRADE } },
          data: { status: 'cancelled', version: { increment: 1 } },
        });
        cancelled = c.count;
      }
      await tx.adoptionReview.create({
        data: {
          id: uuidv7(),
          applicationId: id,
          fromMode: from,
          toMode: to,
          actorId: user.id,
          reason: input.reason,
          acknowledgedReasons: acknowledged,
          stepUp,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          ...audit,
          result: 'success',
          diff: { from, to, reason: input.reason },
          metadata: {
            from,
            to,
            acknowledgedReasons: acknowledged,
            stepUp,
            revisionsCancelled: cancelled,
          },
        },
        tx,
      );
      return tx.application.findUniqueOrThrow({ where: { id }, include: appInclude });
    });
    return this.view(user, updated);
  }

  async history(user: AuthUser, id: string): Promise<AdoptionReview[]> {
    await this.load(user, id);
    const rows = await this.prisma.adoptionReview.findMany({
      where: { applicationId: id },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    return rows.map((r) => ({
      id: r.id,
      applicationId: r.applicationId,
      fromMode: r.fromMode as OwnershipMode,
      toMode: r.toMode as OwnershipMode,
      actorId: r.actorId,
      reason: r.reason,
      acknowledgedReasons: r.acknowledgedReasons,
      stepUp: r.stepUp,
      createdAt: r.createdAt.toISOString(),
    }));
  }

  // ---------------------------------------------------------------- drift acknowledge (§6.4)

  async acknowledgeDrift(
    user: AuthUser,
    id: string,
    ifMatch: number | undefined,
  ): Promise<Application> {
    const app = await this.load(user, id);
    await enforceOnServer(
      this.authz,
      user,
      app.server,
      'apps.read',
      'nginx.write',
      { action: 'applications.drift_acknowledge', targetType: 'application', targetId: id },
      'Application',
    );
    if (!app.flagDriftDetected)
      throw AppError.conflict('No drift to acknowledge', ERROR_CODES.CONFLICT);
    let drift = driftFilesOf(app);
    if (drift.some((d) => d.currentSha256 === 'unknown')) {
      // checksum unknown (file missing / manual recovery): accept only what a newer scan observed
      const latest = await this.prisma.discoveryScan.findFirst({
        where: {
          serverId: app.serverId,
          status: 'completed',
          NOT: { configFiles: { equals: [] } },
        },
        orderBy: { completedAt: 'desc' },
      });
      const seen = new Map(
        ((latest?.configFiles ?? []) as Array<{ path: string; sha256: string }>).map((f) => [
          f.path,
          f.sha256,
        ]),
      );
      const aliasOf = (p: string) => nginxFilesOf(app).find((f) => f.resolvedPath === p)?.path ?? p;
      const unresolved: string[] = [];
      drift = drift.map((d) => {
        if (d.currentSha256 !== 'unknown') return d;
        const cur = seen.get(d.path) ?? seen.get(aliasOf(d.path));
        const fresh =
          !!latest?.completedAt &&
          (!d.detectedAt || latest.completedAt.getTime() > new Date(d.detectedAt).getTime());
        if (!cur || !fresh) unresolved.push(d.path);
        if (!fresh) return d;
        return cur ? { ...d, currentSha256: cur } : d;
      });
      if (unresolved.length)
        throw AppError.conflict(
          'Current checksum unknown: run a new discovery scan before acknowledging',
          ERROR_CODES.DRIFT_REVIEW_REQUIRED,
          { rescanRequired: true, paths: unresolved },
        );
    }
    const files = nginxFilesOf(app).map((f) => {
      const d = drift.find(
        (x) => x.path === f.path || (f.resolvedPath && x.path === f.resolvedPath),
      );
      return d ? { ...f, lastKnownSha256: d.currentSha256 } : f;
    });
    const updated = await this.prisma.$transaction(async (tx) => {
      const r = await tx.application.updateMany({
        where: {
          id,
          flagDriftDetected: true,
          ...(ifMatch !== undefined ? { version: ifMatch } : {}),
        },
        data: {
          flagDriftDetected: false,
          driftFiles: [],
          nginxFiles: files as unknown as Prisma.InputJsonValue,
          version: { increment: 1 },
        },
      });
      if (r.count !== 1)
        throw AppError.conflict(
          'Application was modified by someone else',
          ERROR_CODES.VERSION_CONFLICT,
        );
      await this.audit.record(
        {
          actorId: user.id,
          action: 'applications.drift_acknowledge',
          targetType: 'application',
          targetId: id,
          result: 'success',
          diff: { drift },
          metadata: { files: drift.map((d) => ({ path: d.path, accepted: d.currentSha256 })) },
        },
        tx,
      );
      return tx.application.findUniqueOrThrow({ where: { id }, include: appInclude });
    });
    return this.view(user, updated);
  }
}
