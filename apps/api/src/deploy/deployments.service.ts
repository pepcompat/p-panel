import { Injectable, type OnModuleInit } from '@nestjs/common';
import {
  APPROVAL_TTL_MINUTES,
  type CreateDeploymentInput,
  DEPLOYMENT_ACTIVE_STATUSES,
  DEPLOYMENT_CANCELLABLE_STATUSES,
  type Deployment,
  type DeploymentAction,
  type DeploymentStatus,
  type DeploymentStepName,
  type DeploymentTrigger,
  ERROR_CODES,
  isDigestPinned,
  MANAGED_PORT_MAX,
  MANAGED_PORT_MIN,
  type PreflightCheck,
  type SourceRef,
} from '@ppanel/shared-contracts';
import type {
  Deployment as DeploymentRow,
  DeploymentStep as StepRow,
  OperationApproval,
  Prisma,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { containsKnownValue, logger, redactKnownValues } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { ApplicationsService } from '../discovery/applications.service';
import { DiscoveryService } from '../discovery/discovery.service';
import { appInclude, type AppWithServer, nginxFilesOf, serverScope } from '../discovery/p3-common';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import { contentSha256 } from '../nginx/nginx-plan';
import { stableHash } from '../common/crypto';
import {
  composeApplyParamsOf,
  composePlanDigest,
  type ComposeServiceResult,
  healthStatusOf,
  planOf,
  type StoredComposePlan,
} from './compose-plan';
import {
  containerNameFor,
  deploymentPlanHash,
  envOf,
  healthcheckOf,
  resourcesOf,
  tlsOf,
  volumesOf,
} from './container-common';
import { firstFailure, PreflightService } from './preflight.service';
import { renderRoute, routePath } from './route-template';
import { type ContainerAppRef, loadContainerApp, SecretsService } from './secrets.service';

const ACTIVE = [...DEPLOYMENT_ACTIVE_STATUSES] as string[];
const CANCELLABLE = [...DEPLOYMENT_CANCELLABLE_STATUSES] as string[];
const RUN_TTL_SEC = 1800;
const CONTAINER_TTL_SEC = 600;
const ROUTE_TTL_SEC = 600;
/** Old containers kept for rollback besides the serving one. */
export const KEEP_OLD_CONTAINERS = 2;
/** Agent codes after which no candidate container exists (port can be released). */
const NOTHING_CREATED = new Set([
  'CANDIDATE_UNHEALTHY', // agent removes the candidate (details.removed = true)
  'IMAGE_PULL_FAILED',
  'SECRETS_UNAVAILABLE',
  'DOCKER_UNAVAILABLE',
  'CANCELLED',
  'TTL_EXPIRED',
  'REJECTED_EXPIRED',
  'REJECTED_UNKNOWN_TYPE',
  'REJECTED_WRONG_SERVER',
  'REJECTED_INVALID_PARAMS',
  'REJECTED_INVALID_GRANT',
]);

type DeploymentFull = DeploymentRow & { steps: StepRow[] };
type Actor = { user: AuthUser | null; id: string | null };

function errOf(job: FinishedJob): { code: string; message: string; details?: unknown } {
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
    ...(e.details !== undefined ? { details: e.details } : {}),
  };
}

/** What the rendered route depends on (besides the deployment-id comment). */
function routeKeyOf(
  domains: string[],
  tls: { certPath: string; keyPath: string } | null,
  hostPort: number,
): string {
  return stableHash({ domains: [...domains].sort(), tls, hostPort });
}

/** Deployment read model `compose` (plan + per-service results). */
function composeView(d: DeploymentRow): Deployment['compose'] {
  const plan = planOf(d.plan);
  if (!plan) return null;
  const results = Array.isArray(d.serviceResults)
    ? (d.serviceResults as unknown as ComposeServiceResult[])
    : [];
  return {
    versionId: plan.versionId,
    version: plan.version,
    routeService: plan.routeService,
    services: plan.services.map((s) => {
      const r = results.find((x) => x.service === s.service);
      return {
        service: s.service,
        image: s.resolvedImage,
        sourceImage: s.image,
        specHash: s.specHash,
        name: r?.name ?? s.name,
        plannedAction: s.plannedAction,
        action: r?.action ?? null,
        previousName: r?.previousName ?? s.previousName ?? null,
        hostPort: r?.hostPort ?? null,
        health: healthStatusOf(r?.health ?? null),
      };
    }),
    dataRestored: false,
  };
}

function logTailOf(details: unknown): string[] {
  const t = (details as { logTail?: unknown } | null)?.logTail;
  return Array.isArray(t) ? t.filter((x): x is string => typeof x === 'string').slice(-50) : [];
}

export interface CreateDeploymentOptions {
  /** pre-generated id (compose: container names derive from it) */
  id?: string;
  image: string;
  /** P4b: build that produced the image */
  buildId?: string;
  /** P4b compose: resolved plan (digests + spec hashes) */
  compose?: StoredComposePlan;
  /** rollback: deployment whose plan/container is being restored */
  rollbackOfDeploymentId?: string;
  trigger: DeploymentTrigger;
  sourceRef?: SourceRef;
  reason?: string;
  idempotencyKey?: string;
  commitSha?: string;
  webhookDeliveryId?: string;
  /**
   * P6: the deployment re-applies the current plan as the `start_app` step of an approved in-place
   * restore — the restore's own approval (approver ≠ creator, step-up, planHash, single use) covers it.
   */
  preApprovedByRestoreId?: string;
}

/**
 * Deployment orchestrator (§7.3). Durable: every transition is a compare-and-set on Postgres rows,
 * driven by job completion hooks (idempotent per job) and repaired by the sweeper's reconcile pass,
 * so an API restart in the middle of a deployment resumes from the database.
 */
@Injectable()
export class DeploymentsService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly apps: ApplicationsService,
    private readonly discovery: DiscoveryService,
    private readonly secrets: SecretsService,
    private readonly preflight: PreflightService,
  ) {}

  onModuleInit(): void {
    for (const type of [
      'container.run_candidate',
      'container.start',
      'container.stop',
      'container.remove',
      'nginx.apply',
      'compose.apply',
    ])
      this.hooks.register(type, (j) => this.onJobFinished(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  // ---------------------------------------------------------------- views

  private allowedActions(user: AuthUser, d: DeploymentRow, app: AppWithServer): DeploymentAction[] {
    if (app.server.status === 'revoked') return [];
    const scope = serverScope(app.server);
    const out: DeploymentAction[] = [];
    if (
      d.status === 'awaiting_approval' &&
      this.authz.can(user, 'approvals.decide', scope) &&
      d.createdBy !== user.id
    )
      out.push('approve');
    if (CANCELLABLE.includes(d.status) && this.authz.can(user, 'apps.deploy', scope))
      out.push('cancel');
    return out;
  }

  toView(
    user: AuthUser,
    d: DeploymentFull,
    app: AppWithServer,
    approvals: OperationApproval[],
  ): Deployment {
    const latest = approvals.find((a) => a.subjectId === d.id && !a.invalidatedAt) ?? null;
    return {
      id: d.id,
      applicationId: d.applicationId,
      serverId: d.serverId,
      number: d.number,
      trigger: d.trigger as DeploymentTrigger,
      image: d.image,
      sourceRef: (d.sourceRef as SourceRef | null) ?? null,
      reason: d.reason,
      status: d.status as DeploymentStatus,
      preflight: (d.preflight as unknown as PreflightCheck[]) ?? [],
      steps: [...d.steps]
        .sort((a, b) => a.seq - b.seq)
        .map((s) => ({
          name: s.name as DeploymentStepName,
          status: s.status as Deployment['steps'][number]['status'],
          jobId: s.jobId,
          startedAt: s.startedAt?.toISOString() ?? null,
          finishedAt: s.finishedAt?.toISOString() ?? null,
          message: s.message,
          logTail: s.logTail,
          errorCode: s.errorCode,
        })),
      container:
        d.containerName && d.hostPort ? { name: d.containerName, hostPort: d.hostPort } : null,
      previousDeploymentId: d.previousDeploymentId,
      rollbackOfDeploymentId: d.rollbackOfDeploymentId,
      planHash: d.planHash,
      approval: {
        required: d.approvalRequired,
        approvedBy: latest?.approverId ?? null,
        approvedAt: latest?.approvedAt.toISOString() ?? null,
        expiresAt: latest?.expiresAt.toISOString() ?? null,
      },
      createdBy: d.createdBy,
      createdAt: d.createdAt.toISOString(),
      updatedAt: d.updatedAt.toISOString(),
      finishedAt: d.finishedAt?.toISOString() ?? null,
      error: (d.error as Deployment['error']) ?? null,
      allowedActions: this.allowedActions(user, d, app),
      version: d.version,
      buildId: d.buildId,
      ...(app.kind === 'compose' ? { compose: composeView(d) } : {}),
    };
  }

  private async approvalsFor(ids: string[]): Promise<OperationApproval[]> {
    if (ids.length === 0) return [];
    return this.prisma.operationApproval.findMany({
      where: { subjectType: 'deployment', subjectId: { in: ids } },
      orderBy: { approvedAt: 'desc' },
    });
  }

  private async loadDeployment(user: AuthUser, id: string) {
    const d = await this.prisma.deployment.findUnique({ where: { id }, include: { steps: true } });
    if (!d) throw AppError.notFound('Deployment');
    const app = await this.prisma.application.findUnique({
      where: { id: d.applicationId },
      include: appInclude,
    });
    if (!app || !this.authz.can(user, 'apps.read', serverScope(app.server)))
      throw AppError.notFound('Deployment');
    return { d, app };
  }

  async get(user: AuthUser, id: string): Promise<Deployment> {
    let { d, app } = await this.loadDeployment(user, id);
    const running = d.steps.filter((s) => s.status === 'running' && s.jobId);
    if (running.length) {
      for (const s of running) await this.reconcileStep(s);
      ({ d, app } = await this.loadDeployment(user, id));
    }
    return this.toView(user, d, app, await this.approvalsFor([d.id]));
  }

  async listForApp(user: AuthUser, appId: string, pq: ParsedQuery) {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId);
    return this.listWhere(user, pq, { applicationId: appId }, new Map([[app.id, app]]));
  }

  async listAll(user: AuthUser, pq: ParsedQuery) {
    const scope = this.authz.serverWhere(user, 'apps.read');
    if (!scope) throw AppError.forbidden();
    return this.listWhere(user, pq, { application: { server: scope } });
  }

  private async listWhere(
    user: AuthUser,
    pq: ParsedQuery,
    base: Prisma.DeploymentWhereInput,
    known = new Map<string, AppWithServer>(),
  ) {
    const where: Prisma.DeploymentWhereInput = {
      AND: [
        base,
        buildWhere(pq, {
          status: { prop: 'status', type: 'string' },
          server_id: { prop: 'serverId', type: 'uuid' },
          application_id: { prop: 'applicationId', type: 'uuid' },
          trigger: { prop: 'trigger', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }) as Prisma.DeploymentWhereInput,
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.deployment.count({ where }),
      this.prisma.deployment.findMany({
        where,
        include: { steps: true },
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    const missing = [...new Set(rows.map((r) => r.applicationId))].filter((id) => !known.has(id));
    if (missing.length)
      for (const a of await this.prisma.application.findMany({
        where: { id: { in: missing } },
        include: appInclude,
      }))
        known.set(a.id, a);
    const approvals = await this.approvalsFor(rows.map((r) => r.id));
    return new Paginated(
      rows.map((r) => this.toView(user, r, known.get(r.applicationId)!, approvals)),
      paginate(pq, total),
    );
  }

  // ---------------------------------------------------------------- planning

  async planHashFor(
    ref: ContainerAppRef,
    image: string,
    trigger: string,
    targetContainer?: string | null,
    compose?: StoredComposePlan | null,
  ): Promise<string> {
    const { versions } = await this.secrets.keyVersions(ref.app.id);
    return deploymentPlanHash({
      applicationId: ref.app.id,
      serverId: ref.app.serverId,
      // compose: the plan (every service digest + spec hash) is part of what gets approved
      image: compose ? `${image}|compose:${composePlanDigest(compose)}` : image,
      trigger,
      targetContainer,
      container: ref.container,
      domains: ref.app.domains,
      secretVersions: versions,
    });
  }

  async runPreflight(user: AuthUser, appId: string, image: string | undefined) {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId);
    await this.authz.enforce(user, 'apps.deploy', serverScope(ref.app.server), {
      action: 'deployments.preflight',
      targetType: 'application',
      targetId: appId,
    });
    const checks = await this.preflight.run({ app: ref.app, container: ref.container, image });
    return { ok: checks.every((c) => c.ok), checks };
  }

  // ---------------------------------------------------------------- create

  async enforceDeploy(user: AuthUser, ref: ContainerAppRef, action: string) {
    await this.authz.enforce(user, 'apps.deploy', serverScope(ref.app.server), {
      action,
      targetType: 'application',
      targetId: ref.app.id,
    });
    if (ref.app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
  }

  async createManual(
    user: AuthUser,
    appId: string,
    input: CreateDeploymentInput,
    idempotencyKey: string | undefined,
  ) {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.enforceDeploy(user, ref, 'deployments.create');
    if (idempotencyKey !== undefined && !/^[A-Za-z0-9_.:-]{8,128}$/.test(idempotencyKey))
      throw AppError.badRequest('Idempotency-Key must be 8-128 chars of [A-Za-z0-9_.:-]');
    if (!input.image)
      throw new AppError(
        422,
        ERROR_CODES.IMAGE_NOT_PINNED,
        'image is required (registry/repo@sha256:<64 hex>)',
      );
    const { row, created } = await this.create({ user, id: user.id }, ref, {
      image: input.image,
      trigger: 'manual',
      sourceRef: input.sourceRef,
      reason: input.reason,
      idempotencyKey,
      commitSha: input.sourceRef?.commitSha,
    });
    return { created, deployment: await this.get(user, row.id) };
  }

  async redeploy(user: AuthUser, appId: string, reason?: string) {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.enforceDeploy(user, ref, 'deployments.redeploy');
    const current = ref.container.currentDeploymentId
      ? await this.prisma.deployment.findUnique({
          where: { id: ref.container.currentDeploymentId },
        })
      : null;
    if (!current)
      throw AppError.conflict(
        'Application has no current deployment',
        ERROR_CODES.NO_CURRENT_DEPLOYMENT,
      );
    const { row } = await this.create({ user, id: user.id }, ref, {
      image: current.image,
      trigger: 'redeploy',
      sourceRef: (current.sourceRef as SourceRef | null) ?? undefined,
      reason,
      commitSha: current.commitSha ?? undefined,
    });
    return { deployment: await this.get(user, row.id) };
  }

  /**
   * Shared creation path (manual, redeploy, webhook). Preflight runs first; a failing check yields a
   * `failed` deployment with the check results and **no job**. Production → `awaiting_approval`.
   */
  async create(
    actor: Actor,
    ref: ContainerAppRef,
    opts: CreateDeploymentOptions,
  ): Promise<{ row: DeploymentRow; created: boolean }> {
    const { app, container } = ref;
    if (!isDigestPinned(opts.image))
      throw new AppError(
        422,
        ERROR_CODES.IMAGE_NOT_PINNED,
        'Image must be pinned by digest (registry/repo@sha256:<64 hex>)',
        { image: opts.image },
      );
    if (opts.idempotencyKey) {
      const existing = await this.prisma.deployment.findUnique({
        where: {
          applicationId_idempotencyKey: {
            applicationId: app.id,
            idempotencyKey: opts.idempotencyKey,
          },
        },
      });
      if (existing) {
        if (existing.image !== opts.image || existing.trigger !== opts.trigger)
          throw AppError.conflict(
            'Idempotency-Key was already used for a different request',
            ERROR_CODES.CONFLICT,
          );
        return { row: existing, created: false };
      }
    }
    const checks = await this.preflight.run({ app, container, image: opts.image });
    const lock = checks.find((c) => c.check === 'lock' && !c.ok);
    if (lock)
      throw AppError.conflict(lock.message, ERROR_CODES.DEPLOYMENT_IN_PROGRESS, lock.details);
    const failed = firstFailure(checks);
    const planHash = await this.planHashFor(
      ref,
      opts.image,
      opts.trigger,
      opts.trigger === 'rollback' && !opts.compose ? undefined : null,
      opts.compose,
    );
    const approvalRequired =
      app.server.environment === 'production' && !opts.preApprovedByRestoreId;
    const id = opts.id ?? uuidv7();
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        await this.lockApp(tx, app.id);
        const active = await tx.deployment.findFirst({
          where: { applicationId: app.id, status: { in: ACTIVE } },
          select: { id: true, status: true },
        });
        if (active)
          throw AppError.conflict(
            'Another deployment of this application is in progress',
            ERROR_CODES.DEPLOYMENT_IN_PROGRESS,
            { deploymentId: active.id, status: active.status },
          );
        const number = await this.nextNumber(tx, app.id);
        const status: DeploymentStatus = failed
          ? 'failed'
          : approvalRequired
            ? 'awaiting_approval'
            : 'queued';
        const d = await tx.deployment.create({
          data: {
            id,
            applicationId: app.id,
            serverId: app.serverId,
            number,
            trigger: opts.trigger,
            image: opts.image,
            sourceRef: (opts.sourceRef ?? undefined) as Prisma.InputJsonValue | undefined,
            reason: opts.reason ?? null,
            status,
            preflight: checks as unknown as Prisma.InputJsonValue,
            previousDeploymentId: container.currentDeploymentId,
            planHash,
            approvalRequired,
            idempotencyKey: opts.idempotencyKey ?? null,
            commitSha: opts.commitSha ?? null,
            webhookDeliveryId: opts.webhookDeliveryId ?? null,
            buildId: opts.buildId ?? null,
            rollbackOfDeploymentId: opts.rollbackOfDeploymentId ?? null,
            ...(opts.compose
              ? {
                  composeVersionId: opts.compose.versionId,
                  plan: opts.compose as unknown as Prisma.InputJsonValue,
                }
              : {}),
            createdBy: actor.id,
            ...(failed
              ? {
                  error: { code: failed.code ?? 'PREFLIGHT_FAILED', message: failed.message },
                  finishedAt: new Date(),
                }
              : {}),
          },
        });
        await this.addStep(tx, id, 'preflight', failed ? 'failed' : 'succeeded', {
          message: failed ? failed.message : 'All preflight checks passed',
          errorCode: failed?.code ?? null,
        });
        if (opts.compose && !failed)
          await this.addStep(tx, id, 'resolve_images', 'succeeded', {
            message: opts.compose.services
              .map((s) => `${s.service}: ${s.resolvedImage}`)
              .join('; ')
              .slice(0, 2000),
            data: {
              images: Object.fromEntries(
                opts.compose.services.map((s) => [s.service, s.resolvedImage]),
              ),
            },
          });
        await this.audit.record(
          {
            actorId: actor.id,
            ...(actor.id ? {} : { actorType: 'system' as const }),
            action: opts.trigger === 'rollback' ? 'deployments.rollback' : 'deployments.create',
            targetType: 'deployment',
            targetId: id,
            result: failed ? 'failure' : 'success',
            diff: { planHash, image: opts.image },
            metadata: {
              applicationId: app.id,
              serverId: app.serverId,
              trigger: opts.trigger,
              image: opts.image,
              planHash,
              status,
              ...(opts.commitSha ? { commitSha: opts.commitSha } : {}),
              ...(opts.buildId ? { buildId: opts.buildId } : {}),
              ...(opts.compose
                ? {
                    composeVersion: opts.compose.version,
                    images: Object.fromEntries(
                      opts.compose.services.map((s) => [s.service, s.resolvedImage]),
                    ),
                  }
                : {}),
              ...(opts.rollbackOfDeploymentId ? { rollbackOf: opts.rollbackOfDeploymentId } : {}),
              ...(opts.preApprovedByRestoreId ? { restoreId: opts.preApprovedByRestoreId } : {}),
              ...(failed
                ? { preflightFailed: checks.filter((c) => !c.ok).map((c) => c.code) }
                : {}),
            },
          },
          tx,
        );
        if (status === 'queued') await this.begin(tx, d, ref, actor.id);
        return d;
      });
      this.jobs.notify(app.serverId);
      return { row, created: true };
    } catch (e) {
      if (isUniqueViolation(e)) {
        if (opts.idempotencyKey) {
          const raced = await this.prisma.deployment.findUnique({
            where: {
              applicationId_idempotencyKey: {
                applicationId: app.id,
                idempotencyKey: opts.idempotencyKey,
              },
            },
          });
          if (raced) return { row: raced, created: false };
        }
        throw AppError.conflict(
          'Another deployment of this application is in progress',
          ERROR_CODES.DEPLOYMENT_IN_PROGRESS,
        );
      }
      throw e;
    }
  }

  /** Serializes deployment creation per application (row lock on container_apps). */
  private async lockApp(tx: Tx, appId: string): Promise<void> {
    await tx.$queryRaw`SELECT application_id FROM container_apps WHERE application_id = ${appId}::uuid FOR UPDATE`;
  }

  private async nextNumber(tx: Tx, appId: string): Promise<number> {
    const agg = await tx.deployment.aggregate({
      where: { applicationId: appId },
      _max: { number: true },
    });
    return (agg._max.number ?? 0) + 1;
  }

  private async addStep(
    tx: Tx,
    deploymentId: string,
    name: DeploymentStepName,
    status: StepRow['status'],
    extra: {
      jobId?: string | null;
      message?: string | null;
      errorCode?: string | null;
      logTail?: string[];
      data?: Record<string, unknown>;
    } = {},
  ): Promise<StepRow> {
    const agg = await tx.deploymentStep.aggregate({
      where: { deploymentId },
      _max: { seq: true },
    });
    const now = new Date();
    return tx.deploymentStep.create({
      data: {
        id: uuidv7(),
        deploymentId,
        seq: (agg._max.seq ?? 0) + 1,
        name,
        status,
        jobId: extra.jobId ?? null,
        startedAt: now,
        finishedAt: status === 'running' || status === 'pending' ? null : now,
        message: extra.message ?? null,
        errorCode: extra.errorCode ?? null,
        logTail: extra.logTail ?? [],
        data: (extra.data ?? {}) as Prisma.InputJsonValue,
      },
    });
  }

  /** Starts execution: candidate run (deploy/redeploy/webhook) or container.start (rollback). */
  private async begin(tx: Tx, d: DeploymentRow, ref: ContainerAppRef, actorId: string | null) {
    const { app, container } = ref;
    const hc = healthcheckOf(container);
    const plan = planOf(d.plan);
    if (plan) return this.beginCompose(tx, d, ref, plan, actorId);
    if (d.trigger === 'rollback') {
      const job = await this.jobs.createInternal(tx, {
        serverId: d.serverId,
        type: 'container.start',
        params: { app: app.name, name: d.containerName, hostPort: d.hostPort, healthcheck: hc },
        actorId,
        ttlSec: CONTAINER_TTL_SEC,
        metadata: { deploymentId: d.id, applicationId: app.id },
      });
      await this.move(tx, d.id, ['queued', 'awaiting_approval'], { status: 'starting' });
      await this.addStep(tx, d.id, 'start_target', 'running', {
        jobId: job.id,
        message: `Starting previous container ${d.containerName}`,
      });
      return job;
    }
    const hostPort = await this.allocatePort(tx, d.serverId, app.id, d.id);
    if (hostPort === null) {
      await this.move(tx, d.id, ['queued', 'awaiting_approval'], {
        status: 'failed',
        finishedAt: new Date(),
        error: { code: 'NO_PORT_AVAILABLE', message: 'No free managed host port on this server' },
      });
      await this.addStep(tx, d.id, 'pull_start', 'failed', {
        errorCode: 'NO_PORT_AVAILABLE',
        message: 'No free managed host port',
      });
      return null;
    }
    const name = containerNameFor(app.name, d.id);
    const { versions, registry } = await this.secrets.keyVersions(app.id);
    const job = await this.jobs.createInternal(tx, {
      serverId: d.serverId,
      type: 'container.run_candidate',
      params: {
        deploymentId: d.id,
        app: app.name,
        name,
        image: d.image,
        containerPort: container.containerPort,
        hostPort,
        // a key must not be both plain and secret (agent rejects it): the secret wins
        env: Object.fromEntries(Object.entries(envOf(container)).filter(([k]) => !(k in versions))),
        secretEnvKeys: Object.keys(versions).sort(),
        registryAuth: registry,
        volumes: volumesOf(container),
        resources: resourcesOf(container),
        healthcheck: hc,
      },
      actorId,
      ttlSec: RUN_TTL_SEC,
      metadata: { deploymentId: d.id, applicationId: app.id },
    });
    await tx.hostPortAllocation.update({
      where: { serverId_port: { serverId: d.serverId, port: hostPort } },
      data: { containerName: name },
    });
    await this.move(tx, d.id, ['queued', 'awaiting_approval'], {
      status: 'pulling',
      containerName: name,
      hostPort,
    });
    await this.addStep(tx, d.id, 'pull_start', 'running', {
      jobId: job.id,
      message: `Pulling ${d.image} and starting ${name} on 127.0.0.1:${hostPort}`,
    });
    return job;
  }

  /**
   * Compose: allocate a fresh 127.0.0.1 port for the route service (released again when the agent
   * keeps the running route container) and send the normalised plan as one `compose.apply` job.
   */
  private async beginCompose(
    tx: Tx,
    d: DeploymentRow,
    ref: ContainerAppRef,
    plan: StoredComposePlan,
    actorId: string | null,
  ) {
    const { app } = ref;
    const hostPort = await this.allocatePort(tx, d.serverId, app.id, d.id);
    if (hostPort === null) {
      await this.move(tx, d.id, ['queued', 'awaiting_approval'], {
        status: 'failed',
        finishedAt: new Date(),
        error: { code: 'NO_PORT_AVAILABLE', message: 'No free managed host port on this server' },
      });
      await this.addStep(tx, d.id, 'compose_apply', 'failed', {
        errorCode: 'NO_PORT_AVAILABLE',
        message: 'No free managed host port',
      });
      return null;
    }
    const route = plan.services.find((s) => s.service === plan.routeService)!;
    const { registry } = await this.secrets.keyVersions(app.id);
    const job = await this.jobs.createInternal(tx, {
      serverId: d.serverId,
      type: 'compose.apply',
      params: composeApplyParamsOf(d.id, app.name, plan, hostPort, registry),
      actorId,
      ttlSec: RUN_TTL_SEC,
      metadata: { deploymentId: d.id, applicationId: app.id },
    });
    await tx.hostPortAllocation.update({
      where: { serverId_port: { serverId: d.serverId, port: hostPort } },
      data: { containerName: route.name },
    });
    await this.move(tx, d.id, ['queued', 'awaiting_approval'], { status: 'pulling' });
    const changed = plan.services
      .filter((s) => s.plannedAction === 'replace')
      .map((s) => s.service);
    await this.addStep(tx, d.id, 'compose_apply', 'running', {
      jobId: job.id,
      message: changed.length
        ? `Applying compose v${plan.version}: ${changed.join(', ')} change (route candidate 127.0.0.1:${hostPort})`
        : `Applying compose v${plan.version}: no service changes expected`,
      data: { hostPort, routeName: route.name },
    });
    return job;
  }

  /** Lowest free managed port on the server (advisory lock serializes allocations per server). */
  private async allocatePort(
    tx: Tx,
    serverId: string,
    applicationId: string,
    deploymentId: string,
  ): Promise<number | null> {
    await tx.$queryRaw`SELECT 1 AS ok FROM (SELECT pg_advisory_xact_lock(hashtext(${`ports:${serverId}`}))) AS l`;
    const used = new Set(
      (await tx.hostPortAllocation.findMany({ where: { serverId }, select: { port: true } })).map(
        (r) => r.port,
      ),
    );
    for (let p = MANAGED_PORT_MIN; p <= MANAGED_PORT_MAX; p++) {
      if (used.has(p)) continue;
      await tx.hostPortAllocation.create({
        data: { serverId, port: p, applicationId, deploymentId, reason: 'container' },
      });
      return p;
    }
    return null;
  }

  private async releasePort(
    tx: Tx,
    serverId: string,
    port: number | null,
    containerName?: string | null,
  ) {
    if (port === null) return;
    await tx.hostPortAllocation.deleteMany({
      where: {
        serverId,
        port,
        ...(containerName ? { OR: [{ containerName }, { containerName: null }] } : {}),
      },
    });
  }

  /** Compare-and-set deployment transition. */
  private async move(
    tx: Tx,
    id: string,
    from: string[],
    data: Prisma.DeploymentUpdateManyMutationInput,
  ): Promise<boolean> {
    const r = await tx.deployment.updateMany({
      where: { id, status: { in: from } },
      data: { ...data, version: { increment: 1 } },
    });
    return r.count === 1;
  }

  private async moveOrThrow(
    tx: Tx,
    id: string,
    from: string[],
    data: Prisma.DeploymentUpdateManyMutationInput,
  ) {
    if (!(await this.move(tx, id, from, data)))
      throw AppError.conflict(
        'Deployment changed concurrently',
        ERROR_CODES.DEPLOYMENT_STATE_INVALID,
      );
  }

  // ---------------------------------------------------------------- approval / cancel

  private stateError(d: { status: string }, allowed: string[]) {
    return AppError.conflict(`Deployment is ${d.status}`, ERROR_CODES.DEPLOYMENT_STATE_INVALID, {
      status: d.status,
      allowed,
    });
  }

  private async refFor(appId: string): Promise<ContainerAppRef> {
    const app = await this.prisma.application.findUniqueOrThrow({
      where: { id: appId },
      include: appInclude,
    });
    const container = await this.prisma.containerApp.findUniqueOrThrow({
      where: { applicationId: appId },
    });
    return { app, container };
  }

  /**
   * Approve (`approvals.decide`, approver ≠ creator, X-Step-Up, `{planHash}`) and start immediately.
   * The approval is single-use (consumed by the job it starts) and bound to the planHash; any change to
   * image/config/domains/secret versions since the request makes the recomputed hash differ → 409.
   */
  async approve(user: AuthUser, id: string, planHash: string, stepUp: string | undefined) {
    const { d, app } = await this.loadDeployment(user, id);
    const audit = { action: 'deployments.approve', targetType: 'deployment', targetId: id };
    await this.authz.enforce(user, 'approvals.decide', serverScope(app.server), audit);
    if (d.createdBy === user.id) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason: 'approver_is_creator' },
      });
      throw AppError.forbidden(
        'The creator of a deployment cannot approve it',
        ERROR_CODES.APPROVER_IS_CREATOR,
      );
    }
    this.auth.assertStepUp(user, stepUp);
    if (d.status !== 'awaiting_approval') throw this.stateError(d, ['awaiting_approval']);
    if (!d.approvalRequired)
      throw AppError.conflict(
        'This deployment does not require approval',
        ERROR_CODES.APPROVAL_NOT_REQUIRED,
      );
    const ref = await this.refFor(d.applicationId);
    const plan = planOf(d.plan);
    const current = await this.planHashFor(
      ref,
      d.image,
      d.trigger,
      d.trigger === 'rollback' && !plan ? d.containerName : null,
      plan,
    );
    if (current !== d.planHash || planHash !== d.planHash)
      throw AppError.conflict(
        current !== d.planHash
          ? 'The plan changed since this deployment was requested; cancel it and create a new one'
          : 'planHash does not match the current plan',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        { planHash: d.planHash, ...(current !== d.planHash ? { currentPlanHash: current } : {}) },
      );
    const checks = await this.preflight.run({
      app: ref.app,
      container: ref.container,
      image: d.image,
      deploymentId: d.id,
      ...(d.trigger === 'rollback' && !plan
        ? { skip: ['secrets_present', 'port_alloc'] as const }
        : {}),
    } as Parameters<PreflightService['run']>[0]);
    const failed = firstFailure(checks);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      if (failed) {
        await this.moveOrThrow(tx, d.id, ['awaiting_approval'], {
          status: 'failed',
          preflight: checks as unknown as Prisma.InputJsonValue,
          finishedAt: now,
          error: { code: failed.code ?? 'PREFLIGHT_FAILED', message: failed.message },
        });
        await this.addStep(tx, d.id, 'preflight', 'failed', {
          message: `Re-check at approval: ${failed.message}`,
          errorCode: failed.code ?? null,
        });
        await this.audit.record(
          {
            actorId: user.id,
            ...audit,
            result: 'failure',
            metadata: { planHash, preflightFailed: failed.code },
          },
          tx,
        );
        return;
      }
      await tx.operationApproval.updateMany({
        where: { subjectType: 'deployment', subjectId: d.id, usedAt: null, invalidatedAt: null },
        data: { invalidatedAt: now },
      });
      const approval = await tx.operationApproval.create({
        data: {
          id: uuidv7(),
          subjectType: 'deployment',
          subjectId: d.id,
          approverId: user.id,
          planHash,
          approvedAt: now,
          expiresAt: new Date(now.getTime() + APPROVAL_TTL_MINUTES * 60_000),
        },
      });
      await tx.deployment.update({
        where: { id: d.id },
        data: { preflight: checks as unknown as Prisma.InputJsonValue },
      });
      const job = await this.begin(tx, d, ref, user.id);
      // single use: consumed atomically by the job it started
      const used = await tx.operationApproval.updateMany({
        where: {
          id: approval.id,
          usedAt: null,
          invalidatedAt: null,
          planHash: d.planHash,
          expiresAt: { gt: now },
        },
        data: { usedAt: now, usedByJobId: job?.id ?? null },
      });
      if (used.count !== 1)
        throw AppError.conflict('Approval is no longer valid', ERROR_CODES.APPROVAL_REQUIRED);
      await this.audit.record(
        {
          actorId: user.id,
          ...audit,
          result: 'success',
          diff: { planHash },
          metadata: { planHash, approvalId: approval.id, jobId: job?.id ?? null },
        },
        tx,
      );
    });
    this.jobs.notify(d.serverId);
    return this.get(user, id);
  }

  /** Cancel before route_switch. A queued/leased job is cancelled; a running one is cleaned up when it reports. */
  async cancel(user: AuthUser, id: string) {
    const { d, app } = await this.loadDeployment(user, id);
    await this.authz.enforce(user, 'apps.deploy', serverScope(app.server), {
      action: 'deployments.cancel',
      targetType: 'deployment',
      targetId: id,
    });
    if (!CANCELLABLE.includes(d.status)) throw this.stateError(d, CANCELLABLE);
    const now = new Date();
    const cancelledJobs: string[] = [];
    await this.prisma.$transaction(async (tx) => {
      await this.moveOrThrow(tx, d.id, CANCELLABLE, {
        status: 'cancelled',
        finishedAt: now,
        error: { code: 'CANCELLED', message: `Cancelled by ${user.email}` },
      });
      await tx.operationApproval.updateMany({
        where: { subjectType: 'deployment', subjectId: d.id, usedAt: null, invalidatedAt: null },
        data: { invalidatedAt: now },
      });
      for (const s of d.steps.filter((x) => x.status === 'running' && x.jobId)) {
        const r = await tx.job.updateMany({
          where: { id: s.jobId!, status: { in: ['queued', 'leased'] } },
          data: {
            status: 'cancelled',
            finishedAt: now,
            leaseTokenHash: null,
            error: { code: 'CANCELLED' },
          },
        });
        if (r.count === 1) {
          cancelledJobs.push(s.jobId!);
          await tx.deploymentStep.update({
            where: { id: s.id },
            data: { status: 'skipped', finishedAt: now, message: 'Cancelled before execution' },
          });
          if (s.name === 'pull_start') {
            await this.releasePort(tx, d.serverId, d.hostPort, d.containerName);
            await tx.deployment.update({ where: { id: d.id }, data: { containerRemovedAt: now } });
          }
          if (s.name === 'compose_apply') {
            const data = s.data as { hostPort?: number; routeName?: string };
            await this.releasePort(tx, d.serverId, data.hostPort ?? null, data.routeName);
          }
        }
      }
      await this.audit.record(
        {
          actorId: user.id,
          action: 'deployments.cancel',
          targetType: 'deployment',
          targetId: d.id,
          result: 'success',
          metadata: { from: d.status, cancelledJobs },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- rollback

  async rollback(user: AuthUser, appId: string, reason?: string) {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.enforceDeploy(user, ref, 'deployments.rollback');
    const { app, container } = ref;
    const prev = container.previousDeploymentId
      ? await this.prisma.deployment.findUnique({ where: { id: container.previousDeploymentId } })
      : null;
    const current = container.currentDeploymentId
      ? await this.prisma.deployment.findUnique({ where: { id: container.currentDeploymentId } })
      : null;
    if (
      !prev ||
      !prev.containerName ||
      !prev.hostPort ||
      prev.containerRemovedAt ||
      prev.containerName === current?.containerName
    )
      throw AppError.conflict(
        'The previous container no longer exists; redeploy its image instead',
        ERROR_CODES.ROLLBACK_UNAVAILABLE,
        prev ? { previousDeploymentId: prev.id, image: prev.image } : undefined,
      );
    const checks = await this.preflight.run({
      app,
      container,
      image: prev.image,
      skip: ['secrets_present', 'port_alloc'],
    });
    const lock = checks.find((c) => c.check === 'lock' && !c.ok);
    if (lock)
      throw AppError.conflict(lock.message, ERROR_CODES.DEPLOYMENT_IN_PROGRESS, lock.details);
    const failed = firstFailure(checks);
    const planHash = await this.planHashFor(ref, prev.image, 'rollback', prev.containerName);
    const approvalRequired = app.server.environment === 'production';
    const id = uuidv7();
    try {
      await this.prisma.$transaction(async (tx) => {
        await this.lockApp(tx, app.id);
        if (
          await tx.deployment.findFirst({
            where: { applicationId: app.id, status: { in: ACTIVE } },
          })
        )
          throw AppError.conflict(
            'Another deployment of this application is in progress',
            ERROR_CODES.DEPLOYMENT_IN_PROGRESS,
          );
        const status: DeploymentStatus = failed
          ? 'failed'
          : approvalRequired
            ? 'awaiting_approval'
            : 'queued';
        const d = await tx.deployment.create({
          data: {
            id,
            applicationId: app.id,
            serverId: app.serverId,
            number: await this.nextNumber(tx, app.id),
            trigger: 'rollback',
            image: prev.image,
            sourceRef: (prev.sourceRef ?? undefined) as Prisma.InputJsonValue | undefined,
            reason: reason ?? null,
            status,
            preflight: checks as unknown as Prisma.InputJsonValue,
            containerName: prev.containerName,
            hostPort: prev.hostPort,
            previousDeploymentId: current?.id ?? null,
            rollbackOfDeploymentId: prev.id,
            planHash,
            approvalRequired,
            commitSha: prev.commitSha,
            createdBy: user.id,
            ...(failed
              ? {
                  error: { code: failed.code ?? 'PREFLIGHT_FAILED', message: failed.message },
                  finishedAt: new Date(),
                }
              : {}),
          },
        });
        await this.addStep(tx, id, 'preflight', failed ? 'failed' : 'succeeded', {
          message: failed ? failed.message : 'All preflight checks passed',
          errorCode: failed?.code ?? null,
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'deployments.rollback',
            targetType: 'deployment',
            targetId: id,
            result: failed ? 'failure' : 'success',
            diff: { planHash },
            metadata: {
              applicationId: app.id,
              rollbackOf: prev.id,
              from: current?.id ?? null,
              container: prev.containerName,
              planHash,
              status,
            },
          },
          tx,
        );
        if (status === 'queued') await this.begin(tx, d, ref, user.id);
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'Another deployment of this application is in progress',
          ERROR_CODES.DEPLOYMENT_IN_PROGRESS,
        );
      throw e;
    }
    this.jobs.notify(app.serverId);
    return { deployment: await this.get(user, id) };
  }

  // ---------------------------------------------------------------- job hooks (idempotent)

  /** Scrubs any known secret value of the app from a finished job's stored result/error. */
  async scrubJob(job: FinishedJob, applicationId: string): Promise<FinishedJob> {
    const values = await this.secrets.knownValues(applicationId);
    if (!containsKnownValue({ r: job.result, e: job.error }, values)) return job;
    const result = redactKnownValues(job.result, values);
    const error = redactKnownValues(job.error, values);
    await this.prisma.job.update({
      where: { id: job.id },
      data: {
        result: (result ?? undefined) as Prisma.InputJsonValue | undefined,
        error: (error ?? undefined) as Prisma.InputJsonValue | undefined,
      },
    });
    logger.emit('warn', 'secret value scrubbed from job output', { jobId: job.id, type: job.type });
    return { ...job, result, error } as FinishedJob;
  }

  private async onJobFinished(rawJob: FinishedJob): Promise<void> {
    const step = await this.prisma.deploymentStep.findFirst({
      where: { jobId: rawJob.id },
      include: { deployment: true },
    });
    if (!step || step.status !== 'running') return;
    const job = await this.scrubJob(rawJob, step.deployment.applicationId);
    const notify = await this.prisma.$transaction(async (tx) => {
      const d = await tx.deployment.findUniqueOrThrow({ where: { id: step.deploymentId } });
      switch (step.name as DeploymentStepName) {
        case 'pull_start':
          return this.onCandidate(tx, step, d, job);
        case 'compose_apply':
          return this.onComposeApply(tx, step, d, job);
        case 'start_target':
          return this.onStartTarget(tx, step, d, job);
        case 'route_switch':
          return this.onRouteSwitch(tx, step, d, job);
        case 'stop_previous':
          return this.onStopPrevious(tx, step, d, job);
        case 'cleanup_stop':
          return this.onCleanupStop(tx, step, d, job);
        case 'cleanup_remove':
        case 'prune_remove':
          return this.onRemoved(tx, step, d, job);
        default:
          return false;
      }
    });
    if (notify) this.jobs.notify(step.deployment.serverId);
  }

  private async finishStep(
    tx: Tx,
    step: StepRow,
    ok: boolean,
    job: FinishedJob,
    extra: { message?: string; logTail?: string[] } = {},
  ): Promise<boolean> {
    const e = ok ? null : errOf(job);
    const r = await tx.deploymentStep.updateMany({
      where: { id: step.id, status: 'running' },
      data: {
        status: ok ? 'succeeded' : 'failed',
        finishedAt: new Date(),
        message: extra.message ?? (e ? `${e.code}: ${e.message}` : 'done'),
        errorCode: e?.code ?? null,
        ...(extra.logTail ? { logTail: extra.logTail } : {}),
      },
    });
    return r.count === 1;
  }

  private async systemAudit(tx: Tx, d: DeploymentRow, to: string, job: FinishedJob, extra = {}) {
    await this.audit.record(
      {
        actorType: 'system',
        action: 'deployments.status',
        targetType: 'deployment',
        targetId: d.id,
        result: ['succeeded', 'routing', 'starting'].includes(to) ? 'success' : 'failure',
        metadata: {
          from: d.status,
          to,
          jobId: job.id,
          jobType: job.type,
          jobStatus: job.status,
          ...(job.status !== 'succeeded' ? { errorCode: errOf(job).code } : {}),
          ...extra,
        },
      },
      tx,
    );
  }

  private async fail(
    tx: Tx,
    d: DeploymentRow,
    from: string[],
    job: FinishedJob,
    status = 'failed',
  ) {
    const e = errOf(job);
    const moved = await this.move(tx, d.id, from, {
      status,
      finishedAt: new Date(),
      error: { code: e.code, message: e.message } as Prisma.InputJsonValue,
    });
    if (moved) await this.systemAudit(tx, d, status, job);
    return moved;
  }

  private async onCandidate(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    if (job.status === 'succeeded') {
      const out = (job.result ?? {}) as {
        health?: { status?: string; attempts?: number; elapsedMs?: number };
        hostPort?: number;
      };
      if (!(await this.finishStep(tx, step, true, job, { message: 'Candidate started' })))
        return false;
      await this.addStep(tx, d.id, 'health_check', 'succeeded', {
        message: `Healthy (${out.health?.attempts ?? '?'} attempts, ${out.health?.elapsedMs ?? '?'} ms)`,
        jobId: job.id,
      });
      if (d.status === 'pulling') {
        await this.move(tx, d.id, ['pulling'], { status: 'routing' });
        await this.systemAudit(tx, d, 'routing', job);
        await this.startRouteSwitch(tx, { ...d, status: 'routing' }, job.actorId);
        return true;
      }
      // cancelled while the candidate was being created → remove it
      await this.startCleanup(tx, d, job.actorId, true);
      return true;
    }
    const e = errOf(job);
    const logTail = logTailOf(e.details);
    if (!(await this.finishStep(tx, step, false, job, { logTail }))) return false;
    if (e.code === 'CANDIDATE_UNHEALTHY')
      await this.addStep(tx, d.id, 'health_check', 'failed', {
        jobId: job.id,
        errorCode: e.code,
        message: e.message,
        logTail,
      });
    await this.fail(tx, d, ['pulling'], job);
    if (NOTHING_CREATED.has(e.code)) {
      await this.releasePort(tx, d.serverId, d.hostPort, d.containerName);
      await tx.deployment.update({ where: { id: d.id }, data: { containerRemovedAt: new Date() } });
    } else if (e.code === 'PORT_IN_USE' && d.hostPort !== null) {
      // something outside pPanel listens there: keep the port reserved so it is not picked again
      await tx.hostPortAllocation.updateMany({
        where: { serverId: d.serverId, port: d.hostPort },
        data: {
          reason: 'external_in_use',
          deploymentId: null,
          containerName: null,
          applicationId: null,
        },
      });
      await tx.deployment.update({ where: { id: d.id }, data: { containerRemovedAt: new Date() } });
    }
    return false;
  }

  /**
   * compose.apply finished. Route service created/replaced → switch the route to its new port (then
   * the old route container is stopped by `stop_previous`). Route service unchanged → release the
   * spare port; switch only if the rendered route differs (domains/TLS), else promote directly.
   */
  private async onComposeApply(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    const plan = planOf(d.plan)!;
    const data = step.data as { hostPort: number; routeName: string };
    if (job.status === 'succeeded') {
      const out = (job.result ?? {}) as { services?: ComposeServiceResult[] };
      const results = (out.services ?? []).filter((r) => r && typeof r.service === 'string');
      const route = results.find((r) => r.service === plan.routeService);
      const summary = results.map((r) => `${r.service}: ${r.action}`).join(', ');
      if (!(await this.finishStep(tx, step, true, job, { message: `Applied (${summary})` })))
        return false;
      await tx.deployment.update({
        where: { id: d.id },
        data: { serviceResults: results as unknown as Prisma.InputJsonValue },
      });
      await this.addStep(tx, d.id, 'health_check', 'succeeded', {
        jobId: job.id,
        message: results
          .map((r) => `${r.service}: ${healthStatusOf(r.health) ?? 'healthy'}`)
          .join(', '),
      });
      const routeNew = !!route && route.action !== 'unchanged';
      if (!routeNew) await this.releasePort(tx, d.serverId, data.hostPort, data.routeName);
      if (d.status !== 'pulling') {
        // cancelled while applying: remove a freshly created route candidate, touch nothing else
        if (routeNew) {
          await tx.deployment.update({
            where: { id: d.id },
            data: { containerName: route.name, hostPort: data.hostPort },
          });
          await this.startCleanup(
            tx,
            { ...d, containerName: route.name, hostPort: data.hostPort },
            job.actorId,
            true,
          );
        }
        return true;
      }
      const container = await tx.containerApp.findUniqueOrThrow({
        where: { applicationId: d.applicationId },
      });
      const current = container.currentDeploymentId
        ? await tx.deployment.findUnique({ where: { id: container.currentDeploymentId } })
        : null;
      const target = routeNew
        ? { containerName: route.name, hostPort: data.hostPort }
        : {
            containerName: route?.name ?? current?.containerName ?? null,
            hostPort: route?.hostPort ?? current?.hostPort ?? null,
          };
      if (!target.hostPort) {
        await this.fail(tx, d, ['pulling'], {
          ...job,
          status: 'failed',
          error: {
            code: 'COMPOSE_ROUTE_UNKNOWN',
            message: 'Route service was kept but its host port is unknown; redeploy',
          },
        });
        return false;
      }
      const moved = await this.move(tx, d.id, ['pulling'], { status: 'routing', ...target });
      if (!moved) return false;
      await this.systemAudit(tx, d, 'routing', job, {
        services: results.map((r) => [r.service, r.action]),
      });
      const routed = { ...d, status: 'routing', ...target } as DeploymentRow;
      const app = await tx.application.findUniqueOrThrow({ where: { id: d.applicationId } });
      const last = await tx.deploymentStep.findFirst({
        where: {
          name: 'route_switch',
          status: 'succeeded',
          deployment: { applicationId: d.applicationId },
        },
        orderBy: { finishedAt: 'desc' },
        select: { data: true },
      });
      const sameRoute =
        !routeNew &&
        (last?.data as { routeKey?: string } | null)?.routeKey ===
          routeKeyOf(app.domains, tlsOf(container), target.hostPort);
      if (!sameRoute) {
        await this.startRouteSwitch(tx, routed, job.actorId);
        return true;
      }
      await this.addStep(tx, d.id, 'route_switch', 'skipped', {
        message: 'Route service unchanged — route not switched',
      });
      await this.promote(tx, routed, container.currentDeploymentId);
      await this.succeed(tx, routed, job);
      return true;
    }
    const e = errOf(job);
    const logTail = logTailOf(e.details);
    if (!(await this.finishStep(tx, step, false, job, { logTail }))) return false;
    const det = (e.details ?? {}) as { service?: string; services?: ComposeServiceResult[] };
    if (Array.isArray(det.services))
      await tx.deployment.update({
        where: { id: d.id },
        data: { serviceResults: det.services as unknown as Prisma.InputJsonValue },
      });
    if (e.code === 'COMPOSE_SERVICE_UNHEALTHY')
      await this.addStep(tx, d.id, 'health_check', 'failed', {
        jobId: job.id,
        errorCode: e.code,
        message: `${det.service ?? 'service'}: ${e.message}`,
        logTail,
      });
    await this.fail(tx, d, ['pulling'], job);
    const leftover = (det.services ?? []).find(
      (r) => r.service === plan.routeService && r.action !== 'unchanged' && r.name,
    );
    if (leftover && det.service !== plan.routeService) {
      // route candidate was created before a later service failed: stop + remove it
      await tx.deployment.update({
        where: { id: d.id },
        data: { containerName: leftover.name, hostPort: data.hostPort },
      });
      await this.startCleanup(
        tx,
        { ...d, containerName: leftover.name, hostPort: data.hostPort },
        job.actorId,
        true,
      );
      return true;
    }
    await this.releasePort(tx, d.serverId, data.hostPort, data.routeName);
    return false;
  }

  /** current ← d, previous ← old current (route not switched: compose with an unchanged route). */
  private async promote(tx: Tx, d: DeploymentRow, oldCurrentId: string | null) {
    const container = await tx.containerApp.findUniqueOrThrow({
      where: { applicationId: d.applicationId },
    });
    const oldCurrent =
      oldCurrentId && oldCurrentId !== d.id
        ? await tx.deployment.findUnique({ where: { id: oldCurrentId } })
        : null;
    await tx.containerApp.update({
      where: { applicationId: d.applicationId },
      data: {
        currentDeploymentId: d.id,
        previousDeploymentId: oldCurrent?.id ?? container.previousDeploymentId,
      },
    });
    if (d.trigger === 'rollback' && oldCurrent && oldCurrent.status === 'succeeded')
      await tx.deployment.update({
        where: { id: oldCurrent.id },
        data: { status: 'rolled_back', version: { increment: 1 } },
      });
  }

  private async onStartTarget(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    if (job.status === 'succeeded') {
      if (!(await this.finishStep(tx, step, true, job, { message: 'Previous container started' })))
        return false;
      await this.addStep(tx, d.id, 'health_check', 'succeeded', {
        jobId: job.id,
        message: 'Healthy',
      });
      if (d.status === 'starting') {
        await this.move(tx, d.id, ['starting'], { status: 'routing' });
        await this.systemAudit(tx, d, 'routing', job);
        await this.startRouteSwitch(tx, { ...d, status: 'routing' }, job.actorId);
        return true;
      }
      await this.startCleanup(tx, d, job.actorId, false); // cancelled: stop it again, keep it
      return true;
    }
    const e = errOf(job);
    if (!(await this.finishStep(tx, step, false, job, { logTail: logTailOf(e.details) })))
      return false;
    await this.fail(tx, d, ['starting'], job);
    return false;
  }

  private async startRouteSwitch(tx: Tx, d: DeploymentRow, actorId: string | null) {
    const app = await tx.application.findUniqueOrThrow({ where: { id: d.applicationId } });
    const container = await tx.containerApp.findUniqueOrThrow({ where: { applicationId: app.id } });
    const path = routePath(app.name);
    const content = renderRoute({
      deploymentId: d.id,
      app: app.name,
      hostPort: d.hostPort!,
      domains: app.domains,
      tls: tlsOf(container),
    });
    const before = nginxFilesOf(app).find((f) => f.path === path)?.lastKnownSha256 ?? null;
    const hc = healthcheckOf(container);
    const postchecks = app.domains.slice(0, 10).map((hostHeader) => ({
      hostHeader,
      path: hc.path,
      scheme: 'http' as const,
      expectStatus: hc.expectStatus,
    }));
    const job = await this.jobs.createInternal(tx, {
      serverId: d.serverId,
      type: 'nginx.apply',
      params: {
        revisionId: d.id,
        files: [{ path, expectedSha256Before: before, content }],
        postchecks,
      },
      actorId,
      ttlSec: ROUTE_TTL_SEC,
      metadata: { deploymentId: d.id, applicationId: app.id },
    });
    await this.addStep(tx, d.id, 'route_switch', 'running', {
      jobId: job.id,
      message: `Switching ${app.domains.join(', ')} to 127.0.0.1:${d.hostPort}`,
      data: {
        path,
        beforeSha256: before,
        afterSha256: contentSha256(content),
        routeKey: routeKeyOf(app.domains, tlsOf(container), d.hostPort!),
      },
    });
  }

  private async onRouteSwitch(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    const data = step.data as { path: string; beforeSha256: string | null; afterSha256: string };
    if (job.status === 'succeeded') {
      const out = (job.result ?? {}) as {
        files?: Array<{ path: string; sha256After?: string }>;
        postchecks?: Array<{ hostHeader: string; status?: number; ok?: boolean }>;
      };
      const after = out.files?.find((f) => f.path === data.path)?.sha256After ?? data.afterSha256;
      const okProbes = (out.postchecks ?? []).filter((p) => p.ok).length;
      if (
        !(await this.finishStep(tx, step, true, job, {
          message: `Route switched (${okProbes}/${out.postchecks?.length ?? 0} postchecks ok)`,
        }))
      )
        return false;
      const app = await tx.application.findUniqueOrThrow({ where: { id: d.applicationId } });
      const container = await tx.containerApp.findUniqueOrThrow({
        where: { applicationId: app.id },
      });
      // baseline: the next scan must not flag pPanel's own route change as drift
      const files = nginxFilesOf(app).filter((f) => f.path !== data.path);
      files.push({ path: data.path, lastKnownSha256: after });
      await tx.application.update({
        where: { id: app.id },
        data: { nginxFiles: files as unknown as Prisma.InputJsonValue, version: { increment: 1 } },
      });
      const oldCurrentId = container.currentDeploymentId;
      const oldCurrent =
        oldCurrentId && oldCurrentId !== d.id
          ? await tx.deployment.findUnique({ where: { id: oldCurrentId } })
          : null;
      await tx.containerApp.update({
        where: { applicationId: app.id },
        data: {
          currentDeploymentId: d.id,
          previousDeploymentId: oldCurrent?.id ?? container.previousDeploymentId,
          routeSha256: after,
        },
      });
      if (d.trigger === 'rollback' && oldCurrent && oldCurrent.status === 'succeeded')
        await tx.deployment.update({
          where: { id: oldCurrent.id },
          data: { status: 'rolled_back', version: { increment: 1 } },
        });
      const prevContainer =
        oldCurrent?.containerName &&
        !oldCurrent.containerRemovedAt &&
        oldCurrent.containerName !== d.containerName
          ? oldCurrent.containerName
          : null;
      if (prevContainer) {
        const stop = await this.jobs.createInternal(tx, {
          serverId: d.serverId,
          type: 'container.stop',
          params: { app: app.name, name: prevContainer },
          actorId: job.actorId,
          ttlSec: CONTAINER_TTL_SEC,
          metadata: { deploymentId: d.id, applicationId: app.id },
        });
        await this.addStep(tx, d.id, 'stop_previous', 'running', {
          jobId: stop.id,
          message: `Stopping previous container ${prevContainer} (kept for rollback)`,
          data: { container: prevContainer },
        });
        return true;
      }
      await this.succeed(tx, d, job);
      return true;
    }
    const e = errOf(job);
    if (!(await this.finishStep(tx, step, false, job))) return false;
    if (e.code === 'REVERT_FAILED_MANUAL_RECOVERY') {
      logger.emit('fatal', 'route switch revert failed: manual recovery required', {
        deploymentId: d.id,
        serverId: d.serverId,
        jobId: job.id,
      });
      await this.fail(tx, d, ['routing'], job, 'requires_manual_recovery');
      await this.discovery.flagDrift(
        tx,
        d.applicationId,
        [{ path: data.path, lastKnownSha256: data.beforeSha256, currentSha256: 'unknown' }],
        { source: 'agent', jobId: job.id, deploymentId: d.id, errorCode: e.code },
      );
      return false; // host state unknown: touch nothing else
    }
    await this.fail(tx, d, ['routing'], job);
    if (e.code === 'DRIFT_DETECTED') {
      const files = (
        e.details as { files?: Array<{ path: string; actual?: string | null }> } | null
      )?.files;
      const actual = files?.find((f) => f.path === data.path)?.actual;
      await this.discovery.flagDrift(
        tx,
        d.applicationId,
        [
          {
            path: data.path,
            lastKnownSha256: data.beforeSha256,
            currentSha256: typeof actual === 'string' ? actual : 'unknown',
          },
        ],
        { source: 'agent', jobId: job.id, deploymentId: d.id },
      );
    }
    // previous deployment keeps serving (agent auto-reverted the route): remove the candidate,
    // or for a rollback stop the restored container again (it stays available)
    await this.startCleanup(tx, d, job.actorId, d.trigger !== 'rollback');
    return true;
  }

  private async onStopPrevious(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    const ok = job.status === 'succeeded';
    if (
      !(await this.finishStep(tx, step, ok, job, {
        ...(ok ? { message: 'Previous container stopped (kept for rollback)' } : {}),
      }))
    )
      return false;
    await this.succeed(tx, d, job, ok ? undefined : 'previous container could not be stopped');
    return true;
  }

  private async succeed(tx: Tx, d: DeploymentRow, job: FinishedJob, warning?: string) {
    const moved = await this.move(tx, d.id, ['routing'], {
      status: 'succeeded',
      finishedAt: new Date(),
      ...(warning ? { error: { code: 'STOP_PREVIOUS_FAILED', message: warning } } : {}),
    });
    if (!moved) return;
    await this.systemAudit(tx, d, 'succeeded', job, warning ? { warning } : {});
    await this.prune(tx, d, job.actorId);
  }

  /** Retention: keep the serving container + the last KEEP_OLD_CONTAINERS old ones; remove older ones. */
  private async prune(tx: Tx, d: DeploymentRow, actorId: string | null) {
    const app = await tx.application.findUniqueOrThrow({ where: { id: d.applicationId } });
    const container = await tx.containerApp.findUniqueOrThrow({ where: { applicationId: app.id } });
    const current = container.currentDeploymentId
      ? await tx.deployment.findUnique({ where: { id: container.currentDeploymentId } })
      : null;
    const rows = await tx.deployment.findMany({
      where: {
        applicationId: app.id,
        containerName: { not: null },
        containerRemovedAt: null,
        status: { in: ['succeeded', 'rolled_back', 'failed', 'cancelled', 'expired'] },
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      select: { containerName: true },
    });
    const names: string[] = [];
    for (const r of rows)
      if (
        r.containerName &&
        r.containerName !== current?.containerName &&
        !names.includes(r.containerName)
      )
        names.push(r.containerName);
    const doomed = names.slice(KEEP_OLD_CONTAINERS);
    if (doomed.length === 0) return;
    const busy = await tx.deploymentStep.findMany({
      where: {
        status: 'running',
        name: { in: ['cleanup_stop', 'cleanup_remove', 'prune_remove'] },
      },
      select: { data: true },
    });
    const inFlight = new Set(busy.map((b) => (b.data as { container?: string }).container));
    for (const name of doomed) {
      if (inFlight.has(name)) continue;
      const job = await this.jobs.createInternal(tx, {
        serverId: d.serverId,
        type: 'container.remove',
        params: { app: app.name, name },
        actorId,
        ttlSec: CONTAINER_TTL_SEC,
        metadata: { deploymentId: d.id, applicationId: app.id, reason: 'retention' },
      });
      await this.addStep(tx, d.id, 'prune_remove', 'running', {
        jobId: job.id,
        message: `Removing old container ${name} (retention: last ${KEEP_OLD_CONTAINERS})`,
        data: { container: name },
      });
    }
  }

  /** Stop (and optionally then remove) this deployment's container after a failure/cancel. */
  private async startCleanup(tx: Tx, d: DeploymentRow, actorId: string | null, remove: boolean) {
    if (!d.containerName) return;
    const app = await tx.application.findUniqueOrThrow({ where: { id: d.applicationId } });
    const job = await this.jobs.createInternal(tx, {
      serverId: d.serverId,
      type: 'container.stop',
      params: { app: app.name, name: d.containerName },
      actorId,
      ttlSec: CONTAINER_TTL_SEC,
      metadata: { deploymentId: d.id, applicationId: app.id, reason: 'cleanup' },
    });
    await this.addStep(tx, d.id, 'cleanup_stop', 'running', {
      jobId: job.id,
      message: remove
        ? `Stopping candidate ${d.containerName} before removal`
        : `Stopping ${d.containerName} (kept for rollback)`,
      data: { container: d.containerName, remove },
    });
  }

  private async onCleanupStop(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    const e = job.status === 'succeeded' ? null : errOf(job);
    const ok = !e || e.code === 'CONTAINER_NOT_FOUND';
    if (!(await this.finishStep(tx, step, job.status === 'succeeded', job))) return false;
    const data = step.data as { container: string; remove: boolean };
    if (!ok || !data.remove) return false;
    const app = await tx.application.findUniqueOrThrow({ where: { id: d.applicationId } });
    const rm = await this.jobs.createInternal(tx, {
      serverId: d.serverId,
      type: 'container.remove',
      params: { app: app.name, name: data.container },
      actorId: job.actorId,
      ttlSec: CONTAINER_TTL_SEC,
      metadata: { deploymentId: d.id, applicationId: app.id, reason: 'cleanup' },
    });
    await this.addStep(tx, d.id, 'cleanup_remove', 'running', {
      jobId: rm.id,
      message: `Removing candidate ${data.container}`,
      data: { container: data.container },
    });
    return true;
  }

  private async onRemoved(tx: Tx, step: StepRow, d: DeploymentRow, job: FinishedJob) {
    const e = job.status === 'succeeded' ? null : errOf(job);
    const gone = !e || e.code === 'CONTAINER_NOT_FOUND';
    if (!(await this.finishStep(tx, step, job.status === 'succeeded', job))) return false;
    if (!gone) return false;
    const name = (step.data as { container: string }).container;
    await tx.deployment.updateMany({
      where: { applicationId: d.applicationId, containerName: name, containerRemovedAt: null },
      data: { containerRemovedAt: new Date() },
    });
    await tx.hostPortAllocation.deleteMany({
      where: { serverId: d.serverId, containerName: name },
    });
    return false;
  }

  // ---------------------------------------------------------------- reconcile

  private async reconcileStep(s: StepRow): Promise<void> {
    if (!s.jobId) return;
    const job = await this.prisma.job.findUnique({ where: { id: s.jobId } });
    if (job && this.jobs.isTerminal(job.status)) await this.jobs.dispatchFinished(job);
  }

  /** Re-dispatches terminal jobs whose step is still `running` (missed hook, API restart, lease expiry). */
  async reconcile(): Promise<number> {
    const steps = await this.prisma.deploymentStep.findMany({
      where: { status: 'running', jobId: { not: null } },
      orderBy: { startedAt: 'asc' },
      take: 100,
    });
    for (const s of steps) await this.reconcileStep(s);
    return steps.length;
  }
}
