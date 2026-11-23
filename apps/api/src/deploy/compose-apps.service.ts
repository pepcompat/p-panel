import { Injectable } from '@nestjs/common';
import {
  type Application,
  type ComposeValidation,
  type ContainerOperationAccepted,
  containerHealthcheckSchema,
  containerResourcesSchema,
  type CreateComposeAppInput,
  type CreateDeploymentInput,
  DEPLOYMENT_ACTIVE_STATUSES,
  ERROR_CODES,
  isDigestPinned,
  type UpdateComposeInput,
} from '@ppanel/shared-contracts';
import type { ComposeAppVersion, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { sha256Hex } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { ApplicationsService } from '../discovery/applications.service';
import { serverScope } from '../discovery/p3-common';
import { JobsService } from '../jobs/jobs.service';
import {
  composeContainerName,
  type ComposeServiceResult,
  composeSpecHash,
  normalizeComposeDocument,
  planOf,
  type ResolvedService,
  type StoredComposePlan,
} from './compose-plan';
import type { ComposePlanService } from '@ppanel/shared-contracts';
import { parseComposeYaml } from './compose-validator';
import { ContainerAppsService } from './container-apps.service';
import { DeploymentsService } from './deployments.service';
import { PreflightService } from './preflight.service';
import { RegistryClient } from './registry.client';
import { type ContainerAppRef, loadContainerApp, SecretsService } from './secrets.service';

const EXECUTING = (DEPLOYMENT_ACTIVE_STATUSES as readonly string[]).filter(
  (s) => s !== 'awaiting_approval',
);
const OP_TTL_SEC = 600;

/**
 * P4b Compose applications (§8.3): validated + normalised versions, deployments with Center-side digest
 * resolution, rollback = re-apply the previous successful plan (never volumes/data), stop/start.
 * Runtime state (current/previous deployment, route port, tls, declared secret keys) lives in the same
 * `container_apps` row as container apps, so the §7.3 orchestrator (route switch, retention) is reused.
 */
@Injectable()
export class ComposeAppsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly apps: ApplicationsService,
    private readonly jobs: JobsService,
    private readonly preflight: PreflightService,
    private readonly secrets: SecretsService,
    private readonly registry: RegistryClient,
    private readonly deployments: DeploymentsService,
    private readonly containerApps: ContainerAppsService,
  ) {}

  // ---------------------------------------------------------------- validation

  private invalid(v: ComposeValidation): AppError {
    return new AppError(422, ERROR_CODES.COMPOSE_INVALID, 'Compose file is not deployable', {
      violations: v.violations,
      warnings: v.warnings,
    });
  }

  /**
   * Parse + static policy + execution rules; tag refs must resolve to a digest now (they are resolved
   * again at deploy time and the digest is recorded). A registry that needs credentials not yet stored
   * is a warning (resolved at deploy time with the app's registry-auth).
   */
  private async validate(
    yaml: string,
    opts: {
      app: string;
      routeService: string;
      routePort: number;
      healthPath?: string;
      appId?: string;
      existingSecrets?: Set<string>;
    },
  ) {
    const parsed = parseComposeYaml(yaml);
    if ('failure' in parsed) throw this.invalid(parsed.failure);
    const n = normalizeComposeDocument(parsed.doc, opts);
    if (!n.validation.valid) throw this.invalid(n.validation);
    const cred = opts.appId ? await this.secrets.registryCredential(opts.appId) : null;
    for (const s of n.services) {
      if (isDigestPinned(s.image)) continue;
      try {
        await this.registry.resolveDigest(s.image, {
          auth: cred ? { username: cred.username, password: cred.password } : null,
          extraAllowedHosts: cred ? [cred.serveraddress] : [],
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'unresolvable';
        const authNeeded = /authentication/i.test(msg) && !cred;
        (authNeeded ? n.validation.warnings : n.validation.violations).push({
          service: s.service,
          rule: 'image_unresolvable',
          path: `services.${s.service}.image`,
          message: authNeeded
            ? `${msg}; set the registry credential before deploying`
            : `Image ${s.image} cannot be resolved to a digest: ${msg}`,
        });
      }
    }
    if (n.validation.violations.length) throw this.invalid({ ...n.validation, valid: false });
    return n;
  }

  // ---------------------------------------------------------------- create / update

  async create(user: AuthUser, input: CreateComposeAppInput): Promise<Application> {
    const server = await this.prisma.server.findUnique({ where: { id: input.serverId } });
    if (!server || !this.authz.can(user, 'fleet.read', serverScope(server)))
      throw AppError.notFound('Server');
    await this.authz.enforce(user, 'apps.deploy', serverScope(server), {
      action: 'applications.create',
      targetType: 'server',
      targetId: server.id,
    });
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (input.environment && input.environment !== server.environment)
      throw new AppError(
        422,
        ERROR_CODES.ENVIRONMENT_MISMATCH,
        `environment must match the server's environment (${server.environment})`,
        { serverEnvironment: server.environment },
      );
    const n = await this.validate(input.yaml, {
      app: input.name,
      routeService: input.routeService,
      routePort: input.routePort,
      healthPath: input.healthPath,
    });
    const conflicts = await this.preflight.domainConflicts(null, server.id, input.domains);
    if (conflicts.length)
      throw AppError.conflict('Domain already in use', ERROR_CODES.DOMAIN_CONFLICT, { conflicts });
    const id = uuidv7();
    const healthPath = input.healthPath ?? '/';
    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.application.create({
          data: {
            id,
            serverId: server.id,
            name: input.name,
            kind: 'compose',
            domains: input.domains,
            ownershipMode: 'managed',
            sourceFindingFingerprint: `compose:${id}`,
            nginxFiles: [],
          },
        });
        await tx.containerApp.create({
          data: {
            applicationId: id,
            containerPort: input.routePort,
            healthcheck: containerHealthcheckSchema.parse({ path: healthPath }),
            resources: containerResourcesSchema.parse({}),
            env: {},
            secretKeys: n.secretKeys,
            volumes: [],
            tls: (input.tls ?? undefined) as Prisma.InputJsonValue | undefined,
            createdBy: user.id,
          },
        });
        const v = await this.storeVersion(tx, id, 1, input, n, user.id);
        await this.audit.record(
          {
            actorId: user.id,
            action: 'applications.create',
            targetType: 'application',
            targetId: id,
            result: 'success',
            diff: { kind: 'compose', yamlSha256: v.yamlSha256, routeService: input.routeService },
            metadata: {
              kind: 'compose',
              serverId: server.id,
              name: input.name,
              domains: input.domains,
              composeVersion: 1,
              services: n.services.map((s) => s.service),
              // key names only ("secret*" metadata keys are redacted by the audit sink)
              envPlaceholderKeys: n.secretKeys,
            },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          `An application named ${input.name} already exists on this server`,
          ERROR_CODES.APP_NAME_TAKEN,
        );
      throw e;
    }
    return this.apps.get(user, id);
  }

  private storeVersion(
    tx: Prisma.TransactionClient,
    appId: string,
    version: number,
    input: { yaml: string; routeService: string; routePort: number; healthPath?: string },
    n: Awaited<ReturnType<ComposeAppsService['validate']>>,
    userId: string,
  ) {
    return tx.composeAppVersion.create({
      data: {
        id: uuidv7(),
        applicationId: appId,
        version,
        yaml: input.yaml,
        yamlSha256: sha256Hex(input.yaml),
        routeService: input.routeService,
        routePort: input.routePort,
        healthPath: input.healthPath ?? '/',
        plan: n.services as unknown as Prisma.InputJsonValue,
        secretKeys: n.secretKeys,
        warnings: n.validation.warnings as unknown as Prisma.InputJsonValue,
        createdBy: userId,
      },
    });
  }

  /** PUT /applications/:id/compose (If-Match = application version) → new version (validated). */
  async update(
    user: AuthUser,
    appId: string,
    input: UpdateComposeInput,
    ifMatch: number | undefined,
  ): Promise<Application> {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['compose']);
    await this.authz.enforce(user, 'apps.deploy', serverScope(ref.app.server), {
      action: 'applications.compose_update',
      targetType: 'application',
      targetId: appId,
    });
    const executing = await this.prisma.deployment.findFirst({
      where: { applicationId: appId, status: { in: EXECUTING } },
      select: { id: true },
    });
    if (executing)
      throw AppError.conflict('A deployment is executing', ERROR_CODES.DEPLOYMENT_IN_PROGRESS, {
        deploymentId: executing.id,
      });
    const { versions } = await this.secrets.keyVersions(appId);
    const n = await this.validate(input.yaml, {
      app: ref.app.name,
      routeService: input.routeService,
      routePort: input.routePort,
      healthPath: input.healthPath,
      appId,
      existingSecrets: new Set(Object.keys(versions)),
    });
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.application.updateMany({
        where: { id: appId, ...(ifMatch !== undefined ? { version: ifMatch } : {}) },
        data: { version: { increment: 1 } },
      });
      if (r.count !== 1)
        throw AppError.conflict(
          'Application was modified by someone else',
          ERROR_CODES.VERSION_CONFLICT,
        );
      const agg = await tx.composeAppVersion.aggregate({
        where: { applicationId: appId },
        _max: { version: true },
      });
      const version = (agg._max.version ?? 0) + 1;
      const v = await this.storeVersion(tx, appId, version, input, n, user.id);
      await tx.containerApp.update({
        where: { applicationId: appId },
        data: {
          containerPort: input.routePort,
          healthcheck: containerHealthcheckSchema.parse({ path: input.healthPath ?? '/' }),
          secretKeys: n.secretKeys,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'applications.compose_update',
          targetType: 'application',
          targetId: appId,
          result: 'success',
          diff: { yamlSha256: v.yamlSha256, routeService: input.routeService, version },
          metadata: {
            composeVersion: version,
            services: n.services.map((s) => s.service),
            envPlaceholderKeys: n.secretKeys,
          },
        },
        tx,
      );
    });
    return this.apps.get(user, appId);
  }

  async getCompose(user: AuthUser, appId: string, version?: number) {
    await loadContainerApp(this.apps, this.prisma, user, appId, ['compose']);
    const v = await this.versionOf(appId, version);
    return {
      versionId: v.id,
      version: v.version,
      yaml: v.yaml,
      yamlSha256: v.yamlSha256,
      routeService: v.routeService,
      routePort: v.routePort,
      healthPath: v.healthPath,
      services: v.plan as unknown as ComposePlanService[],
      secretKeys: v.secretKeys,
      warnings: v.warnings,
      createdBy: v.createdBy,
      createdAt: v.createdAt.toISOString(),
    };
  }

  private async versionOf(appId: string, version?: number): Promise<ComposeAppVersion> {
    const v = await this.prisma.composeAppVersion.findFirst({
      where: { applicationId: appId, ...(version !== undefined ? { version } : {}) },
      orderBy: { version: 'desc' },
    });
    if (!v)
      throw AppError.notFound(
        version !== undefined ? `Compose version ${version}` : 'Compose version',
      );
    return v;
  }

  // ---------------------------------------------------------------- plans

  /** The plan of the current deployment (what should be running) + reported container names. */
  private async currentPlan(ref: ContainerAppRef) {
    const id = ref.container.currentDeploymentId;
    const d = id ? await this.prisma.deployment.findUnique({ where: { id } }) : null;
    const plan = planOf(d?.plan);
    const results = Array.isArray(d?.serviceResults)
      ? (d!.serviceResults as unknown as ComposeServiceResult[])
      : [];
    return { deployment: d, plan, results };
  }

  private async withPlanMeta(
    ref: ContainerAppRef,
    deploymentId: string,
    meta: { versionId: string; version: number; routeService: string },
    services: Array<ResolvedService & { specHash?: string }>,
    secretVersions: Record<string, number>,
  ): Promise<StoredComposePlan> {
    const cur = await this.currentPlan(ref);
    return {
      ...meta,
      services: services.map((s) => {
        const specHash = s.specHash ?? composeSpecHash(s, secretVersions);
        const prev = cur.plan?.services.find((p) => p.service === s.service);
        const prevName =
          cur.results.find((r) => r.service === s.service)?.name ?? prev?.name ?? null;
        return {
          ...s,
          specHash,
          name: composeContainerName(ref.app.name, s.service, deploymentId),
          plannedAction: prev && prev.specHash === specHash ? 'unchanged' : 'replace',
          previousName: prevName,
        };
      }),
    };
  }

  /** Resolve every image to a digest (registry API; tag refs only from the allowlisted registries). */
  private async resolve(ref: ContainerAppRef, services: ComposePlanService[]) {
    const cred = await this.secrets.registryCredential(ref.app.id);
    const out: ResolvedService[] = [];
    for (const s of services) {
      const resolvedImage = isDigestPinned(s.image)
        ? s.image
        : await this.registry.resolveDigest(s.image, {
            auth: cred ? { username: cred.username, password: cred.password } : null,
            extraAllowedHosts: cred ? [cred.serveraddress] : [],
          });
      out.push({ ...s, resolvedImage });
    }
    return out;
  }

  private routeImage(plan: StoredComposePlan): string {
    return plan.services.find((s) => s.service === plan.routeService)!.resolvedImage;
  }

  // ---------------------------------------------------------------- deployments

  /** POST /applications/:id/deployments for any managed app (container → §7.3 path). */
  async deploy(
    user: AuthUser,
    appId: string,
    input: CreateDeploymentInput,
    idempotencyKey: string | undefined,
  ) {
    const app = await this.apps.load(user, appId);
    if (app.kind !== 'compose')
      return this.deployments.createManual(user, appId, input, idempotencyKey);
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['compose']);
    await this.deployments.enforceDeploy(user, ref, 'deployments.create');
    if (input.image)
      throw AppError.badRequest('Compose deployments take no image (use composeVersion)');
    if (idempotencyKey !== undefined && !/^[A-Za-z0-9_.:-]{8,128}$/.test(idempotencyKey))
      throw AppError.badRequest('Idempotency-Key must be 8-128 chars of [A-Za-z0-9_.:-]');
    if (idempotencyKey) {
      const ex = await this.prisma.deployment.findUnique({
        where: { applicationId_idempotencyKey: { applicationId: appId, idempotencyKey } },
      });
      if (ex) return { created: false, deployment: await this.deployments.get(user, ex.id) };
    }
    const v = await this.prisma.composeAppVersion.findFirst({
      where: {
        applicationId: appId,
        ...(input.composeVersion !== undefined ? { version: input.composeVersion } : {}),
      },
      orderBy: { version: 'desc' },
    });
    if (!v)
      throw AppError.notFound(
        input.composeVersion !== undefined
          ? `Compose version ${input.composeVersion}`
          : 'Compose version',
      );
    const id = uuidv7();
    const { versions } = await this.secrets.keyVersions(appId);
    const resolved = await this.resolve(ref, v.plan as unknown as ComposePlanService[]);
    const plan = await this.withPlanMeta(
      ref,
      id,
      { versionId: v.id, version: v.version, routeService: v.routeService },
      resolved,
      versions,
    );
    const { row, created } = await this.deployments.create({ user, id: user.id }, ref, {
      id,
      image: this.routeImage(plan),
      trigger: 'manual',
      compose: plan,
      reason: input.reason,
      idempotencyKey,
      ...(input.sourceRef
        ? { sourceRef: input.sourceRef, commitSha: input.sourceRef.commitSha }
        : {}),
    });
    return { created, deployment: await this.deployments.get(user, row.id) };
  }

  /** Rollback = re-apply the previous successful plan (images + specs). Volumes/data are never restored. */
  async rollback(user: AuthUser, appId: string, reason?: string) {
    const app = await this.apps.load(user, appId);
    if (app.kind !== 'compose') return this.deployments.rollback(user, appId, reason);
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['compose']);
    await this.deployments.enforceDeploy(user, ref, 'deployments.rollback');
    const prevId = ref.container.previousDeploymentId;
    const prev = prevId ? await this.prisma.deployment.findUnique({ where: { id: prevId } }) : null;
    const prevPlan = planOf(prev?.plan);
    if (!prev || !prevPlan || !['succeeded', 'rolled_back'].includes(prev.status))
      throw AppError.conflict(
        'No previous successful compose plan to re-apply',
        ERROR_CODES.ROLLBACK_UNAVAILABLE,
      );
    const row = await this.reapply(user, ref, prevPlan, 'rollback', reason, prev.id);
    return {
      deployment: await this.deployments.get(user, row.id),
      rollback: { dataRestored: false as const, rollbackOfDeploymentId: prev.id },
    };
  }

  async redeploy(user: AuthUser, appId: string, reason?: string) {
    const app = await this.apps.load(user, appId);
    if (app.kind !== 'compose') return this.deployments.redeploy(user, appId, reason);
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['compose']);
    await this.deployments.enforceDeploy(user, ref, 'deployments.redeploy');
    const cur = await this.currentPlan(ref);
    if (!cur.plan)
      throw AppError.conflict(
        'Application has no current deployment',
        ERROR_CODES.NO_CURRENT_DEPLOYMENT,
      );
    const row = await this.reapply(user, ref, cur.plan, 'redeploy', reason);
    return { deployment: await this.deployments.get(user, row.id) };
  }

  private async reapply(
    user: AuthUser,
    ref: ContainerAppRef,
    source: StoredComposePlan,
    trigger: 'rollback' | 'redeploy',
    reason: string | undefined,
    rollbackOf?: string,
  ) {
    const id = uuidv7();
    const { versions } = await this.secrets.keyVersions(ref.app.id);
    const plan = await this.withPlanMeta(
      ref,
      id,
      { versionId: source.versionId, version: source.version, routeService: source.routeService },
      source.services.map((s) => ({ ...s })),
      versions,
    );
    const { row } = await this.deployments.create({ user, id: user.id }, ref, {
      id,
      image: this.routeImage(plan),
      trigger,
      compose: plan,
      reason,
      ...(rollbackOf ? { rollbackOfDeploymentId: rollbackOf } : {}),
    });
    return row;
  }

  /**
   * P6 in-place restore `start_app`: re-apply the current plan (stopped services are recreated with
   * their health checks) as a `redeploy` deployment pre-approved by the restore's approval.
   */
  async startForRestore(
    appId: string,
    actorId: string,
    restoreId: string,
  ): Promise<{ deploymentId: string; status: string } | null> {
    const app = await this.prisma.application.findUniqueOrThrow({
      where: { id: appId },
      include: { server: { select: { id: true, environment: true, status: true } } },
    });
    const container = await this.prisma.containerApp.findUniqueOrThrow({
      where: { applicationId: appId },
    });
    const ref: ContainerAppRef = { app, container };
    const cur = await this.currentPlan(ref);
    if (!cur.plan) return null;
    const id = uuidv7();
    const { versions } = await this.secrets.keyVersions(app.id);
    const plan = await this.withPlanMeta(
      ref,
      id,
      {
        versionId: cur.plan.versionId,
        version: cur.plan.version,
        routeService: cur.plan.routeService,
      },
      cur.plan.services.map((s) => ({ ...s })),
      versions,
    );
    const { row } = await this.deployments.create({ user: null, id: actorId }, ref, {
      id,
      image: this.routeImage(plan),
      trigger: 'redeploy',
      compose: plan,
      reason: `start after in-place restore ${restoreId}`,
      preApprovedByRestoreId: restoreId,
    });
    return { deploymentId: row.id, status: row.status };
  }

  // ---------------------------------------------------------------- start / stop / restart

  async operate(
    user: AuthUser,
    appId: string,
    op: 'restart' | 'start' | 'stop',
    stepUp: string | undefined,
  ): Promise<ContainerOperationAccepted> {
    const app = await this.apps.load(user, appId);
    if (app.kind !== 'compose') return this.containerApps.operate(user, appId, op, stepUp);
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['compose']);
    await this.authz.enforce(user, 'apps.deploy', serverScope(ref.app.server), {
      action: `applications.${op}`,
      targetType: 'application',
      targetId: appId,
    });
    if (ref.app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (op === 'restart')
      throw AppError.conflict(
        'Compose applications are restarted with redeploy (re-apply of the current plan)',
        ERROR_CODES.OPERATION_NOT_SUPPORTED,
      );
    if (ref.app.server.environment === 'production') this.auth.assertStepUp(user, stepUp);
    const active = await this.prisma.deployment.findFirst({
      where: { applicationId: appId, status: { in: EXECUTING } },
      select: { id: true },
    });
    if (active)
      throw AppError.conflict('A deployment is executing', ERROR_CODES.DEPLOYMENT_IN_PROGRESS, {
        deploymentId: active.id,
      });
    const cur = await this.currentPlan(ref);
    if (!cur.plan || !cur.deployment)
      throw AppError.conflict(
        'Application has no current deployment',
        ERROR_CODES.NO_CURRENT_DEPLOYMENT,
      );
    if (op === 'start') {
      // start = re-apply the current plan (stopped services are recreated, running ones kept)
      const row = await this.reapply(user, ref, cur.plan, 'redeploy', 'start');
      const d = await this.prisma.deployment.findUniqueOrThrow({
        where: { id: row.id },
        include: { steps: true },
      });
      const step = d.steps.find((s) => s.name === 'compose_apply');
      await this.audit.record({
        actorId: user.id,
        action: 'applications.start',
        targetType: 'application',
        targetId: appId,
        result: 'success',
        metadata: { deploymentId: d.id, jobId: step?.jobId ?? null },
      });
      return {
        jobId: step?.jobId ?? '',
        operation: 'start',
        container: cur.deployment.containerName ?? '',
        deploymentId: d.id,
      };
    }
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId: ref.app.serverId,
        type: 'compose.stop',
        params: { app: ref.app.name },
        actorId: user.id,
        ttlSec: OP_TTL_SEC,
        metadata: { applicationId: appId, deploymentId: cur.deployment!.id },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'applications.stop',
          targetType: 'application',
          targetId: appId,
          result: 'success',
          metadata: { jobId: j.id, kind: 'compose', volumesKept: true },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(ref.app.serverId);
    return { jobId: job.id, operation: 'stop', container: cur.deployment.containerName ?? '' };
  }
}
