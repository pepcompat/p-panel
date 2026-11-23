import { Inject, Injectable } from '@nestjs/common';
import {
  type Application,
  type ContainerLogs,
  type ContainerOperationAccepted,
  containerHealthcheckSchema,
  containerResourcesSchema,
  type CreateContainerAppInput,
  DEPLOYMENT_ACTIVE_STATUSES,
  ERROR_CODES,
  type UpdateContainerAppInput,
} from '@ppanel/shared-contracts';
import { type Job as JobRow, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { uuidv7 } from '../common/ids';
import { redactKnownValues } from '../common/logger';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ApplicationsService } from '../discovery/applications.service';
import { appInclude, serverScope } from '../discovery/p3-common';
import { JobsService } from '../jobs/jobs.service';
import { healthcheckOf } from './container-common';
import { DeploymentsService } from './deployments.service';
import { PreflightService } from './preflight.service';
import { type ContainerAppRef, loadContainerApp, SecretsService } from './secrets.service';

const ACTIVE = [...DEPLOYMENT_ACTIVE_STATUSES] as string[];
const OP_TTL_SEC = 600;
const LOGS_TTL_SEC = 120;

@Injectable()
export class ContainerAppsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly apps: ApplicationsService,
    private readonly jobs: JobsService,
    private readonly preflight: PreflightService,
    private readonly secrets: SecretsService,
    private readonly deployments: DeploymentsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** §7.1 POST /applications — managed container application (ownership `managed`). */
  async create(user: AuthUser, input: CreateContainerAppInput): Promise<Application> {
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
    this.assertEnvVsSecrets(input.env ?? {}, input.secretKeys ?? []);
    const conflicts = await this.preflight.domainConflicts(null, server.id, input.domains);
    if (conflicts.length)
      throw AppError.conflict('Domain already in use', ERROR_CODES.DOMAIN_CONFLICT, { conflicts });
    const id = uuidv7();
    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.application.create({
          data: {
            id,
            serverId: server.id,
            name: input.name,
            kind: 'container',
            domains: input.domains,
            ownershipMode: 'managed',
            sourceFindingFingerprint: `container:${id}`,
            nginxFiles: [],
          },
        });
        await tx.containerApp.create({
          data: {
            applicationId: id,
            containerPort: input.containerPort,
            healthcheck: containerHealthcheckSchema.parse(input.healthcheck ?? {}),
            resources: containerResourcesSchema.parse(input.resources ?? {}),
            env: input.env ?? {},
            secretKeys: input.secretKeys ?? [],
            volumes: (input.volumes ?? []) as Prisma.InputJsonValue,
            tls: (input.tls ?? undefined) as Prisma.InputJsonValue | undefined,
            createdBy: user.id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'applications.create',
            targetType: 'application',
            targetId: id,
            result: 'success',
            diff: { ...input, env: Object.keys(input.env ?? {}) },
            metadata: {
              kind: 'container',
              serverId: server.id,
              name: input.name,
              domains: input.domains,
              envKeys: Object.keys(input.env ?? {}),
              secretKeys: input.secretKeys ?? [],
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

  private assertEnvVsSecrets(env: Record<string, string>, secretKeys: string[]) {
    const overlap = secretKeys.filter((k) => k in env);
    if (overlap.length)
      throw AppError.validation(
        [
          {
            path: 'env',
            message: `keys declared as secrets must not have plain values: ${overlap.join(', ')}`,
          },
        ],
        'env and secretKeys overlap',
      );
  }

  /** PATCH /applications/:id/container (If-Match). Pending approvals become invalid (planHash). */
  async update(
    user: AuthUser,
    appId: string,
    input: UpdateContainerAppInput,
    ifMatch: number | undefined,
  ): Promise<Application> {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.authz.enforce(user, 'apps.deploy', serverScope(ref.app.server), {
      action: 'applications.container_update',
      targetType: 'application',
      targetId: appId,
    });
    const executing = await this.prisma.deployment.findFirst({
      where: {
        applicationId: appId,
        status: { in: ACTIVE.filter((s) => s !== 'awaiting_approval') },
      },
      select: { id: true, status: true },
    });
    if (executing)
      throw AppError.conflict('A deployment is executing', ERROR_CODES.DEPLOYMENT_IN_PROGRESS, {
        deploymentId: executing.id,
      });
    const env = input.env ?? (ref.container.env as Record<string, string>);
    const secretKeys = input.secretKeys ?? ref.container.secretKeys;
    this.assertEnvVsSecrets(env, secretKeys);
    if (input.domains) {
      const conflicts = await this.preflight.domainConflicts(
        appId,
        ref.app.serverId,
        input.domains,
      );
      if (conflicts.length)
        throw AppError.conflict('Domain already in use', ERROR_CODES.DOMAIN_CONFLICT, {
          conflicts,
        });
    }
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.application.updateMany({
        where: { id: appId, ...(ifMatch !== undefined ? { version: ifMatch } : {}) },
        data: { ...(input.domains ? { domains: input.domains } : {}), version: { increment: 1 } },
      });
      if (r.count !== 1)
        throw AppError.conflict(
          'Application was modified by someone else',
          ERROR_CODES.VERSION_CONFLICT,
        );
      await tx.containerApp.update({
        where: { applicationId: appId },
        data: {
          ...(input.containerPort !== undefined ? { containerPort: input.containerPort } : {}),
          ...(input.healthcheck ? { healthcheck: input.healthcheck } : {}),
          ...(input.resources ? { resources: input.resources } : {}),
          ...(input.env ? { env: input.env } : {}),
          ...(input.secretKeys ? { secretKeys: input.secretKeys } : {}),
          ...(input.volumes ? { volumes: input.volumes as Prisma.InputJsonValue } : {}),
          ...(input.tls !== undefined
            ? { tls: input.tls === null ? Prisma.DbNull : (input.tls as Prisma.InputJsonValue) }
            : {}),
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'applications.container_update',
          targetType: 'application',
          targetId: appId,
          result: 'success',
          diff: { ...input, env: input.env ? Object.keys(input.env) : undefined },
          metadata: {
            fields: Object.keys(input),
            ...(input.env ? { envKeys: Object.keys(input.env) } : {}),
          },
        },
        tx,
      );
    });
    return this.apps.get(user, appId);
  }

  // ---------------------------------------------------------------- restart / start / stop

  private async currentContainer(ref: ContainerAppRef) {
    const id = ref.container.currentDeploymentId;
    const d = id ? await this.prisma.deployment.findUnique({ where: { id } }) : null;
    if (!d?.containerName || !d.hostPort || d.containerRemovedAt)
      throw AppError.conflict(
        'Application has no current container',
        ERROR_CODES.NO_CURRENT_DEPLOYMENT,
      );
    return { name: d.containerName, hostPort: d.hostPort, deploymentId: d.id };
  }

  /**
   * restart = `container.restart` of the current container (no new deployment; distinct from redeploy,
   * which creates a fresh container from the same digest). start/stop likewise. Audited.
   */
  async operate(
    user: AuthUser,
    appId: string,
    op: 'restart' | 'start' | 'stop',
    stepUp: string | undefined,
  ): Promise<ContainerOperationAccepted> {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    const scope = serverScope(ref.app.server);
    await this.authz.enforce(user, 'apps.deploy', scope, {
      action: `applications.${op}`,
      targetType: 'application',
      targetId: appId,
    });
    if (ref.app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (ref.app.server.environment === 'production') this.auth.assertStepUp(user, stepUp);
    const active = await this.prisma.deployment.findFirst({
      where: {
        applicationId: appId,
        status: { in: ACTIVE.filter((s) => s !== 'awaiting_approval') },
      },
      select: { id: true },
    });
    if (active)
      throw AppError.conflict('A deployment is executing', ERROR_CODES.DEPLOYMENT_IN_PROGRESS, {
        deploymentId: active.id,
      });
    const c = await this.currentContainer(ref);
    const hc = healthcheckOf(ref.container);
    const type = `container.${op}` as const;
    const params =
      op === 'stop'
        ? { app: ref.app.name, name: c.name }
        : { app: ref.app.name, name: c.name, hostPort: c.hostPort, healthcheck: hc };
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId: ref.app.serverId,
        type,
        params,
        actorId: user.id,
        ttlSec: OP_TTL_SEC,
        metadata: { applicationId: appId, deploymentId: c.deploymentId },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: `applications.${op}`,
          targetType: 'application',
          targetId: appId,
          result: 'success',
          metadata: { jobId: j.id, container: c.name, deploymentId: c.deploymentId },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(ref.app.serverId);
    return { jobId: job.id, operation: op, container: c.name };
  }

  // ---------------------------------------------------------------- logs (redacted)

  private async waitForJob(jobId: string): Promise<JobRow> {
    const deadline = Date.now() + this.config.PPANEL_NGINX_READ_WAIT_MS;
    for (;;) {
      const j = await this.prisma.job.findUniqueOrThrow({ where: { id: jobId } });
      if (this.jobs.isTerminal(j.status) || Date.now() >= deadline) return j;
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  /**
   * GET /applications/:id/logs?tail= — `container.logs` of the current container. The Center redacts
   * every known secret value of the app (the agent no longer holds them after the run job).
   */
  async logs(
    user: AuthUser,
    appId: string,
    tail: number,
    jobIdQuery: string | undefined,
  ): Promise<{ pending: boolean; body: ContainerLogs }> {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId);
    let job: JobRow;
    let name: string | null = null;
    if (jobIdQuery) {
      const j = await this.prisma.job.findFirst({
        where: { id: jobIdQuery, serverId: ref.app.serverId, type: 'container.logs' },
      });
      if (!j || (j.params as { app?: string }).app !== ref.app.name)
        throw AppError.notFound('Logs job');
      job = j;
      name = (j.params as { name?: string }).name ?? null;
    } else {
      const c = await this.currentContainer(ref);
      name = c.name;
      if (ref.app.server.status === 'revoked')
        throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
      const created = await this.prisma.$transaction(async (tx) => {
        const j = await this.jobs.createInternal(tx, {
          serverId: ref.app.serverId,
          type: 'container.logs',
          params: { app: ref.app.name, name: c.name, tailLines: tail },
          actorId: user.id,
          ttlSec: LOGS_TTL_SEC,
          metadata: { applicationId: appId },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'applications.logs_read',
            targetType: 'application',
            targetId: appId,
            result: 'success',
            metadata: { jobId: j.id, container: c.name, tail },
          },
          tx,
        );
        return j;
      });
      this.jobs.notify(ref.app.serverId);
      job = await this.waitForJob(created.id);
    }
    if (job.status === 'succeeded') {
      const scrubbed = await this.deployments.scrubJob(job, appId);
      const values = await this.secrets.knownValues(appId);
      const out = redactKnownValues(
        (scrubbed.result ?? {}) as { lines?: unknown; truncated?: unknown },
        values,
      );
      const lines = Array.isArray(out.lines)
        ? out.lines.filter((l): l is string => typeof l === 'string')
        : [];
      return {
        pending: false,
        body: {
          jobId: job.id,
          status: 'succeeded',
          lines,
          truncated: out.truncated === true,
          container: name,
        },
      };
    }
    if (this.jobs.isTerminal(job.status))
      throw new AppError(502, 'LOGS_READ_FAILED', `container.logs job ${job.status}`, {
        jobId: job.id,
        error: redactKnownValues(job.error, await this.secrets.knownValues(appId)),
      });
    return {
      pending: true,
      body: { jobId: job.id, status: 'pending', lines: [], truncated: false, container: name },
    };
  }

  async appView(user: AuthUser, appId: string): Promise<Application> {
    const row = await this.prisma.application.findUnique({
      where: { id: appId },
      include: appInclude,
    });
    if (!row) throw AppError.notFound('Application');
    return this.apps.view(user, row);
  }
}
