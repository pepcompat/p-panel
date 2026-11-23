import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  BUILD_ACTIVE_STATUSES,
  BUILD_LOG_MAX_BYTES,
  BUILD_LOG_MAX_LINES,
  type Build,
  type BuildAction,
  type BuildConfig,
  type BuildConfigInput,
  type BuildLog,
  type BuildStatus,
  type BuildTrigger,
  buildLimitsSchema,
  type CreateBuildInput,
  detectFramework,
  DETECT_MAX_FILE_BYTES,
  ERROR_CODES,
  isDigestPinned,
  SOURCE_INSPECT_FILES,
  type SourceInspection,
  type SourceRef,
} from '@ppanel/shared-contracts';
import type { Build as BuildRow, Job as JobRow, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger, redactKnownValues } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ApplicationsService } from '../discovery/applications.service';
import { appInclude, type AppWithServer, serverScope } from '../discovery/p3-common';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import { DeploymentsService } from './deployments.service';
import { repoOf, toBuildConfig } from './build-common';
import { RegistryClient } from './registry.client';
import { type ContainerAppRef, loadContainerApp, SecretsService } from './secrets.service';

const ACTIVE = [...BUILD_ACTIVE_STATUSES] as string[];
const INSPECT_TTL_SEC = 600;
/** Hosts always allowed outside production (lab git server). */
export const DEV_GIT_HOSTS = ['lab-git'];
// eslint-disable-next-line no-control-regex -- strips terminal escape sequences from build logs
const ANSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const IDEMPOTENCY_RE = /^[A-Za-z0-9_.:-]{8,128}$/;

/** `host[:port]` of a git URL (lowercase), or null. */
export function gitHostOf(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.username || u.password) return null;
    return u.host.toLowerCase();
  } catch {
    return null;
  }
}

/** Entry `host` matches that host on any port; `host:port` matches exactly. */
export function gitHostAllowed(host: string, allowlist: string[]): boolean {
  const bare = host.replace(/:\d+$/, '');
  return allowlist.some((e) => (e.includes(':') ? e === host : e === bare));
}

/** Bounded, ANSI-free, redacted log lines. */
export function boundLog(
  lines: unknown,
  secrets: string[],
): { lines: string[]; truncated: boolean } {
  const src = Array.isArray(lines) ? lines.filter((l): l is string => typeof l === 'string') : [];
  let truncated = src.length > BUILD_LOG_MAX_LINES;
  const kept = src.slice(-BUILD_LOG_MAX_LINES).map((l) => l.replace(ANSI_RE, '').slice(0, 4096));
  const out: string[] = [];
  let bytes = 0;
  for (let i = kept.length - 1; i >= 0; i--) {
    bytes += Buffer.byteLength(kept[i]!, 'utf8') + 1;
    if (bytes > BUILD_LOG_MAX_BYTES) {
      truncated = true;
      break;
    }
    out.unshift(kept[i]!);
  }
  return { lines: redactKnownValues(out, secrets), truncated };
}

interface BuildActor {
  id: string | null;
}

export interface StartBuildOptions {
  commitSha: string;
  branch?: string;
  deployAfter: boolean;
  force: boolean;
  trigger: BuildTrigger;
  idempotencyKey?: string;
  webhookDeliveryId?: string;
}

/**
 * P4b builds (§8.1–8.2): build config + git credential, `image.build` dispatch to a designated build
 * node, status/log from job results, deploy-after (normal §7.3 deployment pinned to the produced
 * digest), `source.inspect` for framework detection. Secrets (git token, registry credential) are only
 * delivered through the fetch-once secrets call and redacted from everything stored.
 */
@Injectable()
export class BuildsService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly apps: ApplicationsService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly secrets: SecretsService,
    private readonly registry: RegistryClient,
    private readonly deployments: DeploymentsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    this.hooks.register('image.build', (j) => this.onBuildFinished(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  // ---------------------------------------------------------------- allowlists

  gitAllowlist(): string[] {
    const out = this.config.PPANEL_GIT_HOST_ALLOWLIST.split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean);
    if (!this.config.isProduction) out.push(...DEV_GIT_HOSTS);
    return out;
  }

  private assertRepoUrl(url: string) {
    const host = gitHostOf(url);
    if (!host || !gitHostAllowed(host, this.gitAllowlist()))
      throw new AppError(
        422,
        ERROR_CODES.GIT_HOST_NOT_ALLOWED,
        `Git host ${host ?? '?'} is not in PPANEL_GIT_HOST_ALLOWLIST`,
        { host },
      );
    if (this.config.isProduction && !url.startsWith('https://'))
      throw new AppError(
        422,
        ERROR_CODES.GIT_HOST_NOT_ALLOWED,
        'Only https:// git URLs are allowed',
      );
  }

  private async assertPushRepo(appId: string, pushRepo: string) {
    const host = pushRepo.split('/')[0]!.toLowerCase();
    const cred = await this.secrets.registryCredential(appId);
    if (!this.registry.allowedHosts(cred ? [cred.serveraddress] : []).has(host))
      throw new AppError(
        422,
        ERROR_CODES.REGISTRY_NOT_ALLOWED,
        `Registry ${host} is not allowlisted for pushRepo`,
        { host },
      );
  }

  /** 409 NO_BUILD_NODE unless the server is designated (`buildNode`) and reports the `build` capability. */
  async assertBuildNode(serverId: string) {
    const s = await this.prisma.server.findUnique({
      where: { id: serverId },
      include: { capabilities: true },
    });
    const capability = !!s?.capabilities.some((c) => c.name === 'build');
    if (!s || s.status === 'revoked' || !s.buildNode || !capability)
      throw AppError.conflict(
        'The build server is not an enabled build node (designation + agent `build` capability)',
        ERROR_CODES.NO_BUILD_NODE,
        {
          serverId,
          buildNode: s?.buildNode ?? false,
          capability,
          revoked: s?.status === 'revoked',
        },
      );
    return s;
  }

  // ---------------------------------------------------------------- build config (§8.1)

  async configView(appId: string): Promise<BuildConfig | null> {
    const r = await this.prisma.buildConfig.findUnique({ where: { applicationId: appId } });
    return r ? toBuildConfig(r, await this.secrets.hasGitToken(appId)) : null;
  }

  async getConfig(user: AuthUser, appId: string): Promise<BuildConfig | null> {
    await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    return this.configView(appId);
  }

  async putConfig(
    user: AuthUser,
    appId: string,
    input: BuildConfigInput,
    ifMatch: number | undefined,
  ): Promise<BuildConfig> {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.authz.enforce(user, 'apps.deploy', serverScope(app.server), {
      action: 'builds.config_set',
      targetType: 'application',
      targetId: appId,
    });
    this.assertRepoUrl(input.repoUrl);
    await this.assertPushRepo(appId, input.pushRepo);
    const bs = await this.prisma.server.findUnique({ where: { id: input.buildServerId } });
    if (!bs || !this.authz.can(user, 'fleet.read', serverScope(bs)))
      throw AppError.validation([{ path: 'buildServerId', message: 'unknown server' }]);
    const data = {
      repoUrl: input.repoUrl,
      subdir: input.subdir,
      dockerfile: input.dockerfile ?? null,
      template: input.template ?? null,
      buildArgs: input.buildArgs,
      target: input.target ?? null,
      buildServerId: input.buildServerId,
      pushRepo: input.pushRepo,
      network: input.network,
      limits: input.limits,
      updatedBy: user.id,
    };
    await this.prisma.$transaction(async (tx) => {
      const cur = await tx.buildConfig.findUnique({ where: { applicationId: appId } });
      if (cur) {
        const r = await tx.buildConfig.updateMany({
          where: { applicationId: appId, ...(ifMatch !== undefined ? { version: ifMatch } : {}) },
          data: { ...data, version: { increment: 1 } },
        });
        if (r.count !== 1)
          throw AppError.conflict(
            'Build config was modified by someone else',
            ERROR_CODES.VERSION_CONFLICT,
          );
      } else
        await tx.buildConfig.create({
          data: { applicationId: appId, createdBy: user.id, ...data },
        });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'builds.config_set',
          targetType: 'application',
          targetId: appId,
          result: 'success',
          diff: { ...input, buildArgs: Object.keys(input.buildArgs) },
          metadata: {
            repoUrl: input.repoUrl,
            pushRepo: input.pushRepo,
            buildServerId: input.buildServerId,
            buildArgKeys: Object.keys(input.buildArgs),
          },
        },
        tx,
      );
    });
    return (await this.configView(appId))!;
  }

  // ---------------------------------------------------------------- builds (§8.2)

  private actions(user: AuthUser, b: BuildRow, app: AppWithServer): BuildAction[] {
    const scope = serverScope(app.server);
    const out: BuildAction[] = [];
    if (ACTIVE.includes(b.status) && this.authz.can(user, 'apps.deploy', scope)) out.push('cancel');
    if (this.authz.can(user, 'apps.read', scope)) out.push('view_log');
    return out;
  }

  private toView(user: AuthUser, b: BuildRow, app: AppWithServer): Build {
    return {
      id: b.id,
      applicationId: b.applicationId,
      buildServerId: b.buildServerId,
      status: b.status as BuildStatus,
      commitSha: b.commitSha,
      branch: b.branch,
      trigger: b.trigger as BuildTrigger,
      image: b.image,
      template: b.template,
      dockerfile: b.dockerfile,
      pushRepo: b.pushRepo,
      deployAfter: b.deployAfter,
      logTail: b.logTail,
      error: (b.error as Build['error']) ?? null,
      durationMs: b.durationMs,
      jobId: b.jobId,
      deploymentId: b.deploymentId,
      deployError: (b.deployError as Build['deployError']) ?? null,
      createdBy: b.createdBy,
      createdAt: b.createdAt.toISOString(),
      updatedAt: b.updatedAt.toISOString(),
      finishedAt: b.finishedAt?.toISOString() ?? null,
      allowedActions: this.actions(user, b, app),
    };
  }

  /** queued → building once the agent leased the job (no progress channel: fetch/build/push = building). */
  private async refresh(rows: BuildRow[]): Promise<BuildRow[]> {
    const active = rows.filter((r) => ACTIVE.includes(r.status) && r.jobId);
    if (active.length === 0) return rows;
    const jobs = new Map(
      (
        await this.prisma.job.findMany({
          where: { id: { in: active.map((r) => r.jobId!) } },
          select: { id: true, status: true },
        })
      ).map((j) => [j.id, j.status]),
    );
    const out: BuildRow[] = [];
    for (const r of rows) {
      const js = r.jobId ? jobs.get(r.jobId) : undefined;
      if (r.status === 'queued' && (js === 'leased' || js === 'running')) {
        const u = await this.prisma.build.updateMany({
          where: { id: r.id, status: 'queued' },
          data: { status: 'building' },
        });
        out.push(u.count ? { ...r, status: 'building' } : r);
      } else if (js && this.jobs.isTerminal(js) && ACTIVE.includes(r.status)) {
        const job = await this.prisma.job.findUnique({ where: { id: r.jobId! } });
        if (job) await this.jobs.dispatchFinished(job);
        out.push((await this.prisma.build.findUnique({ where: { id: r.id } })) ?? r);
      } else out.push(r);
    }
    return out;
  }

  private async loadBuild(user: AuthUser, id: string) {
    const b = await this.prisma.build.findUnique({ where: { id } });
    if (!b) throw AppError.notFound('Build');
    const app = await this.prisma.application.findUnique({
      where: { id: b.applicationId },
      include: appInclude,
    });
    if (!app || !this.authz.can(user, 'apps.read', serverScope(app.server)))
      throw AppError.notFound('Build');
    return { b, app };
  }

  async get(user: AuthUser, id: string): Promise<Build> {
    const { b, app } = await this.loadBuild(user, id);
    const [fresh] = await this.refresh([b]);
    return this.toView(user, fresh!, app);
  }

  async list(user: AuthUser, appId: string, pq: ParsedQuery) {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    const where: Prisma.BuildWhereInput = {
      AND: [
        { applicationId: appId },
        buildWhere(pq, {
          status: { prop: 'status', type: 'string' },
          commit_sha: { prop: 'commitSha', type: 'string' },
          trigger: { prop: 'trigger', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }) as Prisma.BuildWhereInput,
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.build.count({ where }),
      this.prisma.build.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    const fresh = await this.refresh(rows);
    return new Paginated(
      fresh.map((r) => this.toView(user, r, app)),
      paginate(pq, total),
    );
  }

  async log(user: AuthUser, id: string): Promise<BuildLog> {
    const { b } = await this.loadBuild(user, id);
    // stored redacted; redact again in case a secret was set after the build ran
    const lines = redactKnownValues(b.log, await this.secrets.knownValues(b.applicationId));
    return { buildId: b.id, status: b.status as BuildStatus, lines, truncated: b.logTruncated };
  }

  async create(
    user: AuthUser,
    appId: string,
    input: CreateBuildInput,
    idempotencyKey: string | undefined,
  ): Promise<{ created: boolean; build: Build }> {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.deployments.enforceDeploy(user, ref, 'builds.create');
    if (idempotencyKey !== undefined && !IDEMPOTENCY_RE.test(idempotencyKey))
      throw AppError.badRequest('Idempotency-Key must be 8-128 chars of [A-Za-z0-9_.:-]');
    const { row, created } = await this.start({ id: user.id }, ref, {
      commitSha: input.commitSha,
      branch: input.branch,
      deployAfter: input.deployAfter,
      force: input.force,
      trigger: 'manual',
      idempotencyKey,
    });
    return { created, build: this.toView(user, row, ref.app) };
  }

  /**
   * Shared creation path (manual, webhook). Same app + commit: a succeeded build is returned without a
   * rebuild (unless `force`), an active one is returned as is (partial unique index).
   */
  async start(
    actor: BuildActor,
    ref: ContainerAppRef,
    opts: StartBuildOptions,
  ): Promise<{ row: BuildRow; created: boolean }> {
    const { app } = ref;
    const cfg = await this.prisma.buildConfig.findUnique({ where: { applicationId: app.id } });
    if (!cfg)
      throw AppError.conflict(
        'Configure the build source first (PUT /applications/:id/build-config)',
        ERROR_CODES.BUILD_CONFIG_MISSING,
      );
    if (opts.idempotencyKey) {
      const ex = await this.prisma.build.findUnique({
        where: {
          applicationId_idempotencyKey: {
            applicationId: app.id,
            idempotencyKey: opts.idempotencyKey,
          },
        },
      });
      if (ex) {
        if (ex.commitSha !== opts.commitSha)
          throw AppError.conflict(
            'Idempotency-Key was already used for a different request',
            ERROR_CODES.CONFLICT,
          );
        return { row: ex, created: false };
      }
    }
    const active = await this.prisma.build.findFirst({
      where: { applicationId: app.id, commitSha: opts.commitSha, status: { in: ACTIVE } },
    });
    if (active) return { row: active, created: false };
    if (!opts.force) {
      const done = await this.prisma.build.findFirst({
        where: { applicationId: app.id, commitSha: opts.commitSha, status: 'succeeded' },
        orderBy: { createdAt: 'desc' },
      });
      if (done) return { row: done, created: false };
    }
    await this.assertBuildNode(cfg.buildServerId);
    this.assertRepoUrl(cfg.repoUrl);
    const id = uuidv7();
    const gitAuth = await this.secrets.hasGitToken(app.id);
    const { registry } = await this.secrets.keyVersions(app.id);
    const limits = buildLimitsSchema.parse(cfg.limits ?? {});
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const job = await this.jobs.createInternal(tx, {
          serverId: cfg.buildServerId,
          type: 'image.build',
          params: {
            buildId: id,
            app: app.name,
            source: {
              url: cfg.repoUrl,
              commitSha: opts.commitSha,
              subdir: cfg.subdir,
              auth: gitAuth,
            },
            ...(cfg.dockerfile ? { dockerfile: cfg.dockerfile } : {}),
            ...(cfg.template ? { template: cfg.template } : {}),
            buildArgs: (cfg.buildArgs ?? {}) as Record<string, string>,
            ...(cfg.target ? { target: cfg.target } : {}),
            pushRepo: cfg.pushRepo,
            registryAuth: registry,
            network: cfg.network,
            limits,
          },
          actorId: actor.id,
          ttlSec: limits.timeoutSec + 1800, // queue wait on a busy build node + the build itself
          metadata: { buildId: id, applicationId: app.id, commitSha: opts.commitSha },
        });
        const b = await tx.build.create({
          data: {
            id,
            applicationId: app.id,
            buildServerId: cfg.buildServerId,
            status: 'queued',
            commitSha: opts.commitSha,
            branch: opts.branch ?? null,
            trigger: opts.trigger,
            repo: repoOf(cfg.repoUrl),
            dockerfile: cfg.dockerfile,
            template: cfg.template,
            pushRepo: cfg.pushRepo,
            deployAfter: opts.deployAfter,
            force: opts.force,
            jobId: job.id,
            idempotencyKey: opts.idempotencyKey ?? null,
            webhookDeliveryId: opts.webhookDeliveryId ?? null,
            createdBy: actor.id,
          },
        });
        await this.audit.record(
          {
            actorId: actor.id,
            ...(actor.id ? {} : { actorType: 'system' as const }),
            action: 'builds.create',
            targetType: 'build',
            targetId: id,
            result: 'success',
            metadata: {
              applicationId: app.id,
              buildServerId: cfg.buildServerId,
              commitSha: opts.commitSha,
              trigger: opts.trigger,
              deployAfter: opts.deployAfter,
              force: opts.force,
              jobId: job.id,
            },
          },
          tx,
        );
        return b;
      });
      this.jobs.notify(cfg.buildServerId);
      return { row, created: true };
    } catch (e) {
      if (isUniqueViolation(e)) {
        const raced = await this.prisma.build.findFirst({
          where: {
            applicationId: app.id,
            OR: [
              { commitSha: opts.commitSha, status: { in: ACTIVE } },
              ...(opts.idempotencyKey ? [{ idempotencyKey: opts.idempotencyKey }] : []),
            ],
          },
        });
        if (raced) return { row: raced, created: false };
      }
      throw e;
    }
  }

  async cancel(user: AuthUser, id: string): Promise<Build> {
    const { b, app } = await this.loadBuild(user, id);
    await this.authz.enforce(user, 'apps.deploy', serverScope(app.server), {
      action: 'builds.cancel',
      targetType: 'build',
      targetId: id,
    });
    if (!ACTIVE.includes(b.status))
      throw AppError.conflict(`Build is ${b.status}`, ERROR_CODES.BUILD_STATE_INVALID, {
        status: b.status,
        allowed: ACTIVE,
      });
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.build.updateMany({
        where: { id, status: { in: ACTIVE } },
        data: {
          status: 'cancelled',
          finishedAt: now,
          error: { code: 'CANCELLED', message: `Cancelled by ${user.email}` },
        },
      });
      if (r.count !== 1)
        throw AppError.conflict('Build changed concurrently', ERROR_CODES.BUILD_STATE_INVALID);
      // a queued/leased job is cancelled; a running one finishes and its result is discarded
      const j = b.jobId
        ? await tx.job.updateMany({
            where: { id: b.jobId, status: { in: ['queued', 'leased'] } },
            data: {
              status: 'cancelled',
              finishedAt: now,
              leaseTokenHash: null,
              error: { code: 'CANCELLED' },
            },
          })
        : { count: 0 };
      await this.audit.record(
        {
          actorId: user.id,
          action: 'builds.cancel',
          targetType: 'build',
          targetId: id,
          result: 'success',
          metadata: { from: b.status, jobCancelled: j.count === 1 },
        },
        tx,
      );
    });
    return this.get(user, id);
  }

  // ---------------------------------------------------------------- job hook (idempotent)

  /** Stores the redacted bounded log on the build and strips it (and any secret) from the job row. */
  private async scrubBuildJob(job: FinishedJob, secrets: string[]) {
    const result = (job.result ?? null) as Record<string, unknown> | null;
    const slim = result ? { ...result } : null;
    if (slim) delete slim.log;
    const error = redactKnownValues(job.error, secrets) as Record<string, unknown> | null;
    if (error && typeof error === 'object' && error.details && typeof error.details === 'object') {
      const d = { ...(error.details as Record<string, unknown>) };
      delete d.log;
      error.details = d;
    }
    await this.prisma.job.update({
      where: { id: job.id },
      data: {
        result: (redactKnownValues(slim, secrets) ?? undefined) as
          Prisma.InputJsonValue | undefined,
        error: (error ?? undefined) as Prisma.InputJsonValue | undefined,
      },
    });
  }

  private async onBuildFinished(job: FinishedJob): Promise<void> {
    const b = await this.prisma.build.findFirst({ where: { jobId: job.id } });
    if (!b) return;
    const secrets = await this.secrets.knownValues(b.applicationId);
    const out = (job.result ?? {}) as {
      image?: unknown;
      logTail?: unknown;
      log?: unknown;
      durationMs?: unknown;
      template?: unknown;
    };
    const e = (job.error ?? {}) as {
      code?: unknown;
      message?: unknown;
      details?: { logTail?: unknown; log?: unknown };
    };
    const ok = job.status === 'succeeded';
    const full = boundLog(
      ok ? (out.log ?? out.logTail) : (e.details?.log ?? e.details?.logTail),
      secrets,
    );
    const tail = boundLog(ok ? out.logTail : e.details?.logTail, secrets).lines.slice(-200);
    const image = typeof out.image === 'string' ? out.image : null;
    const validImage =
      ok && image && isDigestPinned(image) && image.startsWith(`${b.pushRepo}@sha256:`);
    let status: BuildStatus;
    let error: { code: string; message: string } | null = null;
    if (ok && validImage) status = 'succeeded';
    else if (ok) {
      status = 'failed';
      error = {
        code: 'PUSH_FAILED',
        message: 'Agent returned no digest-pinned image for the push repository',
      };
    } else {
      status =
        job.status === 'expired' ? 'expired' : job.status === 'cancelled' ? 'cancelled' : 'failed';
      error = {
        code:
          typeof e.code === 'string'
            ? e.code
            : job.status === 'expired'
              ? 'LEASE_EXPIRED'
              : job.status === 'cancelled'
                ? 'CANCELLED'
                : 'BUILD_FAILED',
        message: redactKnownValues(
          typeof e.message === 'string' ? e.message.slice(0, 1000) : `job ${job.status}`,
          secrets,
        ),
      };
    }
    const now = new Date();
    const moved = await this.prisma.$transaction(async (tx: Tx) => {
      const r = await tx.build.updateMany({
        where: { id: b.id, status: { in: ACTIVE } },
        data: {
          status,
          image: status === 'succeeded' ? image : null,
          logTail: tail.length ? tail : full.lines.slice(-200),
          log: full.lines,
          logTruncated: full.truncated,
          durationMs:
            typeof out.durationMs === 'number'
              ? Math.round(out.durationMs)
              : now.getTime() - b.createdAt.getTime(),
          error: (error ?? undefined) as Prisma.InputJsonValue | undefined,
          finishedAt: now,
        },
      });
      if (r.count === 1)
        await this.audit.record(
          {
            actorType: 'system',
            action: 'builds.status',
            targetType: 'build',
            targetId: b.id,
            result: status === 'succeeded' ? 'success' : 'failure',
            metadata: {
              from: b.status,
              to: status,
              jobId: job.id,
              applicationId: b.applicationId,
              commitSha: b.commitSha,
              ...(status === 'succeeded' ? { image } : { errorCode: error?.code }),
            },
          },
          tx,
        );
      return r.count === 1;
    });
    await this.scrubBuildJob(job, secrets);
    if (!moved || status !== 'succeeded' || !b.deployAfter) return;
    await this.deployBuild({ ...b, status, image });
  }

  /** deployAfter: a normal deployment pinned to the produced digest (production → awaiting_approval). */
  private async deployBuild(b: BuildRow): Promise<void> {
    try {
      const app = await this.prisma.application.findUniqueOrThrow({
        where: { id: b.applicationId },
        include: appInclude,
      });
      const container = await this.prisma.containerApp.findUniqueOrThrow({
        where: { applicationId: app.id },
      });
      const sourceRef: SourceRef = {
        ...(b.repo ? { repo: b.repo } : {}),
        commitSha: b.commitSha,
        ...(b.branch ? { branch: b.branch } : {}),
      };
      const { row } = await this.deployments.create(
        { user: null, id: b.createdBy },
        { app, container },
        {
          image: b.image!,
          trigger: b.trigger === 'webhook' ? 'webhook' : 'manual',
          sourceRef,
          reason: `build ${b.commitSha.slice(0, 7)}`,
          commitSha: b.commitSha,
          buildId: b.id,
          ...(b.webhookDeliveryId ? { webhookDeliveryId: b.webhookDeliveryId } : {}),
        },
      );
      await this.prisma.build.update({ where: { id: b.id }, data: { deploymentId: row.id } });
      if (b.webhookDeliveryId) {
        const del = await this.prisma.webhookDelivery.findUnique({
          where: { id: b.webhookDeliveryId },
        });
        if (del && !del.deploymentIds.includes(row.id))
          await this.prisma.webhookDelivery.update({
            where: { id: del.id },
            data: {
              deploymentIds: [...del.deploymentIds, row.id],
              ...(del.result === 'building'
                ? {
                    result:
                      row.status === 'awaiting_approval'
                        ? 'awaiting_approval'
                        : row.status === 'failed'
                          ? 'failed'
                          : 'deployed',
                  }
                : {}),
            },
          });
      }
    } catch (err) {
      const code = err instanceof AppError ? String(err.code) : 'INTERNAL_ERROR';
      const message = err instanceof Error ? err.message.slice(0, 500) : 'deployment failed';
      if (!(err instanceof AppError)) logger.emit('error', 'deploy after build failed', { err });
      await this.prisma.build.update({
        where: { id: b.id },
        data: { deployError: { code, message } },
      });
    }
  }

  /** Re-dispatch terminal build jobs whose build is still active (missed hook, restart, expiry). */
  async reconcile(): Promise<number> {
    const rows = await this.prisma.build.findMany({
      where: { status: { in: ACTIVE }, jobId: { not: null } },
      take: 100,
    });
    for (const r of rows) {
      const job = await this.prisma.job.findUnique({ where: { id: r.jobId! } });
      if (job && this.jobs.isTerminal(job.status)) await this.jobs.dispatchFinished(job);
    }
    return rows.length;
  }

  // ---------------------------------------------------------------- source inspection (§8.2)

  private async waitForJob(jobId: string): Promise<JobRow> {
    const deadline = Date.now() + this.config.PPANEL_NGINX_READ_WAIT_MS;
    for (;;) {
      const j = await this.prisma.job.findUniqueOrThrow({ where: { id: jobId } });
      if (this.jobs.isTerminal(j.status) || Date.now() >= deadline) return j;
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  async inspect(
    user: AuthUser,
    appId: string,
    commitSha: string,
  ): Promise<{ pending: boolean; body: SourceInspection }> {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    await this.deployments.enforceDeploy(user, ref, 'builds.inspect_source');
    const cfg = await this.prisma.buildConfig.findUnique({ where: { applicationId: appId } });
    if (!cfg)
      throw AppError.conflict(
        'Configure the build source first (PUT /applications/:id/build-config)',
        ERROR_CODES.BUILD_CONFIG_MISSING,
      );
    await this.assertBuildNode(cfg.buildServerId);
    this.assertRepoUrl(cfg.repoUrl);
    const auth = await this.secrets.hasGitToken(appId);
    const id = uuidv7();
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId: cfg.buildServerId,
        type: 'source.inspect',
        params: { source: { url: cfg.repoUrl, commitSha, subdir: cfg.subdir, auth } },
        actorId: user.id,
        ttlSec: INSPECT_TTL_SEC,
        metadata: { applicationId: appId, inspectionId: id },
      });
      await tx.sourceInspection.create({
        data: { id, applicationId: appId, jobId: j.id, commitSha, createdBy: user.id },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'builds.inspect_source',
          targetType: 'application',
          targetId: appId,
          result: 'success',
          metadata: { inspectionId: id, jobId: j.id, commitSha },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(cfg.buildServerId);
    return this.inspectionView(id, appId, await this.waitForJob(job.id), commitSha);
  }

  async getInspection(user: AuthUser, appId: string, inspectionId: string) {
    await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    const i = await this.prisma.sourceInspection.findFirst({
      where: { id: inspectionId, applicationId: appId },
    });
    if (!i) throw AppError.notFound('Source inspection');
    const job = await this.prisma.job.findUniqueOrThrow({ where: { id: i.jobId } });
    return this.inspectionView(i.id, appId, job, i.commitSha);
  }

  private async inspectionView(
    id: string,
    appId: string,
    job: JobRow,
    commitSha: string,
  ): Promise<{ pending: boolean; body: SourceInspection }> {
    const base = { inspectionId: id, jobId: job.id, commitSha };
    const secrets = await this.secrets.knownValues(appId);
    if (job.status === 'succeeded') {
      const out = (job.result ?? {}) as { files?: unknown; truncated?: unknown };
      const files: Record<string, string> = {};
      const raw =
        out.files && typeof out.files === 'object' ? (out.files as Record<string, unknown>) : {};
      for (const name of SOURCE_INSPECT_FILES) {
        const v = raw[name];
        if (typeof v === 'string' && Buffer.byteLength(v, 'utf8') <= DETECT_MAX_FILE_BYTES)
          files[name] = redactKnownValues(v, secrets);
      }
      const truncated = Array.isArray(out.truncated)
        ? out.truncated.filter((x): x is string => typeof x === 'string').slice(0, 50)
        : [];
      return {
        pending: false,
        body: {
          ...base,
          status: 'succeeded',
          files,
          truncated,
          detection: detectFramework(files),
          error: null,
        },
      };
    }
    if (this.jobs.isTerminal(job.status)) {
      const e = (job.error ?? {}) as { code?: unknown; message?: unknown };
      return {
        pending: false,
        body: {
          ...base,
          status: 'failed',
          files: {},
          truncated: [],
          detection: null,
          error: {
            code: typeof e.code === 'string' ? e.code : job.status.toUpperCase(),
            message: redactKnownValues(
              typeof e.message === 'string' ? e.message.slice(0, 500) : `job ${job.status}`,
              secrets,
            ),
          },
        },
      };
    }
    return {
      pending: true,
      body: { ...base, status: 'pending', files: {}, truncated: [], detection: null, error: null },
    };
  }
}
