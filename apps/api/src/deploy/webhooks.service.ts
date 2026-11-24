import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  type AutoDeployPolicy,
  DEPLOYMENT_ACTIVE_STATUSES,
  type AutoDeployPolicyInput,
  branchMatches,
  ERROR_CODES,
  type Integration,
  renderImageTemplate,
  type WebhookDelivery,
  type WebhookDeliveryResult,
} from '@ppanel/shared-contracts';
import type {
  AutoDeployPolicy as PolicyRow,
  Integration as IntegrationRow,
  WebhookDelivery as DeliveryRow,
} from '@prisma/client';
import type { Prisma } from '@prisma/client';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret } from '../common/crypto';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { paginate, type ParsedQuery } from '../common/query-builder';
import { RateLimiter } from '../common/rate-limiter';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ApplicationsService } from '../discovery/applications.service';
import { appInclude, serverScope } from '../discovery/p3-common';
import { JobHooks } from '../jobs/job-hooks';
import { BuildsService } from './builds.service';
import { DeploymentsService } from './deployments.service';
import { parseTaggedRef, RegistryClient } from './registry.client';
import { loadContainerApp, SecretsService } from './secrets.service';

const ZERO_SHA = /^0{40}$/;
const API_PREFIX = 'api/v1';
const DELIVERY_ID_RE = /^[A-Za-z0-9-]{1,100}$/;
const ACTIVE = [...DEPLOYMENT_ACTIVE_STATUSES] as string[];
/** Reason a delivery row carries while its request is still being processed. */
const PROCESSING = 'processing';

type QueueOutcome = 'queued' | 'already_deployed' | 'already_queued' | 'idle';
interface DeliveryPatch {
  result?: WebhookDeliveryResult;
  reasons?: string[];
  deploymentIds?: string[];
}

/** Constant-time check of `X-Hub-Signature-256: sha256=<hex>` over the raw body. */
export function verifyGithubSignature(
  secret: string,
  raw: Buffer,
  header: string | undefined,
): boolean {
  if (!header || !/^sha256=[a-f0-9]{64}$/.test(header)) return false;
  const expected = Buffer.from(createHmac('sha256', secret).update(raw).digest('hex'), 'utf8');
  const given = Buffer.from(header.slice(7), 'utf8');
  return given.length === expected.length && timingSafeEqual(given, expected);
}

interface PushPayload {
  ref?: unknown;
  after?: unknown;
  deleted?: unknown;
  repository?: { full_name?: unknown };
}

/** Interactive transaction options for the webhook queue (bursts contend for pool connections). */
const TX_OPTS = { maxWait: 15_000, timeout: 20_000 } as const;

@Injectable()
export class WebhooksService implements OnModuleInit {
  /**
   * F-7: per-app in-process serialization of webhook deploy/queue/drain work. Correctness across
   * instances comes from the container_apps row lock; this only stops a delivery storm from piling
   * up concurrent transactions (pool exhaustion) for one app.
   */
  private readonly appChains = new Map<string, Promise<unknown>>();

  private withAppLock<T>(appId: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.appChains.get(appId) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => undefined);
    this.appChains.set(appId, tail);
    void tail.then(() => {
      if (this.appChains.get(appId) === tail) this.appChains.delete(appId);
    });
    return run;
  }

  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly limiter: RateLimiter,
    private readonly apps: ApplicationsService,
    private readonly deployments: DeploymentsService,
    private readonly secrets: SecretsService,
    private readonly registry: RegistryClient,
    private readonly builds: BuildsService,
    private readonly hooks: JobHooks,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    // F-7: start the app's pending (coalesced) webhook commit when its deployment ends; the
    // reconcile pass (sweeper) repairs anything missed (API restart, cancel, approval failure).
    this.deployments.onDeploymentSettled((appId) => this.drainPending(appId).then(() => undefined));
    this.hooks.registerReconciler(() => this.drainAll());
  }

  // ---------------------------------------------------------------- integrations

  private aad(id: string) {
    return `integration:${id}`;
  }

  private toIntegration(r: IntegrationRow): Integration {
    return {
      id: r.id,
      kind: 'github',
      name: r.name,
      webhookUrl: `/${API_PREFIX}/webhooks/github/${r.id}`,
      webhookSecret: { set: true },
      enabled: r.enabled,
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
    };
  }

  async createIntegration(user: AuthUser, input: { name: string; webhookSecret: string }) {
    await this.authz.enforce(user, 'policies.manage', undefined, {
      action: 'integrations.create',
      targetType: 'integration',
    });
    const id = uuidv7();
    const row = await this.prisma.$transaction(async (tx) => {
      const r = await tx.integration.create({
        data: {
          id,
          kind: 'github',
          name: input.name,
          webhookSecretEnc: encryptSecret(this.config.masterKey, input.webhookSecret, this.aad(id)),
          createdBy: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'integrations.create',
          targetType: 'integration',
          targetId: id,
          result: 'success',
          metadata: { kind: 'github', name: input.name },
        },
        tx,
      );
      return r;
    });
    return this.toIntegration(row);
  }

  async listIntegrations(): Promise<Integration[]> {
    const rows = await this.prisma.integration.findMany({ orderBy: { createdAt: 'desc' } });
    return rows.map((r) => this.toIntegration(r));
  }

  /**
   * Delivery log. Global `apps.deploy` sees every delivery; a scoped principal only sees deliveries
   * for repos wired (auto-deploy policy) to applications it can read, with deployment/build ids of
   * other scopes removed (SEC-P7-03: deliveries used to leak repos/SHAs/ids across scopes).
   */
  async deliveries(user: AuthUser, integrationId: string, pq: ParsedQuery) {
    const exists = await this.prisma.integration.findUnique({ where: { id: integrationId } });
    if (!exists) throw AppError.notFound('Integration');
    const global = this.authz.can(user, 'apps.deploy');
    let where: Prisma.WebhookDeliveryWhereInput = { integrationId };
    let visibleApps: Set<string> | null = null;
    if (!global) {
      const serverWhere = this.authz.serverWhere(user, 'apps.read');
      const policies = serverWhere
        ? await this.prisma.autoDeployPolicy.findMany({
            where: { integrationId, application: { server: serverWhere } },
            select: { repo: true, applicationId: true },
          })
        : [];
      visibleApps = new Set(policies.map((p) => p.applicationId));
      where = { integrationId, repo: { in: [...new Set(policies.map((p) => p.repo))] } };
    }
    const [total, rows] = await Promise.all([
      this.prisma.webhookDelivery.count({ where }),
      this.prisma.webhookDelivery.findMany({
        where,
        orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    if (visibleApps) {
      const apps = [...visibleApps];
      const depIds = rows.flatMap((r) => r.deploymentIds);
      const buildIds = rows.flatMap((r) => r.buildIds);
      const [deps, builds] = await Promise.all([
        this.prisma.deployment.findMany({
          where: { id: { in: depIds }, applicationId: { in: apps } },
          select: { id: true },
        }),
        this.prisma.build.findMany({
          where: { id: { in: buildIds }, applicationId: { in: apps } },
          select: { id: true },
        }),
      ]);
      const okDep = new Set(deps.map((d) => d.id));
      const okBuild = new Set(builds.map((b) => b.id));
      for (const r of rows) {
        r.deploymentIds = r.deploymentIds.filter((id) => okDep.has(id));
        r.buildIds = r.buildIds.filter((id) => okBuild.has(id));
      }
    }
    return new Paginated(rows.map(toDelivery), paginate(pq, total));
  }

  // ---------------------------------------------------------------- auto-deploy policies

  private toPolicy(r: PolicyRow): AutoDeployPolicy {
    return {
      id: r.id,
      applicationId: r.applicationId,
      integrationId: r.integrationId,
      repo: r.repo,
      branches: r.branches,
      mode: r.mode as AutoDeployPolicy['mode'],
      imageTemplate: r.imageTemplate,
      enabled: r.enabled,
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    };
  }

  async listPolicies(user: AuthUser, appId: string): Promise<AutoDeployPolicy[]> {
    await loadContainerApp(this.apps, this.prisma, user, appId);
    const rows = await this.prisma.autoDeployPolicy.findMany({
      where: { applicationId: appId },
      orderBy: { createdAt: 'asc' },
    });
    return rows.map((r) => this.toPolicy(r));
  }

  private async assertTemplateHost(appId: string, template: string) {
    const rendered = renderImageTemplate(template, 'a'.repeat(40), 'main');
    const ref = rendered ? parseTaggedRef(rendered) : null;
    const cred = await this.secrets.registryCredential(appId);
    const allowed = this.registry.allowedHosts(cred ? [cred.serveraddress] : []);
    if (!ref || !allowed.has(ref.host))
      throw new AppError(
        422,
        ERROR_CODES.REGISTRY_NOT_ALLOWED,
        'imageTemplate registry is not allowlisted',
        {
          host: ref?.host ?? null,
        },
      );
  }

  /** image mode needs an allowlisted imageTemplate; build mode needs the app's build config. */
  private async assertModeConfig(
    appId: string,
    mode: string,
    imageTemplate: string | null | undefined,
  ) {
    if (mode === 'image') {
      if (!imageTemplate)
        throw AppError.validation(
          [{ path: 'imageTemplate', message: 'imageTemplate is required in image mode' }],
          'imageTemplate is required in image mode',
        );
      await this.assertTemplateHost(appId, imageTemplate);
      return;
    }
    const cfg = await this.prisma.buildConfig.findUnique({ where: { applicationId: appId } });
    if (!cfg)
      throw AppError.conflict(
        'Build mode needs a build config (PUT /applications/:id/build-config)',
        ERROR_CODES.BUILD_CONFIG_MISSING,
      );
  }

  async createPolicy(user: AuthUser, appId: string, input: AutoDeployPolicyInput) {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId, ['container']);
    const scope = serverScope(app.server);
    const audit = { action: 'auto_deploy.create', targetType: 'application', targetId: appId };
    await this.authz.enforce(user, 'apps.deploy', scope, audit);
    await this.authz.enforce(user, 'policies.manage', scope, audit);
    const integ = await this.prisma.integration.findUnique({ where: { id: input.integrationId } });
    if (!integ) throw AppError.notFound('Integration');
    await this.assertModeConfig(appId, input.mode, input.imageTemplate);
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const r = await tx.autoDeployPolicy.create({
          data: {
            id: uuidv7(),
            applicationId: appId,
            integrationId: input.integrationId,
            repo: input.repo,
            branches: input.branches,
            mode: input.mode,
            imageTemplate: input.mode === 'build' ? null : (input.imageTemplate ?? null),
            enabled: input.enabled,
            createdBy: user.id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            ...audit,
            result: 'success',
            diff: input,
            metadata: { ...input, policyId: r.id },
          },
          tx,
        );
        return r;
      });
      return this.toPolicy(row);
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'A policy for this repository already exists',
          ERROR_CODES.CONFLICT,
        );
      throw e;
    }
  }

  async updatePolicy(
    user: AuthUser,
    appId: string,
    policyId: string,
    input: Partial<Omit<AutoDeployPolicyInput, 'integrationId'>>,
  ) {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId);
    const scope = serverScope(app.server);
    const audit = {
      action: 'auto_deploy.update',
      targetType: 'auto_deploy_policy',
      targetId: policyId,
    };
    await this.authz.enforce(user, 'apps.deploy', scope, audit);
    const cur = await this.prisma.autoDeployPolicy.findFirst({
      where: { id: policyId, applicationId: appId },
    });
    if (!cur) throw AppError.notFound('Auto-deploy policy');
    // enabling (or widening what deploys automatically) needs policies.manage too
    if (input.enabled === true || input.branches || input.imageTemplate || input.repo || input.mode)
      await this.authz.enforce(user, 'policies.manage', scope, audit);
    const mode = input.mode ?? cur.mode;
    if (input.mode || input.imageTemplate)
      await this.assertModeConfig(appId, mode, input.imageTemplate ?? cur.imageTemplate);
    const data = {
      ...input,
      ...(mode === 'build' ? { imageTemplate: null } : {}),
    };
    const row = await this.prisma.$transaction(async (tx) => {
      const r = await tx.autoDeployPolicy.update({ where: { id: policyId }, data });
      await this.audit.record(
        { actorId: user.id, ...audit, result: 'success', diff: input, metadata: input },
        tx,
      );
      return r;
    });
    return this.toPolicy(row);
  }

  async deletePolicy(user: AuthUser, appId: string, policyId: string): Promise<void> {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId);
    const audit = {
      action: 'auto_deploy.delete',
      targetType: 'auto_deploy_policy',
      targetId: policyId,
    };
    await this.authz.enforce(user, 'apps.deploy', serverScope(app.server), audit);
    const r = await this.prisma.autoDeployPolicy.deleteMany({
      where: { id: policyId, applicationId: appId },
    });
    if (r.count === 0) throw AppError.notFound('Auto-deploy policy');
    await this.audit.record({ actorId: user.id, ...audit, result: 'success' });
  }

  // ---------------------------------------------------------------- receiver (public)

  /**
   * POST /webhooks/github/:integrationId — raw body, HMAC-SHA256 verified in constant time, deduped by
   * X-GitHub-Delivery, push only, policy match (repo + branch glob), tag → digest via the registry,
   * one deployment per commit per app, production → awaiting_approval.
   */
  async receive(
    integrationId: string,
    headers: Record<string, string | undefined>,
    raw: unknown,
    ip: string | undefined,
  ) {
    this.limiter.hit(`webhook:${ip ?? '-'}`, 120, 60_000);
    const integ = await this.prisma.integration.findUnique({ where: { id: integrationId } });
    if (!integ) throw AppError.notFound('Integration');
    const body = Buffer.isBuffer(raw) ? raw : Buffer.alloc(0);
    let secret: string;
    try {
      secret = decryptSecret(
        this.config.masterKey,
        integ.webhookSecretEnc,
        this.aad(integ.id),
      ).toString('utf8');
    } catch (err) {
      logger.emit('error', 'integration secret undecryptable', { integrationId, err });
      throw AppError.unauthenticated(
        'Webhook signature invalid',
        ERROR_CODES.WEBHOOK_SIGNATURE_INVALID,
      );
    }
    if (!verifyGithubSignature(secret, body, headers['x-hub-signature-256'])) {
      await this.audit.record({
        actorType: 'anonymous',
        action: 'webhooks.github',
        targetType: 'integration',
        targetId: integrationId,
        result: 'denied',
        metadata: {
          reason: 'signature_invalid',
          deliveryId: headers['x-github-delivery']?.slice(0, 100) ?? null,
        },
      });
      logger.emit('warn', 'webhook signature invalid', { integrationId });
      throw AppError.unauthenticated(
        'Webhook signature invalid',
        ERROR_CODES.WEBHOOK_SIGNATURE_INVALID,
      );
    }
    if (!integ.enabled)
      throw AppError.forbidden('Integration is disabled', ERROR_CODES.INTEGRATION_DISABLED);
    const deliveryId = headers['x-github-delivery'] ?? '';
    if (!DELIVERY_ID_RE.test(deliveryId))
      throw AppError.badRequest('X-GitHub-Delivery header required');
    const event = (headers['x-github-event'] ?? 'unknown').slice(0, 64);

    const payload = parsePayload(body, headers['content-type']);
    const repo =
      typeof payload?.repository?.full_name === 'string' ? payload.repository.full_name : null;
    const ref = typeof payload?.ref === 'string' ? payload.ref.slice(0, 255) : null;
    const after =
      typeof payload?.after === 'string' && /^[a-f0-9]{40}$/.test(payload.after)
        ? payload.after
        : null;

    // claim the delivery id first (unique) — concurrent redeliveries cannot both act
    const rowId = uuidv7();
    try {
      await this.prisma.webhookDelivery.create({
        data: {
          id: rowId,
          integrationId,
          deliveryId,
          event,
          repo,
          ref,
          after,
          signatureOk: true,
          result: 'ignored',
          reasons: ['processing'],
        },
      });
    } catch (e) {
      if (isUniqueViolation(e)) return { duplicate: true, deliveryId };
      throw e;
    }

    const { result, reasons, deploymentIds, buildIds } = await this.process(
      event,
      payload,
      repo,
      ref,
      after,
      integrationId,
      rowId,
      deliveryId,
    );
    const saved = await this.finalizeDelivery(rowId, { result, reasons, deploymentIds, buildIds });
    await this.audit.record({
      actorType: 'system',
      action: 'webhooks.github',
      targetType: 'integration',
      targetId: integrationId,
      result: result === 'failed' ? 'failure' : 'success',
      metadata: { deliveryId, event, repo, ref, after, result, reasons, deploymentIds, buildIds },
    });
    return { duplicate: false, ...toDelivery(saved) };
  }

  private async process(
    event: string,
    payload: PushPayload | null,
    repo: string | null,
    ref: string | null,
    after: string | null,
    integrationId: string,
    deliveryRowId: string,
    deliveryId: string,
  ): Promise<{
    result: WebhookDeliveryResult;
    reasons: string[];
    deploymentIds: string[];
    buildIds: string[];
  }> {
    const ignored = (r: string) => ({
      result: 'ignored' as const,
      reasons: [r],
      deploymentIds: [],
      buildIds: [],
    });
    if (event === 'ping') return ignored('ping');
    if (event !== 'push') return ignored('event_not_supported');
    if (!payload || !repo) return ignored('invalid_payload');
    if (!ref?.startsWith('refs/heads/')) return ignored('not_a_branch');
    if (payload.deleted === true || !after || ZERO_SHA.test(after))
      return ignored('branch_deleted');
    const branch = ref.slice('refs/heads/'.length);
    const policies = await this.prisma.autoDeployPolicy.findMany({
      where: { integrationId, enabled: true, repo: { equals: repo, mode: 'insensitive' } },
      orderBy: { createdAt: 'asc' },
    });
    if (policies.length === 0) return ignored('no_matching_policy');
    const matching = policies.filter((p) => p.branches.some((b) => branchMatches(b, branch)));
    if (matching.length === 0) return ignored('branch_not_allowed');

    const reasons: string[] = [];
    const deploymentIds: string[] = [];
    const buildIds: string[] = [];
    const statuses: string[] = [];
    let errors = 0;
    let queued = 0;
    for (const p of matching) {
      try {
        if (p.mode === 'build') {
          const r = await this.buildForPush(p.applicationId, after, branch, deliveryRowId);
          if (r.reason) reasons.push(r.reason);
          if (r.buildId) buildIds.push(r.buildId);
          continue;
        }
        const out = await this.withAppLock(p.applicationId, () =>
          this.deployOrQueue(p, repo, branch, after, deliveryRowId, deliveryId),
        );
        if (out.reason) reasons.push(out.reason);
        if (out.queued) queued++;
        const row = out.row;
        if (!row) continue;
        deploymentIds.push(row.id);
        statuses.push(row.status);
        if (row.status === 'failed')
          reasons.push(
            `preflight_failed:${(row.error as { code?: string } | null)?.code ?? 'UNKNOWN'}`,
          );
      } catch (e) {
        errors++;
        const code = e instanceof AppError ? String(e.code) : 'INTERNAL_ERROR';
        reasons.push(code === ERROR_CODES.DEPLOYMENT_IN_PROGRESS ? 'deployment_in_progress' : code);
        if (!(e instanceof AppError)) logger.emit('error', 'webhook deployment failed', { err: e });
      }
    }
    let result: WebhookDeliveryResult;
    if (deploymentIds.length === 0 && buildIds.length > 0) result = 'building';
    else if (deploymentIds.length === 0 && queued > 0) result = 'queued';
    else if (deploymentIds.length === 0) result = errors > 0 ? 'failed' : 'ignored';
    else if (statuses.every((s) => s === 'failed')) result = 'failed';
    else if (statuses.every((s) => s === 'awaiting_approval' || s === 'failed'))
      result = 'awaiting_approval';
    else result = 'deployed';
    return { result, reasons: [...new Set(reasons)], deploymentIds, buildIds };
  }

  // ---------------------------------------------------------------- F-7 coalescing queue

  /** Image mode, one policy: deploy `after` now, or coalesce it behind the running deployment. */
  private async deployOrQueue(
    p: PolicyRow,
    repo: string,
    branch: string,
    after: string,
    deliveryRowId: string,
    deliveryId: string,
  ): Promise<{
    row: Awaited<ReturnType<DeploymentsService['create']>>['row'] | null;
    reason: string | null;
    queued: boolean;
  }> {
    const done = await this.prisma.deployment.findFirst({
      where: {
        applicationId: p.applicationId,
        commitSha: after,
        status: { notIn: ['failed', 'cancelled', 'expired'] },
      },
      select: { id: true },
    });
    if (done) return { row: null, reason: 'already_deployed', queued: false };
    // F-7: a deployment of the app is running → coalesce instead of failing ("latest wins");
    // the queued commit starts when the running deployment ends
    let row: Awaited<ReturnType<DeploymentsService['create']>>['row'] | null = null;
    let queuedHere = false;
    let reason: string | null = null;
    for (let attempt = 0; attempt < 3 && !row; attempt++) {
      const busy = await this.prisma.deployment.findFirst({
        where: { applicationId: p.applicationId, status: { in: ACTIVE } },
        select: { id: true },
      });
      if (!busy) {
        try {
          row = await this.deployCommit(p, repo, branch, after, deliveryRowId);
          break;
        } catch (e) {
          if (!(e instanceof AppError) || e.code !== ERROR_CODES.DEPLOYMENT_IN_PROGRESS) throw e;
        }
      }
      const q = await this.queueCommit(p, repo, branch, after, deliveryRowId, deliveryId);
      if (q === 'idle') continue; // the running deployment just ended → try to deploy again
      if (q === 'queued') {
        queuedHere = true;
        reason = 'queued_behind_deployment';
      } else reason = q;
      break;
    }
    // the active deployment may have ended between queueing and now: drain right away
    if (!row && queuedHere) await this.drainPendingLocked(p.applicationId);
    return { row, reason, queued: queuedHere };
  }

  /** Resolve the policy's image for `after` and create the webhook deployment. */
  private async deployCommit(
    p: PolicyRow,
    repo: string,
    branch: string,
    after: string,
    deliveryRowId: string,
  ) {
    const app = await this.prisma.application.findUniqueOrThrow({
      where: { id: p.applicationId },
      include: appInclude,
    });
    const container = await this.prisma.containerApp.findUniqueOrThrow({
      where: { applicationId: app.id },
    });
    const ref = renderImageTemplate(p.imageTemplate ?? '', after, branch);
    if (!ref)
      throw new AppError(
        422,
        ERROR_CODES.IMAGE_RESOLVE_FAILED,
        'imageTemplate does not render a valid image reference for this push',
        { branch: branch.slice(0, 255) },
      );
    const cred = await this.secrets.registryCredential(app.id);
    const image = await this.registry.resolveDigest(ref, {
      auth: cred ? { username: cred.username, password: cred.password } : null,
      extraAllowedHosts: cred ? [cred.serveraddress] : [],
    });
    const { row } = await this.deployments.create(
      { user: null, id: null },
      { app, container },
      {
        image,
        trigger: 'webhook',
        sourceRef: { repo, commitSha: after, branch },
        reason: `push ${branch}@${after.slice(0, 7)}`,
        commitSha: after,
        webhookDeliveryId: deliveryRowId,
      },
    );
    return row;
  }

  /** Same row lock as deployment creation: serializes queueing, draining and creating per app. */
  private async lockApp(tx: Tx, appId: string): Promise<void> {
    await tx.$queryRaw`SELECT application_id FROM container_apps WHERE application_id = ${appId}::uuid FOR UPDATE`;
  }

  /**
   * Make `after` the app's pending commit while a deployment runs (latest wins: a queued older
   * commit is superseded). Same-commit duplicates are reported, never queued twice. `idle` = no
   * deployment is active any more (caller deploys directly).
   */
  private async queueCommit(
    p: PolicyRow,
    repo: string,
    branch: string,
    after: string,
    deliveryRowId: string,
    deliveryId: string,
  ): Promise<QueueOutcome> {
    return this.prisma.$transaction(async (tx) => {
      await this.lockApp(tx, p.applicationId);
      const active = await tx.deployment.findFirst({
        where: { applicationId: p.applicationId, status: { in: ACTIVE } },
        select: { commitSha: true },
      });
      if (!active) return 'idle';
      if (active.commitSha === after) return 'already_deployed';
      const cur = await tx.pendingWebhookDeploy.findUnique({
        where: { applicationId: p.applicationId },
      });
      if (cur?.commitSha === after) return 'already_queued';
      const data = {
        policyId: p.id,
        deliveryRowId,
        repo,
        branch,
        commitSha: after,
        queuedAt: new Date(),
      };
      await tx.pendingWebhookDeploy.upsert({
        where: { applicationId: p.applicationId },
        create: { applicationId: p.applicationId, ...data },
        update: data,
      });
      if (cur)
        await this.amendDelivery(tx, cur.deliveryRowId, {
          result: 'superseded',
          reasons: [`superseded_by:${deliveryId}`],
        });
      logger.emit('info', 'webhook commit queued behind running deployment', {
        component: 'webhooks',
        applicationId: p.applicationId,
        commitSha: after,
        supersededCommit: cur?.commitSha ?? null,
      });
      return 'queued';
    }, TX_OPTS);
  }

  /**
   * Start the app's pending commit if no deployment is active (idempotent, safe concurrently: the
   * deployment lock lets one caller create it; the others see DEPLOYMENT_IN_PROGRESS and leave the
   * row for the next drain). Returns the created deployment id, if any.
   */
  async drainPending(appId: string): Promise<string | null> {
    return this.withAppLock(appId, () => this.drainPendingLocked(appId));
  }

  private async drainPendingLocked(appId: string): Promise<string | null> {
    const claim = await this.prisma.$transaction(async (tx) => {
      await this.lockApp(tx, appId);
      const pending = await tx.pendingWebhookDeploy.findUnique({ where: { applicationId: appId } });
      if (!pending) return null;
      const active = await tx.deployment.findFirst({
        where: { applicationId: appId, status: { in: ACTIVE } },
        select: { id: true },
      });
      return active ? null : pending;
    }, TX_OPTS);
    if (!claim) return null;
    const drop = async (patch: DeliveryPatch) =>
      this.prisma.$transaction(async (tx) => {
        const del = await tx.pendingWebhookDeploy.deleteMany({
          where: { applicationId: appId, deliveryRowId: claim.deliveryRowId },
        });
        if (del.count === 1) await this.amendDelivery(tx, claim.deliveryRowId, patch);
        return del.count === 1;
      }, TX_OPTS);
    const p = await this.prisma.autoDeployPolicy.findUnique({ where: { id: claim.policyId } });
    if (!p || !p.enabled || p.mode !== 'image') {
      await drop({ result: 'ignored', reasons: ['dequeued', 'policy_disabled'] });
      return null;
    }
    const done = await this.prisma.deployment.findFirst({
      where: {
        applicationId: appId,
        commitSha: claim.commitSha,
        status: { notIn: ['failed', 'cancelled', 'expired'] },
      },
      select: { id: true },
    });
    if (done) {
      await drop({ result: 'ignored', reasons: ['dequeued', 'already_deployed'] });
      return null;
    }
    let row;
    try {
      row = await this.deployCommit(
        p,
        claim.repo,
        claim.branch,
        claim.commitSha,
        claim.deliveryRowId,
      );
    } catch (e) {
      if (e instanceof AppError && e.code === ERROR_CODES.DEPLOYMENT_IN_PROGRESS) return null;
      const code = e instanceof AppError ? String(e.code) : 'INTERNAL_ERROR';
      if (!(e instanceof AppError))
        logger.emit('error', 'queued webhook deployment failed', { err: e });
      await drop({ result: 'failed', reasons: ['dequeued', code] });
      return null;
    }
    const result: WebhookDeliveryResult =
      row.status === 'failed'
        ? 'failed'
        : row.status === 'awaiting_approval'
          ? 'awaiting_approval'
          : 'deployed';
    await this.prisma.$transaction(async (tx) => {
      await tx.pendingWebhookDeploy.deleteMany({
        where: { applicationId: appId, deliveryRowId: claim.deliveryRowId },
      });
      await this.amendDelivery(tx, claim.deliveryRowId, {
        result,
        reasons: [
          'dequeued',
          ...(row.status === 'failed'
            ? [`preflight_failed:${(row.error as { code?: string } | null)?.code ?? 'UNKNOWN'}`]
            : []),
        ],
        deploymentIds: [row.id],
      });
    }, TX_OPTS);
    await this.audit.record({
      actorType: 'system',
      action: 'webhooks.github.dequeued',
      targetType: 'deployment',
      targetId: row.id,
      result: row.status === 'failed' ? 'failure' : 'success',
      metadata: {
        applicationId: appId,
        commitSha: claim.commitSha,
        deliveryRowId: claim.deliveryRowId,
      },
    });
    return row.id;
  }

  /** Reconcile pass: drain every pending commit whose app has no active deployment. */
  async drainAll(): Promise<number> {
    const rows = await this.prisma.pendingWebhookDeploy.findMany({
      where: { application: { deployments: { none: { status: { in: ACTIVE } } } } },
      select: { applicationId: true },
      orderBy: { queuedAt: 'asc' },
      take: 50,
    });
    let started = 0;
    for (const r of rows) if (await this.drainPending(r.applicationId)) started++;
    return started;
  }

  /**
   * Change another request's delivery row (supersede / dequeue) under a row lock. A row still being
   * processed (reason `processing`) or `queued` takes the new result; any other result is kept
   * (multi-policy delivery) and only reasons / deployment ids are added.
   */
  private async amendDelivery(tx: Tx, id: string, patch: DeliveryPatch): Promise<void> {
    await tx.$queryRaw`SELECT id FROM webhook_deliveries WHERE id = ${id}::uuid FOR UPDATE`;
    const row = await tx.webhookDelivery.findUnique({ where: { id } });
    if (!row) return;
    const replaceable = row.result === 'queued' || row.reasons.includes(PROCESSING);
    await tx.webhookDelivery.update({
      where: { id },
      data: {
        ...(patch.result && replaceable ? { result: patch.result } : {}),
        reasons: [
          ...new Set([...row.reasons.filter((r) => r !== PROCESSING), ...(patch.reasons ?? [])]),
        ],
        deploymentIds: [...new Set([...row.deploymentIds, ...(patch.deploymentIds ?? [])])],
      },
    });
  }

  /**
   * Write the request's own outcome, merging anything a concurrent request already recorded on the
   * row (a newer push superseded it, or the queued commit was already dequeued and deployed).
   */
  private async finalizeDelivery(
    id: string,
    out: {
      result: WebhookDeliveryResult;
      reasons: string[];
      deploymentIds: string[];
      buildIds: string[];
    },
  ): Promise<DeliveryRow> {
    return this.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM webhook_deliveries WHERE id = ${id}::uuid FOR UPDATE`;
      const row = await tx.webhookDelivery.findUniqueOrThrow({ where: { id } });
      const amended = row.result !== 'ignored' || row.reasons.some((r) => r !== PROCESSING);
      if (!amended) return tx.webhookDelivery.update({ where: { id }, data: out });
      return tx.webhookDelivery.update({
        where: { id },
        data: {
          result: out.result === 'queued' ? (row.result as WebhookDeliveryResult) : out.result,
          reasons: [...new Set([...out.reasons, ...row.reasons.filter((r) => r !== PROCESSING)])],
          deploymentIds: [...new Set([...out.deploymentIds, ...row.deploymentIds])],
          buildIds: out.buildIds,
        },
      });
    }, TX_OPTS);
  }

  /**
   * Build mode (§8.2): one build per commit per app — a deployment of the commit (not failed) →
   * `already_deployed`; an active or succeeded build of it → `already_built`; else a webhook build
   * with deployAfter (production deployments still wait for approval).
   */
  private async buildForPush(
    appId: string,
    after: string,
    branch: string,
    deliveryRowId: string,
  ): Promise<{ reason?: string; buildId?: string }> {
    const deployed = await this.prisma.deployment.findFirst({
      where: {
        applicationId: appId,
        commitSha: after,
        status: { notIn: ['failed', 'cancelled', 'expired'] },
      },
      select: { id: true },
    });
    if (deployed) return { reason: 'already_deployed' };
    const built = await this.prisma.build.findFirst({
      where: {
        applicationId: appId,
        commitSha: after,
        status: { in: ['queued', 'fetching', 'building', 'pushing', 'succeeded'] },
      },
      select: { id: true },
    });
    if (built) return { reason: 'already_built' };
    const app = await this.prisma.application.findUniqueOrThrow({
      where: { id: appId },
      include: appInclude,
    });
    const container = await this.prisma.containerApp.findUniqueOrThrow({
      where: { applicationId: appId },
    });
    const { row, created } = await this.builds.start(
      { id: null },
      { app, container },
      {
        commitSha: after,
        branch,
        deployAfter: true,
        force: false,
        trigger: 'webhook',
        webhookDeliveryId: deliveryRowId,
      },
    );
    return created ? { buildId: row.id } : { reason: 'already_built' };
  }
}

function parsePayload(body: Buffer, contentType: string | undefined): PushPayload | null {
  try {
    let text = body.toString('utf8');
    if ((contentType ?? '').includes('application/x-www-form-urlencoded'))
      text = new URLSearchParams(text).get('payload') ?? '';
    const v = JSON.parse(text) as unknown;
    return v !== null && typeof v === 'object' ? (v as PushPayload) : null;
  } catch {
    return null;
  }
}

export function toDelivery(r: DeliveryRow): WebhookDelivery {
  return {
    id: r.id,
    integrationId: r.integrationId,
    deliveryId: r.deliveryId,
    event: r.event,
    repo: r.repo,
    ref: r.ref,
    after: r.after,
    signatureOk: r.signatureOk,
    result: r.result as WebhookDeliveryResult,
    reasons: r.reasons,
    deploymentIds: r.deploymentIds,
    buildIds: r.buildIds,
    receivedAt: r.receivedAt.toISOString(),
  };
}
