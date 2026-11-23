import { Inject, Injectable } from '@nestjs/common';
import {
  type AutoDeployPolicy,
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
import { createHmac, timingSafeEqual } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret } from '../common/crypto';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { paginate, type ParsedQuery } from '../common/query-builder';
import { RateLimiter } from '../common/rate-limiter';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ApplicationsService } from '../discovery/applications.service';
import { appInclude, serverScope } from '../discovery/p3-common';
import { DeploymentsService } from './deployments.service';
import { parseTaggedRef, RegistryClient } from './registry.client';
import { loadContainerApp, SecretsService } from './secrets.service';

const ZERO_SHA = /^0{40}$/;
const API_PREFIX = 'api/v1';
const DELIVERY_ID_RE = /^[A-Za-z0-9-]{1,100}$/;

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

@Injectable()
export class WebhooksService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly limiter: RateLimiter,
    private readonly apps: ApplicationsService,
    private readonly deployments: DeploymentsService,
    private readonly secrets: SecretsService,
    private readonly registry: RegistryClient,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

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

  async deliveries(integrationId: string, pq: ParsedQuery) {
    const exists = await this.prisma.integration.findUnique({ where: { id: integrationId } });
    if (!exists) throw AppError.notFound('Integration');
    const where = { integrationId };
    const [total, rows] = await Promise.all([
      this.prisma.webhookDelivery.count({ where }),
      this.prisma.webhookDelivery.findMany({
        where,
        orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
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
    const ref = parseTaggedRef(renderImageTemplate(template, 'a'.repeat(40), 'main'));
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

  async createPolicy(user: AuthUser, appId: string, input: AutoDeployPolicyInput) {
    const { app } = await loadContainerApp(this.apps, this.prisma, user, appId);
    const scope = serverScope(app.server);
    const audit = { action: 'auto_deploy.create', targetType: 'application', targetId: appId };
    await this.authz.enforce(user, 'apps.deploy', scope, audit);
    await this.authz.enforce(user, 'policies.manage', scope, audit);
    const integ = await this.prisma.integration.findUnique({ where: { id: input.integrationId } });
    if (!integ) throw AppError.notFound('Integration');
    await this.assertTemplateHost(appId, input.imageTemplate);
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const r = await tx.autoDeployPolicy.create({
          data: {
            id: uuidv7(),
            applicationId: appId,
            integrationId: input.integrationId,
            repo: input.repo,
            branches: input.branches,
            imageTemplate: input.imageTemplate,
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
    if (input.enabled === true || input.branches || input.imageTemplate || input.repo)
      await this.authz.enforce(user, 'policies.manage', scope, audit);
    if (input.imageTemplate) await this.assertTemplateHost(appId, input.imageTemplate);
    const row = await this.prisma.$transaction(async (tx) => {
      const r = await tx.autoDeployPolicy.update({ where: { id: policyId }, data: input });
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

    const { result, reasons, deploymentIds } = await this.process(
      event,
      payload,
      repo,
      ref,
      after,
      integrationId,
      rowId,
    );
    const saved = await this.prisma.webhookDelivery.update({
      where: { id: rowId },
      data: { result, reasons, deploymentIds },
    });
    await this.audit.record({
      actorType: 'system',
      action: 'webhooks.github',
      targetType: 'integration',
      targetId: integrationId,
      result: result === 'failed' ? 'failure' : 'success',
      metadata: { deliveryId, event, repo, ref, after, result, reasons, deploymentIds },
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
  ): Promise<{ result: WebhookDeliveryResult; reasons: string[]; deploymentIds: string[] }> {
    const ignored = (r: string) => ({
      result: 'ignored' as const,
      reasons: [r],
      deploymentIds: [],
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
    const statuses: string[] = [];
    let errors = 0;
    for (const p of matching) {
      try {
        const done = await this.prisma.deployment.findFirst({
          where: {
            applicationId: p.applicationId,
            commitSha: after,
            status: { notIn: ['failed', 'cancelled', 'expired'] },
          },
          select: { id: true },
        });
        if (done) {
          reasons.push('already_deployed');
          continue;
        }
        const app = await this.prisma.application.findUniqueOrThrow({
          where: { id: p.applicationId },
          include: appInclude,
        });
        const container = await this.prisma.containerApp.findUniqueOrThrow({
          where: { applicationId: app.id },
        });
        const cred = await this.secrets.registryCredential(app.id);
        const image = await this.registry.resolveDigest(
          renderImageTemplate(p.imageTemplate, after, branch),
          {
            auth: cred ? { username: cred.username, password: cred.password } : null,
            extraAllowedHosts: cred ? [cred.serveraddress] : [],
          },
        );
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
    if (deploymentIds.length === 0) result = errors > 0 ? 'failed' : 'ignored';
    else if (statuses.every((s) => s === 'failed')) result = 'failed';
    else if (statuses.every((s) => s === 'awaiting_approval' || s === 'failed'))
      result = 'awaiting_approval';
    else result = 'deployed';
    return { result, reasons: [...new Set(reasons)], deploymentIds };
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
    receivedAt: r.receivedAt.toISOString(),
  };
}
