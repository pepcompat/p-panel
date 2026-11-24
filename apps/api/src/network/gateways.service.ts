import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  type CreateGatewayInput,
  type CreateGatewayRouteInput,
  ERROR_CODES,
  HTTP_PROBE_DEFAULT_PORTS,
  isDiagnosePrivateAddress,
  type Gateway,
  GATEWAY_MAX_ROUTES,
  type GatewayBackend,
  type GatewayChangePlan,
  type GatewayPlanStatus,
  type GatewayRoute,
  type HttpProbeResult,
  type ShadowProbe,
  type ShadowResult,
  type ShadowTestInput,
  type UpdateGatewayRouteInput,
} from '@ppanel/shared-contracts';
import {
  type Gateway as GatewayRow,
  type GatewayChangePlan as PlanRow,
  type GatewayRoute as RouteRow,
  Prisma,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService, type ResourceScope } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { nginxFilesOf } from '../discovery/p3-common';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import { NginxRevisionsService } from '../nginx/nginx-revisions.service';
import { scopeOf } from '../servers/servers.service';
import {
  buildCutover,
  computeGatewayPlanHash,
  type RenderedFile,
  renderPlanFiles,
} from './gateway-render';
import { knownIpv4s, preferredIpv4 } from './network-common';

const GATEWAY_APP_NAME = 'ppanel-gateway';
const PROBE_TTL_SEC = 120;
const VIA = { viaGateway: true };
/** States in which no other plan of the gateway may be created. */
const PLAN_OPEN: GatewayPlanStatus[] = [
  'draft',
  'validated',
  'shadow_testing',
  'shadow_tested',
  'awaiting_approval',
  'applying',
  'rolling_back',
];

const gatewayServerSelect = {
  id: true,
  name: true,
  environment: true,
  status: true,
  addresses: { select: { family: true, scope: true, address: true, source: true } },
  networkInventory: true,
} satisfies Prisma.ServerSelect;
type GatewayWithServer = GatewayRow & {
  server: Prisma.ServerGetPayload<{ select: typeof gatewayServerSelect }>;
  _count: { routes: number };
};

interface ShadowRun {
  phase: 'pre_apply' | 'post_apply';
  probeServerId: string;
  from: GatewayPlanStatus;
  jobIds: string[];
  jobs: Array<{ jobId: string; domain: string; kind: 'gateway' | 'direct'; url: string }>;
}

function toRoute(r: RouteRow): GatewayRoute {
  return {
    id: r.id,
    gatewayId: r.gatewayId,
    domain: r.domain,
    mode: r.mode as GatewayRoute['mode'],
    backends: r.backends as unknown as GatewayBackend[],
    healthPath: r.healthPath,
    createdAt: r.createdAt.toISOString(),
    updatedAt: r.updatedAt.toISOString(),
    version: r.version,
  };
}

function probeOf(
  job: { status: string; result: unknown; error: unknown } | undefined,
): ShadowProbe {
  if (!job) return { status: null, latencyMs: null, bodySha256: null, error: 'NOT_RUN' };
  const out = (job.result ?? {}) as Partial<HttpProbeResult>;
  const e = (job.error ?? {}) as { code?: unknown };
  const status = typeof out.status === 'number' ? out.status : null;
  const latency = typeof out.latencyMs === 'number' ? Math.round(out.latencyMs) : null;
  const sha =
    typeof out.bodySha256 === 'string' && /^[a-f0-9]{64}$/.test(out.bodySha256)
      ? out.bodySha256
      : null;
  const error =
    typeof out.error === 'string'
      ? out.error.slice(0, 64)
      : job.status !== 'succeeded'
        ? typeof e.code === 'string'
          ? e.code
          : job.status.toUpperCase()
        : undefined;
  return { status, latencyMs: latency, bodySha256: sha, ...(error ? { error } : {}) };
}

@Injectable()
export class GatewaysService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly revisions: NginxRevisionsService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    for (const t of ['nginx.validate', 'nginx.apply', 'nginx.revert'])
      this.hooks.register(t, (j) => this.onRevisionJob(j));
    this.hooks.register('http.probe', (j) => this.onProbeFinished(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  // ---------------------------------------------------------------- gateways

  private scope(gw: { server: { id: string; environment: string } }): ResourceScope {
    return scopeOf(gw.server);
  }

  private async loadGateway(
    user: AuthUser,
    id: string,
    perm?: { perm: 'policies.manage' | 'approvals.decide'; action: string },
  ): Promise<GatewayWithServer> {
    const gw = await this.prisma.gateway.findUnique({
      where: { id },
      include: { server: { select: gatewayServerSelect }, _count: { select: { routes: true } } },
    });
    if (!gw || !this.authz.can(user, 'fleet.read', this.scope(gw)))
      throw AppError.notFound('Gateway');
    if (perm)
      await this.authz.enforce(user, perm.perm, this.scope(gw), {
        action: perm.action,
        targetType: 'gateway',
        targetId: id,
      });
    return gw;
  }

  private gatewayAddresses(gw: GatewayWithServer) {
    return {
      privateIpv4: preferredIpv4(gw.server.addresses, gw.server.networkInventory, 'private'),
      publicIpv4: preferredIpv4(gw.server.addresses, gw.server.networkInventory, 'public'),
    };
  }

  private view(user: AuthUser, gw: GatewayWithServer): Gateway {
    const manage = this.authz.can(user, 'policies.manage', this.scope(gw));
    return {
      id: gw.id,
      serverId: gw.serverId,
      serverName: gw.server.name,
      environment: gw.server.environment as Gateway['environment'],
      name: gw.name,
      status: gw.status as Gateway['status'],
      addresses: this.gatewayAddresses(gw),
      routeCount: gw._count.routes,
      createdAt: gw.createdAt.toISOString(),
      updatedAt: gw.updatedAt.toISOString(),
      allowedActions: manage ? ['manage_routes', 'plan', 'delete'] : [],
    };
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) throw AppError.forbidden();
    const where: Prisma.GatewayWhereInput = { server: visible };
    const [total, rows] = await Promise.all([
      this.prisma.gateway.count({ where }),
      this.prisma.gateway.findMany({
        where,
        include: { server: { select: gatewayServerSelect }, _count: { select: { routes: true } } },
        orderBy: [{ [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(
      rows.map((g) => this.view(user, g)),
      paginate(pq, total),
    );
  }

  async get(user: AuthUser, id: string): Promise<Gateway> {
    return this.view(user, await this.loadGateway(user, id));
  }

  async create(user: AuthUser, input: CreateGatewayInput): Promise<Gateway> {
    const server = await this.prisma.server.findUnique({ where: { id: input.serverId } });
    if (!server || !this.authz.can(user, 'fleet.read', scopeOf(server)))
      throw AppError.validation([{ path: 'serverId', message: 'unknown server' }]);
    await this.authz.enforce(user, 'policies.manage', scopeOf(server), {
      action: 'gateways.create',
      targetType: 'server',
      targetId: server.id,
    });
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const id = uuidv7();
    try {
      await this.prisma.$transaction(async (tx) => {
        // the gateway's nginx revisions hang off one `gateway` application per server (reused when
        // a gateway is re-created on the same server, so revision history survives)
        const fingerprint = `gateway:server:${server.id}`;
        let app = await tx.application.findUnique({
          where: {
            serverId_sourceFindingFingerprint: {
              serverId: server.id,
              sourceFindingFingerprint: fingerprint,
            },
          },
        });
        if (!app) {
          const taken = await tx.application.findUnique({
            where: { serverId_name: { serverId: server.id, name: GATEWAY_APP_NAME } },
          });
          if (taken)
            throw AppError.conflict(
              `An application named ${GATEWAY_APP_NAME} already exists on this server`,
              ERROR_CODES.GATEWAY_EXISTS,
            );
          app = await tx.application.create({
            data: {
              id: uuidv7(),
              serverId: server.id,
              name: GATEWAY_APP_NAME,
              kind: 'gateway',
              ownershipMode: 'managed',
              sourceFindingFingerprint: fingerprint,
              nginxFiles: [],
            },
          });
        }
        await tx.gateway.create({
          data: {
            id,
            serverId: server.id,
            name: input.name,
            applicationId: app.id,
            createdBy: user.id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'gateways.create',
            targetType: 'gateway',
            targetId: id,
            result: 'success',
            diff: input,
            metadata: { serverId: server.id, applicationId: app.id },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'This server already is a gateway, or the name is taken',
          ERROR_CODES.GATEWAY_EXISTS,
        );
      throw e;
    }
    return this.get(user, id);
  }

  async remove(user: AuthUser, id: string): Promise<void> {
    const gw = await this.loadGateway(user, id, {
      perm: 'policies.manage',
      action: 'gateways.delete',
    });
    if (gw._count.routes > 0)
      throw AppError.conflict(
        'Delete the gateway routes (and apply a plan) first',
        ERROR_CODES.GATEWAY_NOT_EMPTY,
        { routeCount: gw._count.routes },
      );
    const open = await this.prisma.gatewayChangePlan.findFirst({
      where: { gatewayId: id, status: { in: PLAN_OPEN } },
      select: { id: true, status: true },
    });
    if (open)
      throw AppError.conflict(
        'A gateway plan is in progress',
        ERROR_CODES.GATEWAY_PLAN_STATE_INVALID,
        {
          planId: open.id,
          status: open.status,
        },
      );
    await this.prisma.$transaction(async (tx) => {
      await tx.gateway.delete({ where: { id } });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateways.delete',
          targetType: 'gateway',
          targetId: id,
          result: 'success',
          metadata: { serverId: gw.serverId, name: gw.name },
        },
        tx,
      );
    });
  }

  // ---------------------------------------------------------------- routes

  async listRoutes(user: AuthUser, gatewayId: string, pq: ParsedQuery) {
    await this.loadGateway(user, gatewayId);
    const where = { gatewayId };
    const [total, rows] = await Promise.all([
      this.prisma.gatewayRoute.count({ where }),
      this.prisma.gatewayRoute.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(rows.map(toRoute), paginate(pq, total));
  }

  /** Backend servers must be visible to the caller; addresses must be one of their known IPv4s. */
  private async resolveBackends(
    user: AuthUser,
    input: CreateGatewayRouteInput['backends'],
  ): Promise<GatewayBackend[]> {
    const servers = await this.prisma.server.findMany({
      where: { id: { in: input.map((b) => b.serverId) } },
      select: gatewayServerSelect,
    });
    const out: GatewayBackend[] = [];
    const errors: Array<{ path: string; message: string }> = [];
    input.forEach((b, i) => {
      const s = servers.find((x) => x.id === b.serverId);
      if (!s || !this.authz.can(user, 'fleet.read', scopeOf(s)) || s.status === 'revoked') {
        errors.push({ path: `backends.${i}.serverId`, message: 'unknown server' });
        return;
      }
      const known = knownIpv4s(s.addresses, s.networkInventory);
      const address =
        b.address ??
        preferredIpv4(s.addresses, s.networkInventory, 'private') ??
        preferredIpv4(s.addresses, s.networkInventory, 'public');
      if (!address) {
        errors.push({ path: `backends.${i}.address`, message: 'server has no known IPv4 address' });
        return;
      }
      if (!known.has(address)) {
        errors.push({
          path: `backends.${i}.address`,
          message: 'address is not one of the server’s known addresses',
        });
        return;
      }
      out.push({ serverId: s.id, address, port: b.port });
    });
    if (errors.length)
      throw new AppError(
        422,
        ERROR_CODES.BACKEND_ADDRESS_UNKNOWN,
        'Backend servers / addresses are not valid',
        errors,
      );
    return out;
  }

  async createRoute(
    user: AuthUser,
    gatewayId: string,
    input: CreateGatewayRouteInput,
  ): Promise<GatewayRoute> {
    const gw = await this.loadGateway(user, gatewayId, {
      perm: 'policies.manage',
      action: 'gateway_routes.create',
    });
    if (gw._count.routes >= GATEWAY_MAX_ROUTES)
      throw new AppError(
        422,
        ERROR_CODES.GATEWAY_TOO_MANY_ROUTES,
        `A gateway holds at most ${GATEWAY_MAX_ROUTES} routes`,
      );
    const backends = await this.resolveBackends(user, input.backends);
    const id = uuidv7();
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const r = await tx.gatewayRoute.create({
          data: {
            id,
            gatewayId,
            domain: input.domain,
            mode: input.mode,
            backends: backends as unknown as Prisma.InputJsonValue,
            healthPath: input.healthPath,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'gateway_routes.create',
            targetType: 'gateway_route',
            targetId: id,
            result: 'success',
            diff: { ...input, backends },
            metadata: { gatewayId, domain: input.domain },
          },
          tx,
        );
        return r;
      });
      return toRoute(row);
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict(
          'This domain is already routed by a gateway',
          ERROR_CODES.ROUTE_DOMAIN_TAKEN,
        );
      throw e;
    }
  }

  private async loadRoute(gatewayId: string, routeId: string): Promise<RouteRow> {
    const r = await this.prisma.gatewayRoute.findFirst({ where: { id: routeId, gatewayId } });
    if (!r) throw AppError.notFound('Gateway route');
    return r;
  }

  async updateRoute(
    user: AuthUser,
    gatewayId: string,
    routeId: string,
    input: UpdateGatewayRouteInput,
  ): Promise<GatewayRoute> {
    await this.loadGateway(user, gatewayId, {
      perm: 'policies.manage',
      action: 'gateway_routes.update',
    });
    const cur = await this.loadRoute(gatewayId, routeId);
    const backends = input.backends ? await this.resolveBackends(user, input.backends) : undefined;
    const row = await this.prisma.$transaction(async (tx) => {
      const r = await tx.gatewayRoute.update({
        where: { id: routeId },
        data: {
          ...(input.mode ? { mode: input.mode } : {}),
          ...(input.healthPath ? { healthPath: input.healthPath } : {}),
          ...(backends ? { backends: backends as unknown as Prisma.InputJsonValue } : {}),
          version: { increment: 1 },
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_routes.update',
          targetType: 'gateway_route',
          targetId: routeId,
          result: 'success',
          diff: {
            before: { mode: cur.mode, backends: cur.backends, healthPath: cur.healthPath },
            after: { ...input, ...(backends ? { backends } : {}) },
          },
          metadata: { gatewayId, domain: cur.domain },
        },
        tx,
      );
      return r;
    });
    return toRoute(row);
  }

  async removeRoute(user: AuthUser, gatewayId: string, routeId: string): Promise<void> {
    await this.loadGateway(user, gatewayId, {
      perm: 'policies.manage',
      action: 'gateway_routes.delete',
    });
    const cur = await this.loadRoute(gatewayId, routeId);
    await this.prisma.$transaction(async (tx) => {
      await tx.gatewayRoute.delete({ where: { id: routeId } });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_routes.delete',
          targetType: 'gateway_route',
          targetId: routeId,
          result: 'success',
          metadata: { gatewayId, domain: cur.domain, mode: cur.mode },
        },
        tx,
      );
    });
  }

  // ---------------------------------------------------------------- plans: views

  private routesOf(p: PlanRow): GatewayRoute[] {
    return p.routesSnapshot as unknown as GatewayRoute[];
  }
  private renderedOf(p: PlanRow): RenderedFile[] {
    return p.rendered as unknown as RenderedFile[];
  }

  private hashOf(p: PlanRow, revisionPlanHash: string | null): string {
    return computeGatewayPlanHash({
      gatewayId: p.gatewayId,
      routes: this.routesOf(p),
      rendered: this.renderedOf(p),
      revisionPlanHash,
      shadowResults: (p.shadowResults as ShadowResult[] | null) ?? null,
    });
  }

  private approvalRequired(gw: GatewayWithServer): boolean {
    return gw.server.environment === 'production';
  }

  private async planView(
    user: AuthUser,
    gw: GatewayWithServer,
    p: PlanRow,
  ): Promise<GatewayChangePlan> {
    const rev = p.nginxRevisionId
      ? await this.prisma.nginxConfigRevision.findUnique({ where: { id: p.nginxRevisionId } })
      : null;
    const routes = this.routesOf(p);
    const backendIds = [...new Set(routes.flatMap((r) => r.backends.map((b) => b.serverId)))];
    const backendServers = await this.prisma.server.findMany({
      where: { id: { in: backendIds } },
      select: gatewayServerSelect,
    });
    const directTargetOf = (r: GatewayRoute) => {
      const s = backendServers.find((x) => x.id === r.backends[0]?.serverId);
      return s ? preferredIpv4(s.addresses, s.networkInventory, 'public') : null;
    };
    const scope = this.scope(gw);
    const status = p.status as GatewayPlanStatus;
    const manage = this.authz.can(user, 'policies.manage', scope);
    const required = this.approvalRequired(gw);
    const approved = !!p.approvedPlanHash && p.approvedPlanHash === p.planHash;
    const actions: GatewayChangePlan['allowedActions'] = [];
    if (manage && ['validated', 'shadow_tested', 'applied'].includes(status))
      actions.push('shadow_test');
    if (manage && status === 'awaiting_approval' && !approved) actions.push('shadow_test');
    if (
      status === 'awaiting_approval' &&
      !approved &&
      user.id !== p.createdBy &&
      this.authz.can(user, 'approvals.decide', scope)
    )
      actions.push('approve');
    if (
      manage &&
      (required
        ? status === 'awaiting_approval' && approved
        : ['validated', 'shadow_tested'].includes(status))
    )
      actions.push('apply');
    if (manage && status === 'applied' && rev?.status === 'applied') actions.push('rollback');
    if (manage && ['draft', 'validated', 'shadow_tested', 'awaiting_approval'].includes(status))
      actions.push('cancel');
    const validation = rev?.validation as {
      valid?: boolean | null;
      nginxTestOutput?: string | null;
    } | null;
    const labelIds = [p.createdBy, approved ? p.approvedBy : null].filter((x): x is string => !!x);
    const labels = new Map(
      labelIds.length
        ? (
            await this.prisma.user.findMany({
              where: { id: { in: labelIds } },
              select: { id: true, displayName: true },
            })
          ).map((u) => [u.id, u.displayName])
        : [],
    );
    return {
      id: p.id,
      gatewayId: p.gatewayId,
      status,
      routesSnapshot: routes,
      rendered: this.renderedOf(p),
      planHash: p.planHash,
      nginxRevisionId: p.nginxRevisionId,
      nginxRevisionStatus: rev?.status ?? null,
      validation: validation
        ? { valid: validation.valid ?? null, nginxTestOutput: validation.nginxTestOutput ?? null }
        : null,
      shadowResults: (p.shadowResults as ShadowResult[] | null) ?? null,
      verification: (p.verification as ShadowResult[] | null) ?? null,
      approval: {
        required,
        approvedBy: approved ? p.approvedBy : null,
        approvedByLabel: approved && p.approvedBy ? (labels.get(p.approvedBy) ?? null) : null,
        approvedAt: approved ? (p.approvedAt?.toISOString() ?? null) : null,
      },
      cutover: buildCutover(p.id, routes, this.gatewayAddresses(gw), directTargetOf),
      createdBy: p.createdBy,
      createdByLabel: p.createdBy ? (labels.get(p.createdBy) ?? null) : null,
      createdAt: p.createdAt.toISOString(),
      updatedAt: p.updatedAt.toISOString(),
      allowedActions: actions,
    };
  }

  private async loadPlan(
    user: AuthUser,
    id: string,
    perm?: { perm: 'policies.manage' | 'approvals.decide'; action: string },
  ): Promise<{ gw: GatewayWithServer; plan: PlanRow }> {
    const plan = await this.prisma.gatewayChangePlan.findUnique({ where: { id } });
    if (!plan) throw AppError.notFound('Gateway plan');
    let gw: GatewayWithServer;
    try {
      gw = await this.loadGateway(user, plan.gatewayId, perm);
    } catch (e) {
      if (e instanceof AppError && e.status === 404) throw AppError.notFound('Gateway plan');
      throw e;
    }
    // let the revision workflow reconcile a finished job first (lazy, like GET /nginx-revisions/:id)
    if (plan.nginxRevisionId)
      await this.revisions.get(user, plan.nginxRevisionId).catch(() => undefined);
    await this.syncFromRevision(plan);
    const fresh = await this.prisma.gatewayChangePlan.findUniqueOrThrow({ where: { id } });
    return { gw, plan: fresh };
  }

  async getPlan(user: AuthUser, id: string): Promise<GatewayChangePlan> {
    const { gw, plan } = await this.loadPlan(user, id);
    if (plan.shadowRun) await this.finishShadowIfDone(plan.id);
    const cur = await this.prisma.gatewayChangePlan.findUniqueOrThrow({ where: { id } });
    return this.planView(user, gw, cur);
  }

  async listPlans(user: AuthUser, gatewayId: string, pq: ParsedQuery) {
    const gw = await this.loadGateway(user, gatewayId);
    const where = { gatewayId };
    const [total, rows] = await Promise.all([
      this.prisma.gatewayChangePlan.count({ where }),
      this.prisma.gatewayChangePlan.findMany({
        where,
        orderBy: [{ createdAt: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    const items: GatewayChangePlan[] = [];
    for (const r of rows) items.push(await this.planView(user, gw, r));
    return new Paginated(items, paginate(pq, total));
  }

  // ---------------------------------------------------------------- plans: flow

  private stateError(p: { status: string }, allowed: string[]): AppError {
    return AppError.conflict(
      `Gateway plan is ${p.status}`,
      ERROR_CODES.GATEWAY_PLAN_STATE_INVALID,
      {
        status: p.status,
        allowed,
      },
    );
  }

  /** Compare-and-set status move; returns false when the plan moved meanwhile. */
  private async move(
    tx: Prisma.TransactionClient,
    id: string,
    from: GatewayPlanStatus[],
    data: Prisma.GatewayChangePlanUpdateManyMutationInput,
  ): Promise<boolean> {
    const r = await tx.gatewayChangePlan.updateMany({
      where: { id, status: { in: from } },
      data: { ...data, version: { increment: 1 } },
    });
    return r.count === 1;
  }

  /**
   * POST /gateways/:id/plans — render the routes, create the Nginx revision on the gateway server
   * through the P3 revision service (current files read from the host) and start `nginx -t`.
   */
  async createPlan(user: AuthUser, gatewayId: string): Promise<GatewayChangePlan> {
    const gw = await this.loadGateway(user, gatewayId, {
      perm: 'policies.manage',
      action: 'gateway_plans.create',
    });
    if (gw.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const open = await this.prisma.gatewayChangePlan.findFirst({
      where: { gatewayId, status: { in: PLAN_OPEN } },
      select: { id: true, status: true },
    });
    if (open)
      throw AppError.conflict(
        'Another gateway plan is in progress',
        ERROR_CODES.GATEWAY_PLAN_STATE_INVALID,
        { planId: open.id, status: open.status },
      );
    const routes = (
      await this.prisma.gatewayRoute.findMany({ where: { gatewayId }, orderBy: { domain: 'asc' } })
    ).map(toRoute);
    const app = await this.prisma.application.findUniqueOrThrow({
      where: { id: gw.applicationId },
    });
    const rendered = renderPlanFiles(gw.id, routes, nginxFilesOf(app));
    if (rendered.length > 20)
      throw new AppError(
        422,
        ERROR_CODES.GATEWAY_TOO_MANY_ROUTES,
        'Too many gateway files for one plan (max 20 incl. removed domains)',
      );
    const postchecks = routes
      .filter((r) => r.mode !== 'direct')
      .slice(0, 10)
      .map((r) => ({
        hostHeader: r.domain,
        path: r.healthPath,
        scheme: 'http' as const,
        expectStatus: [200, 204],
      }));
    const rev = await this.revisions.createForGateway(user, app.id, {
      files: rendered.map((f) => ({ path: f.path, content: f.content })),
      postchecks,
    });
    try {
      await this.revisions.validate(user, rev.id, VIA);
    } catch (e) {
      await this.revisions.cancel(user, rev.id, VIA).catch(() => undefined);
      throw e;
    }
    const id = uuidv7();
    await this.prisma.$transaction(async (tx) => {
      const base = {
        id,
        gatewayId,
        status: 'draft',
        routesSnapshot: routes as unknown as Prisma.InputJsonValue,
        rendered: rendered as unknown as Prisma.InputJsonValue,
        nginxRevisionId: rev.id,
        createdBy: user.id,
      };
      const planHash = computeGatewayPlanHash({
        gatewayId,
        routes,
        rendered,
        revisionPlanHash: rev.planHash,
        shadowResults: null,
      });
      await tx.gatewayChangePlan.create({ data: { ...base, planHash } });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_plans.create',
          targetType: 'gateway_plan',
          targetId: id,
          result: 'success',
          diff: { planHash },
          metadata: {
            gatewayId,
            nginxRevisionId: rev.id,
            planHash,
            domains: routes.map((r) => r.domain),
            paths: rendered.map((f) => f.path),
          },
        },
        tx,
      );
    });
    return this.getPlan(user, id);
  }

  /** Plan status follows its Nginx revision (validate / apply / revert outcomes). Idempotent. */
  async syncFromRevision(p: PlanRow): Promise<void> {
    if (!p.nginxRevisionId) return;
    const rev = await this.prisma.nginxConfigRevision.findUnique({
      where: { id: p.nginxRevisionId },
    });
    if (!rev) return;
    const status = p.status as GatewayPlanStatus;
    let to: GatewayPlanStatus | null = null;
    if (status === 'draft') {
      if (rev.status === 'valid' || rev.status === 'awaiting_approval') to = 'validated';
      else if (
        ['invalid', 'drift_blocked', 'cancelled', 'requires_manual_recovery'].includes(rev.status)
      )
        to = 'failed';
    } else if (status === 'applying') {
      if (rev.status === 'applied') to = 'applied';
      else if (rev.status === 'valid' || rev.status === 'awaiting_approval')
        // apply never executed (TTL lapse / interrupted): back to where it was
        to = p.shadowResults
          ? rev.status === 'awaiting_approval'
            ? 'awaiting_approval'
            : 'shadow_tested'
          : 'validated';
      else if (
        ['apply_failed', 'drift_blocked', 'requires_manual_recovery', 'cancelled'].includes(
          rev.status,
        )
      )
        to = 'failed';
    } else if (status === 'rolling_back') {
      if (rev.status === 'reverted') to = 'rolled_back';
      else if (rev.status === 'applied') to = 'applied';
      else if (['apply_failed', 'drift_blocked', 'requires_manual_recovery'].includes(rev.status))
        to = 'failed';
    }
    if (!to) return;
    const moved = await this.prisma.$transaction(async (tx) => {
      const ok = await this.move(tx, p.id, [status], {
        status: to,
        // an approval is single-use: an apply that did not run needs a new one
        ...(status === 'applying' && to !== 'applied'
          ? { approvedBy: null, approvedAt: null, approvedPlanHash: null }
          : {}),
      });
      if (ok)
        await this.audit.record(
          {
            actorType: 'system',
            action: 'gateway_plans.status',
            targetType: 'gateway_plan',
            targetId: p.id,
            result: ['validated', 'applied', 'rolled_back'].includes(to) ? 'success' : 'failure',
            metadata: { from: status, to, nginxRevisionId: rev.id, revisionStatus: rev.status },
          },
          tx,
        );
      return ok;
    });
    if (moved && to === 'failed')
      logger.emit('warn', 'gateway plan failed', { planId: p.id, revisionStatus: rev.status });
  }

  private async onRevisionJob(job: FinishedJob): Promise<void> {
    const rev = await this.prisma.nginxConfigRevision.findFirst({
      where: { OR: [{ validateJobId: job.id }, { applyJobId: job.id }, { revertJobId: job.id }] },
      select: { id: true },
    });
    if (!rev) return;
    const plans = await this.prisma.gatewayChangePlan.findMany({
      where: { nginxRevisionId: rev.id, status: { in: ['draft', 'applying', 'rolling_back'] } },
    });
    for (const p of plans) await this.syncFromRevision(p);
  }

  async shadowTest(user: AuthUser, id: string, input: ShadowTestInput): Promise<GatewayChangePlan> {
    const { gw, plan } = await this.loadPlan(user, id, {
      perm: 'policies.manage',
      action: 'gateway_plans.shadow_test',
    });
    const status = plan.status as GatewayPlanStatus;
    const approved = !!plan.approvedPlanHash && plan.approvedPlanHash === plan.planHash;
    const allowed: GatewayPlanStatus[] = [
      'validated',
      'shadow_tested',
      'awaiting_approval',
      'applied',
    ];
    if (!allowed.includes(status) || (status === 'awaiting_approval' && approved))
      throw this.stateError(plan, allowed);
    const probeServerId = input.probeServerId ?? gw.serverId;
    const probe = await this.prisma.server.findUnique({
      where: { id: probeServerId },
      select: gatewayServerSelect,
    });
    if (!probe || !this.authz.can(user, 'fleet.read', scopeOf(probe)))
      throw AppError.validation([{ path: 'probeServerId', message: 'unknown server' }]);
    await this.authz.enforce(user, 'servers.operate', scopeOf(probe), {
      action: 'gateway_plans.shadow_test',
      targetType: 'server',
      targetId: probe.id,
    });
    if (probe.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const routes = this.routesOf(plan).filter((r) => r.mode !== 'direct');
    if (routes.length === 0)
      throw this.stateError({ status: 'without hybrid/gateway routes' }, ['validated']);
    // the agent dials private-range literals only (also when probing on the gateway itself)
    const gwAddr = this.gatewayAddresses(gw).privateIpv4;
    if (!gwAddr)
      throw new AppError(
        422,
        ERROR_CODES.NO_PRIVATE_ADDRESS,
        'The gateway has no known private IPv4 address',
      );
    // probes are limited to the plan's domains, the gateway's known addresses and the plan's backends
    const allowedTargets = new Set(
      [
        ...knownIpv4s(gw.server.addresses, gw.server.networkInventory),
        ...routes.flatMap((r) => r.backends.map((b) => b.address)),
      ].filter(isDiagnosePrivateAddress),
    );
    const expectStatus = input.expectStatus ?? [200];
    const specs = routes.flatMap((r) => {
      const url = `http://${r.domain}${input.path ?? r.healthPath}`;
      const b = r.backends[0]!;
      return [
        { domain: r.domain, kind: 'gateway' as const, url, resolveTo: gwAddr, port: 80 },
        { domain: r.domain, kind: 'direct' as const, url, resolveTo: b.address, port: b.port },
      ];
    });
    const bad = specs.filter((s) => !allowedTargets.has(s.resolveTo));
    if (bad.length)
      throw new AppError(422, ERROR_CODES.PROBE_TARGET_NOT_ALLOWED, 'Probe target not allowed', {
        targets: bad.map((b) => b.resolveTo),
      });
    const phase = status === 'applied' ? 'post_apply' : 'pre_apply';
    const run: ShadowRun = { phase, probeServerId: probe.id, from: status, jobIds: [], jobs: [] };
    await this.prisma.$transaction(async (tx) => {
      for (const s of specs) {
        const j = await this.jobs.createInternal(tx, {
          serverId: probe.id,
          type: 'http.probe',
          params: {
            url: s.url,
            resolveTo: s.resolveTo,
            port: s.port,
            method: 'GET',
            expectStatus,
            timeoutSec: 10,
            allowedPorts: (HTTP_PROBE_DEFAULT_PORTS as readonly number[]).includes(s.port)
              ? []
              : [s.port],
          },
          actorId: user.id,
          ttlSec: PROBE_TTL_SEC,
          metadata: { gatewayPlanId: plan.id, domain: s.domain, kind: s.kind },
        });
        run.jobIds.push(j.id);
        run.jobs.push({ jobId: j.id, domain: s.domain, kind: s.kind, url: s.url });
      }
      const ok = await this.move(tx, plan.id, [status], {
        ...(phase === 'pre_apply' ? { status: 'shadow_testing' } : {}),
        shadowRun: run as unknown as Prisma.InputJsonValue,
      });
      if (!ok) throw this.stateError(plan, allowed);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_plans.shadow_test',
          targetType: 'gateway_plan',
          targetId: plan.id,
          result: 'success',
          metadata: { phase, probeServerId: probe.id, jobIds: run.jobIds },
        },
        tx,
      );
    });
    this.jobs.notify(probe.id);
    return this.getPlan(user, id);
  }

  private async onProbeFinished(job: FinishedJob): Promise<void> {
    const plans = await this.prisma.gatewayChangePlan.findMany({
      where: { shadowRun: { path: ['jobIds'], array_contains: [job.id] } },
      select: { id: true },
    });
    for (const p of plans) await this.finishShadowIfDone(p.id);
  }

  /** When every probe of the running shadow test is terminal: store results (+ new plan hash). */
  async finishShadowIfDone(planId: string): Promise<void> {
    const plan = await this.prisma.gatewayChangePlan.findUnique({
      where: { id: planId },
      include: { gateway: { include: { server: { select: { environment: true } } } } },
    });
    const run = plan?.shadowRun as ShadowRun | null | undefined;
    if (!plan || !run) return;
    const jobs = await this.prisma.job.findMany({ where: { id: { in: run.jobIds } } });
    if (jobs.length !== run.jobIds.length || jobs.some((j) => !this.jobs.isTerminal(j.status)))
      return;
    const byId = new Map(jobs.map((j) => [j.id, j]));
    const domains = [...new Set(run.jobs.map((j) => j.domain))];
    const results: ShadowResult[] = domains.map((domain) => {
      const via = run.jobs.find((j) => j.domain === domain && j.kind === 'gateway');
      const dir = run.jobs.find((j) => j.domain === domain && j.kind === 'direct');
      const viaGateway = probeOf(via && byId.get(via.jobId));
      const direct = probeOf(dir && byId.get(dir.jobId));
      return {
        domain,
        url: via?.url ?? dir?.url ?? `http://${domain}/`,
        viaGateway,
        direct,
        match:
          viaGateway.status !== null &&
          viaGateway.status === direct.status &&
          viaGateway.bodySha256 !== null &&
          viaGateway.bodySha256 === direct.bodySha256,
      };
    });
    await this.prisma.$transaction(async (tx) => {
      if (run.phase === 'post_apply') {
        const r = await tx.gatewayChangePlan.updateMany({
          where: { id: planId, version: plan.version },
          data: {
            shadowRun: Prisma.DbNull,
            verification: results as unknown as Prisma.InputJsonValue,
            version: { increment: 1 },
          },
        });
        if (r.count !== 1) return;
      } else {
        const rev = plan.nginxRevisionId
          ? await tx.nginxConfigRevision.findUnique({ where: { id: plan.nginxRevisionId } })
          : null;
        const planHash = computeGatewayPlanHash({
          gatewayId: plan.gatewayId,
          routes: this.routesOf(plan),
          rendered: this.renderedOf(plan),
          revisionPlanHash: rev?.planHash ?? null,
          shadowResults: results,
        });
        const production = plan.gateway.server.environment === 'production';
        const ok = await this.move(tx, planId, ['shadow_testing'], {
          status: production ? 'awaiting_approval' : 'shadow_tested',
          shadowRun: Prisma.DbNull,
          shadowResults: results as unknown as Prisma.InputJsonValue,
          planHash,
          approvedBy: null,
          approvedAt: null,
          approvedPlanHash: null,
        });
        if (!ok) return;
      }
      await this.audit.record(
        {
          actorType: 'system',
          action: 'gateway_plans.shadow_results',
          targetType: 'gateway_plan',
          targetId: planId,
          result: results.every((r) => r.match) ? 'success' : 'failure',
          metadata: {
            phase: run.phase,
            matches: results.filter((r) => r.match).length,
            total: results.length,
          },
        },
        tx,
      );
    });
  }

  private assertIntact(p: PlanRow, revisionPlanHash: string | null): void {
    if (this.hashOf(p, revisionPlanHash) !== p.planHash)
      throw AppError.conflict(
        'Gateway plan changed since it was created',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        {
          planHash: p.planHash,
        },
      );
  }

  private async revisionOf(p: PlanRow) {
    if (!p.nginxRevisionId) throw this.stateError(p, []);
    return this.prisma.nginxConfigRevision.findUniqueOrThrow({ where: { id: p.nginxRevisionId } });
  }

  /** Production: a second person with step-up approves the exact planHash (incl. shadow results). */
  async approve(
    user: AuthUser,
    id: string,
    planHash: string,
    stepUp: string | undefined,
  ): Promise<GatewayChangePlan> {
    const { gw, plan } = await this.loadPlan(user, id, {
      perm: 'approvals.decide',
      action: 'gateway_plans.approve',
    });
    if (plan.createdBy === user.id) {
      await this.audit.record({
        actorId: user.id,
        action: 'gateway_plans.approve',
        targetType: 'gateway_plan',
        targetId: id,
        result: 'denied',
        metadata: { reason: 'approver_is_creator' },
      });
      throw AppError.forbidden(
        'The creator of a plan cannot approve it',
        ERROR_CODES.APPROVER_IS_CREATOR,
      );
    }
    this.auth.assertStepUp(user, stepUp);
    if (!this.approvalRequired(gw))
      throw AppError.conflict(
        'This plan does not require approval',
        ERROR_CODES.APPROVAL_NOT_REQUIRED,
      );
    if (plan.status !== 'awaiting_approval') {
      if (!plan.shadowResults && ['validated', 'shadow_testing'].includes(plan.status))
        throw AppError.conflict('Run the shadow test first', ERROR_CODES.SHADOW_TEST_REQUIRED);
      throw this.stateError(plan, ['awaiting_approval']);
    }
    if (!plan.shadowResults)
      throw AppError.conflict('Run the shadow test first', ERROR_CODES.SHADOW_TEST_REQUIRED);
    const rev = await this.revisionOf(plan);
    this.assertIntact(plan, rev.planHash);
    if (planHash !== plan.planHash)
      throw AppError.conflict(
        'planHash does not match the current plan',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        {
          planHash: plan.planHash,
        },
      );
    if (plan.approvedPlanHash === plan.planHash)
      throw AppError.conflict('This plan is already approved', ERROR_CODES.APPROVAL_ALREADY_EXISTS);
    // same rules as nginx revisions: the revision approval (single use, 60 min) is what apply consumes
    await this.revisions.approve(user, rev.id, rev.planHash, stepUp, VIA);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.gatewayChangePlan.updateMany({
        where: { id, status: 'awaiting_approval', planHash, version: plan.version },
        data: {
          approvedBy: user.id,
          approvedAt: now,
          approvedPlanHash: planHash,
          version: { increment: 1 },
        },
      });
      if (r.count !== 1)
        throw AppError.conflict(
          'Gateway plan changed concurrently',
          ERROR_CODES.GATEWAY_PLAN_STATE_INVALID,
        );
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_plans.approve',
          targetType: 'gateway_plan',
          targetId: id,
          result: 'success',
          diff: { planHash },
          metadata: { planHash, nginxRevisionId: rev.id },
        },
        tx,
      );
    });
    return this.getPlan(user, id);
  }

  async apply(user: AuthUser, id: string, stepUp: string | undefined): Promise<GatewayChangePlan> {
    const { gw, plan } = await this.loadPlan(user, id, {
      perm: 'policies.manage',
      action: 'gateway_plans.apply',
    });
    if (gw.server.environment === 'production') this.auth.assertStepUp(user, stepUp);
    const required = this.approvalRequired(gw);
    const allowed: GatewayPlanStatus[] = required
      ? ['awaiting_approval']
      : ['validated', 'shadow_tested'];
    if (!allowed.includes(plan.status as GatewayPlanStatus)) throw this.stateError(plan, allowed);
    const rev = await this.revisionOf(plan);
    this.assertIntact(plan, rev.planHash);
    if (required && plan.approvedPlanHash !== plan.planHash)
      throw AppError.conflict('Approval required before apply', ERROR_CODES.APPROVAL_REQUIRED);
    await this.revisions.apply(user, rev.id, stepUp, VIA);
    await this.prisma.$transaction(async (tx) => {
      await this.move(tx, id, allowed, { status: 'applying' });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_plans.apply',
          targetType: 'gateway_plan',
          targetId: id,
          result: 'success',
          diff: { planHash: plan.planHash },
          metadata: { planHash: plan.planHash, nginxRevisionId: rev.id },
        },
        tx,
      );
    });
    return this.getPlan(user, id);
  }

  async rollback(
    user: AuthUser,
    id: string,
    stepUp: string | undefined,
  ): Promise<GatewayChangePlan> {
    const { gw, plan } = await this.loadPlan(user, id, {
      perm: 'policies.manage',
      action: 'gateway_plans.rollback',
    });
    if (gw.server.environment === 'production') this.auth.assertStepUp(user, stepUp);
    if (plan.status !== 'applied') throw this.stateError(plan, ['applied']);
    const rev = await this.revisionOf(plan);
    await this.revisions.revert(user, rev.id, stepUp, VIA);
    await this.prisma.$transaction(async (tx) => {
      await this.move(tx, id, ['applied'], { status: 'rolling_back' });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_plans.rollback',
          targetType: 'gateway_plan',
          targetId: id,
          result: 'success',
          metadata: { nginxRevisionId: rev.id },
        },
        tx,
      );
    });
    return this.getPlan(user, id);
  }

  async cancel(user: AuthUser, id: string): Promise<GatewayChangePlan> {
    const { plan } = await this.loadPlan(user, id, {
      perm: 'policies.manage',
      action: 'gateway_plans.cancel',
    });
    const allowed: GatewayPlanStatus[] = [
      'draft',
      'validated',
      'shadow_tested',
      'awaiting_approval',
    ];
    if (!allowed.includes(plan.status as GatewayPlanStatus)) throw this.stateError(plan, allowed);
    const rev = await this.revisionOf(plan);
    if (['draft', 'valid', 'awaiting_approval', 'approved'].includes(rev.status))
      await this.revisions.cancel(user, rev.id, VIA);
    else if (rev.status === 'validating') throw this.stateError({ status: 'validating' }, allowed);
    await this.prisma.$transaction(async (tx) => {
      await this.move(tx, id, allowed, { status: 'cancelled' });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'gateway_plans.cancel',
          targetType: 'gateway_plan',
          targetId: id,
          result: 'success',
          metadata: { from: plan.status },
        },
        tx,
      );
    });
    return this.getPlan(user, id);
  }

  async reconcile(): Promise<void> {
    const rows = await this.prisma.gatewayChangePlan.findMany({
      where: { status: { in: ['draft', 'applying', 'rolling_back', 'shadow_testing', 'applied'] } },
      take: 50,
      orderBy: { updatedAt: 'asc' },
    });
    for (const p of rows) {
      await this.syncFromRevision(p);
      if (p.shadowRun) await this.finishShadowIfDone(p.id);
    }
  }
}
