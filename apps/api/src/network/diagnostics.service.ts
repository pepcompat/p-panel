import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  type ConnectivityTestStatus,
  type CreateConnectivityTestInput,
  type CreateNetworkDiagnosticsInput,
  DIAGNOSE_DEFAULT_PORTS,
  ERROR_CODES,
  isDiagnosePrivateAddress,
  type NetworkConnectivityTest,
  type NetworkDiagnoseParams,
  type NetworkDiagnoseResult,
  type NetworkDiagnosticsCreated,
} from '@ppanel/shared-contracts';
import type { NetworkConnectivityTest as TestRow, Prisma } from '@prisma/client';
import net from 'node:net';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import { ServersService } from '../servers/servers.service';
import { preferredIpv4 } from './network-common';

const DIAGNOSE_TTL_SEC = 300;
const DEFAULT_PORTS = new Set<number>(DIAGNOSE_DEFAULT_PORTS);

/** IP literals of the advertised Center endpoints (hostnames are not addresses → not included). */
export function centerEndpointAddresses(config: Pick<AppConfig, 'gatewayEndpoints'>): Set<string> {
  const out = new Set<string>();
  for (const e of config.gatewayEndpoints) {
    const host = new URL(e.url).hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host)) out.add(host);
  }
  return out;
}

/**
 * Center-side twin of the agent's target policy: tcp hosts must be private (RFC 1918, 100.64/10,
 * fd00::/8) or a Center endpoint address; ports from the default set or `allowedPorts`.
 */
export function checkDiagnoseTargets(
  params: Pick<NetworkDiagnoseParams, 'tcp' | 'allowedPorts'>,
  centerAddresses: Set<string>,
): Array<{ index: number; host: string; port: number; reason: string }> {
  const allowed = new Set([...DEFAULT_PORTS, ...params.allowedPorts]);
  const bad: Array<{ index: number; host: string; port: number; reason: string }> = [];
  params.tcp.forEach((t, index) => {
    if (!isDiagnosePrivateAddress(t.host) && !centerAddresses.has(t.host))
      bad.push({ index, ...t, reason: 'host_not_private' });
    else if (!allowed.has(t.port)) bad.push({ index, ...t, reason: 'port_not_allowed' });
  });
  return bad;
}

@Injectable()
export class DiagnosticsService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly servers: ServersService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    this.hooks.register('network.diagnose', (j) => this.onFinished(j));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  private view(r: TestRow, jobStatus?: string): NetworkConnectivityTest {
    let status = r.status as ConnectivityTestStatus;
    if (status === 'queued' && (jobStatus === 'leased' || jobStatus === 'running'))
      status = 'running';
    const result = (r.result as NetworkDiagnoseResult | null) ?? null;
    const params = r.params as { tcp?: Array<{ host: string; port: number }> };
    let reachable: boolean | null = null;
    if (r.kind === 'pair' && (status === 'succeeded' || status === 'failed')) {
      const target = params.tcp?.[0];
      const hit = result?.tcp?.find((t) => t.host === target?.host && t.port === target?.port);
      reachable = hit ? hit.ok === true : false;
    }
    return {
      id: r.id,
      serverId: r.serverId,
      targetServerId: r.targetServerId,
      kind: r.kind as 'diagnose' | 'pair',
      params: r.params as Record<string, unknown>,
      status,
      jobId: r.jobId,
      reachable,
      result,
      error: (r.error as NetworkConnectivityTest['error']) ?? null,
      requestedBy: r.requestedBy,
      createdAt: r.createdAt.toISOString(),
      finishedAt: r.finishedAt?.toISOString() ?? null,
    };
  }

  /** Ports of managed app allocations on the servers that own the requested tcp hosts. */
  private async appPortsFor(hosts: string[]): Promise<Set<number>> {
    if (hosts.length === 0) return new Set();
    const owners = await this.prisma.server.findMany({
      where: {
        OR: [
          { addresses: { some: { address: { in: hosts } } } },
          { networkInventory: { some: { OR: [{ privateIpv4: { in: hosts } }] } } },
        ],
      },
      select: { portAllocations: { select: { port: true } } },
    });
    return new Set(owners.flatMap((o) => o.portAllocations.map((p) => p.port)));
  }

  private async start(
    user: AuthUser,
    input: {
      serverId: string;
      targetServerId: string | null;
      kind: 'diagnose' | 'pair';
      params: NetworkDiagnoseParams;
    },
  ): Promise<NetworkDiagnosticsCreated> {
    const testId = uuidv7();
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId: input.serverId,
        type: 'network.diagnose',
        params: input.params as unknown as Record<string, unknown>,
        actorId: user.id,
        ttlSec: DIAGNOSE_TTL_SEC,
        metadata: { testId, kind: input.kind },
      });
      await tx.networkConnectivityTest.create({
        data: {
          id: testId,
          serverId: input.serverId,
          targetServerId: input.targetServerId,
          kind: input.kind,
          params: j.params as Prisma.InputJsonValue,
          status: 'queued',
          jobId: j.id,
          requestedBy: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: input.kind === 'pair' ? 'network.connectivity_test' : 'network.diagnose',
          targetType: 'server',
          targetId: input.serverId,
          result: 'success',
          diff: input.params,
          metadata: { testId, jobId: j.id, targetServerId: input.targetServerId },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(input.serverId);
    return { testId, jobId: job.id };
  }

  private async validated(
    user: AuthUser,
    serverId: string,
    params: NetworkDiagnoseParams,
  ): Promise<NetworkDiagnoseParams> {
    const extra = params.tcp.map((t) => t.port).filter((p) => !DEFAULT_PORTS.has(p));
    const appPorts = await this.appPortsFor(params.tcp.map((t) => t.host));
    const allowedPorts = [...new Set(extra.filter((p) => appPorts.has(p)))];
    const out = { ...params, allowedPorts };
    const bad = checkDiagnoseTargets(out, centerEndpointAddresses(this.config));
    if (bad.length) {
      await this.audit.record({
        actorId: user.id,
        action: 'network.diagnose',
        targetType: 'server',
        targetId: serverId,
        result: 'denied',
        metadata: { rejected: bad },
      });
      throw new AppError(
        422,
        ERROR_CODES.DIAGNOSE_TARGET_NOT_ALLOWED,
        'Diagnostics may only dial private addresses (or a Center endpoint) on allowed ports',
        { tcp: bad, defaultPorts: DIAGNOSE_DEFAULT_PORTS },
      );
    }
    return out;
  }

  async diagnose(
    user: AuthUser,
    serverId: string,
    input: CreateNetworkDiagnosticsInput,
  ): Promise<NetworkDiagnosticsCreated> {
    const s = await this.servers.load(user, serverId, 'servers.operate', 'network.diagnose');
    if (s.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const params = await this.validated(user, serverId, { ...input, allowedPorts: [] });
    return this.start(user, { serverId, targetServerId: null, kind: 'diagnose', params });
  }

  /** Pair test: `network.diagnose` on `from` dialing `to`'s private IPv4 (never inferred from region). */
  async pair(
    user: AuthUser,
    input: CreateConnectivityTestInput,
  ): Promise<NetworkDiagnosticsCreated> {
    const from = await this.servers.load(
      user,
      input.fromServerId,
      'servers.operate',
      'network.connectivity_test',
    );
    const to = await this.servers.load(user, input.toServerId, 'fleet.read', 'servers.read');
    if (from.status === 'revoked' || to.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const ip = preferredIpv4(to.addresses, to.networkInventory, 'private');
    if (!ip)
      throw new AppError(
        422,
        ERROR_CODES.NO_PRIVATE_ADDRESS,
        'The target server has no known private IPv4 address',
        { serverId: to.id },
      );
    const params = await this.validated(user, from.id, {
      resolve: [],
      tcp: [{ host: ip, port: input.port }],
      includeRoutes: true,
      allowedPorts: [],
    });
    return this.start(user, {
      serverId: from.id,
      targetServerId: to.id,
      kind: 'pair',
      params,
    });
  }

  private async loadTest(user: AuthUser, id: string): Promise<TestRow> {
    const r = await this.prisma.networkConnectivityTest.findUnique({
      where: { id },
      include: { server: { select: { id: true, environment: true } } },
    });
    if (
      !r ||
      !this.authz.can(user, 'fleet.read', {
        serverId: r.server.id,
        environment: r.server.environment,
      })
    )
      throw AppError.notFound('Network diagnostics run');
    return r;
  }

  async get(user: AuthUser, id: string): Promise<NetworkConnectivityTest> {
    let r = await this.loadTest(user, id);
    let jobStatus: string | undefined;
    if ((r.status === 'queued' || r.status === 'running') && r.jobId) {
      const job = await this.prisma.job.findUnique({ where: { id: r.jobId } });
      jobStatus = job?.status;
      if (job && this.jobs.isTerminal(job.status)) {
        await this.jobs.dispatchFinished(job);
        r = await this.loadTest(user, id);
      }
    }
    return this.view(r, jobStatus);
  }

  async list(user: AuthUser, serverId: string, pq: ParsedQuery) {
    await this.servers.load(user, serverId, 'fleet.read', 'network.diagnostics.list');
    const where = { OR: [{ serverId }, { targetServerId: serverId }] };
    const [total, rows] = await Promise.all([
      this.prisma.networkConnectivityTest.count({ where }),
      this.prisma.networkConnectivityTest.findMany({
        where,
        orderBy: [{ createdAt: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(
      rows.map((r) => this.view(r)),
      paginate(pq, total),
    );
  }

  private async onFinished(job: FinishedJob): Promise<void> {
    const r = await this.prisma.networkConnectivityTest.findFirst({
      where: { jobId: job.id, status: { in: ['queued', 'running'] } },
    });
    if (!r) return;
    const status =
      job.status === 'succeeded'
        ? 'succeeded'
        : job.status === 'expired'
          ? 'expired'
          : job.status === 'cancelled'
            ? 'cancelled'
            : 'failed';
    const e = (job.error ?? null) as { code?: unknown; message?: unknown } | null;
    await this.prisma.networkConnectivityTest.updateMany({
      where: { id: r.id, status: { in: ['queued', 'running'] } },
      data: {
        status,
        finishedAt: new Date(),
        result: (job.status === 'succeeded' ? (job.result ?? {}) : undefined) as
          Prisma.InputJsonValue | undefined,
        error:
          status === 'succeeded'
            ? undefined
            : ({
                code: typeof e?.code === 'string' ? e.code : status.toUpperCase(),
                ...(typeof e?.message === 'string' ? { message: e.message.slice(0, 500) } : {}),
              } as Prisma.InputJsonValue),
      },
    });
  }

  async reconcile(): Promise<void> {
    const rows = await this.prisma.networkConnectivityTest.findMany({
      where: { status: { in: ['queued', 'running'] }, jobId: { not: null } },
      take: 50,
      orderBy: { createdAt: 'asc' },
    });
    for (const r of rows) {
      const job = await this.prisma.job.findUnique({ where: { id: r.jobId! } });
      if (job && this.jobs.isTerminal(job.status)) await this.jobs.dispatchFinished(job);
    }
  }
}
