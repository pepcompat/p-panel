/**
 * P5 heartbeat extension (containers, log shipping) + shared scope/app-resolution helpers used by
 * the scrape endpoint, metrics/logs APIs and the alert evaluator.
 */
import { Injectable } from '@nestjs/common';
import { type HeartbeatInput, type Permission } from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuthzService } from '../auth/authz.service';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';

export const MANAGED_APP_KINDS = ['container', 'compose'];

export interface ManagedAppRef {
  id: string;
  name: string;
  kind: string;
  serverId: string;
  currentDeploymentId: string | null;
}

export interface CurrentContainer {
  name: string;
  service: string;
}

interface ServiceResultLike {
  service?: unknown;
  name?: unknown;
}

/** Names of the containers that make up an app's current deployment (container or compose). */
export function currentContainersOf(d: {
  containerName: string | null;
  serviceResults: unknown;
  plan: unknown;
}): CurrentContainer[] {
  if (d.containerName) return [{ name: d.containerName, service: 'app' }];
  const fromResults = Array.isArray(d.serviceResults)
    ? (d.serviceResults as ServiceResultLike[])
    : Array.isArray((d.plan as { services?: unknown } | null)?.services)
      ? ((d.plan as { services: ServiceResultLike[] }).services ?? [])
      : [];
  return fromResults
    .filter((r) => typeof r.name === 'string' && typeof r.service === 'string')
    .map((r) => ({ name: r.name as string, service: r.service as string }));
}

@Injectable()
export class TelemetryService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
  ) {}

  /** Managed (container/compose) applications of a server keyed by app name. */
  async managedApps(serverId: string): Promise<Map<string, ManagedAppRef>> {
    const rows = await this.prisma.application.findMany({
      where: { serverId, kind: { in: MANAGED_APP_KINDS } },
      select: {
        id: true,
        name: true,
        kind: true,
        serverId: true,
        container: { select: { currentDeploymentId: true } },
      },
    });
    return new Map(
      rows.map((r) => [
        r.name,
        {
          id: r.id,
          name: r.name,
          kind: r.kind,
          serverId: r.serverId,
          currentDeploymentId: r.container?.currentDeploymentId ?? null,
        },
      ]),
    );
  }

  /** Every container name pPanel ever deployed for these apps (spoofing check for log labels). */
  async knownContainerNames(appIds: string[]): Promise<Map<string, string>> {
    if (appIds.length === 0) return new Map();
    const rows = await this.prisma.deployment.findMany({
      where: { applicationId: { in: appIds } },
      select: { applicationId: true, containerName: true, serviceResults: true, plan: true },
      orderBy: { number: 'desc' },
      take: 2000,
    });
    const out = new Map<string, string>();
    for (const r of rows)
      for (const c of currentContainersOf(r))
        if (!out.has(c.name)) out.set(c.name, r.applicationId);
    return out;
  }

  /** Stores the P5 heartbeat extension (called after the core heartbeat transaction). */
  async recordHeartbeat(serverId: string, hb: HeartbeatInput, now: Date): Promise<void> {
    const containers = hb.containers;
    if (containers === undefined && !hb.logShipping) return; // pre-P5 agent
    const apps = containers?.length ? await this.managedApps(serverId) : new Map();
    await this.prisma.$transaction(async (tx) => {
      if (containers !== undefined) {
        const names = containers.map((c) => c.name);
        await tx.containerSample.deleteMany({ where: { serverId, name: { notIn: names } } });
        for (const c of containers) {
          const data = {
            appName: c.app,
            applicationId: (apps.get(c.app) as ManagedAppRef | undefined)?.id ?? null,
            service: c.service ?? null,
            deploymentId: c.deploymentId ?? null,
            state: c.state,
            health: c.health ?? null,
            restartCount: c.restartCount ?? null,
            cpuPct: c.cpuPct ?? null,
            memBytes: c.memBytes == null ? null : BigInt(c.memBytes),
            memLimitBytes: c.memLimitBytes == null ? null : BigInt(c.memLimitBytes),
            sampledAt: now,
          };
          await tx.containerSample.upsert({
            where: { serverId_name: { serverId, name: c.name } },
            create: { serverId, name: c.name, ...data },
            update: data,
          });
        }
      }
      const shipping = hb.logShipping
        ? ({
            bufferedBytes: hb.logShipping.bufferedBytes,
            bufferCapBytes: hb.logShipping.bufferCapBytes ?? null,
            droppedEntries: hb.logShipping.droppedEntries,
            lastShippedAt: hb.logShipping.lastShippedAt ?? null,
            reportedAt: now.toISOString(),
          } as Prisma.InputJsonValue)
        : undefined;
      // agent drops: heartbeat droppedEntries is cumulative (persisted by the agent) → add the delta
      let dropDelta = 0n;
      if (hb.logShipping) {
        const prev = await tx.serverTelemetry.findUnique({
          where: { serverId },
          select: { logShipping: true },
        });
        const prevTotal = (prev?.logShipping as { droppedEntries?: number } | null)?.droppedEntries;
        const cur = hb.logShipping.droppedEntries;
        if (prevTotal === undefined) dropDelta = BigInt(cur);
        else if (cur > prevTotal) dropDelta = BigInt(cur - prevTotal);
        else if (cur < prevTotal) dropDelta = BigInt(cur); // agent state reset
      }
      const patch = {
        ...(dropDelta > 0n ? { lastDroppedAt: now } : {}),
        ...(shipping ? { logShipping: shipping } : {}),
        ...(containers !== undefined ? { containersReportedAt: now } : {}),
      };
      await tx.serverTelemetry.upsert({
        where: { serverId },
        create: { serverId, ...patch, agentDroppedTotal: dropDelta },
        update: { ...patch, agentDroppedTotal: { increment: dropDelta } },
      });
    });
  }

  /** Servers (non-revoked) the user may `perm`, with what the metrics/log views need. */
  async serversInScope(user: AuthUser, perm: Permission) {
    const where = this.authz.serverWhere(user, perm);
    if (!where) return [];
    return this.prisma.server.findMany({
      where: { AND: [where, { status: { not: 'revoked' } }] },
      select: {
        id: true,
        name: true,
        environment: true,
        status: true,
        lastHeartbeatAt: true,
        metrics: true,
        metricsSampledAt: true,
      },
      orderBy: { name: 'asc' },
      take: 5000,
    });
  }
}
