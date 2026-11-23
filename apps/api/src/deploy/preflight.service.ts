import { Injectable } from '@nestjs/common';
import {
  DEPLOYMENT_ACTIVE_STATUSES,
  isDigestPinned,
  MANAGED_PORT_MAX,
  MANAGED_PORT_MIN,
  NGINX_MANAGED_DIR,
  MANAGED_ROUTING_CONF_PATH,
  type PreflightCheck,
  type PreflightCheckName,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { PrismaService, type Tx } from '../common/prisma.service';
import { deriveStatus } from '../servers/server-view';
import type { ContainerAppRow } from './container-common';
import { SecretsService } from './secrets.service';

export const DISK_LOW_PCT = 90;
/** Metrics older than this are treated as unknown for the disk check. */
const METRICS_MAX_AGE_MS = 5 * 60_000;
const ACTIVE = [...DEPLOYMENT_ACTIVE_STATUSES] as string[];

export interface DomainConflict {
  domain: string;
  with: {
    type: 'application' | 'discovered_nginx_server';
    id: string;
    serverId: string;
    name: string;
    file?: string | null;
  };
}

function domainMatches(pattern: string, domain: string): boolean {
  if (pattern === domain) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // ".example.com"
    return domain.endsWith(suffix) && domain.length > suffix.length;
  }
  if (pattern.startsWith('.')) return domain === pattern.slice(1) || domain.endsWith(pattern);
  return false;
}

export interface PreflightTarget {
  app: { id: string; serverId: string; name: string; domains: string[] };
  container: ContainerAppRow;
  image?: string;
  /** checks to omit (e.g. rollback reuses its container/port and needs no secrets) */
  skip?: PreflightCheckName[];
  /** deployment being (re)checked — excluded from the lock check */
  deploymentId?: string;
}

/** §7.4 preflight checks (Center side). Any `ok:false` blocks the deployment before any job is sent. */
@Injectable()
export class PreflightService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly secrets: SecretsService,
  ) {}

  /**
   * Domains used by another application on the same server, a discovered (legacy) nginx server on
   * this server (latest completed scan, pPanel-managed files excluded), or another container app anywhere.
   */
  async domainConflicts(
    appId: string | null,
    serverId: string,
    domains: string[],
    db: Tx | PrismaService = this.prisma,
  ): Promise<DomainConflict[]> {
    const out: DomainConflict[] = [];
    const others = await db.application.findMany({
      where: {
        id: appId ? { not: appId } : undefined,
        OR: [{ serverId }, { kind: 'container' }],
        domains: { hasSome: domains },
      },
      select: { id: true, serverId: true, name: true, domains: true },
    });
    for (const o of others)
      for (const d of domains)
        if (o.domains.includes(d))
          out.push({
            domain: d,
            with: { type: 'application', id: o.id, serverId: o.serverId, name: o.name },
          });
    const scan = await db.discoveryScan.findFirst({
      where: { serverId, status: 'completed' },
      orderBy: { completedAt: 'desc' },
      select: { id: true },
    });
    if (scan) {
      const findings = await db.discoveryFinding.findMany({
        where: { scanId: scan.id, kind: 'nginx_server' },
        select: { id: true, title: true, domains: true, provenance: true, applicationId: true },
      });
      for (const f of findings) {
        if (appId && f.applicationId === appId) continue;
        const file = (f.provenance as { file?: string | null } | null)?.file ?? null;
        if (file && (file.startsWith(NGINX_MANAGED_DIR) || file === MANAGED_ROUTING_CONF_PATH))
          continue; // pPanel's own routes (managed apps are checked through `applications`)
        for (const d of domains)
          if (f.domains.some((p) => domainMatches(p.toLowerCase(), d)))
            out.push({
              domain: d,
              with: {
                type: 'discovered_nginx_server',
                id: f.id,
                serverId,
                name: f.title,
                file,
              },
            });
      }
    }
    return out;
  }

  async run(t: PreflightTarget): Promise<PreflightCheck[]> {
    const skip = new Set(t.skip ?? []);
    const checks: PreflightCheck[] = [];
    const server = await this.prisma.server.findUniqueOrThrow({
      where: { id: t.app.serverId },
      include: { managedRouting: true },
    });
    const push = (c: PreflightCheck) => {
      if (!skip.has(c.check)) checks.push(c);
    };

    const status = deriveStatus(server.status, server.lastHeartbeatAt);
    const online = status === 'online' || status === 'degraded';
    push(
      online
        ? { check: 'agent_online', ok: true, message: `Agent ${status}` }
        : {
            check: 'agent_online',
            ok: false,
            code: 'AGENT_OFFLINE',
            message: `Agent is ${status}`,
            details: { status, lastHeartbeatAt: server.lastHeartbeatAt?.toISOString() ?? null },
          },
    );

    const routing = server.managedRouting;
    push(
      routing?.status === 'enabled'
        ? { check: 'managed_routing', ok: true, message: 'Managed routing enabled' }
        : {
            check: 'managed_routing',
            ok: false,
            code: 'MANAGED_ROUTING_DISABLED',
            message: 'Enable managed routing on this server first',
            details: { status: routing?.status ?? 'disabled' },
          },
    );

    if (t.image !== undefined)
      push(
        isDigestPinned(t.image)
          ? { check: 'image_pinned', ok: true, message: 'Image pinned by digest' }
          : {
              check: 'image_pinned',
              ok: false,
              code: 'IMAGE_NOT_PINNED',
              message: 'Image must be pinned by digest (registry/repo@sha256:…)',
            },
      );

    if (!skip.has('secrets_present')) {
      const { versions } = await this.secrets.keyVersions(t.app.id);
      const missing = t.container.secretKeys.filter((k) => !(k in versions));
      push(
        missing.length === 0
          ? { check: 'secrets_present', ok: true, message: 'All declared secrets are set' }
          : {
              check: 'secrets_present',
              ok: false,
              code: 'SECRETS_MISSING',
              message: `Missing secrets: ${missing.join(', ')}`,
              details: { missing },
            },
      );
    }

    const conflicts = await this.domainConflicts(t.app.id, t.app.serverId, t.app.domains);
    push(
      conflicts.length === 0
        ? { check: 'domain_conflict', ok: true, message: 'No domain conflicts' }
        : {
            check: 'domain_conflict',
            ok: false,
            code: 'DOMAIN_CONFLICT',
            message: `Domain already in use: ${[...new Set(conflicts.map((c) => c.domain))].join(', ')}`,
            details: { conflicts },
          },
    );

    if (!skip.has('port_alloc')) {
      const used = await this.prisma.hostPortAllocation.count({
        where: { serverId: t.app.serverId },
      });
      const capacity = MANAGED_PORT_MAX - MANAGED_PORT_MIN + 1;
      push(
        used < capacity
          ? {
              check: 'port_alloc',
              ok: true,
              message: `${capacity - used} managed host ports free (${MANAGED_PORT_MIN}–${MANAGED_PORT_MAX})`,
            }
          : {
              check: 'port_alloc',
              ok: false,
              code: 'NO_PORT_AVAILABLE',
              message: 'No free managed host port on this server',
            },
      );
    }

    const m = server.metrics as { diskPct?: number | null } | null;
    const fresh =
      online &&
      !!server.metricsSampledAt &&
      Date.now() - server.metricsSampledAt.getTime() <= METRICS_MAX_AGE_MS &&
      typeof m?.diskPct === 'number';
    if (!fresh) {
      const prod = server.environment === 'production';
      push({
        check: 'disk',
        ok: !prod,
        code: 'DISK_UNKNOWN',
        warning: !prod,
        message: prod
          ? 'Disk usage unknown (stale metrics) — blocked in production'
          : 'Disk usage unknown (stale metrics)',
      });
    } else if ((m!.diskPct as number) >= DISK_LOW_PCT) {
      push({
        check: 'disk',
        ok: false,
        code: 'DISK_LOW',
        message: `Disk ${m!.diskPct}% used (≥ ${DISK_LOW_PCT}%)`,
        details: { diskPct: m!.diskPct },
      });
    } else push({ check: 'disk', ok: true, message: `Disk ${m!.diskPct}% used` });

    const where: Prisma.DeploymentWhereInput = {
      applicationId: t.app.id,
      status: { in: ACTIVE },
      ...(t.deploymentId ? { id: { not: t.deploymentId } } : {}),
    };
    const active = await this.prisma.deployment.findFirst({
      where,
      select: { id: true, status: true },
    });
    push(
      active
        ? {
            check: 'lock',
            ok: false,
            code: 'DEPLOYMENT_IN_PROGRESS',
            message: 'Another deployment of this application is in progress',
            details: { deploymentId: active.id, status: active.status },
          }
        : { check: 'lock', ok: true, message: 'No deployment in progress' },
    );
    return checks;
  }
}

export function firstFailure(checks: PreflightCheck[]): PreflightCheck | undefined {
  return checks.find((c) => !c.ok);
}
