import {
  type ConnectionPolicy,
  type Environment,
  OFFLINE_AFTER_SEC,
  type Server,
  type ServerAddress,
  type ServerStatus,
  STALE_AFTER_SEC,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { isAgentOutdated } from '../version/build-info';

export const serverInclude = {
  addresses: { orderBy: { address: 'asc' } },
  capabilities: { orderBy: { name: 'asc' } },
  certificates: { where: { revokedAt: null }, orderBy: { notAfter: 'desc' }, take: 1 },
} satisfies Prisma.ServerInclude;

export type ServerRow = Prisma.ServerGetPayload<{ include: typeof serverInclude }>;

/** Status is derived on read from the last heartbeat; stored status is never overwritten by staleness. */
export function deriveStatus(
  stored: string,
  lastHeartbeatAt: Date | null,
  now = Date.now(),
): ServerStatus {
  if (stored === 'revoked' || stored === 'enrolling') return stored;
  if (!lastHeartbeatAt) return 'offline';
  const ageSec = (now - lastHeartbeatAt.getTime()) / 1000;
  if (ageSec > OFFLINE_AFTER_SEC) return 'offline';
  if (ageSec > STALE_AFTER_SEC) return 'stale';
  return stored === 'degraded' ? 'degraded' : 'online';
}

/** Translate a derived status into a SQL-side filter so pagination stays correct. */
export function statusWhere(status: string, now = Date.now()): Prisma.ServerWhereInput {
  const staleCut = new Date(now - STALE_AFTER_SEC * 1000);
  const offCut = new Date(now - OFFLINE_AFTER_SEC * 1000);
  switch (status) {
    case 'online':
    case 'degraded':
      return { status, lastHeartbeatAt: { gte: staleCut } };
    case 'stale':
      return {
        status: { in: ['online', 'degraded'] },
        lastHeartbeatAt: { lt: staleCut, gte: offCut },
      };
    case 'offline':
      return {
        status: { in: ['online', 'degraded', 'offline', 'stale'] },
        OR: [{ lastHeartbeatAt: null }, { lastHeartbeatAt: { lt: offCut } }],
      };
    default:
      return { status };
  }
}

export function toServer(
  row: ServerRow,
  allowedActions: string[],
  now = Date.now(),
  minAgentVersion = '0.0.0',
): Server {
  const status = deriveStatus(row.status, row.lastHeartbeatAt, now);
  const m = row.metrics as {
    cpuPct?: number | null;
    memPct?: number | null;
    diskPct?: number | null;
    load1?: number | null;
    uptimeSec?: number | null;
  } | null;
  const cert = row.certificates[0];
  return {
    id: row.id,
    name: row.name,
    hostname: row.hostname,
    environment: row.environment as Environment,
    groupId: row.groupId,
    tags: row.tags,
    status,
    lastHeartbeatAt: row.lastHeartbeatAt?.toISOString() ?? null,
    agentVersion: row.agentVersion,
    agentOutdated: isAgentOutdated(row.agentVersion, minAgentVersion),
    os: (row.os as Server['os']) ?? null,
    provider: (row.provider as Server['provider']) ?? null,
    addresses: row.addresses.map((a): ServerAddress => ({
      family: a.family as ServerAddress['family'],
      scope: a.scope as ServerAddress['scope'],
      address: a.address,
      ...(a.interface ? { interface: a.interface } : {}),
      source: a.source as ServerAddress['source'],
      verifiedAt: a.verifiedAt?.toISOString() ?? null,
    })),
    connectionPolicy: row.connectionPolicy as ConnectionPolicy,
    // Metrics are never zeroed: stale/offline servers keep last values flagged stale.
    metrics:
      m && row.metricsSampledAt
        ? {
            cpuPct: m.cpuPct ?? null,
            memPct: m.memPct ?? null,
            diskPct: m.diskPct ?? null,
            load1: m.load1 ?? null,
            uptimeSec: m.uptimeSec ?? null,
            sampledAt: row.metricsSampledAt.toISOString(),
            stale: status !== 'online' && status !== 'degraded',
          }
        : null,
    capabilities: row.capabilities.map((c) => c.name),
    buildNode: row.buildNode,
    certificate: cert ? { serial: cert.serial, notAfter: cert.notAfter.toISOString() } : null,
    allowedActions,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    version: row.version,
    ...({ ownedUnits: row.ownedUnits } as object),
  };
}
