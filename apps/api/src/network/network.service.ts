import { Injectable } from '@nestjs/common';
import {
  ERROR_CODES,
  type NetworkInventoryEntry,
  type NetworkInventoryInput,
  type NetworkSource,
  type NetworkTopology,
} from '@ppanel/shared-contracts';
import type { ServerNetworkInventory } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { scopeOf } from '../servers/servers.service';
import { computeTopology } from './topology';

export function toInventoryEntry(r: ServerNetworkInventory): NetworkInventoryEntry {
  return {
    serverId: r.serverId,
    source: r.source as NetworkSource,
    region: r.region,
    vpcUuid: r.vpcUuid,
    vpcName: r.vpcName,
    dropletId: r.dropletId,
    privateIpv4: r.privateIpv4,
    publicIpv4: r.publicIpv4,
    observedAt: r.observedAt.toISOString(),
  };
}

@Injectable()
export class NetworkService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
  ) {}

  /**
   * User inventory (`source: 'inventory'`): all-or-nothing. Rows name a server by id or by
   * hostname/name (exactly one visible match); every server needs servers.operate in scope.
   */
  async importInventory(
    user: AuthUser,
    input: NetworkInventoryInput,
  ): Promise<{ upserted: number; rows: NetworkInventoryEntry[] }> {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) throw AppError.forbidden();
    const ids = input.rows.flatMap((r) => (r.serverId ? [r.serverId] : []));
    const names = input.rows.flatMap((r) => (r.hostname ? [r.hostname.toLowerCase()] : []));
    const candidates = await this.prisma.server.findMany({
      where: {
        AND: [
          visible,
          { status: { not: 'revoked' } },
          {
            OR: [
              { id: { in: ids } },
              { hostname: { in: names, mode: 'insensitive' } },
              { name: { in: names, mode: 'insensitive' } },
            ],
          },
        ],
      },
      select: { id: true, name: true, hostname: true, environment: true },
    });
    const errors: Array<{ index: number; reason: string }> = [];
    const resolved: Array<{ index: number; server: (typeof candidates)[number] }> = [];
    input.rows.forEach((row, index) => {
      const matches = row.serverId
        ? candidates.filter((c) => c.id === row.serverId)
        : candidates.filter(
            (c) =>
              c.hostname.toLowerCase() === row.hostname!.toLowerCase() ||
              c.name.toLowerCase() === row.hostname!.toLowerCase(),
          );
      if (matches.length !== 1)
        errors.push({
          index,
          reason: matches.length === 0 ? 'server_not_found' : 'ambiguous_hostname',
        });
      else resolved.push({ index, server: matches[0]! });
    });
    const seen = new Map<string, number>();
    for (const r of resolved) {
      const prev = seen.get(r.server.id);
      if (prev !== undefined) errors.push({ index: r.index, reason: `duplicate_of_row_${prev}` });
      else seen.set(r.server.id, r.index);
    }
    if (errors.length)
      throw new AppError(
        422,
        ERROR_CODES.INVENTORY_SERVER_UNRESOLVED,
        'Some inventory rows do not resolve to exactly one server',
        errors.slice(0, 50),
      );
    for (const r of resolved)
      await this.authz.enforce(user, 'servers.operate', scopeOf(r.server), {
        action: 'network.inventory.import',
        targetType: 'server',
        targetId: r.server.id,
      });
    const now = new Date();
    const rows = await this.prisma.$transaction(async (tx) => {
      const out: ServerNetworkInventory[] = [];
      for (const r of resolved) {
        const row = input.rows[r.index]!;
        const data = {
          region: row.region ?? null,
          vpcUuid: row.vpcUuid ?? null,
          vpcName: row.vpcName ?? null,
          dropletId: row.dropletId ?? null,
          privateIpv4: row.privateIpv4 ?? null,
          publicIpv4: row.publicIpv4 ?? null,
          integrationId: null,
          observedAt: now,
        };
        out.push(
          await tx.serverNetworkInventory.upsert({
            where: { serverId_source: { serverId: r.server.id, source: 'inventory' } },
            create: { id: uuidv7(), serverId: r.server.id, source: 'inventory', ...data },
            update: data,
          }),
        );
      }
      await this.audit.record(
        {
          actorId: user.id,
          action: 'network.inventory.import',
          targetType: 'server_network_inventory',
          result: 'success',
          diff: input.rows,
          metadata: { rows: out.length, serverIds: out.map((o) => o.serverId).slice(0, 100) },
        },
        tx,
      );
      return out;
    });
    return { upserted: rows.length, rows: rows.map(toInventoryEntry) };
  }

  /** Scope-filtered: only servers the user may read appear (and only they are compared). */
  async topology(user: AuthUser): Promise<NetworkTopology> {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) throw AppError.forbidden();
    const servers = await this.prisma.server.findMany({
      where: { AND: [visible, { status: { not: 'revoked' } }] },
      select: {
        id: true,
        name: true,
        addresses: { select: { family: true, scope: true, address: true, source: true } },
        networkInventory: true,
      },
      orderBy: { name: 'asc' },
      take: 5000,
    });
    return computeTopology(
      servers.map((s) => ({
        id: s.id,
        name: s.name,
        addresses: s.addresses,
        inventory: s.networkInventory,
      })),
    );
  }
}
