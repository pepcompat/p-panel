import { Injectable } from '@nestjs/common';
import { ERROR_CODES, type Heartbeat, type Server, type UpdateServerInput } from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService, type ResourceScope } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, type FieldMap, paginate, type ParsedQuery } from '../common/query-builder';
import { JobNotifier } from '../jobs/job-notifier';
import { serverInclude, type ServerRow, statusWhere, toServer } from './server-view';

const FIELDS: FieldMap = {
  environment: { prop: 'environment', type: 'string' },
  status: { prop: 'status', type: 'string' },
  group_id: { prop: 'groupId', type: 'uuid' },
  name: { prop: 'name', type: 'string' },
  hostname: { prop: 'hostname', type: 'string' },
  created_at: { prop: 'createdAt', type: 'date' },
  last_heartbeat_at: { prop: 'lastHeartbeatAt', type: 'date' },
};

export function scopeOf(s: { id: string; environment: string }): ResourceScope {
  return { serverId: s.id, environment: s.environment };
}

/** Parse `If-Match: 3`, `"3"` or `W/"3"`. */
export function parseIfMatch(h: string | undefined): number | undefined {
  if (h === undefined) return undefined;
  const m = /^(?:W\/)?"?(\d{1,9})"?$/.exec(h.trim());
  if (!m) throw AppError.badRequest('If-Match must be the resource version number');
  return Number(m[1]);
}

@Injectable()
export class ServersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly notifier: JobNotifier,
  ) {}

  allowedActions(user: AuthUser, row: { id: string; environment: string; status: string }): string[] {
    if (row.status === 'revoked') return [];
    const scope = scopeOf(row);
    const out: string[] = [];
    if (this.authz.can(user, 'servers.operate', scope)) out.push('edit', 'create_job', 'restart_service', 'cancel_job');
    if (this.authz.can(user, 'servers.revoke', scope)) out.push('revoke');
    return out;
  }

  view(user: AuthUser, row: ServerRow): Server {
    return toServer(row, this.allowedActions(user, row));
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const scope = this.authz.serverWhere(user, 'fleet.read');
    if (!scope) throw AppError.forbidden();
    const and: Prisma.ServerWhereInput[] = [scope, buildWhere(pq, FIELDS, ['status'])];
    for (const f of pq.filters.filter((x) => x.field === 'status')) {
      const values = f.op === 'in' ? f.value.split(',') : [f.value];
      if (f.op !== 'eq' && f.op !== 'in') throw AppError.badRequest('status supports eq and in');
      and.push({ OR: values.map((v) => statusWhere(v.trim())) });
    }
    if (pq.q) and.push({ OR: [{ name: { contains: pq.q, mode: 'insensitive' } }, { hostname: { contains: pq.q, mode: 'insensitive' } }] });
    const where: Prisma.ServerWhereInput = { AND: and };
    const [total, rows] = await Promise.all([
      this.prisma.server.count({ where }),
      this.prisma.server.findMany({
        where,
        include: serverInclude,
        orderBy: [pq.sort === 'lastHeartbeatAt' ? { lastHeartbeatAt: { sort: pq.order, nulls: 'last' } } : { [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(
      rows.map((r) => this.view(user, r)),
      paginate(pq, total),
    );
  }

  /** Loads a server and enforces `perm` on its scope; out-of-scope reads look like 404 (no existence oracle). */
  async load(user: AuthUser, id: string, perm: 'fleet.read' | 'servers.operate' | 'servers.revoke', action: string): Promise<ServerRow> {
    const row = await this.prisma.server.findUnique({ where: { id }, include: serverInclude });
    if (!row || !this.authz.can(user, 'fleet.read', scopeOf(row))) throw AppError.notFound('Server');
    if (perm !== 'fleet.read') await this.authz.enforce(user, perm, scopeOf(row), { action, targetType: 'server', targetId: id });
    return row;
  }

  async get(user: AuthUser, id: string): Promise<Server> {
    return this.view(user, await this.load(user, id, 'fleet.read', 'servers.read'));
  }

  async update(user: AuthUser, id: string, input: UpdateServerInput, ifMatch: number | undefined): Promise<Server> {
    const row = await this.load(user, id, 'servers.operate', 'servers.update');
    if (row.status === 'revoked') throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (input.environment && input.environment !== row.environment) {
      // moving a server between environments requires operate rights on the destination too
      await this.authz.enforce(user, 'servers.operate', { serverId: id, environment: input.environment }, {
        action: 'servers.update',
        targetType: 'server',
        targetId: id,
      });
    }
    if (input.groupId) {
      const g = await this.prisma.serverGroup.findUnique({ where: { id: input.groupId } });
      if (!g) throw AppError.validation([{ path: 'groupId', message: 'unknown server group' }]);
    }
    const before = {
      name: row.name,
      environment: row.environment,
      tags: row.tags,
      groupId: row.groupId,
      connectionPolicy: row.connectionPolicy,
      ownedUnits: row.ownedUnits,
    };
    const updated = await this.prisma.$transaction(async (tx) => {
      const r = await tx.server.updateMany({
        where: { id, ...(ifMatch !== undefined ? { version: ifMatch } : {}) },
        data: { ...input, version: { increment: 1 } },
      });
      if (r.count !== 1) {
        const cur = await tx.server.findUnique({ where: { id }, select: { version: true } });
        throw AppError.conflict('Server was modified by someone else', ERROR_CODES.VERSION_CONFLICT, {
          currentVersion: cur?.version,
        });
      }
      await this.audit.record(
        { actorId: user.id, action: 'servers.update', targetType: 'server', targetId: id, result: 'success', diff: { before, after: input } },
        tx,
      );
      return tx.server.findUniqueOrThrow({ where: { id }, include: serverInclude });
    });
    return this.view(user, updated);
  }

  async revoke(user: AuthUser, id: string, stepUpHeader: string | undefined): Promise<Server> {
    const row = await this.load(user, id, 'servers.revoke', 'servers.revoke');
    if (row.environment === 'production') this.auth.assertStepUp(user, stepUpHeader);
    if (row.status === 'revoked') return this.view(user, row);
    const now = new Date();
    const updated = await this.prisma.$transaction(async (tx) => {
      await tx.server.update({ where: { id }, data: { status: 'revoked', revokedAt: now, version: { increment: 1 } } });
      const certs = await tx.agentCertificate.updateMany({
        where: { serverId: id, revokedAt: null },
        data: { revokedAt: now, revokedReason: 'server_revoked' },
      });
      const jobs = await tx.job.updateMany({
        where: { serverId: id, status: { in: ['queued', 'leased', 'running'] } },
        data: { status: 'cancelled', finishedAt: now, leaseTokenHash: null, error: { code: 'SERVER_REVOKED' } },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'servers.revoke',
          targetType: 'server',
          targetId: id,
          result: 'success',
          metadata: { certificatesRevoked: certs.count, jobsCancelled: jobs.count, environment: row.environment },
        },
        tx,
      );
      return tx.server.findUniqueOrThrow({ where: { id }, include: serverInclude });
    });
    this.notifier.notify(id); // wake any long-poll so it notices the revocation
    return this.view(user, updated);
  }

  async heartbeats(user: AuthUser, id: string, limitRaw: string | undefined): Promise<Heartbeat[]> {
    await this.load(user, id, 'fleet.read', 'servers.heartbeats');
    const limit = limitRaw === undefined ? 50 : Number(limitRaw);
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw AppError.badRequest('limit must be 1..500');
    const rows = await this.prisma.agentHeartbeat.findMany({ where: { serverId: id }, orderBy: { receivedAt: 'desc' }, take: limit });
    return rows.map((h) => ({
      id: h.id.toString(),
      seq: Number(h.seq),
      sentAt: h.sentAt?.toISOString() ?? null,
      receivedAt: h.receivedAt.toISOString(),
      agentVersion: h.agentVersion,
      metrics: (h.metrics as Record<string, number> | null) ?? null,
    }));
  }
}
