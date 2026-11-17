import { Controller, Get, Req } from '@nestjs/common';
import type { AuditEvent } from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import type { Request } from 'express';
import { AuthzService } from '../auth/authz.service';
import { CurrentUser, RequirePermission } from '../common/decorators';
import { Paginated } from '../common/envelope';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, type FieldMap, paginate, parseQuery } from '../common/query-builder';

const FIELDS: FieldMap = {
  action: { prop: 'action', type: 'string' },
  actor_id: { prop: 'actorId', type: 'string' },
  actor_type: { prop: 'actorType', type: 'string' },
  target_id: { prop: 'targetId', type: 'string' },
  target_type: { prop: 'targetType', type: 'string' },
  result: { prop: 'result', type: 'string' },
  request_id: { prop: 'requestId', type: 'string' },
  created_at: { prop: 'createdAt', type: 'date' },
};

@Controller('audit-events')
@RequirePermission('audit.read')
export class AuditController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
  ) {}

  @Get()
  async list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    // Audit events span all scopes → global audit.read required.
    await this.authz.enforce(user, 'audit.read', undefined, { action: 'audit.list' });
    const pq = parseQuery(req.originalUrl, { sortable: ['createdAt', 'action'] });
    const where: Prisma.AuditEventWhereInput = buildWhere(pq, FIELDS);
    if (pq.q) where.action = { contains: pq.q, mode: 'insensitive' };
    const [total, rows] = await Promise.all([
      this.prisma.auditEvent.count({ where }),
      this.prisma.auditEvent.findMany({ where, orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }], skip: pq.skip, take: pq.limit }),
    ]);
    const items: AuditEvent[] = rows.map((r) => ({
      id: r.id,
      actorId: r.actorId,
      actorType: r.actorType as AuditEvent['actorType'],
      action: r.action,
      targetType: r.targetType,
      targetId: r.targetId,
      result: r.result as AuditEvent['result'],
      requestId: r.requestId,
      diffHash: r.diffHash,
      metadata: (r.metadata as Record<string, unknown> | null) ?? null,
      createdAt: r.createdAt.toISOString(),
    }));
    return new Paginated(items, paginate(pq, total));
  }
}
