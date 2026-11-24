import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Req,
} from '@nestjs/common';
import {
  type CreateServerGroupInput,
  createServerGroupSchema,
  type Environment,
  ERROR_CODES,
  type ServerGroup,
  type UpdateServerGroupInput,
  updateServerGroupSchema,
} from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { CurrentUser, RequirePermission } from '../common/decorators';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';

type GroupRow = {
  id: string;
  name: string;
  description: string | null;
  environment: string | null;
  createdAt: Date;
  updatedAt: Date;
  _count: { servers: number };
};
const toGroup = (g: GroupRow): ServerGroup => ({
  id: g.id,
  name: g.name,
  description: g.description,
  environment: (g.environment as Environment | null) ?? null,
  serverCount: g._count.servers,
  createdAt: g.createdAt.toISOString(),
  updatedAt: g.updatedAt.toISOString(),
});

const uuid = new ParseUUIDPipe();
const groupScope = (env: string | null | undefined) => (env ? { environment: env } : undefined);

@Controller('server-groups')
export class ServerGroupsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @RequirePermission('fleet.read')
  async list(@Req() req: Request) {
    const pq = parseQuery(req.originalUrl, {
      sortable: ['createdAt', 'name'],
      defaultSort: 'name',
    });
    const where = buildWhere(pq, {
      environment: { prop: 'environment', type: 'string' },
      name: { prop: 'name', type: 'string' },
    });
    const [total, rows] = await Promise.all([
      this.prisma.serverGroup.count({ where }),
      this.prisma.serverGroup.findMany({
        where,
        orderBy: { [pq.sort]: pq.order },
        skip: pq.skip,
        take: pq.limit,
        include: { _count: { select: { servers: true } } },
      }),
    ]);
    return new Paginated(rows.map(toGroup), paginate(pq, total));
  }

  @Post()
  @HttpCode(201)
  @RequirePermission('policies.manage')
  async create(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createServerGroupSchema)) body: CreateServerGroupInput,
  ) {
    await this.authz.enforce(
      user,
      'policies.manage',
      body.environment ? { environment: body.environment } : undefined,
      {
        action: 'server_groups.create',
        targetType: 'server_group',
      },
    );
    try {
      const g = await this.prisma.$transaction(async (tx) => {
        const row = await tx.serverGroup.create({
          data: {
            id: uuidv7(),
            name: body.name,
            description: body.description ?? null,
            environment: body.environment ?? null,
          },
          include: { _count: { select: { servers: true } } },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'server_groups.create',
            targetType: 'server_group',
            targetId: row.id,
            result: 'success',
            diff: body,
          },
          tx,
        );
        return row;
      });
      return toGroup(g);
    } catch (e) {
      if (isUniqueViolation(e)) throw AppError.conflict('A group with this name already exists');
      throw e;
    }
  }

  /** Groups are global objects (names/ids visible to any fleet reader, SEC-P7-A1). */
  @Get(':id')
  @RequirePermission('fleet.read')
  async get(@Param('id', uuid) id: string) {
    const g = await this.prisma.serverGroup.findUnique({
      where: { id },
      include: { _count: { select: { servers: true } } },
    });
    if (!g) throw AppError.notFound('Server group');
    return toGroup(g);
  }

  @Patch(':id')
  @RequirePermission('policies.manage')
  async update(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateServerGroupSchema)) body: UpdateServerGroupInput,
  ) {
    const cur = await this.prisma.serverGroup.findUnique({ where: { id } });
    if (!cur) throw AppError.notFound('Server group');
    const audit = { action: 'server_groups.update', targetType: 'server_group', targetId: id };
    // rights over the group's current scope and over the destination scope
    await this.authz.enforce(user, 'policies.manage', groupScope(cur.environment), audit);
    if (body.environment !== undefined && body.environment !== cur.environment)
      await this.authz.enforce(user, 'policies.manage', groupScope(body.environment), audit);
    try {
      const g = await this.prisma.$transaction(async (tx) => {
        const row = await tx.serverGroup.update({
          where: { id },
          data: {
            ...(body.name !== undefined ? { name: body.name } : {}),
            ...(body.description !== undefined ? { description: body.description } : {}),
            ...(body.environment !== undefined ? { environment: body.environment } : {}),
          },
          include: { _count: { select: { servers: true } } },
        });
        await this.audit.record(
          {
            actorId: user.id,
            ...audit,
            result: 'success',
            diff: {
              before: {
                name: cur.name,
                description: cur.description,
                environment: cur.environment,
              },
              after: body,
            },
          },
          tx,
        );
        return row;
      });
      return toGroup(g);
    } catch (e) {
      if (isUniqueViolation(e)) throw AppError.conflict('A group with this name already exists');
      throw e;
    }
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('policies.manage')
  async remove(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string): Promise<void> {
    const cur = await this.prisma.serverGroup.findUnique({
      where: { id },
      include: { _count: { select: { servers: true } } },
    });
    if (!cur) throw AppError.notFound('Server group');
    const audit = { action: 'server_groups.delete', targetType: 'server_group', targetId: id };
    await this.authz.enforce(user, 'policies.manage', groupScope(cur.environment), audit);
    await this.prisma.$transaction(async (tx) => {
      // re-check inside the transaction: a server assigned meanwhile keeps the group alive
      const count = await tx.server.count({ where: { groupId: id } });
      if (count > 0)
        throw AppError.conflict('Server group still has servers', ERROR_CODES.GROUP_NOT_EMPTY, {
          serverCount: count,
        });
      await tx.serverGroup.delete({ where: { id } });
      await this.audit.record(
        {
          actorId: user.id,
          ...audit,
          result: 'success',
          metadata: { name: cur.name, environment: cur.environment },
        },
        tx,
      );
    });
  }
}
