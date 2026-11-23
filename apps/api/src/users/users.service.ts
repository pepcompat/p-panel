import { Injectable } from '@nestjs/common';
import {
  type CreateRoleBindingInput,
  type CreateUserInput,
  ENVIRONMENTS,
  ERROR_CODES,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { hashPassword } from '../auth/password';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import { type AuthUser, toRoleBinding } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { toUserPublic } from './user-view';

export const USER_FIELDS = {
  email: { prop: 'email', type: 'string' },
  display_name: { prop: 'displayName', type: 'string' },
  status: { prop: 'status', type: 'string' },
  created_at: { prop: 'createdAt', type: 'date' },
} as const;

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly authz: AuthzService,
  ) {}

  private async gate(actor: AuthUser, action: string, targetId?: string) {
    await this.authz.enforce(actor, 'users.manage', undefined, {
      action,
      targetType: 'user',
      targetId,
    });
  }

  async list(actor: AuthUser, pq: ParsedQuery) {
    await this.gate(actor, 'users.list');
    const where: Prisma.UserWhereInput = buildWhere(pq, { ...USER_FIELDS });
    if (pq.q) {
      where.OR = [
        { email: { contains: pq.q, mode: 'insensitive' } },
        { displayName: { contains: pq.q, mode: 'insensitive' } },
      ];
    }
    const [total, rows] = await Promise.all([
      this.prisma.user.count({ where }),
      this.prisma.user.findMany({
        where,
        orderBy: { [pq.sort]: pq.order },
        skip: pq.skip,
        take: pq.limit,
        include: {
          roleBindings: true,
          mfaFactors: { where: { confirmedAt: { not: null } }, select: { id: true } },
        },
      }),
    ]);
    return new Paginated(
      rows.map((u) => ({
        ...toUserPublic(u, u.mfaFactors.length > 0),
        bindings: u.roleBindings.map(toRoleBinding),
      })),
      paginate(pq, total),
    );
  }

  async create(actor: AuthUser, input: CreateUserInput) {
    await this.gate(actor, 'users.create');
    for (const b of input.bindings ?? []) await this.validateScope(b);
    const passwordHash = await hashPassword(input.password);
    try {
      const created = await this.prisma.$transaction(async (tx) => {
        const id = uuidv7();
        const u = await tx.user.create({
          data: { id, email: input.email, displayName: input.displayName, passwordHash },
        });
        const bindings = [];
        for (const b of input.bindings ?? [])
          bindings.push(await this.insertBinding(tx, id, b, actor.id));
        await this.audit.record(
          {
            actorId: actor.id,
            action: 'users.create',
            targetType: 'user',
            targetId: id,
            result: 'success',
            diff: {
              email: input.email,
              displayName: input.displayName,
              bindings: input.bindings ?? [],
            },
          },
          tx,
        );
        return { ...toUserPublic(u, false), bindings: bindings.map(toRoleBinding) };
      });
      return { user: created };
    } catch (e) {
      if (isUniqueViolation(e)) throw AppError.conflict('A user with this email already exists');
      throw e;
    }
  }

  async addBinding(actor: AuthUser, userId: string, input: CreateRoleBindingInput) {
    await this.gate(actor, 'role_bindings.create', userId);
    await this.validateScope(input);
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw AppError.notFound('User');
    try {
      const b = await this.prisma.$transaction(async (tx) => {
        const row = await this.insertBinding(tx, userId, input, actor.id);
        await this.audit.record(
          {
            actorId: actor.id,
            action: 'role_bindings.create',
            targetType: 'role_binding',
            targetId: row.id,
            result: 'success',
            diff: { userId, ...input },
          },
          tx,
        );
        return row;
      });
      return toRoleBinding(b);
    } catch (e) {
      if (isUniqueViolation(e)) throw AppError.conflict('Binding already exists');
      throw e;
    }
  }

  async removeBinding(actor: AuthUser, bindingId: string): Promise<void> {
    await this.gate(actor, 'role_bindings.delete', bindingId);
    await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('ppanel_owner_bindings'))`;
      const b = await tx.roleBinding.findUnique({ where: { id: bindingId } });
      if (!b) throw AppError.notFound('Role binding');
      if (b.roleKey === 'platform_owner' && b.scopeType === 'global') {
        const owners = await tx.roleBinding.count({
          where: { roleKey: 'platform_owner', scopeType: 'global', user: { status: 'active' } },
        });
        if (owners <= 1)
          throw AppError.conflict('Cannot remove the last platform owner', ERROR_CODES.LAST_OWNER);
      }
      await tx.roleBinding.delete({ where: { id: bindingId } });
      await this.audit.record(
        {
          actorId: actor.id,
          action: 'role_bindings.delete',
          targetType: 'role_binding',
          targetId: bindingId,
          result: 'success',
          diff: toRoleBinding(b),
        },
        tx,
      );
    });
  }

  private async validateScope(b: CreateRoleBindingInput): Promise<void> {
    if (
      b.scopeType === 'environment' &&
      !(ENVIRONMENTS as readonly string[]).includes(b.scopeId ?? '')
    ) {
      throw AppError.validation([
        { path: 'scopeId', message: `must be one of ${ENVIRONMENTS.join(', ')}` },
      ]);
    }
    if (b.scopeType === 'server') {
      const ok =
        /^[0-9a-f-]{36}$/i.test(b.scopeId ?? '') &&
        (await this.prisma.server.count({ where: { id: b.scopeId } })) > 0;
      if (!ok) throw AppError.validation([{ path: 'scopeId', message: 'unknown server' }]);
    }
  }

  private insertBinding(tx: Tx, userId: string, b: CreateRoleBindingInput, createdById: string) {
    return tx.roleBinding.create({
      data: {
        id: uuidv7(),
        userId,
        roleKey: b.roleKey,
        scopeType: b.scopeType,
        scopeId: b.scopeId ?? null,
        createdById,
      },
    });
  }
}
