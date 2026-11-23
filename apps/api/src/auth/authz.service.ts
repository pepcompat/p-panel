import { Injectable } from '@nestjs/common';
import { BUILTIN_ROLES, type Permission, type RoleKey } from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AppError } from '../common/app-error';
import type { AuthUser, BindingRow } from '../common/principal';
import { AuditService } from '../audit/audit.service';

export interface ResourceScope {
  environment?: string;
  serverId?: string;
  projectId?: string;
}

export function rolePermissions(roleKey: string): readonly Permission[] {
  return BUILTIN_ROLES[roleKey as RoleKey] ?? [];
}

/** Does `binding` cover the target? global ⊇ environment ⊇ server; project only covers project resources. */
export function bindingCovers(b: BindingRow, target: ResourceScope | undefined): boolean {
  if (b.scopeType === 'global') return true;
  if (!target) return false;
  switch (b.scopeType) {
    case 'environment':
      return target.environment !== undefined && target.environment === b.scopeId;
    case 'server':
      return target.serverId !== undefined && target.serverId === b.scopeId;
    case 'project':
      return target.projectId !== undefined && target.projectId === b.scopeId;
    default:
      return false;
  }
}

@Injectable()
export class AuthzService {
  constructor(private readonly audit: AuditService) {}

  permissionsOf(bindings: BindingRow[]): Permission[] {
    const set = new Set<Permission>();
    for (const b of bindings) for (const p of rolePermissions(b.roleKey)) set.add(p);
    return [...set].sort();
  }

  hasAnywhere(user: AuthUser, perm: Permission): boolean {
    return user.bindings.some((b) => rolePermissions(b.roleKey).includes(perm));
  }

  /** `target` undefined means a global (unscoped) resource → only global bindings qualify. */
  can(user: AuthUser, perm: Permission, target?: ResourceScope): boolean {
    return user.bindings.some(
      (b) => rolePermissions(b.roleKey).includes(perm) && bindingCovers(b, target),
    );
  }

  /** Enforce a scoped permission; denied attempts are audited. */
  async enforce(
    user: AuthUser,
    perm: Permission,
    target: ResourceScope | undefined,
    audit: { action: string; targetType?: string; targetId?: string | null },
  ): Promise<void> {
    if (this.can(user, perm, target)) return;
    await this.audit.record({
      actorId: user.id,
      action: audit.action,
      targetType: audit.targetType,
      targetId: audit.targetId ?? null,
      result: 'denied',
      metadata: {
        permission: perm,
        ...(target?.environment ? { environment: target.environment } : {}),
      },
    });
    throw AppError.forbidden();
  }

  /** Prisma `where` restricting servers to those the user may `perm`. null = no access at all. */
  serverWhere(user: AuthUser, perm: Permission): Prisma.ServerWhereInput | null {
    const relevant = user.bindings.filter((b) => rolePermissions(b.roleKey).includes(perm));
    if (relevant.length === 0) return null;
    if (relevant.some((b) => b.scopeType === 'global')) return {};
    const envs = relevant.filter((b) => b.scopeType === 'environment').map((b) => b.scopeId!);
    const ids = relevant.filter((b) => b.scopeType === 'server').map((b) => b.scopeId!);
    const or: Prisma.ServerWhereInput[] = [];
    if (envs.length) or.push({ environment: { in: envs } });
    if (ids.length) or.push({ id: { in: ids } });
    return or.length ? { OR: or } : null;
  }

  /** Environments in which the user holds `perm` (for enrollment listing). 'all' when global. */
  environmentsFor(user: AuthUser, perm: Permission): string[] | 'all' {
    const relevant = user.bindings.filter((b) => rolePermissions(b.roleKey).includes(perm));
    if (relevant.some((b) => b.scopeType === 'global')) return 'all';
    return relevant.filter((b) => b.scopeType === 'environment').map((b) => b.scopeId!);
  }
}
