import type { RoleKey, ScopeType } from '@ppanel/shared-contracts';

export interface BindingRow {
  id: string;
  userId: string;
  roleKey: string;
  scopeType: string;
  scopeId: string | null;
}

export interface AuthUser {
  id: string;
  email: string;
  sessionId: string;
  amr: string[];
  bindings: BindingRow[];
}

export function toRoleBinding(b: BindingRow) {
  return {
    id: b.id,
    userId: b.userId,
    roleKey: b.roleKey as RoleKey,
    scopeType: b.scopeType as ScopeType,
    ...(b.scopeId ? { scopeId: b.scopeId } : {}),
  };
}
