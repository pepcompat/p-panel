import type { UserPublic } from '@ppanel/shared-contracts';

export function toUserPublic(
  u: { id: string; email: string; displayName: string; status: string; lastLoginAt: Date | null; createdAt: Date; updatedAt: Date },
  mfaEnabled: boolean,
): UserPublic {
  return {
    id: u.id,
    email: u.email,
    displayName: u.displayName,
    status: u.status === 'disabled' ? 'disabled' : 'active',
    mfaEnabled,
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
    updatedAt: u.updatedAt.toISOString(),
  };
}
