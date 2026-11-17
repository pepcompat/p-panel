export const PERMISSIONS = [
  'fleet.read',
  'servers.enroll',
  'servers.operate',
  'servers.revoke',
  'apps.read',
  'apps.deploy',
  'nginx.read',
  'nginx.write',
  'backups.create',
  'backups.restore',
  'policies.manage',
  'audit.read',
  'users.manage',
  'approvals.decide',
  'ssh.connect',
  'credentials.manage',
  'plugins.install',
  'db.manage',
  'ai.admin',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export const ROLE_KEYS = ['platform_owner', 'ops_admin', 'deployer', 'viewer'] as const;
export type RoleKey = (typeof ROLE_KEYS)[number];

export const BUILTIN_ROLES: Record<RoleKey, readonly Permission[]> = {
  platform_owner: PERMISSIONS,
  ops_admin: PERMISSIONS.filter((p) => p !== 'users.manage'),
  deployer: ['fleet.read', 'apps.read', 'apps.deploy', 'nginx.read'],
  viewer: ['fleet.read', 'apps.read', 'nginx.read', 'audit.read'],
};

export type ScopeType = 'global' | 'environment' | 'project' | 'server';
export interface RoleBinding {
  id: string;
  userId: string;
  roleKey: RoleKey;
  scopeType: ScopeType;
  scopeId?: string;
}
