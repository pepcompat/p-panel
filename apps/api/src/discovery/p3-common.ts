import type {
  Application,
  ApplicationAction,
  ApplicationKind,
  OwnershipMode,
  Permission,
} from '@ppanel/shared-contracts';
import { OWNERSHIP_MODES } from '@ppanel/shared-contracts';
import type { Application as AppRow } from '@prisma/client';
import type { AuthzService, ResourceScope } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import type { AuthUser } from '../common/principal';
import type { NginxFileEntry } from '../nginx/nginx-plan';

export type AppWithServer = AppRow & {
  server: { id: string; environment: string; status: string };
};

export const appInclude = { server: { select: { id: true, environment: true, status: true } } };

export function serverScope(s: { id: string; environment: string }): ResourceScope {
  return { serverId: s.id, environment: s.environment };
}

/** Out-of-scope reads look like 404 (no existence oracle); then the specific permission is enforced (audited). */
export async function enforceOnServer(
  authz: AuthzService,
  user: AuthUser,
  server: { id: string; environment: string },
  visibility: Permission,
  perm: Permission | null,
  audit: { action: string; targetType: string; targetId: string },
  what: string,
): Promise<void> {
  const scope = serverScope(server);
  if (!authz.can(user, visibility, scope)) throw AppError.notFound(what);
  if (perm) await authz.enforce(user, perm, scope, audit);
}

export function nginxFilesOf(row: { nginxFiles: unknown }): NginxFileEntry[] {
  return Array.isArray(row.nginxFiles) ? (row.nginxFiles as NginxFileEntry[]) : [];
}

export interface DriftFile {
  path: string;
  lastKnownSha256: string | null;
  currentSha256: string;
  /** when the Center recorded this drift (ISO) */
  detectedAt?: string;
}
export function driftFilesOf(row: { driftFiles: unknown }): DriftFile[] {
  return Array.isArray(row.driftFiles) ? (row.driftFiles as DriftFile[]) : [];
}

export function modeIndex(m: string): number {
  return OWNERSHIP_MODES.indexOf(m as OwnershipMode);
}

const MODE_ACTION: Record<OwnershipMode, ApplicationAction> = {
  discovered: 'discover',
  observed: 'observe',
  adopted: 'adopt',
  managed: 'manage',
};

/** Permission needed to move to `to` from `from` (one step). */
export function ownershipPermission(from: OwnershipMode, to: OwnershipMode): Permission {
  const upgrade = modeIndex(to) > modeIndex(from);
  return upgrade && (to === 'adopted' || to === 'managed') ? 'nginx.write' : 'servers.operate';
}

export function allowedActionsFor(
  authz: AuthzService,
  user: AuthUser,
  row: AppWithServer,
  hasOpenRevision: boolean,
): ApplicationAction[] {
  if (row.server.status === 'revoked') return [];
  const scope = serverScope(row.server);
  const mode = row.ownershipMode as OwnershipMode;
  const i = modeIndex(mode);
  const out: ApplicationAction[] = [];
  for (const j of [i - 1, i + 1]) {
    const to = OWNERSHIP_MODES[j];
    if (!to) continue;
    if (!authz.can(user, ownershipPermission(mode, to), scope)) continue;
    if (j > i && row.flagDriftDetected) continue;
    if (to === 'managed' && row.flagUnsupported) continue;
    out.push(MODE_ACTION[to]);
  }
  if (authz.can(user, 'nginx.read', scope)) out.push('read_files');
  const canWrite = authz.can(user, 'nginx.write', scope);
  if (
    canWrite &&
    (mode === 'adopted' || mode === 'managed') &&
    !row.flagDriftDetected &&
    !hasOpenRevision
  )
    out.push('create_revision');
  if (canWrite && row.flagDriftDetected) out.push('acknowledge_drift');
  return out;
}

export function toApplication(
  row: AppWithServer,
  allowedActions: ApplicationAction[],
): Application {
  return {
    id: row.id,
    serverId: row.serverId,
    name: row.name,
    environment: row.server.environment as Application['environment'],
    kind: row.kind as ApplicationKind,
    domains: row.domains,
    ownershipMode: row.ownershipMode as OwnershipMode,
    flags: {
      unsupported: row.flagUnsupported,
      conflict: row.flagConflict,
      manualReview: row.flagManualReview,
      driftDetected: row.flagDriftDetected,
    },
    reasons: row.reasons,
    unsupportedDirectives: row.unsupportedDirectives,
    sourceFindingFingerprint: row.sourceFindingFingerprint,
    nginxFiles: nginxFilesOf(row).map((f) => ({
      path: f.path,
      lastKnownSha256: f.lastKnownSha256,
      ...(f.resolvedPath ? { resolvedPath: f.resolvedPath } : {}),
    })),
    driftFiles: driftFilesOf(row),
    lastScanId: row.lastScanId,
    allowedActions,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}
