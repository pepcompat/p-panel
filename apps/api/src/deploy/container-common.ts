/** Shared container-app helpers (pure): read model, allowedActions, plan hash, names. */
import {
  type ApplicationAction,
  type ContainerAppConfig,
  containerHealthcheckSchema,
  containerResourcesSchema,
} from '@ppanel/shared-contracts';
import type { ContainerApp as ContainerAppRow } from '@prisma/client';
import type { AuthzService } from '../auth/authz.service';
import { sha256Hex, stableHash, stableStringify } from '../common/crypto';
import type { AuthUser } from '../common/principal';
import type { AppWithServer } from '../discovery/p3-common';
import { serverScope } from '../discovery/p3-common';
import { routePath } from './route-template';

export type { ContainerAppRow };

export interface ContainerRuntimeState {
  current: { containerName: string | null; hostPort: number | null } | null;
  rollbackAvailable: boolean;
  hasActiveDeployment: boolean;
}

export function healthcheckOf(c: ContainerAppRow) {
  return containerHealthcheckSchema.parse(c.healthcheck ?? {});
}
export function resourcesOf(c: ContainerAppRow) {
  return containerResourcesSchema.parse(c.resources ?? {});
}
export function envOf(c: ContainerAppRow): Record<string, string> {
  return (c.env ?? {}) as Record<string, string>;
}
export function volumesOf(c: ContainerAppRow): Array<{ name: string; mountPath: string }> {
  return Array.isArray(c.volumes) ? (c.volumes as Array<{ name: string; mountPath: string }>) : [];
}
export function tlsOf(c: ContainerAppRow): { certPath: string; keyPath: string } | null {
  return (c.tls as { certPath: string; keyPath: string } | null) ?? null;
}

export function toContainerConfig(
  name: string,
  c: ContainerAppRow,
  state: ContainerRuntimeState,
): ContainerAppConfig {
  return {
    containerPort: c.containerPort,
    healthcheck: healthcheckOf(c),
    resources: resourcesOf(c),
    env: envOf(c),
    secretKeys: c.secretKeys,
    volumes: volumesOf(c),
    tls: tlsOf(c),
    currentDeploymentId: c.currentDeploymentId,
    previousDeploymentId: c.previousDeploymentId,
    hostPort: state.current?.hostPort ?? null,
    containerName: state.current?.containerName ?? null,
    routePath: routePath(name),
    rollbackAvailable: state.rollbackAvailable,
  };
}

/** Per-application actions for container apps (UI derives button state from these). */
export function containerActions(
  authz: AuthzService,
  user: AuthUser,
  row: AppWithServer,
  state: ContainerRuntimeState,
): ApplicationAction[] {
  if (row.server.status === 'revoked') return [];
  const scope = serverScope(row.server);
  const out: ApplicationAction[] = [];
  if (authz.can(user, 'nginx.read', scope) && row.nginxFiles && Array.isArray(row.nginxFiles))
    if ((row.nginxFiles as unknown[]).length > 0) out.push('read_files');
  if (authz.can(user, 'nginx.write', scope) && row.flagDriftDetected) out.push('acknowledge_drift');
  const hasCurrent = !!state.current?.containerName;
  if (hasCurrent && authz.can(user, 'apps.read', scope)) out.push('view_logs');
  if (!authz.can(user, 'apps.deploy', scope)) return out;
  out.push('manage_secrets', 'edit_container');
  if (authz.can(user, 'policies.manage', scope)) out.push('manage_auto_deploy');
  if (!state.hasActiveDeployment) {
    out.push('deploy');
    if (hasCurrent) out.push('redeploy', 'restart', 'start', 'stop');
    if (state.rollbackAvailable) out.push('rollback');
  }
  return out;
}

/** `ppanel-<app>-<8 hex>`: the random tail of the deployment id (uuidv7 head is a timestamp). */
export function containerNameFor(app: string, deploymentId: string): string {
  return `ppanel-${app}-${deploymentId.replace(/-/g, '').slice(-8)}`;
}

export interface PlanInput {
  applicationId: string;
  serverId: string;
  image: string;
  trigger: string;
  /** rollback: restored container */
  targetContainer?: string | null;
  container: ContainerAppRow;
  domains: string[];
  /** secret key → version (values never enter the plan) */
  secretVersions: Record<string, number>;
}

/** planHash = sha256(applicationId, serverId, image digest, container config hash, route config hash). */
export function deploymentPlanHash(p: PlanInput): string {
  const c = p.container;
  const containerConfigHash = stableHash({
    containerPort: c.containerPort,
    healthcheck: healthcheckOf(c),
    resources: resourcesOf(c),
    env: envOf(c),
    secretKeys: [...c.secretKeys].sort(),
    secretVersions: p.secretVersions,
    volumes: volumesOf(c),
    trigger: p.trigger,
    targetContainer: p.targetContainer ?? null,
  });
  const routeConfigHash = stableHash({ domains: [...p.domains].sort(), tls: tlsOf(c) });
  return sha256Hex(
    stableStringify({
      applicationId: p.applicationId,
      serverId: p.serverId,
      image: p.image,
      containerConfigHash,
      routeConfigHash,
    }),
  );
}
