/**
 * P4a read models (docs/API_CONTRACTS.md §7). Source of truth: `@ppanel/shared-contracts` (deploy.ts,
 * compose.ts, detect.ts, owned by the API agent). This file re-exports them and adds the few optional,
 * web-requested display fields (marked "web-requested"); the UI never depends on them being present.
 */
import type {
  ContainerAppConfig,
  Deployment as SharedDeployment,
  DeploymentStatus,
  ManagedRouting as SharedManagedRouting,
  WebhookDelivery as SharedDelivery,
} from '@ppanel/shared-contracts';
import {
  DEPLOYMENT_ACTIVE_STATUSES,
  DEPLOYMENT_CANCELLABLE_STATUSES,
} from '@ppanel/shared-contracts';

export {
  DEPLOYMENT_STATUSES,
  DEPLOYMENT_STEP_NAMES,
  DEPLOYMENT_TRIGGERS,
  ENV_KEY_RE,
  FRAMEWORKS,
  HOSTNAME_RE,
  IMAGE_DIGEST_REF_RE,
  PREFLIGHT_CHECKS,
  TLS_PATH_RE,
  IMAGE_TEMPLATE_RE,
  BRANCH_PATTERN_RE,
  COMPOSE_RULES,
  detectFramework,
  isValidHostname,
  isDigestPinned,
} from '@ppanel/shared-contracts';
export type {
  AutoDeployPolicy,
  AutoDeployPolicyInput,
  ComposeValidation,
  ComposeViolation,
  ContainerLogs,
  CreateContainerAppInput,
  DeploymentStatus,
  DeploymentStep,
  DeploymentStepName as StepName,
  DeploymentStepStatus as StepStatus,
  DeploymentTrigger,
  DetectResult,
  Framework,
  Integration,
  PreflightCheck,
  PreflightCheckName,
  RegistryAuthView,
  SecretSummary,
} from '@ppanel/shared-contracts';

/** Container config + web-requested runtime display fields. */
export type ContainerSpec = ContainerAppConfig & {
  /** web-requested: image digest ref of the current deployment. */
  image?: string | null;
  /** web-requested: running state of the current container. */
  runtimeState?: 'running' | 'stopped' | 'unknown';
};

/** Work in progress — poll every second. (`awaiting_approval` is active for locking, not polling.) */
export const DEPLOYMENT_ACTIVE: readonly DeploymentStatus[] = DEPLOYMENT_ACTIVE_STATUSES.filter(
  (s) => s !== 'awaiting_approval',
);
export const DEPLOYMENT_LOCKING: readonly DeploymentStatus[] = DEPLOYMENT_ACTIVE_STATUSES;
/** Cancel only before route_switch (§7.3). */
export const DEPLOYMENT_CANCELLABLE: readonly DeploymentStatus[] = DEPLOYMENT_CANCELLABLE_STATUSES;

export type Deployment = Omit<SharedDeployment, 'allowedActions' | 'version' | 'updatedAt'> & {
  /** Contract field; tolerated missing (older Center builds). */
  allowedActions?: SharedDeployment['allowedActions'];
  version?: number;
  updatedAt?: string;
  approval: SharedDeployment['approval'] & {
    /** web-requested */
    approvedByLabel?: string | null;
  };
  /** web-requested display fields */
  applicationName?: string;
  serverName?: string;
  environment?: 'production' | 'uat' | 'development';
  createdByLabel?: string | null;
  domains?: string[];
};

export type ManagedRouting = Partial<Omit<SharedManagedRouting, 'enabled' | 'revisionId'>> &
  Pick<SharedManagedRouting, 'enabled' | 'revisionId'>;

export type WebhookDelivery = SharedDelivery;

/** Normalised preflight response (the contract names the checks list but not the envelope). */
export interface PreflightResult {
  checks: import('@ppanel/shared-contracts').PreflightCheck[];
  approvalRequired?: boolean;
  planHash?: string;
}
