/**
 * P4b read models (docs/API_CONTRACTS.md §8). Source of truth: `@ppanel/shared-contracts` (build.ts,
 * jobs.ts, deploy.ts, owned by the API agent). This file re-exports them and adds the few optional,
 * web-requested display fields (marked "web-requested"); the UI never depends on them being present.
 */
import type { z } from 'zod';
import type {
  Build as SharedBuild,
  ComposeAppConfig as SharedComposeAppConfig,
  ComposePlanService,
  SourceInspection as SharedSourceInspection,
  buildConfigSchema,
  createBuildSchema,
} from '@ppanel/shared-contracts';

export {
  AUTO_DEPLOY_MODES,
  BUILD_ACTIVE_STATUSES,
  BUILD_LOG_MAX_LINES,
  BUILD_STATUSES,
  COMMIT_SHA_RE,
  COMPOSE_SERVICE_NAME_RE,
  DOCKERFILE_TEMPLATES,
  GIT_URL_RE,
  IMAGE_REPO_RE,
  SOURCE_INSPECT_FILES,
} from '@ppanel/shared-contracts';
export type {
  ApplicationBuildSummary,
  AutoDeployMode,
  BuildAction,
  BuildConfig,
  BuildLog,
  BuildStatus,
  BuildTrigger,
  ComposePlanService,
  ComposeServiceAction,
  CreateComposeAppInput,
  DeploymentCompose,
  UpdateComposeInput,
} from '@ppanel/shared-contracts';

import type { BuildStatus } from '@ppanel/shared-contracts';

export type DockerfileTemplate = 'nextjs' | 'nestjs' | 'laravel';

/** `PUT /applications/:id/build-config` body (defaults applied by the Center). */
export type BuildConfigInput = z.input<typeof buildConfigSchema>;
/** `POST /applications/:id/builds` body. */
export type CreateBuildInput = z.input<typeof createBuildSchema>;

export const BUILD_ACTIVE: readonly BuildStatus[] = ['queued', 'fetching', 'building', 'pushing'];
/**
 * Phases shown as live states. The Center reports queued → building → terminal only (no progress
 * channel for fetch/push); `fetching` / `pushing` are folded into `building` if they ever appear.
 */
export const BUILD_PHASES = ['queued', 'building'] as const;
export type BuildPhase = (typeof BUILD_PHASES)[number];

export type Build = SharedBuild & {
  /** web-requested display fields */
  buildServerName?: string;
  createdByLabel?: string | null;
  deploymentNumber?: number | null;
};

export interface GitAuthView {
  set: boolean;
  /** web-requested */
  updatedAt?: string | null;
}

/** `POST /applications/:id/source/inspect` → may be `pending` (poll), then `succeeded` / `failed`. */
export type SourceInspection = SharedSourceInspection;

/** Display form of a compose health check (shared `ComposeHealth` carries timing fields too). */
export type ComposeHealthView =
  | { type: 'http'; port: number; path: string }
  | { type: 'tcp'; port: number }
  | { type: 'running' };

export type ComposeServiceView = ComposePlanService & {
  /** web-requested: running state reported by the agent. */
  state?: 'running' | 'stopped' | 'exited' | 'unknown';
  /** web-requested */
  containerName?: string | null;
};

/** Compose config on a compose application + web-requested runtime/display fields. */
export type ComposeAppConfig = Omit<SharedComposeAppConfig, 'services'> & {
  services: ComposeServiceView[];
  /** web-requested: YAML of the current version (else fetched via GET …/compose). */
  yaml?: string;
  /** web-requested: aggregated running state (stopped after `stop`). */
  runtimeState?: 'running' | 'stopped' | 'unknown';
};

/** `GET /applications/:id/compose?version=`: a version incl. its YAML. */
export type ComposeCurrent = ComposeAppConfig & { yaml: string };
