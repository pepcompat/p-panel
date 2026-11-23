/** P4b endpoints (docs/API_CONTRACTS.md §8). */
import { api } from './index';
import type { Application } from './p3-types';
import type { Deployment } from './p4-types';
import { normalizePreflight } from './p4-endpoints';
import type {
  Build,
  BuildConfig,
  BuildConfigInput,
  BuildLog,
  CreateBuildInput,
  ComposeCurrent,
  CreateComposeAppInput,
  GitAuthView,
  SourceInspection,
  UpdateComposeInput,
} from './p4b-types';
import { uuid } from '../utils';

const enc = encodeURIComponent;
const stepUp = (token?: string) => (token ? { 'X-Step-Up': token } : undefined);

function unwrap<T>(r: unknown, key: string): T {
  const o = r as Record<string, unknown> | null;
  return (o && typeof o === 'object' && o[key] ? o[key] : o) as T;
}

export const buildConfigApi = {
  get: (appId: string) => api.get<BuildConfig | null>(`/applications/${enc(appId)}/build-config`),
  /** `version` = stored config version (If-Match); omitted on first save. */
  put: (appId: string, body: BuildConfigInput, version?: number) =>
    api
      .request<BuildConfig>('PUT', `/applications/${enc(appId)}/build-config`, {
        body,
        headers: version !== undefined ? { 'If-Match': String(version) } : undefined,
      })
      .then((r) => r.data),
  gitAuth: (appId: string) => api.get<GitAuthView | null>(`/applications/${enc(appId)}/git-auth`),
  putGitAuth: (appId: string, token: string, stepUpToken?: string) =>
    api
      .request<GitAuthView>('PUT', `/applications/${enc(appId)}/git-auth`, {
        body: { token },
        headers: stepUp(stepUpToken),
      })
      .then((r) => r.data),
};

export const buildsApi = {
  list: (appId: string) =>
    api.list<Build>(`/applications/${enc(appId)}/builds`, { query: { limit: 100 } }),
  get: (id: string) => api.get<Build>(`/builds/${enc(id)}`),
  log: (id: string) => api.get<BuildLog>(`/builds/${enc(id)}/log`),
  cancel: (id: string) =>
    api
      .post<{ build: Build } | Build>(`/builds/${enc(id)}/cancel`)
      .then((r) => unwrap<Build>(r, 'build')),
  /** 202 `{ build }`, or 200 `{ build, reused: true }` (same commit already built — no deployment). */
  create: (appId: string, body: CreateBuildInput, idempotencyKey = uuid()) =>
    api
      .post<{ build: Build; reused?: boolean } | Build>(
        `/applications/${enc(appId)}/builds`,
        body,
        {
          headers: { 'Idempotency-Key': idempotencyKey },
        },
      )
      .then((r) => ({
        build: unwrap<Build>(r, 'build'),
        reused: !!(r as { reused?: boolean }).reused,
      })),
  /**
   * Runs `source.inspect` on the build node. The Center may answer `pending` (agent job still
   * running); then poll `GET …/source/inspect/:inspectionId` (assumed path) until it settles.
   */
  async inspect(
    appId: string,
    commitSha: string,
    opts: { pollMs?: number; maxPolls?: number } = {},
  ) {
    let r = await api.post<SourceInspection>(`/applications/${enc(appId)}/source/inspect`, {
      commitSha,
    });
    for (let i = 0; r.status === 'pending' && i < (opts.maxPolls ?? 60); i++) {
      await new Promise((res) => setTimeout(res, opts.pollMs ?? 1000));
      r = await api.get<SourceInspection>(
        `/applications/${enc(appId)}/source/inspect/${enc(r.inspectionId)}`,
      );
    }
    return r;
  },
};

export const composeApi = {
  /** Current (or `version`) compose version incl. YAML (ComposeAppConfig has no YAML). */
  current: (appId: string, version?: number) =>
    api.get<ComposeCurrent>(`/applications/${enc(appId)}/compose`, {
      query: version ? { version } : undefined,
    }),
  create: (input: CreateComposeAppInput) => api.post<Application>('/applications', input),
  update: (appId: string, body: UpdateComposeInput, version: number) =>
    api
      .request<Application>('PUT', `/applications/${enc(appId)}/compose`, {
        body,
        headers: { 'If-Match': String(version) },
      })
      .then((r) => r.data),
  /** Deploy the latest (or a given) compose version — no image in the body. */
  deploy: (
    appId: string,
    body: { composeVersion?: number; reason?: string },
    idempotencyKey = uuid(),
  ) =>
    api
      .post<{ deployment: Deployment } | Deployment>(
        `/applications/${enc(appId)}/deployments`,
        body,
        {
          headers: { 'Idempotency-Key': idempotencyKey },
        },
      )
      .then((r) => unwrap<Deployment>(r, 'deployment')),
};

/** Preflight without an image: Git source (digest comes from the build) and compose (§8). */
export async function preflightPlan(appId: string) {
  return normalizePreflight(
    await api.post<unknown>(`/applications/${enc(appId)}/deployments/preflight`, {}),
  );
}
