/** P4a endpoints (docs/API_CONTRACTS.md §7). */
import { api } from './index';
import type { Query } from './client';
import type { Application } from './p3-types';
import type {
  AutoDeployPolicy,
  AutoDeployPolicyInput,
  ComposeValidation,
  ContainerLogs,
  CreateContainerAppInput,
  Deployment,
  DetectResult,
  Integration,
  ManagedRouting,
  PreflightCheck,
  PreflightResult,
  RegistryAuthView,
  SecretSummary,
  WebhookDelivery,
} from './p4-types';
import { uuid } from '../utils';

const enc = encodeURIComponent;
const stepUp = (token?: string) => (token ? { 'X-Step-Up': token } : undefined);
const MAX_LIMIT = 100;

/** The contract names the preflight list but not the envelope; accept an array or an object. */
export function normalizePreflight(raw: unknown): PreflightResult {
  if (Array.isArray(raw)) return { checks: raw as PreflightCheck[] };
  const r = (raw ?? {}) as Record<string, unknown>;
  const checks = (r.checks ?? r.preflight ?? []) as PreflightCheck[];
  return {
    checks: Array.isArray(checks) ? checks : [],
    approvalRequired: typeof r.approvalRequired === 'boolean' ? r.approvalRequired : undefined,
    planHash: typeof r.planHash === 'string' ? r.planHash : undefined,
  };
}

/** Preflight checks carried in an error's `details` (e.g. 409 DOMAIN_CONFLICT at app creation). */
export function checksFromDetails(details: unknown): PreflightCheck[] | null {
  if (!details) return null;
  const n = normalizePreflight(details);
  return n.checks.length && n.checks.every((c) => typeof c?.check === 'string') ? n.checks : null;
}

export const containerAppsApi = {
  create: (input: CreateContainerAppInput) => api.post<Application>('/applications', input),
  secrets: (id: string) => api.list<SecretSummary>(`/applications/${enc(id)}/secrets`),
  putSecret: (id: string, key: string, value: string, stepUpToken?: string) =>
    api
      .request<{ key: string; set: true; version: number }>(
        'PUT',
        `/applications/${enc(id)}/secrets/${enc(key)}`,
        { body: { value }, headers: stepUp(stepUpToken) },
      )
      .then((r) => r.data),
  deleteSecret: (id: string, key: string, stepUpToken?: string) =>
    api.del(`/applications/${enc(id)}/secrets/${enc(key)}`, { headers: stepUp(stepUpToken) }),
  registryAuth: (id: string) =>
    api.get<RegistryAuthView | null>(`/applications/${enc(id)}/registry-auth`),
  putRegistryAuth: (
    id: string,
    body: { serveraddress: string; username: string; password: string },
    stepUpToken?: string,
  ) =>
    api
      .request<RegistryAuthView>('PUT', `/applications/${enc(id)}/registry-auth`, {
        body,
        headers: stepUp(stepUpToken),
      })
      .then((r) => r.data),
  deployments: (id: string, query?: Query) =>
    api.list<Deployment>(`/applications/${enc(id)}/deployments`, {
      query: { limit: MAX_LIMIT, ...query },
    }),
  preflight: async (id: string, body: { image: string }) =>
    normalizePreflight(
      await api.post<unknown>(`/applications/${enc(id)}/deployments/preflight`, body),
    ),
  deploy: (
    id: string,
    body: { image: string; sourceRef?: Deployment['sourceRef']; reason?: string },
    idempotencyKey = uuid(),
  ) =>
    api
      .post<{ deployment: Deployment } | Deployment>(`/applications/${enc(id)}/deployments`, body, {
        headers: { 'Idempotency-Key': idempotencyKey },
      })
      .then(unwrapDeployment),
  rollback: (id: string, reason?: string) =>
    api
      .post<{ deployment: Deployment } | Deployment>(`/applications/${enc(id)}/rollback`, {
        reason,
      })
      .then(unwrapDeployment),
  redeploy: (id: string, reason?: string) =>
    api
      .post<{ deployment: Deployment } | Deployment>(`/applications/${enc(id)}/redeploy`, {
        reason,
      })
      .then(unwrapDeployment),
  restart: (id: string) => api.post<{ jobId?: string }>(`/applications/${enc(id)}/restart`),
  start: (id: string) => api.post<{ jobId?: string }>(`/applications/${enc(id)}/start`),
  stop: (id: string) => api.post<{ jobId?: string }>(`/applications/${enc(id)}/stop`),
  /** 200 → lines; 202 / status pending → container.logs job still running (caller polls). */
  async logs(id: string, tail: number): Promise<ContainerLogs> {
    const r = await api.request<Partial<ContainerLogs>>('GET', `/applications/${enc(id)}/logs`, {
      query: { tail },
    });
    const d = r.data ?? {};
    const pending = r.status === 202 || d.status === 'pending' || !Array.isArray(d.lines);
    return {
      jobId: d.jobId ?? '',
      status: pending ? 'pending' : 'succeeded',
      lines: Array.isArray(d.lines) ? d.lines : [],
      truncated: !!d.truncated,
      container: d.container ?? null,
    };
  },
  autoDeploy: (id: string) => api.list<AutoDeployPolicy>(`/applications/${enc(id)}/auto-deploy`),
  createAutoDeploy: (id: string, body: AutoDeployPolicyInput) =>
    api.post<AutoDeployPolicy>(`/applications/${enc(id)}/auto-deploy`, body),
  updateAutoDeploy: (
    id: string,
    policyId: string,
    body: Partial<Omit<AutoDeployPolicyInput, 'integrationId'>>,
  ) => api.patch<AutoDeployPolicy>(`/applications/${enc(id)}/auto-deploy/${enc(policyId)}`, body),
  deleteAutoDeploy: (id: string, policyId: string) =>
    api.del(`/applications/${enc(id)}/auto-deploy/${enc(policyId)}`),
};

function unwrapDeployment(r: { deployment: Deployment } | Deployment): Deployment {
  return 'deployment' in r && r.deployment ? r.deployment : (r as Deployment);
}

export const deploymentsApi = {
  list: (query?: Query) =>
    api.list<Deployment>('/deployments', { query: { limit: MAX_LIMIT, ...query } }),
  get: (id: string) => api.get<Deployment>(`/deployments/${enc(id)}`),
  cancel: (id: string) =>
    api
      .post<{ deployment: Deployment } | Deployment>(`/deployments/${enc(id)}/cancel`)
      .then(unwrapDeployment),
  approve: (id: string, planHash: string, stepUpToken?: string) =>
    api
      .post<{ deployment: Deployment } | Deployment>(
        `/deployments/${enc(id)}/approve`,
        { planHash },
        { headers: stepUp(stepUpToken) },
      )
      .then(unwrapDeployment),
};

export const managedRoutingApi = {
  get: (serverId: string) => api.get<ManagedRouting>(`/servers/${enc(serverId)}/managed-routing`),
  enable: (serverId: string, stepUpToken?: string) =>
    api.post<ManagedRouting>(`/servers/${enc(serverId)}/managed-routing`, undefined, {
      headers: stepUp(stepUpToken),
    }),
  /** Assumed endpoint (ManagedRouting.allowedActions includes `approve`; same rules as nginx). */
  approve: (serverId: string, planHash: string, stepUpToken?: string) =>
    api.post<ManagedRouting>(
      `/servers/${enc(serverId)}/managed-routing/approve`,
      { planHash },
      { headers: stepUp(stepUpToken) },
    ),
};

export const integrationsApi = {
  list: () => api.list<Integration>('/integrations'),
  /** GitHub App installation availability (BLOCKED in the lab: { available: false, reason }). */
  githubApp: () => api.get<{ available: boolean; reason?: string }>('/integrations/github/app'),
  create: (body: { name: string; webhookSecret: string }) =>
    api.post<Integration>('/integrations/github', body),
  deliveries: (id: string, query?: Query) =>
    api.list<WebhookDelivery>(`/integrations/github/${enc(id)}/deliveries`, {
      query: { limit: MAX_LIMIT, ...query },
    }),
};

export const deployToolsApi = {
  validateCompose: (yaml: string, environment?: string) =>
    api.post<ComposeValidation>('/deploy/compose/validate', { yaml, environment }),
  detect: (files: Record<string, string>) => api.post<DetectResult>('/deploy/detect', { files }),
};
