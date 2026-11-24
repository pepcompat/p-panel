/**
 * P10 endpoints (docs/P10_SSH_CONTRACT.md). Private keys are write-only: `createCredential` with
 * mode 'import' is the only call that carries one, and the caller passes it straight through (never via
 * React state, the query cache or a mutation's `variables`).
 */
import { api } from './index';
import type { Query } from './client';
import type {
  CreateCredentialInput,
  CreateGrantInput,
  SessionTicket,
  SshCredential,
  SshEndpoint,
  SshGrant,
  SshHostKey,
  SshPath,
  SshSession,
} from './p10-types';

const enc = encodeURIComponent;
const stepUp = (token?: string) => (token ? { 'X-Step-Up': token } : undefined);

export const sshCredentialsApi = {
  list: () =>
    api.list<SshCredential>('/ssh/credentials', { query: { limit: 100 } }).then((r) => r.items),
  /** Step-up always. Import: 422 SSH_KEY_ENCRYPTED / SSH_KEY_UNSUPPORTED, 413 over 16 KiB. */
  create: (body: CreateCredentialInput, stepUpToken: string) =>
    api.post<SshCredential>('/ssh/credentials', body, { headers: stepUp(stepUpToken) }),
  /** 202 { jobId } */
  deploy: (id: string, body: { serverId: string; sshUser: string }) =>
    api.post<{ jobId: string }>(`/ssh/credentials/${enc(id)}/deploy`, body),
  /** 202 */
  removeDeployment: (id: string, deploymentId: string) =>
    api.del<unknown>(`/ssh/credentials/${enc(id)}/deployments/${enc(deploymentId)}`),
  rotate: (id: string, stepUpToken: string) =>
    api.post<SshCredential>(`/ssh/credentials/${enc(id)}/rotate`, undefined, {
      headers: stepUp(stepUpToken),
    }),
  revoke: (id: string, stepUpToken: string) =>
    api.post<SshCredential>(`/ssh/credentials/${enc(id)}/revoke`, undefined, {
      headers: stepUp(stepUpToken),
    }),
};

export const sshEndpointsApi = {
  list: (serverId: string) => api.get<SshEndpoint[]>(`/servers/${enc(serverId)}/ssh/endpoints`),
  /** 422 SSH_ENDPOINT_UNVERIFIED (host not a known address of that scope) / SSH_ROOT_FORBIDDEN. */
  put: (serverId: string, endpoints: SshEndpoint[]) =>
    api
      .request<SshEndpoint[]>('PUT', `/servers/${enc(serverId)}/ssh/endpoints`, {
        body: endpoints,
      })
      .then((r) => r.data),
};

export const sshHostKeysApi = {
  list: (serverId: string) => api.get<SshHostKey[]>(`/servers/${enc(serverId)}/ssh/host-keys`),
  scan: (serverId: string, path: SshPath) =>
    api.post<SshHostKey[]>(`/servers/${enc(serverId)}/ssh/host-keys/scan`, { path }),
  /** Step-up always (never TOFU). */
  trust: (id: string, stepUpToken: string) =>
    api.post<SshHostKey>(`/ssh/host-keys/${enc(id)}/trust`, undefined, {
      headers: stepUp(stepUpToken),
    }),
  reject: (id: string) => api.post<SshHostKey>(`/ssh/host-keys/${enc(id)}/reject`),
};

export const sshGrantsApi = {
  list: (query?: Query) =>
    api.list<SshGrant>('/ssh/grants', { query: { limit: 100, ...query } }).then((r) => r.items),
  /** 422 SSH_NO_CREDENTIAL when no installed deployment of an active key exists for (server, user). */
  create: (body: CreateGrantInput) => api.post<SshGrant>('/ssh/grants', body),
  /** approvals.decide + step-up; 403 SELF_APPROVAL_FORBIDDEN; hash compare-and-set. */
  approve: (g: Pick<SshGrant, 'id' | 'grantHash'>, stepUpToken: string) =>
    api.post<SshGrant>(
      `/ssh/grants/${enc(g.id)}/approve`,
      { grantHash: g.grantHash },
      { headers: stepUp(stepUpToken) },
    ),
  reject: (id: string) => api.post<SshGrant>(`/ssh/grants/${enc(id)}/reject`),
  revoke: (id: string) => api.post<SshGrant>(`/ssh/grants/${enc(id)}/revoke`),
};

export const sshSessionsApi = {
  list: (query?: Query) =>
    api.list<SshSession>('/ssh/sessions', { query: { limit: 100, ...query } }).then((r) => r.items),
  /**
   * 201 with a single-use ticket. Production needs a recent step-up (X-Step-Up). 429 SSH_SESSION_LIMIT,
   * 403 SSH_GRANT_INVALID. Callers must not cache the result (no useQuery/useMutation state).
   */
  create: (body: { grantId: string; cols: number; rows: number }, stepUpToken?: string) =>
    api.post<SessionTicket>('/ssh/sessions', body, { headers: stepUp(stepUpToken) }),
  terminate: (id: string) => api.post<SshSession>(`/ssh/sessions/${enc(id)}/terminate`),
};
