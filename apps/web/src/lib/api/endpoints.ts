import type {
  CreateEnrollmentInput,
  EnrollmentCreated,
  Job,
  Server,
} from '@ppanel/shared-contracts';
import { api } from './index';
import type { Query } from './client';
import type {
  Application,
  DiscoveryFinding,
  DiscoveryScan,
  DiscoverySource,
  ImportMode,
  NginxFileContent,
  NginxFilesResponse,
  NginxRevision,
  OwnershipChange,
  OwnershipMode,
  Postcheck,
} from './p3-types';
import type {
  AuditEvent,
  CreateRoleBindingInput,
  LoginResponse,
  LoginSuccess,
  MeResponse,
  ServerPatch,
  SetupStatus,
  StepUpResponse,
  TotpSetup,
  UserRecord,
} from './types';

export const authApi = {
  setupStatus: () => api.get<SetupStatus>('/setup/status', { auth: false }),
  bootstrap: (body: { email: string; password: string; displayName: string; setupToken: string }) =>
    api.post<{ user: unknown }>('/setup/bootstrap', body, { auth: false }),
  login: (body: { email: string; password: string }) =>
    api.post<LoginResponse>('/auth/login', body, { auth: false }),
  verifyMfa: (body: { mfaToken: string; code?: string; recoveryCode?: string }) =>
    api.post<LoginSuccess>('/auth/mfa/verify', body, { auth: false }),
  logout: () => api.post<void>('/auth/logout'),
  me: () => api.get<MeResponse>('/auth/me'),
  totpSetup: () => api.post<TotpSetup>('/auth/mfa/totp/setup'),
  totpConfirm: (code: string) =>
    api.post<{ recoveryCodes: string[] }>('/auth/mfa/totp/confirm', { code }),
  stepUp: (code: string) => api.post<StepUpResponse>('/auth/step-up', { code }),
};

const MAX_LIMIT = 100;

export const serversApi = {
  list: (query?: Query) => api.list<Server>('/servers', { query: { limit: MAX_LIMIT, ...query } }),
  /** Walks pages so fleet counts are never computed from a truncated page. */
  async listAll(query?: Query): Promise<{ items: Server[]; total: number }> {
    const items: Server[] = [];
    let page = 1;
    let total = 0;
    for (;;) {
      const res = await api.list<Server>('/servers', {
        query: { ...query, page, limit: MAX_LIMIT },
      });
      items.push(...res.items);
      total = res.paginate.total;
      if (items.length >= total || res.items.length === 0 || page >= 50) break;
      page += 1;
    }
    return { items, total };
  },
  get: (id: string) => api.get<Server>(`/servers/${encodeURIComponent(id)}`),
  patch: (id: string, body: ServerPatch, version: number) =>
    api.patch<Server>(`/servers/${encodeURIComponent(id)}`, body, {
      headers: { 'If-Match': String(version) },
    }),
  revoke: (id: string, stepUpToken?: string) =>
    api.post<Server>(`/servers/${encodeURIComponent(id)}/revoke`, undefined, {
      headers: stepUpToken ? { 'X-Step-Up': stepUpToken } : undefined,
    }),
};

export const enrollmentsApi = {
  create: (input: CreateEnrollmentInput) => api.post<EnrollmentCreated>('/enrollments', input),
};

export const usersApi = {
  list: (query?: Query) => api.list<UserRecord>('/users', { query }),
  addBinding: (userId: string, input: CreateRoleBindingInput) =>
    api.post<unknown>(`/users/${encodeURIComponent(userId)}/role-bindings`, input),
  removeBinding: (bindingId: string) => api.del(`/role-bindings/${encodeURIComponent(bindingId)}`),
};

export const auditApi = {
  list: (query?: Query) => api.list<AuditEvent>('/audit-events', { query }),
};

// ---------- P3: discovery, applications, Nginx revisions (API_CONTRACTS §6) ----------

const enc = encodeURIComponent;
const stepUpHeader = (token?: string) => (token ? { 'X-Step-Up': token } : undefined);

export const discoveryApi = {
  list: (query?: Query) =>
    api.list<DiscoveryScan>('/discovery-scans', { query: { limit: MAX_LIMIT, ...query } }),
  get: (id: string) => api.get<DiscoveryScan>(`/discovery-scans/${enc(id)}`),
  findings: (id: string, query?: Query) =>
    api.list<DiscoveryFinding>(`/discovery-scans/${enc(id)}/findings`, {
      query: { limit: MAX_LIMIT, ...query },
    }),
  run: (serverId: string, sources?: DiscoverySource[]) =>
    api.post<{ scanId: string; jobId: string }>(`/servers/${enc(serverId)}/discovery-scans`, {
      sources,
    }),
  import: (scanId: string, findingIds: string[], mode: ImportMode) =>
    api.post<{ applications: Application[] }>(`/discovery-scans/${enc(scanId)}/import`, {
      findingIds,
      mode,
    }),
};

export const applicationsApi = {
  list: (query?: Query) =>
    api.list<Application>('/applications', { query: { limit: MAX_LIMIT, ...query } }),
  get: (id: string) => api.get<Application>(`/applications/${enc(id)}`),
  changeOwnership: (
    app: Pick<Application, 'id' | 'version'>,
    body: { toMode: OwnershipMode; reason: string; acknowledgeReasons?: boolean },
    stepUpToken?: string,
  ) =>
    api.post<Application>(`/applications/${enc(app.id)}/ownership`, body, {
      headers: { 'If-Match': String(app.version), ...stepUpHeader(stepUpToken) },
    }),
  ownershipHistory: (id: string) =>
    api.list<OwnershipChange>(`/applications/${enc(id)}/ownership-history`),
  acknowledgeDrift: (id: string) =>
    api.post<Application>(`/applications/${enc(id)}/drift/acknowledge`),
  /** 200 → files; 202 → job still running (caller polls again). */
  async nginxFiles(id: string): Promise<NginxFilesResponse> {
    const r = await api.request<{ files?: NginxFileContent[]; jobId?: string; status?: string }>(
      'GET',
      `/applications/${enc(id)}/nginx/files`,
    );
    if (r.status === 202 || r.data?.status === 'pending' || !r.data?.files)
      return { state: 'pending', jobId: r.data?.jobId ?? '' };
    return { state: 'ready', files: r.data.files };
  },
  revisions: (id: string) =>
    api.list<NginxRevision>(`/applications/${enc(id)}/nginx/revisions`, {
      query: { limit: MAX_LIMIT },
    }),
  createRevision: (
    id: string,
    body: { files: Array<{ path: string; content: string }>; postchecks?: Postcheck[] },
  ) => api.post<NginxRevision>(`/applications/${enc(id)}/nginx/revisions`, body),
};

export const revisionsApi = {
  get: (id: string) => api.get<NginxRevision>(`/nginx-revisions/${enc(id)}`),
  validate: (id: string) => api.post<{ jobId: string }>(`/nginx-revisions/${enc(id)}/validate`),
  approve: (id: string, planHash: string, stepUpToken?: string) =>
    api.post<NginxRevision>(
      `/nginx-revisions/${enc(id)}/approve`,
      { planHash },
      { headers: stepUpHeader(stepUpToken) },
    ),
  apply: (id: string, stepUpToken?: string) =>
    api.post<{ jobId: string }>(`/nginx-revisions/${enc(id)}/apply`, undefined, {
      headers: stepUpHeader(stepUpToken),
    }),
  revert: (id: string, stepUpToken?: string) =>
    api.post<{ jobId: string }>(`/nginx-revisions/${enc(id)}/revert`, undefined, {
      headers: stepUpHeader(stepUpToken),
    }),
  cancel: (id: string) => api.post<NginxRevision>(`/nginx-revisions/${enc(id)}/cancel`),
};

export const jobsApi = {
  get: (serverId: string, jobId: string) =>
    api.get<Job>(`/servers/${enc(serverId)}/jobs/${enc(jobId)}`),
};
