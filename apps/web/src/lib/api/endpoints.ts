import type { CreateEnrollmentInput, EnrollmentCreated, Server } from '@ppanel/shared-contracts';
import { api } from './index';
import type { Query } from './client';
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
