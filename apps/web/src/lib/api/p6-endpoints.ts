/** P6 endpoints (docs/API_CONTRACTS.md §10). Secrets are never sent back except the recovery export. */
import { api } from './index';
import type {
  BackupPolicy,
  BackupPolicyInput,
  BackupRepository,
  BackupRun,
  BackupRunDetail,
  CreateRestoreInput,
  RecoveryExport,
  Restore,
  SnapshotList,
} from './p6-types';

const enc = encodeURIComponent;
const stepUp = (token?: string) => (token ? { 'X-Step-Up': token } : undefined);
const idem = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`;

export const repositoriesApi = {
  list: () =>
    api
      .list<BackupRepository>('/backup-repositories', { query: { limit: 100 } })
      .then((r) => r.items),
  markInitialized: (id: string, serverId: string) =>
    api.post<BackupRepository>(
      `/backup-repositories/${enc(id)}/servers/${enc(serverId)}/initialized`,
    ),
  /** Returns the repo passwords once (step-up). Never cache the result. */
  recoveryExport: (id: string, stepUpToken: string) =>
    api.get<RecoveryExport>(`/backup-repositories/${enc(id)}/recovery-export`, {
      headers: stepUp(stepUpToken),
    }),
};

export interface PolicyFilters {
  server_id?: string;
}
export const policiesApi = {
  list: (f: PolicyFilters = {}) =>
    api
      .list<BackupPolicy>('/backup-policies', { query: { limit: 100, ...f } })
      .then((r) => r.items),
  get: (id: string) => api.get<BackupPolicy>(`/backup-policies/${enc(id)}`),
  create: (body: BackupPolicyInput) => api.post<BackupPolicy>('/backup-policies', body),
  update: (id: string, body: Partial<BackupPolicyInput>, version: number) =>
    api
      .request<BackupPolicy>('PATCH', `/backup-policies/${enc(id)}`, {
        body,
        headers: { 'If-Match': String(version) },
      })
      .then((r) => r.data),
  remove: (id: string, version: number) =>
    api.del(`/backup-policies/${enc(id)}`, { headers: { 'If-Match': String(version) } }),
  /** 202 { run } */
  runNow: (id: string, idempotencyKey = idem()) =>
    api
      .post<{ run: BackupRun; reused?: boolean }>(`/backup-policies/${enc(id)}/run`, undefined, {
        headers: { 'Idempotency-Key': idempotencyKey },
      })
      .then((r) => r.run),
};

export interface RunFilters {
  policy_id?: string;
  status?: string;
  server_id?: string;
}
export const runsApi = {
  list: (f: RunFilters = {}) =>
    api.list<BackupRun>('/backup-runs', { query: { limit: 100, ...f } }).then((r) => r.items),
  get: (id: string, page = 1, limit = 20) =>
    api.get<BackupRunDetail>(`/backup-runs/${enc(id)}`, {
      query: { manifestPage: page, manifestLimit: limit },
    }),
  verify: (id: string, level: 'check' | 'restore_test') =>
    api.post<BackupRun>(`/backup-runs/${enc(id)}/verify`, { level }),
};

export const snapshotsApi = {
  list: (serverId: string) => api.get<SnapshotList>(`/servers/${enc(serverId)}/snapshots`),
};

export const restoresApi = {
  list: (f: { status?: string; server_id?: string; run_id?: string } = {}) =>
    api.list<Restore>('/restores', { query: { limit: 100, ...f } }).then((r) => r.items),
  get: (id: string) => api.get<Restore>(`/restores/${enc(id)}`),
  create: (body: CreateRestoreInput) => api.post<Restore>('/restores', body),
  /** 202 → dry_run step running; the restore moves to impact_reviewed / awaiting_approval. */
  dryRun: (id: string) => api.post<Restore>(`/restores/${enc(id)}/dry-run`),
  approve: (id: string, planHash: string, stepUpToken: string) =>
    api.post<Restore>(
      `/restores/${enc(id)}/approve`,
      { planHash },
      { headers: stepUp(stepUpToken) },
    ),
  /** The in_place impact confirmation is enforced in the UI (the API has no field for it yet). */
  execute: (id: string, confirmImpact = false) =>
    api.post<Restore>(`/restores/${enc(id)}/execute`, confirmImpact ? { confirmImpact: true } : {}),
  cancel: (id: string) => api.post<Restore>(`/restores/${enc(id)}/cancel`),
};
