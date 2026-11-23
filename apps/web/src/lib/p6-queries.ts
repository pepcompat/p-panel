'use client';

import { keepPreviousData, useQuery } from '@tanstack/react-query';
import {
  policiesApi,
  repositoriesApi,
  restoresApi,
  runsApi,
  snapshotsApi,
  type PolicyFilters,
  type RunFilters,
} from './api/p6-endpoints';
import { isApiError } from './api/errors';
import { RESTORE_TERMINAL, RUN_ACTIVE, type BackupRun, type Restore } from './api/p6-types';
import { useAuth } from './auth/auth-provider';
import { verifyingOf } from './p6-gates';

export const p6k = {
  repos: ['backup-repositories'] as const,
  policies: (f: PolicyFilters = {}) => ['backup-policies', f] as const,
  runs: (f: RunFilters = {}) => ['backup-runs', f] as const,
  run: (id: string, page: number) => ['backup-runs', 'one', id, page] as const,
  snapshots: (serverId: string) => ['snapshots', serverId] as const,
  restores: (f: { status?: string; server_id?: string } = {}) => ['restores', f] as const,
  restore: (id: string) => ['restores', 'one', id] as const,
};

const retry = (n: number, e: unknown) =>
  n < 1 && !(isApiError(e) && [401, 403, 404, 409, 422, 429].includes(e.status));

const busyRuns = (runs: readonly BackupRun[] | undefined) =>
  (runs ?? []).some((r) => RUN_ACTIVE.includes(r.status) || !!r.verifying);

export function useRepositories() {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.repos,
    queryFn: repositoriesApi.list,
    enabled: status === 'authenticated',
    retry,
  });
}

export function usePolicies(f: PolicyFilters = {}) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.policies(f),
    queryFn: () => policiesApi.list(f),
    enabled: status === 'authenticated',
    retry,
  });
}

/** Polls while any run is queued/running or being verified. */
export function useRuns(f: RunFilters = {}, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.runs(f),
    queryFn: () => runsApi.list(f),
    enabled: status === 'authenticated' && enabled,
    refetchInterval: (q) => (busyRuns(q.state.data) ? 1000 : 15_000),
    retry,
  });
}

export function useRun(id: string, page = 1) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.run(id, page),
    queryFn: () => runsApi.get(id, page),
    enabled: status === 'authenticated' && !!id,
    placeholderData: keepPreviousData,
    refetchInterval: (q) =>
      q.state.data && (busyRuns([q.state.data]) || verifyingOf(q.state.data)) ? 1000 : false,
    retry,
  });
}

/** Live list from the agent (`backup.snapshots`): fetched on demand, never assumed current. */
export function useSnapshots(serverId: string | null) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.snapshots(serverId ?? ''),
    queryFn: () => snapshotsApi.list(serverId!),
    enabled: status === 'authenticated' && !!serverId,
    staleTime: 30_000,
    // 202 { pending, jobId } while the agent answers → poll until the list arrives.
    refetchInterval: (q) => (q.state.data?.pending ? 1000 : false),
    retry,
  });
}

export function useRestores(f: { status?: string; server_id?: string } = {}) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.restores(f),
    queryFn: () => restoresApi.list(f),
    enabled: status === 'authenticated',
    refetchInterval: (q) =>
      (q.state.data ?? []).some((r) => !RESTORE_TERMINAL.includes(r.status)) ? 5000 : 30_000,
    retry,
  });
}

const restoreBusy = (r: Restore | undefined) =>
  !!r && (r.status === 'running' || r.status === 'awaiting_approval' || r.status === 'approved');

export function useRestore(id: string | null) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p6k.restore(id ?? ''),
    queryFn: () => restoresApi.get(id!),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: (q) =>
      q.state.data?.status === 'running' || q.state.data?.steps.some((x) => x.status === 'running')
        ? 800
        : restoreBusy(q.state.data)
          ? 3000
          : false,
    retry,
  });
}
