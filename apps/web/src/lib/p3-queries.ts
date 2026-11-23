'use client';

import { useQuery } from '@tanstack/react-query';
import { applicationsApi, discoveryApi, jobsApi, revisionsApi } from './api/endpoints';
import type { Query } from './api/client';
import { REVISION_BUSY, type NginxRevision } from './api/p3-types';
import { useAuth } from './auth/auth-provider';

export const p3k = {
  scans: (q: Query = {}) => ['discovery-scans', q] as const,
  scan: (id: string) => ['discovery-scans', 'one', id] as const,
  findings: (id: string) => ['discovery-scans', 'one', id, 'findings'] as const,
  apps: (q: Query = {}) => ['applications', q] as const,
  app: (id: string) => ['applications', 'one', id] as const,
  history: (id: string) => ['applications', 'one', id, 'history'] as const,
  files: (id: string) => ['applications', 'one', id, 'nginx-files'] as const,
  revisions: (id: string) => ['applications', 'one', id, 'revisions'] as const,
  job: (serverId: string, jobId: string) => ['jobs', serverId, jobId] as const,
};

export const POLL_MS = 1000;

export function useScans(q: Query = {}) {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p3k.scans(q),
    queryFn: () => discoveryApi.list(q),
    enabled: status === 'authenticated' && can('fleet.read'),
    refetchInterval: (query) =>
      query.state.data?.items.some((s) => s.status === 'running') ? POLL_MS * 2 : false,
  });
}

export function useScan(id: string) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p3k.scan(id),
    queryFn: () => discoveryApi.get(id),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: (query) => (query.state.data?.status === 'running' ? POLL_MS : false),
  });
}

export function useFindings(id: string, enabled: boolean) {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p3k.findings(id),
    queryFn: () => discoveryApi.findings(id),
    enabled: status === 'authenticated' && enabled && can('nginx.read'),
  });
}

export function useApplications(q: Query = {}) {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p3k.apps(q),
    queryFn: () => applicationsApi.list(q),
    enabled: status === 'authenticated' && can('apps.read'),
  });
}

export function useApplication(id: string) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p3k.app(id),
    queryFn: () => applicationsApi.get(id),
    enabled: status === 'authenticated' && !!id,
  });
}

export function useOwnershipHistory(id: string) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p3k.history(id),
    queryFn: () => applicationsApi.ownershipHistory(id),
    enabled: status === 'authenticated' && !!id,
  });
}

/** GET nginx/files; while the Center answers 202 (read_files job running) poll every second. */
export function useNginxFiles(id: string, enabled: boolean) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p3k.files(id),
    queryFn: () => applicationsApi.nginxFiles(id),
    enabled: status === 'authenticated' && enabled,
    refetchInterval: (query) => (query.state.data?.state === 'pending' ? POLL_MS : false),
  });
}

export function useRevisions(id: string, enabled: boolean) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p3k.revisions(id),
    queryFn: () => applicationsApi.revisions(id),
    enabled: status === 'authenticated' && enabled,
    refetchInterval: (query) =>
      query.state.data?.items.some((r) => REVISION_BUSY.includes(r.status)) ? POLL_MS : false,
  });
}

export function useRevision(rev: NginxRevision | undefined) {
  const { status } = useAuth();
  return useQuery({
    queryKey: ['nginx-revisions', rev?.id],
    queryFn: () => revisionsApi.get(rev!.id),
    enabled: status === 'authenticated' && !!rev,
    initialData: rev,
    refetchInterval: (query) =>
      query.state.data && REVISION_BUSY.includes(query.state.data.status) ? POLL_MS : false,
  });
}

/** Typed job status (GET /servers/:id/jobs/:jobId) polled until terminal. */
export function useJob(serverId: string, jobId: string | null | undefined) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p3k.job(serverId, jobId ?? ''),
    queryFn: () => jobsApi.get(serverId, jobId!),
    enabled: status === 'authenticated' && !!jobId,
    retry: false,
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return !s || s === 'queued' || s === 'leased' || s === 'running' ? POLL_MS : false;
    },
  });
}
