'use client';

import { useQuery } from '@tanstack/react-query';
import { buildConfigApi, buildsApi, composeApi } from './api/p4b-endpoints';
import { BUILD_ACTIVE, type Build } from './api/p4b-types';
import { useAuth } from './auth/auth-provider';
import { POLL_MS } from './p3-queries';

export const p4bk = {
  builds: (appId: string) => ['applications', 'one', appId, 'builds'] as const,
  build: (id: string) => ['builds', 'one', id] as const,
  buildLog: (id: string) => ['builds', 'one', id, 'log'] as const,
  gitAuth: (appId: string) => ['applications', 'one', appId, 'git-auth'] as const,
};

const live = (b: Pick<Build, 'status'>) => BUILD_ACTIVE.includes(b.status);

export function useBuilds(appId: string, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4bk.builds(appId),
    queryFn: () => buildsApi.list(appId),
    enabled: status === 'authenticated' && !!appId && enabled,
    refetchInterval: (q) => (q.state.data?.items.some(live) ? POLL_MS : false),
  });
}

/** Polled every second while the build runs, then until its deployment is linked. */
export function useBuild(id: string | null | undefined) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4bk.build(id ?? ''),
    queryFn: () => buildsApi.get(id!),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: (q) => {
      const b = q.state.data;
      if (!b || live(b)) return POLL_MS;
      return false;
    },
  });
}

/** Full stored (bounded, redacted) log; refreshed while the build is live. */
export function useBuildLog(id: string | null | undefined, live: boolean, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4bk.buildLog(id ?? ''),
    queryFn: () => buildsApi.log(id!),
    enabled: status === 'authenticated' && !!id && enabled,
    refetchInterval: live ? POLL_MS : false,
  });
}

export function useGitAuth(appId: string | null, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4bk.gitAuth(appId ?? ''),
    queryFn: () => buildConfigApi.gitAuth(appId!),
    enabled: status === 'authenticated' && !!appId && enabled,
  });
}

/** Current compose version incl. YAML (assumed GET …/compose; the app read model has no YAML). */
export function useComposeCurrent(appId: string | null, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: ['applications', 'one', appId ?? '', 'compose'] as const,
    queryFn: () => composeApi.current(appId!),
    enabled: status === 'authenticated' && !!appId && enabled,
  });
}
