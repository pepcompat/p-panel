'use client';

import { useQuery } from '@tanstack/react-query';
import {
  sshCredentialsApi,
  sshEndpointsApi,
  sshGrantsApi,
  sshHostKeysApi,
  sshSessionsApi,
} from './api/p10-endpoints';
import { isApiError } from './api/errors';
import type { SshCredential, SshGrant, SshSession } from './api/p10-types';
import { useAuth } from './auth/auth-provider';

export const p10k = {
  all: ['ssh'] as const,
  credentials: ['ssh', 'credentials'] as const,
  endpoints: (serverId: string) => ['ssh', 'endpoints', serverId] as const,
  hostKeys: (serverId: string) => ['ssh', 'host-keys', serverId] as const,
  grants: ['ssh', 'grants'] as const,
  sessions: ['ssh', 'sessions'] as const,
};

const retry = (n: number, e: unknown) =>
  n < 1 && !(isApiError(e) && [401, 403, 404, 409, 422, 429].includes(e.status));

function useAuthed() {
  const { status } = useAuth();
  return status === 'authenticated';
}

const deploying = (c: SshCredential) =>
  c.deployments.some((d) => d.status === 'pending' || d.status === 'removing');

export function useCredentials(enabled = true) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p10k.credentials,
    queryFn: sshCredentialsApi.list,
    enabled: authed && enabled,
    refetchInterval: (q) => ((q.state.data ?? []).some(deploying) ? 1000 : 30_000),
    retry,
  });
}

export function useSshEndpoints(serverId: string, enabled = true) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p10k.endpoints(serverId),
    queryFn: () => sshEndpointsApi.list(serverId),
    enabled: authed && !!serverId && enabled,
    retry,
  });
}

export function useHostKeys(serverId: string, enabled = true) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p10k.hostKeys(serverId),
    queryFn: () => sshHostKeysApi.list(serverId),
    enabled: authed && !!serverId && enabled,
    retry,
  });
}

/** Every grant the caller may see (own; all with credentials.manage / approvals.decide). */
export function useGrants() {
  const authed = useAuthed();
  return useQuery({
    queryKey: p10k.grants,
    queryFn: () => sshGrantsApi.list(),
    enabled: authed,
    refetchInterval: 15_000,
    retry,
  });
}

/** The caller's own active grants (what a terminal can be opened with). */
export function useMyActiveGrants(): { data: SshGrant[]; isPending: boolean } {
  const { me } = useAuth();
  const q = useGrants();
  const now = Date.now();
  return {
    isPending: q.isPending,
    data: (q.data ?? []).filter(
      (g) =>
        g.userId === me?.user.id &&
        g.status === 'active' &&
        (!g.expiresAt || Date.parse(g.expiresAt) > now),
    ),
  };
}

const sessionLive = (x: SshSession) => x.status === 'open' || x.status === 'pending';

export function useSshSessions() {
  const authed = useAuthed();
  return useQuery({
    queryKey: p10k.sessions,
    queryFn: () => sshSessionsApi.list(),
    enabled: authed,
    refetchInterval: (q) => ((q.state.data ?? []).some(sessionLive) ? 5000 : 30_000),
    retry,
  });
}
