'use client';

import { useQuery } from '@tanstack/react-query';
import { HEARTBEAT_INTERVAL_SEC } from '@ppanel/shared-contracts';
import { serversApi } from './api/endpoints';
import { useAuth } from './auth/auth-provider';

export const qk = {
  servers: ['servers'] as const,
  server: (id: string) => ['servers', id] as const,
  users: ['users'] as const,
  audit: (q: Record<string, unknown>) => ['audit', q] as const,
};

/** Whole fleet in scope; refreshed every heartbeat interval without stealing focus. */
export function useServers() {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: qk.servers,
    queryFn: () => serversApi.listAll(),
    enabled: status === 'authenticated' && can('fleet.read'),
    refetchInterval: HEARTBEAT_INTERVAL_SEC * 1000,
  });
}

export function useServer(id: string) {
  const { status } = useAuth();
  return useQuery({
    queryKey: qk.server(id),
    queryFn: () => serversApi.get(id),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: HEARTBEAT_INTERVAL_SEC * 1000,
  });
}
