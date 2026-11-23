'use client';

import { useQuery } from '@tanstack/react-query';
import type { Query } from './api/client';
import {
  containerAppsApi,
  deploymentsApi,
  integrationsApi,
  managedRoutingApi,
} from './api/p4-endpoints';
import { DEPLOYMENT_ACTIVE, type Deployment } from './api/p4-types';
import { useAuth } from './auth/auth-provider';
import { POLL_MS } from './p3-queries';

export const p4k = {
  deployments: (q: Query = {}) => ['deployments', q] as const,
  deployment: (id: string) => ['deployments', 'one', id] as const,
  appDeployments: (appId: string) => ['applications', 'one', appId, 'deployments'] as const,
  secrets: (appId: string) => ['applications', 'one', appId, 'secrets'] as const,
  registryAuth: (appId: string) => ['applications', 'one', appId, 'registry-auth'] as const,
  logs: (appId: string, tail: number) => ['applications', 'one', appId, 'logs', tail] as const,
  autoDeploy: (appId: string) => ['applications', 'one', appId, 'auto-deploy'] as const,
  routing: (serverId: string) => ['managed-routing', serverId] as const,
  integrations: ['integrations', 'github'] as const,
  deliveries: (id: string) => ['integrations', 'github', id, 'deliveries'] as const,
};

const live = (d: Pick<Deployment, 'status'>) => DEPLOYMENT_ACTIVE.includes(d.status);

export function useDeployments(q: Query = {}, opts: { enabled?: boolean } = {}) {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p4k.deployments(q),
    queryFn: () => deploymentsApi.list(q),
    enabled: status === 'authenticated' && can('apps.read') && opts.enabled !== false,
    refetchInterval: (query) => (query.state.data?.items.some(live) ? POLL_MS * 2 : 15_000),
  });
}

/** Polled every second while the deployment is in progress (execution timeline). */
export function useDeployment(id: string | null | undefined) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.deployment(id ?? ''),
    queryFn: () => deploymentsApi.get(id!),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d) return POLL_MS;
      if (live(d)) return POLL_MS;
      return d.status === 'awaiting_approval' ? POLL_MS * 5 : false;
    },
  });
}

export function useAppDeployments(appId: string, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.appDeployments(appId),
    queryFn: () => containerAppsApi.deployments(appId),
    enabled: status === 'authenticated' && !!appId && enabled,
    refetchInterval: (query) => (query.state.data?.items.some(live) ? POLL_MS : false),
  });
}

export function useSecrets(appId: string | null, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.secrets(appId ?? ''),
    queryFn: () => containerAppsApi.secrets(appId!),
    enabled: status === 'authenticated' && !!appId && enabled,
  });
}

export function useRegistryAuth(appId: string | null, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.registryAuth(appId ?? ''),
    queryFn: () => containerAppsApi.registryAuth(appId!),
    enabled: status === 'authenticated' && !!appId && enabled,
  });
}

export function useAppLogs(appId: string, tail: number, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.logs(appId, tail),
    queryFn: () => containerAppsApi.logs(appId, tail),
    enabled: status === 'authenticated' && enabled,
    refetchInterval: (query) => (query.state.data?.status === 'pending' ? POLL_MS : false),
  });
}

export function useAutoDeploy(appId: string, enabled = true) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.autoDeploy(appId),
    queryFn: () => containerAppsApi.autoDeploy(appId),
    enabled: status === 'authenticated' && enabled,
  });
}

export function useManagedRouting(serverId: string | null | undefined) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.routing(serverId ?? ''),
    queryFn: () => managedRoutingApi.get(serverId!),
    enabled: status === 'authenticated' && !!serverId,
    retry: false,
    refetchInterval: (query) => (query.state.data?.status === 'applying' ? POLL_MS : false),
  });
}

export function useIntegrations() {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p4k.integrations,
    queryFn: () => integrationsApi.list(),
    enabled: status === 'authenticated' && can('apps.read'),
  });
}

export function useDeliveries(id: string | null) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p4k.deliveries(id ?? ''),
    queryFn: () => integrationsApi.deliveries(id!),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: 15_000,
  });
}
