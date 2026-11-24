'use client';

import { useQuery } from '@tanstack/react-query';
import {
  diagnosticsApi,
  gatewaysApi,
  groupsApi,
  integrationsApi,
  networkApi,
  plansApi,
} from './api/p9-endpoints';
import { isApiError } from './api/errors';
import { TEST_ACTIVE, type NetworkConnectivityTest } from './api/p9-types';
import { useAuth } from './auth/auth-provider';
import { planBusy } from './p9-gates';

export const p9k = {
  groups: ['server-groups'] as const,
  topology: ['network', 'topology'] as const,
  integrations: ['provider-integrations'] as const,
  diagnostics: (serverId: string) => ['network-diagnostics', 'server', serverId] as const,
  test: (id: string) => ['network-diagnostics', 'one', id] as const,
  gateways: ['gateways'] as const,
  gateway: (id: string) => ['gateways', 'one', id] as const,
  routes: (id: string) => ['gateways', 'routes', id] as const,
  plans: (id: string) => ['gateways', 'plans', id] as const,
  plan: (id: string) => ['gateway-plans', id] as const,
};

const retry = (n: number, e: unknown) =>
  n < 1 && !(isApiError(e) && [401, 403, 404, 409, 422, 429].includes(e.status));

function useAuthed() {
  const { status } = useAuth();
  return status === 'authenticated';
}

export function useGroups() {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.groups,
    queryFn: () => groupsApi.list(),
    enabled: authed,
    retry,
  });
}

export function useTopology() {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.topology,
    queryFn: networkApi.topology,
    enabled: authed,
    refetchInterval: 30_000,
    retry,
  });
}

export function useIntegrations() {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.integrations,
    queryFn: integrationsApi.list,
    enabled: authed,
    refetchInterval: (q) => ((q.state.data ?? []).some((i) => i.syncInProgress) ? 1000 : 30_000),
    retry,
  });
}

const testBusy = (t: NetworkConnectivityTest | undefined) => !!t && TEST_ACTIVE.includes(t.status);

export function useDiagnostics(serverId: string) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.diagnostics(serverId),
    queryFn: () => diagnosticsApi.list(serverId),
    enabled: authed && !!serverId,
    refetchInterval: (q) => ((q.state.data ?? []).some(testBusy) ? 1000 : 30_000),
    retry,
  });
}

/** One diagnostics / pair test, polled while queued or running. */
export function useTest(testId: string | null) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.test(testId ?? ''),
    queryFn: () => diagnosticsApi.get(testId!),
    enabled: authed && !!testId,
    refetchInterval: (q) => (testBusy(q.state.data) ? 800 : false),
    retry,
  });
}

export function useGateways() {
  const authed = useAuthed();
  return useQuery({ queryKey: p9k.gateways, queryFn: gatewaysApi.list, enabled: authed, retry });
}

export function useGateway(id: string) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.gateway(id),
    queryFn: () => gatewaysApi.get(id),
    enabled: authed && !!id,
    retry,
  });
}

export function useRoutes(gatewayId: string) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.routes(gatewayId),
    queryFn: () => gatewaysApi.routes(gatewayId),
    enabled: authed && !!gatewayId,
    retry,
  });
}

export function usePlans(gatewayId: string) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.plans(gatewayId),
    queryFn: () => gatewaysApi.plans(gatewayId),
    enabled: authed && !!gatewayId,
    refetchInterval: (q) => ((q.state.data ?? []).some(planBusy) ? 1500 : 30_000),
    retry,
  });
}

export function usePlan(id: string) {
  const authed = useAuthed();
  return useQuery({
    queryKey: p9k.plan(id),
    queryFn: () => plansApi.get(id),
    enabled: authed && !!id,
    refetchInterval: (q) => (q.state.data && planBusy(q.state.data) ? 800 : false),
    retry,
  });
}
