'use client';

import { keepPreviousData, useQuery } from '@tanstack/react-query';
import {
  alertRulesApi,
  channelsApi,
  incidentsApi,
  metricsApi,
  type IncidentFilters,
} from './api/p5-endpoints';
import { isApiError } from './api/errors';
import type { MetricName, MetricRange, MetricScope } from './api/p5-types';
import { useAuth } from './auth/auth-provider';

export const p5k = {
  fleet: ['metrics', 'fleet'] as const,
  series: (scope: MetricScope, id: string, metric: MetricName, range: MetricRange) =>
    ['metrics', 'series', scope, id, metric, range] as const,
  incidents: (f: IncidentFilters = {}) => ['incidents', f] as const,
  incident: (id: string) => ['incidents', 'one', id] as const,
  rules: ['alert-rules'] as const,
  channels: ['notification-channels'] as const,
};

/** Don't hammer a 429: retry other failures once, never rate-limit / auth errors. */
const retry = (n: number, e: unknown) =>
  n < 1 && !(isApiError(e) && [401, 403, 404, 429].includes(e.status));

export function useFleetMetrics() {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p5k.fleet,
    queryFn: metricsApi.fleet,
    enabled: status === 'authenticated' && can('fleet.read'),
    refetchInterval: 15_000,
    retry,
  });
}

const RANGE_REFRESH: Record<MetricRange, number> = {
  '1h': 30_000,
  '6h': 60_000,
  '24h': 120_000,
  '7d': 300_000,
};

export function useMetricSeries(
  scope: MetricScope,
  id: string | null | undefined,
  metric: MetricName,
  range: MetricRange,
  enabled = true,
) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p5k.series(scope, id ?? '', metric, range),
    queryFn: () => metricsApi.series(scope, id!, metric, range),
    enabled: status === 'authenticated' && !!id && enabled,
    refetchInterval: RANGE_REFRESH[range],
    staleTime: RANGE_REFRESH[range] / 2,
    placeholderData: keepPreviousData,
    retry,
  });
}

export function useIncidents(f: IncidentFilters = {}, enabled = true) {
  const { status, can } = useAuth();
  return useQuery({
    queryKey: p5k.incidents(f),
    queryFn: () => incidentsApi.list(f),
    enabled: status === 'authenticated' && can('fleet.read') && enabled,
    refetchInterval: 15_000,
    retry,
  });
}

/** Firing + acknowledged (= not resolved) incidents, for badges and the overview. */
export function useActiveIncidents(enabled = true) {
  const q = useIncidents({}, enabled);
  return { ...q, active: (q.data ?? []).filter((i) => i.status !== 'resolved') };
}

export function useIncident(id: string | null) {
  const { status } = useAuth();
  return useQuery({
    queryKey: p5k.incident(id ?? ''),
    queryFn: () => incidentsApi.get(id!),
    enabled: status === 'authenticated' && !!id,
    refetchInterval: 15_000,
    retry,
  });
}

export function useAlertRules() {
  const { status } = useAuth();
  return useQuery({
    queryKey: p5k.rules,
    queryFn: alertRulesApi.list,
    enabled: status === 'authenticated',
    retry,
  });
}

export function useChannels() {
  const { status } = useAuth();
  return useQuery({
    queryKey: p5k.channels,
    queryFn: channelsApi.list,
    enabled: status === 'authenticated',
    retry,
  });
}
