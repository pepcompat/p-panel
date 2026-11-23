/** P5 endpoints (docs/API_CONTRACTS.md §9). The UI never builds PromQL/LogQL — only typed params. */
import { api } from './index';
import { API_BASE } from '../config';
import type { Query } from './client';
import {
  LOG_LEVELS,
  LOG_Q_MAX,
  LOG_SOURCES,
  type AlertRule,
  type AlertRuleInput,
  type ChannelInput,
  type ChannelTestResult,
  type FleetServerSummary,
  type Incident,
  type LogEntry,
  type LogQueryParams,
  type LogQueryResult,
  type LogTailParams,
  type MetricName,
  type MetricRange,
  type MetricScope,
  type MetricSeries,
  type NotificationChannel,
  type TailToken,
} from './p5-types';

const enc = encodeURIComponent;
const UUIDISH = /^[0-9a-zA-Z-]{1,64}$/;

/**
 * Whitelist the typed log params into a flat query. Unknown keys are dropped, enums are checked,
 * `q` is trimmed and capped — it is sent as a plain substring for the Center to escape into a line
 * filter. There is deliberately no field that could carry LogQL.
 */
export function toLogQuery(p: Partial<LogQueryParams>): Query {
  const out: Query = {};
  if (p.serverId && UUIDISH.test(p.serverId)) out.serverId = p.serverId;
  if (p.appId && UUIDISH.test(p.appId)) out.appId = p.appId;
  if (p.source && (LOG_SOURCES as readonly string[]).includes(p.source)) out.source = p.source;
  if (p.level && (LOG_LEVELS as readonly string[]).includes(p.level)) out.level = p.level;
  const q = (p.q ?? '').trim().slice(0, LOG_Q_MAX);
  if (q) out.q = q;
  if (p.from) out.from = p.from;
  if (p.to) out.to = p.to;
  if (p.limit) out.limit = Math.min(1000, Math.max(1, Math.round(p.limit)));
  if (p.direction === 'backward' || p.direction === 'forward') out.direction = p.direction;
  if (p.cursor) out.cursor = p.cursor;
  return out;
}

export const metricsApi = {
  fleet: () => api.list<FleetServerSummary>('/metrics/fleet').then((r) => r.items ?? []),
  series: (scope: MetricScope, id: string, metric: MetricName, range: MetricRange) =>
    api.get<MetricSeries>('/metrics/series', {
      query: { scope, id, metric, range, step: 'auto' },
    }),
};

export const logsApi = {
  query: async (p: LogQueryParams): Promise<LogQueryResult> => {
    const r = await api.request<LogEntry[]>('GET', '/logs/query', { query: toLogQuery(p) });
    // "paginate-like { hasMore, nextCursor }" + meta.retention — accept it at either level.
    const pg = (r.paginate ?? {}) as unknown as { hasMore?: boolean; nextCursor?: string | null };
    const meta = (r.meta ?? {}) as unknown as {
      retention?: { days?: number };
      hasMore?: boolean;
      nextCursor?: string | null;
    };
    const nextCursor = pg.nextCursor ?? meta.nextCursor ?? null;
    return {
      items: Array.isArray(r.data) ? r.data : [],
      hasMore: !!(pg.hasMore ?? meta.hasMore ?? nextCursor),
      nextCursor,
      retentionDays: meta.retention?.days ?? null,
      requestId: r.requestId,
    };
  },
  tailToken: (p: LogTailParams) => api.post<TailToken>('/logs/tail-token', toLogQuery(p)),
  /** Prefer the Center-provided `url` (relative to the API base); else build it from params. */
  tailUrlFor: (tok: TailToken, p: LogTailParams, lastEventId?: string | null): string => {
    if (!tok.url) return logsApi.tailUrl(tok.token, p, lastEventId);
    const u = new URL(`${API_BASE}${tok.url.replace(/^\/api\/v1/, '')}`, 'http://x');
    if (lastEventId) u.searchParams.set('lastEventId', lastEventId);
    return /^https?:/.test(API_BASE) ? u.toString() : `${u.pathname}${u.search}`;
  },
  /** EventSource URL: token in the query (EventSource cannot send headers). */
  tailUrl: (token: string, p: LogTailParams, lastEventId?: string | null): string => {
    const qs = new URLSearchParams();
    qs.set('token', token);
    for (const [k, v] of Object.entries(toLogQuery(p))) if (v != null) qs.set(k, String(v));
    if (lastEventId) qs.set('lastEventId', lastEventId);
    return `${API_BASE}/logs/tail?${qs.toString()}`;
  },
};

export const alertRulesApi = {
  list: () => api.list<AlertRule>('/alert-rules', { query: { limit: 100 } }).then((r) => r.items),
  create: (body: AlertRuleInput) => api.post<AlertRule>('/alert-rules', body),
  /** PATCH never sends `kind` (updateAlertRuleSchema is strict; kind is immutable). */
  update: (id: string, body: Partial<AlertRuleInput>, version: number) =>
    api
      .request<AlertRule>('PATCH', `/alert-rules/${enc(id)}`, {
        body: Object.fromEntries(Object.entries(body).filter(([k]) => k !== 'kind')),
        headers: { 'If-Match': String(version) },
      })
      .then((r) => r.data),
  remove: (id: string, version: number) =>
    api.del(`/alert-rules/${enc(id)}`, { headers: { 'If-Match': String(version) } }),
};

export interface IncidentFilters {
  status?: string;
  severity?: string;
  target_type?: string;
}
export const incidentsApi = {
  list: (f: IncidentFilters = {}) =>
    api
      .list<Incident>('/incidents', {
        query: { limit: 100, status: f.status, severity: f.severity, target_type: f.target_type },
      })
      .then((r) => r.items),
  get: (id: string) => api.get<Incident>(`/incidents/${enc(id)}`),
  acknowledge: (id: string, comment?: string) =>
    api.post<Incident>(`/incidents/${enc(id)}/acknowledge`, comment ? { comment } : {}),
  comment: (id: string, comment: string) =>
    api.post<Incident>(`/incidents/${enc(id)}/comment`, { comment }),
};

export const channelsApi = {
  list: () =>
    api
      .list<NotificationChannel>('/notification-channels', { query: { limit: 100 } })
      .then((r) => r.items),
  create: (body: ChannelInput) => api.post<NotificationChannel>('/notification-channels', body),
  update: (id: string, body: Partial<ChannelInput>) =>
    api.patch<NotificationChannel>(`/notification-channels/${enc(id)}`, body),
  remove: (id: string) => api.del(`/notification-channels/${enc(id)}`),
  test: (id: string) => api.post<ChannelTestResult>(`/notification-channels/${enc(id)}/test`),
};
