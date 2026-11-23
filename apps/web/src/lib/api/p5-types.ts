/**
 * P5 read models (docs/API_CONTRACTS.md §9) — re-exported from `@ppanel/shared-contracts`
 * (observability.ts). Web-side aliases only relax fields the UI tolerates missing (older Center
 * builds) and add the typed client query params; the Center builds every PromQL/LogQL query.
 */
import type {
  AlertRule as SharedAlertRule,
  AppMetric,
  ChannelTestResult as SharedChannelTestResult,
  FleetMetric,
  FleetMetricSample,
  Incident as SharedIncident,
  IncidentEvent,
  LogEntry,
  NotificationChannel as SharedChannel,
  ServerMetric,
  TailTokenResponse,
  ThresholdMetric,
} from '@ppanel/shared-contracts';

export {
  ACTIVE_ALERT_KINDS as CREATABLE_RULE_KINDS,
  ALERT_KINDS as RULE_KINDS,
  ALERT_KIND_SCOPES,
  ALERT_SCOPE_TYPES as SCOPE_TYPES,
  ALERT_SEVERITIES as SEVERITIES,
  APP_METRICS,
  CHANNEL_TYPES,
  INCIDENT_STATUSES,
  LOG_LEVELS,
  LOG_QUERY_MAX_Q as LOG_Q_MAX,
  LOG_SOURCES,
  LOG_TAIL_MAX_DURATION_SEC,
  METRIC_RANGES,
  SERVER_METRICS,
  THRESHOLD_METRICS,
} from '@ppanel/shared-contracts';
export type {
  AlertKind as RuleKind,
  AlertScopeType as RuleScopeType,
  AlertSeverity as Severity,
  AppMetric,
  ChannelType,
  IncidentStatus,
  LogEntry,
  LogLevel,
  LogSource,
  LogTailEndReason,
  MetricPoint,
  MetricRange,
  MetricScope,
  MetricSeries,
  MetricUnit,
  ServerMetric,
  ThresholdMetric,
} from '@ppanel/shared-contracts';
import { LOG_TAIL_MAX_DURATION_SEC, METRIC_RANGES } from '@ppanel/shared-contracts';
import type {
  AlertKind,
  AlertScopeType,
  AlertSeverity,
  ChannelType,
  LogLevel,
  LogSource,
  MetricRange,
} from '@ppanel/shared-contracts';

export const isMetricRange = (v: unknown): v is MetricRange =>
  (METRIC_RANGES as readonly unknown[]).includes(v);
export type MetricName = ServerMetric | AppMetric;

/** Fleet row; container / log-shipping extras tolerated missing. */
export type FleetServerSummary = Omit<
  FleetMetric,
  'sample' | 'containers' | 'logShipping' | 'logDroppedTotal'
> & {
  sample: (Omit<FleetMetricSample, 'load1'> & { load1?: number | null }) | null;
  containers?: FleetMetric['containers'];
  logShipping?: FleetMetric['logShipping'];
  logDroppedTotal?: number;
};

// ---------------------------------------------------------------- logs

export type LogDirection = 'backward' | 'forward';

/** The only parameters the UI sends — typed, no query language. */
export interface LogQueryParams {
  serverId?: string;
  appId?: string;
  source?: LogSource;
  level?: LogLevel;
  /** Plain substring, ≤ 200 chars. */
  q?: string;
  from: string;
  to: string;
  limit?: number;
  direction?: LogDirection;
  /** Opaque cursor from `paginate.nextCursor`. */
  cursor?: string;
}
export type LogTailParams = Omit<LogQueryParams, 'from' | 'to' | 'limit' | 'direction' | 'cursor'>;

export interface LogQueryResult {
  items: LogEntry[];
  hasMore: boolean;
  nextCursor: string | null;
  retentionDays: number | null;
  requestId: string;
}

/** `url` (relative to the API base, token included) is preferred when the Center returns it. */
export type TailToken = Omit<TailTokenResponse, 'url'> & { url?: string };

export const LOG_MAX_SPAN_MS = 7 * 864e5;
export const TAIL_BUFFER_MAX = 2000;
export const TAIL_MAX_MS = LOG_TAIL_MAX_DURATION_SEC * 1000;

// ---------------------------------------------------------------- alerts

export type ThresholdParams = {
  metric: ThresholdMetric;
  op: 'gt' | 'lt';
  value: number;
};
export type LogDroppedParams = { windowSec?: number; minEntries?: number };

/** Tolerant accessors for the channel config view (secrets come back as `{ set: true }`). */
export function channelFields(c: Pick<SharedChannel, 'config'>) {
  const cfg = c.config as Partial<{
    url: string;
    to: string[];
    chatId: string;
    signingSecret: { set: boolean };
    botToken: { set: boolean };
  }>;
  return {
    url: cfg.url,
    to: cfg.to,
    chatId: cfg.chatId,
    signingSecretSet: !!cfg.signingSecret?.set,
    botTokenSet: !!cfg.botToken?.set,
  };
}

/** Incident event `detail` is an object; show a comment/message, else `k: v` pairs. */
export function eventDetailText(d: unknown): string | null {
  if (d === null || d === undefined) return null;
  if (typeof d === 'string') return d || null;
  if (typeof d !== 'object') return String(d);
  const o = d as Record<string, unknown>;
  for (const k of ['comment', 'message', 'summary', 'error'])
    if (typeof o[k] === 'string' && o[k]) return o[k] as string;
  const parts = Object.entries(o)
    .filter(([, v]) => v !== null && v !== undefined && typeof v !== 'object')
    .map(([k, v]) => `${k}: ${String(v)}`);
  return parts.length ? parts.join(' · ') : null;
}

export type AlertRule = Omit<
  SharedAlertRule,
  'active' | 'allowedActions' | 'createdAt' | 'updatedAt' | 'scopeId'
> & {
  scopeId?: string | null;
  active?: boolean;
  allowedActions?: SharedAlertRule['allowedActions'];
  createdAt?: string;
  updatedAt?: string;
};

/** Create body (`createAlertRuleSchema`); PATCH sends the same minus `kind`. */
export interface AlertRuleInput {
  name: string;
  enabled: boolean;
  scopeType: AlertScopeType;
  scopeId: string | null;
  kind: AlertKind;
  params: Record<string, unknown>;
  severity: AlertSeverity;
  forSec: number;
  channelIds: string[];
}

export type IncidentTimelineEntry = IncidentEvent;
export type Incident = Omit<SharedIncident, 'allowedActions'> & {
  allowedActions?: SharedIncident['allowedActions'];
};

export type NotificationChannel = SharedChannel;
export interface ChannelInput {
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: {
    url?: string;
    signingSecret?: string;
    to?: string[];
    chatId?: string;
    botToken?: string;
  };
}
export type ChannelTestResult = Omit<SharedChannelTestResult, 'deliveryId'> & {
  deliveryId?: string;
};
