/**
 * P5 — monitoring, central logs, alerts and incidents (docs/API_CONTRACTS.md §9, AGENT_PROTOCOL
 * "Telemetry (P5)", ADR-0008). Users never send PromQL/LogQL: every query is built by the Center from
 * these typed parameters and always carries the caller's scope selector.
 */
import { z } from 'zod';
import { ENVIRONMENTS, type Environment, type ServerStatus } from './server';

// ------------------------------------------------------------------------------------------ metrics

export const METRIC_RANGES = ['1h', '6h', '24h', '7d'] as const;
export type MetricRange = (typeof METRIC_RANGES)[number];
export const METRIC_RANGE_SECONDS: Record<MetricRange, number> = {
  '1h': 3600,
  '6h': 21_600,
  '24h': 86_400,
  '7d': 604_800,
};
/** `step=auto` → seconds per point (≤ 360 points per series). */
export const METRIC_AUTO_STEP_SECONDS: Record<MetricRange, number> = {
  '1h': 15,
  '6h': 60,
  '24h': 300,
  '7d': 1800,
};
/** Max points a caller-chosen numeric step may produce. */
export const METRIC_MAX_POINTS = 11_000;

export const SERVER_METRICS = ['cpu', 'memory', 'disk', 'load1', 'net_rx', 'net_tx', 'up'] as const;
export type ServerMetric = (typeof SERVER_METRICS)[number];
export const APP_METRICS = ['cpu', 'memory', 'up', 'restarts'] as const;
export type AppMetric = (typeof APP_METRICS)[number];
export const METRIC_SCOPES = ['server', 'app'] as const;
export type MetricScope = (typeof METRIC_SCOPES)[number];

export type MetricUnit = 'percent' | 'bytes' | 'bytes_per_second' | 'load' | 'bool' | 'count';
export const SERVER_METRIC_UNITS: Record<ServerMetric, MetricUnit> = {
  cpu: 'percent',
  memory: 'percent',
  disk: 'percent',
  load1: 'load',
  net_rx: 'bytes_per_second',
  net_tx: 'bytes_per_second',
  up: 'bool',
};
export const APP_METRIC_UNITS: Record<AppMetric, MetricUnit> = {
  cpu: 'percent',
  memory: 'bytes',
  up: 'bool',
  restarts: 'count',
};

/** `GET /metrics/series` query. Unknown params are rejected (no client query strings). */
export const metricsSeriesQuerySchema = z
  .object({
    scope: z.enum(METRIC_SCOPES),
    id: z.string().uuid(),
    metric: z.string().min(1).max(32),
    range: z.enum(METRIC_RANGES).default('1h'),
    step: z.union([z.literal('auto'), z.coerce.number().int().min(15).max(86_400)]).default('auto'),
  })
  .strict()
  .superRefine((v, ctx) => {
    const allowed: readonly string[] = v.scope === 'server' ? SERVER_METRICS : APP_METRICS;
    if (!allowed.includes(v.metric))
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['metric'],
        message: `metric must be one of ${allowed.join(', ')} for scope ${v.scope}`,
      });
    if (typeof v.step === 'number' && METRIC_RANGE_SECONDS[v.range] / v.step > METRIC_MAX_POINTS)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['step'],
        message: 'step too small for range',
      });
  });
export type MetricsSeriesQuery = z.infer<typeof metricsSeriesQuerySchema>;

/** `[unixSec, value | null]` — missing data is null, never 0. */
export type MetricPoint = [number, number | null];

export interface MetricSeries {
  scope: MetricScope;
  id: string;
  metric: string;
  unit: MetricUnit;
  range: MetricRange;
  step: number;
  from: number;
  to: number;
  points: MetricPoint[];
  /** `[fromUnixSec, toUnixSec]` inclusive runs of null points */
  gaps: Array<[number, number]>;
  /** latest sample the Center holds for the target (DB), null if never sampled */
  lastSampleAt: string | null;
  stale: boolean;
}

export interface FleetMetricSample {
  cpuPct: number | null;
  memPct: number | null;
  diskPct: number | null;
  load1: number | null;
  sampledAt: string;
}

export interface FleetMetric {
  serverId: string;
  name: string;
  environment: Environment;
  status: ServerStatus;
  sample: FleetMetricSample | null;
  stale: boolean;
  /** latest container samples counts (managed containers only) */
  containers: { total: number; running: number; unhealthy: number };
  /** agent log shipping state from the last heartbeat (null when not reported) */
  logShipping: {
    bufferedBytes: number;
    bufferCapBytes: number | null;
    droppedEntries: number;
    lastShippedAt: string | null;
  } | null;
  /** entries dropped (agent-reported + rejected by the Center), cumulative */
  logDroppedTotal: number;
}

// ------------------------------------------------------------------------------------------- logs

export const LOG_SOURCES = ['nginx_access', 'nginx_error', 'container', 'agent'] as const;
export type LogSource = (typeof LOG_SOURCES)[number];
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error', 'fatal'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
export const LOG_STREAMS = ['stdout', 'stderr'] as const;

export const LOG_LINE_MAX_BYTES = 16_384;
export const LOG_TRUNCATED_SUFFIX = ' …[truncated]';
export const LOG_BATCH_MAX_ENTRIES = 5000;
export const LOG_BATCH_MAX_COMPRESSED_BYTES = 1024 * 1024;
export const LOG_BATCH_MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024;
export const LOG_QUERY_MAX_SPAN_SEC = 7 * 86_400;
export const LOG_QUERY_MAX_LIMIT = 1000;
export const LOG_QUERY_MAX_Q = 200;
/** Live tail: polling interval, per-connection line cap, per-user connection cap, max duration. */
export const LOG_TAIL_POLL_MS = 2000;
export const LOG_TAIL_MAX_LINES_PER_SEC = 200;
export const LOG_TAIL_MAX_PER_USER = 3;
export const LOG_TAIL_MAX_DURATION_SEC = 900;
export const LOG_TAIL_TOKEN_TTL_SEC = 60;

const APP_LABEL_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const isoTs = z.string().datetime({ offset: true });

export const agentLogEntrySchema = z
  .object({
    ts: isoTs,
    source: z.enum(LOG_SOURCES),
    app: z.string().regex(APP_LABEL_RE).nullish(),
    service: z.string().max(64).nullish(),
    container: z.string().max(160).nullish(),
    file: z.string().max(512).nullish(),
    stream: z.enum(LOG_STREAMS).nullish(),
    level: z.enum(LOG_LEVELS).nullish(),
    /** ≤ 16 KiB (+ truncation marker); the Center truncates again and re-redacts */
    line: z.string().max(LOG_LINE_MAX_BYTES * 2),
  })
  .strip();
export type AgentLogEntry = z.infer<typeof agentLogEntrySchema>;

/** `POST /agent/v1/logs` body (gzip JSON, ≤ 1 MiB compressed / 8 MiB decompressed). */
export const agentLogBatchSchema = z
  .object({
    batchId: z.string().uuid(),
    seq: z.number().int().nonnegative(),
    sentAt: isoTs,
    entries: z.preprocess(
      (v) => (v === null ? [] : v),
      z.array(agentLogEntrySchema).max(LOG_BATCH_MAX_ENTRIES),
    ),
    dropped: z
      .object({
        entries: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).default(0),
        since: isoTs.nullish(),
      })
      .strip()
      .nullish(),
  })
  .strip();
export type AgentLogBatch = z.infer<typeof agentLogBatchSchema>;

export interface AgentLogBatchResponse {
  accepted: number;
  duplicate: boolean;
  /** ext: entries dropped by the Center (label spoofing / unknown app) */
  rejected?: number;
}

/** Plain substring (never LogQL): printable characters only, ≤ 200 chars. */
const searchText = z
  .string()
  .max(LOG_QUERY_MAX_Q)
  // eslint-disable-next-line no-control-regex
  .regex(/^[^\u0000-\u001f\u007f]*$/, 'q must not contain control characters');

const logScopeShape = {
  serverId: z.string().uuid().optional(),
  appId: z.string().uuid().optional(),
  source: z.enum(LOG_SOURCES).optional(),
  /** minimum level */
  level: z.enum(LOG_LEVELS).optional(),
  q: searchText.optional(),
};

export const logsQuerySchema = z
  .object({
    ...logScopeShape,
    from: isoTs.optional(),
    to: isoTs.optional(),
    limit: z.coerce.number().int().min(1).max(LOG_QUERY_MAX_LIMIT).default(200),
    direction: z.enum(['backward', 'forward']).default('backward'),
    /** opaque cursor from a previous page's `paginate.nextCursor` */
    cursor: z
      .string()
      .regex(/^\d{1,20}$/)
      .optional(),
  })
  .strict();
export type LogsQuery = z.infer<typeof logsQuerySchema>;

export const logsTailParamsSchema = z.object(logScopeShape).strict();
export type LogsTailParams = z.infer<typeof logsTailParamsSchema>;

/** `GET /logs/tail` query: the tail params + `token` (+ optional `lastEventId` for reconnects). */
export const logsTailQuerySchema = z
  .object({
    ...logScopeShape,
    token: z.string().min(16).max(128),
    lastEventId: z
      .string()
      .regex(/^\d{1,20}$/)
      .optional(),
  })
  .strict();

export interface LogEntry {
  /** ISO-8601 with nanoseconds when known */
  ts: string;
  serverId: string;
  appId: string | null;
  source: LogSource;
  level: LogLevel | null;
  line: string;
}

export interface LogCursorPaginate {
  limit: number;
  hasMore: boolean;
  nextCursor: string | null;
}

export interface TailTokenResponse {
  token: string;
  expiresAt: string;
  /** path + query to open with EventSource (relative to the API base, includes the token) */
  url: string;
}

/**
 * SSE events on `GET /logs/tail` (`text/event-stream`):
 * - `event: log`     `id: <unix ns>` `data: LogEntry`
 * - `event: dropped` `data: { count }` lines skipped by the 200 lines/s cap
 * - `event: end`     `data: { reason: "max_duration" | "forbidden" | "backend_unavailable" | "server_shutdown" }`
 * - comment `: keepalive` every 15 s
 */
export type LogTailEndReason =
  'max_duration' | 'forbidden' | 'backend_unavailable' | 'server_shutdown';

// ----------------------------------------------------------------------------------------- alerts

export const ALERT_KINDS = [
  'server_offline',
  'metric_threshold',
  'app_down',
  'log_dropped',
  'backup_failed',
] as const;
export type AlertKind = (typeof ALERT_KINDS)[number];
export const ALERT_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type AlertSeverity = (typeof ALERT_SEVERITIES)[number];
export const ALERT_SCOPE_TYPES = ['global', 'environment', 'server', 'app'] as const;
export type AlertScopeType = (typeof ALERT_SCOPE_TYPES)[number];
export const THRESHOLD_METRICS = ['cpu', 'memory', 'disk', 'load1'] as const;
export type ThresholdMetric = (typeof THRESHOLD_METRICS)[number];
export const ALERT_EVAL_INTERVAL_SEC = 15;
/**
 * P7 (F-14): agents reconnect up to ~60 s (+ jitter) after a Center outage, so a `server_offline`
 * rule must wait at least this long before firing, or every server alerts after any outage.
 */
export const SERVER_OFFLINE_MIN_FOR_SEC = 90;
/** Default `forSec` per kind when omitted (server_offline needs the larger minimum). */
export const DEFAULT_ALERT_FOR_SEC = 60;
/**
 * P7 (F-14): after the Center starts, `server_offline` evaluates stale servers as unknown (no new
 * pending state) for this long, so agents get time to reconnect (heartbeat interval × 3 + backoff).
 */
export const SERVER_OFFLINE_STARTUP_GRACE_SEC = 90;

/** Effective forSec used by the evaluator: legacy server_offline rules are clamped to the minimum. */
export function effectiveForSec(kind: AlertKind, forSec: number): number {
  return kind === 'server_offline' ? Math.max(forSec, SERVER_OFFLINE_MIN_FOR_SEC) : forSec;
}

function forSecIssue(kind: AlertKind, forSec: number | undefined): string | null {
  if (kind === 'server_offline' && forSec !== undefined && forSec < SERVER_OFFLINE_MIN_FOR_SEC)
    return `server_offline rules need forSec >= ${SERVER_OFFLINE_MIN_FOR_SEC} (agents may take up to ~60 s to reconnect after a Center restart)`;
  return null;
}

export const alertParamsSchemas = {
  server_offline: z.object({}).strict(),
  metric_threshold: z
    .object({
      metric: z.enum(THRESHOLD_METRICS),
      op: z.enum(['gt', 'lt']),
      value: z.number().finite().min(0).max(1_000_000),
    })
    .strict(),
  app_down: z.object({}).strict(),
  log_dropped: z
    .object({
      /** look-back window for new drops */
      windowSec: z.number().int().min(60).max(86_400).default(300),
      minEntries: z.number().int().min(1).max(1_000_000_000).default(1),
    })
    .strict(),
  backup_failed: z.object({}).strict(),
} satisfies Record<AlertKind, z.ZodTypeAny>;

/** Kinds evaluated by the alert engine (all of them since P6 activated `backup_failed`). */
export const ACTIVE_ALERT_KINDS: readonly AlertKind[] = [
  'server_offline',
  'metric_threshold',
  'app_down',
  'log_dropped',
  'backup_failed',
];

/** Which scope types each kind accepts. */
export const ALERT_KIND_SCOPES: Record<AlertKind, readonly AlertScopeType[]> = {
  server_offline: ['global', 'environment', 'server'],
  metric_threshold: ['global', 'environment', 'server'],
  app_down: ['global', 'environment', 'server', 'app'],
  log_dropped: ['global', 'environment', 'server'],
  backup_failed: ['global', 'environment', 'server', 'app'],
};

const alertRuleBase = {
  name: z.string().trim().min(1).max(120),
  enabled: z.boolean().default(true),
  scopeType: z.enum(ALERT_SCOPE_TYPES),
  scopeId: z.string().max(64).nullish(),
  params: z.record(z.unknown()).default({}),
  severity: z.enum(ALERT_SEVERITIES).default('warning'),
  /** omitted → 60, or SERVER_OFFLINE_MIN_FOR_SEC for server_offline */
  forSec: z.number().int().min(0).max(86_400).optional(),
  channelIds: z.array(z.string().uuid()).max(10).default([]),
};

function refineScope(
  v: { scopeType: AlertScopeType; scopeId?: string | null },
  kind: AlertKind,
  ctx: z.RefinementCtx,
): void {
  if (!ALERT_KIND_SCOPES[kind].includes(v.scopeType))
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['scopeType'],
      message: `${kind} supports scopes ${ALERT_KIND_SCOPES[kind].join(', ')}`,
    });
  if (v.scopeType === 'global' && v.scopeId)
    ctx.addIssue({ code: 'custom', path: ['scopeId'], message: 'global scope has no scopeId' });
  if (
    v.scopeType === 'environment' &&
    !(ENVIRONMENTS as readonly string[]).includes(v.scopeId ?? '')
  )
    ctx.addIssue({
      code: 'custom',
      path: ['scopeId'],
      message: `scopeId must be one of ${ENVIRONMENTS.join(', ')}`,
    });
  if (
    (v.scopeType === 'server' || v.scopeType === 'app') &&
    !z.string().uuid().safeParse(v.scopeId).success
  )
    ctx.addIssue({ code: 'custom', path: ['scopeId'], message: 'scopeId must be a uuid' });
}

/** Validates `params` for `kind` and returns the normalised params (defaults applied). */
export function parseAlertParams(
  kind: AlertKind,
  params: unknown,
):
  | { success: true; data: Record<string, unknown> }
  | { success: false; issues: Array<{ path: string; message: string }> } {
  const r = alertParamsSchemas[kind].safeParse(params ?? {});
  if (r.success) return { success: true, data: r.data as Record<string, unknown> };
  return {
    success: false,
    issues: r.error.issues.map((i) => ({
      path: ['params', ...i.path].join('.'),
      message: i.message,
    })),
  };
}

export const createAlertRuleSchema = z
  .object({ ...alertRuleBase, kind: z.enum(ALERT_KINDS) })
  .strict()
  .superRefine((v, ctx) => {
    refineScope(v, v.kind, ctx);
    const p = parseAlertParams(v.kind, v.params);
    if (!p.success)
      for (const i of p.issues)
        ctx.addIssue({ code: 'custom', path: i.path.split('.'), message: i.message });
    const f = forSecIssue(v.kind, v.forSec);
    if (f) ctx.addIssue({ code: 'custom', path: ['forSec'], message: f });
  })
  .transform((v) => ({
    ...v,
    forSec:
      v.forSec ??
      (v.kind === 'server_offline' ? SERVER_OFFLINE_MIN_FOR_SEC : DEFAULT_ALERT_FOR_SEC),
  }));
export type CreateAlertRuleInput = z.infer<typeof createAlertRuleSchema>;

/** PATCH: any field except `kind` (scope/params re-validated against the stored kind). */
export const updateAlertRuleSchema = z
  .object({
    name: alertRuleBase.name.optional(),
    enabled: z.boolean().optional(),
    scopeType: z.enum(ALERT_SCOPE_TYPES).optional(),
    scopeId: z.string().max(64).nullish(),
    params: z.record(z.unknown()).optional(),
    severity: z.enum(ALERT_SEVERITIES).optional(),
    forSec: z.number().int().min(0).max(86_400).optional(),
    channelIds: z.array(z.string().uuid()).max(10).optional(),
  })
  .strict();
export type UpdateAlertRuleInput = z.infer<typeof updateAlertRuleSchema>;

/** Validates a merged (stored + patch) rule. */
export function validateAlertRule(v: {
  kind: AlertKind;
  scopeType: AlertScopeType;
  scopeId?: string | null;
  params: unknown;
  /** validated only when given (a PATCH that changes it) */
  forSec?: number;
}): Array<{ path: string; message: string }> {
  const issues: Array<{ path: string; message: string }> = [];
  const ctx = {
    addIssue: (i: { path?: (string | number)[]; message?: string }) =>
      issues.push({ path: (i.path ?? []).join('.'), message: i.message ?? 'invalid' }),
    path: [],
  } as unknown as z.RefinementCtx;
  refineScope(v, v.kind, ctx);
  const p = parseAlertParams(v.kind, v.params);
  if (!p.success) issues.push(...p.issues);
  const f = forSecIssue(v.kind, v.forSec);
  if (f) issues.push({ path: 'forSec', message: f });
  return issues;
}

export type AlertRuleAction = 'edit' | 'delete';

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  scopeType: AlertScopeType;
  scopeId: string | null;
  kind: AlertKind;
  params: Record<string, unknown>;
  severity: AlertSeverity;
  forSec: number;
  channelIds: string[];
  /** false for kinds accepted but not evaluated yet (none since P6) */
  active: boolean;
  createdBy: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  allowedActions: AlertRuleAction[];
}

export const INCIDENT_STATUSES = ['firing', 'acknowledged', 'resolved'] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export const INCIDENT_TARGET_TYPES = ['server', 'app', 'backup_policy'] as const;
export type IncidentTargetType = (typeof INCIDENT_TARGET_TYPES)[number];
export const INCIDENT_EVENT_TYPES = [
  'fired',
  'notified',
  'notify_failed',
  'acknowledged',
  'resolved',
  'comment',
] as const;
export type IncidentEventType = (typeof INCIDENT_EVENT_TYPES)[number];

export interface IncidentEvent {
  at: string;
  type: IncidentEventType;
  actor: { id: string; displayName: string } | null;
  detail: Record<string, unknown>;
}

export type IncidentAction = 'acknowledge' | 'comment';

export interface Incident {
  id: string;
  ruleId: string | null;
  ruleName: string;
  kind: AlertKind;
  target: { type: IncidentTargetType; id: string; name: string };
  serverId: string;
  environment: Environment;
  severity: AlertSeverity;
  status: IncidentStatus;
  startedAt: string;
  acknowledgedAt: string | null;
  acknowledgedBy: { id: string; displayName: string } | null;
  resolvedAt: string | null;
  lastValue: number | null;
  /** detail endpoint only (`GET /incidents/:id`); list items omit it */
  timeline?: IncidentEvent[];
  allowedActions: IncidentAction[];
}

export const acknowledgeIncidentSchema = z
  .object({ comment: z.string().trim().min(1).max(2000).optional() })
  .strict();
export const incidentCommentSchema = z
  .object({ comment: z.string().trim().min(1).max(2000) })
  .strict();

// -------------------------------------------------------------------------- notification channels

export const CHANNEL_TYPES = ['webhook', 'email', 'telegram'] as const;
export type ChannelType = (typeof CHANNEL_TYPES)[number];

export const webhookChannelConfigSchema = z
  .object({
    url: z.string().trim().url().max(2048),
    /** HMAC-SHA256 key for `X-PPanel-Signature`; stored encrypted, never returned */
    signingSecret: z.string().min(16).max(256),
  })
  .strict();
export const emailChannelConfigSchema = z
  .object({ to: z.array(z.string().trim().email().max(254)).min(1).max(10) })
  .strict();
export const telegramChannelConfigSchema = z
  .object({
    botToken: z.string().regex(/^\d{3,20}:[A-Za-z0-9_-]{20,100}$/, 'invalid bot token format'),
    chatId: z.string().regex(/^(?:-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/, 'invalid chat id'),
  })
  .strict();

export const CHANNEL_CONFIG_SCHEMAS = {
  webhook: webhookChannelConfigSchema,
  email: emailChannelConfigSchema,
  telegram: telegramChannelConfigSchema,
} as const;
/** Config fields that are secrets: stored encrypted, returned as `{ set: true }`. */
export const CHANNEL_SECRET_FIELDS: Record<ChannelType, readonly string[]> = {
  webhook: ['signingSecret'],
  email: [],
  telegram: ['botToken'],
};

export const createChannelSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('webhook'),
      name: z.string().trim().min(1).max(120),
      enabled: z.boolean().default(true),
      config: webhookChannelConfigSchema,
    })
    .strict(),
  z
    .object({
      type: z.literal('email'),
      name: z.string().trim().min(1).max(120),
      enabled: z.boolean().default(true),
      config: emailChannelConfigSchema,
    })
    .strict(),
  z
    .object({
      type: z.literal('telegram'),
      name: z.string().trim().min(1).max(120),
      enabled: z.boolean().default(true),
      config: telegramChannelConfigSchema,
    })
    .strict(),
]);
export type CreateChannelInput = z.infer<typeof createChannelSchema>;

/** PATCH: `config` keys are merged over the stored config (omit a secret to keep it). */
export const updateChannelSchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    enabled: z.boolean().optional(),
    config: z.record(z.unknown()).optional(),
  })
  .strict();
export type UpdateChannelInput = z.infer<typeof updateChannelSchema>;

export type SecretFlag = { set: true };

export type ChannelConfigView =
  | { url: string; signingSecret: SecretFlag } // webhook: URL path/query masked
  | { to: string[] } // email
  | { chatId: string; botToken: SecretFlag }; // telegram

export interface NotificationChannel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: ChannelConfigView;
  lastDelivery: {
    at: string;
    status: 'delivered' | 'failed';
    error: string | null;
  } | null;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface ChannelTestResult {
  delivered: boolean;
  error?: string;
  deliveryId: string;
}

/** Webhook body (`X-PPanel-Signature: sha256=<hex HMAC(body)>`, `X-PPanel-Event: <event>`). */
export interface WebhookNotificationBody {
  event: 'fired' | 'resolved' | 'test';
  sentAt: string;
  incident: {
    id: string;
    ruleId: string | null;
    ruleName: string;
    kind: AlertKind;
    severity: AlertSeverity;
    status: IncidentStatus;
    target: { type: IncidentTargetType; id: string; name: string };
    environment: string;
    startedAt: string;
    resolvedAt: string | null;
    lastValue: number | null;
    url: string;
  } | null;
}
