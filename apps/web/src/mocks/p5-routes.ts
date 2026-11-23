/**
 * Mock routes for API_CONTRACTS §9 (P5): fleet metrics + series (null gaps, stale), central log query
 * (scope, retention, cursor, redaction, 429), single-use tail tokens (the SSE stream itself is
 * `mock-event-source.ts`), alert rules (If-Match), incidents (ack / comment / timeline) and
 * notification channels (write-only secrets, SSRF hints, test).
 *
 * Fixtures for distinct states (D4-A): worker-uat-01 is offline, db-prod-01 is stale, dev-sandbox-02
 * is online but has never reported metrics, app-prod-01 has a short metrics gap ~25 minutes ago.
 * Test hooks: log query `q=simulate-429` → 429 Retry-After 3; webhook URL containing "fail", email
 * containing "bounce" or Telegram chat id "0" → channel test fails.
 */
import {
  METRIC_AUTO_STEP_SECONDS,
  METRIC_RANGE_SECONDS,
  redactLine,
  type Server,
} from '@ppanel/shared-contracts';
import type { Application } from '@/lib/api/p3-types';
import {
  LOG_LEVELS,
  LOG_SOURCES,
  type AlertRule,
  type ChannelType,
  type Incident,
  type IncidentTimelineEntry,
  type LogEntry,
  type LogLevel,
  type MetricPoint,
  type MetricRange,
  type NotificationChannel,
  type RuleKind,
  type Severity,
} from '@/lib/api/p5-types';
import { p3Internals, type P3Ctx } from './p3-routes';
import { p4Internals } from './p4-routes';

const KEY = 'ppanel.mock.p5';
export const RETENTION_DAYS = 7;
const LOG_STEP_SEC = 20;
const NO_METRICS = 'dev-sandbox-02';
const GAP_SERVER = 'app-prod-01';
const WEBHOOK_HTTP_ALLOW = ['receiver.lab', 'hooks.lab.local'];

interface U {
  id: string;
  displayName: string;
}
/** Stored channel: plain config + "secret set" flags (secret values are never kept). */
interface ChannelRec {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  version: number;
  createdAt: string;
  updatedAt: string;
  lastDelivery: NotificationChannel['lastDelivery'];
  cfg: { url?: string; to?: string[]; chatId?: string };
  secrets: { signingSecret?: boolean; botToken?: boolean };
}
type MockIncident = Omit<Incident, 'timeline' | 'allowedActions'> & {
  timeline: IncidentTimelineEntry[];
};
interface P5State {
  rules: AlertRule[];
  incidents: MockIncident[];
  channels: ChannelRec[];
  tokens: Record<string, { userId: string; params: string; exp: number; used: boolean }>;
}

let st: P5State | null = null;
let ctx: P3Ctx;
const rate: Record<string, number[]> = {};
const activeTails: Record<string, number> = {};

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}
function save() {
  try {
    storage()?.setItem(KEY, JSON.stringify(st));
  } catch {
    /* memory only */
  }
}
export function resetP5State() {
  st = null;
  for (const k of Object.keys(rate)) delete rate[k];
  for (const k of Object.keys(activeTails)) delete activeTails[k];
  storage()?.removeItem(KEY);
}
function s(): P5State {
  p4Internals.state();
  if (!st) {
    const raw = storage()?.getItem(KEY);
    if (raw)
      try {
        st = JSON.parse(raw) as P5State;
      } catch {
        st = null;
      }
    if (!st) {
      st = seed();
      save();
    }
  }
  return st;
}

const iso = (ms: number) => new Date(ms).toISOString();
const apps = (): Application[] => p3Internals.state().apps;
const userOf = (id: string | null): U =>
  (ctx.users().find((x) => x.id === id) ?? ctx.users()[0]!) as U;
const can = (u: U, perm: Parameters<P3Ctx['hasPermFor']>[1], srv?: Server) =>
  ctx.hasPermFor(u as never, perm, srv);
const need = (u: U, perm: Parameters<P3Ctx['requirePerm']>[1], srv?: Server) =>
  ctx.requirePerm(u as never, perm, srv);
const byName = (n: string) => ctx.servers().find((x) => x.name === n);
const srvOf = (id: string) => ctx.servers().find((x) => x.id === id);

/** Deterministic [0,1) hash. */
function h01(str: string): number {
  let x = 2166136261;
  for (let i = 0; i < str.length; i++) {
    x ^= str.charCodeAt(i);
    x = Math.imul(x, 16777619);
  }
  return ((x >>> 0) % 100000) / 100000;
}

function limitRate(u: U, bucket: string, perMin: number) {
  const k = `${u.id}:${bucket}`;
  const now = Date.now();
  const arr = (rate[k] = (rate[k] ?? []).filter((t) => now - t < 60e3));
  if (arr.length >= perMin) {
    const retryAfterSec = Math.max(1, Math.ceil((60e3 - (now - arr[0]!)) / 1000));
    throw new ctx.HttpError(429, 'RATE_LIMITED', `Too many ${bucket} queries; try again shortly`, {
      retryAfterSec,
    });
  }
  arr.push(now);
}

// ---------------------------------------------------------------- metrics

/** When samples stop for this server (ms), or null if it is live. */
function samplesEndAt(srv: Server): number | null {
  if (srv.status === 'offline' || srv.status === 'stale' || srv.status === 'revoked')
    return srv.lastHeartbeatAt ? new Date(srv.lastHeartbeatAt).getTime() : 0;
  return null;
}
const noMetrics = (srv: Server) => srv.name === NO_METRICS;

function fleetRow(srv: Server) {
  const stale = srv.status === 'stale' || srv.status === 'offline' || !!srv.metrics?.stale;
  const m = srv.metrics;
  return {
    serverId: srv.id,
    name: srv.name,
    environment: srv.environment,
    status: srv.status,
    sample:
      noMetrics(srv) || !m
        ? null
        : {
            cpuPct: m.cpuPct,
            memPct: m.memPct,
            diskPct: m.diskPct,
            load1: m.load1 ?? null,
            sampledAt: m.sampledAt,
          },
    stale,
    containers: (() => {
      const total = serverApps(srv.id).length;
      const live = samplesEndAt(srv) === null;
      return { total, running: live ? total : 0, unhealthy: 0 };
    })(),
    logShipping: null,
    logDroppedTotal: srv.name === 'web-legacy-02' ? 128 : 0,
  };
}

const RANGE: Record<MetricRange, { span: number; step: number }> = {
  '1h': { span: METRIC_RANGE_SECONDS['1h'], step: METRIC_AUTO_STEP_SECONDS['1h'] },
  '6h': { span: METRIC_RANGE_SECONDS['6h'], step: METRIC_AUTO_STEP_SECONDS['6h'] },
  '24h': { span: METRIC_RANGE_SECONDS['24h'], step: METRIC_AUTO_STEP_SECONDS['24h'] },
  '7d': { span: METRIC_RANGE_SECONDS['7d'], step: METRIC_AUTO_STEP_SECONDS['7d'] },
};
const UNIT: Record<string, string> = {
  cpu: 'percent',
  memory: 'percent',
  disk: 'percent',
  load1: 'load',
  net_rx: 'bytes_per_second',
  net_tx: 'bytes_per_second',
  up: 'bool',
  restarts: 'count',
};

function serverValue(srv: Server, metric: string, t: number): number {
  const m = srv.metrics;
  const n = h01(`${srv.id}|${metric}|${Math.floor(t / 60)}`);
  const wave = Math.sin(t / 1800 + h01(srv.id) * 6);
  const clamp = (v: number) => Math.max(0, Math.min(100, Math.round(v * 10) / 10));
  switch (metric) {
    case 'cpu':
      return clamp((m?.cpuPct ?? 25) + wave * 8 + (n - 0.5) * 10);
    case 'memory':
      return clamp((m?.memPct ?? 40) + wave * 3 + (n - 0.5) * 3);
    case 'disk':
      return clamp((m?.diskPct ?? 40) - ((Date.now() / 1000 - t) / 86400) * 0.6);
    case 'load1':
      return Math.round((0.3 + ((m?.cpuPct ?? 20) / 30) * (1 + wave * 0.3) + n * 0.4) * 100) / 100;
    case 'net_rx':
      return Math.round((200 + n * 900 + wave * 150) * 1024);
    case 'net_tx':
      return Math.round((80 + n * 400 + wave * 60) * 1024);
    default:
      return 1;
  }
}

function seriesFor(
  kind: 'server' | 'app',
  srv: Server,
  app: Application | null,
  metric: string,
  range: MetricRange,
) {
  const { span, step } = RANGE[range];
  const now = Math.floor(Date.now() / 1000 / step) * step;
  const end = samplesEndAt(srv);
  const gapFrom = Date.now() / 1000 - 31 * 60;
  const gapTo = Date.now() / 1000 - 25 * 60;
  const points: MetricPoint[] = [];
  for (let t = now - span + step; t <= now; t += step) {
    let v: number | null;
    const missing =
      noMetrics(srv) ||
      (end !== null && t * 1000 > end) ||
      (srv.name === GAP_SERVER && t >= gapFrom && t <= gapTo);
    if (metric === 'up') {
      // `up` is always exported: 0 while offline/stale, never a gap after enrollment.
      v = noMetrics(srv) ? null : end !== null && t * 1000 > end ? 0 : 1;
    } else if (missing) v = null;
    else if (kind === 'app') {
      const n = h01(`${app!.id}|${metric}|${Math.floor(t / 60)}`);
      v =
        metric === 'cpu'
          ? Math.round((6 + n * 14) * 10) / 10
          : metric === 'memory'
            ? Math.round((180 + n * 140) * 1024 * 1024)
            : metric === 'restarts'
              ? t > Date.now() / 1000 - 3 * 3600 && app!.name === 'shop-api'
                ? 2
                : 0
              : 1;
    } else v = serverValue(srv, metric, t);
    points.push([t, v]);
  }
  const gaps: Array<[number, number]> = [];
  let start: number | null = null;
  for (const [t, v] of points) {
    if (v === null && start === null) start = t;
    if (v !== null && start !== null) {
      gaps.push([start, t]);
      start = null;
    }
  }
  if (start !== null) gaps.push([start, now]);
  const lastReal = [...points]
    .reverse()
    .find(([t, v]) => v !== null && (metric !== 'up' || end === null || t * 1000 <= end));
  return {
    scope: kind,
    id: kind === 'app' ? app!.id : srv.id,
    range,
    step,
    from: now - span + step,
    to: now,
    metric,
    unit: kind === 'app' && metric === 'memory' ? 'bytes' : (UNIT[metric] ?? 'count'),
    points,
    gaps,
    lastSampleAt: noMetrics(srv)
      ? null
      : end !== null
        ? iso(end)
        : lastReal
          ? iso(lastReal[0] * 1000)
          : null,
    stale: end !== null,
  };
}

// ---------------------------------------------------------------- logs

type Tpl = [LogEntry['source'], LogLevel, string, boolean /* app line */];
const TEMPLATES: Tpl[] = [
  [
    'nginx_access',
    'info',
    '10.104.0.5 - - "GET /api/products HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    false,
  ],
  [
    'nginx_access',
    'info',
    '10.104.0.7 - - "GET /healthz HTTP/1.1" 200 2 "-" "ppanel-agent/0.4"',
    false,
  ],
  [
    'nginx_access',
    'warn',
    '10.104.0.9 - - "GET /api/orders?api_key=sk_live_51HxT2qLmN8 HTTP/1.1" 401 64 "-" "curl/8.5"',
    false,
  ],
  [
    'nginx_error',
    'error',
    'upstream timed out (110: Connection timed out) while reading response header',
    false,
  ],
  ['nginx_error', 'warn', '<script>alert("pwned")</script> rejected by request filter', false],
  ['agent', 'info', 'heartbeat ok rtt=18ms', false],
  ['agent', 'info', 'log shipper: batch sent entries=128 dropped=0', false],
  ['agent', 'warn', 'log shipper: buffer 71% full, center slow (503), retrying', false],
  ['agent', 'info', 'systemd[1]: Started Daily apt download activities.', false],
  [
    'agent',
    'warn',
    'kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.50 DST=10.104.0.11 PROTO=TCP DPT=22',
    false,
  ],
  ['agent', 'error', 'sshd[2231]: Failed password for invalid user admin from 203.0.113.50', false],
  ['container', 'info', 'GET /api/products 200 23ms', true],
  ['container', 'info', 'POST /api/checkout 201 184ms', true],
  ['container', 'warn', 'stripe: retrying request token=tok_9f8e7d6c5b4a', true],
  [
    'container',
    'error',
    'db: connection reset by peer (postgres://shop:hunter2pass@10.104.0.21:5432/shop)',
    true,
  ],
  ['container', 'debug', 'cache miss key=product:4411', true],
  ['container', 'info', 'deployment health check passed (3/3)', true],
];
const LEVEL_RANK: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 };

function serverApps(srvId: string) {
  return apps().filter(
    (a) => a.serverId === srvId && (a.kind === 'container' || a.kind === 'compose'),
  );
}

/** The one generated entry for (server, slot), or null when the slot is quiet. */
function entryAt(srv: Server, slot: number, forceApp?: Application): LogEntry | null {
  const r = h01(`${srv.id}|${slot}`);
  if (r < 0.35) return null;
  const appsHere = forceApp ? [forceApp] : serverApps(srv.id);
  const pool = forceApp ? TEMPLATES.filter((x) => x[3]) : TEMPLATES;
  let tpl = pool[Math.floor(h01(`${srv.id}|tpl|${slot}`) * pool.length)]!;
  if (tpl[3] && appsHere.length === 0) tpl = TEMPLATES[(slot >>> 0) % 11]!;
  const app = tpl[3] ? appsHere[Math.floor(r * 1000) % appsHere.length]! : null;
  const ms = slot * LOG_STEP_SEC * 1000 + Math.floor(h01(`${srv.id}|ms|${slot}`) * 19000);
  return {
    ts: iso(ms),
    serverId: srv.id,
    appId: app?.id ?? null,
    source: tpl[0],
    level: tpl[1],
    line: redactLine(tpl[2]),
  };
}

interface LogFilter {
  servers: Server[];
  app: Application | null;
  source: string | null;
  level: LogLevel | null;
  q: string | null;
}
function matches(e: LogEntry, f: LogFilter) {
  if (f.app && e.appId !== f.app.id) return false;
  if (f.source && e.source !== f.source) return false;
  if (f.level && (e.level === null || LEVEL_RANK[e.level] < LEVEL_RANK[f.level])) return false;
  if (f.q && !e.line.toLowerCase().includes(f.q.toLowerCase())) return false;
  return true;
}
function liveUntil(srv: Server): number {
  return samplesEndAt(srv) ?? Date.now();
}

function resolveLogScope(u: U, url: URL): LogFilter {
  const serverId = url.searchParams.get('serverId');
  const appId = url.searchParams.get('appId');
  const source = url.searchParams.get('source');
  const level = url.searchParams.get('level') as LogLevel | null;
  const q = url.searchParams.get('q');
  const errs: Array<{ field: string; message: string }> = [];
  if (source && !(LOG_SOURCES as readonly string[]).includes(source))
    errs.push({ field: 'source', message: 'Unknown source' });
  if (level && !(LOG_LEVELS as readonly string[]).includes(level))
    errs.push({ field: 'level', message: 'Unknown level' });
  if (q && q.length > 200) errs.push({ field: 'q', message: 'At most 200 characters' });
  for (const k of ['query', 'logql', 'expr'])
    if (url.searchParams.has(k)) errs.push({ field: k, message: 'Raw queries are not accepted' });
  if (errs.length) throw new ctx.HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
  let app: Application | null = null;
  let servers: Server[];
  if (appId) {
    app = apps().find((a) => a.id === appId) ?? null;
    const srv = app ? srvOf(app.serverId) : undefined;
    if (!app || !srv || !can(u, 'apps.read', srv))
      throw new ctx.HttpError(404, 'NOT_FOUND', 'Application not found');
    servers = [srv];
    if (serverId && serverId !== srv.id) servers = [];
  } else if (serverId) {
    const srv = srvOf(serverId);
    if (!srv || !can(u, 'fleet.read', srv))
      throw new ctx.HttpError(404, 'NOT_FOUND', 'Server not found');
    servers = [srv];
  } else {
    // Global fleet.read only: the Center adds server_id=~"<ids in scope>".
    const global = ctx.servers().every((x) => can(u, 'fleet.read', x));
    if (!global)
      throw new ctx.HttpError(422, 'VALIDATION_FAILED', 'Pick a server or application', [
        { field: 'serverId', message: 'Required for scoped access' },
      ]);
    servers = ctx.servers().filter((x) => can(u, 'fleet.read', x));
  }
  return { servers, app, source, level, q };
}

function queryLogs(
  f: LogFilter,
  fromMs: number,
  toMs: number,
  limit: number,
  dir: string,
  cursor: string | null,
) {
  const retentionStart = Date.now() - RETENTION_DAYS * 864e5;
  const lo = Math.max(fromMs, retentionStart);
  const out: LogEntry[] = [];
  if (lo >= toMs || f.servers.length === 0) return { items: out, hasMore: false };
  const cur =
    cursor && /^\d{1,20}$/.test(cursor) ? Number(BigInt(cursor) / BigInt(1_000_000)) : null;
  const step = LOG_STEP_SEC * 1000;
  const first = dir === 'forward' ? Math.floor(lo / step) : Math.floor(toMs / step);
  const last = dir === 'forward' ? Math.floor(toMs / step) : Math.floor(lo / step);
  const inc = dir === 'forward' ? 1 : -1;
  let scanned = 0;
  for (let slot = first; dir === 'forward' ? slot <= last : slot >= last; slot += inc) {
    if (++scanned > 40000) break;
    const batch: LogEntry[] = [];
    for (const srv of f.servers) {
      if (slot * step > liveUntil(srv)) continue;
      const e = entryAt(srv, slot, f.app ?? undefined);
      if (!e) continue;
      const t = new Date(e.ts).getTime();
      if (t < lo || t > toMs) continue;
      if (cur !== null && (dir === 'forward' ? t <= cur : t >= cur)) continue;
      if (matches(e, f)) batch.push(e);
    }
    batch.sort((a, b) => (dir === 'forward' ? a.ts.localeCompare(b.ts) : b.ts.localeCompare(a.ts)));
    out.push(...batch);
    if (out.length > limit) break;
  }
  return { items: out.slice(0, limit), hasMore: out.length > limit };
}

/** Lines streamed by the mock SSE for a validated tail (ts = now). */
function liveLines(u: U, params: URLSearchParams, seq: number): LogEntry[] {
  const fakeUrl = new URL(`http://mock/logs/tail?${params.toString()}`);
  let f: LogFilter;
  try {
    f = resolveLogScope(u, fakeUrl);
  } catch {
    return [];
  }
  const live = f.servers.filter((x) => samplesEndAt(x) === null);
  if (!live.length) return [];
  const out: LogEntry[] = [];
  for (let i = 0; i < 3 && out.length < 2; i++) {
    const srv = live[(seq + i) % live.length]!;
    const pool = f.app ? TEMPLATES.filter((x) => x[3]) : TEMPLATES;
    const tpl = pool[(seq * 7 + i * 3) % pool.length]!;
    const appsHere = f.app ? [f.app] : serverApps(srv.id);
    const app = tpl[3] && appsHere.length ? appsHere[seq % appsHere.length]! : null;
    if (tpl[3] && !app) continue;
    const e: LogEntry = {
      ts: iso(Date.now() + i),
      serverId: srv.id,
      appId: app?.id ?? null,
      source: tpl[0],
      level: tpl[1],
      line: redactLine(tpl[2]),
    };
    if (matches(e, f)) out.push(e);
  }
  return out;
}

export const p5Internals = {
  /** Validate + consume a single-use tail token for the mock EventSource. */
  consumeTail(
    token: string,
    params: URLSearchParams,
  ): { ok: true; user: U } | { ok: false; code: string } {
    const rec = s().tokens[token];
    const p = new URLSearchParams(params);
    p.delete('token');
    p.delete('lastEventId');
    if (!rec) return { ok: false, code: 'TAIL_TOKEN_INVALID' };
    if (rec.used) return { ok: false, code: 'TAIL_TOKEN_USED' };
    if (rec.exp < Date.now()) return { ok: false, code: 'TAIL_TOKEN_EXPIRED' };
    if (rec.params !== canonical(p)) return { ok: false, code: 'TAIL_TOKEN_PARAMS' };
    rec.used = true;
    save();
    activeTails[rec.userId] = (activeTails[rec.userId] ?? 0) + 1;
    return { ok: true, user: userOf(rec.userId) };
  },
  releaseTail(userId: string) {
    activeTails[userId] = Math.max(0, (activeTails[userId] ?? 1) - 1);
  },
  liveLines,
};

function canonical(p: URLSearchParams): string {
  const keys = ['serverId', 'appId', 'source', 'level', 'q'];
  return keys.map((k) => `${k}=${p.get(k) ?? ''}`).join('&');
}

// ---------------------------------------------------------------- alerts seed

function seed(): P5State {
  const [owner, admin] = [ctx.users()[0]!, ctx.users()[1]!];
  const now = Date.now();
  const ch = (
    id: string,
    name: string,
    type: ChannelType,
    cfg: ChannelRec['cfg'],
    secrets: ChannelRec['secrets'],
  ): ChannelRec => ({
    id,
    name,
    type,
    cfg,
    enabled: true,
    version: 1,
    createdAt: iso(now - 30 * 864e5),
    updatedAt: iso(now - 30 * 864e5),
    lastDelivery: null,
    secrets,
  });
  const channels = [
    ch(
      '01934f2a-e001-7000-8000-000000000001',
      'ops-webhook',
      'webhook',
      { url: 'https://hooks.example.com/ppanel' },
      { signingSecret: true },
    ),
    ch(
      '01934f2a-e001-7000-8000-000000000002',
      'ops-email',
      'email',
      { to: ['ops@example.com'] },
      {},
    ),
    ch(
      '01934f2a-e001-7000-8000-000000000003',
      'ops-telegram',
      'telegram',
      { chatId: '-1001234567890' },
      { botToken: true },
    ),
  ];
  const rule = (
    n: number,
    name: string,
    kind: RuleKind,
    params: AlertRule['params'],
    severity: Severity,
    forSec: number,
    channelIds: string[],
    scopeType: AlertRule['scopeType'] = 'global',
    scopeId: string | null = null,
  ): AlertRule => ({
    id: `01934f2a-e002-7000-8000-00000000000${n}`,
    name,
    enabled: true,
    scopeType,
    scopeId,
    kind,
    params,
    severity,
    forSec,
    channelIds,
    createdBy: owner.id,
    version: 1,
    createdAt: iso(now - 20 * 864e5),
    updatedAt: iso(now - 20 * 864e5),
  });
  const rules = [
    rule(
      1,
      'disk-high',
      'metric_threshold',
      { metric: 'disk', op: 'gt', value: 90 },
      'critical',
      300,
      [channels[0]!.id, channels[2]!.id],
    ),
    rule(2, 'agent-lost', 'server_offline', {}, 'critical', 300, [
      channels[0]!.id,
      channels[1]!.id,
    ]),
    rule(3, 'app-down', 'app_down', {}, 'warning', 60, [channels[2]!.id]),
    rule(4, 'log-dropped', 'log_dropped', {}, 'info', 0, []),
  ];
  const srv = (n: string) => byName(n)!;
  const actor = (u: U) => ({ id: u.id, displayName: u.displayName });
  const tl = (
    at: number,
    type: IncidentTimelineEntry['type'],
    detail: Record<string, unknown>,
    who?: U,
  ): IncidentTimelineEntry => ({
    at: iso(at),
    type,
    actor: who ? actor(who) : null,
    detail,
  });
  const inc = (
    n: number,
    r: AlertRule,
    target: Incident['target'] & { srv: Server },
    status: Incident['status'],
    startedAgoMin: number,
    lastValue: Incident['lastValue'],
    timeline: IncidentTimelineEntry[],
    extra: Partial<MockIncident> = {},
  ): MockIncident => ({
    id: `01934f2a-e003-7000-8000-00000000000${n}`,
    ruleId: r.id,
    ruleName: r.name,
    kind: r.kind,
    target: { type: target.type, id: target.id, name: target.name },
    serverId: target.srv.id,
    environment: target.srv.environment,
    severity: r.severity,
    status,
    startedAt: iso(now - startedAgoMin * 60e3),
    acknowledgedAt: null,
    acknowledgedBy: null,
    resolvedAt: null,
    lastValue,
    timeline,
    ...extra,
  });
  const legacy = srv('web-legacy-02');
  const worker = srv('worker-uat-01');
  const db = srv('db-prod-01');
  const shop = apps().find((a) => a.name === 'shop-api');
  const t = (m: number) => now - m * 60e3;
  const incidents: MockIncident[] = [
    inc(
      1,
      rules[0]!,
      { type: 'server', id: legacy.id, name: legacy.name, srv: legacy },
      'firing',
      22,
      91.4,
      [
        tl(t(22), 'fired', { message: 'disk 91.4% > 90% for 5m', value: 91.4 }),
        tl(t(22) + 4000, 'notified', { channel: 'ops-webhook', status: 200 }),
        tl(t(22) + 5000, 'notify_failed', {
          channel: 'ops-telegram',
          error: '502 from api.telegram.org (retry 3/3)',
        }),
      ],
    ),
    inc(
      2,
      rules[1]!,
      { type: 'server', id: worker.id, name: worker.name, srv: worker },
      'firing',
      16,
      null,
      [
        tl(t(16), 'fired', { message: 'offline for ≥ 300s (last heartbeat)' }),
        tl(t(16) + 3000, 'notified', { channel: 'ops-webhook', status: 200 }),
        tl(t(16) + 3500, 'notified', { channel: 'ops-email', status: 'queued' }),
      ],
    ),
    inc(
      3,
      rules[1]!,
      { type: 'server', id: db.id, name: db.name, srv: db },
      'acknowledged',
      9,
      null,
      [
        tl(t(9), 'fired', { message: 'stale for ≥ 300s' }),
        tl(t(9) + 3000, 'notified', { channel: 'ops-webhook', status: 200 }),
        tl(
          t(4),
          'acknowledged',
          { comment: 'Looking at the VPC route, agent restart pending' },
          admin as U,
        ),
      ],
      { acknowledgedAt: iso(t(4)), acknowledgedBy: actor(admin as U) },
    ),
  ];
  if (shop) {
    const ss = srvOf(shop.serverId)!;
    incidents.push(
      inc(
        4,
        rules[2]!,
        { type: 'app', id: shop.id, name: shop.name, srv: ss },
        'resolved',
        26 * 60,
        null,
        [
          tl(t(26 * 60), 'fired', {
            message: 'deployment #3 unhealthy (health check /healthz 500)',
          }),
          tl(t(26 * 60) + 2000, 'notified', { channel: 'ops-telegram', status: 200 }),
          tl(t(25 * 60), 'resolved', { message: 'container healthy again (rolled back to #2)' }),
        ],
        { resolvedAt: iso(t(25 * 60)) },
      ),
    );
  }
  return { rules, incidents, channels, tokens: {} };
}

// ---------------------------------------------------------------- views

function incidentServer(i: MockIncident) {
  return srvOf(i.serverId);
}
/** List items omit the timeline (contract: detail endpoint only). */
function incidentView(u: U, i: MockIncident, withTimeline: boolean): Incident {
  const srv = incidentServer(i);
  const allowed: Incident['allowedActions'] = [];
  if (srv && can(u, 'fleet.read', srv) && can(u, 'servers.operate', srv)) {
    allowed!.push('comment');
    if (i.status === 'firing') allowed!.push('acknowledge');
  }
  const { timeline, ...rest } = i;
  return { ...rest, ...(withTimeline ? { timeline } : {}), allowedActions: allowed };
}
function channelView(c: ChannelRec): NotificationChannel {
  const config: NotificationChannel['config'] =
    c.type === 'webhook'
      ? { url: c.cfg.url ?? '', signingSecret: { set: true } }
      : c.type === 'email'
        ? { to: c.cfg.to ?? [] }
        : { chatId: c.cfg.chatId ?? '', botToken: { set: true } };
  return {
    id: c.id,
    name: c.name,
    type: c.type,
    enabled: c.enabled,
    config,
    lastDelivery: c.lastDelivery,
    version: c.version,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
  };
}

const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|\[?::1\]?$|metadata\.google\.internal)/i;

function validateChannel(body: Record<string, unknown>, existing?: ChannelRec) {
  const errs: Array<{ field: string; message: string }> = [];
  const type = (body.type ?? existing?.type) as ChannelType;
  const name = String(body.name ?? existing?.name ?? '').trim();
  if (!name || name.length > 120) errs.push({ field: 'name', message: '1–120 characters' });
  if (!['webhook', 'email', 'telegram'].includes(type))
    errs.push({ field: 'type', message: 'Unknown type' });
  const cfg = (body.config ?? {}) as Record<string, unknown>;
  if (type === 'webhook') {
    const raw = String(cfg.url ?? existing?.cfg.url ?? '');
    let u: URL | null = null;
    try {
      u = new URL(raw);
    } catch {
      errs.push({ field: 'config.url', message: 'Enter a valid URL' });
    }
    if (u) {
      const allowed = WEBHOOK_HTTP_ALLOW.includes(u.hostname);
      if (u.protocol !== 'https:' && !(u.protocol === 'http:' && allowed))
        errs.push({
          field: 'config.url',
          message: 'https is required (http only for allowlisted lab hosts)',
        });
      if (u.username || u.password)
        errs.push({ field: 'config.url', message: 'Credentials in the URL are not allowed' });
      if (PRIVATE_HOST.test(u.hostname) && !allowed)
        errs.push({
          field: 'config.url',
          message: 'Resolves to a private, loopback or metadata address (SSRF guard)',
        });
    }
  }
  if (type === 'webhook' && !existing && String(cfg.signingSecret ?? '').length < 16)
    errs.push({ field: 'config.signingSecret', message: 'At least 16 characters' });
  if (type === 'email') {
    const to = (cfg.to ?? existing?.cfg.to ?? []) as unknown[];
    if (
      !Array.isArray(to) ||
      to.length === 0 ||
      to.some((x) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(x)))
    )
      errs.push({ field: 'config.to', message: 'One or more valid email addresses' });
  }
  if (type === 'telegram') {
    const chat = String(cfg.chatId ?? existing?.cfg.chatId ?? '');
    if (!/^(?:-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/.test(chat))
      errs.push({ field: 'config.chatId', message: 'Numeric chat id or @channel' });
    if (!existing?.secrets.botToken && !cfg.botToken)
      errs.push({ field: 'config.botToken', message: 'Bot token is required' });
    if (cfg.botToken && !/^\d{3,20}:[A-Za-z0-9_-]{20,100}$/.test(String(cfg.botToken)))
      errs.push({ field: 'config.botToken', message: 'invalid bot token format' });
  }
  if (errs.length) throw new ctx.HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
  return { type, name, cfg };
}

function validateRuleBody(b: Record<string, unknown>, existing?: AlertRule) {
  const r = { ...(existing ?? {}), ...b } as Partial<AlertRule>;
  const errs: Array<{ field: string; message: string }> = [];
  if (!r.name || !String(r.name).trim()) errs.push({ field: 'name', message: 'Required' });
  if (
    !['server_offline', 'metric_threshold', 'app_down', 'log_dropped', 'backup_failed'].includes(
      String(r.kind),
    )
  )
    errs.push({ field: 'kind', message: 'Unknown kind' });
  if (!['info', 'warning', 'critical'].includes(String(r.severity)))
    errs.push({ field: 'severity', message: 'Unknown severity' });
  if (!['global', 'environment', 'server', 'app'].includes(String(r.scopeType)))
    errs.push({ field: 'scopeType', message: 'Unknown scope' });
  if (r.scopeType !== 'global' && !r.scopeId)
    errs.push({ field: 'scopeId', message: 'Required for this scope' });
  if (r.forSec !== undefined && (!Number.isInteger(r.forSec) || r.forSec < 0 || r.forSec > 86400))
    errs.push({ field: 'forSec', message: '0–86400 seconds' });
  if (r.kind === 'metric_threshold') {
    const p = (r.params ?? {}) as Record<string, unknown>;
    if (!['cpu', 'memory', 'disk', 'load1'].includes(String(p.metric)))
      errs.push({ field: 'params.metric', message: 'cpu, memory, disk or load1' });
    if (!['gt', 'lt'].includes(String(p.op)))
      errs.push({ field: 'params.op', message: 'gt or lt' });
    if (typeof p.value !== 'number' || !Number.isFinite(p.value))
      errs.push({ field: 'params.value', message: 'A number' });
  }
  const ids = (r.channelIds ?? []) as string[];
  if (ids.some((id) => !s().channels.some((c) => c.id === id)))
    errs.push({ field: 'channelIds', message: 'Unknown channel' });
  if (errs.length) throw new ctx.HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
}

// ---------------------------------------------------------------- routes

export function registerP5Routes(c: P3Ctx) {
  ctx = c;
  const { on, ok, HttpError } = c;
  const me = (req: Request) => c.currentUser(req) as U;

  on('GET', '/metrics/fleet', ({ req, url, requestId }) => {
    const u = me(req);
    need(u, 'fleet.read');
    const rows = ctx
      .servers()
      .filter((x) => can(u, 'fleet.read', x) && x.status !== 'revoked')
      .map(fleetRow);
    const { slice, paginate } = c.paginate(rows, new URL(`${url.origin}${url.pathname}?limit=100`));
    return ok(requestId, slice, 200, paginate);
  });

  on('GET', '/metrics/series', ({ req, url, requestId }) => {
    const u = me(req);
    const scope = url.searchParams.get('scope');
    const id = url.searchParams.get('id') ?? '';
    const metric = url.searchParams.get('metric') ?? '';
    const range = (url.searchParams.get('range') ?? '1h') as MetricRange;
    const errs: Array<{ field: string; message: string }> = [];
    if (scope !== 'server' && scope !== 'app')
      errs.push({ field: 'scope', message: 'server or app' });
    const allowed =
      scope === 'app'
        ? ['cpu', 'memory', 'up', 'restarts']
        : ['cpu', 'memory', 'disk', 'load1', 'net_rx', 'net_tx', 'up'];
    if (!allowed.includes(metric))
      errs.push({ field: 'metric', message: `One of ${allowed.join(', ')}` });
    if (!RANGE[range]) errs.push({ field: 'range', message: '1h, 6h, 24h or 7d' });
    for (const k of ['query', 'promql', 'expr'])
      if (url.searchParams.has(k)) errs.push({ field: k, message: 'Raw queries are not accepted' });
    if (errs.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
    limitRate(u, 'metrics', 60);
    if (scope === 'server') {
      const srv = srvOf(id);
      if (!srv || !can(u, 'fleet.read', srv))
        throw new HttpError(404, 'NOT_FOUND', 'Server not found');
      return ok(requestId, seriesFor('server', srv, null, metric, range));
    }
    const app = apps().find((a) => a.id === id);
    const srv = app ? srvOf(app.serverId) : undefined;
    if (!app || !srv || !can(u, 'apps.read', srv))
      throw new HttpError(404, 'NOT_FOUND', 'Application not found');
    return ok(requestId, seriesFor('app', srv, app, metric, range));
  });

  on('GET', '/logs/query', ({ req, url, requestId }) => {
    const u = me(req);
    const f = resolveLogScope(u, url);
    if (f.q === 'simulate-429')
      throw new HttpError(429, 'RATE_LIMITED', 'Too many log queries; try again shortly', {
        retryAfterSec: 3,
      });
    limitRate(u, 'logs', 30);
    const from = Date.parse(url.searchParams.get('from') ?? '');
    const to = Date.parse(url.searchParams.get('to') ?? '');
    if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'from', message: 'from must be before to' },
      ]);
    if (to - from > 7 * 864e5)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'to', message: 'At most 7 days' },
      ]);
    const limit = Math.min(1000, Math.max(1, Number(url.searchParams.get('limit') ?? 200) || 200));
    const dir = url.searchParams.get('direction') === 'forward' ? 'forward' : 'backward';
    const r = queryLogs(f, from, to, limit, dir, url.searchParams.get('cursor'));
    // Opaque cursor: unix nanoseconds of the last returned entry (digits only).
    const nextCursor = r.hasMore
      ? (BigInt(Date.parse(r.items.at(-1)!.ts)) * BigInt(1_000_000)).toString()
      : null;
    const body = {
      success: true,
      statusCode: 0,
      message: 'ok',
      data: r.items,
      paginate: { limit, hasMore: r.hasMore, nextCursor },
      meta: { requestId, retention: { days: RETENTION_DAYS } },
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId },
    });
  });

  on('POST', '/logs/tail-token', ({ req, body, requestId }) => {
    const u = me(req);
    const params = new URLSearchParams();
    for (const k of ['serverId', 'appId', 'source', 'level', 'q'])
      if (body[k] !== undefined && body[k] !== '') params.set(k, String(body[k]));
    resolveLogScope(u, new URL(`http://mock/logs/tail?${params.toString()}`));
    if ((activeTails[u.id] ?? 0) >= 3)
      throw new HttpError(429, 'TAIL_LIMIT', 'At most 3 live tails per user', {
        retryAfterSec: 10,
      });
    const token = `mock_tail_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
    const exp = Date.now() + 60e3;
    s().tokens[token] = { userId: u.id, params: canonical(params), exp, used: false };
    for (const [k, v] of Object.entries(s().tokens))
      if (v.exp < Date.now() - 60e3) delete s().tokens[k];
    save();
    return ok(requestId, { token, expiresAt: iso(exp) }, 201);
  });

  // ---- alert rules (policies.manage; If-Match)
  on('GET', '/alert-rules', ({ req, url, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const { slice, paginate } = c.paginate(s().rules, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/alert-rules', ({ req, body, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    validateRuleBody(body);
    const now = iso(Date.now());
    const r: AlertRule = {
      id: c.rid(),
      name: String(body.name).trim(),
      enabled: body.enabled !== false,
      scopeType: body.scopeType as AlertRule['scopeType'],
      scopeId: (body.scopeId as string) ?? null,
      kind: body.kind as RuleKind,
      params: (body.params ?? {}) as AlertRule['params'],
      severity: body.severity as Severity,
      forSec: typeof body.forSec === 'number' ? body.forSec : 60,
      channelIds: (body.channelIds ?? []) as string[],
      createdBy: u.id,
      version: 1,
      createdAt: now,
      updatedAt: now,
    };
    s().rules.push(r);
    save();
    return ok(requestId, r, 201);
  });
  const findRule = (req: Request, id: string) => {
    const r = s().rules.find((x) => x.id === id);
    if (!r) throw new HttpError(404, 'NOT_FOUND', 'Alert rule not found');
    const im = req.headers.get('If-Match');
    if (!im) throw new HttpError(428, 'PRECONDITION_REQUIRED', 'If-Match is required');
    if (Number(im) !== r.version)
      throw new HttpError(
        409,
        'VERSION_CONFLICT',
        'This rule was changed by someone else. Reload and try again.',
        { currentVersion: r.version },
      );
    return r;
  };
  on('PATCH', '/alert-rules/:id', ({ req, params, body, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const r = findRule(req, params[0]!);
    validateRuleBody(body, r);
    const { id: _i, createdBy: _c, version: _v, ...patch } = body as Partial<AlertRule>;
    Object.assign(r, patch, { version: r.version + 1, updatedAt: iso(Date.now()) });
    save();
    return ok(requestId, r);
  });
  on('DELETE', '/alert-rules/:id', ({ req, params, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const r = findRule(req, params[0]!);
    s().rules = s().rules.filter((x) => x.id !== r.id);
    save();
    return new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });
  });

  // ---- incidents
  on('GET', '/incidents', ({ req, url, requestId }) => {
    const u = me(req);
    need(u, 'fleet.read');
    const status = url.searchParams.get('status');
    const severity = url.searchParams.get('severity');
    const tt = url.searchParams.get('target_type');
    const items = s()
      .incidents.filter((i) => {
        const srv = incidentServer(i);
        return !!srv && can(u, 'fleet.read', srv);
      })
      .filter((i) => !status || i.status === status)
      .filter((i) => !severity || i.severity === severity)
      .filter((i) => !tt || i.target.type === tt)
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .map((i) => incidentView(u, i, false));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  const findIncident = (u: U, id: string) => {
    const i = s().incidents.find((x) => x.id === id);
    const srv = i ? incidentServer(i) : undefined;
    if (!i || !srv || !can(u, 'fleet.read', srv))
      throw new HttpError(404, 'NOT_FOUND', 'Incident not found');
    return { i, srv };
  };
  on('GET', '/incidents/:id', ({ req, params, requestId }) => {
    const u = me(req);
    const { i } = findIncident(u, params[0]!);
    return ok(requestId, incidentView(u, i, true));
  });
  on('POST', '/incidents/:id/acknowledge', ({ req, params, body, requestId }) => {
    const u = me(req);
    const { i, srv } = findIncident(u, params[0]!);
    if (!can(u, 'servers.operate', srv)) {
      ctx.audit(u as never, 'incident.acknowledge', srv, 'denied', requestId);
      throw new HttpError(403, 'FORBIDDEN', 'Missing permission servers.operate for this scope', {
        required: 'servers.operate',
      });
    }
    if (i.status !== 'firing')
      throw new HttpError(409, 'INCIDENT_STATE_INVALID', `Incident is ${i.status}`);
    const comment = typeof body.comment === 'string' ? body.comment.trim() : '';
    if (comment.length > 2000)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'comment', message: '1–2000 characters' },
      ]);
    const now = iso(Date.now());
    i.status = 'acknowledged';
    i.acknowledgedAt = now;
    i.acknowledgedBy = { id: u.id, displayName: u.displayName };
    i.timeline.push({
      at: now,
      type: 'acknowledged',
      actor: { id: u.id, displayName: u.displayName },
      detail: comment ? { comment } : {},
    });
    ctx.audit(u as never, 'incident.acknowledge', srv, 'success', requestId);
    save();
    return ok(requestId, incidentView(u, i, true));
  });
  on('POST', '/incidents/:id/comment', ({ req, params, body, requestId }) => {
    const u = me(req);
    const { i, srv } = findIncident(u, params[0]!);
    if (!can(u, 'servers.operate', srv))
      throw new HttpError(403, 'FORBIDDEN', 'Missing permission servers.operate for this scope', {
        required: 'servers.operate',
      });
    const comment = typeof body.comment === 'string' ? body.comment.trim() : '';
    if (!comment || comment.length > 2000)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'comment', message: '1–2000 characters' },
      ]);
    i.timeline.push({
      at: iso(Date.now()),
      type: 'comment',
      actor: { id: u.id, displayName: u.displayName },
      detail: { comment },
    });
    save();
    return ok(requestId, incidentView(u, i, true));
  });

  // ---- notification channels
  on('GET', '/notification-channels', ({ req, url, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const { slice, paginate } = c.paginate(s().channels.map(channelView), url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/notification-channels', ({ req, body, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const { type, name, cfg } = validateChannel(body);
    if (s().channels.some((x) => x.name === name))
      throw new HttpError(409, 'CONFLICT', 'A channel with this name exists', [
        { field: 'name', message: 'Name already in use' },
      ]);
    const rec: ChannelRec = {
      id: c.rid(),
      name,
      type,
      enabled: body.enabled !== false,
      version: 1,
      createdAt: iso(Date.now()),
      updatedAt: iso(Date.now()),
      lastDelivery: null,
      cfg:
        type === 'webhook'
          ? { url: String(cfg.url) }
          : type === 'email'
            ? { to: (cfg.to as string[]).map(String) }
            : { chatId: String(cfg.chatId) },
      // Secret values are never kept by the mock — only "set" flags.
      secrets: { signingSecret: !!cfg.signingSecret, botToken: !!cfg.botToken },
    };
    s().channels.push(rec);
    save();
    return ok(requestId, channelView(rec), 201);
  });
  const findChannel = (id: string) => {
    const ch = s().channels.find((x) => x.id === id);
    if (!ch) throw new HttpError(404, 'NOT_FOUND', 'Channel not found');
    return ch;
  };
  on('PATCH', '/notification-channels/:id', ({ req, params, body, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const ch = findChannel(params[0]!);
    const { cfg } = validateChannel(body, ch);
    if (typeof body.enabled === 'boolean') ch.enabled = body.enabled;
    if (cfg.url) ch.cfg.url = String(cfg.url);
    if (Array.isArray(cfg.to)) ch.cfg.to = (cfg.to as unknown[]).map(String);
    if (cfg.chatId) ch.cfg.chatId = String(cfg.chatId);
    if (cfg.signingSecret) ch.secrets.signingSecret = true;
    if (cfg.botToken) ch.secrets.botToken = true;
    ch.version += 1;
    ch.updatedAt = iso(Date.now());
    save();
    return ok(requestId, channelView(ch));
  });
  on('DELETE', '/notification-channels/:id', ({ req, params, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const ch = findChannel(params[0]!);
    s().channels = s().channels.filter((x) => x.id !== ch.id);
    for (const r of s().rules) r.channelIds = r.channelIds.filter((x) => x !== ch.id);
    save();
    return new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });
  });
  on('POST', '/notification-channels/:id/test', ({ req, params, requestId }) => {
    const u = me(req);
    need(u, 'policies.manage');
    const ch = findChannel(params[0]!);
    let error: string | null = null;
    if (ch.type === 'webhook' && /fail/i.test(ch.cfg.url ?? ''))
      error = 'Receiver answered HTTP 500 after 3 attempts (5 s timeout each)';
    if (ch.type === 'email' && (ch.cfg.to ?? []).some((x) => /bounce/i.test(x)))
      error = 'SMTP 550 5.1.1 recipient rejected';
    if (ch.type === 'telegram' && ch.cfg.chatId === '0')
      error = 'Telegram API: Bad Request: chat not found';
    if (ch.type === 'telegram' && !ch.secrets.botToken) error = 'Bot token is not set';
    const res = { delivered: !error, ...(error ? { error } : {}), deliveryId: c.rid() };
    ch.lastDelivery = {
      at: iso(Date.now()),
      status: error ? 'failed' : 'delivered',
      error,
    };
    save();
    return ok(requestId, res);
  });
}
