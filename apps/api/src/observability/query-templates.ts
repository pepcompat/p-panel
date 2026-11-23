/**
 * Pure PromQL / LogQL builders (P5.02 / P5.03). Users never send query language: every query comes
 * from a fixed template whose only inputs are Center-validated ids/enums and an escaped substring.
 */
import {
  type AppMetric,
  LOG_LEVELS,
  type LogLevel,
  type LogSource,
  type MetricPoint,
  type ServerMetric,
} from '@ppanel/shared-contracts';
import { UUID_RE } from '../common/ids';

/** Escapes a value for a double-quoted PromQL/LogQL string literal (label matcher or line filter). */
export function escapeQuoted(value: string): string {
  let out = '';
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 0x20 || code === 0x7f) out += `\\x${code.toString(16).padStart(2, '0')}`;
    else out += ch;
  }
  return out;
}

function assertUuid(id: string): string {
  if (!UUID_RE.test(id)) throw new Error('query template: id must be a uuid');
  return id.toLowerCase();
}

/** Rate window for counters: ≥ 4 scrape intervals and ≥ 2 steps. */
export function rateWindowSec(stepSec: number): number {
  return Math.max(60, stepSec * 2);
}

export function serverPromQL(metric: ServerMetric, serverId: string, stepSec: number): string {
  const sel = `{server_id="${assertUuid(serverId)}"}`;
  const w = `${rateWindowSec(stepSec)}s`;
  switch (metric) {
    case 'cpu':
      return `max(ppanel_server_cpu_percent${sel})`;
    case 'memory':
      return `max(ppanel_server_memory_percent${sel})`;
    case 'disk':
      return `max(ppanel_server_disk_percent${sel})`;
    case 'load1':
      return `max(ppanel_server_load1${sel})`;
    case 'net_rx':
      return `max(rate(ppanel_server_net_rx_bytes_total${sel}[${w}]))`;
    case 'net_tx':
      return `max(rate(ppanel_server_net_tx_bytes_total${sel}[${w}]))`;
    case 'up':
      return `max(ppanel_server_up${sel})`;
  }
}

export function appPromQL(metric: AppMetric, appId: string): string {
  const sel = `{app_id="${assertUuid(appId)}"}`;
  switch (metric) {
    case 'cpu':
      return `sum(ppanel_container_cpu_percent${sel})`;
    case 'memory':
      return `sum(ppanel_container_memory_bytes${sel})`;
    case 'up':
      return `min(ppanel_container_up${sel})`;
    case 'restarts':
      return `sum(ppanel_container_restarts_total${sel})`;
  }
}

/** Fills a fixed grid start..end/step with Prometheus values; missing → null (never 0). */
export function fillGrid(
  start: number,
  end: number,
  step: number,
  values: Array<[number, string]>,
): MetricPoint[] {
  const byTs = new Map<number, number>();
  for (const [t, v] of values) {
    const n = Number(v);
    if (Number.isFinite(n)) byTs.set(Math.round(t), n);
  }
  const out: MetricPoint[] = [];
  for (let t = start; t <= end; t += step) out.push([t, byTs.has(t) ? byTs.get(t)! : null]);
  return out;
}

/** `[from, to]` runs of null points. */
export function gapsOf(points: MetricPoint[]): Array<[number, number]> {
  const gaps: Array<[number, number]> = [];
  let open: number | null = null;
  let last = 0;
  for (const [t, v] of points) {
    if (v === null) {
      if (open === null) open = t;
      last = t;
    } else if (open !== null) {
      gaps.push([open, last]);
      open = null;
    }
  }
  if (open !== null) gaps.push([open, last]);
  return gaps;
}

// ------------------------------------------------------------------------------------------ LogQL

export interface LogSelector {
  /** allowed server ids (already scope-filtered); one id → `=`, several → `=~` alternation */
  serverIds: string[];
  appId?: string;
  source?: LogSource;
  /** minimum level */
  level?: LogLevel;
  /** plain substring */
  q?: string;
}

export function levelsAtLeast(level: LogLevel): LogLevel[] {
  return LOG_LEVELS.slice(LOG_LEVELS.indexOf(level)) as LogLevel[];
}

/**
 * `{server_id=~"a|b", app_id="…", source="…", level=~"warn|error|fatal"} |= "escaped"`.
 * Ids must be uuids (enforced), enums are from closed lists, `q` is escaped into a line filter.
 */
export function buildLogQL(s: LogSelector): string {
  if (s.serverIds.length === 0) throw new Error('LogQL: empty server scope');
  const ids = s.serverIds.map(assertUuid);
  const matchers = [
    ids.length === 1 ? `server_id="${ids[0]}"` : `server_id=~"${[...new Set(ids)].join('|')}"`,
  ];
  if (s.appId) matchers.push(`app_id="${assertUuid(s.appId)}"`);
  if (s.source) matchers.push(`source="${escapeQuoted(s.source)}"`);
  if (s.level && s.level !== 'debug') matchers.push(`level=~"${levelsAtLeast(s.level).join('|')}"`);
  let q = `{${matchers.join(', ')}}`;
  if (s.q) q += ` |= "${escapeQuoted(s.q)}"`;
  return q;
}

// --------------------------------------------------------------------------- Prometheus exposition

export function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

export interface ExpositionSample {
  labels: Record<string, string>;
  value: number;
}

export function renderFamily(
  name: string,
  type: 'gauge' | 'counter',
  help: string,
  samples: ExpositionSample[],
): string {
  const lines = [`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`];
  const seen = new Set<string>();
  for (const s of samples) {
    if (!Number.isFinite(s.value)) continue;
    const labels = Object.entries(s.labels)
      .filter(([, v]) => v !== '')
      .map(([k, v]) => `${k}="${escapeLabelValue(v)}"`)
      .join(',');
    if (seen.has(labels)) continue; // duplicate series are invalid exposition
    seen.add(labels);
    lines.push(`${name}{${labels}} ${s.value}`);
  }
  return lines.join('\n');
}

// ------------------------------------------------------------------------------------ time helpers

/** ISO-8601 (any fractional precision) → unix nanoseconds. */
export function isoToNs(iso: string): bigint {
  const m = /^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})$/i.exec(iso);
  if (!m) throw new Error('invalid timestamp');
  const secMs = Date.parse(`${m[1]}${m[3]}`);
  if (!Number.isFinite(secMs)) throw new Error('invalid timestamp');
  const frac = (m[2] ?? '').slice(0, 9).padEnd(9, '0');
  return BigInt(secMs) * 1_000_000n + BigInt(frac);
}

/** unix ns → ISO-8601 with nanoseconds (UTC). */
export function nsToIso(ns: bigint): string {
  const ms = ns / 1_000_000n;
  const base = new Date(Number(ms)).toISOString(); // …ss.mmmZ
  const nanos = (ns % 1_000_000_000n).toString().padStart(9, '0');
  return `${base.slice(0, 19)}.${nanos}Z`;
}

export function msToNs(ms: number): bigint {
  return BigInt(Math.floor(ms)) * 1_000_000n;
}
