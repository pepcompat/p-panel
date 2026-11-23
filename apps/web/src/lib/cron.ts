/**
 * 5-field cron (minute hour day-of-month month day-of-week) for the policy editor preview: parse,
 * human-readable description and next runs in an IANA timezone. The Center scheduler is the source
 * of truth; this mirrors standard (Vixie) semantics so the preview matches:
 *  - lists `1,15`, ranges `1-5`, steps `*\/15`, `10-40/10`, names `jan`/`mon`, dow 0 and 7 = Sunday
 *  - when both day-of-month and day-of-week are restricted, a day matches if EITHER matches
 *  - DST: a wall time that does not exist (spring forward) is skipped; an ambiguous one (fall back)
 *    runs once, at its first occurrence.
 */

export interface CronField {
  values: number[];
  /** `*` (or `*\/1`) — unrestricted */
  any: boolean;
}
export interface ParsedCron {
  minute: CronField;
  hour: CronField;
  dom: CronField;
  month: CronField;
  dow: CronField;
}
export type CronError = {
  field: 'minute' | 'hour' | 'dom' | 'month' | 'dow' | 'fields';
  value: string;
};
export type CronParse = { ok: true; cron: ParsedCron } | { ok: false; error: CronError };

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

const SPEC = {
  minute: { min: 0, max: 59, names: null },
  hour: { min: 0, max: 23, names: null },
  dom: { min: 1, max: 31, names: null },
  month: { min: 1, max: 12, names: MONTHS },
  dow: { min: 0, max: 7, names: DAYS },
} as const;
type FieldName = keyof typeof SPEC;
const ORDER: FieldName[] = ['minute', 'hour', 'dom', 'month', 'dow'];

function num(tok: string, f: FieldName): number | null {
  const s = SPEC[f];
  const lower = tok.toLowerCase();
  if (s.names) {
    const i = (s.names as readonly string[]).indexOf(lower);
    if (i >= 0) return f === 'month' ? i + 1 : i;
  }
  if (!/^\d{1,2}$/.test(tok)) return null;
  const n = Number(tok);
  return n >= s.min && n <= s.max ? n : null;
}

function parseField(raw: string, f: FieldName): CronField | null {
  const s = SPEC[f];
  const out = new Set<number>();
  let any = false;
  for (const part of raw.split(',')) {
    if (!part) return null;
    const [range, stepRaw, extra] = part.split('/');
    if (extra !== undefined || range === undefined) return null;
    let step = 1;
    if (stepRaw !== undefined) {
      if (!/^\d{1,2}$/.test(stepRaw) || Number(stepRaw) < 1) return null;
      step = Number(stepRaw);
    }
    let lo: number;
    let hi: number;
    if (range === '*') {
      lo = s.min;
      hi = f === 'dow' ? 6 : s.max;
      if (step === 1) any = true;
    } else if (range.includes('-')) {
      const [a, b, c] = range.split('-');
      if (c !== undefined || a === undefined || b === undefined) return null;
      const x = num(a, f);
      const y = num(b, f);
      if (x === null || y === null || x > y) return null;
      lo = x;
      hi = y;
    } else {
      const x = num(range, f);
      if (x === null) return null;
      lo = x;
      hi = stepRaw !== undefined ? (f === 'dow' ? 6 : s.max) : x;
    }
    for (let v = lo; v <= hi; v += step) out.add(f === 'dow' && v === 7 ? 0 : v);
  }
  return { values: [...out].sort((a, b) => a - b), any };
}

export function parseCron(expr: string): CronParse {
  const parts = expr.trim().split(/\s+/).filter(Boolean);
  if (parts.length !== 5) return { ok: false, error: { field: 'fields', value: expr.trim() } };
  const res: Partial<ParsedCron> = {};
  for (let i = 0; i < 5; i++) {
    const f = ORDER[i]!;
    const parsed = parseField(parts[i]!, f);
    if (!parsed) return { ok: false, error: { field: f, value: parts[i]! } };
    res[f] = parsed;
  }
  return { ok: true, cron: res as ParsedCron };
}

// ---------------------------------------------------------------- timezone helpers

export function isValidTimeZone(tz: string): boolean {
  if (!tz || tz.length > 64) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** IANA zones from the runtime (falls back to a short curated list). */
export function timeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] };
  try {
    const all = intl.supportedValuesOf?.('timeZone');
    if (all && all.length) return all.includes('UTC') ? all : ['UTC', ...all];
  } catch {
    /* older runtime */
  }
  return [
    'UTC',
    'Asia/Bangkok',
    'Asia/Singapore',
    'Asia/Tokyo',
    'Europe/London',
    'Europe/Berlin',
    'America/New_York',
    'America/Los_Angeles',
    'Australia/Sydney',
  ];
}

const fmtCache = new Map<string, Intl.DateTimeFormat>();
function partsFmt(tz: string) {
  let f = fmtCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
      weekday: 'short',
    });
    fmtCache.set(tz, f);
  }
  return f;
}

export interface Wall {
  y: number;
  mo: number;
  d: number;
  h: number;
  mi: number;
  dow: number;
}
export function wallClock(ms: number, tz: string): Wall {
  const p: Record<string, string> = {};
  for (const x of partsFmt(tz).formatToParts(new Date(ms))) p[x.type] = x.value;
  return {
    y: Number(p.year),
    mo: Number(p.month),
    d: Number(p.day),
    h: Number(p.hour) % 24,
    mi: Number(p.minute),
    dow: DAYS.indexOf((p.weekday ?? '').slice(0, 3).toLowerCase()),
  };
}
/** Offset (ms) of `tz` from UTC at instant `ms`. */
export function tzOffsetMs(ms: number, tz: string): number {
  const w = wallClock(ms, tz);
  const asUtc = Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi);
  return asUtc - Math.floor(ms / 60e3) * 60e3;
}
/** UTC instant for a wall-clock time in `tz`; null when that wall time does not exist (DST gap). */
export function zonedToUtc(
  y: number,
  mo: number,
  d: number,
  h: number,
  mi: number,
  tz: string,
): number | null {
  const guess = Date.UTC(y, mo - 1, d, h, mi);
  // Earliest candidate first so an ambiguous (fall-back) time resolves to its first occurrence.
  const offsets = [
    ...new Set([
      tzOffsetMs(guess - 864e5 / 2, tz),
      tzOffsetMs(guess, tz),
      tzOffsetMs(guess + 864e5 / 2, tz),
    ]),
  ].sort((a, b) => b - a);
  for (const off of offsets) {
    const t = guess - off;
    const w = wallClock(t, tz);
    if (w.y === y && w.mo === mo && w.d === d && w.h === h && w.mi === mi) return t;
  }
  return null;
}

function dayMatches(c: ParsedCron, dom: number, dow: number): boolean {
  const domOk = c.dom.values.includes(dom);
  const dowOk = c.dow.values.includes(dow);
  if (c.dom.any && c.dow.any) return true;
  if (c.dom.any) return dowOk;
  if (c.dow.any) return domOk;
  return domOk || dowOk;
}

/**
 * Next `n` run instants (UTC ms) strictly after `from`, evaluated in `tz`. Scans calendar days in
 * the zone (max ~8 years, enough for `0 0 29 2 *`).
 */
export function nextRuns(cron: ParsedCron | string, tz: string, from: number, n = 3): number[] {
  const c =
    typeof cron === 'string' ? (parseCron(cron) as { ok: boolean; cron?: ParsedCron }).cron : cron;
  if (!c || !isValidTimeZone(tz)) return [];
  const out: number[] = [];
  const start = wallClock(from, tz);
  // Iterate calendar days in the zone using a UTC "date cursor" (pure calendar arithmetic).
  let cursor = Date.UTC(start.y, start.mo - 1, start.d);
  for (let i = 0; i < 366 * 8 && out.length < n; i++, cursor += 864e5) {
    const day = new Date(cursor);
    const y = day.getUTCFullYear();
    const mo = day.getUTCMonth() + 1;
    const d = day.getUTCDate();
    if (!c.month.values.includes(mo)) continue;
    if (!dayMatches(c, d, day.getUTCDay())) continue;
    for (const h of c.hour.values) {
      for (const mi of c.minute.values) {
        const t = zonedToUtc(y, mo, d, h, mi, tz);
        if (t === null || t <= from) continue;
        if (!out.includes(t)) out.push(t);
        if (out.length >= n) break;
      }
      if (out.length >= n) break;
    }
  }
  return out.sort((a, b) => a - b).slice(0, n);
}

// ---------------------------------------------------------------- description

export type CronDescription =
  | { kind: 'everyMinute' }
  | { kind: 'everyNMinutes'; n: number }
  | { kind: 'hourly'; minute: number }
  | { kind: 'everyNHours'; n: number; minute: number }
  | { kind: 'daily'; times: string[] }
  | { kind: 'weekly'; days: number[]; times: string[] }
  | { kind: 'monthly'; days: number[]; times: string[] }
  | { kind: 'custom' };

const pad = (n: number) => String(n).padStart(2, '0');
const isStep = (v: number[], start: number, max: number): number | null => {
  if (v.length < 2 || v[0] !== start) return null;
  const s = v[1]! - v[0]!;
  for (let i = 1; i < v.length; i++) if (v[i]! - v[i - 1]! !== s) return null;
  return v[v.length - 1]! + s > max ? s : null;
};

/** Structured description; the UI turns it into EN/TH text. */
export function describeCron(c: ParsedCron): CronDescription {
  const everyDay = c.dom.any && c.month.any && c.dow.any;
  if (c.minute.any && c.hour.any && everyDay) return { kind: 'everyMinute' };
  if (c.hour.any && everyDay) {
    if (c.minute.values.length === 1) return { kind: 'hourly', minute: c.minute.values[0]! };
    const s = isStep(c.minute.values, 0, 59);
    if (s) return { kind: 'everyNMinutes', n: s };
    return { kind: 'custom' };
  }
  if (c.minute.values.length === 1 && !c.hour.any && everyDay) {
    const s = isStep(c.hour.values, c.hour.values[0]!, 23);
    if (s && c.hour.values.length > 3)
      return { kind: 'everyNHours', n: s, minute: c.minute.values[0]! };
  }
  if (c.hour.any || c.minute.any || !c.month.any) return { kind: 'custom' };
  if (c.hour.values.length * c.minute.values.length > 6) return { kind: 'custom' };
  const times = c.hour.values.flatMap((h) => c.minute.values.map((m) => `${pad(h)}:${pad(m)}`));
  if (everyDay) return { kind: 'daily', times };
  if (c.dom.any && !c.dow.any) return { kind: 'weekly', days: c.dow.values, times };
  if (!c.dom.any && c.dow.any) return { kind: 'monthly', days: c.dom.values, times };
  return { kind: 'custom' };
}

export const CRON_PRESETS = [
  { cron: '0 2 * * *', key: 'daily02' },
  { cron: '0 */6 * * *', key: 'every6h' },
  { cron: '30 3 * * 0', key: 'weeklySun' },
  { cron: '0 4 1 * *', key: 'monthly1' },
] as const;
