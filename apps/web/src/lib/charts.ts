/**
 * Pure helpers for the hand-rolled SVG metric charts. A `null` point is a gap: the path is broken
 * there (a new `M` segment starts after it) — it is never drawn as 0.
 */
import type { MetricPoint, MetricUnit } from './api/p5-types';

export interface Segment {
  /** [x, y] in chart pixels. */
  pts: Array<[number, number]>;
}
export interface PathResult {
  d: string;
  segments: Segment[];
  /** Runs of consecutive null points (each run = one visible gap). */
  gapRuns: number;
  nullPoints: number;
}

/** Map points to an SVG path; null points split the line into separate segments. */
export function seriesToPath(
  points: readonly MetricPoint[],
  x: (t: number) => number,
  y: (v: number) => number,
): PathResult {
  const segments: Segment[] = [];
  let cur: Segment | null = null;
  let gapRuns = 0;
  let nullPoints = 0;
  let inGap = false;
  for (const [t, v] of points) {
    if (v === null || !Number.isFinite(v)) {
      nullPoints++;
      if (!inGap) gapRuns++;
      inGap = true;
      cur = null;
      continue;
    }
    inGap = false;
    if (!cur) {
      cur = { pts: [] };
      segments.push(cur);
    }
    cur.pts.push([round(x(t)), round(y(v))]);
  }
  const d = segments
    .map((s) => s.pts.map(([px, py], i) => `${i === 0 ? 'M' : 'L'}${px},${py}`).join(''))
    .join('');
  return { d, segments, gapRuns, nullPoints };
}

const round = (n: number) => Math.round(n * 10) / 10;

/** Contiguous null runs as [fromSec, toSec] (first and last null timestamps). */
export function nullRuns(points: readonly MetricPoint[]): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let start: number | null = null;
  let last: number | null = null;
  for (const [t, v] of points) {
    if (v === null) {
      if (start === null) start = t;
      last = t;
    } else if (start !== null) {
      out.push([start, last!]);
      start = null;
    }
  }
  if (start !== null) out.push([start, last!]);
  return out;
}

export function niceCeil(v: number): number {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  const m = v / p;
  const step = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10;
  return step * p;
}

/** Y domain: percent is always 0–100; booleans 0–1; others 0 → nice max of the data. */
export function yDomain(points: readonly MetricPoint[], unit: MetricUnit): [number, number] {
  if (unit === 'percent') return [0, 100];
  if (unit === 'bool') return [0, 1];
  let max = 0;
  for (const [, v] of points) if (v !== null && v > max) max = v;
  if (unit === 'bytes' || unit === 'bytes_per_second') return [0, niceBytes(max)];
  return [0, niceCeil(max || 1)];
}

function niceBytes(v: number): number {
  if (!(v > 0)) return 1024;
  const k = Math.floor(Math.log(v) / Math.log(1024));
  const base = 1024 ** Math.max(0, k);
  return niceCeil(v / base) * base;
}

export function ticks([lo, hi]: [number, number], n = 4): number[] {
  const out: number[] = [];
  for (let i = 0; i <= n; i++) out.push(lo + ((hi - lo) * i) / n);
  return out;
}

const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

/** Unit-aware value label. `null` → the caller's "no data" text (never "0"). */
export function formatMetric(v: number | null | undefined, unit: MetricUnit, noData = '—'): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return noData;
  switch (unit) {
    case 'percent':
      return `${v >= 10 || v === 0 ? Math.round(v) : v.toFixed(1)}%`;
    case 'bytes':
    case 'bytes_per_second': {
      let n = Math.abs(v);
      let i = 0;
      while (n >= 1024 && i < BYTE_UNITS.length - 1) {
        n /= 1024;
        i++;
      }
      const s = `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${BYTE_UNITS[i]}`;
      return unit === 'bytes_per_second' ? `${s}/s` : s;
    }
    case 'bool':
      return v >= 0.5 ? 'up' : 'down';
    case 'count':
      return String(Math.round(v));
    default:
      return Math.abs(v) >= 100 ? String(Math.round(v)) : String(Math.round(v * 100) / 100);
  }
}

export interface SeriesSummary {
  min: number | null;
  max: number | null;
  last: number | null;
  lastAt: number | null;
  samples: number;
  nullPoints: number;
  gapRuns: number;
}

export function summarize(points: readonly MetricPoint[]): SeriesSummary {
  let min: number | null = null;
  let max: number | null = null;
  let last: number | null = null;
  let lastAt: number | null = null;
  let samples = 0;
  for (const [t, v] of points) {
    if (v === null) continue;
    samples++;
    min = min === null ? v : Math.min(min, v);
    max = max === null ? v : Math.max(max, v);
    last = v;
    lastAt = t;
  }
  const runs = nullRuns(points);
  return {
    min,
    max,
    last,
    lastAt,
    samples,
    nullPoints: points.length - samples,
    gapRuns: runs.length,
  };
}

/** Index of the point nearest to time `t` (for the crosshair / keyboard cursor). */
export function nearestIndex(points: readonly MetricPoint[], t: number): number {
  if (points.length === 0) return -1;
  let best = 0;
  let bestD = Infinity;
  for (let i = 0; i < points.length; i++) {
    const d = Math.abs(points[i]![0] - t);
    if (d < bestD) {
      bestD = d;
      best = i;
    }
  }
  return best;
}
