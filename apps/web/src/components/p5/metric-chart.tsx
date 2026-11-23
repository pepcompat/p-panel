'use client';

import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useI18n } from '@/i18n/provider';
import { isApiError } from '@/lib/api/errors';
import type { MetricRange, MetricSeries } from '@/lib/api/p5-types';
import {
  formatMetric,
  nearestIndex,
  nullRuns,
  seriesToPath,
  summarize,
  ticks,
  yDomain,
} from '@/lib/charts';
import { formatClock } from '@/lib/time';
import { cn } from '@/lib/utils';
import { Skeleton } from '@/components/ui/skeleton';
import type { MessageKey } from '@/i18n/en';

const PAD = { l: 52, r: 12, t: 10, b: 22 };

function useWidth<T extends HTMLElement>(fallback = 560) {
  const ref = useRef<T>(null);
  const [w, setW] = useState(fallback);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(([e]) => {
      const cw = Math.round(e!.contentRect.width);
      if (cw > 0) setW(cw);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

function timeLabel(sec: number, range: MetricRange, locale: string) {
  const d = new Date(sec * 1000);
  const loc = locale === 'th' ? 'th-TH' : 'en-GB';
  if (range === '7d')
    return (
      d.toLocaleDateString(loc, { day: '2-digit', month: 'short' }) +
      ' ' +
      d.toLocaleTimeString(loc, { hour: '2-digit', minute: '2-digit', hour12: false })
    );
  return d.toLocaleTimeString(loc, { hour: '2-digit', minute: '2-digit', hour12: false });
}

/**
 * Single-series line chart. Null points are gaps (the path breaks and the gap is hatched) — never 0.
 * Keyboard: focus the plot, ←/→ move the cursor, Home/End jump, Esc clears. A text summary and a
 * data table are always available to screen readers.
 */
export function MetricChart({
  series,
  title,
  range,
  isLoading,
  error,
  height = 150,
  compact,
  metricKey,
}: {
  series: MetricSeries | undefined;
  title: string;
  range: MetricRange;
  isLoading?: boolean;
  error?: unknown;
  height?: number;
  /** Sparkline mode (fleet cards): no axes, no table. */
  compact?: boolean;
  metricKey?: string;
}) {
  const { t, locale } = useI18n();
  const [wrapRef, width] = useWidth<HTMLDivElement>(compact ? 260 : 560);
  const [cursor, setCursor] = useState<number | null>(null);
  const summaryId = useId();
  const pad = compact ? { l: 0, r: 0, t: 4, b: 4 } : PAD;

  const model = useMemo(() => {
    if (!series || series.points.length === 0) return null;
    const pts = series.points;
    const t0 = pts[0]![0];
    const t1 = pts[pts.length - 1]![0];
    const dom = yDomain(pts, series.unit);
    const iw = Math.max(10, width - pad.l - pad.r);
    const ih = Math.max(10, height - pad.t - pad.b);
    const x = (t: number) => pad.l + (t1 === t0 ? iw / 2 : ((t - t0) / (t1 - t0)) * iw);
    const y = (v: number) =>
      pad.t + ih - ((Math.min(Math.max(v, dom[0]), dom[1]) - dom[0]) / (dom[1] - dom[0] || 1)) * ih;
    const path = seriesToPath(pts, x, y);
    const runs = nullRuns(pts);
    const step = pts.length > 1 ? (t1 - t0) / (pts.length - 1) : 60;
    return { pts, t0, t1, dom, iw, ih, x, y, path, runs, step, sum: summarize(pts) };
  }, [series, width, height, pad.l, pad.r, pad.t, pad.b]);

  const noData = t('common.noData');
  const unit = series?.unit ?? 'count';
  const fmt = (v: number | null) => formatMetric(v, unit, noData);
  const staleAt = series?.stale && series.lastSampleAt ? new Date(series.lastSampleAt) : null;
  const neverReported = !!series && series.lastSampleAt === null && (model?.sum.samples ?? 0) === 0;

  if (isLoading && !series)
    return (
      <div className="flex flex-col gap-1" role="status" aria-busy="true" aria-label={title}>
        {!compact && <span className="text-[12.5px] font-medium">{title}</span>}
        <div style={{ height }}>
          <Skeleton className="h-full w-full" />
        </div>
      </div>
    );

  if (error && !series) {
    const e = isApiError(error) ? error : null;
    return (
      <div className="flex flex-col gap-1" data-testid="metric-chart-error">
        {!compact && <span className="text-[12.5px] font-medium">{title}</span>}
        <div
          role="alert"
          className="grid place-items-center rounded-md border border-dashed border-line-strong bg-surface-2 px-3 text-center text-[12px] text-fg-muted"
          style={{ height }}
        >
          {e?.status === 429
            ? t('mon.rateLimited', { sec: e.retryAfterSec ?? 60 })
            : e?.status === 404
              ? t('mon.notFound')
              : t('mon.loadFailed', { code: e?.code ?? 'ERROR' })}
        </div>
      </div>
    );
  }

  const summaryText = !series
    ? noData
    : neverReported
      ? t('chart.sr.never', { title })
      : t('chart.sr.summary', {
          title,
          range: t(`range.${range}` as MessageKey),
          last: fmt(model?.sum.last ?? null),
          at: model?.sum.lastAt ? formatClock(model.sum.lastAt * 1000, locale) : noData,
          min: fmt(model?.sum.min ?? null),
          max: fmt(model?.sum.max ?? null),
          gaps: model?.sum.gapRuns ?? 0,
        }) + (staleAt ? ` ${t('chart.staleSince', { time: formatClock(staleAt, locale) })}` : '');

  const cur = cursor !== null && model ? model.pts[cursor] : null;

  const onKey = (e: KeyboardEvent) => {
    if (!model) return;
    const n = model.pts.length;
    let next: number | null = cursor;
    if (e.key === 'ArrowRight') next = Math.min(n - 1, (cursor ?? n - 2) + 1);
    else if (e.key === 'ArrowLeft') next = Math.max(0, (cursor ?? n) - 1);
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = n - 1;
    else if (e.key === 'Escape') next = null;
    else return;
    e.preventDefault();
    setCursor(next);
  };

  const hatchId = `${summaryId}-hatch`.replace(/:/g, '');
  const yTicks = model ? ticks(model.dom, compact ? 1 : 3) : [];
  const xTicks = model ? ticks([model.t0, model.t1], 3) : [];
  const staleX = staleAt && model ? model.x(Math.min(model.t1, staleAt.getTime() / 1000)) : null;

  return (
    <figure
      className="m-0 flex min-w-0 flex-col gap-1"
      data-testid="metric-chart"
      data-metric={metricKey ?? series?.metric}
      data-unit={unit}
      data-gaps={model?.sum.gapRuns ?? 0}
      data-null-points={model?.sum.nullPoints ?? 0}
      data-segments={model?.path.segments.length ?? 0}
      data-stale={series?.stale ? 'true' : 'false'}
      data-never={neverReported ? 'true' : 'false'}
    >
      {!compact && (
        <figcaption className="flex flex-wrap items-baseline gap-x-2 text-[12.5px]">
          <span className="font-medium">{title}</span>
          <span className="font-mono text-fg-muted">
            {cur ? fmt(cur[1]) : fmt(model?.sum.last ?? null)}
          </span>
          {staleAt && (
            <span className="text-[11.5px] text-stale" data-testid="stale-marker-label">
              ◐ {t('chart.staleSince', { time: formatClock(staleAt, locale) })}
            </span>
          )}
        </figcaption>
      )}
      <div ref={wrapRef} className="relative w-full">
        {neverReported ? (
          <div
            className="grid place-items-center rounded-md border border-dashed border-line-strong bg-surface-2 text-[12px] text-fg-muted"
            style={{ height }}
            data-testid="chart-never"
          >
            {t('chart.never')}
          </div>
        ) : (
          <div
            tabIndex={compact ? -1 : 0}
            role={compact ? 'img' : 'group'}
            aria-label={compact ? summaryText : t('chart.aria', { title })}
            aria-describedby={compact ? undefined : summaryId}
            onKeyDown={onKey}
            onPointerLeave={() => setCursor(null)}
            onPointerMove={(e) => {
              if (!model || compact) return;
              const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
              const px = e.clientX - rect.left;
              const tt = model.t0 + ((px - pad.l) / model.iw) * (model.t1 - model.t0);
              setCursor(nearestIndex(model.pts, tt));
            }}
            className="rounded-md focus-visible:outline-offset-1"
          >
            <svg
              width={width}
              height={height}
              viewBox={`0 0 ${width} ${height}`}
              className="block overflow-visible"
              aria-hidden="true"
            >
              <defs>
                <pattern
                  id={hatchId}
                  width="6"
                  height="6"
                  patternUnits="userSpaceOnUse"
                  patternTransform="rotate(45)"
                >
                  <line
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="6"
                    className="stroke-line-strong"
                    strokeWidth="1.5"
                  />
                </pattern>
              </defs>
              {model &&
                !compact &&
                yTicks.map((v, i) => (
                  <g key={`y${i}`}>
                    <line
                      x1={pad.l}
                      x2={width - pad.r}
                      y1={model.y(v)}
                      y2={model.y(v)}
                      className="stroke-line-subtle"
                      strokeWidth="1"
                    />
                    <text
                      x={pad.l - 6}
                      y={model.y(v) + 3.5}
                      textAnchor="end"
                      className="fill-fg-muted font-mono text-[10.5px]"
                    >
                      {formatMetric(v, unit)}
                    </text>
                  </g>
                ))}
              {model &&
                !compact &&
                xTicks.map((tv, i) => (
                  <text
                    key={`x${i}`}
                    x={model.x(tv)}
                    y={height - 6}
                    textAnchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}
                    className="fill-fg-muted font-mono text-[10.5px]"
                  >
                    {timeLabel(tv, range, locale)}
                  </text>
                ))}
              {model?.runs.map(([a, b], i) => {
                const x0 = Math.max(
                  pad.l,
                  model.x(a) - (model.step * (model.iw / (model.t1 - model.t0 || 1))) / 2,
                );
                const x1 = Math.min(
                  width - pad.r,
                  model.x(b) + (model.step * (model.iw / (model.t1 - model.t0 || 1))) / 2,
                );
                return (
                  <rect
                    key={`g${i}`}
                    data-testid="chart-gap"
                    x={x0}
                    y={pad.t}
                    width={Math.max(2, x1 - x0)}
                    height={model.ih}
                    fill={`url(#${hatchId})`}
                    opacity={0.7}
                  />
                );
              })}
              {model && (
                <path
                  data-testid="series-path"
                  d={model.path.d}
                  fill="none"
                  className="stroke-accent-text"
                  strokeWidth={compact ? 1.5 : 2}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              )}
              {model?.path.segments
                .filter((s) => s.pts.length === 1)
                .map((s, i) => (
                  <circle
                    key={`p${i}`}
                    cx={s.pts[0]![0]}
                    cy={s.pts[0]![1]}
                    r={2.5}
                    className="fill-accent-text"
                  />
                ))}
              {staleX !== null && model && (
                <g data-testid="stale-marker">
                  <line
                    x1={staleX}
                    x2={staleX}
                    y1={pad.t}
                    y2={pad.t + model.ih}
                    className="stroke-stale"
                    strokeWidth="1.5"
                    strokeDasharray="3 3"
                  />
                </g>
              )}
              {cur && model && (
                <g>
                  <line
                    x1={model.x(cur[0])}
                    x2={model.x(cur[0])}
                    y1={pad.t}
                    y2={pad.t + model.ih}
                    className="stroke-fg-subtle"
                    strokeWidth="1"
                  />
                  {cur[1] !== null && (
                    <circle
                      cx={model.x(cur[0])}
                      cy={model.y(cur[1])}
                      r={4}
                      className="fill-accent-text stroke-surface"
                      strokeWidth="2"
                    />
                  )}
                </g>
              )}
            </svg>
            {cur && model && !compact && (
              <div
                role="status"
                data-testid="chart-tooltip"
                className="pointer-events-none absolute top-1 rounded-md border border-line bg-surface px-2 py-1 text-[11.5px] shadow-sm"
                style={{
                  left: Math.min(Math.max(model.x(cur[0]) + 8, pad.l), width - 150),
                }}
              >
                <div className="font-mono text-fg-muted">{formatClock(cur[0] * 1000, locale)}</div>
                <div className="font-mono">
                  {cur[1] === null ? t('chart.gapPoint') : fmt(cur[1])}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
      <p id={summaryId} className="sr-only" data-testid="chart-summary">
        {summaryText}
      </p>
      {!compact && model && (
        <details className="text-[12px] text-fg-muted">
          <summary className="cursor-pointer select-none">{t('chart.table')}</summary>
          <div className="max-h-48 overflow-auto">
            <table className="w-full border-collapse font-mono text-[11.5px]">
              <caption className="sr-only">{title}</caption>
              <thead>
                <tr className="text-left">
                  <th scope="col" className="py-0.5 pr-3 font-medium">
                    {t('chart.col.time')}
                  </th>
                  <th scope="col" className="py-0.5 font-medium">
                    {t('chart.col.value')}
                  </th>
                </tr>
              </thead>
              <tbody>
                {model.pts.map(([ts, v]) => (
                  <tr key={ts} className={cn(v === null && 'text-fg-subtle')}>
                    <td className="py-0.5 pr-3">{formatClock(ts * 1000, locale)}</td>
                    <td className="py-0.5">{v === null ? t('chart.gapPoint') : fmt(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </figure>
  );
}
