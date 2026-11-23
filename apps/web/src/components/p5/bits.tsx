'use client';

import { useEffect, useState } from 'react';
import { useI18n } from '@/i18n/provider';
import {
  METRIC_RANGES,
  type IncidentStatus,
  type LogLevel,
  type MetricRange,
  type Severity,
} from '@/lib/api/p5-types';
import type { ApiError } from '@/lib/api/errors';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Segmented } from '@/components/ui/segmented';
import { Notice } from '@/components/ui/states';
import type { MessageKey } from '@/i18n/en';

export function RangePicker({
  value,
  onChange,
}: {
  value: MetricRange;
  onChange: (r: MetricRange) => void;
}) {
  const { t } = useI18n();
  return (
    <Segmented
      label={t('range.label')}
      value={value}
      onChange={onChange}
      mono
      options={METRIC_RANGES.map((r) => ({ value: r, label: r }))}
    />
  );
}

export const SEVERITY_TONE: Record<Severity, Tone> = {
  info: 'info',
  warning: 'warn',
  critical: 'crit',
};
export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={SEVERITY_TONE[severity] ?? 'info'} size="sm">
      {t(`sev.${severity}` as MessageKey)}
    </ToneBadge>
  );
}

export const INCIDENT_TONE: Record<IncidentStatus, Tone> = {
  firing: 'crit',
  acknowledged: 'warn',
  resolved: 'ok',
};
export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge
      tone={INCIDENT_TONE[status] ?? 'off'}
      glyph={status === 'acknowledged' ? '◆' : undefined}
      size="sm"
    >
      {t(`inc.status.${status}` as MessageKey)}
    </ToneBadge>
  );
}

const LEVEL_TONE: Record<LogLevel, Tone> = {
  debug: 'off',
  info: 'info',
  warn: 'warn',
  error: 'crit',
  fatal: 'crit',
};
export function LevelBadge({ level }: { level: LogLevel | null }) {
  if (!level)
    return <span className="inline-block w-[52px] font-mono text-[11px] text-fg-subtle">—</span>;
  return (
    <ToneBadge
      tone={LEVEL_TONE[level] ?? 'off'}
      glyph={false}
      size="sm"
      className="w-[52px] justify-center font-mono uppercase"
    >
      {level}
    </ToneBadge>
  );
}

/** 429 notice with a live countdown; `onReady` fires once the wait is over. */
export function RateLimitNotice({ error, onReady }: { error: ApiError; onReady?: () => void }) {
  const { t } = useI18n();
  const total = error.retryAfterSec ?? 30;
  const [left, setLeft] = useState(total);
  useEffect(() => {
    setLeft(total);
    const started = Date.now();
    const id = window.setInterval(() => {
      const l = Math.max(0, total - Math.floor((Date.now() - started) / 1000));
      setLeft(l);
      if (l === 0) window.clearInterval(id);
    }, 500);
    return () => window.clearInterval(id);
  }, [error, total]);
  useEffect(() => {
    if (left === 0) onReady?.();
  }, [left, onReady]);
  return (
    <Notice tone="warn" glyph="▲" role="status" title={t('rl.title')}>
      <span data-testid="rate-limited">
        {left > 0 ? t('rl.body', { sec: left }) : t('rl.ready')}
      </span>
      {error.requestId && (
        <span className="ml-2 font-mono text-[11.5px] text-fg-muted">{error.requestId}</span>
      )}
    </Notice>
  );
}

export const metricTitleKey = (m: string): MessageKey => `metric.name.${m}` as MessageKey;

/** Incidents currently firing against a server (directly, or against one of its apps). */
export function firingForServer(
  serverId: string,
  incidents: ReadonlyArray<{ status: IncidentStatus; serverId?: string }>,
): number {
  return incidents.filter((i) => i.status === 'firing' && i.serverId === serverId).length;
}

export function AlertFiringBadge({ count }: { count: number }) {
  const { t } = useI18n();
  if (count <= 0) return null;
  return (
    <ToneBadge tone="crit" glyph="▲" size="sm" className="font-medium">
      <span data-testid="alert-firing-badge">{t('inc.firingBadge', { n: count })}</span>
    </ToneBadge>
  );
}
