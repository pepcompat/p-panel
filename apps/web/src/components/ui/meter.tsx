import { cn } from '@/lib/utils';

export function meterTone(pct: number): 'ok' | 'warn' | 'crit' {
  return pct >= 90 ? 'crit' : pct >= 70 ? 'warn' : 'ok';
}
const fill = { ok: 'bg-ok', warn: 'bg-warn', crit: 'bg-crit' } as const;
const text = { ok: 'text-fg', warn: 'text-warn', crit: 'text-crit' } as const;

/**
 * ResourceMeter. `value === null` means "no data" (rendered as an empty track + label, never 0%).
 * `stale` renders the last-known value muted with a ◐ marker.
 */
export function ResourceMeter({
  label,
  value,
  stale,
  noDataLabel,
  size = 'sm',
}: {
  label: string;
  value: number | null;
  stale?: boolean;
  noDataLabel: string;
  size?: 'sm' | 'md';
}) {
  const has = value !== null && Number.isFinite(value);
  const pct = has ? Math.max(0, Math.min(100, value)) : 0;
  const tone = meterTone(pct);
  return (
    <div
      className={cn(
        'grid items-center gap-2',
        size === 'sm'
          ? 'grid-cols-[38px_minmax(0,1fr)_72px] text-[12px]'
          : 'grid-cols-[44px_minmax(0,1fr)_84px] text-[12.5px]',
      )}
    >
      <span className="text-fg-muted">{label}</span>
      <div
        role={has ? 'meter' : undefined}
        aria-label={label}
        aria-valuemin={has ? 0 : undefined}
        aria-valuemax={has ? 100 : undefined}
        aria-valuenow={has ? Math.round(pct) : undefined}
        className={cn(
          'overflow-hidden rounded-[3px] bg-track',
          size === 'sm' ? 'h-1.5' : 'h-2 rounded',
        )}
      >
        {has && (
          <div
            className={cn('h-full', fill[tone], stale && 'opacity-45')}
            style={{ width: `${pct}%` }}
          />
        )}
      </div>
      <span
        className={cn(
          'text-right font-mono',
          has ? (stale ? 'text-stale' : text[tone]) : 'text-fg-subtle',
        )}
      >
        {has ? `${stale ? '◐ ' : ''}${Math.round(pct)}%` : noDataLabel}
      </span>
    </div>
  );
}
