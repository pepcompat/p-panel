import type { ReactNode } from 'react';
import type { Environment, ServerStatus } from '@ppanel/shared-contracts';
import { cn } from '@/lib/utils';

export type Tone = 'ok' | 'warn' | 'stale' | 'crit' | 'info' | 'off';

/** Glyphs from the design's tone table — status is never conveyed by colour alone. */
export const TONE_GLYPH: Record<Tone, string> = { ok: '●', warn: '▲', stale: '◐', crit: '✕', info: '◆', off: '○' };

const toneClass: Record<Tone, string> = {
  ok: 'bg-ok-bg text-ok',
  warn: 'bg-warn-bg text-warn',
  stale: 'bg-stale-bg text-stale',
  crit: 'bg-crit-bg text-crit',
  info: 'bg-info-bg text-info',
  off: 'bg-off-bg text-off',
};
export const toneText: Record<Tone, string> = {
  ok: 'text-ok',
  warn: 'text-warn',
  stale: 'text-stale',
  crit: 'text-crit',
  info: 'text-info',
  off: 'text-off',
};
export const toneBorderTop: Record<Tone, string> = {
  ok: 'border-t-ok',
  warn: 'border-t-warn',
  stale: 'border-t-stale',
  crit: 'border-t-crit',
  info: 'border-t-info',
  off: 'border-t-off',
};

export function ToneBadge({
  tone,
  glyph,
  children,
  className,
  size = 'md',
}: {
  tone: Tone;
  glyph?: string | false;
  children: ReactNode;
  className?: string;
  size?: 'sm' | 'md';
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-[5px] rounded px-2 whitespace-nowrap',
        size === 'md' ? 'py-px text-[12px]' : 'px-1.5 text-[11px]',
        toneClass[tone],
        className,
      )}
    >
      {glyph !== false && <span aria-hidden="true">{glyph ?? TONE_GLYPH[tone]}</span>}
      {children}
    </span>
  );
}

export const STATUS_TONE: Record<ServerStatus, Tone> = {
  online: 'ok',
  degraded: 'warn',
  stale: 'stale',
  offline: 'off',
  enrolling: 'info',
  revoked: 'crit',
};

const envClass: Record<Environment, string> = {
  production: 'bg-env-prod text-env-prod-fg',
  uat: 'bg-env-uat text-env-uat-fg',
  development: 'bg-env-dev text-env-dev-fg',
};

/** "■ PRODUCTION" style environment label. */
export function EnvBadge({ env, label, className }: { env: Environment | 'all'; label: string; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded px-2.5 py-0.5 font-mono text-[11.5px] font-semibold tracking-[.06em] whitespace-nowrap',
        env === 'all' ? 'bg-chip-2 text-fg' : envClass[env],
        className,
      )}
    >
      <span aria-hidden="true">■</span>
      {label}
    </span>
  );
}

export function OutlineTag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn('rounded-[3px] border border-line-strong px-1.5 font-mono text-[11px] whitespace-nowrap', className)}>
      {children}
    </span>
  );
}
