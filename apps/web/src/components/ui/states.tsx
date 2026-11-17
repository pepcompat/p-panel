'use client';

import type { ReactNode } from 'react';
import { useT } from '@/i18n/provider';
import { toApiError } from '@/lib/api/errors';
import { cn } from '@/lib/utils';
import { Button } from './button';

export function Notice({
  tone = 'warn',
  glyph,
  title,
  children,
  action,
  className,
  role,
}: {
  tone?: 'warn' | 'crit' | 'info' | 'ok' | 'neutral';
  glyph?: string;
  title?: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
  role?: 'alert' | 'status' | 'note';
}) {
  const box = {
    warn: 'border-notice-line bg-notice-bg',
    crit: 'border-crit bg-crit-bg',
    info: 'border-line bg-info-bg',
    ok: 'border-line bg-ok-bg',
    neutral: 'border-transparent bg-chip-2',
  }[tone];
  const g = { warn: 'text-warn', crit: 'text-crit', info: 'text-info', ok: 'text-ok', neutral: 'text-fg-muted' }[tone];
  return (
    <div role={role} className={cn('flex items-start gap-3 rounded-lg border px-3.5 py-3 text-[13.5px]', box, className)}>
      {glyph && (
        <span aria-hidden="true" className={cn('font-bold', g)}>
          {glyph}
        </span>
      )}
      <div className="min-w-0 flex-1">
        {title && <b>{title} </b>}
        {children}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  const t = useT();
  const e = toApiError(error);
  return (
    <div role="alert" className={cn('flex flex-col gap-2 rounded-lg border border-crit bg-crit-bg p-4 text-[13.5px]', className)}>
      <div className="flex items-center gap-2">
        <span aria-hidden="true" className="font-bold text-crit">
          ✕
        </span>
        <b className="flex-1">{t('state.error.title')}</b>
        {onRetry && (
          <Button size="sm" onClick={onRetry}>
            {t('common.retry')}
          </Button>
        )}
      </div>
      <div>{e.kind === 'network' ? t('state.error.network') : e.message}</div>
      <div className="font-mono text-[12px] text-fg-muted">
        {e.code}
        {e.status ? ` · HTTP ${e.status}` : ''}
        {e.requestId && (
          <>
            {' · '}
            {t('common.requestId')}: <span className="select-all">{e.requestId}</span>
          </>
        )}
      </div>
    </div>
  );
}

export function ForbiddenState({ perm, requestId }: { perm: string; requestId?: string | null }) {
  const t = useT();
  return (
    <div role="alert" className="flex flex-col gap-1 rounded-lg border border-line bg-surface p-5 text-[13.5px]">
      <b>
        <span aria-hidden="true" className="text-off">
          ○{' '}
        </span>
        {t('state.forbidden.title')}
      </b>
      <span className="text-fg-muted">{t('state.forbidden.body', { perm })}</span>
      {requestId && (
        <span className="font-mono text-[12px] text-fg-muted">
          {t('common.requestId')}: {requestId}
        </span>
      )}
    </div>
  );
}

export function EmptyState({ title, body, action }: { title: ReactNode; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed border-line-strong bg-surface p-6 text-[13.5px]">
      <b>{title}</b>
      {body && <span className="text-fg-muted">{body}</span>}
      {action}
    </div>
  );
}

export function ProposedBanner({ body }: { body?: ReactNode }) {
  const t = useT();
  return (
    <Notice tone="info" glyph="◆" title={t('state.proposed.title')} role="note">
      <span className="text-fg-2">{body ?? t('state.proposed.body')}</span>
    </Notice>
  );
}

export function PreviewBanner() {
  const t = useT();
  return (
    <div role="note" data-testid="preview-banner" className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-dashed border-info bg-info-bg px-3.5 py-2.5 text-[13px]">
      <span className="rounded bg-info px-2 py-px font-mono text-[11px] font-semibold tracking-[.06em] text-white">PREVIEW</span>
      <b>{t('state.preview.title')}</b>
      <span className="text-fg-2">{t('state.preview.body')}</span>
    </div>
  );
}
