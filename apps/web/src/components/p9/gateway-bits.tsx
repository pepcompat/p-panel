'use client';

import type { MessageKey } from '@/i18n/en';
import { useI18n } from '@/i18n/provider';
import { PLAN_RUNNING, ROUTE_MODES, type PlanStatus, type RouteMode } from '@/lib/api/p9-types';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

const MODE_TONE: Record<RouteMode, Tone> = { direct: 'off', hybrid: 'info', gateway: 'ok' };
export const modeKey = (m: RouteMode): MessageKey => `p9.mode.${m}` as MessageKey;
export const modeExplainKey = (m: RouteMode): MessageKey => `p9.mode.${m}.explain` as MessageKey;

export function ModeBadge({ mode }: { mode: RouteMode }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={MODE_TONE[mode]} size="sm" glyph={false}>
      <span data-testid="route-mode" data-mode={mode}>
        {t(modeKey(mode))}
      </span>
    </ToneBadge>
  );
}

/** The three modes side by side: what serves the domain and where DNS points. */
export function ModeLegend({ className }: { className?: string }) {
  const { t } = useI18n();
  return (
    <dl
      className={cn('m-0 grid gap-2 sm:grid-cols-3', className)}
      aria-label={t('p9.mode.legend')}
      data-testid="mode-legend"
    >
      {ROUTE_MODES.map((m) => (
        <div key={m} className="flex flex-col gap-1 rounded-md border border-line px-3 py-2">
          <dt className="flex items-center gap-2">
            <ModeBadge mode={m} />
          </dt>
          <dd className="m-0 text-[12.5px] text-fg-2">{t(modeExplainKey(m))}</dd>
          <dd className="m-0 font-mono text-[11.5px] text-fg-muted">
            {t(`p9.mode.${m}.dns` as MessageKey)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

const PLAN_TONE: Record<PlanStatus, Tone> = {
  draft: 'info',
  validated: 'info',
  shadow_testing: 'info',
  shadow_tested: 'ok',
  awaiting_approval: 'warn',
  applying: 'info',
  applied: 'ok',
  rolling_back: 'warn',
  rolled_back: 'off',
  failed: 'crit',
  cancelled: 'off',
};

export function PlanStatusBadge({ status }: { status: PlanStatus }) {
  const { t } = useI18n();
  const busy = PLAN_RUNNING.includes(status) || status === 'draft';
  return (
    <ToneBadge tone={PLAN_TONE[status]} glyph={busy ? '◌' : undefined}>
      <span data-testid="plan-status" data-status={status}>
        {t(`p9.plan.status.${status}` as MessageKey)}
      </span>
    </ToneBadge>
  );
}
