'use client';

import { useI18n } from '@/i18n/provider';
import type { ComposeHealthView, DeploymentCompose } from '@/lib/api/p4b-types';
import type { ComposePlanRow, PlanAction } from '@/lib/p4b-gates';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import type { MessageKey } from '@/i18n/en';

const ACTION_TONE: Record<PlanAction, Tone> = {
  unchanged: 'off',
  created: 'info',
  replaced: 'warn',
  removed: 'crit',
};

export function ComposeActionBadge({ action }: { action: PlanAction }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={ACTION_TONE[action]} size="sm">
      {t(`cmp.action.${action}` as MessageKey)}
    </ToneBadge>
  );
}

/** `http :8000 /healthz` · `tcp :5432` · `running`. */
export function HealthLabel({ h }: { h: ComposeHealthView }) {
  const { t } = useI18n();
  const text =
    h.type === 'http'
      ? `http :${h.port} ${h.path}`
      : h.type === 'tcp'
        ? `tcp :${h.port}`
        : t('cmp.health.running');
  return <span className="font-mono text-[12px]">{text}</span>;
}

const th = 'px-2 py-2 text-left text-[12px] font-medium text-fg-muted';

/** Agent health strings → tone (unknown strings stay neutral). */
function healthTone(h: string | null): Tone {
  if (!h) return 'off';
  if (/unhealthy|fail|exit/i.test(h)) return 'crit';
  if (/healthy|running|ok|kept/i.test(h)) return 'ok';
  if (/start|wait|pending/i.test(h)) return 'info';
  return 'off';
}

type DeploymentService = DeploymentCompose['services'][number];

/**
 * Per-service rows of a compose deployment (§8.3): action (agent-reported, else the planned one) and
 * health. Unchanged services are kept running; the route column marks the service behind Nginx.
 */
export function ComposeServicesTable({
  services,
  routeService,
}: {
  services: readonly DeploymentService[];
  routeService?: string;
}) {
  const { t } = useI18n();
  return (
    <div
      className="overflow-x-auto rounded-md border border-line"
      data-testid="compose-services-table"
    >
      <table className="w-full border-collapse text-[12.5px]" style={{ minWidth: 560 }}>
        <caption className="sr-only">{t('cmp.services')}</caption>
        <thead>
          <tr className="bg-surface-2">
            <th scope="col" className={`${th} pl-3`}>
              {t('cmp.col.service')}
            </th>
            <th scope="col" className={th}>
              {t('cmp.col.action')}
            </th>
            <th scope="col" className={th}>
              {t('cmp.col.health')}
            </th>
            <th scope="col" className={`${th} pr-3`}>
              {t('cmp.col.image')}
            </th>
          </tr>
        </thead>
        <tbody>
          {services.map((s) => {
            const planned: PlanAction =
              s.plannedAction === 'unchanged'
                ? 'unchanged'
                : s.previousName
                  ? 'replaced'
                  : 'created';
            return (
              <tr
                key={s.service}
                className="border-t border-line-subtle"
                data-testid="compose-service-row"
                data-service={s.service}
                data-action={s.action ?? 'pending'}
                data-planned={planned}
              >
                <td className="px-3 py-1.5 font-mono">
                  {s.service}
                  {s.service === routeService && (
                    <span className="ml-1.5 text-[11px] text-fg-muted">{t('cmp.route')}</span>
                  )}
                </td>
                <td className="px-2 py-1.5">
                  {s.action ? (
                    <ComposeActionBadge action={s.action} />
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-[12px] text-fg-muted">
                      <ComposeActionBadge action={planned} />
                      {t('cmp.planned')}
                    </span>
                  )}
                </td>
                <td className="px-2 py-1.5">
                  <ToneBadge tone={healthTone(s.health)} size="sm">
                    {s.health ?? t('cmp.hs.pending')}
                  </ToneBadge>
                </td>
                <td className="px-2 py-1.5 pr-3 font-mono text-[11.5px] break-all text-fg-muted">
                  {s.sourceImage !== s.image ? (
                    <span className="flex flex-col">
                      <span>{s.sourceImage}</span>
                      <span>→ {s.image}</span>
                    </span>
                  ) : (
                    s.image
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Review: expected per-service actions against the current version. */
export function ComposePlanTable({ rows }: { rows: readonly ComposePlanRow[] }) {
  const { t } = useI18n();
  return (
    <div className="overflow-x-auto rounded-md border border-line" data-testid="compose-plan">
      <table className="w-full border-collapse text-[12.5px]" style={{ minWidth: 520 }}>
        <caption className="sr-only">{t('cmp.plan')}</caption>
        <thead>
          <tr className="bg-surface-2">
            <th scope="col" className={`${th} pl-3`}>
              {t('cmp.col.service')}
            </th>
            <th scope="col" className={th}>
              {t('cmp.col.expected')}
            </th>
            <th scope="col" className={`${th} pr-3`}>
              {t('cmp.col.image')}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.service}
              className="border-t border-line-subtle"
              data-testid="compose-plan-row"
              data-service={r.service}
              data-action={r.action}
            >
              <td className="px-3 py-1.5 font-mono">
                {r.service}
                {r.isRoute && (
                  <span className="ml-1.5 text-[11px] text-fg-muted">{t('cmp.route')}</span>
                )}
              </td>
              <td className="px-2 py-1.5">
                <ComposeActionBadge action={r.action} />
              </td>
              <td className="px-2 py-1.5 pr-3 font-mono text-[11.5px] break-all">
                {r.action === 'replaced' && r.previousImage && r.previousImage !== r.image ? (
                  <span className="flex flex-col">
                    <span className="text-fg-muted line-through">{r.previousImage}</span>
                    <span>{r.image}</span>
                  </span>
                ) : (
                  (r.image ?? r.previousImage)
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
