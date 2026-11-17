'use client';

import Link from 'next/link';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { useServers } from '@/lib/queries';
import { isApiError } from '@/lib/api/errors';
import { envLabelKey, fleetCounts, osLabel } from '@/lib/servers';
import { formatClock } from '@/lib/time';
import { useDesignData, type DesignTone } from '@/mocks/use-design-data';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, Page, PageHeader } from '@/components/ui/card';
import { ToneBadge, toneText, TONE_GLYPH } from '@/components/ui/badge';
import { ResourceMeter } from '@/components/ui/meter';
import { Skeleton, TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState } from '@/components/ui/states';
import { StatusBadge } from '@/components/servers/server-bits';
import { cn } from '@/lib/utils';

const SEVERITY: Record<Server['status'], number> = { offline: 0, stale: 1, degraded: 2, revoked: 3, enrolling: 4, online: 5 };

function Stat({ label, value, sub, tone }: { label: string; value: string | number; sub: string; tone?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-line bg-surface px-4 py-3.5">
      <span className="text-[12.5px] text-fg-muted">{label}</span>
      <span className="font-mono text-[26px] font-semibold tracking-[-.02em]">{value}</span>
      <span className={cn('text-[12px] text-fg-muted', tone)}>{sub}</span>
    </div>
  );
}

function PreviewTag() {
  const { t } = useI18n();
  return <span className="rounded border border-dashed border-info px-1.5 font-mono text-[10.5px] text-info">{t('overview.previewNote')}</span>;
}

export function OverviewView() {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const q = useServers();
  const d = useDesignData();
  const servers = q.data?.items ?? [];
  const c = q.data ? fleetCounts(servers) : null;
  const forbidden = !can('fleet.read') || (isApiError(q.error) && q.error.status === 403);
  const v = (n: number | undefined) => (c ? (n ?? 0) : '—');
  const top = [...servers].sort((a, b) => SEVERITY[a.status] - SEVERITY[b.status]).slice(0, 8);

  return (
    <Page className="gap-5">
      <PageHeader
        title={t('overview.title')}
        subtitle={
          q.dataUpdatedAt && c
            ? t('overview.subtitle', { time: formatClock(new Date(q.dataUpdatedAt), locale), stale: c.stale + c.offline })
            : t('overview.subtitleUnknown')
        }
        actions={
          <Button onClick={() => void q.refetch()} disabled={q.isFetching || forbidden}>
            {q.isFetching ? t('common.loading') : t('common.refresh')}
          </Button>
        }
      />
      {forbidden ? (
        <ForbiddenState perm="fleet.read" />
      ) : (
        <>
          {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
          <div className="grid grid-cols-[repeat(auto-fit,minmax(170px,1fr))] gap-3">
            {q.isPending ? (
              Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[98px]" />)
            ) : (
              <>
                <Stat label={t('overview.stat.registered')} value={v(c?.total)} sub={c ? t('overview.stat.subTotal') : t('overview.stat.unknown')} />
                <Stat label={t('overview.stat.online')} value={v(c?.online)} sub={t('overview.stat.subOnline')} tone="text-ok" />
                <Stat label={t('overview.stat.degraded')} value={v(c?.degraded)} sub={t('overview.stat.subDegraded')} tone={c?.degraded ? 'text-warn' : undefined} />
                <Stat label={t('overview.stat.stale')} value={v(c?.stale)} sub={t('overview.stat.subStale')} tone={c?.stale ? 'text-stale' : undefined} />
                <Stat label={t('overview.stat.offline')} value={v(c?.offline)} sub={t('overview.stat.subOffline')} tone={c?.offline ? 'text-crit' : undefined} />
                <Stat label={t('overview.stat.enrolling')} value={v(c?.other)} sub={t('overview.stat.subTotal')} />
              </>
            )}
          </div>
        </>
      )}

      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,520px),1fr))] items-start gap-4">
        <Card className="overflow-hidden">
          <CardHeader
            title={t('overview.serverHealth')}
            actions={
              <Link href="/servers" className="text-[13px]">
                {t('overview.viewAll')}
              </Link>
            }
          />
          {forbidden ? null : q.isPending ? (
            <TableSkeleton label={t('common.loading')} />
          ) : servers.length === 0 ? (
            <div className="p-4">
              <EmptyState title={t('overview.noServers')} action={<Link href="/servers?enroll=1">{t('servers.enroll')}</Link>} />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[560px] border-collapse text-[13px]">
                <thead>
                  <tr className="text-left text-[12px] text-fg-muted">
                    <th scope="col" className="px-4 py-2 font-medium">{t('servers.col.server')}</th>
                    <th scope="col" className="px-2 py-2 font-medium">{t('servers.col.status')}</th>
                    <th scope="col" className="px-2 py-2 font-medium">{t('metric.cpu')}</th>
                    <th scope="col" className="px-2 py-2 font-medium">{t('metric.ram')}</th>
                    <th scope="col" className="px-4 py-2 font-medium">{t('metric.disk')}</th>
                  </tr>
                </thead>
                <tbody>
                  {top.map((s) => {
                    const m = s.metrics;
                    const stale = !!m?.stale;
                    const cell = (n: number | null | undefined) => (m && n != null ? `${stale ? '◐ ' : ''}${Math.round(n)}%` : t('common.noData'));
                    return (
                      <tr key={s.id} className="border-t border-line-subtle">
                        <td className="px-4 py-[9px]">
                          <Link href={`/servers/${s.id}/overview`} className="font-mono text-[12.5px] text-fg">
                            {s.name}
                          </Link>
                          <div className="text-[11.5px] text-fg-subtle">
                            {t(envLabelKey(s.environment))} · {osLabel(s) ?? '—'}
                          </div>
                        </td>
                        <td className="px-2">
                          <StatusBadge status={s.status} />
                        </td>
                        <td className={cn('px-2 font-mono text-[12px]', stale ? 'text-stale' : !m && 'text-fg-subtle')}>{cell(m?.cpuPct)}</td>
                        <td className={cn('px-2 font-mono text-[12px]', stale ? 'text-stale' : !m && 'text-fg-subtle')}>{cell(m?.memPct)}</td>
                        <td className="px-4 py-[9px]">
                          <ResourceMeter label={t('metric.disk')} value={m ? m.diskPct : null} stale={stale} noDataLabel={t('common.noData')} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader title={t('overview.incidents')} actions={<PreviewTag />} />
            {d.INC.map((i) => (
              <div key={i.id} className="flex items-start gap-3 border-t border-line-subtle px-4 py-2.5 first:border-0">
                <span aria-hidden="true" className={cn('w-3.5 font-bold', toneText[i.t as DesignTone])}>
                  {TONE_GLYPH[i.t as DesignTone]}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13.5px]">{i.title}</div>
                  <div className="text-[12px] text-fg-subtle">{i.meta}</div>
                </div>
              </div>
            ))}
          </Card>
          <Card>
            <CardHeader
              title={t('overview.deployments')}
              actions={
                <>
                  <PreviewTag />
                  <Link href="/deployments" className="text-[13px]">
                    {t('overview.newDeploy')}
                  </Link>
                </>
              }
            />
            {d.APPS.slice(0, 4).map((a) => (
              <div key={a.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-0.5 border-t border-line-subtle px-4 py-[9px] first:border-0">
                <span className="text-[13.5px]">
                  {a.id} <span className="font-mono text-[12px] text-fg-subtle">{a.dep}</span>
                </span>
                <ToneBadge tone={a.t as DesignTone}>{a.health}</ToneBadge>
                <span className="text-[12px] text-fg-subtle">
                  {a.env} · {a.server}
                </span>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </Page>
  );
}
