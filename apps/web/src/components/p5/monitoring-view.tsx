'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { ENVIRONMENTS, type Environment } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import { isMetricRange, type FleetServerSummary, type MetricRange } from '@/lib/api/p5-types';
import { useActiveIncidents, useFleetMetrics, useMetricSeries } from '@/lib/p5-queries';
import { useApplications } from '@/lib/p3-queries';
import { envLabelKey } from '@/lib/servers';
import { formatClock, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { Card, CardHeader, Page, PageHeader } from '@/components/ui/card';
import { ToneBadge, toneBorderTop, type Tone } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ResourceMeter } from '@/components/ui/meter';
import { Segmented } from '@/components/ui/segmented';
import { CardSkeletonGrid, TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { StatusBadge } from '@/components/servers/server-bits';
import { Table, Td, Th } from '@/components/preview/shared';
import { MetricChart } from './metric-chart';
import { ServerMetricsPanel } from './metrics-panels';
import { AlertFiringBadge, RangePicker, RateLimitNotice, firingForServer } from './bits';

export type FleetState = 'ok' | 'stale' | 'offline' | 'no_metrics';

/** D4-A: offline, stale and "never reported" are distinct states — none of them is 0. */
export function fleetState(r: Pick<FleetServerSummary, 'status' | 'sample' | 'stale'>): FleetState {
  if (r.status === 'offline' || r.status === 'revoked') return 'offline';
  if (!r.sample) return 'no_metrics';
  if (r.stale || r.status === 'stale') return 'stale';
  return 'ok';
}
const STATE_TONE: Record<FleetState, Tone> = {
  ok: 'ok',
  stale: 'stale',
  offline: 'off',
  no_metrics: 'info',
};

type EnvFilter = 'all' | Environment;
type StateFilter = 'all' | 'attention';

function useMonitoringParams() {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const rangeRaw = sp.get('range');
  const range: MetricRange = isMetricRange(rangeRaw) ? rangeRaw : '1h';
  const envRaw = sp.get('env');
  const env: EnvFilter = (ENVIRONMENTS as readonly string[]).includes(envRaw ?? '')
    ? (envRaw as Environment)
    : 'all';
  const state: StateFilter = sp.get('state') === 'attention' ? 'attention' : 'all';
  const server = sp.get('server');
  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(sp.toString());
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === '' || (k === 'range' && v === '1h') || v === 'all') next.delete(k);
      else next.set(k, v);
    }
    const qs = next.toString();
    router.replace(`${pathname}${qs ? `?${qs}` : ''}`, { scroll: false });
  };
  return { range, env, state, server, set };
}

function FleetCard({
  row,
  range,
  firing,
  selected,
  onSelect,
  now,
}: {
  row: FleetServerSummary;
  range: MetricRange;
  firing: number;
  selected: boolean;
  onSelect: () => void;
  now: number;
}) {
  const { t, locale } = useI18n();
  const st = fleetState(row);
  const cpu = useMetricSeries('server', row.serverId, 'cpu', range, st === 'ok' || st === 'stale');
  const s = row.sample;
  const muted = st === 'stale';
  return (
    <article
      aria-labelledby={`fleet-${row.serverId}`}
      data-testid="fleet-card"
      data-server={row.name}
      data-state={st}
      className={cn(
        'flex flex-col gap-2.5 rounded-lg border border-t-[3px] border-line bg-surface p-3.5',
        toneBorderTop[STATE_TONE[st]],
        selected && 'ring-2 ring-accent-strong/40',
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h3
          id={`fleet-${row.serverId}`}
          className="m-0 flex-1 truncate font-mono text-[13.5px] font-medium"
        >
          {row.name}
        </h3>
        <AlertFiringBadge count={firing} />
        <StatusBadge status={row.status} />
      </div>
      <div className="text-[11.5px] text-fg-subtle">{t(envLabelKey(row.environment))}</div>
      {st === 'offline' ? (
        <div
          className="grid min-h-[104px] place-items-center rounded-md bg-chip px-3 text-center text-[12.5px] text-fg-muted"
          data-testid="state-offline"
        >
          <span>
            <span aria-hidden="true">○ </span>
            {t('mon.state.offline')}
            {s?.sampledAt && (
              <span className="block text-[11.5px]">
                {t('mon.lastSample', { time: relativeTime(s.sampledAt, t, now) })}
              </span>
            )}
          </span>
        </div>
      ) : st === 'no_metrics' ? (
        <div
          className="grid min-h-[104px] place-items-center rounded-md border border-dashed border-line-strong px-3 text-center text-[12.5px] text-fg-muted"
          data-testid="state-no-metrics"
        >
          <span>
            <span aria-hidden="true">◆ </span>
            {t('mon.state.noMetrics')}
            <span className="block text-[11.5px]">{t('mon.state.noMetricsBody')}</span>
          </span>
        </div>
      ) : (
        <>
          <div className="flex flex-col gap-1">
            <ResourceMeter
              label={t('metric.cpu')}
              value={s!.cpuPct}
              stale={muted}
              noDataLabel={t('common.noData')}
            />
            <ResourceMeter
              label={t('metric.ram')}
              value={s!.memPct}
              stale={muted}
              noDataLabel={t('common.noData')}
            />
            <ResourceMeter
              label={t('metric.disk')}
              value={s!.diskPct}
              stale={muted}
              noDataLabel={t('common.noData')}
            />
          </div>
          <MetricChart
            compact
            height={44}
            series={cpu.data}
            isLoading={cpu.isPending}
            error={cpu.error}
            title={t('mon.cpuSpark', { name: row.name, range })}
            range={range}
            metricKey="cpu"
          />
          <span
            className={cn('text-[11.5px]', muted ? 'text-stale' : 'text-fg-muted')}
            data-testid={muted ? 'state-stale' : undefined}
          >
            {muted
              ? `◐ ${t('chart.staleSince', { time: formatClock(new Date(s!.sampledAt), locale) })}`
              : t('mon.sampled', { ago: relativeTime(s!.sampledAt, t, now) })}
          </span>
        </>
      )}
      {row.containers?.total || row.logDroppedTotal ? (
        <div className="flex flex-wrap gap-x-3 text-[11.5px] text-fg-muted">
          {row.containers && row.containers.total > 0 && (
            <span>
              {t('mon.containers', {
                running: row.containers.running,
                total: row.containers.total,
              })}
              {row.containers.unhealthy > 0 &&
                ` · ${t('mon.unhealthy', { n: row.containers.unhealthy })}`}
            </span>
          )}
          {!!row.logDroppedTotal && (
            <span className="text-warn" data-testid="log-dropped">
              ▲ {t('mon.logDropped', { n: row.logDroppedTotal })}
            </span>
          )}
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-2 border-t border-line-subtle pt-2">
        <Button
          size="sm"
          variant={selected ? 'primary' : 'secondary'}
          onClick={onSelect}
          aria-pressed={selected}
        >
          {t('mon.charts')}
        </Button>
        <Link
          href={`/servers/${row.serverId}/monitoring?range=${range}`}
          className="ml-auto text-[12.5px]"
          data-testid="server-monitoring-link"
        >
          {t('mon.openServer')}
        </Link>
      </div>
    </article>
  );
}

function AppHealthTable({ range, serverIds }: { range: MetricRange; serverIds: Set<string> }) {
  const { t } = useI18n();
  const apps = useApplications();
  const { active } = useActiveIncidents();
  const rows = (apps.data?.items ?? []).filter(
    (a) => (a.kind === 'container' || a.kind === 'compose') && serverIds.has(a.serverId),
  );
  if (apps.isPending) return <TableSkeleton label={t('common.loading')} />;
  if (apps.isError)
    return isApiError(apps.error) && apps.error.status === 403 ? (
      <ForbiddenState perm="apps.read" requestId={apps.error.requestId} />
    ) : (
      <ErrorState error={apps.error} onRetry={() => void apps.refetch()} />
    );
  if (rows.length === 0) return <EmptyState title={t('mon.apps.empty')} />;
  return (
    <Table
      minWidth={620}
      head={
        <>
          <Th>{t('mon.apps.col.app')}</Th>
          <Th>{t('mon.apps.col.server')}</Th>
          <Th>{t('mon.apps.col.kind')}</Th>
          <Th>{t('mon.apps.col.health')}</Th>
          <Th>{t('mon.apps.col.incidents')}</Th>
          <Th />
        </>
      }
    >
      {rows.map((a) => {
        const rs = a.container?.runtimeState ?? (a.kind === 'compose' ? undefined : 'unknown');
        const tone: Tone = rs === 'running' ? 'ok' : rs === 'stopped' ? 'crit' : 'off';
        const inc = active.filter((i) => i.target.type === 'app' && i.target.id === a.id);
        return (
          <tr key={a.id} data-testid="app-health-row">
            <Td className="font-mono text-[12.5px]">
              <Link href={`/applications/${a.id}/overview`}>{a.name}</Link>
            </Td>
            <Td className="font-mono text-[12px]">{a.serverName ?? a.serverId.slice(0, 8)}</Td>
            <Td className="text-[12.5px]">{a.kind}</Td>
            <Td>
              <ToneBadge tone={tone} size="sm">
                {t(`mon.runtime.${rs ?? 'unknown'}` as 'mon.runtime.unknown')}
              </ToneBadge>
            </Td>
            <Td>
              {inc.length ? (
                <ToneBadge tone="crit" size="sm">
                  {t('inc.firingBadge', { n: inc.length })}
                </ToneBadge>
              ) : (
                <span className="text-fg-subtle">—</span>
              )}
            </Td>
            <Td className="text-right text-[12.5px] whitespace-nowrap">
              <Link href={`/applications/${a.id}/metrics?range=${range}`}>
                {t('mon.apps.metrics')}
              </Link>
              {' · '}
              <Link href={`/applications/${a.id}/logs`}>{t('mon.apps.logs')}</Link>
            </Td>
          </tr>
        );
      })}
    </Table>
  );
}

export function MonitoringView() {
  const { t } = useI18n();
  const { can } = useAuth();
  const now = useNow(10_000);
  const p = useMonitoringParams();
  const q = useFleetMetrics();
  const { active } = useActiveIncidents();
  const rows = useMemo(() => q.data ?? [], [q.data]);
  const filtered = useMemo(
    () =>
      rows
        .filter((r) => p.env === 'all' || r.environment === p.env)
        .filter((r) => p.state === 'all' || fleetState(r) !== 'ok'),
    [rows, p.env, p.state],
  );
  const selected = rows.find((r) => r.serverId === p.server) ?? null;
  const forbidden = !can('fleet.read') || (isApiError(q.error) && q.error.status === 403);
  const counts = rows.reduce((acc, r) => ((acc[fleetState(r)] += 1), acc), {
    ok: 0,
    stale: 0,
    offline: 0,
    no_metrics: 0,
  } as Record<FleetState, number>);

  return (
    <Page>
      <PageHeader
        title={t('mon.title')}
        subtitle={t('mon.subtitle')}
        actions={<RangePicker value={p.range} onChange={(r) => p.set({ range: r })} />}
      />
      {forbidden ? (
        <ForbiddenState perm="fleet.read" />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Segmented
              label={t('mon.filter.env')}
              value={p.env}
              onChange={(v) => p.set({ env: v })}
              options={[
                { value: 'all', label: t('common.all') },
                ...ENVIRONMENTS.map((e) => ({ value: e, label: t(envLabelKey(e)) })),
              ]}
            />
            <Segmented
              label={t('mon.filter.state')}
              value={p.state}
              onChange={(v) => p.set({ state: v })}
              options={[
                { value: 'all', label: t('common.all') },
                {
                  value: 'attention',
                  label: t('mon.filter.attention'),
                  count: counts.stale + counts.offline + counts.no_metrics,
                },
              ]}
            />
            <span className="ml-auto text-[12px] text-fg-muted" data-testid="fleet-counts">
              {t('mon.counts', {
                ok: counts.ok,
                stale: counts.stale,
                offline: counts.offline,
                none: counts.no_metrics,
              })}
            </span>
          </div>
          {q.isError &&
            (isApiError(q.error) && q.error.status === 429 ? (
              <RateLimitNotice error={q.error} onReady={() => void q.refetch()} />
            ) : (
              <ErrorState error={q.error} onRetry={() => void q.refetch()} />
            ))}
          {q.isPending ? (
            <CardSkeletonGrid label={t('common.loading')} />
          ) : rows.length === 0 ? (
            <EmptyState title={t('mon.empty')} body={t('mon.emptyBody')} />
          ) : filtered.length === 0 ? (
            <EmptyState title={t('mon.emptyFilter')} />
          ) : (
            <div
              className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,290px),1fr))] gap-3"
              data-testid="fleet-grid"
            >
              {filtered.map((r) => (
                <FleetCard
                  key={r.serverId}
                  row={r}
                  range={p.range}
                  firing={firingForServer(r.serverId, active)}
                  selected={r.serverId === p.server}
                  onSelect={() => p.set({ server: r.serverId === p.server ? null : r.serverId })}
                  now={now}
                />
              ))}
            </div>
          )}
          {selected && (
            <Card className="flex flex-col gap-3 p-4" data-testid="drilldown">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="m-0 flex-1 font-mono text-[16px] font-semibold">
                  {t('mon.drilldown', { name: selected.name, range: p.range })}
                </h2>
                <Link
                  href={`/servers/${selected.serverId}/monitoring?range=${p.range}`}
                  className="text-[13px]"
                >
                  {t('mon.openServer')}
                </Link>
                <Button size="sm" variant="ghost" onClick={() => p.set({ server: null })}>
                  {t('common.close')}
                </Button>
              </div>
              {fleetState(selected) === 'offline' && (
                <Notice tone="neutral" glyph="○" role="status">
                  {t('mon.drillOffline')}
                </Notice>
              )}
              <ServerMetricsPanel serverId={selected.serverId} range={p.range} />
            </Card>
          )}
          <Card>
            <CardHeader title={t('mon.apps.title')} />
            <div className="p-3">
              <AppHealthTable
                range={p.range}
                serverIds={new Set(filtered.map((r) => r.serverId))}
              />
            </div>
          </Card>
        </>
      )}
    </Page>
  );
}

/** Server detail → Monitoring tab (range carried in the URL so links keep filters). */
export function ServerMonitoringTab({ serverId, status }: { serverId: string; status: string }) {
  const { t } = useI18n();
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const raw = sp.get('range');
  const range: MetricRange = isMetricRange(raw) ? raw : '1h';
  return (
    <div className="flex flex-col gap-3" data-testid="server-monitoring-tab" data-range={range}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex-1 text-[12.5px] text-fg-muted">{t('mon.subtitle')}</span>
        <Link
          href={`/monitoring?server=${serverId}${range !== '1h' ? `&range=${range}` : ''}`}
          className="text-[13px]"
        >
          {t('mon.backToFleet')}
        </Link>
        <RangePicker
          value={range}
          onChange={(r) =>
            router.replace(`${pathname}${r === '1h' ? '' : `?range=${r}`}`, { scroll: false })
          }
        />
      </div>
      {(status === 'offline' || status === 'stale') && (
        <Notice tone="neutral" glyph="◐" role="status">
          {t('mon.tabStale')}
        </Notice>
      )}
      <ServerMetricsPanel serverId={serverId} range={range} />
    </div>
  );
}
