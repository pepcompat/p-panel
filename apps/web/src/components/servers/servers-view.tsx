'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useMemo, useState } from 'react';
import type { Environment, Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useServers } from '@/lib/queries';
import { useAuth } from '@/lib/auth/auth-provider';
import {
  ENV_DISPLAY_ORDER,
  envBadgeKey,
  envLabelKey,
  fleetCounts,
  groupByEnv,
  matchesQuery,
} from '@/lib/servers';
import { formatClock } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { isApiError } from '@/lib/api/errors';
import { Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Input } from '@/components/ui/form';
import { Segmented } from '@/components/ui/segmented';
import { CardSkeletonGrid, TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ServerCard } from './server-card';
import { firingForServer } from '@/components/p5/bits';
import { useActiveIncidents } from '@/lib/p5-queries';
import { ServerTable } from './server-table';
import { EnrollWizard } from './enroll-wizard';

type EnvFilter = Environment | 'all';
type View = 'cards' | 'table';
const VIEW_KEY = 'ppanel.servers.view';

function EnvGroup({ env, servers, now }: { env: Environment; servers: Server[]; now: number }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(true);
  const { active } = useActiveIncidents();
  const c = fleetCounts(servers);
  const panelId = `env-group-${env}`;
  if (servers.length === 0) return null;
  return (
    <section aria-labelledby={`${panelId}-h`} className="flex flex-col gap-2.5">
      <div className="flex items-center gap-2.5 border-b border-line pb-2">
        <h2 id={`${panelId}-h`} className="m-0">
          <EnvBadge env={env} label={t(envBadgeKey(env))} />
        </h2>
        <span className="flex-1 text-[12.5px] text-fg-muted">
          {t('servers.groupSummary', { count: c.total, online: c.online + c.degraded })}
        </span>
        <Button
          variant="ghost"
          size="sm"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? `▾ ${t('servers.collapse')}` : `▸ ${t('servers.expand')}`}
          <span className="sr-only"> {t(envLabelKey(env))}</span>
        </Button>
      </div>
      <div
        id={panelId}
        hidden={!open}
        className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,300px),1fr))] gap-3"
      >
        {servers.map((s) => (
          <ServerCard key={s.id} server={s} now={now} firing={firingForServer(s.id, active)} />
        ))}
      </div>
    </section>
  );
}

export function ServersView() {
  const { t, locale } = useI18n();
  const router = useRouter();
  const params = useSearchParams();
  const { can } = useAuth();
  const now = useNow(5000);
  const query = useServers();
  const [env, setEnv] = useState<EnvFilter>((params.get('env') as EnvFilter) ?? 'all');
  const [q, setQ] = useState(params.get('q') ?? '');
  const [view, setView] = useState<View>('cards');
  const [enrollOpen, setEnrollOpen] = useState(params.get('enroll') === '1');

  useEffect(() => {
    try {
      const v = localStorage.getItem(VIEW_KEY);
      if (v === 'cards' || v === 'table') setView(v);
    } catch {
      /* ignore */
    }
  }, []);
  useEffect(() => setQ(params.get('q') ?? ''), [params]);

  const setViewPersist = (v: View) => {
    setView(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      /* ignore */
    }
  };

  const all = useMemo(() => query.data?.items ?? [], [query.data]);
  const searched = useMemo(() => all.filter((s) => matchesQuery(s, q)), [all, q]);
  const visible = useMemo(
    () => searched.filter((s) => env === 'all' || s.environment === env),
    [searched, env],
  );
  const staleCount = all.filter((s) => s.status === 'stale' || s.status === 'offline').length;

  const envCounts: Record<EnvFilter, number> = {
    all: searched.length,
    production: searched.filter((s) => s.environment === 'production').length,
    uat: searched.filter((s) => s.environment === 'uat').length,
    development: searched.filter((s) => s.environment === 'development').length,
  };

  const forbidden = !can('fleet.read') || (isApiError(query.error) && query.error.status === 403);

  let body: React.ReactNode;
  if (forbidden) {
    body = (
      <ForbiddenState
        perm="fleet.read"
        requestId={isApiError(query.error) ? query.error.requestId : null}
      />
    );
  } else if (query.isPending) {
    body =
      view === 'cards' ? (
        <CardSkeletonGrid label={t('common.loading')} />
      ) : (
        <TableSkeleton label={t('common.loading')} />
      );
  } else if (query.isError && !query.data) {
    body = <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  } else if (all.length === 0) {
    body = (
      <EmptyState
        title={t('servers.empty.title')}
        body={t('servers.empty.body')}
        action={
          <GatedButton variant="primary" perm="servers.enroll" onClick={() => setEnrollOpen(true)}>
            {t('servers.enroll')}
          </GatedButton>
        }
      />
    );
  } else if (visible.length === 0) {
    body = <EmptyState title={t('servers.empty.filtered')} />;
  } else if (view === 'table') {
    body = <ServerTable servers={visible} now={now} />;
  } else {
    body = (
      <div className="flex flex-col gap-[22px]">
        {groupByEnv(visible).map((g) => (
          <EnvGroup key={g.env} env={g.env} servers={g.servers} now={now} />
        ))}
      </div>
    );
  }

  return (
    <Page>
      <PageHeader
        title={t('servers.title')}
        subtitle={t('servers.subtitle', { count: query.data ? query.data.total : '—' })}
        actions={
          <GatedButton
            variant="primary"
            size="md"
            className="min-h-[38px] px-4"
            perm="servers.enroll"
            aria-expanded={enrollOpen}
            onClick={() => setEnrollOpen((o) => !o)}
          >
            {t('servers.enroll')}
          </GatedButton>
        }
      />
      <div className="flex flex-wrap items-center gap-2">
        <Segmented<EnvFilter>
          label={t('servers.envFilter')}
          value={env}
          onChange={(v) => {
            setEnv(v);
            const sp = new URLSearchParams(params.toString());
            if (v === 'all') sp.delete('env');
            else sp.set('env', v);
            router.replace(`/servers${sp.toString() ? `?${sp}` : ''}`, { scroll: false });
          }}
          options={[
            { value: 'all', label: t('env.all'), count: envCounts.all },
            ...ENV_DISPLAY_ORDER.map((e) => ({
              value: e,
              label: t(envLabelKey(e)),
              count: envCounts[e],
            })),
          ]}
        />
        <label htmlFor="servers-filter" className="sr-only">
          {t('servers.filterPlaceholder')}
        </label>
        <Input
          id="servers-filter"
          type="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={t('servers.filterPlaceholder')}
          className="min-h-8 w-[240px] max-w-full py-1 text-[13px]"
        />
        <Segmented<View>
          label={t('servers.view')}
          value={view}
          onChange={setViewPersist}
          className="order-9 ml-auto"
          options={[
            { value: 'cards', label: t('servers.view.cards') },
            { value: 'table', label: t('servers.view.table') },
          ]}
        />
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-fg-muted">
        <span>{t('env.note')}</span>
        {query.dataUpdatedAt > 0 && (
          <span className="font-mono">
            {t('common.lastUpdated', { time: formatClock(new Date(query.dataUpdatedAt), locale) })}
          </span>
        )}
      </div>
      {query.isError && query.data && (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      )}
      {staleCount > 0 && !forbidden && (
        <Notice tone="warn" glyph="◐" title={t('state.stale.title')} role="status">
          {t('state.stale.body')} ({staleCount})
        </Notice>
      )}
      <div
        className={`grid items-start gap-4 ${enrollOpen ? 'xl:grid-cols-[minmax(0,1fr)_380px]' : 'grid-cols-1'}`}
      >
        <div className="min-w-0">{body}</div>
        {enrollOpen && (
          <aside
            aria-labelledby="enroll-title"
            className="order-first flex flex-col gap-3.5 rounded-lg border border-line bg-surface p-[18px] xl:order-none"
          >
            <div className="flex items-center">
              <h2 id="enroll-title" className="m-0 flex-1 text-[16px] font-semibold">
                {t('enroll.title')}
              </h2>
              <Button
                variant="ghost"
                aria-label={t('common.close')}
                className="h-8 w-8 p-0 text-[16px]"
                onClick={() => setEnrollOpen(false)}
              >
                ✕
              </Button>
            </div>
            <EnrollWizard
              onClose={() => setEnrollOpen(false)}
              defaultEnv={env === 'all' ? 'production' : env}
            />
          </aside>
        )}
      </div>
    </Page>
  );
}
