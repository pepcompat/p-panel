'use client';

import Link from 'next/link';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useServer } from '@/lib/queries';
import { isApiError } from '@/lib/api/errors';
import {
  SERVER_TABS,
  address,
  envBadgeKey,
  osLabel,
  providerLabel,
  type ServerTab,
} from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { EnvBadge } from '@/components/ui/badge';
import { CopyButton } from '@/components/ui/copy-button';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { useSetPageEnv } from '@/components/shell/page-env';
import { PathBadge, StatusBadge, proposedOrOffline, whyKey } from '../server-bits';
import { OverviewTab } from './overview-tab';
import { NetworkTab } from './network-tab';
import { SettingsTab } from './settings-tab';
import { ProposedTab } from './proposed-tab';
import { ServerAppsTab } from '@/components/p3/server-apps-tab';
import type { MessageKey } from '@/i18n/en';

function Header({ server, now }: { server: Server; now: number }) {
  const { t } = useI18n();
  const pub = address(server, 'public');
  const priv = address(server, 'private');
  const why = whyKey(server);
  return (
    <div className="flex flex-wrap items-start gap-3">
      <div className="flex min-w-[260px] flex-1 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="m-0 font-mono text-[22px] font-semibold">{server.name}</h1>
          <EnvBadge env={server.environment} label={t(envBadgeKey(server.environment))} />
          <StatusBadge status={server.status} />
        </div>
        <div className="text-[13px] text-fg-muted">
          {t('detail.meta', {
            provider: providerLabel(server) ?? '—',
            region: server.provider?.region ?? '—',
            os: osLabel(server) ?? '—',
            agent: server.agentVersion ?? '—',
            hb: relativeTime(server.lastHeartbeatAt, t, now),
          })}
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
          {[
            [t('servers.col.public'), pub?.address, 'card.copyPublic'],
            [t('servers.col.private'), priv?.address, 'card.copyPrivate'],
          ].map(([label, addr, key]) => (
            <span
              key={label}
              className="inline-flex items-center gap-1.5 rounded-[5px] border border-line-strong bg-surface py-0.5 pr-1 pl-2.5"
            >
              <span className="text-fg-muted">{label}</span>
              <span className="font-mono">{addr ?? '—'}</span>
              {addr && (
                <CopyButton text={addr} ariaLabel={t(key as MessageKey, { name: server.name })} />
              )}
            </span>
          ))}
          <PathBadge server={server} />
        </div>
        {why && <div className="text-[12px] text-crit">{t(why)}</div>}
      </div>
      <div className="flex flex-wrap gap-2">
        <GatedButton
          variant="dark"
          className="min-h-[38px]"
          perm="ssh.connect"
          action="open_terminal"
          allowedActions={server.allowedActions}
          blockedReason={proposedOrOffline(server)}
        >
          {t('detail.openTerminal')}
        </GatedButton>
        <GatedButton
          className="min-h-[38px]"
          perm="servers.operate"
          action="restart_service"
          allowedActions={server.allowedActions}
          blockedReason={proposedOrOffline(server)}
        >
          {t('detail.restart')}
        </GatedButton>
      </div>
    </div>
  );
}

export function ServerDetail({ id, tab }: { id: string; tab: ServerTab }) {
  const { t } = useI18n();
  const now = useNow(5000);
  const q = useServer(id);
  useSetPageEnv(q.data?.environment);

  let content: React.ReactNode;
  if (q.isPending) {
    content = (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="flex flex-col gap-3"
      >
        <Skeleton className="h-7 w-72" />
        <Skeleton className="h-4 w-96 max-w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  } else if (q.isError && !q.data) {
    const e = q.error;
    content =
      isApiError(e) && e.status === 404 ? (
        <EmptyState title={t('detail.notFound')} body={t('detail.notFoundBody')} />
      ) : isApiError(e) && e.status === 403 ? (
        <ForbiddenState perm="fleet.read" requestId={e.requestId} />
      ) : (
        <ErrorState error={e} onRetry={() => void q.refetch()} />
      );
  }

  const server = q.data;
  return (
    <div className="flex max-w-[1440px] flex-col">
      <div className="flex flex-col gap-3.5 px-4 pt-6 pb-4 sm:px-6">
        <Link href="/servers" className="self-start text-[13px]">
          {t('detail.back')}
        </Link>
        {content}
        {server && (
          <>
            <Header server={server} now={now} />
            {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
            {(server.status === 'stale' || server.status === 'offline') && (
              <Notice tone="warn" glyph="◐" title={t('state.stale.title')} role="status">
                {t('state.stale.body')}{' '}
                {t('common.lastUpdated', { time: relativeTime(server.lastHeartbeatAt, t, now) })}
              </Notice>
            )}
            <nav
              aria-label={t('detail.sections')}
              className="flex gap-0.5 overflow-x-auto border-b border-line"
            >
              {SERVER_TABS.map((k) => {
                const active = k === tab;
                return (
                  <Link
                    key={k}
                    href={`/servers/${server.id}/${k}`}
                    aria-current={active ? 'page' : undefined}
                    scroll={false}
                    className={cn(
                      'flex min-h-10 shrink-0 items-center border-b-2 px-3 text-[13px] whitespace-nowrap no-underline hover:no-underline focus-visible:-outline-offset-2',
                      active
                        ? 'border-accent-strong font-medium text-fg'
                        : 'border-transparent text-fg-muted hover:text-fg',
                    )}
                  >
                    {t(`tab.${k}`)}
                  </Link>
                );
              })}
            </nav>
          </>
        )}
      </div>
      {server && (
        <div className="px-4 pb-6 sm:px-6">
          {tab === 'overview' && <OverviewTab server={server} now={now} />}
          {tab === 'network' && <NetworkTab server={server} now={now} />}
          {tab === 'settings' && <SettingsTab server={server} />}
          {tab === 'applications' && <ServerAppsTab server={server} />}
          {tab !== 'overview' &&
            tab !== 'network' &&
            tab !== 'settings' &&
            tab !== 'applications' && <ProposedTab server={server} tab={tab} now={now} />}
        </div>
      )}
    </div>
  );
}
