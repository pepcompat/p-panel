'use client';

import Link from 'next/link';
import { useI18n } from '@/i18n/provider';
import { isApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { useApplication } from '@/lib/p3-queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { Card, DefList } from '@/components/ui/card';
import { EnvBadge, OutlineTag } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  EmptyState,
  ErrorState,
  ForbiddenState,
  Notice,
  ProposedBanner,
} from '@/components/ui/states';
import { useSetPageEnv } from '@/components/shell/page-env';
import { FlagBadges, OwnershipBadge, Sha } from './bits';
import { NginxTab } from './nginx-tab';
import { OwnershipHistory, OwnershipPanel } from './ownership';
import {
  AppDeploymentsTab,
  AutoDeploySettings,
  CurrentVersionLine,
  EnvSecretsTab,
  LifecyclePanel,
  LogsTab,
} from '@/components/p4/app-tabs';
import { GatedButton } from '@/components/ui/gated-button';
import { useRouter } from 'next/navigation';
import type { MessageKey } from '@/i18n/en';

export const APP_TABS = [
  'overview',
  'nginx',
  'ownership',
  'deployments',
  'domains',
  'env',
  'logs',
  'metrics',
  'backups',
  'settings',
] as const;
export type AppTab = (typeof APP_TABS)[number];
export const REAL_APP_TABS: readonly AppTab[] = ['overview', 'nginx', 'ownership'];
/** Container apps (P4a) additionally have real deployments / env / logs / settings tabs. */
export const REAL_CONTAINER_TABS: readonly AppTab[] = [
  'overview',
  'nginx',
  'ownership',
  'deployments',
  'env',
  'logs',
  'settings',
];
export const realTabsFor = (app: Pick<Application, 'kind'>) =>
  app.kind === 'container' ? REAL_CONTAINER_TABS : REAL_APP_TABS;
export const isAppTab = (v: string): v is AppTab => (APP_TABS as readonly string[]).includes(v);

function OverviewTab({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-4">
      <div className="flex flex-col gap-4">
        <Card className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('app.identity')}</h2>
          <DefList
            keyWidth={140}
            rows={[
              [
                t('apps.col.server'),
                <Link key="s" href={`/servers/${app.serverId}/overview`} className="font-mono">
                  {app.serverName ?? app.serverId.slice(0, 8)}
                </Link>,
              ],
              [
                t('apps.col.env'),
                <EnvBadge key="e" env={app.environment} label={t(envBadgeKey(app.environment))} />,
              ],
              [t('app.kind'), t(`apps.kind.${app.kind}` as MessageKey)],
              [t('apps.col.domains'), app.domains.join(', ') || t('common.dash'), { mono: true }],
              [t('apps.col.ownership'), <OwnershipBadge key="o" mode={app.ownershipMode} />],
              [
                t('app.lastScan'),
                app.lastScanId ? (
                  <Link key="l" href={`/imports/${app.lastScanId}`} className="font-mono">
                    {app.lastScanId.slice(0, 8)}
                  </Link>
                ) : (
                  t('common.dash')
                ),
              ],
              [t('app.fingerprint'), <Sha key="f" value={app.sourceFindingFingerprint} />],
              [t('app.updated'), formatDateTime(app.updatedAt, locale)],
            ]}
          />
        </Card>
        <Card className="flex flex-col gap-2 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('app.nginxFiles')}</h2>
          {app.nginxFiles.length === 0 ? (
            <p className="m-0 text-[13px] text-fg-muted">{t('nginx.files.none')}</p>
          ) : (
            <ul className="m-0 flex list-none flex-col gap-1 p-0">
              {app.nginxFiles.map((f) => (
                <li key={f.path} className="flex flex-wrap items-center gap-2 text-[12.5px]">
                  <span className="flex-1 font-mono break-all">{f.path}</span>
                  <span className="text-fg-muted">{t('app.lastKnown')}</span>
                  <Sha value={f.lastKnownSha256} />
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="flex flex-col gap-2 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('app.flags')}</h2>
          <FlagBadges flags={app.flags} compact />
          {(app.reasons ?? []).length > 0 && (
            <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px]">
              {app.reasons!.map((r) => (
                <li key={r} className="text-warn">
                  <span aria-hidden="true">▲ </span>
                  {r}
                </li>
              ))}
            </ul>
          )}
          <p className="m-0 text-[12px] text-fg-muted">{t('app.flagsNote')}</p>
        </Card>
      </div>
      {app.kind === 'container' ? <LifecyclePanel app={app} /> : <OwnershipPanel app={app} />}
    </div>
  );
}

export function ApplicationDetail({ id, tab }: { id: string; tab: AppTab }) {
  const { t } = useI18n();
  const q = useApplication(id);
  const app = q.data;
  const router = useRouter();
  useSetPageEnv(app?.environment);
  const realTabs = app ? realTabsFor(app) : REAL_APP_TABS;

  let body: React.ReactNode = null;
  if (q.isPending) {
    body = (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="flex flex-col gap-3"
      >
        <Skeleton className="h-7 w-72" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  } else if (q.isError && !app) {
    const e = q.error;
    body =
      isApiError(e) && e.status === 404 ? (
        <EmptyState title={t('app.notFound')} />
      ) : isApiError(e) && e.status === 403 ? (
        <ForbiddenState perm="apps.read" requestId={e.requestId} />
      ) : (
        <ErrorState error={e} onRetry={() => void q.refetch()} />
      );
  }

  return (
    <div className="flex max-w-[1440px] flex-col">
      <div className="flex flex-col gap-3.5 px-4 pt-6 pb-4 sm:px-6">
        <Link href="/applications" className="self-start text-[13px]">
          ← {t('nav.applications')}
        </Link>
        {body}
        {app && (
          <>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="m-0 font-mono text-[22px] font-semibold">{app.name}</h1>
              <EnvBadge env={app.environment} label={t(envBadgeKey(app.environment))} />
              <OwnershipBadge mode={app.ownershipMode} />
              <FlagBadges flags={app.flags} />
              {app.kind === 'container' && (
                <>
                  <span className="flex-1" />
                  <GatedButton
                    variant="primary"
                    perm="apps.deploy"
                    action="deploy"
                    allowedActions={app.allowedActions}
                    onClick={() => router.push(`/deployments/new?app=${app.id}`)}
                    data-testid="app-deploy"
                  >
                    {t('life.deployNew')}
                  </GatedButton>
                </>
              )}
            </div>
            {app.kind === 'container' && <CurrentVersionLine app={app} />}
            <div className="text-[13px] text-fg-muted">
              {t(`apps.kind.${app.kind}` as MessageKey)} ·{' '}
              {app.serverName ?? app.serverId.slice(0, 8)} ·{' '}
              <span className="font-mono">{app.domains.slice(0, 3).join(', ')}</span>
            </div>
            {q.isError && (
              <>
                <Notice tone="warn" glyph="◐" role="status" title={t('state.stale.title')}>
                  {t('state.stale.body')}
                </Notice>
                <ErrorState error={q.error} onRetry={() => void q.refetch()} />
              </>
            )}
            <nav
              aria-label={t('app.sections')}
              className="flex gap-0.5 overflow-x-auto border-b border-line"
            >
              {APP_TABS.map((k) => {
                const active = k === tab;
                return (
                  <Link
                    key={k}
                    href={`/applications/${app.id}/${k}`}
                    aria-current={active ? 'page' : undefined}
                    scroll={false}
                    className={cn(
                      'flex min-h-10 shrink-0 items-center gap-1 border-b-2 px-3 text-[13px] whitespace-nowrap no-underline hover:no-underline',
                      active
                        ? 'border-accent-strong font-medium text-fg'
                        : 'border-transparent text-fg-muted hover:text-fg',
                    )}
                  >
                    {t(`app.tab.${k}` as MessageKey)}
                    {!realTabs.includes(k) && (
                      <OutlineTag className="text-[9.5px]">{t('nav.preview')}</OutlineTag>
                    )}
                  </Link>
                );
              })}
            </nav>
          </>
        )}
      </div>
      {app && (
        <div className="px-4 pb-6 sm:px-6">
          {tab === 'overview' && <OverviewTab app={app} />}
          {tab === 'nginx' && <NginxTab app={app} />}
          {tab === 'ownership' && (
            <div className="flex flex-col gap-4">
              <OwnershipPanel app={app} />
              <h2 className="m-0 text-[15px] font-semibold">{t('own.history.title')}</h2>
              <OwnershipHistory app={app} />
            </div>
          )}
          {app.kind === 'container' && tab === 'deployments' && <AppDeploymentsTab app={app} />}
          {app.kind === 'container' && tab === 'env' && <EnvSecretsTab app={app} />}
          {app.kind === 'container' && tab === 'logs' && <LogsTab app={app} />}
          {app.kind === 'container' && tab === 'settings' && <AutoDeploySettings app={app} />}
          {!realTabs.includes(tab) && <ProposedBanner body={t('app.proposedTab')} />}
        </div>
      )}
    </div>
  );
}
