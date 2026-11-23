'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import {
  DEPLOYMENT_STATUSES,
  DEPLOYMENT_TRIGGERS,
  type Deployment,
  type DeploymentStatus,
  type DeploymentTrigger,
} from '@/lib/api/p4-types';
import { useApplications } from '@/lib/p3-queries';
import { useDeployments } from '@/lib/p4-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDuration, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Field, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { Table, Td, Th } from '@/components/preview/shared';
import { useSetPageEnv } from '@/components/shell/page-env';
import { useRouter } from 'next/navigation';
import { DeploymentStatusBadge, ImageRef, TriggerBadge } from './bits';
import { DeploymentExecution } from './execution';
import { useDeployment } from '@/lib/p4-queries';
import type { MessageKey } from '@/i18n/en';

export function DeploymentsTable({
  items,
  showApp = true,
  markers,
  actions,
}: {
  items: Deployment[];
  showApp?: boolean;
  markers?: { current?: string | null; previous?: string | null };
  actions?: (d: Deployment) => React.ReactNode;
}) {
  const { t } = useI18n();
  const now = useNow(5000);
  return (
    <Table
      minWidth={showApp ? 980 : 820}
      head={
        <>
          <Th>#</Th>
          {showApp && <Th>{t('dep.col.app')}</Th>}
          <Th>{t('dep.col.status')}</Th>
          <Th>{t('dep.col.trigger')}</Th>
          <Th>{t('dep.col.image')}</Th>
          {showApp && <Th>{t('dep.col.server')}</Th>}
          <Th>{t('dep.col.when')}</Th>
          {actions && <Th className="text-right">{t('dep.col.actions')}</Th>}
        </>
      }
    >
      {items.map((d) => {
        const dur = d.finishedAt ? Date.parse(d.finishedAt) - Date.parse(d.createdAt) : null;
        return (
          <tr
            key={d.id}
            className="hover:bg-surface-hover"
            data-testid="deployment-row"
            data-status={d.status}
            data-trigger={d.trigger}
          >
            <Td>
              <Link href={`/deployments/${d.id}`} className="font-mono text-[12.5px] font-medium">
                #{d.number}
              </Link>
              {markers?.current === d.id && (
                <span
                  className="ml-1.5 rounded bg-ok-bg px-1.5 text-[11px] text-ok"
                  data-testid="marker-current"
                >
                  {t('dep.marker.current')}
                </span>
              )}
              {markers?.previous === d.id && (
                <span
                  className="ml-1.5 rounded bg-chip px-1.5 text-[11px] text-fg-muted"
                  data-testid="marker-previous"
                >
                  {t('dep.marker.previous')}
                </span>
              )}
            </Td>
            {showApp && (
              <Td>
                <Link
                  href={`/applications/${d.applicationId}/deployments`}
                  className="font-mono text-[12.5px]"
                >
                  {d.applicationName ?? d.applicationId.slice(0, 8)}
                </Link>
                {d.environment && (
                  <EnvBadge
                    env={d.environment}
                    label={t(envBadgeKey(d.environment))}
                    className="ml-1.5 px-1.5 text-[10px]"
                  />
                )}
              </Td>
            )}
            <Td>
              <DeploymentStatusBadge status={d.status} />
              {d.error?.code && (
                <div className="mt-0.5 font-mono text-[11px] text-crit">{d.error.code}</div>
              )}
            </Td>
            <Td>
              <TriggerBadge trigger={d.trigger} />
              {d.sourceRef?.commitSha && (
                <div className="mt-0.5 font-mono text-[11px] text-fg-muted">
                  {d.sourceRef.branch} @{d.sourceRef.commitSha.slice(0, 7)}
                </div>
              )}
            </Td>
            <Td className="max-w-[300px]">
              <ImageRef image={d.image} />
            </Td>
            {showApp && (
              <Td className="font-mono text-[12px]">{d.serverName ?? d.serverId.slice(0, 8)}</Td>
            )}
            <Td className="text-[12px] whitespace-nowrap">
              {relativeTime(d.createdAt, t, now)}
              <div className="text-fg-muted">
                {d.createdByLabel ?? t(`dep.trigger.${d.trigger}` as MessageKey)}
                {dur !== null && ` · ${formatDuration(dur)}`}
              </div>
            </Td>
            {actions && <Td className="text-right">{actions(d)}</Td>}
          </tr>
        );
      })}
    </Table>
  );
}

export function DeploymentsView() {
  const { t } = useI18n();
  const { can } = useAuth();
  const router = useRouter();
  const servers = useServers();
  const apps = useApplications({ kind: 'container' });
  const [status, setStatus] = useState<'' | DeploymentStatus>('');
  const [serverId, setServerId] = useState('');
  const [appId, setAppId] = useState('');
  const [trigger, setTrigger] = useState<'' | DeploymentTrigger>('');
  const q = useDeployments({
    status: status || undefined,
    server_id: serverId || undefined,
    application_id: appId || undefined,
    trigger: trigger || undefined,
  });
  const forbidden = !can('apps.read') || (isApiError(q.error) && q.error.status === 403);
  const items = q.data?.items ?? [];
  const containerApps = (apps.data?.items ?? []).filter((a) => a.kind === 'container');

  return (
    <Page>
      <PageHeader
        title={t('deps.title')}
        subtitle={q.data ? t('deps.subtitle', { n: q.data.paginate.total }) : t('common.loading')}
        actions={
          <GatedButton
            variant="primary"
            perm="apps.deploy"
            onClick={() => router.push('/deployments/new')}
            data-testid="new-deployment"
          >
            + {t('deps.new')}
          </GatedButton>
        }
      />
      {forbidden ? (
        <ForbiddenState
          perm="apps.read"
          requestId={isApiError(q.error) ? q.error.requestId : null}
        />
      ) : (
        <>
          <div
            className="flex flex-wrap items-end gap-3"
            role="search"
            aria-label={t('deps.filters')}
          >
            <Field label={t('dep.col.status')} className="w-[200px]">
              {(p) => (
                <Select
                  {...p}
                  value={status}
                  onChange={(e) => setStatus(e.target.value as DeploymentStatus | '')}
                >
                  <option value="">{t('common.all')}</option>
                  {DEPLOYMENT_STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {t(`dep.status.${s}` as MessageKey)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('dep.col.server')} className="w-[180px]">
              {(p) => (
                <Select {...p} value={serverId} onChange={(e) => setServerId(e.target.value)}>
                  <option value="">{t('common.all')}</option>
                  {(servers.data?.items ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('dep.col.app')} className="w-[180px]">
              {(p) => (
                <Select {...p} value={appId} onChange={(e) => setAppId(e.target.value)}>
                  <option value="">{t('common.all')}</option>
                  {containerApps.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('dep.col.trigger')} className="w-[160px]">
              {(p) => (
                <Select
                  {...p}
                  value={trigger}
                  onChange={(e) => setTrigger(e.target.value as DeploymentTrigger | '')}
                >
                  <option value="">{t('common.all')}</option>
                  {DEPLOYMENT_TRIGGERS.map((s) => (
                    <option key={s} value={s}>
                      {t(`dep.trigger.${s}` as MessageKey)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          {items.some((d) => d.status === 'awaiting_approval') && (
            <Notice
              tone="warn"
              glyph="▲"
              role="status"
              action={<Link href="/approvals">{t('deps.toApprovals')} →</Link>}
            >
              {t('deps.awaiting', {
                n: items.filter((d) => d.status === 'awaiting_approval').length,
              })}
            </Notice>
          )}
          {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
          {q.isPending ? (
            <TableSkeleton label={t('common.loading')} />
          ) : items.length === 0 && !q.isError ? (
            <EmptyState
              title={
                status || serverId || appId || trigger ? t('deps.emptyFiltered') : t('deps.empty')
              }
              body={t('deps.emptyBody')}
              action={
                can('apps.deploy') ? (
                  <Link href="/deployments/new">{t('deps.new')} →</Link>
                ) : undefined
              }
            />
          ) : items.length > 0 ? (
            <DeploymentsTable items={items} />
          ) : null}
        </>
      )}
    </Page>
  );
}

export function DeploymentDetailView({ id }: { id: string }) {
  const { t } = useI18n();
  const q = useDeployment(id);
  useSetPageEnv(q.data?.environment);
  return (
    <Page>
      <Link href="/deployments" className="self-start text-[13px]">
        ← {t('nav.deployments')}
      </Link>
      <DeploymentExecution id={id} />
    </Page>
  );
}
