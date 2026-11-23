'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import { deploymentsApi } from '@/lib/api/p4-endpoints';
import { deploymentGate } from '@/lib/p4-gates';
import { useDeployments } from '@/lib/p4-queries';
import { envBadgeKey } from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { Card, DefList, Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { DeploymentStatusBadge, ImageRef, PlanApproval, TriggerBadge } from './bits';

export function ApprovalsView() {
  const { t } = useI18n();
  const { me, can } = useAuth();
  const qc = useQueryClient();
  const now = useNow(10_000);
  const q = useDeployments({ status: 'awaiting_approval' });
  const [sel, setSel] = useState<string | null>(null);
  const items = q.data?.items ?? [];
  const d = items.find((x) => x.id === sel) ?? items[0] ?? null;
  const forbidden = !can('apps.read') || (isApiError(q.error) && q.error.status === 403);

  return (
    <Page>
      <PageHeader title={t('appr.title')} subtitle={t('appr.subtitle')} />
      {forbidden ? (
        <ForbiddenState
          perm="apps.read"
          requestId={isApiError(q.error) ? q.error.requestId : null}
        />
      ) : (
        <>
          {!can('approvals.decide') && (
            <Notice tone="neutral" role="note">
              {t('appr.noPerm')}
            </Notice>
          )}
          <h2 className="m-0 text-[15px] font-semibold">
            {t('appr.deployments', { n: items.length })}
          </h2>
          {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
          {q.isPending ? (
            <TableSkeleton label={t('common.loading')} />
          ) : items.length === 0 ? (
            <EmptyState title={t('appr.empty')} body={t('appr.emptyBody')} />
          ) : (
            <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
              <Card className="overflow-hidden">
                {items.map((x) => (
                  <button
                    key={x.id}
                    type="button"
                    aria-pressed={x.id === d?.id}
                    onClick={() => setSel(x.id)}
                    data-testid="approval-item"
                    className={cn(
                      'flex w-full flex-col gap-0.5 border-0 border-t border-line-subtle px-4 py-3 text-left first:border-t-0',
                      x.id === d?.id ? 'bg-info-bg' : 'bg-surface hover:bg-surface-hover',
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span className="flex-1 font-mono text-[12.5px] font-medium">
                        {x.applicationName} #{x.number}
                      </span>
                      <TriggerBadge trigger={x.trigger} />
                    </span>
                    <span className="text-[12px] text-fg-muted">
                      {x.createdByLabel ?? t('common.dash')} · {relativeTime(x.createdAt, t, now)}
                      {x.createdBy === me?.user.id && ` · ${t('appr.yours')}`}
                    </span>
                  </button>
                ))}
              </Card>
              {d && (
                <Card className="flex flex-col gap-3 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="m-0 flex-1 text-[16px] font-semibold">
                      <Link href={`/deployments/${d.id}`}>
                        {t('dep.title', { n: d.number, app: d.applicationName ?? '' })}
                      </Link>
                    </h3>
                    <DeploymentStatusBadge status={d.status} />
                    {d.environment && (
                      <EnvBadge env={d.environment} label={t(envBadgeKey(d.environment))} />
                    )}
                  </div>
                  <DefList
                    keyWidth={120}
                    rows={[
                      [t('dep.col.server'), d.serverName ?? d.serverId.slice(0, 8), { mono: true }],
                      [t('dep.col.image'), <ImageRef key="i" image={d.image} />],
                      [t('dep.route'), (d.domains ?? []).join(', '), { mono: true }],
                      [t('dep.createdBy'), d.createdByLabel ?? t('common.dash')],
                      ...(d.reason
                        ? ([[t('dep.reason'), d.reason]] as Array<[string, string]>)
                        : []),
                    ]}
                  />
                  <PlanApproval
                    planHash={d.planHash}
                    required={d.approval.required}
                    awaiting
                    isCreator={!!d.createdBy && d.createdBy === me?.user.id}
                    gate={deploymentGate('approve', d, me?.permissions, me?.user.id)}
                    onApprove={(hash, token) => deploymentsApi.approve(d.id, hash, token)}
                    onApproved={() =>
                      void qc.invalidateQueries({ queryKey: ['deployments'], exact: false })
                    }
                  />
                </Card>
              )}
            </div>
          )}
          <h2 className="m-0 text-[15px] font-semibold">{t('appr.revisions')}</h2>
          <Notice tone="info" glyph="◆" role="note">
            {t('appr.revisionsNote')} <Link href="/applications">{t('nav.applications')} →</Link>
          </Notice>
        </>
      )}
    </Page>
  );
}
