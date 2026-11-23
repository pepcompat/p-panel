'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import { deploymentsApi } from '@/lib/api/p4-endpoints';
import { DEPLOYMENT_ACTIVE, type Deployment } from '@/lib/api/p4-types';
import { deploymentGate } from '@/lib/p4-gates';
import { useDeployment, useAppDeployments } from '@/lib/p4-queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime, formatDuration } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { Card, DefList } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ActionDialog } from '@/components/p3/action-dialog';
import { Sha } from '@/components/p3/bits';
import {
  DeploymentOutcome,
  DeploymentStatusBadge,
  DeploymentTimeline,
  ImageRef,
  PlanApproval,
  PreflightList,
  TriggerBadge,
} from './bits';

function invalidateDeployment(qc: ReturnType<typeof useQueryClient>, d: Deployment) {
  void qc.invalidateQueries({ queryKey: ['deployments'], exact: false });
  void qc.invalidateQueries({ queryKey: ['applications', 'one', d.applicationId], exact: false });
}

/** Live execution view: status, outcome, timeline with log tails, approval and cancel. */
export function DeploymentExecution({
  id,
  showHeader = true,
}: {
  id: string;
  showHeader?: boolean;
}) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useDeployment(id);
  const d = q.data;
  const now = useNow(1000);
  const [cancelOpen, setCancelOpen] = useState(false);
  const hist = useAppDeployments(d?.applicationId ?? '', !!d && d.status === 'failed');

  if (q.isPending)
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="flex flex-col gap-2"
      >
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  if (q.isError && !d) {
    const e = q.error;
    if (isApiError(e) && e.status === 404) return <EmptyState title={t('dep.notFound')} />;
    if (isApiError(e) && e.status === 403)
      return <ForbiddenState perm="apps.read" requestId={e.requestId} />;
    return <ErrorState error={e} onRetry={() => void q.refetch()} />;
  }
  if (!d) return null;

  const live = DEPLOYMENT_ACTIVE.includes(d.status);
  const cancelGate = deploymentGate('cancel', d, me?.permissions, me?.user.id);
  const approveGate = deploymentGate('approve', d, me?.permissions, me?.user.id);
  const prev = hist.data?.items.find((x) => x.id === d.previousDeploymentId);
  const started = Date.parse(d.createdAt);
  const end = d.finishedAt ? Date.parse(d.finishedAt) : now;

  return (
    <div className="flex flex-col gap-4" data-testid="deployment-execution" data-status={d.status}>
      {showHeader && (
        <div className="flex flex-wrap items-center gap-2.5">
          <h2 className="m-0 text-[17px] font-semibold">
            {t('dep.title', { n: d.number, app: d.applicationName ?? d.applicationId.slice(0, 8) })}
          </h2>
          <DeploymentStatusBadge status={d.status} />
          <TriggerBadge trigger={d.trigger} />
          {d.environment && <EnvBadge env={d.environment} label={t(envBadgeKey(d.environment))} />}
          <span className="font-mono text-[12px] text-fg-muted" aria-live="off">
            {formatDuration(end - started)}
          </span>
        </div>
      )}
      {q.isError && (
        <Notice tone="warn" glyph="◐" role="status" title={t('state.stale.title')}>
          {t('state.stale.body')}
        </Notice>
      )}
      <div aria-live="polite">
        <DeploymentOutcome d={d} previousNumber={prev?.number ?? null} />
      </div>
      {live && (
        <Notice tone="info" glyph="◌" role="status">
          {t('dep.live', { status: t(`dep.status.${d.status}`) })}
        </Notice>
      )}
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,380px)]">
        <Card className="flex flex-col gap-3 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="m-0 flex-1 text-[14.5px] font-semibold">{t('dep.timeline')}</h3>
            {(live || d.status === 'awaiting_approval') && (
              <GatedButton
                size="sm"
                variant="danger"
                perm="apps.deploy"
                blockedReason={cancelGate.allowed ? undefined : cancelGate.reason}
                onClick={() => setCancelOpen(true)}
              >
                {t('dep.cancel')}
              </GatedButton>
            )}
          </div>
          {!cancelGate.allowed && live && (
            <p className="m-0 text-[12px] text-fg-muted">{t('dep.cancelOnlyBefore')}</p>
          )}
          <DeploymentTimeline d={d} now={now} />
        </Card>
        <div className="flex flex-col gap-4">
          <Card className="flex flex-col gap-2 p-4">
            <h3 className="m-0 text-[14.5px] font-semibold">{t('dep.plan')}</h3>
            <DefList
              keyWidth={110}
              rows={[
                [
                  t('dep.col.app'),
                  <Link
                    key="a"
                    href={`/applications/${d.applicationId}/deployments`}
                    className="font-mono"
                  >
                    {d.applicationName ?? d.applicationId.slice(0, 8)}
                  </Link>,
                ],
                [
                  t('dep.col.server'),
                  <Link key="s" href={`/servers/${d.serverId}/overview`} className="font-mono">
                    {d.serverName ?? d.serverId.slice(0, 8)}
                  </Link>,
                ],
                [t('dep.col.image'), <ImageRef key="i" image={d.image} />],
                [
                  t('dep.container'),
                  d.container
                    ? `${d.container.name} · 127.0.0.1:${d.container.hostPort}`
                    : t('common.dash'),
                  { mono: true },
                ],
                [t('dep.route'), (d.domains ?? []).join(', ') || t('common.dash'), { mono: true }],
                [t('approval.planHash'), <Sha key="p" value={d.planHash} />],
                ...(d.sourceRef?.commitSha
                  ? ([
                      [
                        t('dep.commit'),
                        `${d.sourceRef.repo ?? ''}@${d.sourceRef.commitSha.slice(0, 7)} ${d.sourceRef.branch ?? ''}`,
                        { mono: true },
                      ],
                    ] as Array<[string, string, { mono: boolean }]>)
                  : []),
                [
                  t('dep.createdBy'),
                  d.createdByLabel ??
                    (d.trigger === 'webhook' ? t('dep.trigger.webhook') : t('common.dash')),
                ],
                [t('dep.createdAt'), formatDateTime(d.createdAt, locale)],
                ...(d.reason ? ([[t('dep.reason'), d.reason]] as Array<[string, string]>) : []),
              ]}
            />
          </Card>
          {d.approval.required && (
            <PlanApproval
              planHash={d.planHash}
              required
              awaiting={d.status === 'awaiting_approval'}
              isCreator={!!d.createdBy && d.createdBy === me?.user.id}
              gate={approveGate}
              approvedByLabel={
                d.approval.approvedByLabel ??
                (d.approval.approvedBy ? d.approval.approvedBy.slice(0, 8) : null)
              }
              approvedAt={d.approval.approvedAt}
              expiresAt={d.approval.expiresAt}
              onApprove={(hash, token) => deploymentsApi.approve(d.id, hash, token)}
              onApproved={() => invalidateDeployment(qc, d)}
            />
          )}
          {d.preflight && d.preflight.length > 0 && (
            <Card className="flex flex-col gap-2 p-4">
              <h3 className="m-0 text-[14.5px] font-semibold">{t('pf.title')}</h3>
              <PreflightList checks={d.preflight} />
            </Card>
          )}
        </div>
      </div>
      <ActionDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        title={t('dep.cancelTitle', { n: d.number })}
        body={t('dep.cancelBody')}
        confirmLabel={t('dep.cancel')}
        danger
        needsStepUp={false}
        onConfirm={async () => {
          await deploymentsApi.cancel(d.id);
          invalidateDeployment(qc, d);
        }}
      />
    </div>
  );
}
