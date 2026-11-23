'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import { managedRoutingApi } from '@/lib/api/p4-endpoints';
import { evaluateGate } from '@/lib/permissions';
import { p4k, useManagedRouting } from '@/lib/p4-queries';
import { ToneBadge } from '@/components/ui/badge';
import { GatedButton } from '@/components/ui/gated-button';
import { ErrorState, Notice } from '@/components/ui/states';
import { ActionDialog } from '@/components/p3/action-dialog';
import { PlanApproval } from './bits';
import type { MessageKey } from '@/i18n/en';

/** Managed-routing status for one server + "Enable managed routing" (approval flow as Nginx revisions). */
export function ManagedRoutingPanel({ server, compact }: { server: Server; compact?: boolean }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useManagedRouting(server.id);
  const [open, setOpen] = useState(false);
  const r = q.data;
  const refresh = () => void qc.invalidateQueries({ queryKey: p4k.routing(server.id) });
  const status = r ? (r.status ?? (r.enabled ? 'enabled' : 'disabled')) : null;
  const prod = server.environment === 'production';

  if (q.isPending) return <span className="text-[12px] text-fg-muted">{t('common.loading')}</span>;
  if (q.isError)
    return isApiError(q.error) && q.error.status === 404 ? (
      <Notice tone="neutral" role="note">
        {t('mr.notAvailable')}
      </Notice>
    ) : (
      <ErrorState error={q.error} onRetry={() => void q.refetch()} />
    );

  const tone =
    status === 'enabled'
      ? 'ok'
      : status === 'applying'
        ? 'info'
        : status === 'awaiting_approval'
          ? 'warn'
          : status === 'failed' || status === 'requires_manual_recovery'
            ? 'crit'
            : 'off';
  const enableGate = evaluateGate({
    permissions: me?.permissions,
    perm: 'nginx.write',
    action: r?.allowedActions ? 'enable' : undefined,
    allowedActions: r?.allowedActions,
  });
  return (
    <div className="flex flex-col gap-2" data-testid="managed-routing" data-status={status ?? ''}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[12.5px] text-fg-muted">{t('mr.label')}</span>
        <ToneBadge tone={tone} glyph={status === 'applying' ? '◌' : undefined} size="sm">
          {t(`mr.status.${status}` as MessageKey)}
        </ToneBadge>
        {!r?.enabled && status !== 'applying' && status !== 'awaiting_approval' && (
          <GatedButton
            size="sm"
            variant="secondary"
            perm="nginx.write"
            blockedReason={enableGate.allowed ? undefined : enableGate.reason}
            onClick={() => setOpen(true)}
          >
            {t('mr.enable')}
          </GatedButton>
        )}
      </div>
      {!compact && !r?.enabled && (
        <p className="m-0 text-[12px] text-fg-muted">
          {t('mr.explain', { path: r?.path ?? '/etc/nginx/conf.d/ppanel-managed.conf' })}
        </p>
      )}
      {status === 'awaiting_approval' && r && (
        <PlanApproval
          testId="routing-approval"
          planHash={r.planHash ?? null}
          required
          awaiting
          isCreator={r.createdBy === me?.user.id}
          gate={evaluateGate({
            permissions: me?.permissions,
            perm: 'approvals.decide',
            action: r.allowedActions ? 'approve' : undefined,
            allowedActions: r.allowedActions,
          })}
          onApprove={(hash, token) => managedRoutingApi.approve(server.id, hash, token)}
          onApproved={refresh}
        />
      )}
      {r?.error?.message && (
        <Notice tone="crit" glyph="✕" role="alert" title={r.error.code}>
          {r.error.message}
        </Notice>
      )}
      <ActionDialog
        open={open}
        onOpenChange={setOpen}
        title={t('mr.dialog.title', { server: server.name })}
        body={prod ? t('mr.dialog.bodyProd') : t('mr.dialog.body')}
        confirmLabel={t('mr.enable')}
        needsStepUp={false}
        onConfirm={async () => {
          await managedRoutingApi.enable(server.id);
          refresh();
        }}
      />
    </div>
  );
}
