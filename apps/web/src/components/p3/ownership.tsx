'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { applicationsApi, authApi } from '@/lib/api/endpoints';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { OWNERSHIP_ORDER, type Application } from '@/lib/api/p3-types';
import { ownershipConfirmReady, ownershipSteps, type OwnershipStep } from '@/lib/p3-gates';
import { p3k } from '@/lib/p3-queries';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/providers/toast';
import { Card } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog } from '@/components/ui/dialog';
import { Field, Input } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { useOwnershipHistory } from '@/lib/p3-queries';
import { OwnershipBadge, StepUpField, ownKey } from './bits';
import type { MessageKey } from '@/i18n/en';

export function OwnershipDialog({
  app,
  step,
  open,
  onOpenChange,
}: {
  app: Application;
  step: OwnershipStep;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const [reason, setReason] = useState('');
  const [ack, setAck] = useState(false);
  const [otp, setOtp] = useState('');
  const reasons = app.reasons ?? [];

  const m = useMutation<Application, ApiError>({
    mutationFn: async () => {
      try {
        const token = step.needsStepUp ? (await authApi.stepUp(otp)).stepUpToken : undefined;
        return await applicationsApi.changeOwnership(
          app,
          {
            toMode: step.to,
            reason: reason.trim(),
            acknowledgeReasons: step.needsAck ? ack : undefined,
          },
          token,
        );
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (updated) => {
      qc.setQueryData(p3k.app(app.id), updated);
      void qc.invalidateQueries({ queryKey: ['applications'] });
      toast(t('own.done', { mode: t(ownKey(updated.ownershipMode)) }), 'ok');
      onOpenChange(false);
    },
  });

  const ready = ownershipConfirmReady({
    step,
    reason,
    acknowledged: ack,
    otp,
    mfaEnabled: !!me?.mfaEnabled,
  });
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) m.reset();
        onOpenChange(o);
      }}
      closeLabel={t('common.close')}
      className="max-w-[540px]"
      title={t(step.direction === 'up' ? 'own.dialog.upTitle' : 'own.dialog.downTitle', {
        name: app.name,
        mode: t(ownKey(step.to)),
      })}
      description={t(`own.effect.${step.to}` as MessageKey)}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
          <Button variant="primary" disabled={!ready || m.isPending} onClick={() => m.mutate()}>
            {m.isPending
              ? t('common.saving')
              : t('own.dialog.confirm', { mode: t(ownKey(step.to)) })}
          </Button>
        </>
      }
    >
      <div className="flex items-center gap-2 text-[13px]">
        <OwnershipBadge mode={app.ownershipMode} />
        <span aria-hidden="true">→</span>
        <span className="sr-only">{t('diff.to')}</span>
        <OwnershipBadge mode={step.to} />
      </div>
      <Notice tone="ok" glyph="●" role="note">
        {t('own.noHostChange')}
      </Notice>
      {step.direction === 'down' && (
        <Notice tone="warn" glyph="▲" role="note">
          {t('own.downCancels')}
        </Notice>
      )}
      {step.needsAck && (
        <div
          className="flex flex-col gap-2 rounded-md border border-notice-line bg-notice-bg p-3"
          data-testid="ack-reasons"
        >
          <b className="text-[13px]">{t('own.ack.title')}</b>
          <ul className="m-0 flex list-disc flex-col gap-0.5 pl-5 text-[13px]">
            {(reasons.length ? reasons : [t('own.ack.flagsOnly')]).map((r) => (
              <li key={r}>{r}</li>
            ))}
            {app.flags.conflict && !reasons.some((r) => r.includes('duplicate')) && (
              <li>{t('flag.conflict')}</li>
            )}
          </ul>
          <label className="inline-flex items-center gap-2 text-[13px] font-medium">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            {t('own.ack.checkbox')}
          </label>
        </div>
      )}
      <Field label={t('own.reason')} hint={t('own.reasonHint')}>
        {(p) => (
          <Input
            {...p}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={500}
          />
        )}
      </Field>
      {step.needsStepUp && <StepUpField value={otp} onChange={setOtp} hint={t('own.stepUpHint')} />}
      {m.error && <ErrorState error={m.error} />}
    </Dialog>
  );
}

export function OwnershipPanel({ app }: { app: Application }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const steps = ownershipSteps(app, me?.permissions);
  const [active, setActive] = useState<OwnershipStep | null>(null);
  const current = OWNERSHIP_ORDER.indexOf(app.ownershipMode);
  return (
    <Card
      className="flex flex-col gap-3 p-4"
      aria-labelledby="own-title"
      data-testid="ownership-panel"
    >
      <h2 id="own-title" className="m-0 text-[15px] font-semibold">
        {t('own.title')}
      </h2>
      <ol className="m-0 grid list-none grid-cols-4 gap-1 p-0" aria-label={t('own.ladder')}>
        {OWNERSHIP_ORDER.map((m, i) => (
          <li
            key={m}
            aria-current={i === current ? 'step' : undefined}
            className={cn(
              'flex flex-col gap-0.5 rounded-md border px-2 py-1.5 text-[12px]',
              i === current
                ? 'border-accent-strong bg-info-bg font-semibold'
                : i < current
                  ? 'border-line bg-surface-2 text-fg-muted'
                  : 'border-dashed border-line-strong text-fg-muted',
            )}
          >
            <span>
              {i === current ? '◉ ' : i < current ? '✓ ' : '○ '}
              {t(ownKey(m))}
            </span>
          </li>
        ))}
      </ol>
      <p className="m-0 text-[13px] text-fg-2">
        {t(`own.effect.${app.ownershipMode}` as MessageKey)}
      </p>
      <div className="flex flex-wrap gap-2">
        {steps.map((s) => (
          <GatedButton
            key={s.to}
            size="sm"
            variant={s.direction === 'up' ? 'primary' : 'secondary'}
            blockedReason={s.gate.allowed ? undefined : s.gate.reason}
            onClick={() => setActive(s)}
          >
            {t(s.direction === 'up' ? 'own.up' : 'own.down', { mode: t(ownKey(s.to)) })}
          </GatedButton>
        ))}
      </div>
      {app.flags.unsupported && app.ownershipMode !== 'managed' && (
        <Notice tone="info" glyph="◆" role="note">
          {t('own.unsupportedBlocks')}
        </Notice>
      )}
      {app.environment === 'production' && (
        <span className="text-[12px] text-fg-muted">{t('own.prodStepUp')}</span>
      )}
      <span className="text-[12px] text-fg-muted">{t('own.noHostChange')}</span>
      {active && (
        <OwnershipDialog
          app={app}
          step={active}
          open={!!active}
          onOpenChange={(o) => !o && setActive(null)}
        />
      )}
    </Card>
  );
}

export function OwnershipHistory({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const q = useOwnershipHistory(app.id);
  if (q.isPending) return <TableSkeleton label={t('common.loading')} />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const items = q.data.items;
  if (!items.length) return <EmptyState title={t('own.history.empty')} />;
  return (
    <Card>
      <ol className="m-0 list-none p-0" aria-label={t('own.history.title')}>
        {items.map((h) => (
          <li
            key={h.id}
            className="flex flex-col gap-1 border-t border-line-subtle px-4 py-3 first:border-0"
          >
            <div className="flex flex-wrap items-center gap-2 text-[13px]">
              <OwnershipBadge mode={h.fromMode} />
              <span aria-hidden="true">→</span>
              <span className="sr-only">{t('diff.to')}</span>
              <OwnershipBadge mode={h.toMode} />
              <span className="text-fg-muted">
                {t('own.history.by', {
                  actor: h.actorLabel ?? h.actorId.slice(0, 8),
                  time: formatDateTime(h.createdAt, locale),
                })}
              </span>
            </div>
            <div className="text-[13px]">{h.reason}</div>
            {h.acknowledgedReasons.length > 0 && (
              <div className="flex flex-wrap items-center gap-1 text-[12px]">
                <ToneBadge tone="warn" size="sm">
                  {t('own.history.acked')}
                </ToneBadge>
                {h.acknowledgedReasons.join(' · ')}
              </div>
            )}
          </li>
        ))}
      </ol>
    </Card>
  );
}
