'use client';

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { Button } from '@/components/ui/button';
import { Dialog } from '@/components/ui/dialog';
import { ErrorState } from '@/components/ui/states';
import { StepUpField } from './bits';
import type { ReactNode } from 'react';

/** Normalise thrown values so mutation errors always carry code + requestId. */
export function wrap<T>(fn: () => Promise<T>) {
  return async () => {
    try {
      return await fn();
    } catch (e) {
      throw toApiError(e);
    }
  };
}

/** Confirm dialog for a privileged action; optionally collects a fresh 2FA code (X-Step-Up). */
export function ActionDialog({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel,
  danger,
  needsStepUp,
  onConfirm,
  children,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  needsStepUp: boolean;
  children?: ReactNode;
  onConfirm: (stepUpToken?: string) => Promise<unknown>;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const [otp, setOtp] = useState('');
  const m = useMutation<unknown, ApiError>({
    mutationFn: wrap(async () => {
      const token = needsStepUp ? (await authApi.stepUp(otp)).stepUpToken : undefined;
      return onConfirm(token);
    }),
    onSuccess: () => onOpenChange(false),
  });
  const ready = !needsStepUp || (!!me?.mfaEnabled && /^\d{6}$/.test(otp));
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          m.reset();
          setOtp('');
        }
        onOpenChange(o);
      }}
      closeLabel={t('common.close')}
      title={title}
      description={body}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            disabled={!ready || m.isPending}
            onClick={() => m.mutate()}
          >
            {m.isPending ? t('common.saving') : confirmLabel}
          </Button>
        </>
      }
    >
      {children}
      {needsStepUp && <StepUpField value={otp} onChange={setOtp} />}
      {m.error && <ErrorState error={m.error} />}
    </Dialog>
  );
}
