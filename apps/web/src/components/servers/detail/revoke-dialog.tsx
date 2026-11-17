'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi, serversApi } from '@/lib/api/endpoints';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { qk } from '@/lib/queries';
import { useToast } from '@/components/providers/toast';
import { Dialog } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Field, Input } from '@/components/ui/form';
import { ToneBadge } from '@/components/ui/badge';
import { ErrorState, Notice } from '@/components/ui/states';

/** Destructive confirm: type the server name; production additionally requires step-up 2FA (X-Step-Up). */
export function RevokeDialog({ server, open, onOpenChange }: { server: Server; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [typed, setTyped] = useState('');
  const [otp, setOtp] = useState('');
  const prod = server.environment === 'production';
  const mfaMissing = prod && !me?.mfaEnabled;

  const m = useMutation<Server, ApiError>({
    mutationFn: async () => {
      try {
        let token: string | undefined;
        if (prod) token = (await authApi.stepUp(otp)).stepUpToken;
        return await serversApi.revoke(server.id, token);
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (updated) => {
      qc.setQueryData(qk.server(server.id), updated);
      void qc.invalidateQueries({ queryKey: qk.servers, exact: true });
      toast(t('revoke.done'), 'ok');
      close(false);
    },
  });

  const close = (o: boolean) => {
    if (!o) {
      setTyped('');
      setOtp('');
      m.reset();
    }
    onOpenChange(o);
  };

  const ready = typed === server.name && (!prod || /^\d{6}$/.test(otp)) && !mfaMissing;
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      closeLabel={t('common.close')}
      badge={
        <ToneBadge tone="crit" glyph={false} className="self-start font-mono text-[11.5px]">
          destructive
        </ToneBadge>
      }
      title={t('revoke.title', { name: server.name })}
      description={t('revoke.body')}
      footer={
        <>
          <Button onClick={() => close(false)}>{t('common.cancel')}</Button>
          <Button variant="danger" disabled={!ready || m.isPending} onClick={() => m.mutate()}>
            {m.isPending ? t('common.saving') : t('revoke.confirm')}
          </Button>
        </>
      }
    >
      <div className="text-[12.5px] text-fg-muted">
        {t('revoke.target', { target: `${server.name} (${server.environment})` })}
      </div>
      <Field label={t('revoke.typeName', { name: server.name })}>
        {(p) => <Input {...p} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" className="font-mono" />}
      </Field>
      {prod &&
        (mfaMissing ? (
          <Notice tone="crit" glyph="✕" role="alert">
            {t('revoke.mfaMissing')} <a href="/setup/2fa">{t('security.setup')}</a>
          </Notice>
        ) : (
          <Field label={t('revoke.stepUp')} hint={t('revoke.stepUpHint')}>
            {(p) => (
              <Input
                {...p}
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                className="font-mono text-[15px] tracking-[.2em]"
              />
            )}
          </Field>
        ))}
      {m.error && <ErrorState error={m.error} />}
    </Dialog>
  );
}
