'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { toApiError, type ApiError } from '@/lib/api/errors';
import type { TotpSetup } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import { CopyButton } from '@/components/ui/copy-button';
import { Notice } from '@/components/ui/states';
import { Skeleton } from '@/components/ui/skeleton';
import { AuthCard } from './auth-card';
import { OtpInput } from './otp-input';

type Stage =
  { s: 'intro' } | { s: 'scan'; setup: TotpSetup; qr: string } | { s: 'codes'; codes: string[] };

export function TotpSetupFlow() {
  const t = useT();
  const router = useRouter();
  const { status, me, refreshMe } = useAuth();
  const [stage, setStage] = useState<Stage>({ s: 'intro' });
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [ack, setAck] = useState(false);

  useEffect(() => {
    if (status === 'anonymous') router.replace('/login?next=/setup/2fa');
  }, [status, router]);

  if (status !== 'authenticated') {
    return (
      <AuthCard wide>
        <div
          role="status"
          aria-busy="true"
          aria-label={t('common.loading')}
          className="flex flex-col gap-3"
        >
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-40 w-full" />
        </div>
      </AuthCard>
    );
  }

  const errorBox = error && (
    <div role="alert" className="rounded-md border border-crit bg-crit-bg px-3 py-2 text-[13px]">
      {error.message}
      {error.requestId && (
        <div className="font-mono text-[11.5px] text-fg-muted">
          {t('common.requestId')}: {error.requestId}
        </div>
      )}
    </div>
  );

  if (stage.s === 'codes') {
    return (
      <AuthCard wide>
        <h1 className="m-0 text-[20px] font-semibold">{t('setup2fa.recoveryTitle')}</h1>
        <Notice tone="warn" glyph="▲" role="alert">
          {t('setup2fa.recoveryBody')}
        </Notice>
        <ol
          aria-label={t('setup2fa.recoveryTitle')}
          className="m-0 grid list-none grid-cols-2 gap-1.5 rounded-md bg-terminal p-3 font-mono text-[13px] text-terminal-fg"
        >
          {stage.codes.map((c) => (
            <li key={c} className="select-all">
              {c}
            </li>
          ))}
        </ol>
        <CopyButton
          text={stage.codes.join('\n')}
          label={t('setup2fa.copyCodes')}
          variant="secondary"
          size="md"
        />
        <label className="flex cursor-pointer items-start gap-2.5 text-[13px]">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
            className="mt-0.5 h-[18px] w-[18px]"
          />
          {t('setup2fa.ack')}
        </label>
        <Button
          variant="primary"
          size="lg"
          disabled={!ack}
          onClick={() => {
            setStage({ s: 'intro' }); // drop codes from memory
            router.replace('/overview');
          }}
        >
          {t('setup2fa.done')}
        </Button>
      </AuthCard>
    );
  }

  if (me?.mfaEnabled) {
    return (
      <AuthCard wide>
        <h1 className="m-0 text-[20px] font-semibold">{t('setup2fa.title')}</h1>
        <Notice tone="ok" glyph="●">
          {t('setup2fa.already')}
        </Notice>
        <Button variant="primary" onClick={() => router.replace('/overview')}>
          {t('setup2fa.done')}
        </Button>
      </AuthCard>
    );
  }

  if (stage.s === 'scan') {
    return (
      <AuthCard wide>
        <form
          className="flex flex-col gap-3.5"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const res = await authApi.totpConfirm(code);
              await refreshMe();
              setStage({ s: 'codes', codes: res.recoveryCodes });
            } catch (err) {
              setError(toApiError(err));
              setCode('');
            } finally {
              setBusy(false);
            }
          }}
        >
          <h1 className="m-0 text-[20px] font-semibold">{t('setup2fa.title')}</h1>
          <b className="text-[13.5px]">{t('setup2fa.scan')}</b>
          {/* eslint-disable-next-line @next/next/no-img-element -- generated data URL */}
          <img
            src={stage.qr}
            width={200}
            height={200}
            alt={t('setup2fa.qrAlt')}
            className="self-center rounded-md border border-line bg-white p-2"
          />
          <span className="font-mono text-[12px] break-all text-fg-muted">
            {t('setup2fa.secret', { secret: stage.setup.secretMasked })}
          </span>
          <b className="text-[13.5px]">{t('setup2fa.enter')}</b>
          <OtpInput
            value={code}
            onChange={setCode}
            autoFocus
            invalid={!!error}
            groupLabel={t('mfa.code')}
          />
          {errorBox}
          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={busy || !/^\d{6}$/.test(code)}
          >
            {busy ? t('common.saving') : t('setup2fa.confirm')}
          </Button>
        </form>
      </AuthCard>
    );
  }

  return (
    <AuthCard wide>
      <h1 className="m-0 text-[20px] font-semibold">{t('setup2fa.title')}</h1>
      <p className="m-0 text-[13.5px] text-fg-3">{t('setup2fa.intro')}</p>
      {errorBox}
      <Button
        variant="primary"
        size="lg"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            const setup = await authApi.totpSetup();
            const qr = await QRCode.toDataURL(setup.otpauthUrl, {
              margin: 1,
              width: 200,
              errorCorrectionLevel: 'M',
            });
            setStage({ s: 'scan', setup, qr });
          } catch (err) {
            setError(toApiError(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? t('common.loading') : t('setup2fa.start')}
      </Button>
      <Button variant="ghost" onClick={() => router.replace('/overview')}>
        {t('setup2fa.skip')}
      </Button>
    </AuthCard>
  );
}
