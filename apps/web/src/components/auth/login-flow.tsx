'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { isMfaRequired, type LoginSuccess } from '@/lib/api/types';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { API_MOCK } from '@/lib/config';
import { Button } from '@/components/ui/button';
import { Field, Input } from '@/components/ui/form';
import { ErrorState, Notice } from '@/components/ui/states';
import { Skeleton } from '@/components/ui/skeleton';
import { AuthCard } from './auth-card';
import { OtpInput } from './otp-input';

type Step = { kind: 'login' } | { kind: 'mfa'; mfaToken: string };

/** Only allow same-app relative redirects (no open redirect via ?next=). */
function safeNext(next: string | null): string {
  if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/login'))
    return '/overview';
  return next;
}

function ApiErrorLine({ error }: { error: ApiError | null }) {
  const t = useT();
  if (!error) return null;
  return (
    <div role="alert" className="rounded-md border border-crit bg-crit-bg px-3 py-2 text-[13px]">
      {error.kind === 'network' ? t('state.error.network') : error.message}
      {error.requestId && (
        <div className="font-mono text-[11.5px] text-fg-muted">
          {t('common.requestId')}: {error.requestId}
        </div>
      )}
    </div>
  );
}

export function LoginFlow() {
  const t = useT();
  const router = useRouter();
  const params = useSearchParams();
  const { status, completeLogin } = useAuth();
  const next = safeNext(params.get('next'));
  const reason = params.get('reason');

  const setup = useQuery({ queryKey: ['setup-status'], queryFn: authApi.setupStatus, retry: 1 });
  const [bootstrapDone, setBootstrapDone] = useState(false);

  useEffect(() => {
    if (status === 'authenticated') router.replace(next);
  }, [status, next, router]);

  if (setup.isPending) {
    return (
      <AuthCard>
        <div
          role="status"
          aria-busy="true"
          aria-label={t('bootstrap.checking')}
          className="flex flex-col gap-3"
        >
          <Skeleton className="h-6 w-32" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </AuthCard>
    );
  }
  if (setup.isError) {
    return (
      <AuthCard>
        <ErrorState error={setup.error} onRetry={() => void setup.refetch()} />
      </AuthCard>
    );
  }
  if (!setup.data.bootstrapped && !bootstrapDone) {
    return <BootstrapForm onDone={() => setBootstrapDone(true)} />;
  }
  return (
    <SignIn
      notice={
        bootstrapDone
          ? t('bootstrap.done')
          : reason === 'expired'
            ? t('login.sessionExpired')
            : reason === 'signedout'
              ? t('login.signedOut')
              : null
      }
      onSuccess={async (res) => {
        await completeLogin(res);
        router.replace(next);
      }}
    />
  );
}

function SignIn({
  notice,
  onSuccess,
}: {
  notice: string | null;
  onSuccess: (res: LoginSuccess) => Promise<void>;
}) {
  const t = useT();
  const [step, setStep] = useState<Step>({ kind: 'login' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const submitLogin = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await authApi.login({ email: email.trim(), password });
      if (isMfaRequired(res)) {
        setStep({ kind: 'mfa', mfaToken: res.mfaToken });
        setPassword('');
      } else {
        await onSuccess(res);
      }
    } catch (err) {
      setError(toApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const submitMfa = async (e: FormEvent) => {
    e.preventDefault();
    if (step.kind !== 'mfa') return;
    setBusy(true);
    setError(null);
    try {
      const res = await authApi.verifyMfa(
        useRecovery
          ? { mfaToken: step.mfaToken, recoveryCode: recovery.trim() }
          : { mfaToken: step.mfaToken, code },
      );
      await onSuccess(res);
    } catch (err) {
      const apiErr = toApiError(err);
      setError(apiErr);
      setCode('');
      if (apiErr.code === 'UNAUTHENTICATED') setStep({ kind: 'login' });
    } finally {
      setBusy(false);
    }
  };

  if (step.kind === 'mfa') {
    const ready = useRecovery ? recovery.trim().length >= 8 : /^\d{6}$/.test(code);
    return (
      <AuthCard>
        <form onSubmit={submitMfa} className="flex flex-col gap-3.5" noValidate>
          <h1 className="m-0 text-[20px] font-semibold">{t('mfa.title')}</h1>
          {useRecovery ? (
            <Field label={t('mfa.recoveryLabel')} hint={t('mfa.recoveryHint')}>
              {(p) => (
                <Input
                  {...p}
                  autoFocus
                  value={recovery}
                  onChange={(e) => setRecovery(e.target.value)}
                  autoComplete="off"
                  className="font-mono"
                  placeholder="xxxx-xxxx"
                />
              )}
            </Field>
          ) : (
            <>
              <div className="text-[13px] text-fg-3">{t('mfa.hint')}</div>
              <OtpInput
                value={code}
                onChange={setCode}
                autoFocus
                invalid={!!error}
                groupLabel={t('mfa.code')}
              />
            </>
          )}
          <ApiErrorLine error={error} />
          <Button type="submit" variant="primary" size="lg" disabled={!ready || busy}>
            {busy ? t('login.signingIn') : t('mfa.verify')}
          </Button>
          <Button
            variant="link"
            className="self-start text-[13px]"
            onClick={() => {
              setUseRecovery((v) => !v);
              setError(null);
            }}
          >
            {useRecovery ? t('mfa.useCode') : t('mfa.useRecovery')}
          </Button>
          <Button
            variant="link"
            className="self-start text-[13px]"
            onClick={() => setStep({ kind: 'login' })}
          >
            {t('mfa.backToLogin')}
          </Button>
        </form>
      </AuthCard>
    );
  }

  return (
    <AuthCard>
      <form onSubmit={submitLogin} className="flex flex-col gap-3.5" noValidate>
        {notice && (
          <Notice tone="ok" glyph="●" role="status" className="px-3 py-2 text-[12.5px]">
            {notice}
          </Notice>
        )}
        <h1 className="m-0 text-[20px] font-semibold">{t('login.title')}</h1>
        <Field label={t('login.email')}>
          {(p) => (
            <Input
              {...p}
              type="text"
              inputMode="email"
              autoComplete="username"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t('login.password')}>
          {(p) => (
            <Input
              {...p}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          )}
        </Field>
        <ApiErrorLine error={error} />
        <Button type="submit" variant="primary" size="lg" disabled={busy || !email || !password}>
          {busy ? t('login.signingIn') : t('login.continue')}
        </Button>
        {API_MOCK && <p className="m-0 text-[12px] text-fg-muted">{t('login.mockHint')}</p>}
      </form>
    </AuthCard>
  );
}

function BootstrapForm({ onDone }: { onDone: () => void }) {
  const t = useT();
  const [form, setForm] = useState({ email: '', displayName: '', password: '', setupToken: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const fe = error?.fieldErrors ?? {};
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <AuthCard wide>
      <form
        noValidate
        className="flex flex-col gap-3.5"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await authApi.bootstrap({
              ...form,
              email: form.email.trim(),
              displayName: form.displayName.trim(),
              setupToken: form.setupToken.trim(),
            });
            onDone();
          } catch (err) {
            setError(toApiError(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        <h1 className="m-0 text-[20px] font-semibold">{t('bootstrap.title')}</h1>
        <p className="m-0 text-[13px] text-fg-3">{t('bootstrap.body')}</p>
        <Field label={t('login.email')} error={fe.email}>
          {(p) => (
            <Input
              {...p}
              type="email"
              autoComplete="username"
              value={form.email}
              onChange={set('email')}
            />
          )}
        </Field>
        <Field label={t('bootstrap.displayName')} error={fe.displayName}>
          {(p) => (
            <Input
              {...p}
              value={form.displayName}
              onChange={set('displayName')}
              autoComplete="name"
            />
          )}
        </Field>
        <Field label={t('login.password')} hint={t('bootstrap.passwordHint')} error={fe.password}>
          {(p) => (
            <Input
              {...p}
              type="password"
              autoComplete="new-password"
              value={form.password}
              onChange={set('password')}
            />
          )}
        </Field>
        <Field
          label={t('bootstrap.setupToken')}
          hint={t('bootstrap.setupTokenHint')}
          error={fe.setupToken}
        >
          {(p) => (
            <Input
              {...p}
              type="password"
              autoComplete="off"
              className="font-mono"
              value={form.setupToken}
              onChange={set('setupToken')}
            />
          )}
        </Field>
        <ApiErrorLine error={error && Object.keys(fe).length === 0 ? error : null} />
        <Button
          type="submit"
          variant="primary"
          size="lg"
          disabled={busy || !form.email || !form.password || !form.setupToken || !form.displayName}
        >
          {busy ? t('common.saving') : t('bootstrap.submit')}
        </Button>
      </form>
    </AuthCard>
  );
}
