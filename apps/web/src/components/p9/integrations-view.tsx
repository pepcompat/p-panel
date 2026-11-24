'use client';

import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { authApi } from '@/lib/api/endpoints';
import { isApiError, type ApiError } from '@/lib/api/errors';
import { integrationsApi } from '@/lib/api/p9-endpoints';
import type { ProviderIntegration } from '@/lib/api/p9-types';
import { useAuth } from '@/lib/auth/auth-provider';
import { P9_PERM } from '@/lib/p9-gates';
import { p9k, useIntegrations } from '@/lib/p9-queries';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { ActionDialog, wrap } from '@/components/p3/action-dialog';
import { StepUpField } from '@/components/p3/bits';
import { useToast } from '@/components/providers/toast';
import { Card } from '@/components/ui/card';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Field, Input } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { CardTitle } from './net-bits';

const STATUS_TONE: Record<ProviderIntegration['status'], Tone> = {
  ok: 'ok',
  error: 'crit',
  unverified: 'warn',
};

function AddIntegration() {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const tokenRef = useRef<HTMLInputElement>(null);
  const [name, setName] = useState('');
  const [hasToken, setHasToken] = useState(false);
  const [otp, setOtp] = useState('');
  const [saved, setSaved] = useState<string | null>(null);
  const m = useMutation<ProviderIntegration, ApiError>({
    mutationFn: wrap(async () => {
      const token = tokenRef.current?.value ?? '';
      const su = (await authApi.stepUp(otp)).stepUpToken;
      return integrationsApi.create({ provider: 'digitalocean', name: name.trim(), token }, su);
    }),
    onSuccess: (i) => {
      // the token leaves the page with the request; it is never kept or shown again
      if (tokenRef.current) tokenRef.current.value = '';
      setHasToken(false);
      setOtp('');
      setName('');
      setSaved(i.name);
      toast(t('p9.int.added'), 'ok');
      void qc.invalidateQueries({ queryKey: p9k.integrations });
    },
  });
  const fe = m.error?.fieldErrors ?? {};
  const nameOk = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/.test(name.trim());
  const ready = nameOk && hasToken && /^\d{6}$/.test(otp) && !!me?.mfaEnabled && !m.isPending;
  return (
    <Card
      className="flex flex-col gap-3 p-4"
      aria-labelledby="add-int-h"
      data-testid="add-integration"
    >
      <CardTitle id="add-int-h">{t('p9.int.add')}</CardTitle>
      <Notice tone="info" glyph="◆" role="note">
        {t('p9.int.readOnlyNote')}
      </Notice>
      {saved && (
        <Notice tone="ok" glyph="●" role="status" title={t('p9.int.savedTitle', { name: saved })}>
          <span data-testid="token-never-again">{t('p9.int.neverAgain')}</span>
        </Notice>
      )}
      <form
        noValidate
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) m.mutate();
        }}
      >
        <Field label={t('p9.int.name')} hint={t('p9.int.nameHint')} error={fe.name}>
          {(p) => (
            <Input
              {...p}
              value={name}
              maxLength={63}
              onChange={(e) => setName(e.target.value)}
              placeholder="do-main"
            />
          )}
        </Field>
        <Field label={t('p9.int.token')} hint={t('p9.int.tokenHint')} error={fe.token}>
          {(p) => (
            <Input
              {...p}
              ref={tokenRef}
              type="password"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setHasToken(e.target.value.length >= 8)}
              className="font-mono"
            />
          )}
        </Field>
        <div className="max-w-[320px]">
          <StepUpField value={otp} onChange={setOtp} hint={t('p9.int.stepUpHint')} />
        </div>
        {m.error &&
          Object.keys(fe).length === 0 &&
          (m.error.code === 'PROVIDER_AUTH_FAILED' ? (
            <Notice tone="crit" glyph="✕" role="alert" title={t('p9.int.authFailed')}>
              {m.error.message}{' '}
              <span className="font-mono text-[11.5px] text-fg-muted">{m.error.requestId}</span>
            </Notice>
          ) : (
            <ErrorState error={m.error} />
          ))}
        <div>
          <GatedButton
            type="submit"
            variant="primary"
            perm={P9_PERM.settingsManage}
            disabled={!ready}
          >
            {m.isPending ? t('common.saving') : t('p9.int.save')}
          </GatedButton>
        </div>
      </form>
    </Card>
  );
}

function IntegrationRow({ i, now }: { i: ProviderIntegration; now: number }) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const [del, setDel] = useState(false);
  const sync = useMutation<unknown, ApiError>({
    mutationFn: wrap(() => integrationsApi.sync(i.id)),
    onSuccess: () => {
      toast(t('p9.int.syncStarted'), 'ok');
      void qc.invalidateQueries({ queryKey: p9k.integrations });
    },
  });
  const allowed = (a: 'sync' | 'delete') => !i.allowedActions || i.allowedActions.includes(a);
  return (
    <li
      className="flex flex-col gap-2 border-t border-line-subtle px-4 py-3 first:border-t-0"
      data-testid="integration-row"
    >
      <div className="flex flex-wrap items-center gap-2">
        <b className="font-mono text-[13.5px]">{i.name}</b>
        <span className="text-[12px] text-fg-muted">DigitalOcean · {i.apiBase}</span>
        <span className="flex-1" />
        <ToneBadge tone={STATUS_TONE[i.status]} size="sm">
          <span data-testid="integration-status">{t(`p9.int.status.${i.status}`)}</span>
        </ToneBadge>
        {i.syncInProgress && (
          <ToneBadge tone="info" size="sm" glyph="◌">
            <span data-testid="syncing">{t('p9.int.syncing')}</span>
          </ToneBadge>
        )}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12.5px] text-fg-muted">
        <span
          title={i.lastSyncAt ? formatDateTime(i.lastSyncAt, locale) : undefined}
          data-testid="last-sync"
        >
          {t('p9.int.lastSync')}:{' '}
          {i.lastSyncAt ? relativeTime(i.lastSyncAt, t, now) : t('time.never')}
        </span>
        {i.lastSyncSummary && (
          <span>
            {t('p9.int.summary', {
              droplets: i.lastSyncSummary.droplets,
              vpcs: i.lastSyncSummary.vpcs,
              matched: i.lastSyncSummary.matched,
              unmatched: i.lastSyncSummary.unmatched,
            })}
          </span>
        )}
        <span>{t('p9.int.token')}: ••••••••</span>
      </div>
      {i.lastError && (
        <Notice tone="crit" glyph="✕" role="status" title={i.lastError.code}>
          {i.lastError.message}
        </Notice>
      )}
      <div className="flex flex-wrap gap-2">
        <GatedButton
          size="sm"
          perm={P9_PERM.settingsManage}
          blockedReason={
            allowed('sync') ? undefined : { key: 'perm.actionNotAllowed', vars: { action: 'sync' } }
          }
          disabled={sync.isPending || i.syncInProgress}
          onClick={() => sync.mutate()}
          data-testid="sync-integration"
        >
          {t('p9.int.sync')}
        </GatedButton>
        <GatedButton
          size="sm"
          variant="secondary"
          className="border-crit text-crit"
          perm={P9_PERM.settingsManage}
          blockedReason={
            allowed('delete')
              ? undefined
              : { key: 'perm.actionNotAllowed', vars: { action: 'delete' } }
          }
          onClick={() => setDel(true)}
        >
          {t('p9.int.delete')}
        </GatedButton>
      </div>
      {sync.error && <ErrorState error={sync.error} />}
      <ActionDialog
        open={del}
        onOpenChange={setDel}
        title={t('p9.int.deleteTitle', { name: i.name })}
        body={t('p9.int.deleteBody')}
        confirmLabel={t('p9.int.delete')}
        danger
        needsStepUp={false}
        onConfirm={async () => {
          await integrationsApi.remove(i.id);
          void qc.invalidateQueries({ queryKey: p9k.integrations });
        }}
      />
    </li>
  );
}

export function IntegrationsView() {
  const { t } = useI18n();
  const now = useNow(10_000);
  const q = useIntegrations();
  const forbidden = isApiError(q.error) && q.error.status === 403;
  return (
    <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
      <Card className="overflow-hidden" aria-labelledby="int-h">
        <div className="border-b border-line-soft px-4 py-3">
          <CardTitle id="int-h">{t('p9.int.title')}</CardTitle>
          <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.int.subtitle')}</p>
        </div>
        {forbidden ? (
          <div className="p-4">
            <ForbiddenState
              perm="fleet.read"
              requestId={isApiError(q.error) ? q.error.requestId : null}
            />
          </div>
        ) : q.isPending ? (
          <div className="p-4">
            <TableSkeleton label={t('common.loading')} />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : q.data.length === 0 ? (
          <div className="p-4">
            <EmptyState title={t('p9.int.empty')} body={t('p9.int.emptyBody')} />
          </div>
        ) : (
          <ul className="m-0 list-none p-0">
            {q.data.map((i) => (
              <IntegrationRow key={i.id} i={i} now={now} />
            ))}
          </ul>
        )}
      </Card>
      <AddIntegration />
    </div>
  );
}
