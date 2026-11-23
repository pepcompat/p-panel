'use client';

import Link from 'next/link';
import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { API_BASE, API_MOCK } from '@/lib/config';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import { integrationsApi } from '@/lib/api/p4-endpoints';
import type { Integration } from '@/lib/api/p4-types';
import { p4k, useDeliveries, useIntegrations } from '@/lib/p4-queries';
import { formatDateTime } from '@/lib/time';
import { Card } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CopyButton } from '@/components/ui/copy-button';
import { Field, Input } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { Table, Td, Th } from '@/components/preview/shared';
import { DeliveryResultBadge } from './bits';

/** Absolute webhook URL to paste into GitHub (the API returns a path). */
export function absoluteWebhookUrl(path: string): string {
  if (/^https?:\/\//.test(path)) return path;
  const origin =
    API_MOCK || !/^https?:\/\//.test(API_BASE)
      ? typeof window !== 'undefined'
        ? window.location.origin
        : ''
      : new URL(API_BASE).origin;
  return `${origin}${path}`;
}

function CreateIntegration({ onCreated }: { onCreated: (i: Integration) => void }) {
  const { t } = useI18n();
  const [name, setName] = useState('');
  const secretRef = useRef<HTMLInputElement>(null);
  const [secretLen, setSecretLen] = useState(0);
  const m = useMutation<Integration, ApiError>({
    mutationFn: async () => {
      try {
        return await integrationsApi.create({
          name: name.trim(),
          webhookSecret: secretRef.current?.value ?? '',
        });
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (i) => {
      if (secretRef.current) secretRef.current.value = '';
      setSecretLen(0);
      setName('');
      onCreated(i);
    },
  });
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate();
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t('int.name')}>
          {(p) => (
            <Input
              {...p}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="w3co GitHub"
            />
          )}
        </Field>
        <Field label={t('int.secret')} hint={t('int.secretHint')}>
          {(p) => (
            <input
              {...p}
              ref={secretRef}
              type="password"
              autoComplete="new-password"
              spellCheck={false}
              onChange={(e) => setSecretLen(e.currentTarget.value.length)}
              className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[13px]"
            />
          )}
        </Field>
      </div>
      <div>
        <Button
          type="submit"
          variant="primary"
          disabled={m.isPending || name.trim().length < 2 || secretLen < 16}
        >
          {m.isPending ? t('common.saving') : t('int.create')}
        </Button>
      </div>
      {m.error && <ErrorState error={m.error} />}
    </form>
  );
}

function Deliveries({ integration }: { integration: Integration }) {
  const { t, locale } = useI18n();
  const q = useDeliveries(integration.id);
  if (q.isPending) return <TableSkeleton label={t('common.loading')} />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const items = q.data?.items ?? [];
  if (!items.length)
    return <EmptyState title={t('int.deliveries.empty')} body={t('int.deliveries.emptyBody')} />;
  return (
    <Table
      minWidth={980}
      head={
        <>
          <Th>{t('int.col.delivery')}</Th>
          <Th>{t('int.col.event')}</Th>
          <Th>{t('int.col.repo')}</Th>
          <Th>{t('int.col.ref')}</Th>
          <Th>{t('int.col.commit')}</Th>
          <Th>{t('int.col.signature')}</Th>
          <Th>{t('int.col.result')}</Th>
          <Th>{t('int.col.received')}</Th>
        </>
      }
    >
      {items.map((d) => (
        <tr key={d.id} data-testid="delivery-row">
          <Td className="font-mono text-[11.5px]">{d.deliveryId.slice(0, 13)}…</Td>
          <Td className="font-mono text-[12px]">{d.event}</Td>
          <Td className="font-mono text-[12px]">{d.repo ?? t('common.dash')}</Td>
          <Td className="font-mono text-[12px]">
            {d.ref?.replace('refs/heads/', '') ?? t('common.dash')}
          </Td>
          <Td className="font-mono text-[12px]">
            {d.after ? d.after.slice(0, 7) : t('common.dash')}
          </Td>
          <Td>
            {d.signatureOk ? (
              <ToneBadge tone="ok" size="sm">
                {t('int.sig.ok')}
              </ToneBadge>
            ) : (
              <ToneBadge tone="crit" size="sm">
                {t('int.sig.bad')}
              </ToneBadge>
            )}
          </Td>
          <Td>
            <DeliveryResultBadge d={d} />
            {d.deploymentIds.map((id) => (
              <Link key={id} href={`/deployments/${id}`} className="ml-1.5 font-mono text-[11.5px]">
                {t('int.viewDeployment')}
              </Link>
            ))}
          </Td>
          <Td className="text-[12px] whitespace-nowrap">{formatDateTime(d.receivedAt, locale)}</Td>
        </tr>
      ))}
    </Table>
  );
}

export function IntegrationsView() {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useIntegrations();
  const ghApp = useQuery({
    queryKey: ['integrations', 'github', 'app'],
    queryFn: () => integrationsApi.githubApp(),
    retry: false,
  });
  const [created, setCreated] = useState<Integration | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const items = q.data?.items ?? [];
  const current = items.find((i) => i.id === selected) ?? items[0] ?? null;
  if (!can('apps.read') || (isApiError(q.error) && q.error.status === 403))
    return (
      <ForbiddenState perm="apps.read" requestId={isApiError(q.error) ? q.error.requestId : null} />
    );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 flex-1 text-[17px] font-semibold">{t('int.title')}</h2>
        <GatedButton
          variant="primary"
          perm="policies.manage"
          onClick={() => setShowCreate((v) => !v)}
        >
          + {t('int.add')}
        </GatedButton>
      </div>
      {ghApp.data?.available !== true && (
        <Notice tone="crit" glyph="✕" role="note" title={t('int.appBlockedTitle')}>
          {t('int.appBlockedBody')}
          {ghApp.data?.reason && (
            <span className="mt-1 block font-mono text-[12px] text-fg-muted">
              {ghApp.data.reason}
            </span>
          )}
        </Notice>
      )}
      {showCreate && (
        <Card className="flex flex-col gap-3 p-4">
          <h3 className="m-0 text-[14.5px] font-semibold">{t('int.add')}</h3>
          <CreateIntegration
            onCreated={(i) => {
              setCreated(i);
              setShowCreate(false);
              setSelected(i.id);
              void qc.invalidateQueries({ queryKey: p4k.integrations }); // gitleaks:allow (TanStack query key, not a secret)
            }}
          />
        </Card>
      )}
      {created && (
        <Notice tone="ok" glyph="●" role="status" title={t('int.created', { name: created.name })}>
          <span className="block">{t('int.createdBody')}</span>
          <span className="mt-1 flex flex-wrap items-center gap-2">
            <code
              className="rounded bg-surface px-2 py-1 font-mono text-[12px] break-all"
              data-testid="webhook-url"
            >
              {absoluteWebhookUrl(created.webhookUrl)}
            </code>
            <CopyButton text={absoluteWebhookUrl(created.webhookUrl)} />
          </span>
          <span className="mt-1 block text-[12px] text-fg-muted">{t('int.secretNotShown')}</span>
        </Notice>
      )}
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : items.length === 0 ? (
        <EmptyState title={t('int.empty')} body={t('int.emptyBody')} />
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,320px)_minmax(0,1fr)]">
          <Card className="overflow-hidden">
            {items.map((i) => (
              <button
                key={i.id}
                type="button"
                aria-pressed={current?.id === i.id}
                onClick={() => setSelected(i.id)}
                className={`flex w-full flex-col gap-0.5 border-0 border-t border-line-subtle px-4 py-3 text-left first:border-t-0 ${current?.id === i.id ? 'bg-info-bg' : 'bg-surface hover:bg-surface-hover'}`}
              >
                <span className="flex items-center gap-2 text-[13.5px] font-medium">
                  {i.name}
                  <ToneBadge tone={i.enabled ? 'ok' : 'off'} size="sm">
                    {i.enabled ? t('ad.enabled') : t('ad.disabled')}
                  </ToneBadge>
                </span>
                <span className="font-mono text-[11.5px] break-all text-fg-muted">
                  {i.webhookUrl}
                </span>
              </button>
            ))}
          </Card>
          {current && (
            <div className="flex flex-col gap-3">
              <Card className="flex flex-col gap-2 p-4">
                <h3 className="m-0 text-[14.5px] font-semibold">{current.name}</h3>
                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                  <span className="text-fg-muted">{t('int.webhookUrl')}</span>
                  <code className="font-mono text-[12px] break-all">
                    {absoluteWebhookUrl(current.webhookUrl)}
                  </code>
                  <CopyButton text={absoluteWebhookUrl(current.webhookUrl)} />
                </div>
                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                  <span className="text-fg-muted">{t('int.secretLabel')}</span>
                  <ToneBadge tone="ok" glyph="✓" size="sm">
                    {t('int.secretSet')}
                  </ToneBadge>
                  <span className="text-[12px] text-fg-muted">{t('int.secretNotShown')}</span>
                </div>
                <p className="m-0 text-[12px] text-fg-muted">
                  {t('int.howto')} ·{' '}
                  {current.createdAt && formatDateTime(current.createdAt, locale)}
                </p>
              </Card>
              <h3 className="m-0 text-[14.5px] font-semibold">{t('int.deliveries')}</h3>
              <Deliveries integration={current} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
