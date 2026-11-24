'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { isApiError, type ApiError } from '@/lib/api/errors';
import { gatewaysApi } from '@/lib/api/p9-endpoints';
import type { Gateway } from '@/lib/api/p9-types';
import { P9_PERM } from '@/lib/p9-gates';
import { p9k, useGateways } from '@/lib/p9-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey, isLive } from '@/lib/servers';
import { wrap } from '@/components/p3/action-dialog';
import { Card } from '@/components/ui/card';
import { EnvBadge, ToneBadge } from '@/components/ui/badge';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { CardSkeletonGrid } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ModeLegend } from './gateway-bits';
import { CardTitle } from './net-bits';

function CreateGateway({ existing }: { existing: Gateway[] }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const router = useRouter();
  const servers = useServers();
  const taken = new Set(existing.map((g) => g.serverId));
  const candidates = (servers.data?.items ?? []).filter(
    (s) => !taken.has(s.id) && s.status !== 'revoked' && s.capabilities.includes('nginx'),
  );
  const [serverId, setServerId] = useState('');
  const [name, setName] = useState('');
  const m = useMutation<Gateway, ApiError>({
    mutationFn: wrap(() => gatewaysApi.create({ serverId, name: name.trim() })),
    onSuccess: (g) => {
      void qc.invalidateQueries({ queryKey: p9k.gateways });
      router.push(`/network/gateways/${g.id}`);
    },
  });
  const nameOk = /^[a-z0-9][a-z0-9-]{0,62}$/.test(name.trim());
  const fe = m.error?.fieldErrors ?? {};
  return (
    <Card
      className="flex flex-col gap-3 p-4"
      aria-labelledby="gw-new-h"
      data-testid="create-gateway"
    >
      <CardTitle id="gw-new-h">{t('p9.gw.new')}</CardTitle>
      <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.gw.newIntro')}</p>
      <form
        noValidate
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (serverId && nameOk) m.mutate();
        }}
      >
        <Field label={t('p9.gw.server')} hint={t('p9.gw.serverHint')} error={fe.serverId}>
          {(p) => (
            <Select {...p} value={serverId} onChange={(e) => setServerId(e.target.value)}>
              <option value="">{t('p9.groups.pickServer')}</option>
              {candidates.map((s) => (
                <option key={s.id} value={s.id} disabled={!isLive(s)}>
                  {s.name} · {s.environment}
                  {!isLive(s) ? ` (${t(`status.${s.status}`)})` : ''}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field
          label={t('p9.gw.name')}
          hint={t('enroll.nameHint')}
          error={name && !nameOk ? t('p9.gw.err.name') : fe.name}
        >
          {(p) => (
            <Input
              {...p}
              value={name}
              maxLength={63}
              onChange={(e) => setName(e.target.value.toLowerCase())}
              className="font-mono"
              placeholder="edge-sgp1"
            />
          )}
        </Field>
        {m.error && Object.keys(fe).length === 0 && <ErrorState error={m.error} />}
        <div>
          <GatedButton
            type="submit"
            variant="primary"
            perm={P9_PERM.gateways}
            disabled={!serverId || !nameOk || m.isPending}
          >
            {m.isPending ? t('common.saving') : t('p9.gw.create')}
          </GatedButton>
        </div>
      </form>
    </Card>
  );
}

export function GatewaysView() {
  const { t } = useI18n();
  const q = useGateways();
  const forbidden = isApiError(q.error) && q.error.status === 403;
  return (
    <div className="flex flex-col gap-4">
      <Card className="flex flex-col gap-3 p-4" aria-labelledby="gw-modes-h">
        <CardTitle id="gw-modes-h">{t('p9.gw.modesTitle')}</CardTitle>
        <ModeLegend />
        <Notice tone="warn" glyph="▲" role="note">
          <span data-testid="never-dns">{t('p9.gw.neverDns')}</span>
        </Notice>
        <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.gw.survivesCenter')}</p>
      </Card>
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <section aria-labelledby="gw-list-h" className="flex flex-col gap-3">
          <h2 id="gw-list-h" className="m-0 text-[15px] font-semibold">
            {t('p9.gw.list', { n: q.data?.length ?? 0 })}
          </h2>
          {forbidden ? (
            <ForbiddenState
              perm="fleet.read"
              requestId={isApiError(q.error) ? q.error.requestId : null}
            />
          ) : q.isPending ? (
            <CardSkeletonGrid label={t('common.loading')} />
          ) : q.isError ? (
            <ErrorState error={q.error} onRetry={() => void q.refetch()} />
          ) : q.data.length === 0 ? (
            <EmptyState title={t('p9.gw.empty')} body={t('p9.gw.emptyBody')} />
          ) : (
            <ul className="m-0 grid list-none grid-cols-[repeat(auto-fill,minmax(min(100%,280px),1fr))] gap-3 p-0">
              {q.data.map((g) => (
                <li key={g.id}>
                  <article
                    aria-labelledby={`gw-${g.id}`}
                    data-testid="gateway-card"
                    className="flex h-full flex-col gap-2 rounded-lg border border-line bg-surface p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <h3
                        id={`gw-${g.id}`}
                        className="m-0 flex-1 font-mono text-[14px] font-medium"
                      >
                        <Link
                          href={`/network/gateways/${g.id}`}
                          className="text-fg no-underline hover:text-accent-text"
                        >
                          {g.name}
                        </Link>
                      </h3>
                      <ToneBadge tone={g.status === 'active' ? 'ok' : 'off'} size="sm">
                        {t(`p9.gw.status.${g.status}`)}
                      </ToneBadge>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                      <EnvBadge
                        env={g.environment}
                        label={t(envBadgeKey(g.environment))}
                        className="px-1.5 py-0 text-[10.5px]"
                      />
                      <Link href={`/servers/${g.serverId}/network`} className="font-mono">
                        {g.serverName}
                      </Link>
                    </div>
                    <dl className="m-0 grid grid-cols-[80px_minmax(0,1fr)] gap-x-2 gap-y-0.5 text-[12.5px]">
                      <dt className="text-fg-muted">{t('servers.col.private')}</dt>
                      <dd className="m-0 font-mono">
                        {g.addresses?.privateIpv4 ?? t('common.dash')}
                      </dd>
                      <dt className="text-fg-muted">{t('servers.col.public')}</dt>
                      <dd className="m-0 font-mono">
                        {g.addresses?.publicIpv4 ?? t('common.dash')}
                      </dd>
                      <dt className="text-fg-muted">{t('p9.gw.routes')}</dt>
                      <dd className="m-0" data-testid="gateway-route-count">
                        {g.routeCount}
                      </dd>
                    </dl>
                    <Link
                      href={`/network/gateways/${g.id}`}
                      className="mt-auto inline-flex min-h-8 items-center self-start rounded-[5px] bg-accent-strong px-3 text-[12.5px] text-on-accent no-underline hover:text-on-accent hover:no-underline hover:brightness-110"
                    >
                      {t('p9.gw.open')}
                    </Link>
                  </article>
                </li>
              ))}
            </ul>
          )}
        </section>
        <CreateGateway existing={q.data ?? []} />
      </div>
    </div>
  );
}
