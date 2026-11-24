'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { isApiError, type ApiError } from '@/lib/api/errors';
import { gatewaysApi } from '@/lib/api/p9-endpoints';
import {
  ROUTE_MODES,
  type Gateway,
  type GatewayChangePlan,
  type GatewayRoute,
  type RouteMode,
  type ServerView,
} from '@/lib/api/p9-types';
import {
  P9_PERM,
  backendAddressFor,
  routeBody,
  routeValid,
  validateRoute,
  vpcDisplay,
  type RouteDraft,
} from '@/lib/p9-gates';
import { p9k, useGateway, usePlans, useRoutes } from '@/lib/p9-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { ActionDialog, wrap } from '@/components/p3/action-dialog';
import { Sha } from '@/components/p3/bits';
import { useToast } from '@/components/providers/toast';
import { Card } from '@/components/ui/card';
import { EnvBadge, OutlineTag, ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { Segmented } from '@/components/ui/segmented';
import { Skeleton, TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ModeBadge, ModeLegend, PlanStatusBadge, modeExplainKey, modeKey } from './gateway-bits';
import { CardTitle, serverName } from './net-bits';

const emptyDraft = (): RouteDraft => ({
  domain: '',
  mode: 'hybrid',
  healthPath: '/',
  backends: [{ serverId: '', address: '', port: '80' }],
});

function draftOf(r: GatewayRoute): RouteDraft {
  return {
    domain: r.domain,
    mode: r.mode,
    healthPath: r.healthPath,
    backends: r.backends.map((b) => ({
      serverId: b.serverId,
      address: b.address,
      port: String(b.port),
    })),
  };
}

function RouteForm({
  gateway,
  route,
  routes,
  servers,
  onDone,
}: {
  gateway: Gateway;
  route?: GatewayRoute;
  routes: GatewayRoute[];
  servers: ServerView[];
  onDone: () => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const [d, setD] = useState<RouteDraft>(route ? draftOf(route) : emptyDraft());
  const [touched, setTouched] = useState(false);
  const errors = validateRoute(
    d,
    routes.filter((r) => r.id !== route?.id).map((r) => r.domain),
    !!route,
  );
  const gwServer = servers.find((s) => s.id === gateway.serverId);
  const gwVpc = gwServer ? vpcDisplay(gwServer) : null;
  const m = useMutation<GatewayRoute, ApiError>({
    mutationFn: wrap(() => {
      const body = routeBody(d);
      return route
        ? gatewaysApi.updateRoute(gateway.id, route, {
            mode: body.mode,
            backends: body.backends,
            healthPath: body.healthPath,
          })
        : gatewaysApi.createRoute(gateway.id, body);
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: p9k.routes(gateway.id) });
      void qc.invalidateQueries({ queryKey: p9k.gateways });
      toast(t(route ? 'p9.route.saved' : 'p9.route.created'), 'ok');
      onDone();
    },
  });
  const setBackend = (i: number, patch: Partial<RouteDraft['backends'][number]>) =>
    setD((x) => ({ ...x, backends: x.backends.map((b, j) => (j === i ? { ...b, ...patch } : b)) }));
  const err = (k?: MessageKey) => (touched && k ? t(k) : undefined);
  const fe = m.error?.fieldErrors ?? {};
  return (
    <form
      noValidate
      className="flex flex-col gap-3 rounded-md border border-line p-3"
      data-testid="route-form"
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        if (routeValid(errors)) m.mutate();
      }}
    >
      <h3 className="m-0 text-[14px] font-semibold">
        {route ? t('p9.route.editTitle', { domain: route.domain }) : t('p9.route.newTitle')}
      </h3>
      {!route && (
        <Field
          label={t('p9.route.domain')}
          hint={t('p9.route.domainHint')}
          error={err(errors.domain) ?? fe.domain}
        >
          {(p) => (
            <Input
              {...p}
              value={d.domain}
              onChange={(e) => setD({ ...d, domain: e.target.value })}
              className="font-mono"
              placeholder="shop.example.com"
            />
          )}
        </Field>
      )}
      <div className="flex flex-col gap-1">
        <span className="text-[12.5px] text-fg-3" id="route-mode-label">
          {t('p9.route.mode')}
        </span>
        <Segmented<RouteMode>
          label={t('p9.route.mode')}
          value={d.mode}
          onChange={(mode) => setD({ ...d, mode })}
          className="self-start"
          options={ROUTE_MODES.map((x) => ({ value: x, label: t(modeKey(x)) }))}
        />
        <span className="text-[12px] text-fg-2" role="status" data-testid="mode-explain">
          {t(modeExplainKey(d.mode))}
        </span>
      </div>
      <fieldset className="m-0 flex flex-col gap-2 border-0 p-0">
        <legend className="mb-1 text-[12.5px] text-fg-3">{t('p9.route.backends')}</legend>
        {d.backends.map((b, i) => {
          const s = servers.find((x) => x.id === b.serverId);
          const pref = s ? backendAddressFor(s) : null;
          const bVpc = s ? vpcDisplay(s) : null;
          const crossVpc =
            !!gwVpc?.known &&
            !!bVpc?.known &&
            gwVpc.uuid !== bVpc.uuid &&
            (!b.address || b.address === s?.privateIpv4);
          const rowErr = touched ? errors.backendRows?.[i] : undefined;
          return (
            <div
              key={i}
              className="flex flex-col gap-1 rounded bg-chip px-2 py-2"
              data-testid="backend-row"
            >
              <div className="flex flex-wrap items-end gap-2">
                <Field label={t('p9.route.backendServer')} className="min-w-[160px] flex-1">
                  {(p) => (
                    <Select
                      {...p}
                      value={b.serverId}
                      onChange={(e) => setBackend(i, { serverId: e.target.value, address: '' })}
                    >
                      <option value="">{t('p9.groups.pickServer')}</option>
                      {servers.map((x) => (
                        <option key={x.id} value={x.id}>
                          {x.name}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                <Field label={t('p9.route.address')} className="w-[150px]">
                  {(p) => (
                    <Input
                      {...p}
                      value={b.address}
                      onChange={(e) => setBackend(i, { address: e.target.value })}
                      placeholder={pref?.address ?? '10.0.0.10'}
                      className="font-mono text-[13px]"
                    />
                  )}
                </Field>
                <Field label={t('p9.route.port')} className="w-[90px]">
                  {(p) => (
                    <Input
                      {...p}
                      value={b.port}
                      inputMode="numeric"
                      onChange={(e) =>
                        setBackend(i, { port: e.target.value.replace(/\D/g, '').slice(0, 5) })
                      }
                      className="font-mono text-[13px]"
                    />
                  )}
                </Field>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={t('p9.route.removeBackend', { n: i + 1 })}
                  disabled={d.backends.length === 1}
                  onClick={() =>
                    setD((x) => ({ ...x, backends: x.backends.filter((_, j) => j !== i) }))
                  }
                >
                  ✕
                </Button>
              </div>
              {pref && !b.address && (
                <span className="text-[11.5px] text-fg-muted">
                  {t(
                    pref.scope === 'private' ? 'p9.route.defaultPrivate' : 'p9.route.defaultPublic',
                    { ip: pref.address },
                  )}
                </span>
              )}
              {crossVpc && (
                <span
                  className="text-[11.5px] text-warn"
                  role="status"
                  data-testid="cross-vpc-warning"
                >
                  ▲ {t('p9.route.crossVpc')}
                </span>
              )}
              {rowErr && (
                <span role="alert" className="text-[12px] text-crit">
                  {t(rowErr)}
                </span>
              )}
            </div>
          );
        })}
        {touched && errors.backends && (
          <span role="alert" className="text-[12px] text-crit">
            {t(errors.backends)}
          </span>
        )}
        <Button
          size="sm"
          className="self-start"
          disabled={d.backends.length >= 10}
          onClick={() =>
            setD((x) => ({
              ...x,
              backends: [...x.backends, { serverId: '', address: '', port: '80' }],
            }))
          }
        >
          {t('p9.route.addBackend')}
        </Button>
      </fieldset>
      <Field
        label={t('p9.route.healthPath')}
        hint={t('p9.route.healthHint')}
        error={err(errors.healthPath) ?? fe.healthPath}
      >
        {(p) => (
          <Input
            {...p}
            value={d.healthPath}
            onChange={(e) => setD({ ...d, healthPath: e.target.value })}
            className="w-[240px] font-mono"
          />
        )}
      </Field>
      <p className="m-0 text-[12px] text-fg-muted">{t('p9.route.noApplyYet')}</p>
      {m.error && Object.keys(fe).length === 0 && <ErrorState error={m.error} />}
      <div className="flex gap-2">
        <GatedButton type="submit" variant="primary" perm={P9_PERM.gateways} disabled={m.isPending}>
          {m.isPending ? t('common.saving') : t(route ? 'common.save' : 'p9.route.create')}
        </GatedButton>
        <Button variant="ghost" onClick={onDone}>
          {t('common.cancel')}
        </Button>
      </div>
    </form>
  );
}

function RoutesCard({ gateway, servers }: { gateway: Gateway; servers: ServerView[] }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const q = useRoutes(gateway.id);
  const [form, setForm] = useState<'new' | string | null>(null);
  const [del, setDel] = useState<GatewayRoute | null>(null);
  const routes = q.data ?? [];
  return (
    <Card className="flex flex-col gap-3 p-4" aria-labelledby="routes-h" data-testid="routes">
      <CardTitle
        id="routes-h"
        actions={
          <GatedButton
            size="sm"
            perm={P9_PERM.gateways}
            onClick={() => setForm('new')}
            aria-expanded={form === 'new'}
            data-testid="add-route"
          >
            {t('p9.route.add')}
          </GatedButton>
        }
      >
        {t('p9.route.title', { n: routes.length })}
      </CardTitle>
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {form === 'new' && (
        <RouteForm
          gateway={gateway}
          routes={routes}
          servers={servers}
          onDone={() => setForm(null)}
        />
      )}
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : routes.length === 0 ? (
        <EmptyState title={t('p9.route.empty')} body={t('p9.route.emptyBody')} />
      ) : (
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          {routes.map((r) => (
            <li
              key={r.id}
              className="flex flex-col gap-1.5 rounded-md border border-line px-3 py-2"
              data-testid="route-row"
              data-domain={r.domain}
            >
              <div className="flex flex-wrap items-center gap-2">
                <b className="min-w-[160px] flex-1 font-mono text-[13.5px]">{r.domain}</b>
                <ModeBadge mode={r.mode} />
                <OutlineTag>{r.healthPath}</OutlineTag>
                <GatedButton
                  size="sm"
                  variant="ghost"
                  perm={P9_PERM.gateways}
                  onClick={() => setForm(r.id)}
                  aria-label={t('p9.route.editAria', { domain: r.domain })}
                >
                  {t('p9.groups.edit')}
                </GatedButton>
                <GatedButton
                  size="sm"
                  variant="ghost"
                  className="text-crit"
                  perm={P9_PERM.gateways}
                  onClick={() => setDel(r)}
                  aria-label={t('p9.route.deleteAria', { domain: r.domain })}
                >
                  {t('p9.groups.delete')}
                </GatedButton>
              </div>
              <span className="text-[12px] text-fg-muted">{t(modeExplainKey(r.mode))}</span>
              <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0 text-[12px]">
                {r.backends.map((b) => {
                  const s = servers.find((x) => x.id === b.serverId);
                  const isPrivate = !!s && s.privateIpv4 === b.address;
                  return (
                    <li
                      key={`${b.serverId}-${b.port}`}
                      className="rounded bg-chip px-1.5 font-mono"
                    >
                      {serverName(servers, b.serverId)} · {b.address}:{b.port}{' '}
                      <span className={isPrivate ? 'text-ok' : 'text-warn'}>
                        {isPrivate ? t('p9.route.viaPrivate') : t('p9.route.viaPublic')}
                      </span>
                    </li>
                  );
                })}
              </ul>
              {form === r.id && (
                <RouteForm
                  gateway={gateway}
                  route={r}
                  routes={routes}
                  servers={servers}
                  onDone={() => setForm(null)}
                />
              )}
            </li>
          ))}
        </ul>
      )}
      <ActionDialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={t('p9.route.deleteTitle', { domain: del?.domain ?? '' })}
        body={t('p9.route.deleteBody')}
        confirmLabel={t('p9.groups.delete')}
        danger
        needsStepUp={false}
        onConfirm={async () => {
          if (!del) return;
          await gatewaysApi.removeRoute(gateway.id, del.id);
          void qc.invalidateQueries({ queryKey: p9k.routes(gateway.id) });
          void qc.invalidateQueries({ queryKey: p9k.gateways });
        }}
      />
    </Card>
  );
}

function PlansCard({ gateway }: { gateway: Gateway }) {
  const { t, locale } = useI18n();
  const router = useRouter();
  const qc = useQueryClient();
  const now = useNow(10_000);
  const plans = usePlans(gateway.id);
  const routes = useRoutes(gateway.id);
  const servable = (routes.data ?? []).some((r) => r.mode !== 'direct');
  const m = useMutation<GatewayChangePlan, ApiError>({
    mutationFn: wrap(() => gatewaysApi.createPlan(gateway.id)),
    onSuccess: (p) => {
      void qc.invalidateQueries({ queryKey: p9k.plans(gateway.id) });
      router.push(`/network/gateways/${gateway.id}/plans/${p.id}`);
    },
  });
  const label = (p: GatewayChangePlan) =>
    (p as GatewayChangePlan & { createdByLabel?: string | null }).createdByLabel ??
    p.createdBy.slice(0, 8);
  return (
    <Card className="flex flex-col gap-3 p-4" aria-labelledby="plans-h" data-testid="plans">
      <CardTitle
        id="plans-h"
        actions={
          <GatedButton
            variant="primary"
            size="sm"
            perm={P9_PERM.gateways}
            blockedReason={servable ? undefined : { key: 'p9.plan.gate.noRoutes' }}
            disabled={m.isPending}
            onClick={() => m.mutate()}
            data-testid="create-plan"
          >
            {m.isPending ? t('common.saving') : t('p9.plan.create')}
          </GatedButton>
        }
      >
        {t('p9.plan.title')}
      </CardTitle>
      <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.plan.intro')}</p>
      {m.error && <ErrorState error={m.error} />}
      {plans.isError && <ErrorState error={plans.error} onRetry={() => void plans.refetch()} />}
      {(plans.data ?? []).length === 0 ? (
        <p className="m-0 text-[13px] text-fg-muted">{t('p9.plan.none')}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
          {plans.data!.map((p) => (
            <li key={p.id}>
              <Link
                href={`/network/gateways/${gateway.id}/plans/${p.id}`}
                className="flex flex-wrap items-center gap-2 rounded-md border border-line px-3 py-2 text-[12.5px] text-fg no-underline hover:bg-surface-hover hover:no-underline"
                data-testid="plan-row"
              >
                <PlanStatusBadge status={p.status} />
                <Sha value={p.planHash} />
                <span className="flex-1 text-fg-muted">
                  {t('p9.plan.byWhen', { who: label(p), ago: relativeTime(p.createdAt, t, now) })}
                </span>
                <span className="text-fg-muted" title={formatDateTime(p.createdAt, locale)}>
                  {t('p9.plan.domains', {
                    n: p.routesSnapshot.filter((r) => r.mode !== 'direct').length,
                  })}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function GatewayDetail({ id }: { id: string }) {
  const { t } = useI18n();
  const router = useRouter();
  const q = useGateway(id);
  const servers = useServers();
  const [delOpen, setDelOpen] = useState(false);
  const qc = useQueryClient();
  const g = q.data;
  const all = servers.data?.items ?? [];
  return (
    <div className="flex flex-col gap-4">
      <Link href="/network/gateways" className="self-start text-[13px]">
        {t('p9.gw.back')}
      </Link>
      {q.isPending ? (
        <Skeleton className="h-24 w-full" />
      ) : q.isError ? (
        isApiError(q.error) && q.error.status === 404 ? (
          <EmptyState title={t('p9.gw.notFound')} />
        ) : isApiError(q.error) && q.error.status === 403 ? (
          <ForbiddenState perm="fleet.read" requestId={q.error.requestId} />
        ) : (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        )
      ) : (
        g && (
          <>
            <div className="flex flex-wrap items-start gap-3">
              <div className="flex min-w-[240px] flex-1 flex-col gap-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="m-0 font-mono text-[19px] font-semibold">{g.name}</h2>
                  <EnvBadge env={g.environment} label={t(envBadgeKey(g.environment))} />
                  <ToneBadge tone={g.status === 'active' ? 'ok' : 'off'} size="sm">
                    {t(`p9.gw.status.${g.status}`)}
                  </ToneBadge>
                </div>
                <span className="text-[13px] text-fg-muted">
                  {t('p9.gw.on')}{' '}
                  <Link href={`/servers/${g.serverId}/network`} className="font-mono">
                    {g.serverName}
                  </Link>{' '}
                  · {t('servers.col.private')}{' '}
                  <span className="font-mono">{g.addresses?.privateIpv4 ?? '—'}</span> ·{' '}
                  {t('servers.col.public')}{' '}
                  <span className="font-mono">{g.addresses?.publicIpv4 ?? '—'}</span>
                </span>
              </div>
              <GatedButton
                variant="secondary"
                className="border-crit text-crit"
                perm={P9_PERM.gateways}
                onClick={() => setDelOpen(true)}
              >
                {t('p9.gw.delete')}
              </GatedButton>
            </div>
            {g.environment === 'production' && (
              <Notice tone="warn" glyph="▲" role="note">
                {t('p9.gw.prodNote')}
              </Notice>
            )}
            <details className="rounded-lg border border-line bg-surface px-4 py-3">
              <summary className="cursor-pointer text-[13.5px] font-medium">
                {t('p9.gw.modesTitle')}
              </summary>
              <ModeLegend className="mt-3" />
            </details>
            <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
              <RoutesCard gateway={g} servers={all} />
              <PlansCard gateway={g} />
            </div>
            <ActionDialog
              open={delOpen}
              onOpenChange={setDelOpen}
              title={t('p9.gw.deleteTitle', { name: g.name })}
              body={t('p9.gw.deleteBody')}
              confirmLabel={t('p9.gw.delete')}
              danger
              needsStepUp={false}
              onConfirm={async () => {
                await gatewaysApi.remove(g.id);
                void qc.invalidateQueries({ queryKey: p9k.gateways });
                router.push('/network/gateways');
              }}
            />
          </>
        )
      )}
    </div>
  );
}
