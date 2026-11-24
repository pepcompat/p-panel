'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { CONNECTION_POLICIES, type ConnectionPolicy, type Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { authApi } from '@/lib/api/endpoints';
import type { ApiError } from '@/lib/api/errors';
import { serverNetApi } from '@/lib/api/p9-endpoints';
import { useAuth } from '@/lib/auth/auth-provider';
import {
  P9_PERM,
  pathHealth,
  pathState,
  policyChangeCheck,
  probeFor,
  regionOf,
  vpcDisplay,
} from '@/lib/p9-gates';
import { useDiagnostics } from '@/lib/p9-queries';
import { qk } from '@/lib/queries';
import { providerLabel } from '@/lib/servers';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useToast } from '@/components/providers/toast';
import { wrap } from '@/components/p3/action-dialog';
import { StepUpField } from '@/components/p3/bits';
import { Card, DefList } from '@/components/ui/card';
import { OutlineTag, ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Segmented } from '@/components/ui/segmented';
import { ErrorState, Notice } from '@/components/ui/states';
import { DiagnosticsPanel, MiniTable, OkCell } from '@/components/p9/diagnostics';
import {
  CardTitle,
  PATH_ORDER,
  SourceTag,
  VpcLabel,
  pathKey,
  policyKey,
} from '@/components/p9/net-bits';

function AddressesCard({ server, now }: { server: Server; now: number }) {
  const { t } = useI18n();
  const verifiedLabel = (iso: string | null) =>
    iso ? t('net.verified', { ago: relativeTime(iso, t, now) }) : t('net.unverified');
  return (
    <Card className="p-4">
      <CardTitle>{t('net.addresses')}</CardTitle>
      <dl className="mt-2.5 mb-3 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[13px]">
        <dt className="text-fg-muted">{t('p9.addr.preferredPublic')}</dt>
        <dd className="m-0 font-mono">{server.publicIpv4 ?? t('common.dash')}</dd>
        <dt className="text-fg-muted">{t('p9.addr.preferredPrivate')}</dt>
        <dd className="m-0 font-mono">{server.privateIpv4 ?? t('common.dash')}</dd>
      </dl>
      {server.addresses.length === 0 ? (
        <p className="m-0 text-[13px] text-fg-muted">{t('common.noData')}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-2.5 p-0">
          {server.addresses.map((a) => (
            <li
              key={`${a.scope}-${a.family}-${a.address}`}
              className="flex flex-col gap-0.5 border-b border-line-subtle pb-2 last:border-0 last:pb-0"
            >
              <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-fg-muted">
                <span className="min-w-[110px]">
                  {t(`net.field.${a.scope}${a.family === 'ipv4' ? 'Ipv4' : 'Ipv6'}` as MessageKey)}
                </span>
                <OutlineTag>
                  {a.source === 'override' ? t('net.override') : t('net.detected')}
                </OutlineTag>
                {a.interface && <OutlineTag>{a.interface}</OutlineTag>}
                <ToneBadge tone={a.verifiedAt ? 'ok' : 'warn'} size="sm">
                  {verifiedLabel(a.verifiedAt)}
                </ToneBadge>
              </div>
              <span className="font-mono text-[13px] break-all">{a.address}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function PathsCard({ server, now }: { server: Server; now: number }) {
  const { t } = useI18n();
  const st = pathState(server);
  const c = server.connection;
  return (
    <Card className="flex flex-col gap-3 p-4" data-testid="mgmt-paths">
      <CardTitle>{t('p9.paths.title')}</CardTitle>
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <span className="text-fg-muted">{t('net.policy')}:</span>
        <OutlineTag>{t(policyKey(server.connectionPolicy))}</OutlineTag>
        {st && (
          <ToneBadge tone={st.tone} size="sm">
            <span data-testid="active-path" data-path={st.activePath ?? 'none'}>
              {t(st.key)}
            </span>
          </ToneBadge>
        )}
      </div>
      {st?.failClosed && (
        <Notice tone="crit" glyph="✕" role="alert" title={t('p9.failClosed.title')}>
          <span data-testid="fail-closed">{t('p9.failClosed.body')}</span>
        </Notice>
      )}
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {PATH_ORDER.map((path) => {
          const p = probeFor(server, path);
          const h = pathHealth(p);
          const active = c?.activePath === path;
          const forbidden =
            (server.connectionPolicy === 'private_only' && path === 'public') ||
            (server.connectionPolicy === 'public_only' && path === 'private');
          return (
            <li
              key={path}
              data-testid={`probe-${path}`}
              data-health={h}
              className="flex flex-col gap-0.5 rounded-md border border-line px-3 py-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <b className="flex-1 text-[13.5px]">{t(pathKey(path))}</b>
                {active && <OutlineTag>{t('p9.path.active')}</OutlineTag>}
                {forbidden && <OutlineTag>{t('p9.path.notAllowed')}</OutlineTag>}
                <ToneBadge tone={h === 'ok' ? 'ok' : h === 'down' ? 'crit' : 'off'} size="sm">
                  {t(`p9.health.${h}` as MessageKey)}
                </ToneBadge>
              </div>
              <span className="text-[12px] text-fg-muted">
                {[
                  p?.latencyMs != null ? `${p.latencyMs} ms` : null,
                  p?.error ?? null,
                  p?.checkedAt
                    ? t('p9.probe.checked', { ago: relativeTime(p.checkedAt, t, now) })
                    : t('p9.probe.never'),
                ]
                  .filter(Boolean)
                  .join(' · ')}
              </span>
            </li>
          );
        })}
      </ul>
      <p className="m-0 text-[12px] text-fg-muted">
        {c?.reportedAt
          ? t('p9.probe.reported', { ago: relativeTime(c.reportedAt, t, now) })
          : t('p9.probe.noReport')}
      </p>
    </Card>
  );
}

function PolicyEditor({ server, now }: { server: Server; now: number }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [policy, setPolicy] = useState<ConnectionPolicy>(server.connectionPolicy);
  const [otp, setOtp] = useState('');
  useEffect(() => setPolicy(server.connectionPolicy), [server.connectionPolicy]);
  const check = policyChangeCheck(server, policy, now);
  const dirty = policy !== server.connectionPolicy;
  const m = useMutation<Server, ApiError>({
    mutationFn: wrap(async () => {
      const token = check.needsStepUp ? (await authApi.stepUp(otp)).stepUpToken : undefined;
      return serverNetApi.setPolicy(server.id, policy, server.version, token);
    }),
    onSuccess: (updated) => {
      setOtp('');
      qc.setQueryData(qk.server(server.id), updated);
      void qc.invalidateQueries({ queryKey: qk.servers, exact: true });
      toast(t('net.saved'), 'ok');
    },
  });
  const e = m.error;
  const unverified = e?.code === 'PRIVATE_PATH_UNVERIFIED';
  const conflict = e?.status === 409;
  const lastProbe = (
    e?.details as { lastPrivateProbe?: { checkedAt?: string; error?: string } } | undefined
  )?.lastPrivateProbe;
  const ready =
    dirty && !m.isPending && (!check.needsStepUp || (!!me?.mfaEnabled && /^\d{6}$/.test(otp)));
  return (
    <Card
      className="flex flex-col gap-3 p-4"
      aria-labelledby="policy-h"
      data-testid="policy-editor"
    >
      <CardTitle id="policy-h">{t('net.policy')}</CardTitle>
      <Segmented<ConnectionPolicy>
        label={t('net.policy')}
        value={policy}
        onChange={(v) => {
          setPolicy(v);
          m.reset();
        }}
        size="md"
        className="self-start"
        options={CONNECTION_POLICIES.map((p) => ({ value: p, label: t(policyKey(p)) }))}
      />
      <Notice
        tone={
          policy === 'private_only' || policy === 'public_only' || policy === 'public_preferred'
            ? 'warn'
            : 'info'
        }
        glyph={policy === 'private_only' ? '▲' : '◆'}
        title={t(policyKey(policy))}
        role="status"
      >
        <span className="text-fg-2">{t(`policy.explain.${policy}` as MessageKey)}</span>
      </Notice>
      {check.failClosedWarning && (
        <Notice tone="crit" glyph="✕" role="note" title={t('p9.failClosed.title')}>
          <span data-testid="fail-closed-explain">{t('p9.policy.failClosedExplain')}</span>
        </Notice>
      )}
      {dirty && check.privateUnverified && !unverified && (
        <Notice tone="warn" glyph="▲" role="status">
          {t('p9.policy.predictUnverified')}
        </Notice>
      )}
      {dirty && check.publicWarning && (
        <Notice tone="warn" glyph="▲" role="status">
          {t('p9.policy.publicWarning')}
        </Notice>
      )}
      <p className="m-0 text-[12px] text-fg-muted">{t('net.policyHelp')}</p>
      {dirty && check.needsStepUp && (
        <div className="max-w-[320px]">
          <StepUpField value={otp} onChange={setOtp} hint={t('p9.policy.stepUpHint')} />
        </div>
      )}
      {unverified && (
        <Notice tone="crit" glyph="✕" role="alert" title={t('p9.err.privateUnverified.title')}>
          <span data-testid="private-unverified-error">{t('p9.err.privateUnverified.body')}</span>
          {lastProbe && (
            <span className="mt-1 block text-[12px] text-fg-muted">
              {t('p9.err.privateUnverified.last', {
                when: lastProbe.checkedAt
                  ? relativeTime(lastProbe.checkedAt, t, now)
                  : t('time.never'),
                error: lastProbe.error ?? t('common.dash'),
              })}
            </span>
          )}
          <span className="mt-1 block font-mono text-[11.5px] text-fg-muted">
            {e?.code} · {t('common.requestId')}: {e?.requestId}
          </span>
        </Notice>
      )}
      {conflict && (
        <Notice
          tone="crit"
          glyph="✕"
          role="alert"
          action={
            <Button
              size="sm"
              onClick={() => {
                m.reset();
                void qc.invalidateQueries({ queryKey: qk.server(server.id) });
              }}
            >
              {t('common.reload')}
            </Button>
          }
        >
          {t('net.conflict')}{' '}
          <span className="font-mono text-[11.5px] text-fg-muted">{e?.requestId}</span>
        </Notice>
      )}
      {e && !unverified && !conflict && <ErrorState error={e} />}
      <div className="flex gap-2">
        <GatedButton
          variant="primary"
          perm={P9_PERM.serversManage}
          action="edit"
          allowedActions={server.allowedActions}
          disabled={!ready}
          onClick={() => m.mutate()}
          data-testid="save-policy"
        >
          {m.isPending ? t('common.saving') : t('net.save')}
        </GatedButton>
        {dirty && (
          <Button
            variant="ghost"
            onClick={() => {
              setPolicy(server.connectionPolicy);
              m.reset();
            }}
          >
            {t('common.cancel')}
          </Button>
        )}
      </div>
    </Card>
  );
}

function RegionCard({ server }: { server: Server }) {
  const { t } = useI18n();
  const v = vpcDisplay(server);
  return (
    <Card className="flex flex-col gap-2.5 p-4" data-testid="region-card">
      <CardTitle actions={<OutlineTag>{t('net.readOnly')}</OutlineTag>}>
        {t('p9.region.title')}
      </CardTitle>
      <DefList
        keyWidth={130}
        rows={[
          [t('net.field.region'), regionOf(server) ?? t('common.unknown'), { mono: true }],
          [t('p9.card.vpc'), <VpcLabel key="v" server={server} full />],
          ...(v.known
            ? ([[t('net.field.vpc'), v.uuid, { mono: true }]] as Array<
                [string, string, { mono: boolean }]
              >)
            : []),
          [t('net.field.provider'), providerLabel(server) ?? t('common.dash')],
          [t('net.field.droplet'), server.provider?.dropletId ?? t('common.dash'), { mono: true }],
        ]}
      />
      <p className="m-0 text-[12px] text-fg-muted">
        {v.known ? t('p9.region.knownFrom', { source: t(v.key) }) : t('p9.vpc.unknownWhy')}
      </p>
      <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-fg-muted">
        {t('p9.region.sources')}: <SourceTag source="provider" /> <SourceTag source="inventory" />{' '}
        <SourceTag source="agent" />
      </div>
    </Card>
  );
}

/** Path health over time from the agent's probe report (now) and past diagnostics runs. */
function HealthHistory({ server, now }: { server: Server; now: number }) {
  const { t, locale } = useI18n();
  const list = useDiagnostics(server.id);
  const rows = useMemo(() => {
    const out: Array<{
      at: string;
      source: MessageKey;
      priv?: { ok: boolean; error?: string };
      pub?: { ok: boolean; error?: string };
    }> = [];
    if (server.connection?.reportedAt) {
      const pr = probeFor(server, 'private');
      const pu = probeFor(server, 'public');
      out.push({
        at: server.connection.reportedAt,
        source: 'p9.history.heartbeat',
        priv: pr,
        pub: pu,
      });
    }
    for (const x of list.data ?? []) {
      const ce = x.result?.centerEndpoints;
      if (!ce || !x.finishedAt) continue;
      out.push({
        at: x.finishedAt,
        source: 'p9.history.diagnostics',
        priv: ce.find((e) => e.path === 'private'),
        pub: ce.find((e) => e.path === 'public'),
      });
    }
    return out;
  }, [server, list.data]);
  const cell = (p?: { ok: boolean; error?: string }) =>
    p ? (
      <OkCell ok={p.ok} error={p.error} />
    ) : (
      <span className="text-fg-subtle">{t('common.dash')}</span>
    );
  return (
    <Card className="flex flex-col gap-2.5 p-4" data-testid="health-history">
      <CardTitle>{t('p9.history.title')}</CardTitle>
      <MiniTable
        caption={t('p9.history.caption')}
        head={[
          t('p9.col.when'),
          t('p9.col.source'),
          t('p9.pathName.private'),
          t('p9.pathName.public'),
        ]}
        empty={t('p9.history.empty')}
        rows={rows.map((r) => [
          <span key="w" title={formatDateTime(r.at, locale)}>
            {relativeTime(r.at, t, now)}
          </span>,
          t(r.source),
          cell(r.priv),
          cell(r.pub),
        ])}
      />
      <p className="m-0 text-[12px] text-fg-muted">{t('p9.history.note')}</p>
    </Card>
  );
}

export function NetworkTab({ server, now }: { server: Server; now: number }) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md bg-chip-2 px-3 py-2.5 text-[13px]">{t('net.note')}</div>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] items-start gap-4">
        <AddressesCard server={server} now={now} />
        <PathsCard server={server} now={now} />
      </div>
      <PolicyEditor server={server} now={now} />
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] items-start gap-4">
        <RegionCard server={server} />
        <HealthHistory server={server} now={now} />
      </div>
      <DiagnosticsPanel server={server} now={now} />
    </div>
  );
}
