'use client';

import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { CONNECTION_POLICIES, type ConnectionPolicy, type Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { address, connectionPath, isLive, providerLabel } from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import { qk } from '@/lib/queries';
import { useToast } from '@/components/providers/toast';
import { Card, DefList } from '@/components/ui/card';
import { OutlineTag, ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Segmented } from '@/components/ui/segmented';
import { ErrorState, Notice, ProposedBanner } from '@/components/ui/states';
import { usePatchServer } from './use-patch-server';
import type { MessageKey } from '@/i18n/en';

export function NetworkTab({ server, now }: { server: Server; now: number }) {
  const { t } = useI18n();
  const toast = useToast();
  const qc = useQueryClient();
  const [policy, setPolicy] = useState<ConnectionPolicy>(server.connectionPolicy);
  const patch = usePatchServer(server);
  useEffect(() => setPolicy(server.connectionPolicy), [server.connectionPolicy]);

  const priv = address(server, 'private');
  const pub = address(server, 'public');
  const verifiedLabel = (iso: string | null) => (iso ? t('net.verified', { ago: relativeTime(iso, t, now) }) : t('net.unverified'));

  // Effective management endpoint per the *saved* policy (preview of a draft would be misleading).
  const path = connectionPath(server);
  const usesPrivate = path.key === 'path.private' || path.key === 'path.privateStale' || path.key === 'path.privateOnlyUnreachable';
  const mgmt = usesPrivate ? priv : path.key === 'path.blocked' ? undefined : (pub ?? priv);
  const dirty = policy !== server.connectionPolicy;
  const conflict = patch.error?.status === 409;

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md bg-chip-2 px-3 py-2.5 text-[13px]">{t('net.note')}</div>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] items-start gap-4">
        <Card className="p-4">
          <div className="mb-2.5 flex items-center">
            <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('net.addresses')}</h2>
          </div>
          {server.addresses.length === 0 ? (
            <p className="m-0 text-[13px] text-fg-muted">{t('common.noData')}</p>
          ) : (
            <ul className="m-0 flex list-none flex-col gap-2.5 p-0">
              {server.addresses.map((a) => (
                <li key={`${a.scope}-${a.family}-${a.address}`} className="flex flex-col gap-0.5 border-b border-line-subtle pb-2 last:border-0 last:pb-0">
                  <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-fg-muted">
                    <span className="min-w-[110px]">{t(`net.field.${a.scope}${a.family === 'ipv4' ? 'Ipv4' : 'Ipv6'}` as MessageKey)}</span>
                    <OutlineTag>{a.source === 'override' ? t('net.override') : t('net.detected')}</OutlineTag>
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
        <Card className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('net.endpoints')}</h2>
          <div className="flex flex-col gap-1 rounded-md border border-line px-3 py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <b className="flex-1 text-[13.5px]">{t('net.mgmt')}</b>
              {mgmt && <OutlineTag>{mgmt.source === 'override' ? t('net.override') : t('net.detected')}</OutlineTag>}
              <ToneBadge tone={path.tone} size="sm">
                {t(path.key)}
              </ToneBadge>
            </div>
            <span className="font-mono text-[13px]">{mgmt?.address ?? '—'}</span>
            <span className="text-[12px] text-fg-muted">
              {t(`policy.${server.connectionPolicy}`)} · {mgmt ? verifiedLabel(mgmt.verifiedAt) : t('net.unverified')}
            </span>
          </div>
          <div className="flex flex-col gap-1 rounded-md border border-dashed border-line-strong px-3 py-2.5">
            <b className="text-[13.5px]">{t('net.appEndpoint')}</b>
            <span className="text-[12px] text-fg-muted">{t('net.appEndpointProposed')}</span>
          </div>
        </Card>
      </div>

      <Card className="flex flex-col gap-3 p-4" aria-labelledby="policy-h">
        <h2 id="policy-h" className="m-0 text-[15px] font-semibold">
          {t('net.policy')}
        </h2>
        <Segmented<ConnectionPolicy>
          label={t('net.policy')}
          value={policy}
          onChange={setPolicy}
          size="md"
          className="self-start"
          options={CONNECTION_POLICIES.map((p) => ({ value: p, label: t(`policy.${p}`) }))}
        />
        <Notice tone={policy === 'private_only' ? 'warn' : policy === 'public_only' || policy === 'public_preferred' ? 'warn' : 'info'} glyph={policy === 'private_only' ? '▲' : '◆'} title={t(`policy.${policy}`)} role="status">
          <span className="text-fg-2">{t(`policy.explain.${policy}`)}</span>
          {policy === 'private_only' && !priv?.verifiedAt && <div className="mt-1 font-medium text-crit">{t('net.privateOnlyNoPrivate')}</div>}
        </Notice>
        <p className="m-0 text-[12px] text-fg-muted">{t('net.policyHelp')}</p>
        {conflict && (
          <Notice
            tone="crit"
            glyph="✕"
            role="alert"
            action={
              <Button
                size="sm"
                onClick={() => {
                  patch.reset();
                  void qc.invalidateQueries({ queryKey: qk.server(server.id) });
                }}
              >
                {t('common.reload')}
              </Button>
            }
          >
            {t('net.conflict')} <span className="font-mono text-[11.5px] text-fg-muted">{patch.error?.requestId}</span>
          </Notice>
        )}
        {patch.error && !conflict && <ErrorState error={patch.error} />}
        <div className="flex gap-2">
          <GatedButton
            variant="primary"
            perm="servers.operate"
            action="edit"
            allowedActions={server.allowedActions}
            disabled={!dirty || patch.isPending}
            onClick={() =>
              patch.mutate(
                { connectionPolicy: policy },
                { onSuccess: () => toast(t('net.saved'), 'ok') },
              )
            }
          >
            {patch.isPending ? t('common.saving') : t('net.save')}
          </GatedButton>
          {dirty && (
            <Button variant="ghost" onClick={() => setPolicy(server.connectionPolicy)}>
              {t('common.cancel')}
            </Button>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] items-start gap-4">
        <Card className="flex flex-col gap-2.5 p-4">
          <div className="flex items-center gap-2">
            <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('net.diag')}</h2>
            <ToneBadge tone="ok" glyph={false} size="sm" className="font-mono">
              read-only
            </ToneBadge>
          </div>
          <ProposedBanner />
          <GatedButton size="sm" className="self-start" perm="fleet.read" blockedReason={isLive(server) ? { key: 'perm.proposed' } : { key: 'perm.offline' }}>
            {t('net.runDiag')}
          </GatedButton>
        </Card>
        <Card className="flex flex-col gap-2.5 p-4">
          <div className="flex items-center gap-2">
            <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('net.do')}</h2>
            <OutlineTag>{t('net.readOnly')}</OutlineTag>
          </div>
          <DefList
            rows={[
              [t('net.field.provider'), providerLabel(server) ?? '—'],
              [t('net.field.region'), server.provider?.region ?? '—', { mono: true }],
              [t('net.field.droplet'), server.provider?.dropletId ?? '—', { mono: true }],
              [t('net.field.vpc'), server.provider?.vpcUuid ?? '—', { mono: true }],
            ]}
          />
        </Card>
      </div>
    </div>
  );
}
