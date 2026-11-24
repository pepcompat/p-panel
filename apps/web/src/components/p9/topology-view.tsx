'use client';

import Link from 'next/link';
import { useI18n } from '@/i18n/provider';
import { isApiError } from '@/lib/api/errors';
import type { ServerView, Topology } from '@/lib/api/p9-types';
import { findingKey, findingWhatKey } from '@/lib/p9-gates';
import { useGateways, useIntegrations, useTopology } from '@/lib/p9-queries';
import { useServers } from '@/lib/queries';
import { relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { Card } from '@/components/ui/card';
import { OutlineTag, STATUS_TONE, TONE_GLYPH, toneText } from '@/components/ui/badge';
import { CardSkeletonGrid } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { cn } from '@/lib/utils';
import { CardTitle, ConnectionSummary, FindingBadge, SourceTag } from './net-bits';

function ServerRow({ s, now }: { s: ServerView | undefined; id: string; now: number }) {
  const { t } = useI18n();
  if (!s) return null;
  const tone = STATUS_TONE[s.status];
  return (
    <li className="flex flex-wrap items-center gap-2 border-t border-line-subtle pt-1.5 text-[12.5px]">
      <span className={toneText[tone]} aria-hidden="true">
        {TONE_GLYPH[tone]}
      </span>
      <span className="sr-only">{t(`status.${s.status}`)}</span>
      <Link href={`/servers/${s.id}/network`} className="min-w-[110px] flex-1 font-mono">
        {s.name}
      </Link>
      <ConnectionSummary server={s} now={now} showPolicy={false} />
    </li>
  );
}

function RegionBlock({
  region,
  byId,
  now,
}: {
  region: Topology['regions'][number];
  byId: Map<string, ServerView>;
  now: number;
}) {
  const { t } = useI18n();
  return (
    <section
      aria-labelledby={`region-${region.region ?? 'unknown'}`}
      className="flex flex-col gap-2.5"
      data-testid="topology-region"
      data-region={region.region ?? 'unknown'}
    >
      <h3
        id={`region-${region.region ?? 'unknown'}`}
        className="m-0 flex items-center gap-2 text-[14px] font-semibold"
      >
        <span className="font-mono">{region.region ?? t('p9.topo.regionUnknown')}</span>
        <span className="text-[12px] font-normal text-fg-muted">
          {t('p9.topo.regionSummary', {
            vpcs: region.vpcs.length,
            unknown: region.unknownVpc.length,
          })}
        </span>
      </h3>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,280px),1fr))] gap-3">
        {region.vpcs.map((v) => (
          <div
            key={v.vpcUuid}
            data-testid="topology-vpc"
            data-vpc={v.vpcName ?? v.vpcUuid}
            className="flex flex-col gap-1.5 rounded-lg border border-line-strong p-3"
          >
            <div className="flex flex-wrap items-center gap-2">
              <b className="flex-1 font-mono text-[13px]">{v.vpcName ?? t('p9.topo.unnamedVpc')}</b>
              <SourceTag source={v.source} />
            </div>
            <span className="font-mono text-[11px] text-fg-muted" title={v.vpcUuid}>
              {v.vpcUuid}
            </span>
            <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
              {v.servers.map((id) => (
                <ServerRow key={id} id={id} s={byId.get(id)} now={now} />
              ))}
            </ul>
          </div>
        ))}
        {region.unknownVpc.length > 0 && (
          <div
            data-testid="topology-vpc"
            data-vpc="unknown"
            className="flex flex-col gap-1.5 rounded-lg border border-dashed border-line-strong p-3"
          >
            <div className="flex flex-wrap items-center gap-2">
              <b className="flex-1 text-[13px]">{t('p9.vpc.unknown')}</b>
              <SourceTag source={null} />
            </div>
            <span className="text-[11.5px] text-fg-muted">{t('p9.vpc.unknownWhy')}</span>
            <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
              {region.unknownVpc.map((id) => (
                <ServerRow key={id} id={id} s={byId.get(id)} now={now} />
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

export function TopologyView() {
  const { t } = useI18n();
  const now = useNow(10_000);
  const q = useTopology();
  const servers = useServers();
  const gateways = useGateways();
  const integrations = useIntegrations();
  const byId = new Map((servers.data?.items ?? []).map((s) => [s.id, s]));
  const forbidden = isApiError(q.error) && q.error.status === 403;
  const lastSync = (integrations.data ?? [])
    .map((i) => i.lastSyncAt)
    .filter((x): x is string => !!x)
    .sort()
    .pop();

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,220px),1fr))] gap-3">
        {[
          [t('p9.topo.ingress'), t('p9.topo.ingressBody'), 'border-dashed border-line-strong'],
          [t('p9.topo.center'), t('p9.topo.centerBody'), 'border-line-strong bg-surface-2'],
          [
            t('p9.topo.gateways'),
            t('p9.topo.gatewaysBody', { n: gateways.data?.length ?? 0 }),
            'border-line-strong',
          ],
        ].map(([a, b, cls]) => (
          <div key={a} className={cn('flex flex-col gap-1 rounded-lg border p-3 text-[13px]', cls)}>
            <b>{a}</b>
            <span className="text-[12px] text-fg-muted">{b}</span>
          </div>
        ))}
      </div>
      <Notice tone="info" glyph="◆" role="note">
        {t('p9.topo.rule')}{' '}
        <span className="text-fg-muted">
          {lastSync
            ? t('p9.topo.lastSync', { ago: relativeTime(lastSync, t, now) })
            : t('p9.topo.noSync')}{' '}
          <Link href="/network/providers">{t('p9.nav.providers')} →</Link>
        </span>
      </Notice>

      {forbidden ? (
        <ForbiddenState
          perm="fleet.read"
          requestId={isApiError(q.error) ? q.error.requestId : null}
        />
      ) : q.isPending ? (
        <CardSkeletonGrid label={t('common.loading')} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <>
          <Card
            className="flex flex-col gap-3 p-4"
            aria-labelledby="findings-h"
            data-testid="findings"
          >
            <CardTitle id="findings-h">
              {t('p9.topo.findings', { n: q.data.findings.length })}
            </CardTitle>
            {q.data.findings.length === 0 ? (
              <p className="m-0 text-[13px] text-fg-muted">{t('p9.topo.noFindings')}</p>
            ) : (
              <ul className="m-0 flex list-none flex-col gap-2 p-0">
                {q.data.findings.map((f, i) => (
                  <li
                    key={`${f.code}-${i}`}
                    data-testid="finding"
                    data-code={f.code}
                    className="flex flex-col gap-1 rounded-md border border-line px-3 py-2"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <FindingBadge code={f.code} />
                      <b className="text-[13px]">{t(findingKey(f.code))}</b>
                    </div>
                    <span className="text-[12.5px] text-fg-2">{f.message}</span>
                    <span className="text-[12px] text-fg-muted">{t(findingWhatKey(f.code))}</span>
                    {f.serverIds.length > 0 && (
                      <span className="flex flex-wrap gap-1">
                        {f.serverIds.map((id) => (
                          <Link
                            key={id}
                            href={`/servers/${id}/network`}
                            className="rounded bg-chip px-1.5 font-mono text-[11.5px] no-underline"
                          >
                            {byId.get(id)?.name ?? id.slice(0, 8)}
                          </Link>
                        ))}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card className="flex flex-col gap-4 p-4" aria-labelledby="topo-h">
            <CardTitle
              id="topo-h"
              actions={
                <span className="flex flex-wrap items-center gap-1 text-[12px] text-fg-muted">
                  {t('p9.region.sources')}: <SourceTag source="provider" />{' '}
                  <SourceTag source="inventory" />
                  <OutlineTag>{t('p9.source.unknown')}</OutlineTag>
                </span>
              }
            >
              {t('p9.topo.title')}
            </CardTitle>
            {q.data.regions.length === 0 ? (
              <EmptyState title={t('p9.topo.empty')} />
            ) : (
              q.data.regions.map((r) => (
                <RegionBlock key={r.region ?? 'unknown'} region={r} byId={byId} now={now} />
              ))
            )}
          </Card>
        </>
      )}
    </div>
  );
}
