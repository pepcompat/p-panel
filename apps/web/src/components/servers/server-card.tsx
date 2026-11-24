'use client';

import Link from 'next/link';
import type { Server } from '@ppanel/shared-contracts';
import { useT } from '@/i18n/provider';
import { EnvBadge, OutlineTag, toneBorderTop } from '@/components/ui/badge';
import { CopyButton } from '@/components/ui/copy-button';
import { GatedButton } from '@/components/ui/gated-button';
import { AddressValue, ConnectionSummary, VpcLabel } from '@/components/p9/net-bits';
import { regionOf } from '@/lib/p9-gates';
import { address, envBadgeKey, osLabel, providerLabel } from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import { AlertFiringBadge } from '@/components/p5/bits';
import { cn } from '@/lib/utils';
import { ServerMeters, StatusBadge, proposedOrOffline, serverTone, whyKey } from './server-bits';

export function ServerCard({
  server,
  now,
  firing = 0,
}: {
  server: Server;
  now: number;
  /** P5: incidents currently firing for this server (alert badge). */
  firing?: number;
}) {
  const t = useT();
  const pub = address(server, 'public');
  const priv = address(server, 'private');
  const why = whyKey(server);
  const sub = [providerLabel(server), regionOf(server), osLabel(server), server.tags.join(', ')]
    .filter(Boolean)
    .join(' · ');
  const disk = server.metrics?.diskPct ?? null;
  const diskAlert = disk !== null && disk >= 90 ? `Disk ${Math.round(disk)}%` : null;
  return (
    <article
      aria-labelledby={`srv-${server.id}`}
      data-testid="server-card"
      className={cn(
        'flex flex-col gap-3 rounded-lg border border-t-[3px] border-line bg-surface px-4 py-3.5',
        toneBorderTop[serverTone(server)],
      )}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <h3 id={`srv-${server.id}`} className="m-0 truncate font-mono text-[14px] font-medium">
            <Link
              href={`/servers/${server.id}/overview`}
              className="text-fg no-underline hover:text-accent-text"
            >
              {server.name}
            </Link>
          </h3>
          <div className="text-[12px] text-fg-subtle">{sub || '—'}</div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-1">
          <AlertFiringBadge count={firing} />
          <StatusBadge status={server.status} />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <EnvBadge
          env={server.environment}
          label={t(envBadgeKey(server.environment))}
          className="px-1.5 py-0 text-[10.5px]"
        />
        {server.groupName ? (
          <OutlineTag className="text-[11px]">
            <span className="sr-only">{t('p9.group')}: </span>
            <span data-testid="card-group">{server.groupName}</span>
          </OutlineTag>
        ) : (
          <span className="text-[11px] text-fg-subtle">{t('p9.group.none')}</span>
        )}
      </div>

      <div className="grid grid-cols-[52px_minmax(0,1fr)_auto] items-center gap-x-2 gap-y-[3px] text-[12px]">
        <span className="text-fg-muted">{t('servers.col.public')}</span>
        <span className="min-w-0">
          {pub || server.publicIpv4 ? (
            <AddressValue server={server} scope="public" />
          ) : (
            <span className="font-mono">{t('card.noPublic')}</span>
          )}
        </span>
        {pub ? (
          <CopyButton text={pub.address} ariaLabel={t('card.copyPublic', { name: server.name })} />
        ) : (
          <span />
        )}
        <span className="text-fg-muted">{t('servers.col.private')}</span>
        <span className="min-w-0">
          <AddressValue server={server} scope="private" />
        </span>
        {priv ? (
          <CopyButton
            text={priv.address}
            ariaLabel={t('card.copyPrivate', { name: server.name })}
          />
        ) : (
          <span />
        )}
      </div>

      <div className="flex flex-col gap-1.5 text-[12px]">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="w-[52px] shrink-0 text-fg-muted">{t('p9.card.path')}</span>
          <ConnectionSummary server={server} now={now} />
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="w-[52px] shrink-0 text-fg-muted">{t('p9.card.vpc')}</span>
          <VpcLabel server={server} />
        </div>
      </div>

      {diskAlert && <div className="text-[12px] font-medium text-crit">▲ {diskAlert}</div>}

      <ServerMeters server={server} now={now} />

      <dl className="m-0 grid grid-cols-[76px_minmax(0,1fr)] gap-x-2.5 gap-y-[3px] text-[12.5px]">
        <dt className="text-fg-muted">{t('card.heartbeat')}</dt>
        <dd className="m-0">{relativeTime(server.lastHeartbeatAt, t, now)}</dd>
        <dt className="text-fg-muted">{t('card.agent')}</dt>
        <dd className="m-0 font-mono text-[12px]">{server.agentVersion ?? '—'}</dd>
        <dt className="text-fg-muted">{t('card.capabilities')}</dt>
        <dd className="m-0 text-fg-3">{server.capabilities.join(' · ') || '—'}</dd>
      </dl>

      {why && <div className="text-[11.5px] text-crit">{t(why)}</div>}

      <div className="mt-auto flex flex-wrap gap-1.5 border-t border-line-subtle pt-2.5">
        <Link
          href={`/servers/${server.id}/overview`}
          className="inline-flex min-h-8 items-center rounded-[5px] bg-accent-strong px-3 text-[12.5px] text-on-accent no-underline hover:text-on-accent hover:no-underline hover:brightness-110"
        >
          {t('card.details')}
        </Link>
        <GatedButton
          size="sm"
          className="font-mono"
          perm="ssh.connect"
          action="open_terminal"
          allowedActions={server.allowedActions}
          blockedReason={proposedOrOffline(server)}
        >
          {t('card.terminal')}
        </GatedButton>
        <Link
          href={`/servers/${server.id}/monitoring`}
          className="inline-flex min-h-8 items-center rounded-[5px] border border-line-strong bg-surface px-3 text-[12.5px] text-fg no-underline hover:no-underline"
        >
          {t('card.metrics')}
        </Link>
        <GatedButton
          size="sm"
          perm="servers.operate"
          action="restart_service"
          allowedActions={server.allowedActions}
          blockedReason={proposedOrOffline(server)}
        >
          {t('card.restart')}
        </GatedButton>
      </div>
    </article>
  );
}
