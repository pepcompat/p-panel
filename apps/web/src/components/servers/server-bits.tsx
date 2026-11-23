'use client';

import type { Server } from '@ppanel/shared-contracts';
import { useT } from '@/i18n/provider';
import { ToneBadge, STATUS_TONE, type Tone } from '@/components/ui/badge';
import { ResourceMeter } from '@/components/ui/meter';
import { connectionPath, isLive, statusKey } from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import type { MessageKey } from '@/i18n/en';

export function StatusBadge({ status }: { status: Server['status'] }) {
  const t = useT();
  return <ToneBadge tone={STATUS_TONE[status]}>{t(statusKey(status))}</ToneBadge>;
}

export function PathBadge({
  server,
  className,
}: {
  server: Pick<Server, 'status' | 'connectionPolicy' | 'addresses'>;
  className?: string;
}) {
  const t = useT();
  const p = connectionPath(server);
  return (
    <ToneBadge tone={p.tone} glyph={false} size="md" className={className}>
      {t(p.key)}
    </ToneBadge>
  );
}

/**
 * CPU/RAM/Disk meters. Stale/offline servers keep their last-known values with a stale marker;
 * a server that never reported shows "No data" — metrics are never rendered as 0.
 */
export function ServerMeters({
  server,
  size = 'sm',
  now,
}: {
  server: Pick<Server, 'metrics' | 'status'>;
  size?: 'sm' | 'md';
  now: number;
}) {
  const t = useT();
  const m = server.metrics;
  const stale = !!m && (m.stale || !isLive(server));
  return (
    <div className="flex flex-col gap-1.5">
      <ResourceMeter
        size={size}
        label={t('metric.cpu')}
        value={m ? m.cpuPct : null}
        stale={stale}
        noDataLabel={t('common.noData')}
      />
      <ResourceMeter
        size={size}
        label={t('metric.ram')}
        value={m ? m.memPct : null}
        stale={stale}
        noDataLabel={t('common.noData')}
      />
      <ResourceMeter
        size={size}
        label={t('metric.disk')}
        value={m ? m.diskPct : null}
        stale={stale}
        noDataLabel={t('common.noData')}
      />
      {m && stale && (
        <span data-testid="stale-marker" className="text-[11.5px] text-stale">
          {t('card.staleMarker', { ago: relativeTime(m.sampledAt, t, now) })}
        </span>
      )}
      {!m && <span className="text-[11.5px] text-fg-muted">{t('card.noMetrics')}</span>}
    </div>
  );
}

export function whyKey(s: Pick<Server, 'status'>): MessageKey | null {
  if (s.status === 'offline') return 'card.offlineWhy';
  if (s.status === 'stale') return 'card.staleWhy';
  if (s.status === 'revoked') return 'card.revokedWhy';
  return null;
}

export function serverTone(s: Pick<Server, 'status'>): Tone {
  return STATUS_TONE[s.status];
}

/** Gate reason for actions whose backend does not exist yet, preferring the offline explanation. */
export function proposedOrOffline(s: Pick<Server, 'status'>): { key: MessageKey } {
  return isLive(s) ? { key: 'perm.proposed' } : { key: 'perm.offline' };
}
