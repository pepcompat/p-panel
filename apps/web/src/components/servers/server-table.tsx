'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import type { Server } from '@ppanel/shared-contracts';
import { useT } from '@/i18n/provider';
import { envLabelKey } from '@/lib/servers';
import { relativeTime } from '@/lib/time';
import { AddressValue, ConnectionSummary, VpcLabel } from '@/components/p9/net-bits';
import { StatusBadge } from './server-bits';

function metricsCell(s: Server, noData: string) {
  if (!s.metrics) return <span className="text-fg-subtle">{noData}</span>;
  const stale = s.metrics.stale;
  return (
    <span className={stale ? 'text-stale' : undefined}>
      {stale ? '◐ ' : ''}
      {[s.metrics.cpuPct, s.metrics.memPct, s.metrics.diskPct]
        .map((n) => (n === null ? '—' : `${Math.round(n)}%`))
        .join(' / ')}
    </span>
  );
}

export function ServerTable({ servers, now }: { servers: Server[]; now: number }) {
  const t = useT();
  const router = useRouter();
  const th = 'px-2 py-[9px] font-medium';
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full min-w-[1180px] border-collapse text-[13px]">
        <thead>
          <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
            <th scope="col" className={`${th} pl-4`}>
              {t('servers.col.server')}
            </th>
            <th scope="col" className={th}>
              {t('servers.col.env')}
            </th>
            <th scope="col" className={th}>
              {t('p9.group')}
            </th>
            <th scope="col" className={th}>
              {t('servers.col.status')}
            </th>
            <th scope="col" className={th}>
              {t('servers.col.public')}
            </th>
            <th scope="col" className={th}>
              {t('servers.col.private')}
            </th>
            <th scope="col" className={th}>
              {t('servers.col.path')}
            </th>
            <th scope="col" className={th}>
              {t('p9.card.vpc')}
            </th>
            <th scope="col" className={th}>
              {t('servers.col.metrics')}
            </th>
            <th scope="col" className={`${th} pr-4`}>
              {t('servers.col.heartbeat')}
            </th>
          </tr>
        </thead>
        <tbody>
          {servers.map((s) => (
            <tr
              key={s.id}
              onClick={() => router.push(`/servers/${s.id}/overview`)}
              className="cursor-pointer border-t border-line-subtle hover:bg-surface-hover"
            >
              <td className="py-[9px] pr-2 pl-4 font-mono text-[12.5px]">
                <Link
                  href={`/servers/${s.id}/overview`}
                  className="text-accent-text"
                  onClick={(e) => e.stopPropagation()}
                >
                  {s.name}
                </Link>
              </td>
              <td className="px-2 text-[12px]">{t(envLabelKey(s.environment))}</td>
              <td className="px-2 text-[12px]">{s.groupName ?? t('common.dash')}</td>
              <td className="px-2">
                <StatusBadge status={s.status} />
              </td>
              <td className="px-2 text-[12px]">
                <AddressValue server={s} scope="public" />
              </td>
              <td className="px-2 text-[12px]">
                <AddressValue server={s} scope="private" />
              </td>
              <td className="px-2" onClick={(e) => e.stopPropagation()}>
                <ConnectionSummary server={s} now={now} />
              </td>
              <td className="px-2">
                <VpcLabel server={s} />
              </td>
              <td className="px-2 font-mono text-[12px]">{metricsCell(s, t('common.noData'))}</td>
              <td className="py-[9px] pr-4 pl-2 text-[12px]">
                {relativeTime(s.lastHeartbeatAt, t, now)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
