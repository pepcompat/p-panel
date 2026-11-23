'use client';

import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { formatDateTime, relativeTime } from '@/lib/time';
import { Card, DefList } from '@/components/ui/card';
import { ServerMeters } from '../server-bits';
import type { MessageKey } from '@/i18n/en';

const KNOWN_ACTIONS = [
  'edit',
  'restart_service',
  'rotate_cert',
  'revoke',
  'open_terminal',
] as const;

export function OverviewTab({ server, now }: { server: Server; now: number }) {
  const { t, locale } = useI18n();
  const cert = server.certificate;
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,320px),1fr))] items-start gap-4">
      <Card className="flex flex-col gap-2 p-4">
        <h2 className="m-0 mb-1 text-[15px] font-semibold">{t('sd.capacity')}</h2>
        <ServerMeters server={server} size="md" now={now} />
        {server.metrics && (
          <span className="text-[12px] text-fg-muted">
            {t('sd.capacityNote', { ago: relativeTime(server.metrics.sampledAt, t, now) })}
          </span>
        )}
      </Card>
      <Card className="p-4">
        <h2 className="m-0 mb-2.5 text-[15px] font-semibold">{t('sd.agentRuntime')}</h2>
        <DefList
          rows={[
            [t('sd.agent'), `${server.agentVersion ?? '—'} · mTLS`, { mono: true }],
            [
              t('sd.certificate'),
              cert
                ? t('sd.certExpires', {
                    serial: cert.serial.slice(0, 12),
                    date: formatDateTime(cert.notAfter, locale),
                  })
                : t('sd.noCert'),
              { mono: true },
            ],
            [t('sd.heartbeat'), relativeTime(server.lastHeartbeatAt, t, now)],
            [t('sd.capabilities'), server.capabilities.join(' · ') || '—'],
            [
              t('sd.os'),
              server.os
                ? `${server.os.id} ${server.os.version} · ${server.os.arch}${server.os.kernel ? ` · ${server.os.kernel}` : ''}`
                : '—',
              { mono: true },
            ],
          ]}
        />
      </Card>
      <Card className="flex flex-col gap-2 p-4">
        <h2 className="m-0 mb-1 text-[15px] font-semibold">{t('sd.allowedActions')}</h2>
        <p className="m-0 text-[12px] text-fg-muted">{t('sd.allowedHint')}</p>
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          {KNOWN_ACTIONS.map((a) => {
            const ok = server.allowedActions.includes(a);
            return (
              <li key={a} className="flex items-start gap-2.5 text-[13px]">
                <span
                  aria-hidden="true"
                  className={`w-3.5 font-bold ${ok ? 'text-ok' : 'text-off'}`}
                >
                  {ok ? '●' : '○'}
                </span>
                <div className="flex-1">
                  <div>{t(`sd.action.${a}` as MessageKey)}</div>
                  <div className="text-[12px] text-fg-muted">
                    {ok ? t('sd.action.granted') : t('sd.action.notGranted')}
                  </div>
                </div>
              </li>
            );
          })}
          <li className="flex items-start gap-2.5 text-[13px]">
            <span aria-hidden="true" className="w-3.5 font-bold text-crit">
              ✕
            </span>
            <div className="flex-1">
              <div>{t('sd.action.arbitrary')}</div>
              <div className="text-[12px] text-fg-muted">{t('sd.action.arbitraryWhy')}</div>
            </div>
          </li>
        </ul>
      </Card>
    </div>
  );
}
