'use client';

import { useCallback, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useI18n } from '@/i18n/provider';
import type { SshGrant } from '@/lib/api/p10-types';
import { useGrants } from '@/lib/p10-queries';
import { useAuth } from '@/lib/auth/auth-provider';
import { PageHeader } from '@/components/ui/card';
import { Notice } from '@/components/ui/states';
import { TabStrip } from './bits';
import { CredentialsView } from './credentials-view';
import { GrantsView } from './grants-view';
import { HostKeysView } from './host-keys-view';
import { SessionsView } from './sessions-view';
import { TerminalWorkspace } from './terminal-workspace';

export const SSH_TABS = ['terminal', 'grants', 'credentials', 'host-keys', 'sessions'] as const;
export type SshTab = (typeof SSH_TABS)[number];
const isTab = (v: string | null): v is SshTab => !!v && (SSH_TABS as readonly string[]).includes(v);

/** SSH & Credentials: terminal sessions, access grants, keys, host keys and the session log. */
export function SshView() {
  const { t } = useI18n();
  const { me } = useAuth();
  const router = useRouter();
  const pathname = usePathname() ?? '/ssh';
  const sp = useSearchParams();
  const tab: SshTab = isTab(sp.get('tab')) ? (sp.get('tab') as SshTab) : 'terminal';
  const grants = useGrants();
  const pendingForMe = (grants.data ?? []).filter(
    (g) => g.status === 'awaiting_approval' && g.userId !== me?.user.id,
  ).length;
  const urlGrant = sp.get('grant');
  const [openRequest, setOpenRequest] = useState<{ grantId: string; nonce: number } | null>(
    urlGrant ? { grantId: urlGrant, nonce: 0 } : null,
  );

  const go = useCallback(
    (next: SshTab, extra: Record<string, string> = {}) => {
      const p = new URLSearchParams({ tab: next, ...extra });
      router.replace(`${pathname}?${p.toString()}`, { scroll: false });
    },
    [router, pathname],
  );

  const openTerminal = (g: SshGrant) => {
    setOpenRequest({ grantId: g.id, nonce: Date.now() });
    go('terminal');
  };

  const labels: Record<SshTab, string> = {
    terminal: t('p10.tab.terminal'),
    grants: t('p10.tab.grants'),
    credentials: t('p10.tab.credentials'),
    'host-keys': t('p10.tab.hostKeys'),
    sessions: t('p10.tab.sessions'),
  };

  return (
    <div className="flex max-w-[1440px] flex-col gap-4 p-4 sm:p-6">
      <PageHeader title={t('nav.ssh')} subtitle={t('p10.subtitle')} />
      <Notice tone="neutral" glyph="◆" role="note">
        {t('p10.gatewayGate')}
      </Notice>
      <TabStrip
        label={t('p10.sections')}
        idPrefix="ssh"
        value={tab}
        onChange={(v) => go(v)}
        tabs={SSH_TABS.map((v) => ({
          value: v,
          label: labels[v],
          extra:
            v === 'grants' && pendingForMe > 0 ? (
              <span
                className="rounded-full bg-warn-bg px-1.5 font-mono text-[11px] text-warn"
                aria-label={t('p10.grant.pendingCount', { n: pendingForMe })}
              >
                {pendingForMe}
              </span>
            ) : undefined,
        }))}
      />
      {/* the terminal stays mounted so open sessions survive switching sections */}
      <div
        id="ssh-panel-terminal"
        role="tabpanel"
        aria-labelledby="ssh-tab-terminal"
        hidden={tab !== 'terminal'}
      >
        <TerminalWorkspace openRequest={openRequest} onRequestGrant={() => go('grants')} />
      </div>
      {tab !== 'terminal' && (
        <div id={`ssh-panel-${tab}`} role="tabpanel" aria-labelledby={`ssh-tab-${tab}`}>
          {tab === 'grants' && (
            <GrantsView
              prefill={{ serverId: sp.get('server'), path: sp.get('path'), user: sp.get('user') }}
              onOpenTerminal={openTerminal}
            />
          )}
          {tab === 'credentials' && <CredentialsView />}
          {tab === 'host-keys' && (
            <HostKeysView
              serverId={sp.get('server')}
              onServerChange={(id) => go('host-keys', { server: id })}
            />
          )}
          {tab === 'sessions' && <SessionsView />}
        </div>
      )}
    </div>
  );
}
