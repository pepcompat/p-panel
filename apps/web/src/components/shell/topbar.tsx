'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import type { Environment } from '@ppanel/shared-contracts';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { useServers } from '@/lib/queries';
import { fleetCounts, envBadgeKey } from '@/lib/servers';
import { EnvBadge } from '@/components/ui/badge';
import { Tip } from '@/components/ui/tooltip';
import { LangToggle } from './lang-toggle';
import { AccountMenu } from './account-menu';
import { usePageEnv } from './page-env';

function scopeEnv(bindings: { scopeType: string; scopeId?: string }[]): Environment | 'all' {
  if (bindings.some((b) => b.scopeType === 'global')) return 'production';
  const envs = bindings.filter((b) => b.scopeType === 'environment').map((b) => b.scopeId);
  if (envs.includes('production')) return 'production';
  if (envs.includes('uat')) return 'uat';
  if (envs.includes('development')) return 'development';
  return 'all';
}

export function Topbar({ onMenu }: { onMenu: () => void }) {
  const t = useT();
  const router = useRouter();
  const pathname = usePathname() ?? '';
  const { me } = useAuth();
  const pageEnv = usePageEnv();
  const env = pageEnv ?? scopeEnv(me?.bindings ?? []);
  const servers = useServers();
  const counts = servers.data ? fleetCounts(servers.data.items) : null;
  const [q, setQ] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);

  // "/" focuses search (design shows the shortcut hint), unless typing in a field already
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) && !el.isContentEditable) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <header className="sticky top-0 z-20 flex flex-wrap items-center gap-x-3.5 gap-y-2 border-b border-line bg-topbar px-4 py-2.5 sm:px-6">
      <button
        type="button"
        onClick={onMenu}
        aria-label={t('nav.open')}
        className="grid h-8 w-8 place-items-center rounded-md border border-line-strong bg-surface lg:hidden"
      >
        <span aria-hidden="true">☰</span>
      </button>
      <Tip content={t('top.envIndicator')}>
        <span tabIndex={0} className="rounded">
          <EnvBadge env={env} label={env === 'all' ? t('env.badge.all') : t(envBadgeKey(env))} />
        </span>
      </Tip>
      <span className="hidden font-mono text-[12.5px] text-fg-muted md:inline">{pathname}</span>
      <LangToggle className="order-9" />
      <form
        role="search"
        className="order-last ml-auto flex max-w-[420px] min-w-[180px] flex-1 items-center gap-2 rounded-md border border-line bg-surface px-2.5 py-1.5 text-[13px] text-fg-subtle sm:order-none"
        onSubmit={(e) => {
          e.preventDefault();
          router.push(`/servers${q.trim() ? `?q=${encodeURIComponent(q.trim())}` : ''}`);
        }}
      >
        <span aria-hidden="true">⌕</span>
        <label htmlFor="global-search" className="sr-only">
          {t('top.searchLabel')}
        </label>
        <input
          id="global-search"
          ref={searchRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={t('top.search')}
          className="min-w-0 flex-1 border-0 bg-transparent text-fg outline-none placeholder:text-fg-subtle"
        />
        <kbd className="rounded-[3px] border border-line px-[5px] font-mono text-[11px]">/</kbd>
      </form>
      <div className="flex flex-wrap items-center gap-4 text-[12.5px] text-fg-3" aria-label={t('top.fleetLabel')}>
        <Link href="/servers" className="text-fg-3 no-underline hover:text-fg">
          {counts ? (
            <>
              <b className="text-ok" aria-hidden="true">
                ●
              </b>{' '}
              {t('top.fleetOnline', { online: counts.online + counts.degraded, total: counts.total })}
              {counts.stale + counts.offline > 0 && (
                <span className="ml-2 text-stale">
                  ◐ {counts.stale + counts.offline}
                </span>
              )}
            </>
          ) : (
            <>
              <b className="text-off" aria-hidden="true">
                ○
              </b>{' '}
              {t('top.fleetUnknown')}
            </>
          )}
        </Link>
      </div>
      <AccountMenu />
    </header>
  );
}
