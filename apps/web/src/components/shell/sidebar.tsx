'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Fragment } from 'react';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { cn } from '@/lib/utils';
import { NAV, isActive } from './nav';

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <div
      aria-hidden="true"
      className="grid place-items-center rounded-md bg-accent font-mono text-[13px] font-bold text-white"
      style={{ width: size, height: size }}
    >
      p
    </div>
  );
}

export function scopeSummary(bindings: { scopeType: string; scopeId?: string }[]): string {
  if (bindings.some((b) => b.scopeType === 'global')) return 'global';
  return bindings.map((b) => b.scopeId ?? b.scopeType).join(', ') || '—';
}

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const t = useT();
  const pathname = usePathname() ?? '';
  const { me, logout } = useAuth();
  const role = me?.bindings[0]?.roleKey;
  return (
    <aside className="flex h-full flex-col bg-sidebar text-sidebar-fg">
      <div className="flex items-center gap-2.5 px-4 pt-4 pb-[18px]">
        <Logo />
        <div className="flex flex-col">
          <span className="text-[14px] font-semibold text-sidebar-fg-strong">{t('app.name')}</span>
          <span className="font-mono text-[11px] text-sidebar-muted">{t('app.tagline')}</span>
        </div>
      </div>
      <nav
        aria-label={t('nav.label')}
        className="flex flex-1 flex-col gap-0.5 overflow-auto px-2 pb-2"
      >
        {NAV.map((item, i) => {
          const head = i === 0 || NAV[i - 1]!.section !== item.section;
          const active = isActive(item, pathname);
          return (
            <Fragment key={item.id}>
              {head && (
                <div
                  className="px-2.5 pt-3 pb-1 text-[10.5px] tracking-[.08em] text-sidebar-dim uppercase"
                  aria-hidden="true"
                >
                  {t(item.section)}
                </div>
              )}
              <Link
                href={item.href}
                onClick={onNavigate}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'flex min-h-9 items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[13.5px] no-underline hover:no-underline focus-visible:outline-offset-[-2px]',
                  active
                    ? 'bg-sidebar-active text-sidebar-fg-strong'
                    : 'text-sidebar-fg hover:bg-sidebar-hover hover:text-sidebar-fg-strong',
                )}
              >
                <span
                  aria-hidden="true"
                  className="w-[18px] font-mono text-[11px] text-sidebar-dim"
                >
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span className="flex-1">{t(item.label)}</span>
                {item.preview && (
                  <span
                    className="font-mono text-[10px] text-sidebar-dim"
                    title={t('state.preview.title')}
                  >
                    {t('nav.preview')}
                  </span>
                )}
              </Link>
            </Fragment>
          );
        })}
      </nav>
      <div className="flex flex-col gap-0.5 border-t border-sidebar-line px-4 py-3">
        <span className="text-[13px] text-sidebar-fg-strong">
          {me?.user.displayName ?? '—'}
          {role ? ` · ${t(`role.${role}`)}` : ''}
        </span>
        <span className="text-[11.5px] text-sidebar-muted">
          {t('account.scope', { scope: scopeSummary(me?.bindings ?? []) })} ·{' '}
          {me?.mfaEnabled ? t('account.mfaOn') : t('account.mfaOff')}
        </span>
        <button
          type="button"
          onClick={() => void logout()}
          className="mt-1.5 self-start rounded-[5px] border border-sidebar-btn-line bg-transparent px-2.5 py-1 text-[12px] text-sidebar-fg hover:text-sidebar-fg-strong"
        >
          {t('account.signOut')}
        </button>
      </div>
    </aside>
  );
}
