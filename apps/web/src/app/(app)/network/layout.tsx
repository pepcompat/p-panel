'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useT } from '@/i18n/provider';
import { cn } from '@/lib/utils';

const TABS = [
  ['/network', 'p9.nav.topology', true],
  ['/network/providers', 'p9.nav.providers', false],
  ['/network/inventory', 'p9.nav.inventory', false],
  ['/network/connectivity', 'p9.nav.connectivity', false],
  ['/network/gateways', 'p9.nav.gateways', false],
] as const;

export default function NetworkLayout({ children }: { children: React.ReactNode }) {
  const t = useT();
  const pathname = usePathname() ?? '';
  return (
    <div className="flex max-w-[1440px] flex-col gap-4 p-4 sm:p-6">
      <div>
        <h1 className="m-0 text-[22px] font-semibold">{t('nav.network')}</h1>
        <div className="text-[13px] text-fg-muted">{t('p9.network.subtitle')}</div>
      </div>
      <nav
        aria-label={t('p9.nav.label')}
        className="flex gap-0.5 overflow-x-auto border-b border-line"
      >
        {TABS.map(([href, key, exact]) => {
          const active = exact ? pathname === href : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? 'page' : undefined}
              className={cn(
                'flex min-h-10 shrink-0 items-center border-b-2 px-3 text-[13px] whitespace-nowrap no-underline hover:no-underline focus-visible:-outline-offset-2',
                active
                  ? 'border-accent-strong font-medium text-fg'
                  : 'border-transparent text-fg-muted hover:text-fg',
              )}
            >
              {t(key)}
            </Link>
          );
        })}
      </nav>
      {children}
    </div>
  );
}
