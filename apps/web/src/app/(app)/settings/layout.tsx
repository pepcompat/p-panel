'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useT } from '@/i18n/provider';
import { cn } from '@/lib/utils';

const TABS = [
  ['/settings/users', 'settingsNav.users'],
  ['/settings/security', 'settingsNav.security'],
  ['/settings/audit', 'settingsNav.audit'],
] as const;

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  const t = useT();
  const pathname = usePathname() ?? '';
  return (
    <div className="flex max-w-[1440px] flex-col gap-4 p-4 sm:p-6">
      <h1 className="m-0 text-[22px] font-semibold">{t('nav.settings')}</h1>
      <nav
        aria-label={t('settingsNav.label')}
        className="flex gap-0.5 overflow-x-auto border-b border-line"
      >
        {TABS.map(([href, key]) => {
          const active = pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? 'page' : undefined}
              className={cn(
                'flex min-h-10 items-center border-b-2 px-3 text-[13px] whitespace-nowrap no-underline hover:no-underline',
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
