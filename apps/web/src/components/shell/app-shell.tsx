'use client';

import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import * as D from '@radix-ui/react-dialog';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { Skeleton } from '@/components/ui/skeleton';
import { Sidebar } from './sidebar';
import { Topbar } from './topbar';
import { PageEnvProvider } from './page-env';

export function AppShell({ children }: { children: ReactNode }) {
  const t = useT();
  const { status } = useAuth();
  const router = useRouter();
  const pathname = usePathname() ?? '/';
  const [drawer, setDrawer] = useState(false);

  useEffect(() => {
    if (status === 'anonymous') router.replace(`/login?next=${encodeURIComponent(pathname)}`);
  }, [status, router, pathname]);

  if (status !== 'authenticated') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="grid min-h-screen lg:grid-cols-[228px_minmax(0,1fr)]"
      >
        <div className="hidden bg-sidebar lg:block" />
        <div className="flex flex-col gap-4 p-6">
          <Skeleton className="h-6 w-60" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      </div>
    );
  }

  return (
    <PageEnvProvider>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2"
      >
        {t('app.skipToContent')}
      </a>
      <div className="grid min-h-screen text-[14px] leading-normal lg:grid-cols-[228px_minmax(0,1fr)]">
        <div className="sticky top-0 hidden h-screen lg:block">
          <Sidebar />
        </div>
        <D.Root open={drawer} onOpenChange={setDrawer}>
          <D.Portal>
            <D.Overlay className="fixed inset-0 z-40 bg-overlay lg:hidden" />
            <D.Content
              className="fixed inset-y-0 left-0 z-50 w-[260px] max-w-[85vw] lg:hidden"
              aria-describedby={undefined}
            >
              <D.Title className="sr-only">{t('nav.label')}</D.Title>
              <D.Close
                aria-label={t('nav.close')}
                className="absolute top-3 right-3 z-10 h-8 w-8 rounded border-0 bg-transparent text-sidebar-fg"
              >
                ✕
              </D.Close>
              <Sidebar onNavigate={() => setDrawer(false)} />
            </D.Content>
          </D.Portal>
        </D.Root>
        <main className="flex min-w-0 flex-col">
          <Topbar onMenu={() => setDrawer(true)} />
          <div id="main" tabIndex={-1} className="outline-none">
            {children}
          </div>
        </main>
      </div>
    </PageEnvProvider>
  );
}
