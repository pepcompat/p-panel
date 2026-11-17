'use client';

import { useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as Tooltip from '@radix-ui/react-tooltip';
import { I18nProvider } from '@/i18n/provider';
import { AuthProvider } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import { ThemeProvider } from './theme';
import { ToastProvider } from './toast';

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        // never retry client errors (401/403/404/409/422); retry transient ones twice
        retry: (count, err) => !(isApiError(err) && err.status >= 400 && err.status < 500) && count < 2,
        refetchOnWindowFocus: true,
      },
      mutations: { retry: false },
    },
  });
}

export function AppProviders({ children }: { children: ReactNode }) {
  const [qc] = useState(makeQueryClient);
  return (
    <QueryClientProvider client={qc}>
      <ThemeProvider>
        <I18nProvider>
          <Tooltip.Provider delayDuration={200}>
            <ToastProvider>
              <AuthProvider>{children}</AuthProvider>
            </ToastProvider>
          </Tooltip.Provider>
        </I18nProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
