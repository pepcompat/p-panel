'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import type { Permission } from '@ppanel/shared-contracts';
import { api, setAuthFailureHandler, tokenStore } from '@/lib/api';
import { authApi } from '@/lib/api/endpoints';
import type { LoginSuccess, MeResponse } from '@/lib/api/types';

type Status = 'loading' | 'authenticated' | 'anonymous';

interface AuthValue {
  status: Status;
  me: MeResponse | null;
  can: (perm: Permission) => boolean;
  /** Store the access token from login / MFA verify and load /auth/me. */
  completeLogin: (res: LoginSuccess) => Promise<void>;
  refreshMe: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('loading');
  const [me, setMe] = useState<MeResponse | null>(null);
  const router = useRouter();
  const pathname = usePathname();
  const qc = useQueryClient();
  const pathRef = useRef(pathname);
  pathRef.current = pathname;

  const loadMe = useCallback(async () => {
    const data = await authApi.me();
    setMe(data);
    setStatus('authenticated');
  }, []);

  // Boot: access token is memory-only, so after a reload we try the HttpOnly refresh cookie once.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (!tokenStore.get()) {
          const ok = await api.refresh();
          if (!ok) throw new Error('no session');
        }
        if (!cancelled) await loadMe();
      } catch {
        if (!cancelled) {
          setMe(null);
          setStatus('anonymous');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [loadMe]);

  useEffect(() => {
    setAuthFailureHandler(() => {
      setMe(null);
      setStatus('anonymous');
      qc.clear();
      const here = pathRef.current;
      if (here && !here.startsWith('/login')) {
        router.replace(`/login?reason=expired&next=${encodeURIComponent(here)}`);
      }
    });
    return () => setAuthFailureHandler(() => {});
  }, [qc, router]);

  const completeLogin = useCallback(
    async (res: LoginSuccess) => {
      tokenStore.set(res.accessToken);
      await loadMe();
    },
    [loadMe],
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      /* session may already be gone; clear locally regardless */
    }
    tokenStore.set(null);
    setMe(null);
    setStatus('anonymous');
    qc.clear();
    router.replace('/login?reason=signedout');
  }, [qc, router]);

  const value = useMemo<AuthValue>(
    () => ({
      status,
      me,
      can: (perm) => (me?.permissions as string[] | undefined)?.includes(perm) ?? false,
      completeLogin,
      refreshMe: loadMe,
      logout,
    }),
    [status, me, completeLogin, loadMe, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

/** Test/helper context provider with a fixed identity. */
export function StaticAuthProvider({
  me,
  children,
}: {
  me: MeResponse | null;
  children: ReactNode;
}) {
  const value = useMemo<AuthValue>(
    () => ({
      status: me ? 'authenticated' : 'anonymous',
      me,
      can: (perm) => (me?.permissions as string[] | undefined)?.includes(perm) ?? false,
      completeLogin: async () => {},
      refreshMe: async () => {},
      logout: async () => {},
    }),
    [me],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
