'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import type { Environment } from '@ppanel/shared-contracts';

/** Lets a page (e.g. server detail) tell the top bar which environment is in view. */
const Ctx = createContext<{ env: Environment | null; setEnv: (e: Environment | null) => void }>({ env: null, setEnv: () => {} });

export function PageEnvProvider({ children }: { children: ReactNode }) {
  const [env, setEnv] = useState<Environment | null>(null);
  return <Ctx.Provider value={{ env, setEnv }}>{children}</Ctx.Provider>;
}

export const usePageEnv = () => useContext(Ctx).env;

export function useSetPageEnv(env: Environment | null | undefined) {
  const { setEnv } = useContext(Ctx);
  useEffect(() => {
    setEnv(env ?? null);
    return () => setEnv(null);
  }, [env, setEnv]);
}
