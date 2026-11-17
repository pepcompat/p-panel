'use client';

import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

type Tone = 'neutral' | 'ok' | 'crit';
interface Toast {
  id: number;
  text: string;
  tone: Tone;
}

const ToastContext = createContext<(text: string, tone?: Tone) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Tone = 'neutral') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-2), { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      {/* No secrets are ever passed to toasts. role=status → polite, never steals focus. */}
      <div role="status" aria-live="polite" className="fixed right-5 bottom-5 z-50 flex max-w-[380px] flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              'rounded-lg bg-sidebar px-4 py-3 text-[13.5px] text-sidebar-fg-strong shadow-[0_10px_30px_rgba(0,0,0,.25)]',
              t.tone === 'ok' && 'border-l-4 border-ok',
              t.tone === 'crit' && 'border-l-4 border-crit',
            )}
          >
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
