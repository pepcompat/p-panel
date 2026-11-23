import type { ReactNode } from 'react';
import { Logo } from '@/components/shell/sidebar';
import { LangToggle } from '@/components/shell/lang-toggle';

export function AuthCard({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return (
    <main
      className={`flex w-full flex-col gap-3.5 rounded-[10px] border border-line bg-surface p-7 ${wide ? 'max-w-[520px]' : 'max-w-[380px]'}`}
    >
      <div className="flex items-center gap-2.5">
        <Logo size={32} />
        <span className="flex-1 font-semibold">pPanel</span>
        <LangToggle />
      </div>
      {children}
    </main>
  );
}
