'use client';

import * as T from '@radix-ui/react-tooltip';
import type { ReactNode } from 'react';

export function Tip({ content, children }: { content: ReactNode; children: ReactNode }) {
  if (!content) return <>{children}</>;
  return (
    <T.Root>
      <T.Trigger asChild>{children}</T.Trigger>
      <T.Portal>
        <T.Content
          sideOffset={6}
          className="z-50 max-w-[300px] rounded-md bg-sidebar px-2.5 py-1.5 text-[12px] leading-snug text-sidebar-fg-strong shadow-lg"
        >
          {content}
          <T.Arrow className="fill-sidebar" />
        </T.Content>
      </T.Portal>
    </T.Root>
  );
}
