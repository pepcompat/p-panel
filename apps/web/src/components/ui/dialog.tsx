'use client';

import * as D from '@radix-ui/react-dialog';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/** Accessible modal (focus trap, Esc, return focus) styled like the design's action dialog. */
export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  badge,
  children,
  footer,
  closeLabel,
  className,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  badge?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  closeLabel: string;
  className?: string;
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-overlay" />
        <D.Content
          className={cn(
            'fixed top-1/2 left-1/2 z-40 flex max-h-[calc(100vh-48px)] w-[calc(100%-48px)] max-w-[460px] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-auto rounded-[10px] bg-surface p-5 shadow-[0_20px_50px_rgba(0,0,0,.2)]',
            className,
          )}
        >
          {badge}
          <div className="flex items-start gap-2">
            <D.Title className="m-0 flex-1 text-[17px] font-semibold">{title}</D.Title>
            <D.Close aria-label={closeLabel} className="-mt-1 -mr-1 h-8 w-8 rounded border-0 bg-transparent text-[16px]">
              ✕
            </D.Close>
          </div>
          {description ? (
            <D.Description className="m-0 text-[13.5px] text-fg-2">{description}</D.Description>
          ) : (
            <D.Description className="sr-only">{typeof title === 'string' ? title : ''}</D.Description>
          )}
          {children}
          {footer && <div className="flex justify-end gap-2">{footer}</div>}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
