'use client';

import type { ReactNode } from 'react';
import { useT } from '@/i18n/provider';
import { Page, PageHeader } from '@/components/ui/card';
import { Button, type ButtonProps } from '@/components/ui/button';
import { PreviewBanner } from '@/components/ui/states';
import { Tip } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

/** Every preview route renders through this: visible "Preview — mock data, backend PROPOSED" banner first. */
export function PreviewPage({ title, subtitle, crumb, actions, children }: { title: ReactNode; subtitle?: ReactNode; crumb?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <Page>
      <PreviewBanner />
      <PageHeader title={title} subtitle={subtitle} crumb={crumb} actions={actions} />
      {children}
    </Page>
  );
}

/** Action buttons in previews never pretend to succeed: always disabled with an explanation. */
export function PreviewAction({ children, ...rest }: ButtonProps) {
  const t = useT();
  return (
    <Tip content={t('preview.disabledAction')}>
      <span tabIndex={0} className="inline-flex rounded-md">
        <Button {...rest} disabled aria-disabled>
          {children}
        </Button>
      </span>
    </Tip>
  );
}

/** Local (non-routing) tab strip used inside preview screens. */
export function LocalTabs<V extends string>({ label, tabs, value, onChange }: { label: string; tabs: Array<[V, ReactNode]>; value: V; onChange: (v: V) => void }) {
  return (
    <div role="tablist" aria-label={label} className="flex gap-0.5 overflow-x-auto border-b border-line">
      {tabs.map(([v, l]) => (
        <button
          key={v}
          role="tab"
          type="button"
          aria-selected={v === value}
          onClick={() => onChange(v)}
          className={cn(
            'min-h-10 shrink-0 border-0 border-b-2 bg-transparent px-3 text-[13px] whitespace-nowrap',
            v === value ? 'border-accent-strong font-medium text-fg' : 'border-transparent text-fg-muted hover:text-fg',
          )}
        >
          {l}
        </button>
      ))}
    </div>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th scope="col" className={cn('px-2 py-[9px] font-medium first:pl-4 last:pr-4', className)}>
      {children}
    </th>
  );
}
export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn('px-2 py-[9px] first:pl-4 last:pr-4', className)}>{children}</td>;
}
export function Table({ head, children, minWidth = 720 }: { head: ReactNode; children: ReactNode; minWidth?: number }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full border-collapse text-[13px]" style={{ minWidth }}>
        <thead>
          <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">{head}</tr>
        </thead>
        <tbody className="[&>tr]:border-t [&>tr]:border-line-subtle">{children}</tbody>
      </table>
    </div>
  );
}

export const riskTone = (r: string) => (r === 'DESTRUCTIVE' ? 'crit' : r === 'HIGH' ? 'warn' : r === 'LOW' ? 'info' : 'ok') as 'crit' | 'warn' | 'info' | 'ok';
