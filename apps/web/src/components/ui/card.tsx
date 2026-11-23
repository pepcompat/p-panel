import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function Card({
  children,
  className,
  as: As = 'section',
  ...rest
}: {
  children: ReactNode;
  className?: string;
  as?: 'section' | 'article' | 'div' | 'aside';
} & Record<string, unknown>) {
  return (
    <As className={cn('rounded-lg border border-line bg-surface', className)} {...rest}>
      {children}
    </As>
  );
}

export function CardHeader({
  title,
  actions,
  id,
  className,
}: {
  title: ReactNode;
  actions?: ReactNode;
  id?: string;
  className?: string;
}) {
  return (
    <div className={cn('flex items-center gap-2 border-b border-line-soft px-4 py-3', className)}>
      <h2 id={id} className="m-0 flex-1 text-[15px] font-semibold">
        {title}
      </h2>
      {actions}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  crumb,
  actions,
  mono,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  crumb?: ReactNode;
  actions?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-end gap-4">
      <div className="min-w-[240px] flex-1">
        {crumb && <div className="font-mono text-[12px] text-fg-muted">{crumb}</div>}
        <h1 className={cn('m-0 text-[22px] font-semibold', mono && 'font-mono')}>{title}</h1>
        {subtitle && <div className="text-[13px] text-fg-muted">{subtitle}</div>}
      </div>
      {actions}
    </div>
  );
}

export function Page({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('flex max-w-[1440px] flex-col gap-4 p-4 sm:p-6', className)}>{children}</div>
  );
}

export function DefList({
  rows,
  keyWidth = 120,
}: {
  rows: Array<[ReactNode, ReactNode, { mono?: boolean; className?: string }?]>;
  keyWidth?: number;
}) {
  return (
    <dl
      className="m-0 grid gap-x-3 gap-y-1.5 text-[13px]"
      style={{ gridTemplateColumns: `${keyWidth}px minmax(0,1fr)` }}
    >
      {rows.map(([k, v, o], i) => (
        <div key={i} className="contents">
          <dt className="text-fg-muted">{k}</dt>
          <dd
            className={cn(
              'm-0 break-words',
              o?.mono && 'font-mono text-[12.5px] break-all',
              o?.className,
            )}
          >
            {v}
          </dd>
        </div>
      ))}
    </dl>
  );
}
