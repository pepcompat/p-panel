'use client';

import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

export interface SegOption<V extends string> {
  value: V;
  label: ReactNode;
  count?: number | string;
  disabled?: boolean;
}

/** Design "radiogroup" button strip with roving tabindex and arrow-key navigation. */
export function Segmented<V extends string>({
  label,
  options,
  value,
  onChange,
  size = 'sm',
  mono,
  className,
  disabled,
}: {
  label: string;
  options: SegOption<V>[];
  value: V;
  onChange: (v: V) => void;
  size?: 'sm' | 'md';
  mono?: boolean;
  className?: string;
  disabled?: boolean;
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const enabled = options.filter((o) => !o.disabled && !disabled);
  const onKey = (e: KeyboardEvent, idx: number) => {
    const dir = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
    if (!dir || enabled.length === 0) return;
    e.preventDefault();
    const cur = enabled.findIndex((o) => o.value === options[idx]!.value);
    const next = enabled[(cur + dir + enabled.length) % enabled.length]!;
    onChange(next.value);
    refs.current[options.indexOf(next)]?.focus();
  };
  return (
    <div role="radiogroup" aria-label={label} className={cn('flex flex-wrap overflow-hidden rounded-md border border-line-strong', className)}>
      {options.map((o, i) => {
        const checked = o.value === value;
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={checked}
            tabIndex={checked ? 0 : -1}
            disabled={o.disabled || disabled}
            onClick={() => onChange(o.value)}
            onKeyDown={(e) => onKey(e, i)}
            className={cn(
              'flex items-center gap-1.5 border-0 px-3 text-[12.5px] focus-visible:-outline-offset-2 disabled:opacity-50',
              size === 'sm' ? 'min-h-8' : 'min-h-9',
              mono && 'min-w-10 justify-center font-mono text-[12px]',
              checked ? 'bg-sidebar text-sidebar-fg-strong dark:bg-accent-strong' : 'bg-surface text-fg-3 hover:bg-surface-hover',
            )}
          >
            {o.label}
            {o.count !== undefined && <span className="font-mono text-[11px] opacity-70">{o.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
