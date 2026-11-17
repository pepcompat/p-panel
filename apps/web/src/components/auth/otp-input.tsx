'use client';

import { useRef, type ClipboardEvent, type KeyboardEvent } from 'react';
import { useT } from '@/i18n/provider';
import { cn } from '@/lib/utils';

/** Six single-digit boxes (design: login 2FA). Supports paste of the full code and autofill. */
export function OtpInput({ value, onChange, autoFocus, invalid, groupLabel }: { value: string; onChange: (v: string) => void; autoFocus?: boolean; invalid?: boolean; groupLabel: string }) {
  const t = useT();
  const refs = useRef<Array<HTMLInputElement | null>>([]);
  const digits = Array.from({ length: 6 }, (_, i) => value[i] ?? '');

  const setAt = (i: number, d: string) => {
    const next = digits.slice();
    next[i] = d;
    onChange(next.join('').replace(/\s/g, ''));
  };
  const onInput = (i: number, raw: string) => {
    const clean = raw.replace(/\D/g, '');
    if (clean.length > 1) {
      onChange(clean.slice(0, 6));
      refs.current[Math.min(clean.length, 6) - 1]?.focus();
      return;
    }
    setAt(i, clean);
    if (clean && i < 5) refs.current[i + 1]?.focus();
  };
  const onKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      e.preventDefault();
      setAt(i - 1, '');
      refs.current[i - 1]?.focus();
    } else if (e.key === 'ArrowLeft' && i > 0) refs.current[i - 1]?.focus();
    else if (e.key === 'ArrowRight' && i < 5) refs.current[i + 1]?.focus();
  };
  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (text) {
      e.preventDefault();
      onChange(text);
      refs.current[Math.min(text.length, 6) - 1]?.focus();
    }
  };
  return (
    <div role="group" aria-label={groupLabel} className="grid grid-cols-6 gap-2">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          autoFocus={autoFocus && i === 0}
          value={d}
          onChange={(e) => onInput(i, e.target.value)}
          onKeyDown={(e) => onKey(i, e)}
          onPaste={onPaste}
          onFocus={(e) => e.target.select()}
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          maxLength={6}
          aria-label={t('mfa.digit', { n: i + 1 })}
          aria-invalid={invalid || undefined}
          className={cn(
            'h-[52px] w-full min-w-0 rounded-lg border bg-surface p-0 text-center font-mono text-[22px] font-medium text-fg',
            invalid ? 'border-crit' : d ? 'border-accent' : 'border-line-strong',
          )}
        />
      ))}
    </div>
  );
}
