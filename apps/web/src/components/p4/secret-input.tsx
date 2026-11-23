'use client';

import { useId, useRef, useState } from 'react';
import { useI18n } from '@/i18n/provider';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { cn } from '@/lib/utils';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ErrorState } from '@/components/ui/states';

export interface SecretStatus {
  /** The Center holds a value (GET …/secrets lists the key). */
  set: boolean;
  version?: number;
  /** Wizard only: a value was handed over and will be written when the application is created. */
  staged?: boolean;
}

/**
 * Write-only secret field. The value lives only in the uncontrolled `<input type=password>` until it
 * is submitted; it is never copied into React state, never rendered back, and the field is cleared
 * as soon as `onSubmit` resolves. Status shows "set ✓ vN" — never the value or its length.
 */
export function SecretInput({
  secretKey,
  status,
  onSubmit,
  disabled,
  label,
  submitLabel,
  className,
}: {
  secretKey: string;
  status: SecretStatus;
  /** Receives the value exactly once; must not retain it. */
  onSubmit: (value: string) => Promise<unknown> | void;
  disabled?: boolean;
  label?: string;
  submitLabel?: string;
  className?: string;
}) {
  const { t } = useI18n();
  const id = useId();
  const ref = useRef<HTMLInputElement>(null);
  const [hasValue, setHasValue] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit() {
    const el = ref.current;
    if (!el || !el.value) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(el.value);
      el.value = '';
      setHasValue(false);
    } catch (e) {
      setError(toApiError(e));
    } finally {
      setBusy(false);
    }
  }

  const statusBadge = status.set ? (
    <ToneBadge tone="ok" glyph="✓" size="sm" className="font-mono">
      {t('secret.set', { v: status.version ?? 1 })}
    </ToneBadge>
  ) : status.staged ? (
    <ToneBadge tone="info" glyph="◆" size="sm">
      {t('secret.staged')}
    </ToneBadge>
  ) : (
    <ToneBadge tone="warn" glyph="▲" size="sm">
      {t('secret.notSet')}
    </ToneBadge>
  );

  return (
    <div
      className={cn('flex flex-col gap-1', className)}
      data-testid="secret-input"
      data-key={secretKey}
    >
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={id} className="font-mono text-[12.5px] font-medium">
          {label ?? secretKey}
        </label>
        <span data-testid="secret-status">{statusBadge}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <input
          ref={ref}
          id={id}
          type="password"
          name={`secret-${secretKey}`}
          autoComplete="new-password"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          data-1p-ignore
          data-lpignore="true"
          disabled={disabled || busy}
          placeholder={
            status.set || status.staged ? t('secret.replacePlaceholder') : t('secret.placeholder')
          }
          onChange={(e) => setHasValue(e.currentTarget.value.length > 0)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              void submit();
            }
          }}
          className="min-w-[200px] flex-1 rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[13px] text-fg placeholder:text-fg-subtle disabled:bg-chip"
          aria-describedby={`${id}-hint`}
        />
        <Button size="sm" disabled={disabled || busy || !hasValue} onClick={() => void submit()}>
          {busy
            ? t('common.saving')
            : (submitLabel ??
              (status.set || status.staged ? t('secret.replace') : t('secret.setAction')))}
        </Button>
      </div>
      <span id={`${id}-hint`} className="text-[11.5px] text-fg-muted">
        {t('secret.writeOnly')}
      </span>
      {error && <ErrorState error={error} />}
    </div>
  );
}
