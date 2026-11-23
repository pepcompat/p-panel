'use client';

import { useState } from 'react';
import { useT } from '@/i18n/provider';
import { Button, type ButtonProps } from './button';

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function CopyButton({
  text,
  label,
  ariaLabel,
  variant = 'chip',
  size = 'xs',
  ...rest
}: { text: string; label?: string; ariaLabel?: string } & ButtonProps) {
  const t = useT();
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  return (
    <Button
      variant={variant}
      size={size}
      aria-label={ariaLabel}
      onClick={async () => {
        const ok = await copyText(text);
        setState(ok ? 'ok' : 'fail');
        setTimeout(() => setState('idle'), 1600);
      }}
      {...rest}
    >
      <span aria-live="polite">
        {state === 'ok'
          ? t('common.copied')
          : state === 'fail'
            ? t('common.copyFailed')
            : (label ?? t('common.copy'))}
      </span>
    </Button>
  );
}
