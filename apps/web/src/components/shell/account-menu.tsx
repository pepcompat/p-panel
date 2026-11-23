'use client';

import * as DM from '@radix-ui/react-dropdown-menu';
import Link from 'next/link';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { useTheme, type ThemePref } from '@/components/providers/theme';

const item =
  'flex min-h-8 cursor-pointer items-center gap-2 rounded px-2.5 text-[13px] outline-none data-[highlighted]:bg-surface-hover';

export function AccountMenu() {
  const t = useT();
  const { me, logout } = useAuth();
  const { pref, setPref } = useTheme();
  const initials = (me?.user.displayName ?? '?')
    .split(/\s+/)
    .map((p) => p[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();
  return (
    <DM.Root>
      <DM.Trigger
        aria-label={t('account.menu')}
        className="grid h-8 w-8 place-items-center rounded-full border border-line-strong bg-surface font-mono text-[11.5px] font-semibold"
      >
        {initials}
      </DM.Trigger>
      <DM.Portal>
        <DM.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-[240px] rounded-lg border border-line bg-surface p-1.5 text-fg shadow-xl"
        >
          <div className="px-2.5 py-2">
            <div className="text-[13.5px] font-semibold">{me?.user.displayName}</div>
            <div className="text-[12px] text-fg-muted">{me?.user.email}</div>
            <div className="mt-1 text-[12px]">
              <span className={me?.mfaEnabled ? 'text-ok' : 'text-warn'}>
                {me?.mfaEnabled ? '●' : '▲'}
              </span>{' '}
              {me?.mfaEnabled ? t('account.mfaOn') : t('account.mfaOff')}
            </div>
          </div>
          <DM.Separator className="my-1 h-px bg-line" />
          <DM.Item asChild className={item}>
            <Link
              href={me?.mfaEnabled ? '/settings/security' : '/setup/2fa'}
              className="text-fg no-underline hover:no-underline"
            >
              {me?.mfaEnabled ? t('account.security') : t('account.enableMfa')}
            </Link>
          </DM.Item>
          <DM.Separator className="my-1 h-px bg-line" />
          <DM.Label className="px-2.5 pt-1 text-[11px] tracking-[.06em] text-fg-muted uppercase">
            {t('account.theme')}
          </DM.Label>
          <DM.RadioGroup value={pref} onValueChange={(v) => setPref(v as ThemePref)}>
            {(['light', 'dark', 'system'] as const).map((p) => (
              <DM.RadioItem key={p} value={p} className={item}>
                <span className="w-3" aria-hidden="true">
                  <DM.ItemIndicator>●</DM.ItemIndicator>
                </span>
                {t(`theme.${p}`)}
              </DM.RadioItem>
            ))}
          </DM.RadioGroup>
          <DM.Separator className="my-1 h-px bg-line" />
          <DM.Item className={item} onSelect={() => void logout()}>
            {t('account.signOut')}
          </DM.Item>
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}
