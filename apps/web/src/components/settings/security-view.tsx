'use client';

import Link from 'next/link';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { Card } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { PreviewBanner } from '@/components/ui/states';
import { RecoveryCard } from '@/components/p6/recovery-card';

export function SecurityView() {
  const t = useT();
  const { me } = useAuth();
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,380px),1fr))] items-start gap-4">
      <Card className="flex flex-col gap-2.5 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('security.mfa')}</h2>
        <ToneBadge tone={me?.mfaEnabled ? 'ok' : 'warn'} className="self-start">
          {me?.mfaEnabled ? t('account.mfaOn') : t('account.mfaOff')}
        </ToneBadge>
        <p className="m-0 text-[13px] text-fg-3">
          {me?.mfaEnabled ? t('security.mfaOn') : t('security.mfaOff')}
        </p>
        {!me?.mfaEnabled && (
          <Link
            href="/setup/2fa"
            className="self-start rounded-md bg-accent-strong px-3.5 py-2 text-[13.5px] text-on-accent no-underline hover:text-on-accent hover:no-underline"
          >
            {t('security.setup')}
          </Link>
        )}
      </Card>
      <Card className="flex flex-col gap-2.5 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('security.sessions')}</h2>
        <PreviewBanner />
        <p className="m-0 text-[13px] text-fg-3">{t('users.policyNote')}</p>
      </Card>
      <RecoveryCard />
    </div>
  );
}
