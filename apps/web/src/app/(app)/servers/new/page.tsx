'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useT } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { Page, PageHeader } from '@/components/ui/card';
import { ForbiddenState } from '@/components/ui/states';
import { EnrollWizard } from '@/components/servers/enroll-wizard';

export default function EnrollServerPage() {
  const t = useT();
  const router = useRouter();
  const { can } = useAuth();
  return (
    <Page>
      <Link href="/servers" className="self-start text-[13px]">
        {t('detail.back')}
      </Link>
      <PageHeader title={t('enroll.title')} subtitle={t('enroll.pageSubtitle')} />
      <div className="max-w-[560px] rounded-lg border border-line bg-surface p-[18px]">
        {can('servers.enroll') ? (
          <EnrollWizard onClose={() => router.push('/servers')} />
        ) : (
          <ForbiddenState perm="servers.enroll" />
        )}
      </div>
    </Page>
  );
}
