'use client';

import { useI18n } from '@/i18n/provider';
import { Page, PageHeader } from '@/components/ui/card';
import { LogExplorer } from './log-explorer';

export function LogsView() {
  const { t } = useI18n();
  return (
    <Page>
      <PageHeader title={t('logs.pageTitle')} subtitle={t('logs.pageSubtitle')} />
      <LogExplorer syncUrl />
    </Page>
  );
}
