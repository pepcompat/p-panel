'use client';

import { useI18n } from '@/i18n/provider';
import { Segmented } from '@/components/ui/segmented';
import type { Locale } from '@/i18n/core';

export function LangToggle({ className }: { className?: string }) {
  const { locale, setLocale, t } = useI18n();
  return (
    <Segmented<Locale>
      label={t('top.language')}
      value={locale}
      onChange={setLocale}
      mono
      className={className}
      options={[
        { value: 'en', label: 'EN' },
        { value: 'th', label: 'TH' },
      ]}
    />
  );
}
