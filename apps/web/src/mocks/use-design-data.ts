'use client';

import { useI18n } from '@/i18n/provider';
import { designEn, designNeutral, designTh } from './design-data';

/** Prototype mock data for PREVIEW screens only (never for API-backed screens). */
export function useDesignData() {
  const { locale } = useI18n();
  return { ...(locale === 'th' ? designTh : designEn), ...designNeutral };
}

export type DesignTone = 'ok' | 'warn' | 'stale' | 'crit' | 'info' | 'off';
