'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useI18n } from '@/i18n/provider';
import { isMetricRange, type MetricRange } from '@/lib/api/p5-types';
import { AppMetricsPanel } from './metrics-panels';
import { RangePicker } from './bits';

/** Application → Metrics tab: container cpu / memory / up / restarts with a URL-carried range. */
export function AppMetricsTab({ appId }: { appId: string }) {
  const { t } = useI18n();
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const raw = sp.get('range');
  const range: MetricRange = isMetricRange(raw) ? raw : '1h';
  return (
    <div className="flex flex-col gap-3" data-testid="app-metrics-tab" data-range={range}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex-1 text-[12.5px] text-fg-muted">{t('mon.appSubtitle')}</span>
        <RangePicker
          value={range}
          onChange={(r) =>
            router.replace(`${pathname}${r === '1h' ? '' : `?range=${r}`}`, { scroll: false })
          }
        />
      </div>
      <AppMetricsPanel appId={appId} range={range} />
    </div>
  );
}
