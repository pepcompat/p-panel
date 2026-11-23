'use client';

import { useI18n } from '@/i18n/provider';
import {
  APP_METRICS,
  type AppMetric,
  type MetricRange,
  type MetricScope,
  type ServerMetric,
} from '@/lib/api/p5-types';
import { useMetricSeries } from '@/lib/p5-queries';
import { Card } from '@/components/ui/card';
import { MetricChart } from './metric-chart';
import { metricTitleKey } from './bits';

const SERVER_CHARTS: ServerMetric[] = ['cpu', 'memory', 'disk', 'load1', 'net_rx', 'net_tx'];

function SeriesCard({
  scope,
  id,
  metric,
  range,
}: {
  scope: MetricScope;
  id: string;
  metric: ServerMetric | AppMetric;
  range: MetricRange;
}) {
  const { t } = useI18n();
  const q = useMetricSeries(scope, id, metric, range);
  return (
    <Card className="p-3.5">
      <MetricChart
        series={q.data}
        isLoading={q.isPending}
        error={q.error}
        title={t(metricTitleKey(scope === 'app' && metric === 'memory' ? 'memory_bytes' : metric))}
        range={range}
        metricKey={metric}
      />
    </Card>
  );
}

/** Six server charts (cpu/mem/disk/load/net rx/tx) for one server and range. */
export function ServerMetricsPanel({ serverId, range }: { serverId: string; range: MetricRange }) {
  return (
    <div
      className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,420px),1fr))] gap-3"
      data-testid="server-metrics"
    >
      {SERVER_CHARTS.map((m) => (
        <SeriesCard key={m} scope="server" id={serverId} metric={m} range={range} />
      ))}
    </div>
  );
}

export function AppMetricsPanel({ appId, range }: { appId: string; range: MetricRange }) {
  return (
    <div
      className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,420px),1fr))] gap-3"
      data-testid="app-metrics"
    >
      {APP_METRICS.map((m) => (
        <SeriesCard key={m} scope="app" id={appId} metric={m} range={range} />
      ))}
    </div>
  );
}
