import { Suspense } from 'react';
import { MonitoringView } from '@/components/p5/monitoring-view';

export const metadata = { title: 'Monitoring' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <MonitoringView />
    </Suspense>
  );
}
