import { Suspense } from 'react';
import { LogsView } from '@/components/p5/logs-view';

export const metadata = { title: 'Logs' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <LogsView />
    </Suspense>
  );
}
