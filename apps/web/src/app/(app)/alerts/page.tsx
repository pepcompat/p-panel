import { Suspense } from 'react';
import { AlertsView } from '@/components/p5/alerts-view';

export const metadata = { title: 'Alerts' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <AlertsView />
    </Suspense>
  );
}
