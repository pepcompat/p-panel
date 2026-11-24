import { Suspense } from 'react';
import { ConnectivityView } from '@/components/p9/connectivity-view';

export const metadata = { title: 'Network · Connectivity' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <ConnectivityView />
    </Suspense>
  );
}
