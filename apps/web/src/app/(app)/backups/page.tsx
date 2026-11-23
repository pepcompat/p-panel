'use client';

import { Suspense } from 'react';
import { BackupsView } from '@/components/p6/backups-view';

export default function Page() {
  return (
    <Suspense fallback={null}>
      <BackupsView />
    </Suspense>
  );
}
