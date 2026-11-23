'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { RestoreWizard } from '@/components/p6/restore-wizard';

function WizardPage() {
  const p = useSearchParams();
  return (
    <RestoreWizard
      runId={p.get('runId')}
      snapshotId={p.get('snapshotId')}
      restoreId={p.get('restoreId')}
    />
  );
}

export default function Page() {
  return (
    <Suspense fallback={null}>
      <WizardPage />
    </Suspense>
  );
}
