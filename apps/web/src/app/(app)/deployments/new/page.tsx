'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { DeployWizard } from '@/components/p4/deploy-wizard';

function WizardPage() {
  const params = useSearchParams();
  return <DeployWizard appId={params.get('app')} />;
}

export default function Page() {
  return (
    <Suspense fallback={null}>
      <WizardPage />
    </Suspense>
  );
}
