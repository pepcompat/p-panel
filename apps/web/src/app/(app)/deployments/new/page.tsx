'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { DeployWizard } from '@/components/p4/deploy-wizard';

function WizardPage() {
  const params = useSearchParams();
  const source = params.get('source');
  return (
    <DeployWizard appId={params.get('app')} initialSource={source === 'git' ? 'git' : undefined} />
  );
}

export default function Page() {
  return (
    <Suspense fallback={null}>
      <WizardPage />
    </Suspense>
  );
}
