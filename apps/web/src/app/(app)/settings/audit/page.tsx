import { Suspense } from 'react';
import { AuditView } from '@/components/settings/audit-view';

export default function AuditPage() {
  return (
    <Suspense fallback={null}>
      <AuditView />
    </Suspense>
  );
}
