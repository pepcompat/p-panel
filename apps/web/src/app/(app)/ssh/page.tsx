import { Suspense } from 'react';
import { SshView } from '@/components/p10/ssh-view';

export const metadata = { title: 'SSH & Credentials' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <SshView />
    </Suspense>
  );
}
