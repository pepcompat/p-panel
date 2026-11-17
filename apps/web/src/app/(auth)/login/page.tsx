import { Suspense } from 'react';
import type { Metadata } from 'next';
import { LoginFlow } from '@/components/auth/login-flow';

export const metadata: Metadata = { title: 'Sign in' };

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginFlow />
    </Suspense>
  );
}
