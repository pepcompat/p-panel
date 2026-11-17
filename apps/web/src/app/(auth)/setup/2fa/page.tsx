import type { Metadata } from 'next';
import { TotpSetupFlow } from '@/components/auth/totp-setup';

export const metadata: Metadata = { title: 'Two-factor setup' };

export default function SetupTwoFactorPage() {
  return <TotpSetupFlow />;
}
