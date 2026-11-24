'use client';

import { useParams } from 'next/navigation';
import { GatewayDetail } from '@/components/p9/gateway-detail';

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <GatewayDetail id={id} />;
}
