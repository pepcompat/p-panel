'use client';

import { useParams } from 'next/navigation';
import { PlanDetail } from '@/components/p9/plan-detail';

export default function Page() {
  const { id, planId } = useParams<{ id: string; planId: string }>();
  return <PlanDetail gatewayId={id} planId={planId} />;
}
