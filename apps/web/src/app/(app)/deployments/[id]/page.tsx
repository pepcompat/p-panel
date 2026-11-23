'use client';

import { useParams } from 'next/navigation';
import { DeploymentDetailView } from '@/components/p4/deployments-view';

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <DeploymentDetailView id={id} />;
}
