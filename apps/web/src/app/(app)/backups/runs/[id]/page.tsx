'use client';

import { useParams } from 'next/navigation';
import { RunDetailView } from '@/components/p6/run-detail';

export default function Page() {
  const { id } = useParams<{ id: string }>();
  return <RunDetailView id={id} />;
}
