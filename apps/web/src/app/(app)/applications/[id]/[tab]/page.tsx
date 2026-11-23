'use client';

import { notFound, useParams } from 'next/navigation';
import { ApplicationDetail, isAppTab } from '@/components/p3/application-detail';

export default function ApplicationTabPage() {
  const { id, tab } = useParams<{ id: string; tab: string }>();
  if (!isAppTab(tab)) notFound();
  return <ApplicationDetail id={id} tab={tab} />;
}
