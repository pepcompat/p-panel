'use client';

import { Suspense } from 'react';
import { notFound, useParams } from 'next/navigation';
import { ApplicationDetail, isAppTab } from '@/components/p3/application-detail';

export default function ApplicationTabPage() {
  const { id, tab } = useParams<{ id: string; tab: string }>();
  if (!isAppTab(tab)) notFound();
  return (
    <Suspense fallback={null}>
      <ApplicationDetail id={id} tab={tab} />
    </Suspense>
  );
}
