'use client';

import { notFound, useParams } from 'next/navigation';
import { ServerDetail } from '@/components/servers/detail/server-detail';
import { isServerTab } from '@/lib/servers';

export default function ServerTabPage() {
  const { id, tab } = useParams<{ id: string; tab: string }>();
  if (!isServerTab(tab)) notFound();
  return <ServerDetail id={id} tab={tab} />;
}
