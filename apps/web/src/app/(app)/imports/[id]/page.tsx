'use client';

import { useParams } from 'next/navigation';
import { ScanDetail } from '@/components/p3/scan-detail';

export default function ScanPage() {
  const { id } = useParams<{ id: string }>();
  return <ScanDetail id={id} />;
}
