import type { Metadata } from 'next';
import { GroupsView } from '@/components/p9/groups-view';

export const metadata: Metadata = { title: 'Server groups' };

export default function GroupsPage() {
  return <GroupsView />;
}
