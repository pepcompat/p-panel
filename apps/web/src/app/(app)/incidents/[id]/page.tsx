import { redirect } from 'next/navigation';

/** Notification links (`PPANEL_PUBLIC_WEB_URL/incidents/:id`) open the incident in /alerts. */
export default async function IncidentRedirect({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  redirect(`/alerts?incident=${encodeURIComponent(id)}`);
}
