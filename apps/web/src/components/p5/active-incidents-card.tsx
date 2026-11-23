'use client';

import Link from 'next/link';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { useActiveIncidents } from '@/lib/p5-queries';
import { relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { Card, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ui/states';
import { IncidentStatusBadge, SeverityBadge } from './bits';

/** Overview card: open (firing + acknowledged) incidents with a count and links into /alerts. */
export function ActiveIncidentsCard() {
  const { t } = useI18n();
  const { can } = useAuth();
  const now = useNow(30_000);
  const q = useActiveIncidents(can('fleet.read'));
  const firing = q.active.filter((i) => i.status === 'firing').length;
  return (
    <Card data-testid="overview-incidents">
      <CardHeader
        title={
          <span className="inline-flex items-center gap-2">
            {t('overview.incidents')}
            <span
              className="rounded bg-chip px-1.5 font-mono text-[12px]"
              data-testid="active-incident-count"
            >
              {q.data ? q.active.length : '—'}
            </span>
          </span>
        }
        actions={
          <Link href="/alerts" className="text-[13px]">
            {t('overview.viewIncidents', { n: firing })}
          </Link>
        }
      />
      {q.isPending ? (
        <div className="flex flex-col gap-2 p-4">
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ) : q.isError ? (
        <div className="p-3">
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        </div>
      ) : q.active.length === 0 ? (
        <p className="m-0 px-4 py-3 text-[13px] text-fg-muted">{t('overview.noIncidents')}</p>
      ) : (
        q.active.slice(0, 5).map((i) => (
          <Link
            key={i.id}
            href={`/alerts?incident=${i.id}`}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line-subtle px-4 py-2.5 text-fg no-underline first:border-0 hover:bg-surface-hover hover:no-underline"
          >
            <SeverityBadge severity={i.severity} />
            <span className="min-w-0 flex-1">
              <span className="block text-[13.5px]">
                <span className="font-mono">{i.ruleName || (i.ruleId ?? '').slice(0, 8)}</span> ·{' '}
                <span className="font-mono">{i.target.name}</span>
              </span>
              <span className="block text-[12px] text-fg-subtle">
                {t('inc.started', { ago: relativeTime(i.startedAt, t, now) })}
              </span>
            </span>
            <IncidentStatusBadge status={i.status} />
          </Link>
        ))
      )}
    </Card>
  );
}
