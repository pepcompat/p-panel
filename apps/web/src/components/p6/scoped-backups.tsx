'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import type { Application } from '@/lib/api/p3-types';
import { usePolicies, useRuns } from '@/lib/p6-queries';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/states';
import { AppendOnlyNotice } from './bits';
import { VerificationLegend } from './backups-view';
import { PoliciesTable, RunsTable, SnapshotsPanel } from './tables';

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="m-0 text-[15px] font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Scoped({
  kind,
  serverId,
  appId,
  appName,
}: {
  kind: 'server' | 'app';
  serverId: string;
  appId?: string;
  appName?: string;
}) {
  const { t } = useI18n();
  const router = useRouter();
  // The API filters by server; app scoping = policies with a target referencing the app.
  const allPolicies = usePolicies({ server_id: serverId });
  const allRuns = useRuns({ server_id: serverId });
  const mine = (allPolicies.data ?? []).filter(
    (p) =>
      !appId ||
      p.targets.some(
        (t) =>
          (t.type !== 'paths' && t.applicationId === appId) ||
          (t.type === 'paths' && !!appName && t.paths.some((x) => x.includes(`/${appName}`))),
      ),
  );
  const ids = new Set(mine.map((p) => p.id));
  const policies = { ...allPolicies, data: allPolicies.data ? mine : undefined };
  const runs = {
    ...allRuns,
    data: allRuns.data ? allRuns.data.filter((r) => !appId || ids.has(r.policyId)) : undefined,
  };
  const kindLabel = t(kind === 'server' ? 'bk.scoped.kind.server' : 'bk.scoped.kind.app');
  const createHref = `/backups?tab=policies&new=1&server=${serverId}${appId ? `&app=${appId}` : ''}`;
  return (
    <div className="flex flex-col gap-4" data-testid="scoped-backups">
      <div className="flex flex-wrap items-center gap-2">
        <VerificationLegend />
        <span className="flex-1" />
        <Link href="/backups" className="text-[13px]">
          {t('bk.scoped.all')}
        </Link>
      </div>
      <Section title={t('bk.scoped.policies', { kind: kindLabel })}>
        {policies.isError && (
          <ErrorState error={policies.error} onRetry={() => void policies.refetch()} />
        )}
        {policies.isPending ? (
          <TableSkeleton label={t('common.loading')} />
        ) : (policies.data ?? []).length === 0 ? (
          <EmptyState
            title={t('bk.scoped.none', { kind: kindLabel })}
            action={
              <GatedButton
                perm="backups.create"
                variant="primary"
                onClick={() => router.push(createHref)}
              >
                {t('bk.scoped.create')}
              </GatedButton>
            }
          />
        ) : (
          <PoliciesTable policies={policies.data ?? []} compact={kind === 'server'} />
        )}
      </Section>
      <Section title={t('bk.scoped.runs')}>
        {runs.isError && <ErrorState error={runs.error} onRetry={() => void runs.refetch()} />}
        {runs.isPending ? (
          <TableSkeleton label={t('common.loading')} />
        ) : (runs.data ?? []).length === 0 ? (
          <EmptyState title={t('bk.runs.empty')} />
        ) : (
          <RunsTable runs={(runs.data ?? []).slice(0, 10)} compact />
        )}
      </Section>
      {kind === 'server' && (
        <Section title={t('bk.scoped.snapshots')}>
          <SnapshotsPanel serverId={serverId} />
        </Section>
      )}
      <AppendOnlyNotice />
    </div>
  );
}

export function ServerBackupsTab({ server }: { server: Server }) {
  return <Scoped kind="server" serverId={server.id} />;
}

export function AppBackupsTab({ app }: { app: Application }) {
  return <Scoped kind="app" serverId={app.serverId} appId={app.id} appName={app.name} />;
}
