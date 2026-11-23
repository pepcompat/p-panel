'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { useServers } from '@/lib/queries';
import { usePolicies, useRestores, useRuns } from '@/lib/p6-queries';
import { RUN_STATUSES, type BackupPolicy } from '@/lib/api/p6-types';
import { cn } from '@/lib/utils';
import { Page, PageHeader } from '@/components/ui/card';
import { Field, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/states';
import { ToneBadge } from '@/components/ui/badge';
import type { MessageKey } from '@/i18n/en';
import { AppendOnlyNotice } from './bits';
import { PolicyForm } from './policy-form';
import { RepositoriesTab } from './repositories';
import { PoliciesTable, RestoresTable, RunsTable, SnapshotsPanel } from './tables';

export const BACKUP_TABS = ['policies', 'runs', 'snapshots', 'repositories', 'restores'] as const;
export type BackupTab = (typeof BACKUP_TABS)[number];

export function VerificationLegend() {
  const { t } = useI18n();
  return (
    <div
      className="flex flex-wrap gap-x-4 gap-y-1 text-[12.5px]"
      aria-label={t('bk.legend')}
      role="note"
    >
      <span className="inline-flex items-center gap-1.5">
        <ToneBadge tone="stale" size="sm">
          {t('bk.ver.notVerified')}
        </ToneBadge>
        <span className="text-fg-muted">{t('bk.legend.none')}</span>
      </span>
      <span className="inline-flex items-center gap-1.5">
        <ToneBadge tone="info" size="sm">
          {t('bk.ver.repoChecked')}
        </ToneBadge>
        <span className="text-fg-muted">{t('bk.legend.checked')}</span>
      </span>
      <span className="inline-flex items-center gap-1.5">
        <ToneBadge tone="ok" size="sm">
          {t('bk.ver.restoreVerified')}
        </ToneBadge>
        <span className="text-fg-muted">{t('bk.legend.verified')}</span>
      </span>
    </div>
  );
}

export function BackupsView() {
  const { t } = useI18n();
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const raw = params.get('tab');
  const tab: BackupTab = (BACKUP_TABS as readonly string[]).includes(raw ?? '')
    ? (raw as BackupTab)
    : 'policies';
  const setTab = (k: BackupTab) => {
    const sp = new URLSearchParams(params.toString());
    sp.set('tab', k);
    sp.delete('new');
    router.replace(`${pathname}?${sp.toString()}`, { scroll: false });
  };
  return (
    <Page>
      <PageHeader title={t('bk.title')} subtitle={t('bk.subtitle')} />
      <VerificationLegend />
      <nav aria-label={t('bk.tabs')} className="flex gap-0.5 overflow-x-auto border-b border-line">
        {BACKUP_TABS.map((k) => (
          <button
            key={k}
            type="button"
            aria-current={k === tab ? 'page' : undefined}
            onClick={() => setTab(k)}
            data-testid={`bk-tab-${k}`}
            className={cn(
              'flex min-h-10 shrink-0 items-center border-0 border-b-2 bg-transparent px-3 text-[13px] whitespace-nowrap',
              k === tab
                ? 'border-accent-strong font-medium text-fg'
                : 'border-transparent text-fg-muted hover:text-fg',
            )}
          >
            {t(`bk.tab.${k}` as MessageKey)}
          </button>
        ))}
      </nav>
      {tab === 'policies' && (
        <PoliciesTab
          openNew={params.get('new') === '1'}
          initialServer={params.get('server') ?? ''}
          initialApp={params.get('app') ?? undefined}
        />
      )}
      {tab === 'runs' && <RunsTab />}
      {tab === 'snapshots' && <SnapshotsTab initialServer={params.get('server') ?? ''} />}
      {tab === 'repositories' && <RepositoriesTab />}
      {tab === 'restores' && <RestoresTab />}
    </Page>
  );
}

function PoliciesTab({
  openNew,
  initialServer,
  initialApp,
}: {
  openNew: boolean;
  initialServer: string;
  initialApp?: string;
}) {
  const { t } = useI18n();
  const q = usePolicies();
  const [editing, setEditing] = useState<BackupPolicy | 'new' | null>(openNew ? 'new' : null);
  useEffect(() => {
    if (openNew) setEditing('new');
  }, [openNew]);
  if (editing)
    return (
      <PolicyForm
        policy={editing === 'new' ? null : editing}
        initial={
          editing === 'new' ? { serverId: initialServer, applicationId: initialApp } : undefined
        }
        onDone={() => setEditing(null)}
        onCancel={() => setEditing(null)}
      />
    );
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex-1" />
        <GatedButton
          perm="backups.create"
          variant="primary"
          onClick={() => setEditing('new')}
          data-testid="policy-new"
        >
          {t('bk.pol.new')}
        </GatedButton>
      </div>
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : (q.data ?? []).length === 0 ? (
        <EmptyState title={t('bk.pol.empty')} body={t('bk.pol.emptyBody')} />
      ) : (
        <PoliciesTable policies={q.data ?? []} onEdit={(p) => setEditing(p)} />
      )}
    </div>
  );
}

function RunsTab() {
  const { t } = useI18n();
  const [status, setStatus] = useState('');
  const q = useRuns(status ? { status } : {});
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-2">
        <Field label={t('bk.runs.filter')} className="w-[220px]">
          {(p) => (
            <Select {...p} value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">{t('common.all')}</option>
              {RUN_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {t(`bk.run.status.${s}` as MessageKey)}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : (q.data ?? []).length === 0 ? (
        <EmptyState title={t('bk.runs.empty')} body={t('bk.runs.emptyBody')} />
      ) : (
        <RunsTable runs={q.data ?? []} />
      )}
    </div>
  );
}

function SnapshotsTab({ initialServer }: { initialServer: string }) {
  const { t } = useI18n();
  const servers = useServers();
  const [serverId, setServerId] = useState(initialServer);
  return (
    <div className="flex flex-col gap-3">
      <Field label={t('bk.snap.server')} className="w-[280px]">
        {(p) => (
          <Select {...p} value={serverId} onChange={(e) => setServerId(e.target.value)}>
            <option value="">{t('bk.form.serverPick')}</option>
            {(servers.data?.items ?? []).map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {serverId ? <SnapshotsPanel serverId={serverId} /> : <EmptyState title={t('bk.snap.pick')} />}
    </div>
  );
}

function RestoresTab() {
  const { t } = useI18n();
  const q = useRestores();
  const { can } = useAuth();
  return (
    <div className="flex flex-col gap-3">
      {!can('backups.restore') && <AppendOnlyNotice />}
      {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : (q.data ?? []).length === 0 ? (
        <EmptyState title={t('bk.rs.empty')} body={t('bk.rs.emptyBody')} />
      ) : (
        <RestoresTable restores={q.data ?? []} />
      )}
    </div>
  );
}
