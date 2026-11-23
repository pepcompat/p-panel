'use client';

import Link from 'next/link';
import { useState } from 'react';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { useApplications, useScans } from '@/lib/p3-queries';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ApplicationsTable } from './applications-view';
import { RunScanDialog } from './imports-view';
import { ScanStatusBadge } from './bits';

/** Server detail → Applications tab (real, P3): apps on this server + latest scan + scan action. */
export function ServerAppsTab({ server }: { server: Server }) {
  const { t } = useI18n();
  const { can } = useAuth();
  const apps = useApplications({ server_id: server.id });
  const scans = useScans({ server_id: server.id });
  const [open, setOpen] = useState(false);
  const last = scans.data?.items[0];
  if (!can('apps.read')) return <ForbiddenState perm="apps.read" />;
  const items = apps.data?.items ?? [];
  const drift = items.filter((a) => a.flags.driftDetected).length;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        {last ? (
          <>
            <span className="text-fg-muted">{t('server.apps.lastScan')}</span>
            <Link href={`/imports/${last.id}`} className="font-mono">
              {last.id.slice(0, 8)}
            </Link>
            <ScanStatusBadge status={last.status} />
          </>
        ) : (
          <span className="text-fg-muted">{t('server.apps.noScan')}</span>
        )}
        <span className="flex-1" />
        <GatedButton size="sm" perm="nginx.read" onClick={() => setOpen(true)}>
          {t('scan.run.open')}
        </GatedButton>
      </div>
      {drift > 0 && (
        <Notice tone="crit" glyph="≠" role="status">
          {t('apps.driftWarning', { n: drift })}
        </Notice>
      )}
      {apps.isError && <ErrorState error={apps.error} onRetry={() => void apps.refetch()} />}
      {apps.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : items.length === 0 && !apps.isError ? (
        <EmptyState title={t('apps.empty')} body={t('server.apps.emptyBody')} />
      ) : (
        items.length > 0 && <ApplicationsTable apps={items} showServer={false} />
      )}
      {open && <RunScanDialog open={open} onOpenChange={setOpen} defaultServerId={server.id} />}
    </div>
  );
}
