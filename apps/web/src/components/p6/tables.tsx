'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { policiesApi, runsApi } from '@/lib/api/p6-endpoints';
import { isApiError, type ApiError } from '@/lib/api/errors';
import type { BackupPolicy, BackupRun, Restore } from '@/lib/api/p6-types';
import { useSnapshots } from '@/lib/p6-queries';
import { formatBytes, runGate, targetLabel } from '@/lib/p6-gates';
import { evaluateGate } from '@/lib/permissions';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Dialog } from '@/components/ui/dialog';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { envBadgeKey } from '@/lib/servers';
import {
  RestoreStatusBadge,
  RunLink,
  RunStatusBadge,
  TriggerTag,
  Td,
  Th,
  VerificationBadge,
  describeSchedule,
  shortDate,
} from './bits';

function TableWrap({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full border-collapse" aria-label={label}>
        {children}
      </table>
    </div>
  );
}

// ---------------------------------------------------------------- policies

export function PoliciesTable({
  policies,
  onEdit,
  compact,
}: {
  policies: BackupPolicy[];
  onEdit?: (p: BackupPolicy) => void;
  compact?: boolean;
}) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const [queued, setQueued] = useState<{ policyId: string; runId: string } | null>(null);
  const [del, setDel] = useState<BackupPolicy | null>(null);
  const run = useMutation<BackupRun, ApiError, BackupPolicy>({
    mutationFn: (p) => policiesApi.runNow(p.id),
    onSuccess: (r, p) => {
      setQueued({ policyId: p.id, runId: r.id });
      void qc.invalidateQueries({ queryKey: ['backup-runs'], exact: false });
      void qc.invalidateQueries({ queryKey: ['backup-policies'], exact: false });
    },
  });
  const remove = useMutation<unknown, ApiError, BackupPolicy>({
    mutationFn: (p) => policiesApi.remove(p.id, p.version),
    onSuccess: () => {
      setDel(null);
      void qc.invalidateQueries({ queryKey: ['backup-policies'], exact: false });
    },
  });
  return (
    <div className="flex flex-col gap-2">
      {queued && (
        <Notice tone="info" glyph="◆" role="status">
          <span data-testid="run-queued">
            {t('bk.pol.runQueued')}{' '}
            <Link href={`/backups/runs/${queued.runId}`}>{t('bk.pol.viewRun')}</Link>
          </span>
        </Notice>
      )}
      {run.error && <ErrorState error={run.error} />}
      <TableWrap label={t('bk.tab.policies')}>
        <thead>
          <tr>
            <Th>{t('bk.pol.col.name')}</Th>
            {!compact && <Th>{t('bk.pol.col.server')}</Th>}
            <Th>{t('bk.pol.col.targets')}</Th>
            <Th>{t('bk.pol.col.schedule')}</Th>
            <Th>{t('bk.pol.col.last')}</Th>
            <Th>{t('bk.pol.col.actions')}</Th>
          </tr>
        </thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id} data-testid="policy-row" data-name={p.name}>
              <Td>
                <div className="font-medium">{p.name}</div>
                <div className="text-[12px] text-fg-muted">
                  {p.repositoryName ?? p.repositoryId.slice(0, 8)}
                  {!p.enabled && ` · ${t('bk.pol.disabled')}`}
                </div>
              </Td>
              {!compact && (
                <Td>
                  <Link href={`/servers/${p.serverId}/backups`} className="font-mono text-[12.5px]">
                    {p.serverName ?? p.serverId.slice(0, 8)}
                  </Link>
                  {p.environment && (
                    <div>
                      <EnvBadge env={p.environment} label={t(envBadgeKey(p.environment))} />
                    </div>
                  )}
                </Td>
              )}
              <Td>
                <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
                  {p.targets.map((x, i) => (
                    <li key={i} className="text-[12.5px]">
                      <span className="text-fg-muted">{x.type}</span>{' '}
                      <span className="font-mono break-all">{targetLabel(x)}</span>
                    </li>
                  ))}
                </ul>
              </Td>
              <Td>
                <div className="text-[12.5px]">
                  {describeSchedule(p.schedule.cron, p.schedule.timezone, t)}
                </div>
                <code className="font-mono text-[11.5px] text-fg-muted">{p.schedule.cron}</code>
                {p.nextRunAt && (
                  <div className="text-[12px] text-fg-muted">
                    {t('bk.pol.col.next')}: {shortDate(p.nextRunAt, locale)}
                  </div>
                )}
              </Td>
              <Td>
                {p.lastRun ? (
                  <div className="flex flex-col items-start gap-1">
                    <RunLink id={p.lastRun.id} />
                    <VerificationBadge
                      run={{ ...p.lastRun, verifiedAt: null, error: null, verifying: null }}
                    />
                  </div>
                ) : (
                  <span className="text-[12px] text-fg-muted">{t('bk.pol.never')}</span>
                )}
              </Td>
              <Td>
                <div className="flex flex-wrap gap-1.5">
                  <GatedButton
                    size="sm"
                    variant="primary"
                    perm="backups.create"
                    action="run"
                    allowedActions={p.allowedActions}
                    disabled={run.isPending}
                    onClick={() => run.mutate(p)}
                    data-testid="run-now"
                  >
                    {t('bk.pol.runNow')}
                  </GatedButton>
                  {onEdit && (
                    <GatedButton
                      size="sm"
                      perm="backups.create"
                      action="edit"
                      allowedActions={p.allowedActions}
                      onClick={() => onEdit(p)}
                    >
                      {t('bk.pol.edit')}
                    </GatedButton>
                  )}
                  {onEdit && (
                    <GatedButton
                      size="sm"
                      variant="ghost"
                      perm="backups.create"
                      action="delete"
                      allowedActions={p.allowedActions}
                      onClick={() => setDel(p)}
                    >
                      {t('bk.pol.delete')}
                    </GatedButton>
                  )}
                </div>
              </Td>
            </tr>
          ))}
        </tbody>
      </TableWrap>
      <Dialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={t('bk.pol.deleteTitle', { name: del?.name ?? '' })}
        description={t('bk.pol.deleteBody')}
        closeLabel={t('common.close')}
        footer={
          <>
            <Button onClick={() => setDel(null)}>{t('common.cancel')}</Button>
            <Button
              variant="danger"
              disabled={
                remove.isPending ||
                !evaluateGate({ permissions: me?.permissions, perm: 'backups.create' }).allowed
              }
              onClick={() => del && remove.mutate(del)}
            >
              {t('bk.pol.delete')}
            </Button>
          </>
        }
      >
        {remove.error && <ErrorState error={remove.error} />}
      </Dialog>
    </div>
  );
}

// ---------------------------------------------------------------- runs

export function RunsTable({ runs, compact }: { runs: BackupRun[]; compact?: boolean }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const router = useRouter();
  const qc = useQueryClient();
  const now = useNow(10_000);
  const verify = useMutation<BackupRun, ApiError, { id: string; level: 'check' | 'restore_test' }>({
    mutationFn: ({ id, level }) => runsApi.verify(id, level),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['backup-runs'], exact: false }),
  });
  return (
    <div className="flex flex-col gap-2">
      {verify.error && <ErrorState error={verify.error} />}
      <TableWrap label={t('bk.tab.runs')}>
        <thead>
          <tr>
            <Th>{t('bk.runs.col.run')}</Th>
            {!compact && <Th>{t('bk.runs.col.policy')}</Th>}
            <Th>{t('bk.runs.col.status')}</Th>
            <Th>{t('bk.runs.col.verification')}</Th>
            <Th>{t('bk.runs.col.size')}</Th>
            <Th>{t('bk.runs.col.actions')}</Th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => {
            const vc = runGate('verify_check', r, me?.permissions);
            const vr = runGate('verify_restore_test', r, me?.permissions);
            const rg = runGate('restore', r, me?.permissions);
            return (
              <tr key={r.id} data-testid="run-row" data-run-id={r.id} data-status={r.status}>
                <Td>
                  <RunLink id={r.id} />
                  <div className="flex flex-wrap items-center gap-1 text-[12px] text-fg-muted">
                    <TriggerTag trigger={r.trigger} />
                    <span title={formatDateTime(r.createdAt, locale)}>
                      {relativeTime(r.createdAt, t, now)}
                    </span>
                  </div>
                </Td>
                {!compact && (
                  <Td>
                    <div>{r.policyName ?? r.policyId.slice(0, 8)}</div>
                    <div className="font-mono text-[12px] text-fg-muted">{r.serverName}</div>
                  </Td>
                )}
                <Td>
                  <RunStatusBadge status={r.status} />
                  {r.error && (
                    <div className="mt-0.5 font-mono text-[11.5px] text-crit">{r.error.code}</div>
                  )}
                </Td>
                <Td>
                  <VerificationBadge run={r} />
                </Td>
                <Td className="font-mono text-[12px]">
                  {r.status === 'uploaded' ? formatBytes(r.manifest.bytes) : t('common.dash')}
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-1.5">
                    <GatedButton
                      size="xs"
                      perm="backups.create"
                      blockedReason={vc.allowed ? undefined : vc.reason}
                      disabled={verify.isPending}
                      onClick={() => verify.mutate({ id: r.id, level: 'check' })}
                      data-testid="verify-check"
                    >
                      {t('bk.run.verifyCheck')}
                    </GatedButton>
                    <GatedButton
                      size="xs"
                      perm="backups.create"
                      blockedReason={vr.allowed ? undefined : vr.reason}
                      disabled={verify.isPending}
                      onClick={() => verify.mutate({ id: r.id, level: 'restore_test' })}
                      data-testid="verify-restore"
                    >
                      {t('bk.run.verifyRestore')}
                    </GatedButton>
                    <GatedButton
                      size="xs"
                      variant="primary"
                      perm="backups.restore"
                      blockedReason={rg.allowed ? undefined : rg.reason}
                      onClick={() => router.push(`/restore/new?runId=${r.id}`)}
                      data-testid="restore-action"
                    >
                      {t('bk.run.restore')}
                    </GatedButton>
                  </div>
                </Td>
              </tr>
            );
          })}
        </tbody>
      </TableWrap>
    </div>
  );
}

// ---------------------------------------------------------------- live snapshots

export function SnapshotsPanel({ serverId }: { serverId: string }) {
  const { t, locale } = useI18n();
  const router = useRouter();
  const { me } = useAuth();
  const q = useSnapshots(serverId);
  const canRestore = evaluateGate({ permissions: me?.permissions, perm: 'backups.restore' });
  if (q.isPending) return <TableSkeleton label={t('common.loading')} />;
  if (q.isError) {
    const code = isApiError(q.error) ? q.error.code : null;
    if (code === 'AGENT_OFFLINE')
      return (
        <Notice tone="warn" glyph="◐" role="status">
          <span data-testid="snapshots-offline">{t('bk.snap.offline')}</span>
        </Notice>
      );
    if (isApiError(q.error) && q.error.status === 403)
      return (
        <Notice tone="neutral" glyph="◆" role="note">
          <span data-testid="snapshots-forbidden">{t('bk.snap.forbidden')}</span>
        </Notice>
      );
    if (code === 'REPO_NOT_INITIALIZED' || code === 'REPO_ACCESS_MISSING')
      return (
        <Notice tone="warn" glyph="▲" role="status">
          {t('bk.snap.notInit')}
        </Notice>
      );
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  }
  const d = q.data;
  if (d.pending || !Array.isArray(d.snapshots))
    return (
      <div
        role="status"
        aria-busy="true"
        className="flex items-center gap-2 text-[13px] text-fg-muted"
        data-testid="snapshots-pending"
      >
        <span aria-hidden="true">◌</span>
        {t('bk.snap.pending', { job: d.jobId?.slice(0, 8) ?? '' })}
      </div>
    );
  const runOf = (tags: string[]) => tags.find((x) => x.startsWith('run='))?.slice(4) ?? null;
  return (
    <div className="flex flex-col gap-2" data-testid="snapshots-panel">
      <div className="flex flex-wrap items-center gap-2 text-[12.5px] text-fg-muted">
        <span className="flex-1">
          {t('bk.snap.live', {
            time: formatDateTime(new Date(q.dataUpdatedAt).toISOString(), locale),
          })}
        </span>
        <Button size="sm" onClick={() => void q.refetch()} disabled={q.isFetching}>
          {t('common.refresh')}
        </Button>
      </div>
      {d.snapshots.length === 0 ? (
        <EmptyState title={t('bk.snap.empty')} />
      ) : (
        <TableWrap label={t('bk.tab.snapshots')}>
          <thead>
            <tr>
              <Th>{t('bk.snap.col.id')}</Th>
              <Th>{t('bk.snap.col.time')}</Th>
              <Th>{t('bk.snap.col.paths')}</Th>
              <Th>{t('bk.snap.col.size')}</Th>
              <Th>{t('bk.snap.col.run')}</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {d.snapshots.map((x) => {
              const runId = runOf(x.tags);
              return (
                <tr key={x.id} data-testid="snapshot-row">
                  <Td className="font-mono text-[12.5px]">
                    <span title={x.id}>{x.shortId ?? x.id.slice(0, 8)}</span>
                  </Td>
                  <Td className="text-[12.5px]">
                    {x.time ? formatDateTime(x.time, locale) : t('common.dash')}
                  </Td>
                  <Td>
                    <span className="font-mono text-[12px] break-all">{x.paths.join(', ')}</span>
                    <div className="text-[11.5px] text-fg-muted">
                      {x.tags
                        .filter((g) => !g.startsWith('run=') && !g.startsWith('policy='))
                        .join(' ')}
                    </div>
                  </Td>
                  <Td className="font-mono text-[12px]">{formatBytes(x.sizeBytes)}</Td>
                  <Td>{runId ? <RunLink id={runId} /> : t('common.dash')}</Td>
                  <Td>
                    {runId && (
                      <GatedButton
                        size="xs"
                        perm="backups.restore"
                        blockedReason={canRestore.allowed ? undefined : canRestore.reason}
                        onClick={() =>
                          router.push(`/restore/new?runId=${runId}&snapshotId=${x.id}`)
                        }
                      >
                        {t('bk.run.restore')}
                      </GatedButton>
                    )}
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </TableWrap>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- restores

export function RestoresTable({ restores }: { restores: Restore[] }) {
  const { t, locale } = useI18n();
  return (
    <TableWrap label={t('bk.tab.restores')}>
      <thead>
        <tr>
          <Th>{t('bk.rs.col.id')}</Th>
          <Th>{t('bk.rs.col.target')}</Th>
          <Th>{t('bk.rs.col.status')}</Th>
          <Th>{t('bk.rs.col.created')}</Th>
          <Th />
        </tr>
      </thead>
      <tbody>
        {restores.map((r) => (
          <tr key={r.id} data-testid="restore-row" data-status={r.status}>
            <Td>
              <span className="font-mono text-[12.5px]">{r.id.slice(0, 8)}</span>
              <div className="font-mono text-[12px] text-fg-muted">
                {r.serverName} · {r.snapshotId.slice(0, 8)}
              </div>
            </Td>
            <Td>
              <span className="text-[12px] text-fg-muted">{r.target.type}</span>{' '}
              <span className="font-mono text-[12.5px]">
                {r.target.type === 'paths'
                  ? (r.target.include ?? []).join(', ') || '*'
                  : r.target.type === 'volume'
                    ? `${r.target.app}/${r.target.volume}`
                    : `${r.target.app}/${r.target.service}/${r.target.database}`}
              </span>
              <div
                className={
                  r.target.mode === 'in_place'
                    ? 'text-[12px] font-medium text-crit'
                    : 'text-[12px] text-fg-muted'
                }
              >
                {t(`rs.mode.${r.target.mode}`)}
              </div>
            </Td>
            <Td>
              <RestoreStatusBadge status={r.status} />
            </Td>
            <Td className="text-[12.5px]">
              {formatDateTime(r.createdAt, locale)}
              <div className="text-[12px] text-fg-muted">{r.createdByLabel}</div>
            </Td>
            <Td>
              <Link href={`/restore/new?restoreId=${r.id}`} className="text-[13px]">
                {t('bk.rs.open')}
              </Link>
            </Td>
          </tr>
        ))}
      </tbody>
    </TableWrap>
  );
}
