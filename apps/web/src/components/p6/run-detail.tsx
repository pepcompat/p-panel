'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { runsApi } from '@/lib/api/p6-endpoints';
import { isApiError, type ApiError } from '@/lib/api/errors';
import type { BackupManifestRow, BackupRun } from '@/lib/api/p6-types';
import { useRun } from '@/lib/p6-queries';
import { formatBytes, lastVerifyError, runGate, targetLabel, verifyingOf } from '@/lib/p6-gates';
import { formatDateTime } from '@/lib/time';
import { envBadgeKey } from '@/lib/servers';
import { Card, DefList, Page } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { useSetPageEnv } from '@/components/shell/page-env';
import { RunStatusBadge, Td, Th, TriggerTag, VerificationBadge } from './bits';

const PAGE = 20;

export function RunDetailView({ id }: { id: string }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const router = useRouter();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const q = useRun(id, page);
  const r = q.data;
  useSetPageEnv(r?.environment);
  const verify = useMutation<BackupRun, ApiError, 'check' | 'restore_test'>({
    mutationFn: (level) => runsApi.verify(id, level),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['backup-runs'], exact: false }),
  });

  if (q.isPending)
    return (
      <Page>
        <div
          role="status"
          aria-busy="true"
          aria-label={t('common.loading')}
          className="flex flex-col gap-3"
        >
          <Skeleton className="h-7 w-72" />
          <Skeleton className="h-40 w-full" />
        </div>
      </Page>
    );
  if (q.isError && !r) {
    const e = q.error;
    return (
      <Page>
        <Link href="/backups?tab=runs" className="self-start text-[13px]">
          {t('bk.run.back')}
        </Link>
        {isApiError(e) && e.status === 404 ? (
          <EmptyState title={t('bk.run.notFound')} />
        ) : isApiError(e) && e.status === 403 ? (
          <ForbiddenState perm="fleet.read" requestId={e.requestId} />
        ) : (
          <ErrorState error={e} onRetry={() => void q.refetch()} />
        )}
      </Page>
    );
  }
  if (!r) return null;
  const verifying = verifyingOf(r);
  const gr = { ...r, verifying };
  const vc = runGate('verify_check', gr, me?.permissions);
  const vr = runGate('verify_restore_test', gr, me?.permissions);
  const rg = runGate('restore', gr, me?.permissions);
  const verifyError = r.verification === 'verify_failed' ? lastVerifyError(r) : null;
  const fileRows = r.manifestEntries.filter(
    (e): e is Extract<BackupManifestRow, { kind: 'file' }> => e.kind === 'file',
  );
  const dbRows = r.manifestEntries.filter(
    (e): e is Extract<BackupManifestRow, { kind: 'database' }> => e.kind === 'database',
  );
  const logs = r.logs ?? [];
  const pages = Math.max(
    1,
    Math.ceil(r.manifestPaginate.total / (r.manifestPaginate.limit || PAGE)),
  );

  return (
    <Page>
      <Link href="/backups?tab=runs" className="self-start text-[13px]">
        {t('bk.run.back')}
      </Link>
      <div
        className="flex flex-wrap items-center gap-2.5"
        data-testid="run-detail"
        data-status={r.status}
        data-verification={r.verification}
      >
        <h1 className="m-0 font-mono text-[22px] font-semibold">
          {t('bk.run.title', { id: r.id.slice(0, 8) })}
        </h1>
        <RunStatusBadge status={r.status} />
        {r.environment && <EnvBadge env={r.environment} label={t(envBadgeKey(r.environment))} />}
        <span className="flex-1" />
        <GatedButton
          perm="backups.create"
          blockedReason={vc.allowed ? undefined : vc.reason}
          disabled={verify.isPending}
          onClick={() => verify.mutate('check')}
          data-testid="verify-check"
        >
          {t('bk.run.verifyCheck')}
        </GatedButton>
        <GatedButton
          perm="backups.create"
          blockedReason={vr.allowed ? undefined : vr.reason}
          disabled={verify.isPending}
          onClick={() => verify.mutate('restore_test')}
          data-testid="verify-restore"
        >
          {t('bk.run.verifyRestore')}
        </GatedButton>
        <GatedButton
          variant="primary"
          perm="backups.restore"
          blockedReason={rg.allowed ? undefined : rg.reason}
          onClick={() => router.push(`/restore/new?runId=${r.id}`)}
          data-testid="restore-action"
        >
          {t('bk.run.restore')}
        </GatedButton>
      </div>
      <VerificationBadge run={gr} showHint />
      {verify.error && <ErrorState error={verify.error} />}
      {r.trigger === 'safety' && r.restoreId && (
        <Notice tone="warn" glyph="▲" role="note">
          {t('bk.run.safetyFor', { id: '' })}
          <Link href={`/restore/new?restoreId=${r.restoreId}`} className="font-mono">
            {r.restoreId.slice(0, 8)}
          </Link>
        </Notice>
      )}
      {r.error && (
        <Notice tone="crit" glyph="✕" role="alert" title={r.error.code}>
          <span data-testid="run-error">{r.error.message}</span>
        </Notice>
      )}
      {verifyError && (
        <Notice
          tone="crit"
          glyph="✕"
          role="alert"
          title={`${t('bk.run.verifyError')} · ${verifyError.code}`}
        >
          {verifyError.message}
        </Notice>
      )}

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Card className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('bk.run.summary')}</h2>
          <DefList
            keyWidth={120}
            rows={[
              [t('bk.run.policy'), r.policyName ?? r.policyId.slice(0, 8)],
              [
                t('bk.run.server'),
                <Link key="s" href={`/servers/${r.serverId}/backups`} className="font-mono">
                  {r.serverName ?? r.serverId.slice(0, 8)}
                </Link>,
              ],
              [t('bk.run.trigger'), <TriggerTag key="tr" trigger={r.trigger} />],
              [
                t('bk.run.started'),
                r.startedAt ? formatDateTime(r.startedAt, locale) : t('common.dash'),
              ],
              [
                t('bk.run.finished'),
                r.finishedAt ? formatDateTime(r.finishedAt, locale) : t('common.dash'),
              ],
              [
                t('bk.run.size'),
                r.manifest
                  ? `${formatBytes(r.manifest.bytes)} · ${t('bk.run.files', { n: r.manifest.files })}`
                  : t('common.dash'),
              ],
              [t('bk.run.job'), r.jobId ?? t('common.dash'), { mono: true }],
            ]}
          />
        </Card>
        <Card className="flex flex-col gap-2 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('bk.run.snapshots')}</h2>
          {r.snapshots.length === 0 ? (
            <p className="m-0 text-[13px] text-fg-muted">{t('bk.run.snapshotsNone')}</p>
          ) : (
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <Th>{t('bk.run.snap.col.id')}</Th>
                  <Th>{t('bk.run.snap.col.target')}</Th>
                  <Th>{t('bk.run.snap.col.size')}</Th>
                </tr>
              </thead>
              <tbody>
                {r.snapshots.map((s) => {
                  const tg = r.targets[s.target];
                  return (
                    <tr key={s.snapshotId}>
                      <Td className="font-mono text-[12.5px]">
                        <span title={s.snapshotId}>{s.shortId ?? s.snapshotId.slice(0, 8)}</span>
                      </Td>
                      <Td className="font-mono text-[12px] break-all">
                        {s.targetType} {tg ? targetLabel(tg) : `#${s.target + 1}`}
                      </Td>
                      <Td className="font-mono text-[12px]">{formatBytes(s.sizeBytes)}</Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <Card className="flex flex-col gap-2 p-4" data-testid="manifest">
        <h2 className="m-0 text-[15px] font-semibold">{t('bk.run.manifest')}</h2>
        {r.manifest.truncated && (
          <Notice tone="warn" glyph="▲" role="note">
            {t('bk.run.manifest.truncated')}
          </Notice>
        )}
        {r.manifestPaginate.total === 0 ? (
          <p className="m-0 text-[13px] text-fg-muted">{t('bk.run.manifest.empty')}</p>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse" aria-label={t('bk.run.manifest')}>
                <thead>
                  <tr>
                    <Th>{t('bk.run.manifest.col.path')}</Th>
                    <Th className="text-right">{t('bk.run.manifest.col.size')}</Th>
                    <Th>{t('bk.run.manifest.col.sha')}</Th>
                  </tr>
                </thead>
                <tbody>
                  {fileRows.map((e) => (
                    <tr key={`${e.target}:${e.path}`} data-testid="manifest-row">
                      <Td className="font-mono text-[12px] break-all">{e.path}</Td>
                      <Td className="text-right font-mono text-[12px] whitespace-nowrap">
                        {formatBytes(e.size)}
                      </Td>
                      <Td className="font-mono text-[11.5px] break-all text-fg-2">{e.sha256}</Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-end gap-2 text-[12.5px]">
              <Button size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                {t('common.previous')}
              </Button>
              <span data-testid="manifest-page">{t('common.page', { page, pages })}</span>
              <Button size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
                {t('common.next')}
              </Button>
            </div>
          </>
        )}
      </Card>

      {dbRows.length > 0 && (
        <Card className="flex flex-col gap-2 p-4" data-testid="db-manifest">
          <h2 className="m-0 text-[15px] font-semibold">{t('bk.run.db')}</h2>
          {dbRows.map((d) => (
            <div key={`${d.target}:${d.database}`} className="flex flex-col gap-1">
              <div className="flex flex-wrap items-center gap-2 text-[13px]">
                <b className="font-mono">
                  {r.targets[d.target] ? targetLabel(r.targets[d.target]!) : d.database}
                </b>
                <span className="text-fg-muted">{r.targets[d.target]?.type}</span>
                <span className="font-mono text-fg-muted">{formatBytes(d.bytes)}</span>
                <span className="text-fg-muted">
                  {t('bk.run.db.total', {
                    tables: d.tables.length,
                    rows: d.tables
                      .reduce((x, y) => x + y.rows, 0)
                      .toLocaleString(locale === 'th' ? 'th-TH' : 'en-US'),
                  })}
                </span>
              </div>
              <table className="w-full max-w-[520px] border-collapse">
                <thead>
                  <tr>
                    <Th>{t('bk.run.db.col.table')}</Th>
                    <Th className="text-right">{t('bk.run.db.col.rows')}</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.tables.map((x) => (
                    <tr key={x.name}>
                      <Td className="font-mono text-[12.5px]">{x.name}</Td>
                      <Td className="text-right font-mono text-[12.5px]">
                        {x.rows.toLocaleString(locale === 'th' ? 'th-TH' : 'en-US')}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </Card>
      )}

      <Card className="flex flex-col gap-2 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('bk.run.logs')}</h2>
        {logs.length === 0 ? (
          <p className="m-0 text-[13px] text-fg-muted">
            {t('bk.run.logsEmpty')} {r.jobId && <code className="font-mono">{r.jobId}</code>}
          </p>
        ) : (
          <pre
            className="m-0 max-h-72 overflow-auto rounded-md bg-terminal px-3 py-2 font-mono text-[11.5px] leading-[1.55] whitespace-pre-wrap text-terminal-fg"
            data-testid="run-logs"
          >
            {logs.join('\n')}
          </pre>
        )}
      </Card>
    </Page>
  );
}
