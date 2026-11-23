'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { repositoriesApi } from '@/lib/api/p6-endpoints';
import type { ApiError } from '@/lib/api/errors';
import {
  MAINTENANCE_KINDS,
  type BackupRepository,
  type MaintenanceStatus,
  type RecoveryExport,
} from '@/lib/api/p6-types';
import { useRepositories } from '@/lib/p6-queries';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { Card, DefList } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CopyButton } from '@/components/ui/copy-button';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { StepUpField } from '@/components/p3/bits';
import { wrap } from '@/components/p3/action-dialog';
import { AppendOnlyNotice, Td, Th } from './bits';

export function RepositoriesTab() {
  const { t } = useI18n();
  const q = useRepositories();
  if (q.isPending) return <TableSkeleton label={t('common.loading')} />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <div className="flex flex-col gap-4">
      <AppendOnlyNotice />
      {q.data.length === 0 && <EmptyState title={t('common.noData')} />}
      {q.data.map((r) => (
        <RepositoryCard key={r.id} repo={r} />
      ))}
    </div>
  );
}

function latest(reports: MaintenanceStatus[], kind: string) {
  return reports
    .filter((x) => x.kind === kind)
    .sort((a, b) => b.finishedAt.localeCompare(a.finishedAt))[0];
}
/** Report `detail` is free-form JSON from the operator script: show its message or a compact summary. */
function detailText(d: Record<string, unknown>): string {
  if (typeof d.message === 'string') return d.message;
  if (typeof d.error === 'string') return d.error;
  const s = JSON.stringify(d);
  return s === '{}' ? '' : s.slice(0, 200);
}

function RepositoryCard({ repo }: { repo: BackupRepository }) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const mark = useMutation<BackupRepository, ApiError, string>({
    mutationFn: (serverId) => repositoriesApi.markInitialized(repo.id, serverId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['backup-repositories'] }),
  });
  return (
    <Card className="flex flex-col gap-3 p-4" data-testid="repo-card">
      <h2 className="m-0 font-mono text-[16px] font-semibold">{repo.name}</h2>
      <DefList
        keyWidth={170}
        rows={[
          [t('bk.repo.baseUrl'), repo.baseUrl, { mono: true }],
          [
            t('bk.repo.offsite'),
            repo.offsite
              ? `s3 · ${repo.offsite.endpoint} · ${repo.offsite.bucket}`
              : t('bk.repo.offsiteNone'),
            { mono: !!repo.offsite },
          ],
          [t('bk.repo.password'), t('bk.repo.passwordSet')],
        ]}
      />
      <h3 className="m-0 text-[14px] font-semibold">{t('bk.repo.access')}</h3>
      <p className="m-0 text-[12.5px] text-fg-muted">{t('bk.repo.maint.note')}</p>
      {mark.error && <ErrorState error={mark.error} />}
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full border-collapse" aria-label={t('bk.repo.access')}>
          <thead>
            <tr>
              <Th>{t('bk.repo.col.server')}</Th>
              <Th>{t('bk.repo.col.initialized')}</Th>
              <Th>{t('bk.repo.col.maintenance')}</Th>
            </tr>
          </thead>
          <tbody>
            {repo.servers.map((a) => (
              <tr key={a.serverId} data-testid="repo-access" data-server={a.serverName}>
                <Td>
                  <div className="font-mono text-[12.5px]">
                    {a.serverName ?? a.serverId.slice(0, 8)}
                  </div>
                  <div className="font-mono text-[11.5px] text-fg-muted">
                    {t('bk.repo.col.user')}: {a.restUser}
                  </div>
                </Td>
                <Td>
                  {a.initialized ? (
                    <ToneBadge tone="ok">
                      {t('bk.repo.initYes', {
                        date: a.initializedAt ? formatDateTime(a.initializedAt, locale) : '',
                      })}
                    </ToneBadge>
                  ) : (
                    <div
                      className="flex flex-col items-start gap-1.5"
                      data-testid="repo-not-initialized"
                    >
                      <ToneBadge tone="warn">{t('bk.repo.initNo')}</ToneBadge>
                      <span className="text-[12px] text-fg-2">{t('bk.repo.initCmd')}</span>
                      <span className="flex items-center gap-1">
                        <code
                          className="rounded bg-terminal px-2 py-1 font-mono text-[12px] text-terminal-fg"
                          data-testid="init-command"
                        >
                          scripts/backup/maintenance.sh init {a.restUser}
                        </code>
                        <CopyButton
                          text={`scripts/backup/maintenance.sh init ${a.restUser}`}
                          ariaLabel={t('common.copy')}
                        />
                      </span>
                      <GatedButton
                        size="xs"
                        perm="policies.manage"
                        action="mark_initialized"
                        allowedActions={repo.allowedActions}
                        disabled={mark.isPending}
                        onClick={() => mark.mutate(a.serverId)}
                      >
                        {t('bk.repo.markInit')}
                      </GatedButton>
                    </div>
                  )}
                </Td>
                <Td>
                  <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
                    {MAINTENANCE_KINDS.filter(
                      (k) => k !== 'unlock' || latest(a.maintenance, k),
                    ).map((k) => {
                      const r = latest(a.maintenance, k);
                      return (
                        <li
                          key={k}
                          className="flex flex-wrap items-center gap-1.5 text-[12.5px]"
                          data-testid="maint"
                          data-kind={k}
                          data-ok={r ? String(r.ok) : 'none'}
                        >
                          <span className="w-[92px] text-fg-muted">
                            {t(`bk.repo.maint.kind.${k}` as MessageKey)}
                          </span>
                          {r ? (
                            <>
                              <ToneBadge tone={r.ok ? 'ok' : 'crit'} size="sm">
                                {t(r.ok ? 'bk.repo.maint.ok' : 'bk.repo.maint.failed')}
                              </ToneBadge>
                              <span className="text-[11.5px] text-fg-muted">
                                {formatDateTime(r.finishedAt, locale)}
                              </span>
                              {!r.ok && detailText(r.detail) && (
                                <span className="basis-full text-[12px] text-crit">
                                  {detailText(r.detail)}
                                </span>
                              )}
                            </>
                          ) : (
                            <ToneBadge tone="off" size="sm">
                              {t('bk.repo.maint.never')}
                            </ToneBadge>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <RecoveryExportPanel repo={repo} />
    </Card>
  );
}

/**
 * Step-up → one-time display of the repository passwords. The values live only in this component's
 * state (never in the query cache / storage) and are wiped when the operator confirms the checklist.
 */
export function RecoveryExportPanel({ repo }: { repo: BackupRepository }) {
  const { t, locale } = useI18n();
  const { me, can } = useAuth();
  const qc = useQueryClient();
  const [otp, setOtp] = useState('');
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<RecoveryExport | null>(null);
  const [checks, setChecks] = useState([false, false, false]);
  const [cleared, setCleared] = useState(false);
  const m = useMutation<RecoveryExport, ApiError>({
    mutationFn: wrap(async () => {
      const token = (await authApi.stepUp(otp)).stepUpToken;
      return repositoriesApi.recoveryExport(repo.id, token);
    }),
    onSuccess: (d) => {
      setOtp('');
      setData(d);
      setCleared(false);
      setChecks([false, false, false]);
      void qc.invalidateQueries({ queryKey: ['backup-repositories'] });
    },
  });
  const allowed =
    can('policies.manage') &&
    (repo.allowedActions ?? ['recovery_export']).includes('recovery_export');
  return (
    <section
      className="flex flex-col gap-2 rounded-md border border-line p-3"
      data-testid="recovery-export"
    >
      <h3 className="m-0 text-[14px] font-semibold">{t('bk.repo.export.title')}</h3>
      <p className="m-0 text-[12.5px] text-fg-2">{t('bk.repo.export.body')}</p>
      <p
        className={cn(
          'm-0 text-[12.5px]',
          repo.lastRecoveryExportAt === null ? 'text-warn' : 'text-fg-muted',
        )}
      >
        {repo.lastRecoveryExportAt
          ? t('bk.repo.export.last', { date: formatDateTime(repo.lastRecoveryExportAt, locale) })
          : repo.lastRecoveryExportAt === null
            ? t('bk.repo.export.never')
            : t('sec.recovery.exportUnknown', { repo: repo.name })}
      </p>
      {data ? (
        <div className="flex flex-col gap-2" data-testid="export-values">
          <Notice tone="warn" glyph="▲" role="alert">
            {t('bk.repo.export.once')}
          </Notice>
          {data.note && (
            <p className="m-0 text-[12.5px] text-fg-2">
              {t('bk.repo.export.note', { note: data.note })}
            </p>
          )}
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full border-collapse">
              <thead>
                <tr>
                  <Th>{t('bk.repo.export.col.user')}</Th>
                  <Th>{t('bk.repo.export.col.password')}</Th>
                </tr>
              </thead>
              <tbody>
                {data.servers.map((e) => (
                  <tr key={e.restUser}>
                    <Td className="font-mono text-[12.5px]">{e.restUser}</Td>
                    <Td>
                      <span className="flex items-center gap-1">
                        <code
                          className="font-mono text-[12px] break-all"
                          data-testid="export-password"
                        >
                          {e.repoPassword}
                        </code>
                        <CopyButton text={e.repoPassword} ariaLabel={t('common.copy')} />
                      </span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <fieldset className="m-0 flex flex-col gap-1 border-0 p-0">
            <legend className="mb-1 text-[13px] font-semibold">
              {t('bk.repo.export.checklist')}
            </legend>
            {(
              ['bk.repo.export.check1', 'bk.repo.export.check2', 'bk.repo.export.check3'] as const
            ).map((k, i) => (
              <label key={k} className="flex items-start gap-2 text-[13px]">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={checks[i]}
                  onChange={(e) =>
                    setChecks((c) => c.map((x, j) => (j === i ? e.target.checked : x)))
                  }
                />
                {t(k)}
              </label>
            ))}
          </fieldset>
          <div>
            <Button
              variant="primary"
              disabled={!checks.every(Boolean)}
              onClick={() => {
                setData(null);
                setCleared(true);
                setOpen(false);
              }}
              data-testid="export-done"
            >
              {t('bk.repo.export.done')}
            </Button>
          </div>
        </div>
      ) : open ? (
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[220px] flex-1">
            <StepUpField value={otp} onChange={setOtp} hint={t('bk.repo.export.stepUpHint')} />
          </div>
          <Button
            variant="primary"
            disabled={!/^\d{6}$/.test(otp) || !me?.mfaEnabled || m.isPending}
            onClick={() => m.mutate()}
            data-testid="export-confirm"
          >
            {m.isPending ? t('common.loading') : t('bk.repo.export.action')}
          </Button>
          <Button onClick={() => setOpen(false)}>{t('common.cancel')}</Button>
        </div>
      ) : (
        <div>
          <GatedButton
            perm="policies.manage"
            blockedReason={
              allowed
                ? undefined
                : { key: 'perm.actionNotAllowed', vars: { action: 'recovery_export' } }
            }
            onClick={() => setOpen(true)}
            data-testid="export-open"
          >
            {t('bk.repo.export.action')}
          </GatedButton>
        </div>
      )}
      {cleared && (
        <Notice tone="ok" glyph="●" role="status">
          <span data-testid="export-cleared">{t('bk.repo.export.cleared')}</span>
        </Notice>
      )}
      {m.error && <ErrorState error={m.error} />}
    </section>
  );
}
