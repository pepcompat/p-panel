'use client';

import Link from 'next/link';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import type { Vars } from '@/i18n/core';
import { describeCron, parseCron, type CronDescription } from '@/lib/cron';
import { verificationBadge } from '@/lib/p6-gates';
import type { BackupRun, Restore, RestoreStatus, RestoreStep, RunStatus } from '@/lib/api/p6-types';
import { expectedSteps } from '@/lib/api/p6-types';
import { formatDateTime, formatDuration } from '@/lib/time';
import { cn } from '@/lib/utils';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Notice } from '@/components/ui/states';

type TFn = (key: MessageKey, vars?: Vars) => string;

export function shortDate(iso: string, locale: string) {
  return new Date(iso).toLocaleString(locale === 'th' ? 'th-TH' : 'en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

const RUN_TONE: Record<RunStatus, Tone> = {
  queued: 'info',
  running: 'info',
  uploaded: 'ok',
  failed: 'crit',
  expired: 'off',
  cancelled: 'off',
};

export function RunStatusBadge({ status }: { status: RunStatus }) {
  const { t } = useI18n();
  const busy = status === 'queued' || status === 'running';
  return (
    <ToneBadge tone={RUN_TONE[status]} glyph={busy ? '◌' : undefined}>
      <span data-testid="run-status" data-status={status}>
        {t(`bk.run.status.${status}` as MessageKey)}
      </span>
    </ToneBadge>
  );
}

/** One honest verification badge per run (see verificationBadge). */
export function VerificationBadge({
  run,
  showHint,
}: {
  run: Pick<BackupRun, 'status' | 'verification' | 'verifiedAt' | 'error' | 'verifying'>;
  showHint?: boolean;
}) {
  const { t, locale } = useI18n();
  const spec = verificationBadge(run, (d) => formatDateTime(d, locale));
  const hint =
    spec.level === 'none'
      ? 'bk.ver.hint.none'
      : spec.level === 'repository_checked'
        ? 'bk.ver.hint.checked'
        : spec.level === 'restore_verified'
          ? 'bk.ver.hint.verified'
          : spec.level === 'verify_failed'
            ? 'bk.ver.hint.failed'
            : null;
  return (
    <span className="inline-flex flex-col items-start gap-0.5">
      <span className="inline-flex flex-wrap items-center gap-1">
        <ToneBadge tone={spec.tone}>
          <span data-testid="verification-badge" data-level={spec.level}>
            {t(spec.key, spec.vars)}
          </span>
        </ToneBadge>
        {run.verifying && (
          <ToneBadge tone="info" glyph="◌" size="sm">
            <span data-testid="verifying">
              {t('bk.ver.verifying', {
                level: t(`bk.verifyLevel.${run.verifying.level}` as MessageKey),
              })}
            </span>
          </ToneBadge>
        )}
      </span>
      {showHint && hint && (
        <span className="text-[12px] text-fg-muted">{t(hint as MessageKey)}</span>
      )}
    </span>
  );
}

const RS_TONE: Record<RestoreStatus, Tone> = {
  planned: 'info',
  impact_reviewed: 'info',
  awaiting_approval: 'warn',
  approved: 'info',
  running: 'info',
  verified: 'ok',
  failed: 'crit',
  requires_manual_recovery: 'crit',
  cancelled: 'off',
};
export function RestoreStatusBadge({ status }: { status: RestoreStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={RS_TONE[status]} glyph={status === 'running' ? '◌' : undefined}>
      <span data-testid="restore-status" data-status={status}>
        {t(`rs.status.${status}` as MessageKey)}
      </span>
    </ToneBadge>
  );
}

export function cronText(d: CronDescription, t: TFn): string {
  const days = (xs: number[]) => xs.map((x) => t(`cron.dow.${x}` as MessageKey)).join(', ');
  switch (d.kind) {
    case 'everyMinute':
      return t('cron.everyMinute');
    case 'everyNMinutes':
      return t('cron.everyNMinutes', { n: d.n });
    case 'hourly':
      return t('cron.hourly', { m: d.minute });
    case 'everyNHours':
      return t('cron.everyNHours', { n: d.n, m: d.minute });
    case 'daily':
      return t('cron.daily', { times: d.times.join(', ') });
    case 'weekly':
      return t('cron.weekly', { days: days(d.days), times: d.times.join(', ') });
    case 'monthly':
      return t('cron.monthly', { days: d.days.join(', '), times: d.times.join(', ') });
    default:
      return t('cron.custom');
  }
}

/** "Every day at 02:00 (Asia/Bangkok)" or the parse error. */
export function describeSchedule(cron: string, tz: string, t: TFn): string {
  const p = parseCron(cron);
  if (!p.ok)
    return t('cron.invalid', {
      field: t(`cron.field.${p.error.field}` as MessageKey),
      value: p.error.value,
    });
  return t('cron.inTz', { desc: cronText(describeCron(p.cron), t), tz });
}

export function TriggerTag({ trigger }: { trigger: BackupRun['trigger'] }) {
  const { t } = useI18n();
  return (
    <span
      className={cn(
        'rounded px-1.5 text-[11px]',
        trigger === 'safety' ? 'bg-warn-bg text-warn' : 'bg-chip text-fg-3',
      )}
    >
      {t(`bk.trigger.${trigger}` as MessageKey)}
    </span>
  );
}

export function RunLink({ id }: { id: string }) {
  return (
    <Link href={`/backups/runs/${id}`} className="font-mono text-[12.5px]">
      {id.slice(0, 8)}
    </Link>
  );
}

type StepStatus = RestoreStep['status'] | 'pending';
const STEP_GLYPH: Record<StepStatus, [string, string]> = {
  pending: ['○', 'text-fg-subtle'],
  running: ['◌', 'text-info'],
  succeeded: ['●', 'text-ok'],
  failed: ['✕', 'text-crit'],
  skipped: ['–', 'text-fg-subtle'],
};

/** Steps the API has started (in order) + the expected remaining ones shown as pending. */
function timelineSteps(r: Restore) {
  const plan = expectedSteps(r.target);
  const started = r.steps.filter((x) => x.name !== 'dry_run' || r.status !== 'running');
  const names = [...new Set([...plan, ...r.steps.map((x) => x.name)])].filter(
    (n) => n !== 'dry_run' || started.some((x) => x.name === 'dry_run'),
  );
  return names.map(
    (name) =>
      r.steps.find((x) => x.name === name) ?? {
        name,
        status: 'pending' as StepStatus,
        startedAt: null,
        finishedAt: null,
        message: null,
        errorCode: null,
      },
  );
}

export function RestoreTimeline({ r, now }: { r: Restore; now: number }) {
  const { t } = useI18n();
  const steps = timelineSteps(r);
  return (
    <ol
      className="m-0 flex list-none flex-col p-0"
      aria-label={t('rs.exec.title')}
      data-testid="restore-timeline"
    >
      {steps.map((s, i) => {
        const [g, tone] = STEP_GLYPH[s.status as StepStatus];
        const start = s.startedAt ? Date.parse(s.startedAt) : null;
        const end = s.finishedAt ? Date.parse(s.finishedAt) : s.status === 'running' ? now : null;
        const last = i === steps.length - 1;
        return (
          <li
            key={s.name}
            data-testid="restore-step"
            data-step={s.name}
            data-status={s.status}
            aria-current={s.status === 'running' ? 'step' : undefined}
            className="grid grid-cols-[22px_minmax(0,1fr)] gap-x-2"
          >
            <div className="flex flex-col items-center">
              <span aria-hidden="true" className={cn('text-[14px] leading-6 font-bold', tone)}>
                {g}
              </span>
              {!last && <span aria-hidden="true" className="w-px flex-1 bg-line" />}
            </div>
            <div className={cn('flex flex-col gap-0.5', !last && 'pb-3')}>
              <div className="flex flex-wrap items-center gap-2 text-[13.5px] leading-6">
                <b className="font-medium">{t(`rs.stepn.${s.name}` as MessageKey)}</b>
                <span className="text-[12px] text-fg-muted">
                  {t(`rs.stepStatus.${s.status}` as MessageKey)}
                </span>
                {start !== null && end !== null && (
                  <span className="font-mono text-[11.5px] text-fg-muted">
                    {formatDuration(end - start)}
                  </span>
                )}
              </div>
              {s.errorCode && (
                <code className="font-mono text-[11.5px] text-crit">{s.errorCode}</code>
              )}
              {s.message && (
                <span
                  className={cn('text-[12.5px]', s.status === 'failed' ? 'text-crit' : 'text-fg-2')}
                >
                  {s.message}
                </span>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/** Critical banner for requires_manual_recovery: safety snapshot id + runbook link. */
export function ManualRecoveryBanner({ r }: { r: Restore }) {
  const { t } = useI18n();
  return (
    <div
      role="alert"
      data-testid="manual-recovery"
      className="flex flex-col gap-1.5 rounded-lg border-2 border-crit bg-crit-bg px-4 py-3 text-[13.5px]"
    >
      <b className="text-crit">
        <span aria-hidden="true">✕ </span>
        {t('rs.manual.title')}
      </b>
      <span>{r.error?.message ?? t('rs.manual.body')}</span>
      <span data-testid="safety-snapshot">
        {r.safetySnapshotRunId ? (
          <>
            {t('rs.manual.safety', { id: '' })}
            <Link href={`/backups/runs/${r.safetySnapshotRunId}`} className="font-mono">
              {r.safetySnapshotRunId.slice(0, 8)}
            </Link>
            {r.safetySnapshotIds.length > 0 && (
              <code className="ml-2 font-mono text-[12px]" data-testid="safety-snapshot-ids">
                {r.safetySnapshotIds.map((x) => x.slice(0, 8)).join(', ')}
              </code>
            )}
          </>
        ) : (
          t('rs.manual.noSafety')
        )}
      </span>
      <ol className="m-0 flex flex-col gap-0.5 pl-5 text-[12.5px]">
        <li>{t('rs.manual.s1')}</li>
        <li>{t('rs.manual.s2')}</li>
        <li>{t('rs.manual.s3')}</li>
      </ol>
      <Link
        href="/settings/security#recovery-runbook"
        className="self-start text-[13px] font-medium"
      >
        {t('rs.manual.runbook')}
      </Link>
      {r.error?.code && <code className="font-mono text-[12px] text-fg-muted">{r.error.code}</code>}
    </div>
  );
}

export function AppendOnlyNotice() {
  const { t } = useI18n();
  return (
    <Notice tone="info" glyph="◆" role="note" title={t('bk.appendOnly.title')}>
      <span data-testid="append-only">{t('bk.appendOnly.body')}</span>
    </Notice>
  );
}

/** Small key–value table helper. */
export function Th({ children, className }: { children?: React.ReactNode; className?: string }) {
  return (
    <th
      scope="col"
      className={cn(
        'border-b border-line px-3 py-2 text-left text-[12px] font-medium whitespace-nowrap text-fg-muted',
        className,
      )}
    >
      {children}
    </th>
  );
}
export function Td({ children, className }: { children?: React.ReactNode; className?: string }) {
  return (
    <td className={cn('border-b border-line-subtle px-3 py-2 align-top text-[13px]', className)}>
      {children}
    </td>
  );
}
