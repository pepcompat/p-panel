'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { restoresApi } from '@/lib/api/p6-endpoints';
import type { ApiError } from '@/lib/api/errors';
import type {
  BackupRunDetail,
  Restore,
  RestoreMode,
  RestoreTargetInput,
  RunSnapshot,
} from '@/lib/api/p6-types';
import { useRestore, useRun } from '@/lib/p6-queries';
import {
  WIZARD_STEPS,
  defaultModeFor,
  formatBytes,
  impactGate,
  parseDryListing,
  parseRestoreResult,
  targetLabel,
  restoreGate,
  restoreNeedsApproval,
  runIsRestorable,
  stepForStatus,
  type WizardStep,
} from '@/lib/p6-gates';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { Card, Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { Field } from '@/components/ui/form';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { StepUpField } from '@/components/p3/bits';
import { wrap } from '@/components/p3/action-dialog';
import { useSetPageEnv } from '@/components/shell/page-env';
import {
  ManualRecoveryBanner,
  RestoreStatusBadge,
  RestoreTimeline,
  Td,
  Th,
  VerificationBadge,
} from './bits';

const lines = (s: string) =>
  s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean);

function Stepper({ current, skipApproval }: { current: WizardStep; skipApproval: boolean }) {
  const { t } = useI18n();
  const idx = WIZARD_STEPS.indexOf(current);
  return (
    <ol className="m-0 flex list-none flex-wrap gap-1 p-0" aria-label={t('rs.steps')}>
      {WIZARD_STEPS.map((s, i) => (
        <li
          key={s}
          aria-current={s === current ? 'step' : undefined}
          className={cn(
            'flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px]',
            s === current
              ? 'bg-sidebar font-medium text-sidebar-fg-strong dark:bg-accent-strong'
              : i < idx
                ? 'bg-ok-bg text-ok'
                : 'bg-chip text-fg-muted',
            s === 'approval' && skipApproval && 'line-through opacity-60',
          )}
        >
          <span aria-hidden="true">{i < idx ? '●' : i + 1}</span>
          {t(`rs.step.${s}` as MessageKey)}
        </li>
      ))}
    </ol>
  );
}

export function RestoreWizard({
  runId,
  snapshotId,
  restoreId,
}: {
  runId: string | null;
  snapshotId: string | null;
  restoreId: string | null;
}) {
  const { t } = useI18n();
  const { can, status } = useAuth();
  const rq = useRestore(restoreId);
  const effectiveRunId = runId ?? rq.data?.runId ?? null;
  const run = useRun(effectiveRunId ?? '');
  useSetPageEnv(run.data?.environment ?? rq.data?.environment);

  let body: React.ReactNode;
  if (status === 'authenticated' && !restoreId && !can('backups.restore')) {
    body = <ForbiddenState perm="backups.restore" />;
  } else if (!restoreId && !runId) {
    body = (
      <EmptyState
        title={t('rs.pickRun')}
        action={
          <Link href="/backups?tab=runs" className="text-[13px]">
            {t('rs.pickRunCta')}
          </Link>
        }
      />
    );
  } else if ((restoreId && rq.isPending) || (effectiveRunId && run.isPending)) {
    body = (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="flex flex-col gap-3"
      >
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  } else if (restoreId && rq.isError) {
    body = <ErrorState error={rq.error} onRetry={() => void rq.refetch()} />;
  } else if (run.isError && !run.data) {
    body = <ErrorState error={run.error} onRetry={() => void run.refetch()} />;
  } else if (rq.data) {
    body = <ExistingRestore r={rq.data} run={run.data ?? null} />;
  } else if (run.data) {
    body = <NewRestore run={run.data} initialSnapshot={snapshotId} />;
  }
  return (
    <Page>
      <Link href="/backups?tab=restores" className="self-start text-[13px]">
        {t('bk.run.back')}
      </Link>
      <PageHeader title={t('rs.title')} subtitle={t('rs.subtitle')} />
      {body}
    </Page>
  );
}

function RunHeader({ run }: { run: BackupRunDetail }) {
  const { t, locale } = useI18n();
  return (
    <div className="flex flex-wrap items-center gap-2 text-[13px]">
      <span className="text-fg-2">
        {t('rs.snap.fromRun', {
          id: run.id.slice(0, 8),
          policy: run.policyName ?? '',
          server: run.serverName ?? '',
          date: formatDateTime(run.finishedAt ?? run.createdAt, locale),
        })}
      </span>
      {run.environment && (
        <EnvBadge env={run.environment} label={t(envBadgeKey(run.environment))} />
      )}
      <VerificationBadge run={run} />
    </div>
  );
}

// ---------------------------------------------------------------- steps 1–2 (local until the plan is created)

function NewRestore({
  run,
  initialSnapshot,
}: {
  run: BackupRunDetail;
  initialSnapshot: string | null;
}) {
  const { t } = useI18n();
  const router = useRouter();
  const qc = useQueryClient();
  const [step, setStep] = useState<'snapshot' | 'target'>(initialSnapshot ? 'target' : 'snapshot');
  const [snapId, setSnapId] = useState<string>(
    run.snapshots.find((s) => s.snapshotId === initialSnapshot)?.snapshotId ??
      run.snapshots[0]?.snapshotId ??
      '',
  );
  const snap = run.snapshots.find((s) => s.snapshotId === snapId) ?? null;
  const [mode, setMode] = useState<RestoreMode>(snap ? defaultModeFor(snap.targetType) : 'staging');
  const [include, setInclude] = useState('');
  const snapType = snap?.targetType;
  useEffect(() => {
    if (snapType) setMode(defaultModeFor(snapType));
  }, [snapId, snapType]);
  const m = useMutation<Restore, ApiError, RestoreTargetInput>({
    mutationFn: (target) => restoresApi.create({ runId: run.id, snapshotId: snapId, target }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ['restores'], exact: false });
      router.replace(`/restore/new?restoreId=${r.id}`);
    },
  });

  if (!runIsRestorable(run))
    return (
      <>
        <RunHeader run={run} />
        <Notice tone="crit" glyph="✕" role="alert">
          <span data-testid="not-restorable">
            {t('rs.notRestorable', { status: t(`bk.run.status.${run.status}` as MessageKey) })}
          </span>
        </Notice>
      </>
    );

  const buildTarget = (): RestoreTargetInput | null => {
    // The run records its own targets; the snapshot points at one of them by index.
    const src = snap ? run.targets[snap.target] : undefined;
    if (!src) return null;
    if (src.type === 'paths')
      return {
        type: 'paths',
        include: lines(include),
        mode: mode === 'in_place' ? 'in_place' : 'staging',
      };
    if (src.type === 'volume')
      return {
        type: 'volume',
        app: src.app,
        volume: src.volume,
        mode: mode === 'in_place' ? 'in_place' : 'staging',
      };
    return {
      type: src.type,
      app: src.app,
      service: src.service,
      database: src.database,
      user: src.user,
      passwordSecretKey: src.passwordSecretKey,
      mode: mode === 'in_place' ? 'in_place' : 'scratch',
    };
  };
  const needsApproval = restoreNeedsApproval(mode, run.environment);
  const isDb = snap?.targetType === 'postgres' || snap?.targetType === 'mysql';
  const safeMode: RestoreMode = isDb ? 'scratch' : 'staging';

  return (
    <div className="flex flex-col gap-4" data-testid="restore-wizard" data-step={step}>
      <Stepper current={step} skipApproval={!needsApproval} />
      <RunHeader run={run} />
      {step === 'snapshot' && (
        <Card className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('rs.snap.title')}</h2>
          <div role="radiogroup" aria-label={t('rs.snap.title')} className="flex flex-col gap-2">
            {run.snapshots.map((s) => (
              <SnapRadio
                key={s.snapshotId}
                s={s}
                label={
                  run.targets[s.target]
                    ? `${s.targetType} ${targetLabel(run.targets[s.target]!)}`
                    : s.targetType
                }
                checked={s.snapshotId === snapId}
                onSelect={() => setSnapId(s.snapshotId)}
              />
            ))}
          </div>
          <div className="flex justify-end">
            <Button
              variant="primary"
              disabled={!snap}
              onClick={() => setStep('target')}
              data-testid="wizard-next"
            >
              {t('rs.continue')}
            </Button>
          </div>
        </Card>
      )}
      {step === 'target' && snap && (
        <Card className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('rs.target.title')}</h2>
          <p className="m-0 font-mono text-[12.5px] text-fg-2">
            {snap.targetType}{' '}
            {run.targets[snap.target] ? targetLabel(run.targets[snap.target]!) : ''}
          </p>
          <div role="radiogroup" aria-label={t('rs.target.title')} className="flex flex-col gap-2">
            {([safeMode, 'in_place'] as RestoreMode[]).map((md) => (
              <button
                key={md}
                type="button"
                role="radio"
                aria-checked={mode === md}
                onClick={() => setMode(md)}
                data-testid={`mode-${md}`}
                className={cn(
                  'flex flex-col items-start gap-0.5 rounded-md border p-3 text-left text-[13px]',
                  mode === md
                    ? md === 'in_place'
                      ? 'border-crit bg-crit-bg'
                      : 'border-accent-strong bg-info-bg'
                    : 'border-line bg-surface hover:bg-surface-hover',
                )}
              >
                <b className={md === 'in_place' ? 'text-crit' : undefined}>
                  <span aria-hidden="true">{mode === md ? '◉ ' : '○ '}</span>
                  {md === 'in_place' && <span aria-hidden="true">▲ </span>}
                  {t(`rs.mode.${md}` as MessageKey)}
                </b>
                <span className="text-[12.5px] text-fg-2">
                  {t(`rs.mode.${md}.body` as MessageKey)}
                </span>
              </button>
            ))}
          </div>
          {snap.targetType === 'paths' && (
            <Field label={t('rs.include')} hint={t('rs.includeHint')}>
              {(p) => (
                <textarea
                  {...p}
                  rows={2}
                  value={include}
                  onChange={(e) => setInclude(e.target.value)}
                  className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[13px]"
                />
              )}
            </Field>
          )}
          <Notice
            tone={needsApproval ? 'warn' : 'neutral'}
            glyph={needsApproval ? '▲' : '◆'}
            role="note"
          >
            <span data-testid="approval-notice">
              {t(needsApproval ? 'rs.impact.approval' : 'rs.impact.noApproval')}
            </span>
          </Notice>
          {m.error && <ErrorState error={m.error} />}
          <div className="flex justify-between gap-2">
            <Button onClick={() => setStep('snapshot')}>{t('rs.back')}</Button>
            <Button
              variant={mode === 'in_place' ? 'danger' : 'primary'}
              disabled={m.isPending || !run.targets[snap.target]}
              onClick={() => {
                const target = buildTarget();
                if (target) m.mutate(target);
              }}
              data-testid="create-plan"
            >
              {m.isPending ? t('common.loading') : t('rs.createPlan')}
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}

function SnapRadio({
  s,
  label,
  checked,
  onSelect,
}: {
  s: RunSnapshot;
  label: string;
  checked: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      onClick={onSelect}
      className={cn(
        'flex flex-wrap items-center gap-2 rounded-md border p-3 text-left text-[13px]',
        checked
          ? 'border-accent-strong bg-info-bg'
          : 'border-line bg-surface hover:bg-surface-hover',
      )}
    >
      <span aria-hidden="true">{checked ? '◉' : '○'}</span>
      <code className="font-mono text-[12.5px]" title={s.snapshotId}>
        {s.shortId ?? s.snapshotId.slice(0, 8)}
      </code>
      <span className="font-mono text-[12.5px] break-all">{label}</span>
      <span className="text-[12px] text-fg-muted">{formatBytes(s.sizeBytes)}</span>
    </button>
  );
}

// ---------------------------------------------------------------- steps 3–7 (server-side restore record)

function targetRef(t: RestoreTargetInput) {
  if (t.type === 'paths') return (t.include ?? []).length ? (t.include ?? []).join(', ') : '*';
  if (t.type === 'volume') return `${t.app}/${t.volume}`;
  return `${t.app}/${t.service}/${t.database}`;
}

function ExistingRestore({ r, run }: { r: Restore; run: BackupRunDetail | null }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const now = useNow(1000);
  const [confirmed, setConfirmed] = useState(false);
  const [otp, setOtp] = useState('');
  useEffect(() => setConfirmed(false), [r.id]);
  const step = stepForStatus(r.status);
  const inPlace = r.target.mode === 'in_place';
  const dataItems = r.plan.impact.filter((i) => i.effect === 'overwrite' || i.effect === 'create');
  const downtime = r.plan.impact.filter((i) => i.effect === 'downtime');
  const notes = r.plan.impact.filter((i) => i.effect === 'note' && i.ref !== 'config_vs_data');
  const dryRunning = r.steps.some((x) => x.name === 'dry_run' && x.status === 'running');
  const onSuccess = (x: Restore) => {
    qc.setQueryData(['restores', 'one', r.id], x);
    void qc.invalidateQueries({ queryKey: ['restores'], exact: false });
  };
  const dry = useMutation<Restore, ApiError>({
    mutationFn: () => restoresApi.dryRun(r.id),
    onSuccess,
  });
  const exec = useMutation<Restore, ApiError>({
    // the in_place impact checkbox is also enforced by the API (IMPACT_CONFIRMATION_REQUIRED)
    mutationFn: () => restoresApi.execute(r.id, inPlace && confirmed),
    onSuccess,
  });
  const cancel = useMutation<Restore, ApiError>({
    mutationFn: () => restoresApi.cancel(r.id),
    onSuccess,
  });
  const approve = useMutation<Restore, ApiError>({
    mutationFn: wrap(async () => {
      const token = (await authApi.stepUp(otp)).stepUpToken;
      return restoresApi.approve(r.id, r.planHash ?? '', token);
    }),
    onSuccess: (x) => {
      setOtp('');
      onSuccess(x);
    },
  });
  const perms = me?.permissions;
  const uid = me?.user.id;
  const ig = impactGate(r.target.mode, confirmed);
  const execGate = restoreGate('execute', r, perms, uid, confirmed, r.target.mode);
  const approveGate = restoreGate('approve', r, perms, uid);
  const cancelGate = restoreGate('cancel', r, perms, uid);
  const isCreator = r.createdBy === uid;
  const snapDate = run
    ? formatDateTime(run.finishedAt ?? run.createdAt, locale)
    : r.snapshotId.slice(0, 8);
  const confirmBox = inPlace && (
    <label
      className="flex items-start gap-2 rounded-md border-2 border-crit bg-crit-bg p-3 text-[13px]"
      data-testid="impact-confirm-box"
    >
      <input
        type="checkbox"
        className="mt-1"
        checked={confirmed}
        onChange={(e) => setConfirmed(e.target.checked)}
        data-testid="impact-confirm"
        aria-describedby="impact-confirm-title"
      />
      <span>
        <b id="impact-confirm-title" className="block text-crit">
          {t('rs.impact.confirmTitle')}
        </b>
        {t('rs.impact.confirm', { ref: targetRef(r.target), date: snapDate })}
      </span>
    </label>
  );

  return (
    <div
      className="flex flex-col gap-4"
      data-testid="restore-wizard"
      data-step={step}
      data-status={r.status}
    >
      <Stepper current={step} skipApproval={!r.approval.required} />
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 font-mono text-[16px] font-semibold">{r.id.slice(0, 8)}</h2>
        <RestoreStatusBadge status={r.status} />
        {r.environment && <EnvBadge env={r.environment} label={t(envBadgeKey(r.environment))} />}
        <span
          className={cn('text-[12.5px]', inPlace ? 'font-semibold text-crit' : 'text-fg-muted')}
        >
          {t(`rs.mode.${r.target.mode}` as MessageKey)}
        </span>
        <span className="font-mono text-[12.5px] text-fg-2">
          {r.target.type} {targetRef(r.target)} · {r.serverName}
        </span>
        <span className="text-[12px] text-fg-muted">
          {t('rs.createdBy', { who: r.createdByLabel ?? '—' })}
        </span>
      </div>
      {run && <RunHeader run={run} />}

      {/* Impact — always visible so it is never skipped */}
      <Card className="flex flex-col gap-3 p-4" data-testid="impact">
        <h2 className="m-0 text-[15px] font-semibold">{t('rs.impact.title')}</h2>
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
          {dataItems.map((i) => (
            <li
              key={`${i.effect}:${i.ref}`}
              data-testid="impact-item"
              data-action={i.effect}
              className="flex flex-wrap items-baseline gap-2 text-[13px]"
            >
              <span
                className={cn('font-semibold', i.effect === 'overwrite' ? 'text-crit' : 'text-ok')}
              >
                <span aria-hidden="true">{i.effect === 'overwrite' ? '✕ ' : '+ '}</span>
                {t(i.effect === 'overwrite' ? 'rs.impact.overwrite' : 'rs.impact.create')}
              </span>
              <span className="text-fg-muted">{i.kind}</span>
              <code className="font-mono text-[12.5px] break-all">{i.ref}</code>
              {i.detail && <span className="text-[12.5px] text-fg-2">— {i.detail}</span>}
            </li>
          ))}
        </ul>
        <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[13px]">
          <li data-testid="impact-downtime">
            {downtime.length > 0 ? (
              downtime.map((d) => (
                <span key={d.ref} className="block text-warn">
                  ▲ {t('rs.impact.downtimeLabel')}: <code className="font-mono">{d.ref}</code> —{' '}
                  {d.detail}
                </span>
              ))
            ) : (
              <span>● {t('rs.impact.noDowntime')}</span>
            )}
          </li>
          <li data-testid="impact-safety">
            {inPlace
              ? `◆ ${t('rs.impact.safety', { targets: targetRef(r.target) })}`
              : `○ ${t('rs.impact.noSafety')}`}
          </li>
          {notes.map((n) => (
            <li key={n.ref} className="text-fg-2">
              ◆ {t('rs.impact.noteLabel')}: {n.detail}
            </li>
          ))}
          <li>◆ {t(r.approval.required ? 'rs.impact.approval' : 'rs.impact.noApproval')}</li>
        </ul>
        <Notice tone="warn" glyph="▲" role="note">
          <span data-testid="config-note">{t('rs.impact.configNote')}</span>
        </Notice>
        {step === 'impact' && (
          <>
            {confirmBox}
            <p className="m-0 text-[12.5px] text-fg-muted">{t('rs.dry.body')}</p>
            {dry.error && <ErrorState error={dry.error} />}
            <div className="flex flex-wrap justify-between gap-2">
              <GatedButton
                variant="ghost"
                perm="backups.restore"
                blockedReason={cancelGate.allowed ? undefined : cancelGate.reason}
                onClick={() => cancel.mutate()}
              >
                {t('rs.cancel')}
              </GatedButton>
              <GatedButton
                variant="primary"
                perm="backups.restore"
                blockedReason={ig.allowed ? undefined : ig.reason}
                disabled={dry.isPending || dryRunning}
                onClick={() => dry.mutate()}
                data-testid="dry-run"
              >
                {dry.isPending || dryRunning ? t('common.loading') : t('rs.dry.run')}
              </GatedButton>
            </div>
          </>
        )}
      </Card>

      {r.plan.dryRun && <DryRunCard r={r} />}

      {(step === 'dryrun' || step === 'approval') && (
        <Card className="flex flex-col gap-3 p-4" data-testid="approval-panel">
          <h2 className="m-0 text-[15px] font-semibold">{t('rs.appr.title')}</h2>
          {r.approval.required ? (
            <>
              <dl className="m-0 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
                <dt className="text-fg-muted">{t('rs.appr.planHash')}</dt>
                <dd className="m-0 font-mono text-[12px] break-all" data-testid="plan-hash">
                  {r.planHash}
                </dd>
                <dt className="text-fg-muted">{t('approval.rule')}</dt>
                <dd className="m-0">{t('rs.appr.rule')}</dd>
              </dl>
              {r.status === 'approved' && r.approval.approvedBy && (
                <Notice tone="ok" glyph="●" role="status">
                  <span data-testid="approved-by">
                    {t('rs.appr.approvedBy', {
                      who: r.approvedByLabel ?? r.approval.approvedBy,
                      date: r.approval.expiresAt
                        ? formatDateTime(r.approval.expiresAt, locale)
                        : '—',
                    })}
                  </span>
                </Notice>
              )}
              {r.status === 'awaiting_approval' &&
                (isCreator ? (
                  <Notice tone="warn" glyph="◐" role="status">
                    <span data-testid="waiting-approver">{t('rs.appr.waiting')}</span>
                  </Notice>
                ) : approveGate.allowed ? (
                  <div className="flex flex-wrap items-end gap-2">
                    <div className="min-w-[220px] flex-1">
                      <StepUpField value={otp} onChange={setOtp} hint={t('rs.appr.stepUpHint')} />
                    </div>
                    <Button
                      variant="primary"
                      disabled={!/^\d{6}$/.test(otp) || !me?.mfaEnabled || approve.isPending}
                      onClick={() => approve.mutate()}
                      data-testid="approve"
                    >
                      {approve.isPending
                        ? t('common.saving')
                        : t('rs.appr.approve', { hash: (r.planHash ?? '').slice(0, 12) })}
                    </Button>
                  </div>
                ) : (
                  <GatedButton perm="approvals.decide" blockedReason={approveGate.reason}>
                    {t('rs.appr.approve', { hash: (r.planHash ?? '').slice(0, 12) })}
                  </GatedButton>
                ))}
              {approve.error && <ErrorState error={approve.error} />}
            </>
          ) : (
            <p className="m-0 text-[13px] text-fg-muted" data-testid="approval-not-required">
              {t('rs.appr.notRequired')}
            </p>
          )}
          {(r.status === 'impact_reviewed' || r.status === 'approved') && (
            <>
              {confirmBox}
              {exec.error && <ErrorState error={exec.error} />}
              <div className="flex flex-wrap justify-between gap-2">
                <GatedButton
                  variant="ghost"
                  perm="backups.restore"
                  blockedReason={cancelGate.allowed ? undefined : cancelGate.reason}
                  onClick={() => cancel.mutate()}
                >
                  {t('rs.cancel')}
                </GatedButton>
                <GatedButton
                  variant={inPlace ? 'danger' : 'primary'}
                  perm="backups.restore"
                  blockedReason={execGate.allowed ? undefined : execGate.reason}
                  disabled={exec.isPending}
                  onClick={() => exec.mutate()}
                  data-testid="execute"
                >
                  {exec.isPending
                    ? t('common.loading')
                    : t(inPlace ? 'rs.exec.startInPlace' : 'rs.exec.start')}
                </GatedButton>
              </div>
            </>
          )}
          {r.status === 'awaiting_approval' && (
            <div>
              <GatedButton
                variant="ghost"
                perm="backups.restore"
                blockedReason={cancelGate.allowed ? undefined : cancelGate.reason}
                onClick={() => cancel.mutate()}
              >
                {t('rs.cancel')}
              </GatedButton>
            </div>
          )}
          {cancel.error && <ErrorState error={cancel.error} />}
        </Card>
      )}

      {(step === 'execute' || step === 'result') && r.status !== 'cancelled' && (
        <Card className="flex flex-col gap-3 p-4" data-testid="restore-execution">
          <h2 className="m-0 text-[15px] font-semibold">{t('rs.exec.title')}</h2>
          <RestoreTimeline r={r} now={now} />
        </Card>
      )}
      {step === 'result' && <RestoreResult r={r} />}
    </div>
  );
}

function DryRunCard({ r }: { r: Restore }) {
  const { t } = useI18n();
  const dr = r.plan.dryRun!;
  const d = parseDryListing(dr.listing, r.target.mode === 'in_place');
  const ok = dr.ok !== false;
  return (
    <Card className="flex flex-col gap-2 p-4" data-testid="dry-run-result">
      <h2 className="m-0 text-[15px] font-semibold">{t('rs.dry.title')}</h2>
      <p className="m-0 text-[13px]">
        <span className={ok ? 'text-ok' : 'text-crit'} aria-hidden="true">
          {ok ? '● ' : '✕ '}
        </span>
        {t('rs.dry.summary', {
          files: d.files ?? d.entries.length,
          bytes: formatBytes(d.bytes),
        })}
      </p>
      {!ok && dr.error != null && (
        <Notice tone="crit" glyph="✕" role="alert">
          {typeof dr.error === 'string' ? dr.error : JSON.stringify(dr.error).slice(0, 300)}
        </Notice>
      )}
      {d.warnings.map((w) => (
        <Notice key={w} tone="warn" glyph="▲" role="note">
          {w}
        </Notice>
      ))}
      {d.entries.length > 0 && (
        <div className="max-h-64 overflow-auto rounded-md border border-line">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                <Th>{t('rs.dry.col.path')}</Th>
                <Th>{t('rs.dry.col.action')}</Th>
              </tr>
            </thead>
            <tbody>
              {d.entries.map((e) => (
                <tr key={e.path} data-testid="dry-entry">
                  <Td className="font-mono text-[12px] break-all">{e.path}</Td>
                  <Td
                    className={cn(
                      'text-[12.5px]',
                      e.action === 'overwrite' && 'font-medium text-crit',
                    )}
                  >
                    {t(`rs.dry.action.${e.action}` as MessageKey)}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d.files !== null && d.files > d.entries.length && d.entries.length > 0 && (
        <span className="text-[12px] text-fg-muted">
          {t('rs.dry.more', { n: d.files - d.entries.length })}
        </span>
      )}
      {d.tables.length > 0 && (
        <p className="m-0 text-[12.5px] text-fg-2">
          {t('rs.dry.tables')}:{' '}
          <span className="font-mono">
            {d.tables.map((x) => `${x.name} (${x.rows})`).join(', ')}
          </span>
        </p>
      )}
    </Card>
  );
}

function RestoreResult({ r }: { r: Restore }) {
  const { t } = useI18n();
  if (r.status === 'requires_manual_recovery') return <ManualRecoveryBanner r={r} />;
  if (r.status === 'cancelled')
    return (
      <Notice tone="neutral" glyph="○" role="status">
        <span data-testid="restore-result" data-outcome="cancelled">
          {t('rs.result.cancelled')}
        </span>
      </Notice>
    );
  if (r.status === 'failed')
    return (
      <Notice tone="crit" glyph="✕" role="alert" title={t('rs.result.failed')}>
        <span data-testid="restore-result" data-outcome="failed">
          {r.error?.message ?? t('rs.result.failedBody')}
        </span>
        {r.error?.code && <code className="ml-2 font-mono text-[12px]">{r.error.code}</code>}
      </Notice>
    );
  const res = parseRestoreResult(r.result);
  return (
    <Card className="flex flex-col gap-2 p-4">
      <Notice tone="ok" glyph="●" role="status" title={t('rs.result.verified')}>
        <span data-testid="restore-result" data-outcome="verified">
          {t('rs.result.verifiedBody')}
        </span>
      </Notice>
      {res.location && (
        <p className="m-0 text-[13px]">
          {t('rs.result.location', { loc: '' })}
          <code className="font-mono text-[12.5px]" data-testid="staging-location">
            {res.location}
          </code>
        </p>
      )}
      {res.compared !== null && (
        <p className="m-0 text-[13px]" data-testid="compare-files">
          {t('rs.result.compared', { n: res.compared, m: res.mismatches })}
        </p>
      )}
      {res.tables.length > 0 && (
        <table className="w-full max-w-[560px] border-collapse" data-testid="compare-tables">
          <thead>
            <tr>
              <Th>{t('rs.result.col.table')}</Th>
              <Th className="text-right">{t('rs.result.col.expected')}</Th>
              <Th className="text-right">{t('rs.result.col.actual')}</Th>
            </tr>
          </thead>
          <tbody>
            {res.tables.map((x) => (
              <tr key={x.name}>
                <Td className="font-mono text-[12.5px]">{x.name}</Td>
                <Td className="text-right font-mono text-[12.5px]">{x.expected}</Td>
                <Td
                  className={cn(
                    'text-right font-mono text-[12.5px]',
                    x.actual !== x.expected && 'text-crit',
                  )}
                >
                  {x.actual}
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
