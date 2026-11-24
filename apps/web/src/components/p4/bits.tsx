'use client';

import Link from 'next/link';
import { useState, type ReactNode } from 'react';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import type { ApiError } from '@/lib/api/errors';
import type {
  Deployment,
  DeploymentStatus,
  DeploymentStep,
  DeploymentTrigger,
  PreflightCheck,
  WebhookDelivery,
} from '@/lib/api/p4-types';
import { DEPLOYMENT_ACTIVE } from '@/lib/api/p4-types';
import { approvalExpiredAt } from '@/lib/p4-gates';
import type { GateResult } from '@/lib/permissions';
import { formatDateTime, formatDuration } from '@/lib/time';
import { cn } from '@/lib/utils';
import { useMutation } from '@tanstack/react-query';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { ErrorState, Notice } from '@/components/ui/states';
import { StepUpField } from '@/components/p3/bits';
import { wrap } from '@/components/p3/action-dialog';
import type { MessageKey } from '@/i18n/en';

const DEP_TONE: Record<DeploymentStatus, Tone> = {
  awaiting_approval: 'warn',
  queued: 'info',
  preflight: 'info',
  pulling: 'info',
  starting: 'info',
  health_check: 'info',
  routing: 'info',
  succeeded: 'ok',
  failed: 'crit',
  rollback_pending: 'warn',
  rolled_back: 'off',
  requires_manual_recovery: 'crit',
  cancelled: 'off',
  expired: 'off',
};

export function DeploymentStatusBadge({ status }: { status: DeploymentStatus }) {
  const { t } = useI18n();
  const busy = DEPLOYMENT_ACTIVE.includes(status);
  return (
    <ToneBadge tone={DEP_TONE[status]} glyph={busy ? '◌' : undefined} className="font-medium">
      <span data-testid="deployment-status" data-status={status}>
        {t(`dep.status.${status}` as MessageKey)}
      </span>
    </ToneBadge>
  );
}

const TRIGGER: Record<DeploymentTrigger, { glyph: string; tone: Tone }> = {
  manual: { glyph: '◆', tone: 'info' },
  webhook: { glyph: '⇄', tone: 'stale' },
  rollback: { glyph: '↶', tone: 'warn' },
  redeploy: { glyph: '↻', tone: 'off' },
};
export function TriggerBadge({ trigger }: { trigger: DeploymentTrigger }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={TRIGGER[trigger].tone} glyph={TRIGGER[trigger].glyph} size="sm">
      <span data-testid="trigger-badge">{t(`dep.trigger.${trigger}` as MessageKey)}</span>
    </ToneBadge>
  );
}

/** `registry/repo@sha256:abcd…` shortened, full value in title + screen-reader text. */
export function ImageRef({
  image,
  className,
}: {
  image: string | null | undefined;
  className?: string;
}) {
  const { t } = useI18n();
  if (!image) return <span className="text-fg-subtle">{t('common.dash')}</span>;
  const [repo, digest] = image.split('@');
  return (
    <span className={cn('font-mono text-[12px] break-all', className)} title={image}>
      <span aria-hidden="true">
        {repo}
        {digest ? `@${digest.slice(0, 19)}…` : ''}
      </span>
      <span className="sr-only">{image}</span>
    </span>
  );
}

// ---------------------------------------------------------------- preflight

const KNOWN_PF_CODES = [
  'AGENT_OFFLINE',
  'MANAGED_ROUTING_DISABLED',
  'IMAGE_NOT_PINNED',
  'SECRETS_MISSING',
  'DOMAIN_CONFLICT',
  'NO_PORT_AVAILABLE',
  'PORT_IN_USE',
  'DISK_LOW',
  'DISK_UNKNOWN',
  'DEPLOYMENT_IN_PROGRESS',
];

export function PreflightList({ checks }: { checks: readonly PreflightCheck[] }) {
  const { t } = useI18n();
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0" data-testid="preflight-list">
      {checks.map((c) => {
        const warn = c.ok && (c.warning || !!c.code);
        const glyph = !c.ok ? '✕' : warn ? '▲' : '●';
        const tone = !c.ok ? 'text-crit' : warn ? 'text-warn' : 'text-ok';
        const fix =
          c.code && KNOWN_PF_CODES.includes(c.code) ? t(`pf.fix.${c.code}` as MessageKey) : null;
        return (
          <li
            key={c.check}
            data-testid="preflight-check"
            data-check={c.check}
            data-ok={c.ok ? 'true' : 'false'}
            className="flex flex-wrap items-start gap-x-2 gap-y-0.5 rounded-md border border-line px-3 py-2 text-[13px]"
          >
            <span aria-hidden="true" className={cn('font-bold', tone)}>
              {glyph}
            </span>
            <span className="min-w-[160px] font-medium">
              {t(`pf.check.${c.check}` as MessageKey)}
            </span>
            <span className="sr-only">
              {c.ok ? (warn ? t('pf.warning') : t('pf.ok')) : t('pf.failed')}
            </span>
            {c.code && <code className="font-mono text-[11.5px] text-fg-muted">{c.code}</code>}
            <span className="basis-full pl-5 text-fg-2">{c.message}</span>
            {!c.ok && fix && (
              <span className="basis-full pl-5 text-[12.5px] text-fg-muted">
                <b className="font-medium text-fg-3">{t('pf.remediation')}</b> {fix}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

// ---------------------------------------------------------------- timeline

const STEP_GLYPH: Record<DeploymentStep['status'], [string, string]> = {
  pending: ['○', 'text-off'],
  running: ['◌', 'text-info'],
  succeeded: ['●', 'text-ok'],
  failed: ['✕', 'text-crit'],
  skipped: ['–', 'text-fg-subtle'],
};

export function stepLabelKey(name: string): MessageKey {
  return `step.${name}` as MessageKey;
}

export function DeploymentTimeline({ d, now }: { d: Deployment; now: number }) {
  const { t } = useI18n();
  return (
    <ol
      className="m-0 flex list-none flex-col p-0"
      aria-label={t('dep.timeline')}
      data-testid="timeline"
    >
      {d.steps.map((s, i) => {
        const [g, tone] = STEP_GLYPH[s.status];
        const start = s.startedAt ? Date.parse(s.startedAt) : null;
        const end = s.finishedAt ? Date.parse(s.finishedAt) : s.status === 'running' ? now : null;
        const showLog = s.logTail.length > 0;
        const last = i === d.steps.length - 1;
        return (
          <li
            key={`${s.name}-${i}`}
            data-testid="deployment-step"
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
            <div className={cn('flex flex-col gap-1', !last && 'pb-3')}>
              <div className="flex flex-wrap items-center gap-2 text-[13.5px] leading-6">
                <b className="font-medium">{t(stepLabelKey(s.name))}</b>
                <span className="text-[12px] text-fg-muted">
                  {t(`step.status.${s.status}` as MessageKey)}
                </span>
                {start !== null && end !== null && (
                  <span className="font-mono text-[11.5px] text-fg-muted">
                    {formatDuration(end - start)}
                  </span>
                )}
                {s.errorCode && (
                  <code className="font-mono text-[11.5px] text-crit">{s.errorCode}</code>
                )}
              </div>
              {s.message && <span className="text-[12.5px] text-fg-2">{s.message}</span>}
              {showLog && (
                <pre
                  className="m-0 max-h-40 overflow-auto rounded-md bg-terminal px-3 py-2 font-mono text-[11.5px] leading-[1.55] whitespace-pre-wrap text-terminal-fg"
                  aria-label={t('dep.logTail', { step: t(stepLabelKey(s.name)) })}
                  data-testid="log-tail"
                >
                  {s.logTail.join('\n')}
                </pre>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

// ---------------------------------------------------------------- terminal outcome

export function DeploymentOutcome({
  d,
  previousNumber,
}: {
  d: Deployment;
  previousNumber?: number | null;
}) {
  const { t } = useI18n();
  const code = d.error?.code;
  if (d.status === 'succeeded')
    return (
      <>
        <Notice tone="ok" glyph="●" role="status" title={t('dep.out.succeeded', { n: d.number })}>
          <span data-testid="outcome" data-outcome="succeeded">
            {t('dep.out.succeededBody')}{' '}
            {(d.domains ?? []).slice(0, 3).map((dom) => (
              <a
                key={dom}
                href={`http://${dom}`}
                target="_blank"
                rel="noreferrer"
                className="mr-2 font-mono"
              >
                {dom} ↗
              </a>
            ))}
          </span>
        </Notice>
        {code === 'STOP_PREVIOUS_FAILED' && (
          <Notice tone="warn" glyph="▲" role="status" title={code}>
            {t('dep.out.stopPreviousFailed')}
          </Notice>
        )}
      </>
    );
  if (d.status === 'requires_manual_recovery')
    return (
      <div
        role="alert"
        data-testid="manual-recovery"
        className="flex flex-col gap-1.5 rounded-lg border-2 border-crit bg-crit-bg px-4 py-3 text-[13.5px]"
      >
        <b className="text-crit">
          <span aria-hidden="true">✕ </span>
          {t('dep.out.manual.title')}
        </b>
        <span>{d.error?.message ?? t('dep.out.manual.body')}</span>
        <ol className="m-0 flex flex-col gap-0.5 pl-5 text-[12.5px]">
          <li>{t('dep.out.manual.s1')}</li>
          <li>{t('dep.out.manual.s2')}</li>
          <li>{t('dep.out.manual.s3')}</li>
        </ol>
        {code && <code className="font-mono text-[12px] text-fg-muted">{code}</code>}
      </div>
    );
  if (d.status === 'failed') {
    const atPreflight = d.steps.find((s) => s.name === 'preflight')?.status === 'failed';
    const known =
      code &&
      [
        'CANDIDATE_UNHEALTHY',
        'IMAGE_PULL_FAILED',
        'POSTCHECK_FAILED_REVERTED',
        'PORT_IN_USE',
        'SECRETS_UNAVAILABLE',
      ].includes(code);
    return (
      <Notice
        tone="crit"
        glyph="✕"
        role="alert"
        title={t('dep.out.failed', { code: code ?? 'FAILED' })}
      >
        <span data-testid="outcome" data-outcome="failed" data-code={code}>
          {atPreflight
            ? t('dep.out.preflightFailed')
            : known
              ? t(`dep.err.${code}` as MessageKey)
              : (d.error?.message ?? t('dep.out.failedGeneric'))}
        </span>
        {code === 'CANDIDATE_UNHEALTHY' && <UnhealthyDetails details={d.error?.details} />}
        {!atPreflight && (
          <span className="mt-1 block font-medium text-ok" data-testid="live-untouched">
            ●{' '}
            {previousNumber
              ? t('dep.out.liveUntouchedN', { n: previousNumber })
              : t('dep.out.liveUntouched')}
          </span>
        )}
      </Notice>
    );
  }
  if (d.status === 'awaiting_approval')
    return (
      <Notice tone="warn" glyph="▲" role="status" title={t('dep.out.awaiting')}>
        <span data-testid="outcome" data-outcome="awaiting_approval">
          {t('dep.out.awaitingBody')}
        </span>
      </Notice>
    );
  if (d.status === 'cancelled')
    return (
      <Notice tone="neutral" glyph="○" role="status" title={t('dep.out.cancelled')}>
        <span data-testid="outcome" data-outcome="cancelled">
          {t('dep.out.cancelledBody')}
        </span>
      </Notice>
    );
  if (d.status === 'expired')
    return (
      <Notice tone="neutral" glyph="○" role="status" title={t('dep.status.expired')}>
        {t('dep.out.expiredBody')}
      </Notice>
    );
  return null;
}

/** Agent CANDIDATE_UNHEALTHY details: {logTail[], attempts, elapsedMs, reason, removed, exitCode?, lastStatus?, lastError?}. */
function UnhealthyDetails({ details }: { details: unknown }) {
  const { t } = useI18n();
  if (!details || typeof details !== 'object') return null;
  const x = details as {
    logTail?: string[];
    attempts?: number;
    elapsedMs?: number;
    reason?: string;
    removed?: boolean;
    exitCode?: number;
    lastStatus?: number;
    lastError?: string;
  };
  const facts = [
    x.attempts !== undefined && t('dep.unhealthy.attempts', { n: x.attempts }),
    x.elapsedMs !== undefined && formatDuration(x.elapsedMs),
    x.lastStatus !== undefined && `HTTP ${x.lastStatus}`,
    x.exitCode !== undefined && t('dep.unhealthy.exit', { code: x.exitCode }),
    x.reason,
    x.lastError,
    x.removed && t('dep.unhealthy.removed'),
  ].filter(Boolean);
  return (
    <span className="mt-1 flex flex-col gap-1" data-testid="unhealthy-details">
      {facts.length > 0 && (
        <span className="font-mono text-[12px] text-fg-2">{facts.join(' · ')}</span>
      )}
      {x.logTail && x.logTail.length > 0 && (
        <pre className="m-0 max-h-40 overflow-auto rounded-md bg-terminal px-3 py-2 font-mono text-[11.5px] whitespace-pre-wrap text-terminal-fg">
          {x.logTail.join('\n')}
        </pre>
      )}
    </span>
  );
}

// ---------------------------------------------------------------- approval (planHash + step-up)

/**
 * Two-person approval with a fresh 2FA code, bound to the exact plan hash (same rules as Nginx
 * revisions: approver ≠ creator, single use, 60 minutes).
 */
export function PlanApproval({
  planHash,
  required,
  awaiting,
  isCreator,
  gate,
  approvedByLabel,
  approvedAt,
  expiresAt,
  onApprove,
  onApproved,
  testId = 'approval-panel',
  copy,
}: {
  /** P9 reuse: override the deployment-specific wording (rule / waiting / not required). */
  copy?: { rule?: MessageKey; waiting?: MessageKey; notRequired?: MessageKey };
  planHash: string | null;
  required: boolean;
  awaiting: boolean;
  isCreator: boolean;
  gate: GateResult;
  approvedByLabel?: string | null;
  approvedAt?: string | null;
  expiresAt?: string | null;
  onApprove: (planHash: string, stepUpToken: string) => Promise<unknown>;
  onApproved?: () => void;
  testId?: string;
}) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const [otp, setOtp] = useState('');
  const m = useMutation<unknown, ApiError>({
    mutationFn: wrap(async () => {
      const token = (await authApi.stepUp(otp)).stepUpToken;
      return onApprove(planHash ?? '', token);
    }),
    onSuccess: () => {
      setOtp('');
      onApproved?.();
    },
  });
  if (!required)
    return (
      <p className="m-0 text-[12.5px] text-fg-muted">
        {t(copy?.notRequired ?? 'dep.approval.notRequired')}
      </p>
    );
  const expired = approvalExpiredAt(expiresAt);
  return (
    <section className="flex flex-col gap-2 rounded-md border border-line p-3" data-testid={testId}>
      <h3 className="m-0 text-[13.5px] font-semibold">{t('approval.title')}</h3>
      <dl className="m-0 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
        <dt className="text-fg-muted">{t('approval.planHash')}</dt>
        <dd className="m-0 font-mono text-[12px] break-all" data-testid="plan-hash">
          {planHash ?? t('common.dash')}
        </dd>
        <dt className="text-fg-muted">{t('approval.rule')}</dt>
        <dd className="m-0">{t(copy?.rule ?? 'dep.approval.rule')}</dd>
        {approvedByLabel && (
          <>
            <dt className="text-fg-muted">{t('approval.approvedBy')}</dt>
            <dd className="m-0">
              {approvedByLabel}
              {approvedAt && ` · ${formatDateTime(approvedAt, locale)}`}
            </dd>
            <dt className="text-fg-muted">{t('approval.expires')}</dt>
            <dd className={cn('m-0', expired && 'text-crit')}>
              {expiresAt ? formatDateTime(expiresAt, locale) : t('common.dash')}
              {expired && ` · ${t('approval.expired')}`}
            </dd>
          </>
        )}
      </dl>
      {awaiting &&
        (isCreator ? (
          <Notice tone="warn" glyph="◐" role="status">
            <span data-testid="waiting-approver">{t(copy?.waiting ?? 'dep.approval.waiting')}</span>
          </Notice>
        ) : gate.allowed ? (
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[220px] flex-1">
              <StepUpField value={otp} onChange={setOtp} hint={t('approval.stepUpHint')} />
            </div>
            <Button
              variant="primary"
              disabled={!/^\d{6}$/.test(otp) || !me?.mfaEnabled || m.isPending || !planHash}
              onClick={() => m.mutate()}
            >
              {m.isPending
                ? t('common.saving')
                : t('approval.approve', { hash: (planHash ?? '').slice(0, 12) })}
            </Button>
          </div>
        ) : (
          <GatedButton perm="approvals.decide" blockedReason={gate.reason}>
            {t('approval.approve', { hash: (planHash ?? '').slice(0, 12) })}
          </GatedButton>
        ))}
      {m.error && <ErrorState error={m.error} />}
    </section>
  );
}

// ---------------------------------------------------------------- webhook deliveries

export function DeliveryResultBadge({ d }: { d: WebhookDelivery }) {
  const { t } = useI18n();
  const reasons = d.reasons ?? [];
  const duplicate =
    (d as { duplicate?: boolean }).duplicate === true ||
    reasons.includes('duplicate_delivery') ||
    (d.result as string) === 'duplicate';
  const invalid = !d.signatureOk || (d.result as string) === 'invalid';
  let tone: Tone = 'off';
  let key: MessageKey = 'wh.result.ignored';
  if (invalid) {
    tone = 'crit';
    key = 'wh.result.invalid';
  } else if (duplicate) {
    tone = 'off';
    key = 'wh.result.duplicate';
  } else if (d.result === 'deployed') {
    tone = 'ok';
    key = 'wh.result.deployed';
  } else if (d.result === 'awaiting_approval') {
    tone = 'warn';
    key = 'wh.result.awaiting_approval';
  } else if ((d.result as string) === 'building') {
    tone = 'warn';
    key = 'wh.result.building';
  } else if ((d.result as string) === 'queued') {
    tone = 'warn';
    key = 'wh.result.queued';
  } else if ((d.result as string) === 'superseded') {
    tone = 'off';
    key = 'wh.result.superseded';
  } else if (d.result === 'failed') {
    tone = 'crit';
    key = 'wh.result.failed';
  }
  const reasonText = reasons.filter((r) => r !== 'duplicate_delivery').join(', ');
  return (
    <span
      className="inline-flex flex-wrap items-center gap-1"
      data-testid="delivery-result"
      data-result={invalid ? 'invalid' : duplicate ? 'duplicate' : d.result}
    >
      <ToneBadge tone={tone} size="sm">
        {t(key)}
      </ToneBadge>
      {reasonText && !invalid && (
        <span className="font-mono text-[11.5px] text-fg-muted">({reasonText})</span>
      )}
    </span>
  );
}

export function DeploymentLink({
  id,
  n,
  children,
}: {
  id: string;
  n?: number;
  children?: ReactNode;
}) {
  return (
    <Link href={`/deployments/${id}`} className="font-mono text-[12.5px]">
      {children ?? `#${n ?? id.slice(0, 8)}`}
    </Link>
  );
}
