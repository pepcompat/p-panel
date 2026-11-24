'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { isApiError, type ApiError } from '@/lib/api/errors';
import { plansApi } from '@/lib/api/p9-endpoints';
import type { GatewayChangePlan, ShadowResult } from '@/lib/api/p9-types';
import { useAuth } from '@/lib/auth/auth-provider';
import {
  PLAN_STEPS,
  cutoverText,
  planGate,
  planStepState,
  shadowAllMatch,
  type PlanStep,
  type StepState,
} from '@/lib/p9-gates';
import { p9k, useGateway, usePlan } from '@/lib/p9-queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { ActionDialog, wrap } from '@/components/p3/action-dialog';
import { Sha } from '@/components/p3/bits';
import { PlanApproval } from '@/components/p4/bits';
import { Card } from '@/components/ui/card';
import { EnvBadge, ToneBadge } from '@/components/ui/badge';
import { CopyButton } from '@/components/ui/copy-button';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { MiniTable } from './diagnostics';
import { ModeBadge, PlanStatusBadge } from './gateway-bits';
import { CardTitle } from './net-bits';

type PlanView = GatewayChangePlan & {
  createdByLabel?: string | null;
  approvedByLabel?: string | null;
  approvalExpiresAt?: string | null;
  error?: { code: string; message: string } | null;
};

const STEP_GLYPH: Record<StepState, { g: string; cls: string }> = {
  done: { g: '●', cls: 'text-ok' },
  current: { g: '◆', cls: 'text-info' },
  running: { g: '◌', cls: 'text-info' },
  todo: { g: '○', cls: 'text-off' },
  skipped: { g: '–', cls: 'text-off' },
  failed: { g: '✕', cls: 'text-crit' },
};

function Stepper({ plan }: { plan: PlanView }) {
  const { t } = useI18n();
  const st = planStepState(plan);
  return (
    <ol
      className="m-0 grid list-none gap-2 p-0 sm:grid-cols-5"
      aria-label={t('p9.plan.steps')}
      data-testid="plan-stepper"
    >
      <li className="flex items-center gap-2 rounded-md border border-line px-3 py-2 text-[13px]">
        <span aria-hidden="true" className="font-bold text-ok">
          ●
        </span>
        <span className="flex-1">{t('p9.plan.step.create')}</span>
      </li>
      {PLAN_STEPS.map((k: PlanStep) => (
        <li
          key={k}
          data-step={k}
          data-state={st[k]}
          aria-current={st[k] === 'current' || st[k] === 'running' ? 'step' : undefined}
          className={cn(
            'flex items-center gap-2 rounded-md border px-3 py-2 text-[13px]',
            st[k] === 'current' || st[k] === 'running' ? 'border-info bg-info-bg' : 'border-line',
          )}
        >
          <span aria-hidden="true" className={cn('font-bold', STEP_GLYPH[st[k]].cls)}>
            {STEP_GLYPH[st[k]].g}
          </span>
          <span className="flex-1">{t(`p9.plan.step.${k}` as MessageKey)}</span>
          <span className="text-[11px] text-fg-muted">{t(`p9.step.${st[k]}` as MessageKey)}</span>
        </li>
      ))}
    </ol>
  );
}

function ProbeCell({ p }: { p: ShadowResult['viaGateway'] }) {
  const { t } = useI18n();
  return (
    <span className="flex flex-col gap-0.5 font-mono text-[12px]">
      <span>
        {p.status ?? t('common.dash')}
        {p.latencyMs != null && <span className="text-fg-muted"> · {p.latencyMs} ms</span>}
      </span>
      <Sha value={p.bodySha256} />
      {p.error && <span className="text-crit">{p.error}</span>}
    </span>
  );
}

export function ShadowTable({
  results,
  caption,
  testId,
}: {
  results: ShadowResult[];
  caption: string;
  testId?: string;
}) {
  const { t } = useI18n();
  return (
    <MiniTable
      testId={testId}
      caption={caption}
      head={[
        t('p9.shadow.domain'),
        t('p9.shadow.via'),
        t('p9.shadow.direct'),
        t('p9.shadow.match'),
      ]}
      rows={results.map((r) => [
        <span key="d" className="flex flex-col">
          <span className="font-mono">{r.domain}</span>
          {r.url && <span className="font-mono text-[11px] text-fg-muted">{r.url}</span>}
        </span>,
        <ProbeCell key="v" p={r.viaGateway} />,
        <ProbeCell key="x" p={r.direct} />,
        <ToneBadge key="m" tone={r.match ? 'ok' : 'crit'} size="sm">
          <span data-testid="shadow-match" data-match={String(r.match)}>
            {r.match ? t('p9.shadow.matches') : t('p9.shadow.differs')}
          </span>
        </ToneBadge>,
      ])}
    />
  );
}

function CutoverChecklist({ plan }: { plan: PlanView }) {
  const { t } = useI18n();
  const c = plan.cutover;
  const [done, setDone] = useState<Record<string, boolean>>({});
  if (!c) return null;
  const changes = c.dnsChanges.filter((x) => x.action !== 'none');
  const item = (id: string, children: React.ReactNode) => (
    <li className="flex items-start gap-2">
      <input
        id={`co-${id}`}
        type="checkbox"
        className="mt-1"
        checked={!!done[id]}
        onChange={(e) => setDone((d) => ({ ...d, [id]: e.target.checked }))}
      />
      <label htmlFor={`co-${id}`} className="min-w-0 flex-1 text-[13px]">
        {children}
      </label>
    </li>
  );
  return (
    <Card
      className="flex flex-col gap-3 border-2 border-info p-4"
      aria-labelledby="cutover-h"
      data-testid="cutover"
    >
      <CardTitle
        id="cutover-h"
        actions={
          <CopyButton
            text={cutoverText(plan)}
            label={t('p9.cutover.copyAll')}
            size="sm"
            variant="secondary"
          />
        }
      >
        {t('p9.cutover.title')}
      </CardTitle>
      <Notice tone="warn" glyph="▲" role="note" title={t('p9.cutover.neverDnsTitle')}>
        <span data-testid="cutover-never-dns">{t('p9.cutover.neverDns')}</span>
        {c.note && <span className="mt-1 block text-[12.5px] text-fg-2">{c.note}</span>}
      </Notice>
      <section aria-labelledby="co-dns-h" className="flex flex-col gap-2">
        <h3 id="co-dns-h" className="m-0 text-[13.5px] font-semibold">
          {t('p9.cutover.dns')}
        </h3>
        {changes.length === 0 ? (
          <p className="m-0 text-[13px] text-fg-muted" data-testid="cutover-no-dns">
            {t('p9.cutover.noDns')}
          </p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
            {changes.map((r) => {
              const value = (r.action === 'point_to_gateway' ? r.target : r.directTarget) ?? '?';
              const line = `${r.domain}. ${r.recordType} ${value}`;
              return item(
                `dns-${r.domain}`,
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">{line}</span>
                  <span className="text-[12px] text-fg-muted">
                    {t(
                      r.action === 'point_to_gateway'
                        ? 'p9.cutover.wasDirect'
                        : 'p9.cutover.backDirect',
                      {
                        ip: r.directTarget ?? '?',
                      },
                    )}
                  </span>
                  <CopyButton
                    text={line}
                    ariaLabel={t('p9.cutover.copyRecord', { domain: r.domain })}
                  />
                </span>,
              );
            })}
          </ul>
        )}
        <MiniTable
          caption={t('p9.cutover.perDomain')}
          head={[
            t('p9.shadow.domain'),
            t('p9.route.mode'),
            t('p9.cutover.points'),
            t('p9.cutover.action'),
          ]}
          rows={c.dnsChanges.map((r) => [
            <span key="d" className="font-mono">
              {r.domain}
            </span>,
            <ModeBadge key="m" mode={r.mode} />,
            <span key="p" className="font-mono">
              {r.target ?? '—'}
            </span>,
            t(`p9.cutover.act.${r.action}` as MessageKey),
          ])}
        />
      </section>
      <section aria-labelledby="co-ttl-h" className="flex flex-col gap-1">
        <h3 id="co-ttl-h" className="m-0 text-[13.5px] font-semibold">
          {t('p9.cutover.ttl')}
        </h3>
        <p className="m-0 text-[13px] text-fg-2">{c.ttlAdvice}</p>
      </section>
      <section aria-labelledby="co-verify-h" className="flex flex-col gap-1.5">
        <h3 id="co-verify-h" className="m-0 text-[13.5px] font-semibold">
          {t('p9.cutover.verify')}
        </h3>
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
          {c.verification.map((cmd, i) =>
            item(
              `v-${i}`,
              <span className="flex flex-wrap items-center gap-2">
                <code className="rounded bg-chip px-1.5 py-0.5 font-mono text-[12px] break-all">
                  {cmd}
                </code>
                <CopyButton text={cmd} ariaLabel={t('p9.cutover.copyCommand', { n: i + 1 })} />
              </span>,
            ),
          )}
        </ul>
      </section>
      <section aria-labelledby="co-rb-h" className="flex flex-col gap-1.5">
        <h3 id="co-rb-h" className="m-0 text-[13.5px] font-semibold">
          {t('p9.cutover.rollback')}
        </h3>
        <ol
          className="m-0 flex list-decimal flex-col gap-1 pl-5 text-[13px]"
          data-testid="cutover-rollback"
        >
          {c.rollback.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
      </section>
    </Card>
  );
}

export function PlanDetail({ gatewayId, planId }: { gatewayId: string; planId: string }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = usePlan(planId);
  const gw = useGateway(gatewayId);
  const [applyOpen, setApplyOpen] = useState(false);
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const plan = q.data as PlanView | undefined;
  const prod = gw.data?.environment === 'production' || !!plan?.approval?.required;
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: p9k.plan(planId) });
    void qc.invalidateQueries({ queryKey: p9k.plans(gatewayId) });
  };
  const shadow = useMutation<unknown, ApiError>({
    mutationFn: wrap(() => plansApi.shadowTest(planId)),
    onSuccess: refresh,
  });
  if (q.isPending) return <Skeleton className="h-64 w-full" />;
  if (q.isError)
    return isApiError(q.error) && q.error.status === 404 ? (
      <EmptyState title={t('p9.plan.notFound')} />
    ) : isApiError(q.error) && q.error.status === 403 ? (
      <ForbiddenState perm="fleet.read" requestId={q.error.requestId} />
    ) : (
      <ErrorState error={q.error} onRetry={() => void q.refetch()} />
    );
  if (!plan) return null;
  const gate = (a: Parameters<typeof planGate>[0]) =>
    planGate(a, plan, me?.permissions, me?.user.id);
  const isCreator = plan.createdBy === me?.user.id;
  const allMatch = shadowAllMatch(plan);
  return (
    <div className="flex flex-col gap-4" data-testid="plan-detail" data-status={plan.status}>
      <Link href={`/network/gateways/${gatewayId}`} className="self-start text-[13px]">
        {t('p9.plan.back', { name: gw.data?.name ?? '' })}
      </Link>
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 flex-1 text-[19px] font-semibold">
          {t('p9.plan.heading', { name: gw.data?.name ?? '' })}
        </h2>
        {gw.data && (
          <EnvBadge env={gw.data.environment} label={t(envBadgeKey(gw.data.environment))} />
        )}
        <PlanStatusBadge status={plan.status} />
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12.5px] text-fg-muted">
        <span>
          {t('p9.plan.createdBy', {
            who: plan.createdByLabel ?? plan.createdBy.slice(0, 8),
            when: formatDateTime(plan.createdAt, locale),
          })}
          {isCreator && ` · ${t('appr.yours')}`}
        </span>
        <span>
          {t('approval.planHash')}: <Sha value={plan.planHash} />
        </span>
        {plan.nginxRevisionId && (
          <span>
            {t('p9.plan.revision')}:{' '}
            <span className="font-mono">{plan.nginxRevisionId.slice(0, 8)}</span>
            {plan.nginxRevisionStatus && ` (${plan.nginxRevisionStatus})`}
          </span>
        )}
      </div>
      <Stepper plan={plan} />
      {plan.error && (
        <Notice tone="crit" glyph="✕" role="alert" title={plan.error.code}>
          {plan.error.message}
        </Notice>
      )}

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <div className="flex flex-col gap-4">
          <Card
            className="flex flex-col gap-2.5 p-4"
            aria-labelledby="val-h"
            data-testid="validation"
          >
            <CardTitle id="val-h">{t('p9.plan.validation')}</CardTitle>
            {plan.validation?.valid == null ? (
              <p className="m-0 text-[13px] text-fg-muted" role="status">
                ◌ {t('p9.plan.validating')}
              </p>
            ) : (
              <ToneBadge tone={plan.validation.valid ? 'ok' : 'crit'} className="self-start">
                <span data-testid="validation-result">
                  {plan.validation.valid ? t('p9.plan.valid') : t('p9.plan.invalid')}
                </span>
              </ToneBadge>
            )}
            {plan.validation?.nginxTestOutput && (
              <pre className="m-0 overflow-x-auto rounded bg-chip p-2 font-mono text-[12px] whitespace-pre-wrap">
                {plan.validation.nginxTestOutput}
              </pre>
            )}
            <details>
              <summary className="cursor-pointer text-[12.5px]">
                {t('p9.plan.files', { n: plan.rendered.length })}
              </summary>
              <ul className="m-0 mt-2 flex list-none flex-col gap-2 p-0">
                {plan.rendered.map((f) => (
                  <li key={f.path} className="flex flex-col gap-1">
                    <span className="flex flex-wrap items-center gap-2 font-mono text-[12px]">
                      {f.path} <Sha value={f.sha256} />
                    </span>
                    <pre className="m-0 max-h-64 overflow-auto rounded bg-chip p-2 font-mono text-[11.5px]">
                      {f.content}
                    </pre>
                  </li>
                ))}
              </ul>
            </details>
          </Card>

          <Card
            className="flex flex-col gap-2.5 p-4"
            aria-labelledby="shadow-h"
            data-testid="shadow"
          >
            <CardTitle
              id="shadow-h"
              actions={
                <GatedButton
                  size="sm"
                  variant={plan.status === 'validated' ? 'primary' : 'secondary'}
                  perm="policies.manage"
                  blockedReason={
                    gate('shadow_test').allowed ? undefined : gate('shadow_test').reason
                  }
                  disabled={shadow.isPending}
                  onClick={() => shadow.mutate()}
                  data-testid="run-shadow"
                >
                  {plan.shadowResults ? t('p9.shadow.rerun') : t('p9.shadow.run')}
                </GatedButton>
              }
            >
              {t('p9.shadow.title')}
            </CardTitle>
            <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.shadow.intro')}</p>
            {plan.status === 'shadow_testing' && (
              <p className="m-0 text-[13px]" role="status">
                ◌ {t('p9.shadow.running')}
              </p>
            )}
            {shadow.error && <ErrorState error={shadow.error} />}
            {plan.shadowResults && (
              <>
                <ShadowTable
                  testId="shadow-results"
                  results={plan.shadowResults}
                  caption={t('p9.shadow.caption')}
                />
                {!allMatch && (
                  <Notice tone="crit" glyph="✕" role="status" title={t('p9.shadow.mismatchTitle')}>
                    <span data-testid="shadow-mismatch">{t('p9.shadow.mismatch')}</span>
                  </Notice>
                )}
              </>
            )}
          </Card>

          {plan.verification && (
            <Card className="flex flex-col gap-2.5 p-4" aria-labelledby="verif-h">
              <CardTitle id="verif-h">{t('p9.plan.verification')}</CardTitle>
              <ShadowTable results={plan.verification} caption={t('p9.plan.verificationCaption')} />
            </Card>
          )}
        </div>

        <div className="flex flex-col gap-4">
          <Card className="flex flex-col gap-3 p-4" aria-label={t('p9.plan.approvalTitle')}>
            <PlanApproval
              testId="plan-approval"
              planHash={plan.planHash}
              required={!!plan.approval?.required}
              awaiting={plan.status === 'awaiting_approval' && !plan.approval?.approvedBy}
              isCreator={isCreator}
              gate={gate('approve')}
              approvedByLabel={
                plan.approval?.approvedBy
                  ? (plan.approval.approvedByLabel ??
                    plan.approvedByLabel ??
                    plan.approval.approvedBy.slice(0, 8))
                  : null
              }
              approvedAt={plan.approval?.approvedAt ?? null}
              expiresAt={plan.approvalExpiresAt ?? null}
              onApprove={(hash, token) => plansApi.approve(plan.id, hash, token)}
              onApproved={refresh}
              copy={{
                rule: 'p9.plan.approvalRule',
                waiting: 'p9.plan.approvalWaiting',
                notRequired: 'p9.plan.approvalNotRequired',
              }}
            />
            {plan.approval?.required && !allMatch && plan.shadowResults && (
              <p className="m-0 text-[12px] text-warn">▲ {t('p9.plan.approveMismatch')}</p>
            )}
          </Card>
          <Card
            className="flex flex-col gap-3 p-4"
            aria-labelledby="apply-h"
            data-testid="apply-card"
          >
            <CardTitle id="apply-h">{t('p9.plan.applyTitle')}</CardTitle>
            <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.plan.applyIntro')}</p>
            {plan.status === 'applying' && (
              <p className="m-0 text-[13px]" role="status">
                ◌ {t('p9.plan.applying')}
              </p>
            )}
            {plan.status === 'rolling_back' && (
              <p className="m-0 text-[13px]" role="status">
                ◌ {t('p9.plan.rollingBack')}
              </p>
            )}
            <div className="flex flex-wrap gap-2">
              <GatedButton
                variant="primary"
                perm="policies.manage"
                blockedReason={gate('apply').allowed ? undefined : gate('apply').reason}
                onClick={() => setApplyOpen(true)}
                data-testid="apply-plan"
              >
                {t('p9.plan.apply')}
              </GatedButton>
              <GatedButton
                variant="secondary"
                perm="policies.manage"
                blockedReason={gate('rollback').allowed ? undefined : gate('rollback').reason}
                onClick={() => setRollbackOpen(true)}
                data-testid="rollback-plan"
              >
                {t('p9.plan.rollback')}
              </GatedButton>
            </div>
          </Card>
        </div>
      </div>

      <CutoverChecklist plan={plan} />

      <ActionDialog
        open={applyOpen}
        onOpenChange={setApplyOpen}
        title={t('p9.plan.applyConfirmTitle', { name: gw.data?.name ?? '' })}
        body={t('p9.plan.applyConfirmBody')}
        confirmLabel={t('p9.plan.apply')}
        needsStepUp={prod}
        onConfirm={async (token) => {
          await plansApi.apply(plan.id, token);
          refresh();
        }}
      />
      <ActionDialog
        open={rollbackOpen}
        onOpenChange={setRollbackOpen}
        title={t('p9.plan.rollbackConfirmTitle')}
        body={t('p9.plan.rollbackConfirmBody')}
        confirmLabel={t('p9.plan.rollback')}
        danger
        needsStepUp={prod}
        onConfirm={async (token) => {
          await plansApi.rollback(plan.id, token);
          refresh();
        }}
      />
    </div>
  );
}
