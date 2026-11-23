'use client';

import Link from 'next/link';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import { containerAppsApi } from '@/lib/api/p4-endpoints';
import type { Deployment } from '@/lib/api/p4-types';
import { buildsApi } from '@/lib/api/p4b-endpoints';
import { BUILD_ACTIVE, BUILD_PHASES, type Build, type BuildStatus } from '@/lib/api/p4b-types';
import { boundLog, buildPhaseStates, type PhaseState } from '@/lib/p4b-gates';
import { evaluateGate } from '@/lib/permissions';
import { useBuild, useBuildLog } from '@/lib/p4b-queries';
import { formatDateTime, formatDuration } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { Card, DefList } from '@/components/ui/card';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { CopyButton } from '@/components/ui/copy-button';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ActionDialog } from '@/components/p3/action-dialog';
import { Sha } from '@/components/p3/bits';
import { ImageRef } from './bits';
import { DeploymentExecution } from './execution';
import type { MessageKey } from '@/i18n/en';

const STATUS_TONE: Record<BuildStatus, Tone> = {
  queued: 'off',
  fetching: 'info',
  building: 'info',
  pushing: 'info',
  succeeded: 'ok',
  failed: 'crit',
  cancelled: 'off',
  expired: 'stale',
};

export function BuildStatusBadge({ status }: { status: BuildStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge
      tone={STATUS_TONE[status]}
      size="sm"
      glyph={BUILD_ACTIVE.includes(status) ? '◌' : undefined}
    >
      <span data-testid="build-status" data-status={status}>
        {t(`build.status.${status}` as MessageKey)}
      </span>
    </ToneBadge>
  );
}

const PHASE_GLYPH: Record<PhaseState, [string, string]> = {
  done: ['●', 'text-ok'],
  current: ['◌', 'text-info'],
  pending: ['○', 'text-off'],
  failed: ['✕', 'text-crit'],
  skipped: ['–', 'text-fg-subtle'],
};

/** queued → building strip (glyph + text, never colour alone). */
export function BuildPhases({ build }: { build: Pick<Build, 'status' | 'error'> }) {
  const { t } = useI18n();
  const states = buildPhaseStates(build);
  return (
    <ol
      className="m-0 flex list-none flex-wrap gap-1.5 p-0"
      aria-label={t('build.phases')}
      data-testid="build-phases"
    >
      {BUILD_PHASES.map((p) => {
        const s = states[p];
        const [g, tone] = PHASE_GLYPH[s];
        return (
          <li
            key={p}
            data-phase={p}
            data-state={s}
            aria-current={s === 'current' ? 'step' : undefined}
            className={cn(
              'flex min-h-8 items-center gap-1.5 rounded-md border px-2.5 text-[12.5px]',
              s === 'current'
                ? 'border-accent-strong bg-info-bg font-medium'
                : 'border-line bg-surface',
            )}
          >
            <span aria-hidden="true" className={cn('font-bold', tone)}>
              {g}
            </span>
            {t(`build.status.${p}` as MessageKey)}
            <span className="sr-only">{t(`build.phase.${s}` as MessageKey)}</span>
          </li>
        );
      })}
    </ol>
  );
}

/**
 * Bounded, monospace build log: keeps the last N lines, optional auto-scroll (pauses while the reader
 * scrolls up), copy. Output from the build host is never translated.
 */
export function BuildLogViewer({
  lines,
  live,
  truncated,
  max,
  label,
}: {
  lines: readonly string[];
  live: boolean;
  truncated?: boolean;
  max?: number;
  label?: string;
}) {
  const { t } = useI18n();
  const ref = useRef<HTMLPreElement>(null);
  const [follow, setFollow] = useState(true);
  const b = boundLog(lines, max);
  const text = b.lines.join('\n');
  useLayoutEffect(() => {
    const el = ref.current;
    if (el && follow) el.scrollTop = el.scrollHeight;
  }, [text, follow]);
  return (
    <div className="flex flex-col gap-1.5" data-testid="build-log">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-muted">
        <span className="flex-1">
          {t('build.log.lines', { n: b.lines.length })}
          {(b.dropped > 0 || truncated) && ` · ${t('build.log.dropped', { n: b.dropped })}`}
          {b.clipped > 0 && ` · ${t('build.log.clipped', { n: b.clipped })}`}
          {live && ` · ${t('build.log.live')}`}
        </span>
        <label className="inline-flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={follow}
            onChange={(e) => setFollow(e.target.checked)}
            data-testid="build-log-follow"
          />
          {t('build.log.autoscroll')}
        </label>
        <CopyButton text={text} />
      </div>
      {b.lines.length === 0 ? (
        <p className="m-0 rounded-md bg-terminal px-3 py-2.5 font-mono text-[12px] text-terminal-fg">
          {live ? t('build.log.waiting') : t('build.log.empty')}
        </p>
      ) : (
        <pre
          ref={ref}
          tabIndex={0}
          aria-label={label ?? t('build.log.title')}
          data-testid="build-log-text"
          data-dropped={b.dropped}
          onScroll={(e) => {
            const el = e.currentTarget;
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
            if (!atBottom && follow && live) setFollow(false);
          }}
          className="m-0 max-h-[420px] overflow-auto rounded-md bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.55] whitespace-pre-wrap text-terminal-fg"
        >
          {text}
        </pre>
      )}
    </div>
  );
}

/** Log of one build: stored full log when available, else the live tail. */
export function BuildLog({ build }: { build: Build }) {
  const live = BUILD_ACTIVE.includes(build.status);
  const log = useBuildLog(build.id, live);
  // Refetch the stored log once when the status changes (e.g. building → failed): the last live
  // poll may predate the final lines.
  const { refetch } = log;
  useEffect(() => {
    void refetch();
  }, [build.status, refetch]);
  const lines = log.data?.lines?.length ? log.data.lines : build.logTail;
  return <BuildLogViewer lines={lines} live={live} truncated={log.data?.truncated} />;
}

/**
 * Build phase of the execution step: status + phases + live log + cancel; on success hands over to
 * the deployment timeline (P4a), on failure states that nothing was deployed.
 */
export function BuildExecution({
  buildId,
  serverName,
  reused = false,
}: {
  buildId: string;
  serverName?: string;
  /** 200 `{ reused: true }`: the commit was already built; the Center created no deployment. */
  reused?: boolean;
}) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useBuild(buildId);
  const b = q.data;
  const now = useNow(1000);
  const [cancelOpen, setCancelOpen] = useState(false);
  const [manualDep, setManualDep] = useState<string | null>(null);
  const deployDigest = useMutation<Deployment, ApiError>({
    mutationFn: async () => {
      try {
        return await containerAppsApi.deploy(b!.applicationId, {
          image: b!.image!,
          sourceRef: { commitSha: b!.commitSha, ...(b!.branch ? { branch: b!.branch } : {}) },
          reason: `Build ${b!.commitSha.slice(0, 7)} (reused)`,
        });
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (d) => {
      setManualDep(d.id);
      void qc.invalidateQueries({ queryKey: ['deployments'], exact: false });
    },
  });
  const waitDeploy =
    !!b &&
    b.status === 'succeeded' &&
    !b.deploymentId &&
    !reused &&
    !b.deployError &&
    b.deployAfter !== false;
  const live = !!b && BUILD_ACTIVE.includes(b.status);
  // After success the deployment id may arrive a poll later: keep polling briefly.
  const { refetch } = q;
  useEffect(() => {
    if (!waitDeploy) return;
    const h = setInterval(() => void refetch(), 1000);
    return () => clearInterval(h);
  }, [waitDeploy, refetch]);

  if (q.isPending)
    return (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="flex flex-col gap-2"
      >
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  if (q.isError && !b) {
    const e = q.error;
    if (isApiError(e) && e.status === 404) return <EmptyState title={t('build.notFound')} />;
    if (isApiError(e) && e.status === 403)
      return <ForbiddenState perm="apps.read" requestId={e.requestId} />;
    return <ErrorState error={e} onRetry={() => void q.refetch()} />;
  }
  if (!b) return null;

  const cancelGate = evaluateGate({
    permissions: me?.permissions,
    perm: 'apps.deploy',
    action: b.allowedActions ? 'cancel' : undefined,
    allowedActions: b.allowedActions,
    blockedReason: live ? undefined : { key: 'build.block.notRunning' },
  });
  const start = Date.parse(b.createdAt);
  const end = b.finishedAt ? Date.parse(b.finishedAt) : now;
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['builds'], exact: false });
    void qc.invalidateQueries({ queryKey: ['applications', 'one', b.applicationId], exact: false });
  };

  return (
    <div className="flex flex-col gap-4" data-testid="build-execution" data-status={b.status}>
      <section className="flex flex-col gap-3" aria-labelledby="build-phase-title">
        <div className="flex flex-wrap items-center gap-2.5">
          <h3 id="build-phase-title" className="m-0 text-[15px] font-semibold">
            {t('build.phaseTitle')}
          </h3>
          <BuildStatusBadge status={b.status} />
          <span className="font-mono text-[12px] text-fg-muted">
            {b.durationMs ? formatDuration(b.durationMs) : formatDuration(end - start)}
          </span>
          <span className="flex-1" />
          {live && (
            <GatedButton
              size="sm"
              variant="danger"
              perm="apps.deploy"
              blockedReason={cancelGate.allowed ? undefined : cancelGate.reason}
              onClick={() => setCancelOpen(true)}
              data-testid="build-cancel"
            >
              {t('build.cancel')}
            </GatedButton>
          )}
        </div>
        {q.isError && (
          <Notice tone="warn" glyph="◐" role="status" title={t('state.stale.title')}>
            {t('state.stale.body')}
          </Notice>
        )}
        <BuildPhases build={b} />
        <div aria-live="polite">
          {b.status === 'failed' && (
            <Notice
              tone="crit"
              glyph="✕"
              role="alert"
              title={t('build.failed.title', { code: b.error?.code ?? 'IMAGE_BUILD_FAILED' })}
            >
              <span data-testid="build-failed" className="block">
                {t('build.failed.body')}
              </span>
              {b.error?.message && (
                <span className="mt-1 block font-mono text-[12px]">{b.error.message}</span>
              )}
              <span className="mt-1 block font-medium text-ok" data-testid="live-untouched">
                ● {t('build.failed.liveUntouched')}
              </span>
            </Notice>
          )}
          {b.status === 'cancelled' && (
            <Notice tone="neutral" glyph="○" role="status" title={t('build.status.cancelled')}>
              {t('build.cancelledBody')}
            </Notice>
          )}
          {b.status === 'expired' && (
            <Notice tone="neutral" glyph="◐" role="status" title={t('build.status.expired')}>
              {t('build.expiredBody')}
            </Notice>
          )}
          {b.status === 'succeeded' && (
            <Notice tone="ok" glyph="●" role="status" title={t('build.succeeded.title')}>
              <span className="font-mono text-[12px] break-all" data-testid="build-image">
                {b.image}
              </span>
            </Notice>
          )}
        </div>
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,340px)]">
          <Card className="flex flex-col gap-2 p-4">
            <h4 className="m-0 text-[14px] font-semibold">{t('build.log.title')}</h4>
            <BuildLog build={b} />
          </Card>
          <Card className="flex flex-col gap-2 p-4">
            <DefList
              keyWidth={110}
              rows={[
                [
                  t('build.node'),
                  b.buildServerName ?? serverName ?? b.buildServerId.slice(0, 8),
                  { mono: true },
                ],
                [t('build.commit'), <Sha key="c" value={b.commitSha} />],
                [t('build.branch'), b.branch ?? t('common.dash'), { mono: true }],
                [
                  t('build.method'),
                  b.template
                    ? t(`build.template.${b.template}` as MessageKey)
                    : (b.dockerfile ?? 'Dockerfile'),
                  { mono: !b.template },
                ],
                [
                  t('build.image'),
                  b.image ? <ImageRef key="i" image={b.image} /> : t('common.dash'),
                ],
                [t('dep.createdAt'), formatDateTime(b.createdAt, locale)],
              ]}
            />
          </Card>
        </div>
      </section>

      {b.status === 'succeeded' && (
        <section
          className="flex flex-col gap-2 border-t border-line-subtle pt-4"
          aria-labelledby="deploy-phase-title"
        >
          <h3 id="deploy-phase-title" className="m-0 text-[15px] font-semibold">
            {t('build.deployPhase')}
          </h3>
          {b.deploymentId || manualDep ? (
            <>
              {reused && b.deploymentId && !manualDep && (
                <Notice tone="info" glyph="◆" role="status">
                  {t('build.reusedLinked')}
                </Notice>
              )}
              <DeploymentExecution id={(manualDep ?? b.deploymentId)!} />
              <Link
                href={`/deployments/${manualDep ?? b.deploymentId}`}
                className="self-start text-[13px]"
              >
                {t('wiz.exec.open')} →
              </Link>
            </>
          ) : reused || b.deployError || b.deployAfter === false ? (
            <div className="flex flex-col gap-2" data-testid="build-no-deployment">
              <Notice
                tone={b.deployError ? 'warn' : 'info'}
                glyph={b.deployError ? '▲' : '◆'}
                role="status"
              >
                {b.deployError
                  ? `${b.deployError.code}: ${b.deployError.message}`
                  : t('build.reusedBody')}
              </Notice>
              {b.image && (
                <div>
                  <GatedButton
                    variant="primary"
                    perm="apps.deploy"
                    disabled={deployDigest.isPending}
                    onClick={() => deployDigest.mutate()}
                    data-testid="deploy-digest"
                  >
                    {deployDigest.isPending ? t('wiz.rev.deploying') : t('build.deployDigest')}
                  </GatedButton>
                </div>
              )}
              {deployDigest.error && <ErrorState error={deployDigest.error} />}
            </div>
          ) : (
            <p role="status" className="m-0 text-[13px] text-fg-muted">
              {t('build.waitingDeployment')}
            </p>
          )}
        </section>
      )}

      <ActionDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        title={t('build.cancelTitle')}
        body={t('build.cancelBody')}
        confirmLabel={t('build.cancel')}
        danger
        needsStepUp={false}
        onConfirm={async () => {
          await buildsApi.cancel(b.id);
          refresh();
        }}
      />
    </div>
  );
}
