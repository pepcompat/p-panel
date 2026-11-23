'use client';

import Link from 'next/link';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { checksFromDetails, containerAppsApi } from '@/lib/api/p4-endpoints';
import type { CreateContainerAppInput, Deployment, PreflightResult } from '@/lib/api/p4-types';
import {
  WIZARD_STEPS,
  canEnterStep,
  deployReady,
  failingChecks,
  initialWizard,
  maxReachableStep,
  resolveImage,
  stepIssues,
  type WizardState,
  type WizardStep,
} from '@/lib/p4-gates';
import { useApplication, useApplications } from '@/lib/p3-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey } from '@/lib/servers';
import { cn, uuid } from '@/lib/utils';
import { Card, DefList, Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/form';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { StepUpField } from '@/components/p3/bits';
import { useSetPageEnv } from '@/components/shell/page-env';
import { PreflightList } from './bits';
import { DeploymentExecution } from './execution';
import {
  ConfigureStep,
  DetectStep,
  DomainStep,
  SourceStep,
  TargetStep,
  type Patch,
} from './wizard-steps';
import type { MessageKey } from '@/i18n/en';

type Env = 'production' | 'uat' | 'development';

/** Prefill the wizard from an existing container application ("Deploy" entry point). */
function fromApp(app: Application): WizardState {
  const w = initialWizard('existing');
  const repo = app.container?.image?.split('@')[0] ?? '';
  return {
    ...w,
    appId: app.id,
    source: { ...w.source, repo },
    target: { serverId: app.serverId },
    config: { ...w.config, name: app.name },
    domain: { ...w.domain, domains: [...app.domains] },
  };
}

export function DeployWizard({ appId }: { appId: string | null }) {
  const { t } = useI18n();
  const { can, status } = useAuth();
  const appQ = useApplication(appId ?? '');
  if (status === 'authenticated' && !can('apps.deploy'))
    return (
      <Page>
        <PageHeader title={t('wiz.title')} />
        <ForbiddenState perm="apps.deploy" />
      </Page>
    );
  if (appId) {
    if (appQ.isPending)
      return (
        <Page>
          <div
            role="status"
            aria-busy="true"
            aria-label={t('common.loading')}
            className="flex flex-col gap-3"
          >
            <Skeleton className="h-7 w-72" />
            <Skeleton className="h-64 w-full" />
          </div>
        </Page>
      );
    if (appQ.isError)
      return (
        <Page>
          <PageHeader title={t('wiz.title')} />
          <ErrorState error={appQ.error} onRetry={() => void appQ.refetch()} />
        </Page>
      );
    if (appQ.data && appQ.data.kind !== 'container')
      return (
        <Page>
          <PageHeader title={t('wiz.title')} />
          <Notice tone="warn" glyph="▲" role="alert">
            {t('wiz.notContainer')}
          </Notice>
        </Page>
      );
  }
  return <Wizard key={appQ.data?.id ?? 'new'} app={appQ.data ?? null} />;
}

function Wizard({ app: initialApp }: { app: Application | null }) {
  const { t } = useI18n();
  const { can } = useAuth();
  const servers = useServers();
  const inventory = useApplications();
  const [w, setW] = useState<WizardState>(() =>
    initialApp ? fromApp(initialApp) : initialWizard('new'),
  );
  const [step, setStep] = useState<WizardStep>('source');
  const [deploymentId, setDeploymentId] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const firstRender = useRef(true);
  /** Secret values staged in Configure, keyed by row id. Not React state; cleared after writing. */
  const secretValues = useRef(new Map<string, string>()).current;
  const registryPassword = useRef<string | null>(null);

  const createdApp = useApplication(w.mode === 'existing' && w.appId ? w.appId : '');
  const app = createdApp.data ?? initialApp;
  const serverList = useMemo(() => servers.data?.items ?? [], [servers.data]);
  const ctx = useMemo(() => ({ servers: serverList }), [serverList]);
  const target = serverList.find((s) => s.id === w.target.serverId) ?? null;
  useSetPageEnv(target?.environment ?? app?.environment);

  const patch: Patch = (fn) => setW((x) => fn(x));
  const idx = WIZARD_STEPS.indexOf(step);
  const reachable = maxReachableStep(w, ctx);
  const issues = stepIssues(step, w, ctx);

  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    headingRef.current?.focus();
  }, [step]);

  function go(s: WizardStep) {
    if (s === 'execution' ? !!deploymentId : canEnterStep(s, w, ctx)) setStep(s);
  }

  const image = useMemo(() => {
    const r = resolveImage(w.source.repo, w.source.ref, w.source.digestRef);
    return r.kind === 'pinned' ? r.ref : r.kind === 'tag' ? r.ref : null;
  }, [w.source]);

  return (
    <Page>
      <PageHeader
        crumb={
          <Link href="/deployments" className="text-fg-muted">
            ← {t('nav.deployments')}
          </Link>
        }
        title={app && w.mode === 'existing' ? t('wiz.titleApp', { app: app.name }) : t('wiz.title')}
        subtitle={t('wiz.subtitle')}
        actions={
          app?.environment ? (
            <EnvBadge env={app.environment} label={t(envBadgeKey(app.environment))} />
          ) : undefined
        }
      />

      <nav aria-label={t('wiz.steps')}>
        <ol className="m-0 flex list-none flex-wrap gap-1.5 p-0">
          {WIZARD_STEPS.map((s, i) => {
            const current = s === step;
            const done = deploymentId ? s !== 'execution' : i < idx;
            const enabled = s === 'execution' ? !!deploymentId : !deploymentId && i <= reachable;
            return (
              <li key={s}>
                <button
                  type="button"
                  aria-current={current ? 'step' : undefined}
                  disabled={!enabled}
                  onClick={() => go(s)}
                  data-testid={`wizard-step-${s}`}
                  className={cn(
                    'flex min-h-9 items-center gap-2 rounded-md border px-3 text-[13px] disabled:cursor-not-allowed disabled:opacity-60',
                    current
                      ? 'border-accent-strong bg-info-bg font-medium'
                      : 'border-line bg-surface hover:bg-surface-hover',
                  )}
                >
                  <span className="font-mono text-[11px] text-fg-muted">
                    {i + 1} <span aria-hidden="true">{done ? '●' : current ? '◆' : '○'}</span>
                  </span>
                  {t(`wiz.step.${s}` as MessageKey)}
                  {done && <span className="sr-only">{t('wiz.stepDone')}</span>}
                </button>
              </li>
            );
          })}
        </ol>
      </nav>

      <Card className="flex flex-col gap-4 p-5" data-testid="wizard" data-step={step}>
        <h2 ref={headingRef} tabIndex={-1} className="m-0 text-[17px] font-semibold outline-none">
          {t(`wiz.step.${step}` as MessageKey)}
          <span className="ml-2 text-[12.5px] font-normal text-fg-muted">
            {t('wiz.stepOf', { n: idx + 1, total: WIZARD_STEPS.length })}
          </span>
        </h2>
        <p className="m-0 -mt-2 text-[13px] text-fg-muted">
          {t(`wiz.step.${step}.desc` as MessageKey)}
        </p>

        {servers.isError && (
          <ErrorState error={servers.error} onRetry={() => void servers.refetch()} />
        )}

        {step === 'source' && <SourceStep w={w} patch={patch} environment={target?.environment} />}
        {step === 'detect' && <DetectStep w={w} patch={patch} />}
        {step === 'target' && <TargetStep w={w} patch={patch} servers={serverList} app={app} />}
        {step === 'configure' && (
          <ConfigureStep
            w={w}
            patch={patch}
            app={app}
            secretValues={secretValues}
            registryPassword={registryPassword}
          />
        )}
        {step === 'domain' && (
          <DomainStep
            w={w}
            patch={patch}
            inventory={inventory.data?.items.filter((a) => a.id !== w.appId)}
            app={app}
          />
        )}
        {step === 'review' && (
          <ReviewStep
            w={w}
            setW={setW}
            app={app}
            image={image}
            serverName={target?.name ?? app?.serverName ?? ''}
            environment={target?.environment ?? app?.environment ?? 'development'}
            secretValues={secretValues}
            registryPassword={registryPassword}
            canDeploy={can('apps.deploy')}
            onDeployed={(d) => {
              setDeploymentId(d.id);
              setStep('execution');
            }}
          />
        )}
        {step === 'execution' && deploymentId && (
          <div className="flex flex-col gap-3">
            <DeploymentExecution id={deploymentId} />
            <Link href={`/deployments/${deploymentId}`} className="self-start text-[13px]">
              {t('wiz.exec.open')} →
            </Link>
          </div>
        )}

        {step !== 'execution' && (
          <div className="flex flex-col gap-2 border-t border-line-subtle pt-3">
            {issues.length > 0 && (
              <ul
                className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px] text-warn"
                id="step-issues"
                data-testid="step-issues"
              >
                {issues.map((k) => (
                  <li key={k}>
                    <span aria-hidden="true">▲ </span>
                    {t(k)}
                  </li>
                ))}
              </ul>
            )}
            <div className="flex justify-between gap-2">
              <Button disabled={idx === 0} onClick={() => go(WIZARD_STEPS[idx - 1]!)}>
                ← {t('common.back')}
              </Button>
              {step !== 'review' && (
                <Button
                  variant="primary"
                  disabled={issues.length > 0}
                  aria-describedby={issues.length ? 'step-issues' : undefined}
                  onClick={() => go(WIZARD_STEPS[idx + 1]!)}
                >
                  {t('common.next')} →
                </Button>
              )}
            </div>
          </div>
        )}
      </Card>
    </Page>
  );
}

// ---------------------------------------------------------------- Review

function toCreateInput(w: WizardState, environment: Env): CreateContainerAppInput {
  const c = w.config;
  const status = Number(c.hcStatus);
  return {
    serverId: w.target.serverId,
    name: c.name,
    environment,
    domains: w.domain.domains.map((d) => d.trim()).filter(Boolean),
    containerPort: Number(c.containerPort),
    healthcheck: {
      path: c.hcPath,
      expectStatus: [status],
      intervalSec: 2,
      timeoutSec: Number(c.hcTimeoutSec),
      startPeriodSec: Number(c.hcStartPeriodSec),
    },
    resources: { memoryMb: Number(c.memoryMb), cpus: Number(c.cpus), pids: 512 },
    env: Object.fromEntries(c.env.filter((e) => e.key).map((e) => [e.key, e.value])),
    secretKeys: c.secrets.map((s) => s.key),
    volumes: c.volumes.map((v) => ({ name: v.name.trim(), mountPath: v.mountPath.trim() })),
    tls:
      w.domain.tls === 'existing'
        ? { certPath: w.domain.certPath, keyPath: w.domain.keyPath }
        : undefined,
  };
}

function ReviewStep({
  w,
  setW,
  app,
  image,
  serverName,
  environment,
  secretValues,
  registryPassword,
  canDeploy,
  onDeployed,
}: {
  w: WizardState;
  setW: (fn: (w: WizardState) => WizardState) => void;
  app: Application | null;
  image: string | null;
  serverName: string;
  environment: Env;
  secretValues: Map<string, string>;
  registryPassword: { current: string | null };
  canDeploy: boolean;
  onDeployed: (d: Deployment) => void;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const prod = environment === 'production';
  const [otp, setOtp] = useState('');
  const [reason, setReason] = useState('');
  const [pf, setPf] = useState<(PreflightResult & { key: string }) | null>(null);
  const [createChecks, setCreateChecks] = useState<PreflightResult['checks'] | null>(null);
  const idemKey = useRef<string>(uuid());
  const planKey = `${w.appId}|${image}`;
  const stale = !!pf && pf.key !== planKey;
  const needsCreate = w.mode === 'new' && !w.appId;
  const stagedSecrets =
    w.config.secrets.filter((s) => s.staged).length + (w.config.registry.passwordStaged ? 1 : 0);
  const needsStepUp = needsCreate && prod && stagedSecrets > 0;

  const preflight = useMutation<PreflightResult, ApiError, string>({
    mutationFn: async (appId) => {
      try {
        return await containerAppsApi.preflight(appId, { image: image ?? '' });
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (r, appId) => {
      setPf({ ...r, key: `${appId}|${image}` });
      idemKey.current = uuid();
    },
  });

  /** Create the application, write staged secrets + registry credential (then drop them), preflight. */
  const prepare = useMutation<Application, ApiError>({
    mutationFn: async () => {
      setCreateChecks(null);
      try {
        const token = needsStepUp ? (await authApi.stepUp(otp)).stepUpToken : undefined;
        const created = await containerAppsApi.create(toCreateInput(w, environment));
        for (const row of w.config.secrets) {
          const v = secretValues.get(row.id);
          if (v === undefined) continue;
          await containerAppsApi.putSecret(created.id, row.key, v, token);
          secretValues.delete(row.id);
        }
        if (w.config.registry.passwordStaged && registryPassword.current !== null) {
          await containerAppsApi.putRegistryAuth(
            created.id,
            {
              serveraddress: w.config.registry.serveraddress,
              username: w.config.registry.username,
              password: registryPassword.current,
            },
            token,
          );
          registryPassword.current = null;
        }
        return created;
      } catch (e) {
        const err = toApiError(e);
        const checks = checksFromDetails(err.details);
        if (checks) setCreateChecks(checks);
        throw err;
      }
    },
    onSuccess: (created) => {
      setOtp('');
      void qc.invalidateQueries({ queryKey: ['applications'], exact: false });
      setW((x) => ({ ...x, mode: 'existing', appId: created.id }));
      preflight.mutate(created.id);
    },
  });

  const deploy = useMutation<Deployment, ApiError>({
    mutationFn: async () => {
      try {
        return await containerAppsApi.deploy(
          w.appId!,
          {
            image: image!,
            reason: reason.trim() || undefined,
            sourceRef:
              w.source.ref && !w.source.ref.startsWith('sha256:')
                ? { tag: w.source.ref }
                : undefined,
          },
          idemKey.current,
        );
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (d) => {
      void qc.invalidateQueries({ queryKey: ['deployments'], exact: false });
      void qc.invalidateQueries({
        queryKey: ['applications', 'one', d.applicationId],
        exact: false,
      });
      onDeployed(d);
    },
  });

  // Run preflight automatically when the plan is known and not yet checked.
  const { mutate: runPreflight, isPending: preflightPending } = preflight;
  useEffect(() => {
    if (w.appId && image && (!pf || pf.key !== `${w.appId}|${image}`) && !preflightPending)
      runPreflight(w.appId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [w.appId, image]);

  const checks = pf && !stale ? pf.checks : createChecks;
  const ready = deployReady({
    checks: pf?.checks,
    stale,
    canDeploy,
    busy: deploy.isPending || preflight.isPending || prepare.isPending,
  });
  const failing = failingChecks(checks);
  const spec = app?.container;
  const domains = needsCreate ? w.domain.domains.filter(Boolean) : (app?.domains ?? []);
  const volumes = needsCreate ? w.config.volumes : (spec?.volumes ?? []);
  const firstDeploy = !spec?.currentDeploymentId;
  const tls = needsCreate
    ? w.domain.tls === 'existing'
      ? w.domain.certPath
      : null
    : (spec?.tls?.certPath ?? null);
  const fromTag = resolveImage(w.source.repo, w.source.ref, w.source.digestRef).kind === 'tag';

  const risks: Array<{ tone: 'warn' | 'crit' | 'info'; key: MessageKey }> = [];
  if (prod) risks.push({ tone: 'warn', key: 'wiz.rev.risk.prod' });
  if (volumes.length) risks.push({ tone: 'warn', key: 'wiz.rev.risk.volumes' });
  if (firstDeploy) risks.push({ tone: 'info', key: 'wiz.rev.risk.first' });
  if (prod && !tls) risks.push({ tone: 'warn', key: 'wiz.rev.risk.httpOnly' });
  if (fromTag) risks.push({ tone: 'info', key: 'wiz.rev.risk.fromTag' });

  return (
    <div className="flex flex-col gap-4">
      {needsCreate && (
        <section
          className="flex flex-col gap-2 rounded-md border border-line p-3"
          data-testid="prepare"
        >
          <h3 className="m-0 text-[14px] font-semibold">{t('wiz.rev.prepare')}</h3>
          <p className="m-0 text-[12.5px] text-fg-muted">
            {t('wiz.rev.prepareBody', { n: stagedSecrets })}
          </p>
          {needsStepUp && (
            <StepUpField value={otp} onChange={setOtp} hint={t('wiz.rev.stepUpSecrets')} />
          )}
          <div>
            <Button
              variant="primary"
              disabled={
                prepare.isPending || (needsStepUp && (!me?.mfaEnabled || !/^\d{6}$/.test(otp)))
              }
              onClick={() => prepare.mutate()}
            >
              {prepare.isPending ? t('common.saving') : t('wiz.rev.create')}
            </Button>
          </div>
          {prepare.error && <ErrorState error={prepare.error} />}
        </section>
      )}

      <section className="flex flex-col gap-2" aria-labelledby="pf-title">
        <div className="flex flex-wrap items-center gap-2">
          <h3 id="pf-title" className="m-0 flex-1 text-[14px] font-semibold">
            {t('pf.title')}
          </h3>
          {w.appId && (
            <Button
              size="sm"
              disabled={preflight.isPending || !image}
              onClick={() => preflight.mutate(w.appId!)}
            >
              {preflight.isPending ? t('pf.running') : t('pf.rerun')}
            </Button>
          )}
        </div>
        {!checks && !preflight.isPending && (
          <p className="m-0 text-[13px] text-fg-muted">
            {needsCreate ? t('pf.afterCreate') : t('pf.notRun')}
          </p>
        )}
        {preflight.isPending && (
          <div role="status" aria-busy="true" className="flex flex-col gap-1.5">
            <span className="text-[12.5px] text-fg-muted">{t('pf.running')}</span>
            <Skeleton className="h-24 w-full" />
          </div>
        )}
        {preflight.error && (
          <ErrorState
            error={preflight.error}
            onRetry={() => w.appId && preflight.mutate(w.appId)}
          />
        )}
        {stale && (
          <Notice tone="warn" glyph="◐" role="status">
            {t('pf.stale')}
          </Notice>
        )}
        {checks && !preflight.isPending && (
          <>
            {failing.length > 0 ? (
              <Notice
                tone="crit"
                glyph="✕"
                role="alert"
                title={t('pf.blocked', { n: failing.length })}
              >
                <span data-testid="preflight-blocked">{t('pf.blockedBody')}</span>
              </Notice>
            ) : (
              <Notice tone="ok" glyph="●" role="status">
                <span data-testid="preflight-ok">{t('pf.allOk')}</span>
              </Notice>
            )}
            <PreflightList checks={checks} />
          </>
        )}
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="plan-title" data-testid="plan">
        <h3 id="plan-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.rev.plan')}
        </h3>
        <DefList
          keyWidth={150}
          rows={[
            [t('dep.col.app'), needsCreate ? w.config.name : (app?.name ?? ''), { mono: true }],
            [t('dep.col.server'), `${serverName} · ${t(envBadgeKey(environment))}`, { mono: true }],
            [
              t('wiz.rev.image'),
              <span key="i" className="font-mono text-[12px] break-all" data-testid="plan-image">
                {image ?? t('common.dash')}
              </span>,
            ],
            [
              t('wiz.rev.port'),
              `${t('wiz.rev.portValue', { port: needsCreate ? w.config.containerPort : String(spec?.containerPort ?? '') })}`,
              { mono: true },
            ],
            [
              t('wiz.rev.route'),
              `${domains.join(', ')} → ${t('wiz.rev.routeTarget')}${spec?.routePath ? ` (${spec.routePath})` : ''}`,
              { mono: true },
            ],
            [
              t('wiz.dom.tls'),
              tls ? t('wiz.rev.tlsExisting', { path: tls }) : t('wiz.dom.tls.http'),
            ],
            [
              t('wiz.cfg.health'),
              needsCreate
                ? `GET ${w.config.hcPath} → ${w.config.hcStatus} · ${w.config.hcStartPeriodSec}s`
                : spec
                  ? `GET ${spec.healthcheck.path} → ${spec.healthcheck.expectStatus.join('/')} · ${spec.healthcheck.startPeriodSec}s`
                  : t('common.dash'),
              { mono: true },
            ],
            [
              t('wiz.cfg.secrets'),
              (needsCreate ? w.config.secrets.map((s) => s.key) : (spec?.secretKeys ?? [])).join(
                ', ',
              ) || t('common.none'),
              { mono: true },
            ],
            [
              t('wiz.cfg.volumes'),
              volumes.map((v) => `${v.name}:${v.mountPath}`).join(', ') || t('common.none'),
              { mono: true },
            ],
          ]}
        />
        <ol className="m-0 flex flex-col gap-1 pl-5 text-[13px]">
          <li>{t('wiz.rev.s1')}</li>
          <li>{t('wiz.rev.s2')}</li>
          <li>{t('wiz.rev.s3')}</li>
          <li>{t('wiz.rev.s4')}</li>
        </ol>
      </section>

      {risks.length > 0 && (
        <section className="flex flex-col gap-1.5" aria-labelledby="risk-title">
          <h3 id="risk-title" className="m-0 text-[14px] font-semibold">
            {t('wiz.rev.risks')}
          </h3>
          <ul
            className="m-0 flex list-none flex-col gap-1 p-0 text-[13px]"
            data-testid="risk-flags"
          >
            {risks.map((r) => (
              <li key={r.key} className="flex gap-2">
                <span
                  aria-hidden="true"
                  className={
                    r.tone === 'crit' ? 'text-crit' : r.tone === 'warn' ? 'text-warn' : 'text-info'
                  }
                >
                  {r.tone === 'info' ? '◆' : '▲'}
                </span>
                {t(r.key)}
              </li>
            ))}
          </ul>
        </section>
      )}

      {prod && (
        <Notice tone="warn" glyph="▲" role="note" title={t('wiz.rev.approvalTitle')}>
          <span data-testid="approval-notice">{t('wiz.rev.approvalBody')}</span>
        </Notice>
      )}

      <Field label={t('wiz.rev.reason')} hint={t('wiz.rev.reasonHint')} className="max-w-[560px]">
        {(p) => (
          <input
            {...p}
            value={reason}
            maxLength={500}
            onChange={(e) => setReason(e.target.value)}
            className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 text-[14px]"
          />
        )}
      </Field>

      {deploy.error && <ErrorState error={deploy.error} />}
      {deploy.error &&
        isApiError(deploy.error) &&
        deploy.error.code === 'DEPLOYMENT_IN_PROGRESS' && (
          <Notice tone="warn" glyph="▲" role="status">
            {t('wiz.rev.inProgress')}
          </Notice>
        )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line-subtle pt-3">
        <Button
          variant="primary"
          size="lg"
          disabled={!ready.ready || !w.appId || !image}
          aria-describedby="deploy-reason"
          onClick={() => deploy.mutate()}
          data-testid="deploy-button"
        >
          {deploy.isPending
            ? t('wiz.rev.deploying')
            : prod
              ? t('wiz.rev.requestDeploy')
              : t('wiz.rev.deploy')}
        </Button>
        <span
          id="deploy-reason"
          className="text-[12.5px] text-fg-muted"
          data-testid="deploy-blocked-reason"
        >
          {ready.reason ? t(ready.reason) : prod ? t('wiz.rev.readyProd') : t('wiz.rev.ready')}
        </span>
      </div>
    </div>
  );
}
