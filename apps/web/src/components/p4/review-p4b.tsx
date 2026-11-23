'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { checksFromDetails, containerAppsApi } from '@/lib/api/p4-endpoints';
import type { CreateContainerAppInput, Deployment, PreflightResult } from '@/lib/api/p4-types';
import { buildConfigApi, buildsApi, composeApi, preflightPlan } from '@/lib/api/p4b-endpoints';
import type { Build, BuildConfig, BuildConfigInput } from '@/lib/api/p4b-types';
import { deployReady, failingChecks, type WizardState } from '@/lib/p4-gates';
import { buildGate, composePlan, deriveComposeServices, toBuildConfig } from '@/lib/p4b-gates';
import { envBadgeKey } from '@/lib/servers';
import { uuid } from '@/lib/utils';
import { DefList } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/form';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, Notice } from '@/components/ui/states';
import { StepUpField } from '@/components/p3/bits';
import { PreflightList } from './bits';
import { ComposePlanTable } from './compose-bits';
import type { MessageKey } from '@/i18n/en';

type Env = 'production' | 'uat' | 'development';
type SetW = (fn: (w: WizardState) => WizardState) => void;

function usePreflight(appId: string | null, planKey: string) {
  const [pf, setPf] = useState<(PreflightResult & { key: string }) | null>(null);
  const m = useMutation<PreflightResult, ApiError, string>({
    mutationFn: async (id) => {
      try {
        return await preflightPlan(id);
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (r, id) => setPf({ ...r, key: `${id}|${planKey}` }),
  });
  const stale = !!pf && pf.key !== `${appId}|${planKey}`;
  const { mutate, isPending } = m;
  useEffect(() => {
    if (appId && (!pf || pf.key !== `${appId}|${planKey}`) && !isPending) mutate(appId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appId, planKey]);
  return { m, pf, stale };
}

function PreflightSection({
  appId,
  m,
  checks,
  stale,
  needsCreate,
}: {
  appId: string | null;
  m: ReturnType<typeof usePreflight>['m'];
  checks: PreflightResult['checks'] | null;
  stale: boolean;
  needsCreate: boolean;
}) {
  const { t } = useI18n();
  const failing = failingChecks(checks);
  return (
    <section className="flex flex-col gap-2" aria-labelledby="pf-title">
      <div className="flex flex-wrap items-center gap-2">
        <h3 id="pf-title" className="m-0 flex-1 text-[14px] font-semibold">
          {t('pf.title')}
        </h3>
        {appId && (
          <Button size="sm" disabled={m.isPending} onClick={() => m.mutate(appId)}>
            {m.isPending ? t('pf.running') : t('pf.rerun')}
          </Button>
        )}
      </div>
      {!checks && !m.isPending && (
        <p className="m-0 text-[13px] text-fg-muted">
          {needsCreate ? t('pf.afterCreate') : t('pf.notRun')}
        </p>
      )}
      {m.isPending && (
        <div role="status" aria-busy="true" className="flex flex-col gap-1.5">
          <span className="text-[12.5px] text-fg-muted">{t('pf.running')}</span>
          <Skeleton className="h-24 w-full" />
        </div>
      )}
      {m.error && <ErrorState error={m.error} onRetry={() => appId && m.mutate(appId)} />}
      {stale && (
        <Notice tone="warn" glyph="◐" role="status">
          {t('pf.stale')}
        </Notice>
      )}
      {checks && !m.isPending && (
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
  );
}

function Risks({ items }: { items: Array<{ tone: 'warn' | 'info'; key: MessageKey }> }) {
  const { t } = useI18n();
  if (!items.length) return null;
  return (
    <section className="flex flex-col gap-1.5" aria-labelledby="risk-title">
      <h3 id="risk-title" className="m-0 text-[14px] font-semibold">
        {t('wiz.rev.risks')}
      </h3>
      <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[13px]" data-testid="risk-flags">
        {items.map((r) => (
          <li key={r.key} className="flex gap-2">
            <span aria-hidden="true" className={r.tone === 'warn' ? 'text-warn' : 'text-info'}>
              {r.tone === 'info' ? '◆' : '▲'}
            </span>
            {t(r.key)}
          </li>
        ))}
      </ul>
    </section>
  );
}

function ReasonField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useI18n();
  return (
    <Field label={t('wiz.rev.reason')} hint={t('wiz.rev.reasonHint')} className="max-w-[560px]">
      {(p) => (
        <input
          {...p}
          value={value}
          maxLength={500}
          onChange={(e) => onChange(e.target.value)}
          className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 text-[14px]"
        />
      )}
    </Field>
  );
}

// ---------------------------------------------------------------- Git source review

/** Comparable form of a build config (missing optional fields = defaults). */
function normCfg(c: BuildConfigInput | BuildConfig) {
  return JSON.stringify({
    repoUrl: c.repoUrl,
    subdir: c.subdir || '',
    dockerfile: c.dockerfile || '',
    template: c.template || '',
    buildArgs: c.buildArgs ?? {},
    target: c.target || '',
    buildServerId: c.buildServerId,
    pushRepo: c.pushRepo,
    network: c.network ?? 'default',
    limits: { memoryMb: 2048, cpus: 2, timeoutSec: 900, ...(c.limits ?? {}) },
  });
}

/**
 * Review for a Git source: create the app (new) + store build config / token / secrets, preflight
 * without an image, then "Build & deploy": build on the node → push → deploy the produced digest.
 */
export function GitReview({
  w,
  setW,
  app,
  servers,
  createInput,
  serverName,
  environment,
  secretValues,
  registryPassword,
  gitToken,
  onBuild,
}: {
  w: WizardState;
  setW: SetW;
  app: Application | null;
  servers: Server[];
  createInput: CreateContainerAppInput;
  serverName: string;
  environment: Env;
  secretValues: Map<string, string>;
  registryPassword: { current: string | null };
  gitToken: { current: string | null };
  onBuild: (b: Build, reused: boolean) => void;
}) {
  const { t } = useI18n();
  const { me, can } = useAuth();
  const qc = useQueryClient();
  const prod = environment === 'production';
  const [otp, setOtp] = useState('');
  const [reason, setReason] = useState('');
  const [createChecks, setCreateChecks] = useState<PreflightResult['checks'] | null>(null);
  const idem = useRef(uuid());
  const needsCreate = w.mode === 'new' && !w.appId;
  const cfg = useMemo(() => toBuildConfig(w.git), [w.git]);
  const node = servers.find((s) => s.id === w.git.buildServerId);
  const stagedSecrets =
    w.config.secrets.filter((s) => s.staged).length +
    (w.config.registry.passwordStaged ? 1 : 0) +
    (w.git.tokenStaged ? 1 : 0);
  const needsStepUp = needsCreate && prod && stagedSecrets > 0;
  const stored = app?.build?.config ?? null;
  const cfgChanged = !stored || normCfg(stored) !== normCfg(cfg);
  const { m: preflight, pf, stale } = usePreflight(w.appId, `git|${w.git.commitSha}`);

  const prepare = useMutation<Application, ApiError>({
    mutationFn: async () => {
      setCreateChecks(null);
      try {
        const token = needsStepUp ? (await authApi.stepUp(otp)).stepUpToken : undefined;
        const created = await containerAppsApi.create(createInput);
        await buildConfigApi.put(created.id, cfg);
        if (w.git.tokenStaged && gitToken.current !== null) {
          await buildConfigApi.putGitAuth(created.id, gitToken.current, token);
          gitToken.current = null;
        }
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
    },
  });

  const build = useMutation<{ build: Build; reused: boolean }, ApiError>({
    mutationFn: async () => {
      try {
        if (w.mode === 'existing' && cfgChanged)
          await buildConfigApi.put(w.appId!, cfg, stored?.version);
        return await buildsApi.create(
          w.appId!,
          {
            commitSha: w.git.commitSha.trim(),
            branch: w.git.branch.trim() || undefined,
            deployAfter: true,
          },
          idem.current,
        );
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: ({ build: b, reused }) => {
      void qc.invalidateQueries({
        queryKey: ['applications', 'one', b.applicationId],
        exact: false,
      });
      onBuild(b, reused);
    },
  });

  const checks = pf && !stale ? pf.checks : createChecks;
  const gate = app
    ? buildGate({ allowedActions: app.allowedActions, build: { config: cfg } }, me?.permissions)
    : { allowed: can('apps.deploy') };
  const ready = deployReady({
    checks: pf?.checks,
    stale,
    canDeploy: gate.allowed,
    busy: build.isPending || preflight.isPending || prepare.isPending,
  });
  const risks: Array<{ tone: 'warn' | 'info'; key: MessageKey }> = [];
  if (prod) risks.push({ tone: 'warn', key: 'wiz.rev.risk.prod' });
  if (w.git.network === 'default') risks.push({ tone: 'info', key: 'wiz.git.risk.network' });
  risks.push({ tone: 'info', key: 'wiz.git.risk.buildNode' });
  if (w.mode === 'existing' && cfgChanged && stored)
    risks.push({ tone: 'info', key: 'wiz.git.risk.cfgChanged' });

  return (
    <div className="flex flex-col gap-4" data-testid="git-review">
      {needsCreate && (
        <section
          className="flex flex-col gap-2 rounded-md border border-line p-3"
          data-testid="prepare"
        >
          <h3 className="m-0 text-[14px] font-semibold">{t('wiz.rev.prepare')}</h3>
          <p className="m-0 text-[12.5px] text-fg-muted">
            {t('wiz.git.prepareBody', { n: stagedSecrets })}
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
              {prepare.isPending ? t('common.saving') : t('wiz.git.create')}
            </Button>
          </div>
          {prepare.error && <ErrorState error={prepare.error} />}
        </section>
      )}

      <PreflightSection
        appId={w.appId}
        m={preflight}
        checks={checks}
        stale={stale}
        needsCreate={needsCreate}
      />

      <section className="flex flex-col gap-2" aria-labelledby="plan-title" data-testid="plan">
        <h3 id="plan-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.rev.plan')}
        </h3>
        <p
          className="m-0 rounded-md bg-chip-2 px-3 py-2 font-mono text-[12.5px]"
          data-testid="build-flow"
        >
          {t('wiz.git.flowLine', {
            node: node?.name ?? stored?.buildServerId.slice(0, 8) ?? '?',
            repo: cfg.pushRepo,
          })}
        </p>
        <DefList
          keyWidth={150}
          rows={[
            [t('dep.col.app'), needsCreate ? w.config.name : (app?.name ?? ''), { mono: true }],
            [t('dep.col.server'), `${serverName} · ${t(envBadgeKey(environment))}`, { mono: true }],
            [
              t('wiz.git.repoUrl'),
              cfg.repoUrl + (cfg.subdir ? ` · ${cfg.subdir}` : ''),
              { mono: true },
            ],
            [
              t('build.commit'),
              <span key="c" className="font-mono text-[12px] break-all" data-testid="plan-commit">
                {w.git.commitSha}
                {w.git.branch && (
                  <span className="text-fg-muted">
                    {' '}
                    ({t('wiz.git.branchContext', { branch: w.git.branch })})
                  </span>
                )}
              </span>,
            ],
            [
              t('build.method'),
              cfg.template
                ? t(`build.template.${cfg.template}` as MessageKey)
                : `Dockerfile: ${cfg.dockerfile}`,
              { mono: !cfg.template },
            ],
            [
              t('wiz.git.args'),
              Object.keys(cfg.buildArgs ?? {}).join(', ') || t('common.none'),
              { mono: true },
            ],
            [t('wiz.git.push'), cfg.pushRepo, { mono: true }],
            [
              t('wiz.git.sandbox'),
              `${cfg.network === 'none' ? t('wiz.git.network.off') : t('wiz.git.network.on')} · ${cfg.limits?.memoryMb} MiB · ${cfg.limits?.cpus} vCPU · ${cfg.limits?.timeoutSec}s`,
            ],
          ]}
        />
        <ol className="m-0 flex flex-col gap-1 pl-5 text-[13px]">
          <li>{t('wiz.git.s1')}</li>
          <li>{t('wiz.git.s2')}</li>
          <li>{t('wiz.git.s3')}</li>
          <li>{t('wiz.rev.s3')}</li>
          <li>{t('wiz.rev.s4')}</li>
        </ol>
      </section>

      <Risks items={risks} />

      {prod && (
        <Notice tone="warn" glyph="▲" role="note" title={t('wiz.rev.approvalTitle')}>
          <span data-testid="approval-notice">{t('wiz.git.approvalBody')}</span>
        </Notice>
      )}

      <ReasonField value={reason} onChange={setReason} />
      {build.error && <ErrorState error={build.error} />}
      {build.error && isApiError(build.error) && build.error.code === 'NO_BUILD_NODE' && (
        <Notice tone="warn" glyph="▲" role="status">
          {t('wiz.git.noBuildNode')}
        </Notice>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-line-subtle pt-3">
        <Button
          variant="primary"
          size="lg"
          disabled={!ready.ready || !w.appId}
          onClick={() => build.mutate()}
          data-testid="build-deploy-button"
        >
          {build.isPending ? t('wiz.git.starting') : t('wiz.git.buildDeploy')}
        </Button>
        <span className="text-[12.5px] text-fg-muted" data-testid="deploy-blocked-reason">
          {!gate.allowed && 'reason' in gate && gate.reason
            ? t(gate.reason.key, gate.reason.vars)
            : ready.reason
              ? t(ready.reason)
              : t('wiz.git.ready')}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- Compose review

export function ComposeReview({
  w,
  setW,
  app,
  serverName,
  environment,
  setSecrets,
  secretValues,
  onDeployed,
  currentYaml,
}: {
  w: WizardState;
  setW: SetW;
  app: Application | null;
  serverName: string;
  environment: Env;
  /** YAML of the stored version (the app read model has none). */
  currentYaml?: string;
  setSecrets: readonly string[];
  secretValues: Map<string, string>;
  onDeployed: (d: Deployment) => void;
}) {
  const { t } = useI18n();
  const { me, can } = useAuth();
  const qc = useQueryClient();
  const prod = environment === 'production';
  const [otp, setOtp] = useState('');
  const [reason, setReason] = useState('');
  const idem = useRef(uuid());
  const c = w.compose;
  const needsCreate = w.mode === 'new' && !w.appId;
  const stored = app?.compose ?? null;
  const changed =
    !!stored &&
    ((stored.yaml ?? currentYaml ?? c.yaml) !== c.yaml ||
      stored.routeService !== c.routeService ||
      String(stored.routePort) !== c.routePort ||
      stored.healthPath !== c.healthPath);
  const needsStepUp = prod && c.staged.length > 0 && needsCreate;
  const rows = useMemo(
    () =>
      deriveComposeServices({
        yaml: c.yaml,
        routeService: c.routeService,
        routePort: Number(c.routePort),
        healthPath: c.healthPath,
        secretStatus: (k) =>
          setSecrets.includes(k) ? 'set' : c.staged.includes(k) ? 'staged' : 'missing',
      }),
    [c, setSecrets],
  );
  const plan = useMemo(() => composePlan(stored?.services ?? null, rows), [stored, rows]);
  const planKey = `cmp|${stored?.version ?? 0}|${changed ? 'dirty' : 'clean'}`;
  const { m: preflight, pf, stale } = usePreflight(changed ? null : w.appId, planKey);
  const input = {
    yaml: c.yaml,
    routeService: c.routeService,
    routePort: Number(c.routePort),
    healthPath: c.healthPath || '/',
  };

  const prepare = useMutation<Application, ApiError>({
    mutationFn: async () => {
      try {
        if (!needsCreate && app) {
          const updated = await composeApi.update(app.id, input, app.version);
          return updated;
        }
        const token = needsStepUp ? (await authApi.stepUp(otp)).stepUpToken : undefined;
        const created = await composeApi.create({
          kind: 'compose',
          serverId: w.target.serverId,
          name: w.config.name,
          environment,
          domains: w.domain.domains.map((d) => d.trim()).filter(Boolean),
          ...input,
        });
        for (const key of c.staged) {
          const v = secretValues.get(`cmp:${key}`);
          if (v === undefined) continue;
          await containerAppsApi.putSecret(created.id, key, v, token);
          secretValues.delete(`cmp:${key}`);
        }
        return created;
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (a) => {
      setOtp('');
      void qc.invalidateQueries({ queryKey: ['applications'], exact: false });
      qc.setQueryData(['applications', 'one', a.id], a);
      setW((x) => ({ ...x, mode: 'existing', appId: a.id, compose: { ...x.compose, staged: [] } }));
    },
  });

  const deploy = useMutation<Deployment, ApiError>({
    mutationFn: async () => {
      try {
        return await composeApi.deploy(
          w.appId!,
          { reason: reason.trim() || undefined },
          idem.current,
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

  const checks = pf && !stale ? pf.checks : null;
  const ready = deployReady({
    checks: changed ? null : pf?.checks,
    stale,
    canDeploy: can('apps.deploy'),
    busy: deploy.isPending || preflight.isPending || prepare.isPending,
  });
  const nonRouteRestart = plan.some(
    (p) => !p.isRoute && (p.action === 'replaced' || p.action === 'removed'),
  );
  const risks: Array<{ tone: 'warn' | 'info'; key: MessageKey }> = [];
  if (prod) risks.push({ tone: 'warn', key: 'wiz.rev.risk.prod' });
  risks.push({
    tone: 'warn',
    key: nonRouteRestart ? 'wiz.cmp.risk.restartNow' : 'wiz.cmp.risk.restart',
  });
  risks.push({ tone: 'warn', key: 'wiz.cmp.risk.noData' });
  if (rows.some((r) => !r.pinned)) risks.push({ tone: 'info', key: 'wiz.cmp.risk.resolve' });

  return (
    <div className="flex flex-col gap-4" data-testid="compose-review">
      {(needsCreate || changed) && (
        <section
          className="flex flex-col gap-2 rounded-md border border-line p-3"
          data-testid="prepare"
        >
          <h3 className="m-0 text-[14px] font-semibold">
            {needsCreate ? t('wiz.rev.prepare') : t('wiz.cmp.saveVersionTitle')}
          </h3>
          <p className="m-0 text-[12.5px] text-fg-muted">
            {needsCreate
              ? t('wiz.cmp.prepareBody', { n: c.staged.length })
              : t('wiz.cmp.saveVersionBody', { v: (stored?.version ?? 0) + 1 })}
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
              data-testid="compose-prepare"
            >
              {prepare.isPending
                ? t('common.saving')
                : needsCreate
                  ? t('wiz.cmp.create')
                  : t('wiz.cmp.saveVersion', { v: (stored?.version ?? 0) + 1 })}
            </Button>
          </div>
          {prepare.error && <ErrorState error={prepare.error} />}
        </section>
      )}

      <PreflightSection
        appId={changed ? null : w.appId}
        m={preflight}
        checks={checks}
        stale={stale}
        needsCreate={needsCreate || changed}
      />

      <section className="flex flex-col gap-2" aria-labelledby="plan-title" data-testid="plan">
        <h3 id="plan-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.cmp.planTitle')}
        </h3>
        <DefList
          keyWidth={150}
          rows={[
            [t('dep.col.app'), needsCreate ? w.config.name : (app?.name ?? ''), { mono: true }],
            [t('dep.col.server'), `${serverName} · ${t(envBadgeKey(environment))}`, { mono: true }],
            [
              t('cmp.version'),
              stored
                ? changed
                  ? `v${stored.version} → v${stored.version + 1}`
                  : `v${stored.version}`
                : 'v1',
              { mono: true },
            ],
            [
              t('wiz.rev.route'),
              `${(needsCreate ? w.domain.domains.filter(Boolean) : (app?.domains ?? [])).join(', ')} → ${c.routeService}:${c.routePort} (GET ${c.healthPath || '/'})`,
              { mono: true },
            ],
          ]}
        />
        <ComposePlanTable rows={plan} />
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.cmp.planNote')}</p>
        <ol className="m-0 flex flex-col gap-1 pl-5 text-[13px]">
          <li>{t('wiz.cmp.s1')}</li>
          <li>{t('wiz.cmp.s2')}</li>
          <li>{t('wiz.cmp.s3')}</li>
          <li>{t('wiz.cmp.s4')}</li>
        </ol>
      </section>

      <Risks items={risks} />

      {prod && (
        <Notice tone="warn" glyph="▲" role="note" title={t('wiz.rev.approvalTitle')}>
          <span data-testid="approval-notice">{t('wiz.rev.approvalBody')}</span>
        </Notice>
      )}

      <ReasonField value={reason} onChange={setReason} />
      {deploy.error && <ErrorState error={deploy.error} />}

      <div className="flex flex-wrap items-center gap-3 border-t border-line-subtle pt-3">
        <Button
          variant="primary"
          size="lg"
          disabled={!ready.ready || !w.appId || changed}
          onClick={() => deploy.mutate()}
          data-testid="deploy-button"
        >
          {deploy.isPending
            ? t('wiz.rev.deploying')
            : prod
              ? t('wiz.rev.requestDeploy')
              : t('wiz.rev.deploy')}
        </Button>
        <span className="text-[12.5px] text-fg-muted" data-testid="deploy-blocked-reason">
          {changed
            ? t('wiz.cmp.saveFirst')
            : ready.reason
              ? t(ready.reason)
              : prod
                ? t('wiz.rev.readyProd')
                : t('wiz.rev.ready')}
        </span>
      </div>
    </div>
  );
}
