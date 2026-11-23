'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { containerAppsApi } from '@/lib/api/p4-endpoints';
import { DEPLOYMENT_LOCKING, type AutoDeployPolicy, type Deployment } from '@/lib/api/p4-types';
import { isEnvKey, lifecycleActions, type LifecycleAction } from '@/lib/p4-gates';
import { evaluateGate } from '@/lib/permissions';
import {
  useAppDeployments,
  useAppLogs,
  useAutoDeploy,
  useIntegrations,
  useRegistryAuth,
  useSecrets,
  p4k,
} from '@/lib/p4-queries';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { useToast } from '@/components/providers/toast';
import { Card, DefList } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton, TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ActionDialog } from '@/components/p3/action-dialog';
import { StepUpField } from '@/components/p3/bits';
import { DeploymentStatusBadge, ImageRef } from './bits';
import { DeploymentsTable } from './deployments-view';
import { SecretInput } from './secret-input';
import type { MessageKey } from '@/i18n/en';

function useInvalidateContainerApp(appId: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ['applications', 'one', appId], exact: false });
    void qc.invalidateQueries({ queryKey: ['deployments'], exact: false });
  };
}

// ---------------------------------------------------------------- lifecycle (Overview)

const LIFE_GLYPH: Record<LifecycleAction, string> = {
  restart: '↻',
  redeploy: '⟳',
  rollback: '↶',
  stop: '■',
  start: '▶',
};

/** Distinct Restart / Redeploy / Rollback / Stop / Start actions, each with its exact effect. */
export function LifecyclePanel({ app }: { app: Application }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const router = useRouter();
  const toast = useToast();
  const invalidate = useInvalidateContainerApp(app.id);
  const deps = useAppDeployments(app.id);
  const [open, setOpen] = useState<LifecycleAction | null>(null);
  const active = (deps.data?.items ?? []).find((d) => DEPLOYMENT_LOCKING.includes(d.status));
  const items = lifecycleActions(app, me?.permissions, !!active);
  const prod = app.environment === 'production';
  const c = app.container;
  const current = deps.data?.items.find((d) => d.id === c?.currentDeploymentId);
  const previous = deps.data?.items.find((d) => d.id === c?.previousDeploymentId);

  async function run(a: LifecycleAction): Promise<Deployment | null> {
    switch (a) {
      case 'restart':
        await containerAppsApi.restart(app.id);
        return null;
      case 'start':
        await containerAppsApi.start(app.id);
        return null;
      case 'stop':
        await containerAppsApi.stop(app.id);
        return null;
      case 'redeploy':
        return containerAppsApi.redeploy(app.id);
      case 'rollback':
        return containerAppsApi.rollback(app.id);
    }
  }

  return (
    <Card className="flex flex-col gap-3 p-4" data-testid="lifecycle-panel">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('life.title')}</h2>
        <GatedButton
          size="sm"
          variant="primary"
          perm="apps.deploy"
          action="deploy"
          allowedActions={app.allowedActions}
          onClick={() => router.push(`/deployments/new?app=${app.id}`)}
        >
          {t('life.deployNew')}
        </GatedButton>
      </div>
      <DefList
        keyWidth={130}
        rows={[
          [
            t('life.current'),
            current ? (
              <span key="c" className="inline-flex flex-wrap items-center gap-2">
                <Link href={`/deployments/${current.id}`} className="font-mono">
                  #{current.number}
                </Link>
                <ImageRef image={current.image} />
              </span>
            ) : (
              t('life.nothingDeployed')
            ),
          ],
          [
            t('life.previous'),
            previous ? (
              <span key="p" className="inline-flex flex-wrap items-center gap-2">
                <Link href={`/deployments/${previous.id}`} className="font-mono">
                  #{previous.number}
                </Link>
                <ImageRef image={previous.image} />
              </span>
            ) : (
              t('common.dash')
            ),
          ],
          [
            t('life.container'),
            c?.containerName ? `${c.containerName} · 127.0.0.1:${c.hostPort}` : t('common.dash'),
            { mono: true },
          ],
          [
            t('life.state'),
            <ToneBadge
              key="s"
              tone={
                c?.runtimeState === 'stopped'
                  ? 'off'
                  : c?.runtimeState === 'running'
                    ? 'ok'
                    : 'stale'
              }
              size="sm"
            >
              {t(`life.state.${c?.runtimeState ?? 'unknown'}` as MessageKey)}
            </ToneBadge>,
          ],
        ]}
      />
      {active && (
        <Notice tone="info" glyph="◌" role="status">
          {t('life.activeDeployment', { n: active.number })}{' '}
          <Link href={`/deployments/${active.id}`}>{t('life.view')} →</Link>
        </Notice>
      )}
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {items.map((it) => (
          <li
            key={it.action}
            data-testid="lifecycle-action"
            data-action={it.action}
            className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-3 rounded-md border border-line px-3 py-2.5"
          >
            <div className="flex flex-col gap-0.5 text-[13px]">
              <b className="font-medium">
                <span aria-hidden="true" className="mr-1.5 text-fg-muted">
                  {LIFE_GLYPH[it.action]}
                </span>
                {t(`life.${it.action}` as MessageKey)}
                {it.createsDeployment && (
                  <span className="ml-2 text-[11.5px] font-normal text-fg-muted">
                    {t('life.createsDeployment')}
                  </span>
                )}
              </b>
              <span className="text-fg-2" data-testid="lifecycle-effect">
                {t(it.effect)}
              </span>
              {it.warning && (
                <span
                  className={cn(
                    'text-[12.5px]',
                    it.action === 'rollback' ? 'font-medium text-warn' : 'text-fg-muted',
                  )}
                >
                  <span aria-hidden="true">▲ </span>
                  {t(it.warning)}
                </span>
              )}
            </div>
            <GatedButton
              size="sm"
              variant={it.danger ? 'danger' : 'secondary'}
              perm="apps.deploy"
              blockedReason={it.gate.allowed ? undefined : it.gate.reason}
              onClick={() => setOpen(it.action)}
            >
              {t(`life.${it.action}` as MessageKey)}
            </GatedButton>
          </li>
        ))}
      </ul>
      <p className="m-0 text-[12px] text-fg-muted">{t('life.restoreNote')}</p>
      {open && (
        <ActionDialog
          open
          onOpenChange={(o) => !o && setOpen(null)}
          title={t(`life.${open}.confirmTitle` as MessageKey, { app: app.name })}
          body={
            <span className="flex flex-col gap-1.5">
              <span>{t(`life.${open}.effect` as MessageKey)}</span>
              {open === 'rollback' && (
                <b className="text-warn">
                  {t('life.rollback.noData')}
                  {previous ? ` ${t('life.rollback.target', { n: previous.number })}` : ''}
                </b>
              )}
              {prod && (open === 'redeploy' || open === 'rollback') && (
                <span>{t('life.prodApproval')}</span>
              )}
            </span>
          }
          confirmLabel={t(`life.${open}` as MessageKey)}
          danger={open === 'stop'}
          needsStepUp={false}
          onConfirm={async () => {
            const d = await run(open);
            invalidate();
            if (d) router.push(`/deployments/${d.id}`);
            else toast(t('life.queued', { action: t(`life.${open}` as MessageKey) }), 'ok');
          }}
        />
      )}
    </Card>
  );
}

// ---------------------------------------------------------------- Deployments tab

export function AppDeploymentsTab({ app }: { app: Application }) {
  const { t } = useI18n();
  const q = useAppDeployments(app.id);
  const c = app.container;
  if (q.isPending) return <TableSkeleton label={t('common.loading')} />;
  if (q.isError && !q.data)
    return isApiError(q.error) && q.error.status === 403 ? (
      <ForbiddenState perm="apps.read" requestId={q.error.requestId} />
    ) : (
      <ErrorState error={q.error} onRetry={() => void q.refetch()} />
    );
  const items = q.data?.items ?? [];
  return (
    <div className="flex flex-col gap-4">
      <LifecyclePanel app={app} />
      <h2 className="m-0 text-[15px] font-semibold">{t('app.deps.history')}</h2>
      {items.length === 0 ? (
        <EmptyState
          title={t('app.deps.empty')}
          action={<Link href={`/deployments/new?app=${app.id}`}>{t('life.deployNew')} →</Link>}
        />
      ) : (
        <DeploymentsTable
          items={items}
          showApp={false}
          markers={{ current: c?.currentDeploymentId, previous: c?.previousDeploymentId }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Env & Secrets tab

export function EnvSecretsTab({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const secrets = useSecrets(app.id);
  const reg = useRegistryAuth(app.id);
  const deps = useAppDeployments(app.id);
  const pending = deps.data?.items.find((d) => d.status === 'awaiting_approval');
  const prod = app.environment === 'production';
  const [otp, setOtp] = useState('');
  const [newKey, setNewKey] = useState('');
  const [regForm, setRegForm] = useState({ serveraddress: '', username: '' });
  const gate = evaluateGate({
    permissions: me?.permissions,
    perm: 'apps.deploy',
    action: 'manage_secrets',
    allowedActions: app.allowedActions,
  });
  const c = app.container;
  const declared = Array.from(
    new Set([...(c?.secretKeys ?? []), ...(secrets.data?.items.map((s) => s.key) ?? [])]),
  );
  const stepUpReady = !prod || (!!me?.mfaEnabled && /^\d{6}$/.test(otp));
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: p4k.secrets(app.id) });
    void qc.invalidateQueries({ queryKey: ['applications', 'one', app.id], exact: false });
  };
  const token = async () => (prod ? (await authApi.stepUp(otp)).stepUpToken : undefined);

  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-4">
      <Card className="flex flex-col gap-2 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('env.plain')}</h2>
        <p className="m-0 text-[12px] text-fg-muted">{t('env.plainHint')}</p>
        {c && Object.keys(c.env).length ? (
          <DefList
            keyWidth={180}
            rows={Object.entries(c.env).map(([k, v]) => [
              <code key={k} className="font-mono text-[12px]">
                {k}
              </code>,
              v,
              { mono: true },
            ])}
          />
        ) : (
          <p className="m-0 text-[13px] text-fg-muted">{t('common.none')}</p>
        )}
      </Card>
      <Card className="flex flex-col gap-3 p-4" data-testid="secrets-card">
        <h2 className="m-0 text-[15px] font-semibold">{t('env.secrets')}</h2>
        <Notice tone="neutral" role="note">
          {t('env.secretsNote')}
        </Notice>
        {pending && (
          <Notice tone="warn" glyph="▲" role="status">
            <span data-testid="approval-invalidation">
              {t('env.invalidatesApproval', { n: pending.number })}
            </span>
          </Notice>
        )}
        {!gate.allowed && (
          <Notice tone="warn" glyph="▲" role="status">
            {gate.reason ? t(gate.reason.key, gate.reason.vars) : ''}
          </Notice>
        )}
        {prod && gate.allowed && (
          <StepUpField value={otp} onChange={setOtp} hint={t('env.stepUpHint')} />
        )}
        {secrets.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : secrets.isError ? (
          <ErrorState error={secrets.error} onRetry={() => void secrets.refetch()} />
        ) : (
          <div className="flex flex-col gap-3">
            {declared.length === 0 && (
              <p className="m-0 text-[13px] text-fg-muted">{t('env.noSecrets')}</p>
            )}
            {declared.map((k) => {
              const meta = secrets.data?.items.find((s) => s.key === k);
              return (
                <div key={k} className="flex flex-col gap-0.5">
                  <SecretInput
                    secretKey={k}
                    status={{ set: !!meta, version: meta?.version }}
                    disabled={!gate.allowed || !stepUpReady}
                    onSubmit={async (value) => {
                      await containerAppsApi.putSecret(app.id, k, value, await token());
                      setOtp('');
                      refresh();
                    }}
                  />
                  {meta && (
                    <span className="text-[11.5px] text-fg-muted">
                      {t('env.updated', { when: formatDateTime(meta.updatedAt, locale) })}
                    </span>
                  )}
                </div>
              );
            })}
            {gate.allowed && (
              <div className="flex flex-wrap items-end gap-2 border-t border-line-subtle pt-3">
                <Field
                  label={t('env.addKey')}
                  error={newKey && !isEnvKey(newKey) ? t('wiz.cfg.issue.envKeys') : undefined}
                >
                  {(p) => (
                    <Input
                      {...p}
                      value={newKey}
                      onChange={(e) => setNewKey(e.target.value.toUpperCase())}
                      placeholder="NEW_SECRET"
                      className="w-[240px] font-mono"
                    />
                  )}
                </Field>
                {isEnvKey(newKey) && !declared.includes(newKey) && (
                  <SecretInput
                    secretKey={newKey}
                    status={{ set: false }}
                    disabled={!stepUpReady}
                    className="min-w-[280px] flex-1"
                    onSubmit={async (value) => {
                      await containerAppsApi.putSecret(app.id, newKey, value, await token());
                      setNewKey('');
                      setOtp('');
                      refresh();
                    }}
                  />
                )}
              </div>
            )}
          </div>
        )}
      </Card>
      <Card className="flex flex-col gap-3 p-4">
        <h2 className="m-0 text-[15px] font-semibold">{t('env.registry')}</h2>
        {reg.isPending ? (
          <Skeleton className="h-10 w-full" />
        ) : reg.isError ? (
          <ErrorState error={reg.error} onRetry={() => void reg.refetch()} />
        ) : (
          <>
            {reg.data?.set ? (
              <p className="m-0 text-[13px]">
                <ToneBadge tone="ok" glyph="✓" size="sm">
                  {t('secret.set', { v: reg.data.version ?? 1 })}
                </ToneBadge>{' '}
                <span className="font-mono">
                  {reg.data.username}@{reg.data.serveraddress}
                </span>
              </p>
            ) : (
              <p className="m-0 text-[13px] text-fg-muted">{t('env.registryNone')}</p>
            )}
            {gate.allowed && (
              <>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Field label={t('wiz.cfg.regServer')}>
                    {(p) => (
                      <Input
                        {...p}
                        value={regForm.serveraddress}
                        onChange={(e) =>
                          setRegForm((f) => ({ ...f, serveraddress: e.target.value.trim() }))
                        }
                        className="font-mono"
                        placeholder={reg.data?.serveraddress ?? 'registry.example.lab'}
                      />
                    )}
                  </Field>
                  <Field label={t('wiz.cfg.regUser')}>
                    {(p) => (
                      <Input
                        {...p}
                        value={regForm.username}
                        onChange={(e) =>
                          setRegForm((f) => ({ ...f, username: e.target.value.trim() }))
                        }
                        className="font-mono"
                        placeholder={reg.data?.username ?? ''}
                      />
                    )}
                  </Field>
                </div>
                <SecretInput
                  secretKey="registry-password"
                  label={t('wiz.cfg.regPassword')}
                  status={{ set: !!reg.data?.set }}
                  disabled={!regForm.serveraddress || !regForm.username || !stepUpReady}
                  onSubmit={async (password) => {
                    await containerAppsApi.putRegistryAuth(
                      app.id,
                      { ...regForm, password },
                      await token(),
                    );
                    setOtp('');
                    void qc.invalidateQueries({ queryKey: p4k.registryAuth(app.id) });
                  }}
                />
              </>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------- Logs tab

export function LogsTab({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const [tail, setTail] = useState(200);
  const q = useAppLogs(app.id, tail);
  return (
    <Card className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-end gap-2">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('logs.title')}</h2>
        <Field label={t('logs.tail')} className="w-[120px]">
          {(p) => (
            <Select {...p} value={String(tail)} onChange={(e) => setTail(Number(e.target.value))}>
              {[50, 200, 500, 1000].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button size="sm" onClick={() => void q.refetch()} disabled={q.isFetching}>
          {q.isFetching ? t('common.loading') : t('common.refresh')}
        </Button>
      </div>
      <Notice tone="neutral" glyph="◆" role="note">
        <span data-testid="redacted-notice">{t('logs.redacted')}</span>
      </Notice>
      {q.isPending || q.data?.status === 'pending' ? (
        <div role="status" aria-busy="true" className="flex flex-col gap-1">
          <span className="text-[12.5px] text-fg-muted">{t('logs.fetching')}</span>
          <Skeleton className="h-40 w-full" />
        </div>
      ) : q.isError ? (
        isApiError(q.error) && q.error.status === 403 ? (
          <ForbiddenState perm="apps.read" requestId={q.error.requestId} />
        ) : (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        )
      ) : (
        <>
          <div className="text-[12px] text-fg-muted">
            {q.data?.container && <span className="font-mono">{q.data.container} · </span>}
            {t('logs.lines', { n: q.data?.lines.length ?? 0 })}
            {q.data?.truncated && ` · ${t('logs.truncated')}`}
            {q.dataUpdatedAt
              ? ` · ${formatDateTime(new Date(q.dataUpdatedAt).toISOString(), locale)}`
              : ''}
          </div>
          {q.data && q.data.lines.length === 0 ? (
            <EmptyState title={t('logs.empty')} />
          ) : (
            <pre
              className="m-0 max-h-[480px] overflow-auto rounded-md bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.6] whitespace-pre-wrap text-terminal-fg"
              data-testid="container-logs"
              tabIndex={0}
              aria-label={t('logs.title')}
            >
              {q.data?.lines.join('\n')}
            </pre>
          )}
        </>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------- Settings → Auto-deploy

export function AutoDeploySettings({ app }: { app: Application }) {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const q = useAutoDeploy(app.id);
  const integrations = useIntegrations();
  const gate = evaluateGate({
    permissions: me?.permissions,
    perm: 'policies.manage',
    action: 'manage_auto_deploy',
    allowedActions: app.allowedActions,
  });
  const [form, setForm] = useState({
    integrationId: '',
    repo: '',
    branches: 'main',
    imageTemplate: '',
    enabled: true,
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: p4k.autoDeploy(app.id) });
  const create = useMutation<AutoDeployPolicy, ApiError>({
    mutationFn: async () => {
      try {
        return await containerAppsApi.createAutoDeploy(app.id, {
          integrationId: form.integrationId || integrations.data?.items[0]?.id || '',
          repo: form.repo.trim(),
          branches: form.branches
            .split(',')
            .map((b) => b.trim())
            .filter(Boolean),
          imageTemplate: form.imageTemplate.trim(),
          enabled: form.enabled,
        });
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: () => {
      setForm({ integrationId: '', repo: '', branches: 'main', imageTemplate: '', enabled: true });
      refresh();
    },
  });
  const toggle = useMutation<AutoDeployPolicy, ApiError, AutoDeployPolicy>({
    mutationFn: async (p) => {
      try {
        return await containerAppsApi.updateAutoDeploy(app.id, p.id, { enabled: !p.enabled });
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: refresh,
  });
  const prod = app.environment === 'production';
  const integName = (id: string) =>
    integrations.data?.items.find((i) => i.id === id)?.name ?? id.slice(0, 8);

  return (
    <Card className="flex flex-col gap-3 p-4" data-testid="auto-deploy">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('ad.title')}</h2>
        <Link href="/settings/integrations" className="text-[13px]">
          {t('ad.toIntegrations')} →
        </Link>
      </div>
      <p className="m-0 text-[12.5px] text-fg-muted">{t('ad.explain')}</p>
      {prod && (
        <Notice tone="warn" glyph="▲" role="note">
          {t('ad.prodNote')}
        </Notice>
      )}
      {q.isPending ? (
        <Skeleton className="h-16 w-full" />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (q.data?.items ?? []).length === 0 ? (
        <p className="m-0 text-[13px] text-fg-muted">{t('ad.none')}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          {q.data!.items.map((p) => (
            <li
              key={p.id}
              className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-line px-3 py-2 text-[13px]"
              data-testid="policy-row"
            >
              <b className="font-mono">{p.repo}</b>
              <span className="font-mono text-[12px]">{p.branches.join(', ')}</span>
              <span className="font-mono text-[12px] break-all text-fg-muted">
                {p.imageTemplate}
              </span>
              <span className="text-[12px] text-fg-muted">{integName(p.integrationId)}</span>
              <ToneBadge tone={p.enabled ? 'ok' : 'off'} size="sm">
                {p.enabled ? t('ad.enabled') : t('ad.disabled')}
              </ToneBadge>
              <span className="flex-1" />
              <GatedButton
                size="sm"
                perm="policies.manage"
                blockedReason={gate.allowed ? undefined : gate.reason}
                onClick={() => toggle.mutate(p)}
              >
                {p.enabled ? t('ad.disable') : t('ad.enable')}
              </GatedButton>
            </li>
          ))}
        </ul>
      )}
      {toggle.error && <ErrorState error={toggle.error} />}
      {gate.allowed && (
        <form
          className="flex flex-col gap-2 border-t border-line-subtle pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <h3 className="m-0 text-[13.5px] font-semibold">{t('ad.add')}</h3>
          <div className="grid gap-2 sm:grid-cols-2">
            <Field label={t('ad.integration')}>
              {(p) => (
                <Select
                  {...p}
                  value={form.integrationId}
                  onChange={(e) => setForm((f) => ({ ...f, integrationId: e.target.value }))}
                >
                  {(integrations.data?.items ?? []).map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('ad.repo')}>
              {(p) => (
                <Input
                  {...p}
                  value={form.repo}
                  onChange={(e) => setForm((f) => ({ ...f, repo: e.target.value }))}
                  placeholder="org/app"
                  className="font-mono"
                />
              )}
            </Field>
            <Field label={t('ad.branches')} hint={t('ad.branchesHint')}>
              {(p) => (
                <Input
                  {...p}
                  value={form.branches}
                  onChange={(e) => setForm((f) => ({ ...f, branches: e.target.value }))}
                  className="font-mono"
                />
              )}
            </Field>
            <Field label={t('ad.template')} hint={t('ad.templateHint')}>
              {(p) => (
                <Input
                  {...p}
                  value={form.imageTemplate}
                  onChange={(e) => setForm((f) => ({ ...f, imageTemplate: e.target.value }))}
                  placeholder="registry.example.lab/org/app:sha-{sha7}"
                  className="font-mono"
                />
              )}
            </Field>
          </div>
          <label className="flex items-center gap-2 text-[13px]">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
            />
            {t('ad.enabledOnCreate')}
          </label>
          <div>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={
                create.isPending ||
                !form.repo ||
                !form.imageTemplate ||
                !integrations.data?.items.length
              }
            >
              {create.isPending ? t('common.saving') : t('ad.save')}
            </Button>
          </div>
          {create.error && <ErrorState error={create.error} />}
        </form>
      )}
    </Card>
  );
}

/** Small status line for the app header. */
export function CurrentVersionLine({ app }: { app: Application }) {
  const { t } = useI18n();
  const deps = useAppDeployments(app.id);
  const cur = deps.data?.items.find((d) => d.id === app.container?.currentDeploymentId);
  const latest = deps.data?.items[0];
  if (!latest) return null;
  return (
    <span className="inline-flex flex-wrap items-center gap-2 text-[12.5px] text-fg-muted">
      {cur && (
        <>
          {t('life.current')} <span className="font-mono">#{cur.number}</span>
        </>
      )}
      {latest && latest.id !== cur?.id && (
        <>
          · {t('life.latest')} <span className="font-mono">#{latest.number}</span>{' '}
          <DeploymentStatusBadge status={latest.status} />
        </>
      )}
    </span>
  );
}
