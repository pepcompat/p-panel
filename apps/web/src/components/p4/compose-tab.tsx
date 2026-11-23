'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { containerAppsApi } from '@/lib/api/p4-endpoints';
import { composeApi } from '@/lib/api/p4b-endpoints';
import type { ComposeValidation } from '@/lib/api/p4-types';
import {
  composeIssues,
  composePlan,
  deriveComposeServices,
  healthView,
  initialCompose,
  type ComposeState,
} from '@/lib/p4b-gates';
import { evaluateGate } from '@/lib/permissions';
import { p4k, useSecrets } from '@/lib/p4-queries';
import { useComposeCurrent } from '@/lib/p4b-queries';
import { formatDateTime } from '@/lib/time';
import { useToast } from '@/components/providers/toast';
import { Card, DefList } from '@/components/ui/card';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState, Notice } from '@/components/ui/states';
import { ComposePlanTable, HealthLabel } from './compose-bits';
import {
  ComposeRouteFields,
  ComposeServicesDetected,
  ComposeViolations,
  useComposeValidation,
} from './compose-source';
import { SecretInput } from './secret-input';
import type { MessageKey } from '@/i18n/en';

const STATE_TONE: Record<string, Tone> = {
  running: 'ok',
  stopped: 'off',
  exited: 'crit',
  unknown: 'stale',
};

/** Compose tab (§8.3): current version (read-only YAML), services with running state, edit → new version. */
export function ComposeTab({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const cfg = app.compose;
  const current = useComposeCurrent(app.id, !cfg?.yaml);
  const secrets = useSecrets(app.id);
  const yaml = cfg?.yaml ?? current.data?.yaml ?? '';
  const [edit, setEdit] = useState<ComposeState | null>(null);
  const [saved, setSaved] = useState<number | null>(null);
  const setKeys = useMemo(() => secrets.data?.items.map((s) => s.key) ?? [], [secrets.data]);
  const gate = evaluateGate({
    permissions: me?.permissions,
    perm: 'apps.deploy',
    action: 'edit_compose',
    allowedActions: app.allowedActions,
  });
  const patchEdit = (p: Partial<ComposeState>) => setEdit((e) => (e ? { ...e, ...p } : e));
  const validation = useComposeValidation(
    edit?.yaml ?? '',
    app.environment,
    (y: string, r: ComposeValidation) =>
      setEdit((e) => (e && e.yaml === y ? { ...e, validation: r, validatedYaml: y } : e)),
  );
  const rows = useMemo(
    () =>
      edit
        ? deriveComposeServices({
            yaml: edit.yaml,
            routeService: edit.routeService,
            routePort: Number(edit.routePort),
            healthPath: edit.healthPath,
            secretStatus: (k) => (setKeys.includes(k) ? 'set' : 'missing'),
          })
        : [],
    [edit, setKeys],
  );
  const issues = edit
    ? composeIssues(edit, setKeys).filter((k) => k !== 'wiz.cmp.issue.secrets')
    : [];
  const unchanged =
    !!edit &&
    edit.yaml === yaml &&
    edit.routeService === cfg?.routeService &&
    edit.routePort === String(cfg?.routePort) &&
    edit.healthPath === cfg?.healthPath;
  const save = useMutation<Application, ApiError>({
    mutationFn: async () => {
      try {
        return await composeApi.update(
          app.id,
          {
            yaml: edit!.yaml,
            routeService: edit!.routeService,
            routePort: Number(edit!.routePort),
            healthPath: edit!.healthPath || '/',
          },
          app.version,
        );
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (a) => {
      setSaved(a.compose?.version ?? (cfg?.version ?? 0) + 1);
      setEdit(null);
      toast(t('cmp.saved', { v: a.compose?.version ?? '' }), 'ok');
      void qc.invalidateQueries({ queryKey: ['applications', 'one', app.id], exact: false });
    },
  });

  if (!cfg) return <ErrorState error={new Error('compose config missing')} />;

  return (
    <div className="flex flex-col gap-4" data-testid="compose-tab">
      {saved && (
        <Notice
          tone="ok"
          glyph="●"
          role="status"
          title={t('cmp.savedTitle', { v: saved })}
          action={
            <Link href={`/deployments/new?app=${app.id}`} className="text-[13px]">
              {t('cmp.deployVersion', { v: saved })} →
            </Link>
          }
        >
          {t('cmp.savedBody')}
        </Notice>
      )}
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-4">
        <Card className="flex flex-col gap-2 p-4">
          <h2 className="m-0 text-[15px] font-semibold">
            {t('cmp.currentVersion', { v: cfg.version })}
          </h2>
          <DefList
            keyWidth={140}
            rows={[
              [t('cmp.version'), `v${cfg.version} · ${cfg.versionId.slice(0, 8)}`, { mono: true }],
              [t('wiz.cmp.routeService'), `${cfg.routeService}:${cfg.routePort}`, { mono: true }],
              [t('wiz.cmp.healthPath'), cfg.healthPath, { mono: true }],
              [t('cmp.secretKeys'), cfg.secretKeys.join(', ') || t('common.none'), { mono: true }],
              [t('dep.createdAt'), formatDateTime(cfg.createdAt, locale)],
            ]}
          />
          {cfg.warnings.length > 0 && (
            <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px] text-warn">
              {cfg.warnings.map((w) => (
                <li key={`${w.path}-${w.rule}`}>
                  ▲ <span className="font-mono">{w.rule}</span> · {w.message}
                </li>
              ))}
            </ul>
          )}
          <p className="m-0 text-[12px] text-fg-muted">{t('cmp.rollbackNote')}</p>
        </Card>
        <Card className="flex flex-col gap-2 p-4">
          <h2 className="m-0 text-[15px] font-semibold">{t('cmp.services')}</h2>
          <ul
            className="m-0 flex list-none flex-col gap-1.5 p-0"
            data-testid="compose-running-services"
          >
            {cfg.services.map((sv) => (
              <li
                key={sv.service}
                className="flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-md border border-line px-3 py-2 text-[13px]"
                data-testid="compose-running-service"
                data-service={sv.service}
                data-state={sv.state ?? 'unknown'}
              >
                <b className="font-mono">{sv.service}</b>
                {sv.service === cfg.routeService && (
                  <ToneBadge tone="info" size="sm">
                    {t('cmp.route')}
                  </ToneBadge>
                )}
                <ToneBadge tone={STATE_TONE[sv.state ?? 'unknown'] ?? 'stale'} size="sm">
                  {t(`cmp.state.${sv.state ?? 'unknown'}` as MessageKey)}
                </ToneBadge>
                <HealthLabel h={healthView(sv.health)} />
                <span className="basis-full font-mono text-[11.5px] break-all text-fg-muted">
                  {sv.image}
                </span>
                {sv.volumes.length > 0 && (
                  <span className="basis-full text-[11.5px] text-fg-muted">
                    {t('wiz.cfg.volumes')}:{' '}
                    {sv.volumes.map((v) => `${v.name}:${v.mountPath}`).join(', ')}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card className="flex flex-col gap-3 p-4" data-testid="compose-yaml-card">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('cmp.yaml')}</h2>
          {!edit && (
            <GatedButton
              size="sm"
              perm="apps.deploy"
              action="edit_compose"
              allowedActions={app.allowedActions}
              disabled={!yaml}
              onClick={() =>
                setEdit({
                  ...initialCompose(),
                  yaml,
                  routeService: cfg.routeService,
                  routePort: String(cfg.routePort),
                  healthPath: cfg.healthPath,
                })
              }
              data-testid="compose-edit"
            >
              {t('cmp.edit')}
            </GatedButton>
          )}
        </div>
        {!gate.allowed && gate.reason && (
          <p className="m-0 text-[12px] text-fg-muted">{t(gate.reason.key, gate.reason.vars)}</p>
        )}
        {!edit &&
          (current.isPending && !cfg.yaml ? (
            <Skeleton className="h-48 w-full" />
          ) : current.isError && !yaml ? (
            <ErrorState error={current.error} onRetry={() => void current.refetch()} />
          ) : (
            <pre
              tabIndex={0}
              aria-label={t('cmp.yaml')}
              data-testid="compose-yaml-readonly"
              className="m-0 max-h-[420px] overflow-auto rounded-md bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.55] whitespace-pre text-terminal-fg"
            >
              {yaml}
            </pre>
          ))}
        {edit && (
          <div className="flex flex-col gap-3">
            <Field
              label={t('wiz.src.compose.label')}
              hint={t('cmp.editHint', { v: cfg.version + 1 })}
            >
              {(p) => (
                <textarea
                  {...p}
                  rows={16}
                  value={edit.yaml}
                  onChange={(e) => patchEdit({ yaml: e.target.value })}
                  spellCheck={false}
                  className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg"
                  data-testid="compose-edit-yaml"
                />
              )}
            </Field>
            {validation.isPending && (
              <span className="text-[12.5px] text-fg-muted">{t('wiz.src.compose.validating')}</span>
            )}
            {edit.validation && edit.validatedYaml === edit.yaml && (
              <ComposeViolations r={edit.validation} />
            )}
            <ComposeRouteFields
              c={edit}
              services={rows.map((r) => r.service)}
              onChange={patchEdit}
            />
            <ComposeServicesDetected
              rows={rows}
              renderSecret={(key, status) => (
                <SecretInput
                  secretKey={key}
                  status={{ set: status === 'set' }}
                  disabled={!gate.allowed}
                  onSubmit={async (v) => {
                    await containerAppsApi.putSecret(app.id, key, v);
                    void qc.invalidateQueries({ queryKey: p4k.secrets(app.id) });
                  }}
                />
              )}
            />
            <section className="flex flex-col gap-1.5">
              <h3 className="m-0 text-[14px] font-semibold">{t('cmp.plan')}</h3>
              <ComposePlanTable rows={composePlan(cfg.services, rows)} />
              <p className="m-0 text-[12px] text-fg-muted">{t('wiz.cmp.planNote')}</p>
            </section>
            {issues.length > 0 && (
              <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px] text-warn">
                {issues.map((k) => (
                  <li key={k}>▲ {t(k)}</li>
                ))}
              </ul>
            )}
            {save.error && <ErrorState error={save.error} />}
            {save.error && isApiError(save.error) && save.error.status === 409 && (
              <Notice tone="warn" glyph="▲" role="status">
                {t('net.conflict')}
              </Notice>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                variant="primary"
                disabled={issues.length > 0 || unchanged || save.isPending}
                onClick={() => save.mutate()}
                data-testid="compose-save"
              >
                {save.isPending ? t('common.saving') : t('cmp.saveVersion', { v: cfg.version + 1 })}
              </Button>
              <Button onClick={() => setEdit(null)}>{t('common.cancel')}</Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
