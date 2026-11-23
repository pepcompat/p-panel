'use client';

import { useEffect, useMemo } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { containerAppsApi, deployToolsApi } from '@/lib/api/p4-endpoints';
import type { ComposeValidation } from '@/lib/api/p4-types';
import {
  HEALTH_PATH_RE,
  deriveComposeServices,
  hasDependencyCycle,
  type ComposeServiceRow,
  type ComposeState,
} from '@/lib/p4b-gates';
import type { WizardState } from '@/lib/p4-gates';
import { p4k } from '@/lib/p4-queries';
import { ToneBadge } from '@/components/ui/badge';
import { Field, Input, Select } from '@/components/ui/form';
import { ErrorState, Notice } from '@/components/ui/states';
import { HealthLabel } from './compose-bits';
import { SecretInput } from './secret-input';

type Patch = (fn: (w: WizardState) => WizardState) => void;

const textarea =
  'w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg placeholder:text-fg-subtle';

export const COMPOSE_PLACEHOLDER = `services:
  app:
    image: registry.example.lab/w3/crm-app@sha256:…
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
    depends_on: [db]
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata: {}`;

/** Violations + warnings table of the Center's static validator (§7.6). */
export function ComposeViolations({ r }: { r: ComposeValidation }) {
  const { t } = useI18n();
  const rows = [
    ...r.violations.map((v) => ({ ...v, warn: false })),
    ...(r.warnings ?? []).map((v) => ({ ...v, warn: true })),
  ];
  return (
    <div
      className="flex flex-col gap-2"
      aria-live="polite"
      data-testid="compose-result"
      data-valid={r.valid ? 'true' : 'false'}
    >
      {r.valid ? (
        <Notice tone="ok" glyph="●" role="status">
          {t('wiz.src.compose.valid', { n: r.services.length })}
        </Notice>
      ) : (
        <Notice tone="crit" glyph="✕" role="alert">
          {t('wiz.src.compose.invalid', { n: r.violations.length })}
        </Notice>
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full border-collapse text-[12.5px]" style={{ minWidth: 560 }}>
            <thead>
              <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
                <th scope="col" className="px-3 py-2 font-medium">
                  {t('wiz.src.compose.col.severity')}
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  {t('wiz.src.compose.col.rule')}
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  {t('wiz.src.compose.col.path')}
                </th>
                <th scope="col" className="px-2 py-2 pr-3 font-medium">
                  {t('wiz.src.compose.col.message')}
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v, i) => (
                <tr
                  key={`${v.path}-${v.rule}-${i}`}
                  className="border-t border-line-subtle"
                  data-testid="compose-violation"
                  data-rule={v.rule}
                >
                  <td className="px-3 py-1.5">
                    <ToneBadge tone={v.warn ? 'warn' : 'crit'} size="sm">
                      {v.warn ? t('wiz.src.compose.warning') : t('wiz.src.compose.violation')}
                    </ToneBadge>
                  </td>
                  <td className="px-2 py-1.5 font-mono">{v.rule}</td>
                  <td className="px-2 py-1.5 font-mono break-all">{v.path}</td>
                  <td className="px-2 py-1.5 pr-3">{v.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Debounced live validation; the result is written back for exactly the YAML it validated. */
export function useComposeValidation(
  yaml: string,
  environment: string | undefined,
  onResult: (yaml: string, r: ComposeValidation) => void,
) {
  const m = useMutation<ComposeValidation, ApiError, string>({
    mutationFn: (y) => deployToolsApi.validateCompose(y, environment),
    onSuccess: (r, y) => onResult(y, r),
  });
  const { mutate } = m;
  useEffect(() => {
    if (!yaml.trim()) return;
    const h = setTimeout(() => mutate(yaml), 400);
    return () => clearTimeout(h);
  }, [yaml, mutate, environment]);
  return m;
}

/** Route service + port + health path pickers. */
export function ComposeRouteFields({
  c,
  services,
  onChange,
}: {
  c: Pick<ComposeState, 'routeService' | 'routePort' | 'healthPath'>;
  services: readonly string[];
  onChange: (p: Partial<ComposeState>) => void;
}) {
  const { t } = useI18n();
  const port = Number(c.routePort);
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <Field
        label={t('wiz.cmp.routeService')}
        hint={t('wiz.cmp.routeServiceHint')}
        error={
          c.routeService && !services.includes(c.routeService)
            ? t('wiz.cmp.issue.route')
            : undefined
        }
      >
        {(p) => (
          <Select
            {...p}
            value={c.routeService}
            onChange={(e) => onChange({ routeService: e.target.value })}
          >
            <option value="">{t('wiz.cmp.routePick')}</option>
            {services.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field
        label={t('wiz.cmp.routePort')}
        hint={t('wiz.cmp.routePortHint')}
        error={c.routePort && !(port >= 1 && port <= 65535) ? t('wiz.cmp.issue.port') : undefined}
      >
        {(p) => (
          <Input
            {...p}
            inputMode="numeric"
            value={c.routePort}
            onChange={(e) => onChange({ routePort: e.target.value.replace(/\D/g, '') })}
            className="font-mono"
          />
        )}
      </Field>
      <Field
        label={t('wiz.cmp.healthPath')}
        hint={t('wiz.cmp.healthPathHint')}
        error={HEALTH_PATH_RE.test(c.healthPath) ? undefined : t('wiz.cmp.issue.health')}
      >
        {(p) => (
          <Input
            {...p}
            value={c.healthPath}
            onChange={(e) => onChange({ healthPath: e.target.value.trim() })}
            className="font-mono"
          />
        )}
      </Field>
    </div>
  );
}

/** Detected services: image, inferred health, secret placeholders (inline write-only inputs). */
export function ComposeServicesDetected({
  rows,
  renderSecret,
}: {
  rows: readonly ComposeServiceRow[];
  renderSecret: (key: string, status: 'set' | 'staged' | 'missing') => React.ReactNode;
}) {
  const { t } = useI18n();
  const th = 'px-2 py-2 text-left text-[12px] font-medium text-fg-muted';
  return (
    <div className="overflow-x-auto rounded-md border border-line" data-testid="compose-services">
      <table className="w-full border-collapse text-[12.5px]" style={{ minWidth: 640 }}>
        <caption className="sr-only">{t('wiz.cmp.detected')}</caption>
        <thead>
          <tr className="bg-surface-2">
            <th scope="col" className={`${th} pl-3`}>
              {t('cmp.col.service')}
            </th>
            <th scope="col" className={th}>
              {t('cmp.col.image')}
            </th>
            <th scope="col" className={th}>
              {t('cmp.col.health')}
            </th>
            <th scope="col" className={`${th} pr-3`}>
              {t('cmp.col.secrets')}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.service}
              className="border-t border-line-subtle align-top"
              data-testid="compose-detected-row"
              data-service={r.service}
              data-health={r.health.type}
            >
              <td className="px-3 py-2 font-mono">
                {r.service}
                {r.isRoute && (
                  <ToneBadge tone="info" size="sm" className="ml-1.5">
                    {t('cmp.route')}
                  </ToneBadge>
                )}
                {r.volumes.length > 0 && (
                  <span className="mt-0.5 block text-[11.5px] text-fg-muted">
                    {r.volumes.map((v) => `${v.name}:${v.mountPath}`).join(', ')}
                  </span>
                )}
                {r.portsNotAllowed && (
                  <span className="mt-0.5 block text-[11.5px] text-crit">
                    ✕ {t('wiz.cmp.issue.ports')}
                  </span>
                )}
              </td>
              <td className="px-2 py-2 font-mono text-[11.5px] break-all">
                {r.image ?? t('common.dash')}
                <span className="mt-0.5 block">
                  {r.pinned ? (
                    <ToneBadge tone="ok" size="sm">
                      {t('wiz.cmp.pinned')}
                    </ToneBadge>
                  ) : (
                    <ToneBadge tone="off" size="sm">
                      {t('wiz.cmp.resolveAtDeploy')}
                    </ToneBadge>
                  )}
                </span>
              </td>
              <td className="px-2 py-2">
                <HealthLabel h={r.health} />
                <span className="block text-[11px] text-fg-muted">
                  {t(
                    r.isRoute
                      ? 'wiz.cmp.health.route'
                      : r.health.type === 'tcp'
                        ? 'wiz.cmp.health.db'
                        : 'wiz.cmp.health.other',
                  )}
                </span>
              </td>
              <td className="px-2 py-2 pr-3">
                {r.placeholders.length === 0 ? (
                  <span className="text-fg-muted">{t('common.none')}</span>
                ) : (
                  <div className="flex flex-col gap-2">
                    {r.placeholders.map((p) => (
                      <div
                        key={p.key}
                        data-testid="compose-placeholder"
                        data-key={p.key}
                        data-status={p.status}
                      >
                        {renderSecret(p.key, p.status)}
                      </div>
                    ))}
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Wizard Source → Compose (§8.3). New apps stage placeholder values (written after creation); for an
 * existing compose app values are written straight to the app's secrets.
 */
export function ComposeSourceForm({
  w,
  patch,
  environment,
  app,
  setSecrets,
  secretValues,
}: {
  w: WizardState;
  patch: Patch;
  environment?: string;
  app: Application | null;
  setSecrets: readonly string[];
  secretValues: Map<string, string>;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const c = w.compose;
  const setC = (p: Partial<ComposeState>) =>
    patch((x) => ({ ...x, compose: { ...x.compose, ...p } }));
  const m = useComposeValidation(c.yaml, environment, (yaml, r) =>
    patch((x) =>
      x.compose.yaml === yaml
        ? { ...x, compose: { ...x.compose, validation: r, validatedYaml: yaml } }
        : x,
    ),
  );
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
    [c.yaml, c.routeService, c.routePort, c.healthPath, c.staged, setSecrets],
  );
  const names = rows.map((r) => r.service);
  // Default route service: the only service that declares ports, else the first one.
  useEffect(() => {
    if (c.routeService || !names.length) return;
    patch((x) => ({ ...x, compose: { ...x.compose, routeService: names[0]! } }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [names.join(',')]);
  const r = c.yaml.trim() && c.validatedYaml === c.yaml ? c.validation : null;
  const existing = w.mode === 'existing' && app ? app : null;
  const missing = rows.flatMap((x) => x.placeholders).filter((p) => p.status === 'missing');

  return (
    <div className="flex flex-col gap-4" data-testid="compose-source">
      <Field label={t('wiz.src.compose.label')} hint={t('wiz.cmp.yamlHint')}>
        {(p) => (
          <textarea
            {...p}
            rows={14}
            value={c.yaml}
            onChange={(e) => setC({ yaml: e.target.value })}
            spellCheck={false}
            className={textarea}
            placeholder={COMPOSE_PLACEHOLDER}
            data-testid="compose-yaml"
          />
        )}
      </Field>
      {!environment && (
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.cmp.strictUntilTarget')}</p>
      )}
      {m.isPending && (
        <span className="text-[12.5px] text-fg-muted">{t('wiz.src.compose.validating')}</span>
      )}
      {m.error && <ErrorState error={m.error} />}
      {r && <ComposeViolations r={r} />}

      {rows.length > 0 && (
        <>
          <ComposeRouteFields c={c} services={names} onChange={setC} />
          <section className="flex flex-col gap-2" aria-labelledby="cmp-detected">
            <h3 id="cmp-detected" className="m-0 text-[14px] font-semibold">
              {t('wiz.cmp.detected')}
            </h3>
            <ComposeServicesDetected
              rows={rows}
              renderSecret={(key, status) =>
                existing ? (
                  <SecretInput
                    secretKey={key}
                    status={{ set: status === 'set' }}
                    onSubmit={async (v) => {
                      await containerAppsApi.putSecret(existing.id, key, v);
                      void qc.invalidateQueries({ queryKey: p4k.secrets(existing.id) });
                    }}
                  />
                ) : (
                  <SecretInput
                    secretKey={key}
                    status={{ set: false, staged: status === 'staged' }}
                    submitLabel={status === 'staged' ? t('secret.replace') : t('wiz.cfg.stage')}
                    onSubmit={(v) => {
                      secretValues.set(`cmp:${key}`, v);
                      setC({ staged: [...new Set([...c.staged, key])] });
                    }}
                  />
                )
              }
            />
            {missing.length > 0 && (
              <p className="m-0 text-[12.5px] text-warn" data-testid="placeholders-missing">
                ▲{' '}
                {t('wiz.cmp.missingSecrets', {
                  keys: [...new Set(missing.map((p) => p.key))].join(', '),
                })}
              </p>
            )}
            {hasDependencyCycle(rows) && (
              <p className="m-0 text-[12.5px] text-crit">✕ {t('wiz.cmp.issue.cycle')}</p>
            )}
          </section>
        </>
      )}

      <Notice tone="warn" glyph="▲" role="note" title={t('wiz.cmp.riskTitle')}>
        <span data-testid="compose-risk">{t('wiz.cmp.risk')}</span>
      </Notice>
    </div>
  );
}
