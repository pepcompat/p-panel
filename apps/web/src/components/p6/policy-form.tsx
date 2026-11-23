'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { useServers } from '@/lib/queries';
import { useApplications } from '@/lib/p3-queries';
import { useRepositories } from '@/lib/p6-queries';
import { policiesApi } from '@/lib/api/p6-endpoints';
import { isApiError, type ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import {
  RESTORE_TEST_EVERY,
  VERIFY_AFTER,
  type BackupPolicy,
  type BackupPolicyInput,
  type BackupTargetInput,
  type DbTarget,
} from '@/lib/api/p6-types';
import { CRON_PRESETS, isValidTimeZone, nextRuns, parseCron, timeZones } from '@/lib/cron';
import { validatePolicy } from '@/lib/p6-gates';
import { formatDateTime } from '@/lib/time';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Field, Input, Select } from '@/components/ui/form';
import { ErrorState, Notice } from '@/components/ui/states';
import { describeSchedule } from './bits';

const DEFAULT_TZ = 'Asia/Bangkok';
const lines = (s: string) =>
  s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean);

export function emptyPolicy(serverId = '', repositoryId = ''): BackupPolicyInput {
  return {
    name: '',
    serverId,
    repositoryId,
    targets: [],
    schedule: { cron: '0 2 * * *', timezone: DEFAULT_TZ },
    retention: { keepDaily: 7, keepWeekly: 4, keepMonthly: 6 },
    verify: { afterBackup: 'none', restoreTestEvery: 'weekly' },
    enabled: true,
  };
}

/** Compose services that look like a DB (image name) → engine. */
export function dbServicesOf(app: Application | undefined) {
  return (app?.compose?.services ?? [])
    .map((s) => {
      const img = s.image.toLowerCase();
      const engine = /postgres|postgis|timescale/.test(img)
        ? ('postgres' as const)
        : /mysql|mariadb/.test(img)
          ? ('mysql' as const)
          : null;
      return engine ? { service: s.service, engine, image: s.image } : null;
    })
    .filter((x): x is NonNullable<typeof x> => !!x);
}
export const volumesOf = (app: Application | undefined) => [
  ...new Set([
    ...(app?.container?.volumes ?? []).map((v) => v.name),
    ...(app?.compose?.services ?? []).flatMap((s) => s.volumes.map((v) => v.name)),
  ]),
];
export const secretKeysOf = (app: Application | undefined) =>
  app?.compose?.secretKeys ?? app?.container?.secretKeys ?? [];

/** Stored targets carry the resolved `app` slug; the strict input schema takes `applicationId` only. */
function stripApp(
  t: BackupTargetInput | (BackupTargetInput & { app?: string }),
): BackupTargetInput {
  if (t.type === 'paths') return { type: 'paths', paths: t.paths, excludes: t.excludes ?? [] };
  const { app: _app, ...rest } = t as BackupTargetInput & { app?: string };
  return rest as BackupTargetInput;
}

interface TargetDraft {
  key: string;
  t: BackupTargetInput;
  pathsText: string;
  excludesText: string;
}
let seq = 0;
const draftOf = (t: BackupTargetInput): TargetDraft => ({
  key: `t${++seq}`,
  t,
  pathsText: t.type === 'paths' ? t.paths.join('\n') : '',
  excludesText: t.type === 'paths' ? t.excludes.join('\n') : '',
});

export function PolicyForm({
  policy,
  initial,
  onDone,
  onCancel,
}: {
  policy?: BackupPolicy | null;
  initial?: Partial<BackupPolicyInput> & { applicationId?: string };
  onDone: (p: BackupPolicy) => void;
  onCancel: () => void;
}) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const servers = useServers();
  const repos = useRepositories();
  const base = policy ?? { ...emptyPolicy(), ...initial };
  const [name, setName] = useState(base.name);
  const [serverId, setServerId] = useState(base.serverId);
  const [repositoryId, setRepositoryId] = useState(base.repositoryId || repos.data?.[0]?.id || '');
  const [targets, setTargets] = useState<TargetDraft[]>(() => {
    const ts = (base.targets ?? []).map(draftOf);
    if (!policy && initial?.applicationId)
      ts.push(draftOf({ type: 'volume', applicationId: initial.applicationId, volume: '' }));
    return ts;
  });
  const [cron, setCron] = useState(base.schedule.cron);
  const [tz, setTz] = useState(base.schedule.timezone);
  const [retention, setRetention] = useState(base.retention);
  const [verify, setVerify] = useState(base.verify);
  const [enabled, setEnabled] = useState(base.enabled);
  const [submitted, setSubmitted] = useState(false);
  const apps = useApplications(serverId ? { server_id: serverId } : {});
  const appList = (apps.data?.items ?? []).filter(
    (a) => a.serverId === serverId && (a.kind === 'container' || a.kind === 'compose'),
  );
  const zones = useMemo(() => timeZones(), []);
  const repoId = repositoryId || repos.data?.[0]?.id || '';
  const firstRepo = repos.data?.[0]?.id;
  useEffect(() => {
    if (!repositoryId && firstRepo) setRepositoryId(firstRepo);
  }, [repositoryId, firstRepo]);
  const repo = repos.data?.find((r) => r.id === repoId);
  const access = repo?.servers.find((a) => a.serverId === serverId);

  const input: BackupPolicyInput = {
    name: name.trim(),
    serverId,
    repositoryId: repoId,
    targets: targets.map((d) =>
      d.t.type === 'paths'
        ? { type: 'paths', paths: lines(d.pathsText), excludes: lines(d.excludesText) }
        : stripApp(d.t),
    ),
    schedule: { cron: cron.trim().replace(/\s+/g, ' '), timezone: tz.trim() },
    retention,
    verify,
    enabled,
  };
  const errors = validatePolicy(input);
  const err = (k: string) => (submitted && errors[k] ? t(errors[k]!) : undefined);

  const m = useMutation<BackupPolicy, ApiError>({
    mutationFn: () =>
      policy
        ? policiesApi.update(
            policy.id,
            Object.fromEntries(Object.entries(input).filter(([k]) => k !== 'serverId')),
            policy.version,
          )
        : policiesApi.create(input),
    onSuccess: (p) => {
      void qc.invalidateQueries({ queryKey: ['backup-policies'], exact: false });
      onDone(p);
    },
  });
  const serverErrors = (
    isApiError(m.error) && Array.isArray(m.error.details)
      ? (m.error.details as Array<{ path?: string; field?: string; message: string }>)
      : []
  ).reduce<Record<string, string>>(
    (a, d) => ({ ...a, [String(d.path ?? d.field ?? '')]: d.message }),
    {},
  );
  const fieldErr = (k: string) => {
    const local = err(k);
    if (local) return local;
    const s = serverErrors[k];
    if (!s) return undefined;
    return s.startsWith('bk.') ? t(s as MessageKey) : s;
  };

  const update = (key: string, fn: (d: TargetDraft) => TargetDraft) =>
    setTargets((ts) => ts.map((d) => (d.key === key ? fn(d) : d)));

  const parsed = parseCron(cron);
  const tzOk = isValidTimeZone(tz.trim());
  const now = Date.now();
  const upcoming = parsed.ok && tzOk ? nextRuns(parsed.cron, tz.trim(), now, 3) : [];
  const zoneFmt = (ms: number) =>
    new Date(ms).toLocaleString(locale === 'th' ? 'th-TH' : 'en-GB', {
      timeZone: tz.trim(),
      weekday: 'short',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });

  const submit = () => {
    setSubmitted(true);
    if (Object.keys(errors).length) return;
    m.mutate();
  };

  return (
    <Card className="flex flex-col gap-4 p-4" data-testid="policy-form">
      <h2 className="m-0 text-[16px] font-semibold">
        {policy ? t('bk.form.titleEdit', { name: policy.name }) : t('bk.form.titleNew')}
      </h2>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label={t('bk.form.name')} error={fieldErr('name')}>
          {(p) => (
            <Input {...p} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
          )}
        </Field>
        <Field
          label={t('bk.form.server')}
          error={fieldErr('serverId')}
          hint={policy ? t('bk.form.serverFixed') : undefined}
        >
          {(p) => (
            <Select
              {...p}
              value={serverId}
              disabled={!!policy}
              onChange={(e) => {
                setServerId(e.target.value);
                setTargets((ts) => ts.filter((d) => d.t.type === 'paths'));
              }}
            >
              <option value="">{t('bk.form.serverPick')}</option>
              {(servers.data?.items ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} · {s.environment}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('bk.form.repository')} error={fieldErr('repositoryId')}>
          {(p) => (
            <Select {...p} value={repoId} onChange={(e) => setRepositoryId(e.target.value)}>
              <option value="">{t('bk.form.repoPick')}</option>
              {(repos.data ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      {repos.isError && <ErrorState error={repos.error} onRetry={() => void repos.refetch()} />}
      {serverId && repo && !access && (
        <Notice tone="warn" glyph="▲" role="status">
          {t('bk.form.repoNoAccess', { repo: repo.name })}
        </Notice>
      )}
      {serverId && access && !access.initialized && (
        <Notice tone="warn" glyph="▲" role="status">
          <span data-testid="repo-not-init">{t('bk.form.repoNotInit')}</span>
        </Notice>
      )}

      {/* targets builder */}
      <section className="flex flex-col gap-2" aria-labelledby="bk-targets">
        <div className="flex flex-wrap items-center gap-2">
          <h3 id="bk-targets" className="m-0 flex-1 text-[14px] font-semibold">
            {t('bk.form.targets')}
          </h3>
          <Button
            size="sm"
            onClick={() =>
              setTargets((ts) => [...ts, draftOf({ type: 'paths', paths: [], excludes: [] })])
            }
          >
            {t('bk.form.addPaths')}
          </Button>
          <Button
            size="sm"
            disabled={!serverId}
            onClick={() =>
              setTargets((ts) => [
                ...ts,
                draftOf({ type: 'volume', applicationId: '', volume: '' }),
              ])
            }
          >
            {t('bk.form.addVolume')}
          </Button>
          <Button
            size="sm"
            disabled={!serverId}
            onClick={() =>
              setTargets((ts) => [
                ...ts,
                draftOf({
                  type: 'postgres',
                  applicationId: '',
                  service: '',
                  database: '',
                  user: '',
                  passwordSecretKey: '',
                }),
              ])
            }
          >
            {t('bk.form.addDb')}
          </Button>
        </div>
        {err('targets') && (
          <span role="alert" className="text-[12px] text-crit">
            {err('targets')}
          </span>
        )}
        {targets.map((d, i) => (
          <div
            key={d.key}
            className="flex flex-col gap-2 rounded-md border border-line p-3"
            data-testid="target-row"
            data-type={d.t.type}
          >
            <div className="flex items-center gap-2">
              <b className="flex-1 text-[13px]">
                {i + 1}.{' '}
                {t(
                  d.t.type === 'paths'
                    ? 'bk.form.target.paths'
                    : d.t.type === 'volume'
                      ? 'bk.form.target.volume'
                      : 'bk.form.target.db',
                )}
              </b>
              <Button
                size="xs"
                variant="ghost"
                onClick={() => setTargets((ts) => ts.filter((x) => x.key !== d.key))}
              >
                {t('bk.form.removeTarget')}
              </Button>
            </div>
            {d.t.type === 'paths' ? (
              <div className="grid gap-2 sm:grid-cols-2">
                <Field
                  label={t('bk.form.paths')}
                  hint={t('bk.form.pathsHint')}
                  error={
                    fieldErr(`targets.${i}.paths`) ??
                    lines(d.pathsText)
                      .map((_, j) => fieldErr(`targets.${i}.paths.${j}`))
                      .find(Boolean)
                  }
                >
                  {(p) => (
                    <textarea
                      {...p}
                      rows={3}
                      value={d.pathsText}
                      onChange={(e) => update(d.key, (x) => ({ ...x, pathsText: e.target.value }))}
                      placeholder="/srv/app/uploads"
                      className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[13px] aria-[invalid=true]:border-crit"
                    />
                  )}
                </Field>
                <Field
                  label={t('bk.form.excludes')}
                  error={lines(d.excludesText)
                    .map((_, j) => fieldErr(`targets.${i}.excludes.${j}`))
                    .find(Boolean)}
                >
                  {(p) => (
                    <textarea
                      {...p}
                      rows={3}
                      value={d.excludesText}
                      onChange={(e) =>
                        update(d.key, (x) => ({ ...x, excludesText: e.target.value }))
                      }
                      placeholder="*.tmp"
                      className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[13px] aria-[invalid=true]:border-crit"
                    />
                  )}
                </Field>
              </div>
            ) : (
              <AppTargetEditor
                index={i}
                target={d.t}
                apps={appList}
                fieldErr={fieldErr}
                onChange={(nt) => update(d.key, (x) => ({ ...x, t: nt }))}
              />
            )}
          </div>
        ))}
      </section>

      {/* schedule */}
      <section className="flex flex-col gap-2" aria-labelledby="bk-sched">
        <h3 id="bk-sched" className="m-0 text-[14px] font-semibold">
          {t('bk.form.schedule')}
        </h3>
        <div
          className="flex flex-wrap items-center gap-1.5"
          role="group"
          aria-label={t('bk.form.presets')}
        >
          {CRON_PRESETS.map((p) => (
            <Button key={p.cron} size="xs" variant="chip" onClick={() => setCron(p.cron)}>
              {t(`bk.form.preset.${p.key}` as MessageKey)}
            </Button>
          ))}
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label={t('bk.form.cron')}
            hint={t('bk.form.cronHint')}
            error={fieldErr('cron') ?? fieldErr('schedule.cron')}
          >
            {(p) => (
              <Input
                {...p}
                value={cron}
                onChange={(e) => setCron(e.target.value)}
                className="font-mono"
                spellCheck={false}
              />
            )}
          </Field>
          <Field
            label={t('bk.form.timezone')}
            hint={t('bk.form.timezoneHint')}
            error={fieldErr('timezone') ?? fieldErr('schedule.timezone')}
          >
            {(p) => (
              <>
                <Input
                  {...p}
                  value={tz}
                  onChange={(e) => setTz(e.target.value)}
                  list="bk-tz-list"
                  className="font-mono"
                  spellCheck={false}
                  autoComplete="off"
                />
                <datalist id="bk-tz-list">
                  {zones.map((z) => (
                    <option key={z} value={z} />
                  ))}
                </datalist>
              </>
            )}
          </Field>
        </div>
        <div
          className="flex flex-col gap-1 rounded-md bg-chip-2 px-3 py-2 text-[13px]"
          aria-live="polite"
          data-testid="cron-preview"
        >
          <b data-testid="cron-description">{describeSchedule(cron, tz.trim() || '—', t)}</b>
          <span className="text-[12px] text-fg-muted">{t('bk.form.nextRuns')}</span>
          {upcoming.length === 0 ? (
            <span className="text-fg-muted">{t('bk.form.nextRunsNone')}</span>
          ) : (
            <ol className="m-0 flex flex-col gap-0.5 pl-5" data-testid="next-runs">
              {upcoming.map((ms) => (
                <li key={ms}>
                  <span className="font-mono text-[12.5px]">{zoneFmt(ms)}</span>{' '}
                  <span className="text-[12px] text-fg-muted">
                    · {new Date(ms).toISOString().replace('.000Z', 'Z')}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </section>

      {/* retention + verify */}
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="flex flex-col gap-2" aria-labelledby="bk-ret">
          <h3 id="bk-ret" className="m-0 text-[14px] font-semibold">
            {t('bk.form.retention')}
          </h3>
          <Notice tone="neutral" glyph="◆" role="note">
            <span data-testid="retention-note">{t('bk.form.retentionNote')}</span>
          </Notice>
          <div className="grid grid-cols-3 gap-2">
            {(['keepDaily', 'keepWeekly', 'keepMonthly'] as const).map((k) => (
              <Field
                key={k}
                label={t(`bk.form.${k}` as MessageKey)}
                error={fieldErr(`retention.${k}`)}
              >
                {(p) => (
                  <Input
                    {...p}
                    type="number"
                    min={0}
                    max={1000}
                    value={String(retention[k])}
                    onChange={(e) => setRetention((r) => ({ ...r, [k]: Number(e.target.value) }))}
                  />
                )}
              </Field>
            ))}
          </div>
        </section>
        <section className="flex flex-col gap-2" aria-labelledby="bk-ver">
          <h3 id="bk-ver" className="m-0 text-[14px] font-semibold">
            {t('bk.form.verify')}
          </h3>
          <Field label={t('bk.form.afterBackup')}>
            {(p) => (
              <Select
                {...p}
                value={verify.afterBackup}
                onChange={(e) =>
                  setVerify((v) => ({ ...v, afterBackup: e.target.value as typeof v.afterBackup }))
                }
              >
                {VERIFY_AFTER.map((x) => (
                  <option key={x} value={x}>
                    {t(`bk.form.after.${x}` as MessageKey)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t('bk.form.restoreTestEvery')}>
            {(p) => (
              <Select
                {...p}
                value={verify.restoreTestEvery}
                onChange={(e) =>
                  setVerify((v) => ({
                    ...v,
                    restoreTestEvery: e.target.value as typeof v.restoreTestEvery,
                  }))
                }
              >
                {RESTORE_TEST_EVERY.map((x) => (
                  <option key={x} value={x}>
                    {t(`bk.form.every.${x}` as MessageKey)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <label className="flex items-center gap-2 text-[13px]">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            {t('bk.form.enabled')}
          </label>
        </section>
      </div>

      {submitted && Object.keys(errors).length > 0 && (
        <Notice tone="crit" glyph="✕" role="alert">
          {t('bk.form.fixErrors')}
        </Notice>
      )}
      {m.error && <ErrorState error={m.error} />}
      <div className="flex flex-wrap justify-end gap-2">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button
          variant="primary"
          onClick={submit}
          disabled={m.isPending}
          data-testid="policy-submit"
        >
          {m.isPending ? t('common.saving') : policy ? t('bk.form.save') : t('bk.form.create')}
        </Button>
      </div>
      {policy && (
        <p className="m-0 text-[12px] text-fg-muted">
          v{policy.version} · {formatDateTime(policy.updatedAt, locale)}
        </p>
      )}
    </Card>
  );
}

function AppTargetEditor({
  index,
  target,
  apps,
  fieldErr,
  onChange,
}: {
  index: number;
  target: Exclude<BackupTargetInput, { type: 'paths' }>;
  apps: Application[];
  fieldErr: (k: string) => string | undefined;
  onChange: (t: BackupTargetInput) => void;
}) {
  const { t } = useI18n();
  const app = apps.find((a) => a.id === target.applicationId);
  const k = (f: string) => `targets.${index}.${f}`;
  const appSelect = (
    <Field label={t('bk.form.app')} error={fieldErr(k('app'))}>
      {(p) => (
        <Select
          {...p}
          value={target.applicationId}
          onChange={(e) => {
            const next = apps.find((a) => a.id === e.target.value);
            if (target.type === 'volume')
              onChange({
                ...target,
                applicationId: e.target.value,
                volume: volumesOf(next)[0] ?? '',
              });
            else {
              const db = dbServicesOf(next)[0];
              onChange({
                ...target,
                type: db?.engine ?? target.type,
                applicationId: e.target.value,
                service: db?.service ?? '',
                passwordSecretKey: secretKeysOf(next)[0] ?? '',
              });
            }
          }}
        >
          <option value="">{t('bk.form.appPick')}</option>
          {apps.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name} · {a.kind}
            </option>
          ))}
        </Select>
      )}
    </Field>
  );
  if (apps.length === 0)
    return <p className="m-0 text-[12.5px] text-fg-muted">{t('bk.form.noApps')}</p>;
  if (target.type === 'volume') {
    const vols = volumesOf(app);
    return (
      <div className="grid gap-2 sm:grid-cols-2">
        {appSelect}
        <Field label={t('bk.form.volume')} error={fieldErr(k('volume'))}>
          {(p) =>
            app && vols.length === 0 ? (
              <span className="text-[12.5px] text-fg-muted">{t('bk.form.noVolumes')}</span>
            ) : (
              <Select
                {...p}
                value={target.volume}
                onChange={(e) => onChange({ ...target, volume: e.target.value })}
              >
                <option value="">—</option>
                {vols.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </Select>
            )
          }
        </Field>
      </div>
    );
  }
  const dbt = target as DbTarget;
  const services = dbServicesOf(app);
  const keys = secretKeysOf(app);
  return (
    <div className="grid gap-2 sm:grid-cols-3">
      {appSelect}
      <Field label={t('bk.form.service')} error={fieldErr(k('service'))}>
        {(p) =>
          app && services.length === 0 ? (
            <span className="text-[12.5px] text-fg-muted">{t('bk.form.noDbServices')}</span>
          ) : (
            <Select
              {...p}
              value={dbt.service}
              onChange={(e) => {
                const svc = services.find((x) => x.service === e.target.value);
                onChange({ ...dbt, service: e.target.value, type: svc?.engine ?? dbt.type });
              }}
            >
              <option value="">{t('bk.form.servicePick')}</option>
              {services.map((x) => (
                <option key={x.service} value={x.service}>
                  {x.service} · {x.engine}
                </option>
              ))}
            </Select>
          )
        }
      </Field>
      <Field label={t('bk.form.engine')}>
        {(p) => (
          <Select
            {...p}
            value={dbt.type}
            onChange={(e) => onChange({ ...dbt, type: e.target.value as DbTarget['type'] })}
          >
            <option value="postgres">postgres</option>
            <option value="mysql">mysql</option>
          </Select>
        )}
      </Field>
      <Field label={t('bk.form.database')} error={fieldErr(k('database'))}>
        {(p) => (
          <Input
            {...p}
            value={dbt.database}
            onChange={(e) => onChange({ ...dbt, database: e.target.value })}
            className="font-mono"
          />
        )}
      </Field>
      <Field label={t('bk.form.dbUser')} error={fieldErr(k('user'))}>
        {(p) => (
          <Input
            {...p}
            value={dbt.user}
            onChange={(e) => onChange({ ...dbt, user: e.target.value })}
            className="font-mono"
          />
        )}
      </Field>
      <Field
        label={t('bk.form.secretKey')}
        hint={t('bk.form.secretKeyHint')}
        error={fieldErr(k('passwordSecretKey'))}
      >
        {(p) =>
          app && keys.length === 0 ? (
            <span className="text-[12.5px] text-fg-muted">{t('bk.form.noSecrets')}</span>
          ) : (
            <Select
              {...p}
              value={dbt.passwordSecretKey}
              onChange={(e) => onChange({ ...dbt, passwordSecretKey: e.target.value })}
              className="font-mono"
            >
              <option value="">{t('bk.form.secretKeyPick')}</option>
              {keys.map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </Select>
          )
        }
      </Field>
    </div>
  );
}
