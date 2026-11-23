'use client';

import Link from 'next/link';
import { useMemo, useState, type ReactNode } from 'react';
import { useMutation } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import type { ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { toApiError } from '@/lib/api/errors';
import { buildsApi } from '@/lib/api/p4b-endpoints';
import type { SourceInspection } from '@/lib/api/p4b-types';
import { FRAMEWORKS, detectFramework, type Framework } from '@/lib/api/p4-types';
import { useAuth } from '@/lib/auth/auth-provider';
import { evaluateGate } from '@/lib/permissions';
import { commitShaError } from '@/lib/p4b-gates';
import { GatedButton } from '@/components/ui/gated-button';
import {
  hostnameError,
  isEnvKey,
  resolveImage,
  targetBlockReason,
  tlsPathError,
  volumeError,
  type SourceKind,
  type WizardState,
} from '@/lib/p4-gates';
import { envBadgeKey, envLabelKey, statusKey } from '@/lib/servers';
import { cn, uuid } from '@/lib/utils';
import { EnvBadge, STATUS_TONE, ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CopyButton } from '@/components/ui/copy-button';
import { DefList } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Segmented } from '@/components/ui/segmented';
import { ErrorState, Notice } from '@/components/ui/states';
import { ConfidenceBadge } from '@/components/p3/bits';
import { ManagedRoutingPanel } from './managed-routing';
import { ComposeSourceForm } from './compose-source';
import { GitSourceForm } from './git-source';
import { SecretInput } from './secret-input';
import type { MessageKey } from '@/i18n/en';

export type Patch = (fn: (w: WizardState) => WizardState) => void;

const textarea =
  'w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg placeholder:text-fg-subtle';

function SubTitle({ children }: { children: ReactNode }) {
  return <h3 className="m-0 text-[14px] font-semibold">{children}</h3>;
}

// ---------------------------------------------------------------- Source

const SOURCES: Array<{
  kind: SourceKind;
  glyph: string;
  tag: MessageKey;
  tone: 'ok' | 'crit' | 'info';
}> = [
  { kind: 'registry', glyph: '◉', tag: 'wiz.src.tag.supported', tone: 'ok' },
  { kind: 'git', glyph: '⎇', tag: 'wiz.src.tag.build', tone: 'ok' },
  { kind: 'compose', glyph: '▤', tag: 'wiz.src.tag.supported', tone: 'ok' },
  { kind: 'github', glyph: '◇', tag: 'wiz.src.tag.blocked', tone: 'crit' },
];

/** Which source kinds a wizard may use (existing apps keep their kind). */
function kindAllowed(w: WizardState, app: Application | null, kind: SourceKind) {
  if (w.mode !== 'existing') return true;
  if (app?.kind === 'compose') return kind === 'compose';
  return kind === 'registry' || kind === 'git';
}

export function SourceStep({
  w,
  patch,
  environment,
  servers,
  app,
  gitToken,
  setSecrets,
  secretValues,
}: {
  w: WizardState;
  patch: Patch;
  environment?: string;
  servers: Server[];
  app: Application | null;
  gitToken: { current: string | null };
  setSecrets: readonly string[];
  secretValues: Map<string, string>;
}) {
  const { t } = useI18n();
  const res = resolveImage(w.source.repo, w.source.ref, w.source.digestRef);
  return (
    <div className="flex flex-col gap-4">
      <div
        role="radiogroup"
        aria-label={t('wiz.src.kind')}
        className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,190px),1fr))] gap-2.5"
      >
        {SOURCES.map((s) => {
          const on = w.source.kind === s.kind;
          return (
            <label
              key={s.kind}
              className={cn(
                'flex cursor-pointer flex-col gap-1 rounded-md border p-3 text-[13px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent-strong',
                on
                  ? 'border-accent-strong bg-info-bg'
                  : 'border-line bg-surface hover:bg-surface-hover',
              )}
            >
              <input
                type="radio"
                name="source-kind"
                value={s.kind}
                checked={on}
                disabled={!kindAllowed(w, app, s.kind)}
                onChange={() => patch((x) => ({ ...x, source: { ...x.source, kind: s.kind } }))}
                className="sr-only"
              />
              <span className="flex items-center gap-2">
                <b>
                  <span aria-hidden="true">{s.glyph} </span>
                  {t(`wiz.src.${s.kind}` as MessageKey)}
                </b>
                <ToneBadge tone={s.tone} size="sm" glyph={false}>
                  {t(s.tag)}
                </ToneBadge>
              </span>
              <span className="text-fg-muted">{t(`wiz.src.${s.kind}.desc` as MessageKey)}</span>
            </label>
          );
        })}
      </div>

      {w.source.kind === 'registry' && (
        <div className="flex flex-col gap-3">
          <div className="grid gap-3 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <Field label={t('wiz.src.repo')} hint={t('wiz.src.repoHint')}>
              {(p) => (
                <Input
                  {...p}
                  value={w.source.repo}
                  onChange={(e) =>
                    patch((x) => ({ ...x, source: { ...x.source, repo: e.target.value.trim() } }))
                  }
                  placeholder="registry.example.lab/w3/shop-api"
                  className="font-mono text-[13px]"
                  spellCheck={false}
                />
              )}
            </Field>
            <Field label={t('wiz.src.ref')} hint={t('wiz.src.refHint')}>
              {(p) => (
                <Input
                  {...p}
                  value={w.source.ref}
                  onChange={(e) =>
                    patch((x) => ({ ...x, source: { ...x.source, ref: e.target.value.trim() } }))
                  }
                  placeholder="sha256:… or v1.4.2"
                  className="font-mono text-[13px]"
                  spellCheck={false}
                />
              )}
            </Field>
          </div>
          {res.kind === 'invalid' && (
            <Notice tone="crit" glyph="✕" role="alert">
              {t(res.reason)}
            </Notice>
          )}
          {res.kind === 'pinned' && (
            <Notice tone="ok" glyph="●" role="status" title={t('wiz.src.pinned')}>
              <span className="font-mono text-[12.5px] break-all" data-testid="resolved-image">
                {res.ref}
              </span>
            </Notice>
          )}
          {res.kind === 'tag' && (
            <div
              className="flex flex-col gap-2 rounded-md border border-line p-3"
              data-testid="tag-resolution"
            >
              <Notice
                tone="warn"
                glyph="▲"
                role="status"
                title={t('wiz.src.tagTitle', { tag: res.tagRef })}
              >
                {t('wiz.src.tagBody')}
              </Notice>
              <div className="flex flex-wrap items-center gap-2">
                <code className="rounded bg-chip px-2 py-1 font-mono text-[12px]">
                  docker buildx imagetools inspect {res.tagRef} --format{' '}
                  {'"{{json .Manifest.Digest}}"'}
                </code>
                <CopyButton
                  text={`docker buildx imagetools inspect ${res.tagRef} --format '{{json .Manifest.Digest}}'`}
                />
              </div>
              <Field
                label={t('wiz.src.digestRef')}
                hint={t('wiz.src.digestRefHint', {
                  repo: res.tagRef.slice(0, res.tagRef.lastIndexOf(':')),
                })}
                error={res.pasted && !res.pastedValid ? t('wiz.src.err.pasted') : undefined}
              >
                {(p) => (
                  <Input
                    {...p}
                    value={w.source.digestRef}
                    onChange={(e) =>
                      patch((x) => ({
                        ...x,
                        source: { ...x.source, digestRef: e.target.value.trim() },
                      }))
                    }
                    placeholder={`${res.tagRef.slice(0, res.tagRef.lastIndexOf(':'))}@sha256:…`}
                    className="font-mono text-[13px]"
                    spellCheck={false}
                  />
                )}
              </Field>
            </div>
          )}
        </div>
      )}

      {w.source.kind === 'github' && (
        <Notice tone="crit" glyph="✕" role="note" title={t('wiz.src.github.blockedTitle')}>
          <span className="block">{t('wiz.src.github.blockedBody')}</span>
          <Link href="/settings/integrations" className="mt-1 inline-block">
            {t('wiz.src.github.toIntegrations')} →
          </Link>
        </Notice>
      )}

      {w.source.kind === 'compose' && (
        <ComposeSourceForm
          w={w}
          patch={patch}
          environment={environment}
          app={app}
          setSecrets={setSecrets}
          secretValues={secretValues}
        />
      )}

      {w.source.kind === 'git' && (
        <GitSourceForm w={w} patch={patch} servers={servers} app={app} gitToken={gitToken} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Detect

const DETECT_FILES = ['package.json', 'composer.json', 'Dockerfile'] as const;

export function DetectStep({
  w,
  patch,
  app,
}: {
  w: WizardState;
  patch: Patch;
  app: Application | null;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const [files, setFiles] = useState<Record<string, string>>({});
  const inspect = useMutation<SourceInspection, ApiError>({
    mutationFn: async () => {
      try {
        return await buildsApi.inspect(w.appId!, w.git.commitSha.trim());
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: (r) => {
      if (r.status === 'succeeded') setFiles((f) => ({ ...f, ...r.files }));
    },
  });
  const isGit = w.source.kind === 'git';
  const inspectGate = evaluateGate({
    permissions: me?.permissions,
    perm: 'apps.deploy',
    action: 'inspect_source',
    allowedActions: app?.allowedActions,
    blockedReason: !w.appId
      ? { key: 'wiz.det.inspect.afterCreate' }
      : !app?.build?.config
        ? { key: 'wiz.det.inspect.noConfig' }
        : commitShaError(w.git.commitSha)
          ? { key: 'wiz.det.inspect.needSha' }
          : undefined,
  });
  const [active, setActive] = useState<(typeof DETECT_FILES)[number]>('package.json');
  const present = useMemo(
    () => Object.fromEntries(Object.entries(files).filter(([, v]) => v.trim().length > 0)),
    [files],
  );
  const result = useMemo(
    () => (Object.keys(present).length ? detectFramework(present) : null),
    [present],
  );
  const effective: Framework | null = w.detect.override || result?.framework || null;

  async function onUpload(list: FileList | null) {
    if (!list) return;
    const next = { ...files };
    for (const f of Array.from(list)) {
      if (f.size > 64 * 1024) continue;
      const name =
        f.name === 'docker-compose.yml' ||
        f.name === 'artisan' ||
        DETECT_FILES.includes(f.name as never)
          ? f.name
          : null;
      if (name) next[name] = await f.text();
    }
    setFiles(next);
  }

  return (
    <div className="flex flex-col gap-4">
      {isGit && (
        <section
          className="flex flex-col gap-2 rounded-md border border-line p-3"
          data-testid="inspect-source"
          aria-labelledby="inspect-title"
        >
          <div className="flex flex-wrap items-center gap-2">
            <h3 id="inspect-title" className="m-0 flex-1 text-[14px] font-semibold">
              {t('wiz.det.inspect.title')}
            </h3>
            <GatedButton
              size="sm"
              variant="primary"
              perm="apps.deploy"
              blockedReason={inspectGate.allowed ? undefined : inspectGate.reason}
              disabled={inspect.isPending}
              onClick={() => inspect.mutate()}
              data-testid="inspect-button"
            >
              {inspect.isPending ? t('wiz.det.inspect.running') : t('wiz.det.inspect.button')}
            </GatedButton>
          </div>
          <p className="m-0 text-[12.5px] text-fg-muted">
            {t('wiz.det.inspect.body', { sha: w.git.commitSha.slice(0, 12) || '—' })}
          </p>
          {inspect.error && <ErrorState error={inspect.error} />}
          {inspect.data && inspect.data.status !== 'succeeded' && (
            <Notice
              tone={inspect.data.status === 'failed' ? 'crit' : 'warn'}
              glyph="▲"
              role="alert"
            >
              {inspect.data.error
                ? `${inspect.data.error.code}: ${inspect.data.error.message}`
                : t('wiz.det.inspect.timeout')}
            </Notice>
          )}
          {inspect.data?.status === 'succeeded' && inspect.data.detection && (
            <div className="flex flex-col gap-1.5" data-testid="inspect-result">
              <div className="flex flex-wrap items-center gap-2 text-[13px]">
                <span>{t('wiz.det.inspect.server')}</span>
                <b data-testid="inspected-framework">
                  {t(`fw.${inspect.data.detection.framework}` as MessageKey)}
                </b>
                <ConfidenceBadge c={inspect.data.detection.confidence} />
              </div>
              <span className="text-[12.5px] text-fg-muted">{t('wiz.det.inspect.files')}</span>
              <ul
                className="m-0 flex list-none flex-wrap gap-1.5 p-0"
                data-testid="inspected-files"
              >
                {Object.keys(inspect.data.files).map((f) => (
                  <li key={f} className="rounded bg-chip px-2 py-0.5 font-mono text-[12px]">
                    {f}
                  </li>
                ))}
              </ul>
              {inspect.data.detection.evidence.length > 0 && (
                <ul className="m-0 flex flex-col gap-0.5 pl-5 text-[12.5px]">
                  {inspect.data.detection.evidence.map((e) => (
                    <li key={e} className="font-mono">
                      {e}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>
      )}
      <Notice tone="neutral" role="note">
        {isGit ? t('wiz.det.optionalGit') : t('wiz.det.optional')}
      </Notice>
      <div className="flex flex-wrap items-center gap-2">
        <Segmented
          label={t('wiz.det.file')}
          value={active}
          onChange={setActive}
          options={DETECT_FILES.map((f) => ({
            value: f,
            label: f,
            count: files[f]?.trim() ? '●' : undefined,
          }))}
          mono
        />
        <label className="inline-flex min-h-8 cursor-pointer items-center rounded-md border border-line-strong bg-surface px-3 text-[12.5px] hover:bg-surface-hover">
          {t('wiz.det.upload')}
          <input
            type="file"
            multiple
            className="sr-only"
            onChange={(e) => void onUpload(e.target.files)}
          />
        </label>
      </div>
      <Field label={t('wiz.det.paste', { file: active })}>
        {(p) => (
          <textarea
            {...p}
            rows={8}
            value={files[active] ?? ''}
            onChange={(e) => setFiles((f) => ({ ...f, [active]: e.target.value }))}
            spellCheck={false}
            className={textarea}
            placeholder={
              active === 'package.json' ? '{ "dependencies": { "next": "15.0.0" } }' : ''
            }
          />
        )}
      </Field>
      <div
        className="flex flex-col gap-2 rounded-md border border-line p-3"
        data-testid="detect-result"
      >
        <SubTitle>{t('wiz.det.result')}</SubTitle>
        {!result ? (
          <p className="m-0 text-[13px] text-fg-muted">{t('wiz.det.none')}</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <b className="text-[15px]" data-testid="detected-framework">
                {t(`fw.${result.framework}` as MessageKey)}
              </b>
              <ConfidenceBadge c={result.confidence} />
            </div>
            {result.evidence.length > 0 && (
              <ul className="m-0 flex flex-col gap-0.5 pl-5 text-[12.5px]">
                {result.evidence.map((e) => (
                  <li key={e} className="font-mono">
                    {e}
                  </li>
                ))}
              </ul>
            )}
            <DefList
              keyWidth={150}
              rows={[
                [
                  t('wiz.det.port'),
                  result.suggested.containerPort ?? t('common.dash'),
                  { mono: true },
                ],
                [t('wiz.det.health'), result.suggested.healthcheckPath, { mono: true }],
                [
                  t('wiz.det.build'),
                  t(`wiz.det.build.${result.suggested.buildMethod}` as MessageKey),
                ],
              ]}
            />
            {w.mode === 'new' && (
              <div>
                <Button
                  size="sm"
                  onClick={() =>
                    patch((x) => ({
                      ...x,
                      config: {
                        ...x.config,
                        containerPort: result.suggested.containerPort
                          ? String(result.suggested.containerPort)
                          : x.config.containerPort,
                        hcPath: result.suggested.healthcheckPath || x.config.hcPath,
                      },
                    }))
                  }
                >
                  {t('wiz.det.apply')}
                </Button>
              </div>
            )}
            {result.suggested.buildMethod !== 'none' && (
              <p className="m-0 text-[12px] text-fg-muted">{t('wiz.det.buildNote')}</p>
            )}
          </>
        )}
      </div>
      <Field
        label={t('wiz.det.override')}
        hint={t('wiz.det.overrideHint')}
        className="max-w-[320px]"
      >
        {(p) => (
          <Select
            {...p}
            value={w.detect.override}
            onChange={(e) =>
              patch((x) => ({
                ...x,
                detect: { ...x.detect, override: e.target.value as Framework | '' },
              }))
            }
          >
            <option value="">{t('wiz.det.auto')}</option>
            {FRAMEWORKS.map((f) => (
              <option key={f} value={f}>
                {t(`fw.${f}` as MessageKey)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {effective && (
        <p className="m-0 text-[12.5px] text-fg-muted" data-testid="effective-framework">
          {t('wiz.det.effective', { fw: t(`fw.${effective}` as MessageKey) })}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Target

export function TargetStep({
  w,
  patch,
  servers,
  app,
}: {
  w: WizardState;
  patch: Patch;
  servers: Server[];
  app: Application | null;
}) {
  const { t } = useI18n();
  const [env, setEnv] = useState<'all' | Server['environment']>('all');
  const selected = servers.find((s) => s.id === w.target.serverId) ?? null;
  if (w.mode === 'existing') {
    return (
      <div className="flex flex-col gap-3">
        <Notice tone="neutral" role="note">
          {t('wiz.tgt.fixed', { app: app?.name ?? '' })}
        </Notice>
        {selected && <ServerRow s={selected} checked disabled={false} onSelect={() => {}} />}
        {selected && <ManagedRoutingPanel server={selected} />}
      </div>
    );
  }
  const list = servers.filter(
    (s) => s.status !== 'revoked' && (env === 'all' || s.environment === env),
  );
  return (
    <div className="flex flex-col gap-3">
      <Segmented
        label={t('wiz.tgt.env')}
        value={env}
        onChange={setEnv}
        options={[
          { value: 'all', label: t('common.all') },
          { value: 'production', label: t(envLabelKey('production')) },
          { value: 'uat', label: t(envLabelKey('uat')) },
          { value: 'development', label: t(envLabelKey('development')) },
        ]}
      />
      <div role="radiogroup" aria-label={t('wiz.tgt.server')} className="flex flex-col gap-1.5">
        {list.map((s) => (
          <ServerRow
            key={s.id}
            s={s}
            checked={s.id === w.target.serverId}
            disabled={!!targetBlockReason(s)}
            onSelect={() => patch((x) => ({ ...x, target: { serverId: s.id } }))}
          />
        ))}
      </div>
      {selected && (
        <div className="flex flex-col gap-2 rounded-md border border-line p-3">
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <b className="font-mono">{selected.name}</b>
            <EnvBadge env={selected.environment} label={t(envBadgeKey(selected.environment))} />
            <span className="text-fg-muted">{t('wiz.tgt.envFromServer')}</span>
          </div>
          <ManagedRoutingPanel server={selected} />
          <p className="m-0 text-[12px] text-fg-muted">{t('wiz.tgt.limits')}</p>
        </div>
      )}
    </div>
  );
}

function ServerRow({
  s,
  checked,
  disabled,
  onSelect,
}: {
  s: Server;
  checked: boolean;
  disabled: boolean;
  onSelect: () => void;
}) {
  const { t } = useI18n();
  const reason = targetBlockReason(s);
  return (
    <label
      data-testid="target-server"
      data-server={s.name}
      className={cn(
        'flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border px-3 py-2 text-[13px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent-strong',
        checked ? 'border-accent-strong bg-info-bg' : 'border-line bg-surface',
        disabled ? 'cursor-not-allowed opacity-70' : 'cursor-pointer hover:bg-surface-hover',
      )}
    >
      <input
        type="radio"
        name="target-server"
        checked={checked}
        disabled={disabled}
        onChange={onSelect}
        aria-describedby={reason ? `reason-${s.id}` : undefined}
        aria-label={s.name}
      />
      <b className="font-mono">{s.name}</b>
      <EnvBadge
        env={s.environment}
        label={t(envBadgeKey(s.environment))}
        className="px-1.5 text-[10.5px]"
      />
      <ToneBadge tone={STATUS_TONE[s.status]} size="sm">
        {t(statusKey(s.status))}
      </ToneBadge>
      <span className="font-mono text-[12px] text-fg-muted">
        {(s.capabilities ?? []).join(' · ')}
        {s.metrics ? ` · ${t('wiz.tgt.disk', { pct: s.metrics.diskPct ?? '?' })}` : ''}
      </span>
      {reason && (
        <span id={`reason-${s.id}`} className="basis-full pl-6 text-[12px] text-fg-muted">
          {t(reason)}
        </span>
      )}
    </label>
  );
}

// ---------------------------------------------------------------- Configure

export function ConfigureStep({
  w,
  patch,
  app,
  secretValues,
  registryPassword,
}: {
  w: WizardState;
  patch: Patch;
  app: Application | null;
  secretValues: Map<string, string>;
  registryPassword: { current: string | null };
}) {
  const { t } = useI18n();
  const c = w.config;
  const set = (k: keyof WizardState['config'], v: string) =>
    patch((x) => ({ ...x, config: { ...x.config, [k]: v } }));

  if (w.mode === 'existing' && app?.kind === 'compose') {
    return (
      <Notice tone="neutral" role="note">
        {t('wiz.cfg.existingCompose')}{' '}
        <Link href={`/applications/${app.id}/compose`}>{t('wiz.cfg.toCompose')} →</Link>
      </Notice>
    );
  }

  if (w.mode !== 'existing' && w.source.kind === 'compose') {
    return (
      <div className="flex flex-col gap-3">
        <Field
          label={t('wiz.cfg.name')}
          hint={t('wiz.cfg.nameHint')}
          error={
            c.name && !/^[a-z0-9][a-z0-9-]{0,40}$/.test(c.name)
              ? t('wiz.cfg.issue.name')
              : undefined
          }
          className="max-w-[360px]"
        >
          {(p) => (
            <Input
              {...p}
              value={c.name}
              onChange={(e) => set('name', e.target.value.trim())}
              placeholder="crm-suite"
              className="font-mono"
            />
          )}
        </Field>
        <Notice tone="neutral" role="note">
          {t('wiz.cfg.composeNote')}
        </Notice>
      </div>
    );
  }

  if (w.mode === 'existing') {
    const spec = app?.container;
    return (
      <div className="flex flex-col gap-3">
        <Notice tone="neutral" role="note">
          {t('wiz.cfg.existing')}{' '}
          {app && <Link href={`/applications/${app.id}/env`}>{t('wiz.cfg.toEnv')} →</Link>}
        </Notice>
        {spec && (
          <DefList
            keyWidth={160}
            rows={[
              [t('wiz.cfg.port'), String(spec.containerPort), { mono: true }],
              [
                t('wiz.cfg.health'),
                `GET ${spec.healthcheck.path} → ${spec.healthcheck.expectStatus.join('/')}`,
                { mono: true },
              ],
              [
                t('wiz.cfg.resources'),
                `${spec.resources.memoryMb} MiB · ${spec.resources.cpus} vCPU`,
                { mono: true },
              ],
              [
                t('wiz.cfg.env'),
                Object.keys(spec.env).join(', ') || t('common.none'),
                { mono: true },
              ],
              [
                t('wiz.cfg.secrets'),
                spec.secretKeys.join(', ') || t('common.none'),
                { mono: true },
              ],
              [
                t('wiz.cfg.volumes'),
                spec.volumes.map((v) => `${v.name}:${v.mountPath}`).join(', ') || t('common.none'),
                { mono: true },
              ],
            ]}
          />
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field
          label={t('wiz.cfg.name')}
          hint={t('wiz.cfg.nameHint')}
          error={
            c.name && !/^[a-z0-9][a-z0-9-]{0,40}$/.test(c.name)
              ? t('wiz.cfg.issue.name')
              : undefined
          }
        >
          {(p) => (
            <Input
              {...p}
              value={c.name}
              onChange={(e) => set('name', e.target.value.trim())}
              placeholder="shop-web"
              className="font-mono"
            />
          )}
        </Field>
        <Field label={t('wiz.cfg.port')} hint={t('wiz.cfg.portHint')}>
          {(p) => (
            <Input
              {...p}
              inputMode="numeric"
              value={c.containerPort}
              onChange={(e) => set('containerPort', e.target.value.replace(/\D/g, ''))}
              className="font-mono"
            />
          )}
        </Field>
      </section>

      <section className="flex flex-col gap-2">
        <SubTitle>{t('wiz.cfg.health')}</SubTitle>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label={t('wiz.cfg.hcPath')}>
            {(p) => (
              <Input
                {...p}
                value={c.hcPath}
                onChange={(e) => set('hcPath', e.target.value.trim())}
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.cfg.hcStatus')}>
            {(p) => (
              <Input
                {...p}
                inputMode="numeric"
                value={c.hcStatus}
                onChange={(e) => set('hcStatus', e.target.value.replace(/\D/g, ''))}
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.cfg.hcTimeout')}>
            {(p) => (
              <Input
                {...p}
                inputMode="numeric"
                value={c.hcTimeoutSec}
                onChange={(e) => set('hcTimeoutSec', e.target.value.replace(/\D/g, ''))}
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.cfg.hcStart')}>
            {(p) => (
              <Input
                {...p}
                inputMode="numeric"
                value={c.hcStartPeriodSec}
                onChange={(e) => set('hcStartPeriodSec', e.target.value.replace(/\D/g, ''))}
                className="font-mono"
              />
            )}
          </Field>
        </div>
      </section>

      <section className="flex flex-col gap-2">
        <SubTitle>{t('wiz.cfg.resources')}</SubTitle>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label={t('wiz.cfg.memory')}>
            {(p) => (
              <Input
                {...p}
                inputMode="numeric"
                value={c.memoryMb}
                onChange={(e) => set('memoryMb', e.target.value.replace(/\D/g, ''))}
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.cfg.cpus')}>
            {(p) => (
              <Input
                {...p}
                inputMode="decimal"
                value={c.cpus}
                onChange={(e) => set('cpus', e.target.value.replace(/[^\d.]/g, ''))}
                className="font-mono"
              />
            )}
          </Field>
        </div>
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.cfg.hardening')}</p>
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="env-title">
        <h3 id="env-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.cfg.env')}
        </h3>
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.cfg.envHint')}</p>
        {c.env.map((row) => (
          <div key={row.id} className="flex flex-wrap items-start gap-2" data-testid="env-row">
            <Input
              aria-label={t('wiz.cfg.envKey')}
              value={row.key}
              aria-invalid={row.key && !isEnvKey(row.key) ? true : undefined}
              onChange={(e) =>
                patch((x) => ({
                  ...x,
                  config: {
                    ...x.config,
                    env: x.config.env.map((r) =>
                      r.id === row.id ? { ...r, key: e.target.value.toUpperCase() } : r,
                    ),
                  },
                }))
              }
              placeholder="LOG_LEVEL"
              className="w-[220px] font-mono text-[13px]"
            />
            <Input
              aria-label={t('wiz.cfg.envValue', { key: row.key || '…' })}
              value={row.value}
              onChange={(e) =>
                patch((x) => ({
                  ...x,
                  config: {
                    ...x.config,
                    env: x.config.env.map((r) =>
                      r.id === row.id ? { ...r, value: e.target.value } : r,
                    ),
                  },
                }))
              }
              className="min-w-[200px] flex-1 font-mono text-[13px]"
            />
            <Button
              size="sm"
              variant="ghost"
              aria-label={t('wiz.cfg.remove', { key: row.key || '…' })}
              onClick={() =>
                patch((x) => ({
                  ...x,
                  config: { ...x.config, env: x.config.env.filter((r) => r.id !== row.id) },
                }))
              }
            >
              ✕
            </Button>
          </div>
        ))}
        <div>
          <Button
            size="sm"
            onClick={() =>
              patch((x) => ({
                ...x,
                config: { ...x.config, env: [...x.config.env, { id: uuid(), key: '', value: '' }] },
              }))
            }
          >
            + {t('wiz.cfg.addEnv')}
          </Button>
        </div>
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="sec-title">
        <h3 id="sec-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.cfg.secrets')}
        </h3>
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.cfg.secretsHint')}</p>
        {c.secrets.map((row) => (
          <div
            key={row.id}
            className="flex flex-col gap-1.5 rounded-md border border-line p-2.5"
            data-testid="secret-row"
          >
            <div className="flex flex-wrap items-center gap-2">
              <Input
                aria-label={t('wiz.cfg.secretKey')}
                value={row.key}
                disabled={row.staged}
                aria-invalid={row.key && !isEnvKey(row.key) ? true : undefined}
                onChange={(e) =>
                  patch((x) => ({
                    ...x,
                    config: {
                      ...x.config,
                      secrets: x.config.secrets.map((r) =>
                        r.id === row.id ? { ...r, key: e.target.value.toUpperCase() } : r,
                      ),
                    },
                  }))
                }
                placeholder="STRIPE_SECRET_KEY"
                className="w-[240px] font-mono text-[13px]"
              />
              <Button
                size="sm"
                variant="ghost"
                aria-label={t('wiz.cfg.remove', { key: row.key || '…' })}
                onClick={() => {
                  secretValues.delete(row.id);
                  patch((x) => ({
                    ...x,
                    config: {
                      ...x.config,
                      secrets: x.config.secrets.filter((r) => r.id !== row.id),
                    },
                  }));
                }}
              >
                ✕
              </Button>
            </div>
            {isEnvKey(row.key) && (
              <SecretInput
                secretKey={row.key}
                status={{ set: false, staged: row.staged }}
                submitLabel={row.staged ? t('secret.replace') : t('wiz.cfg.stage')}
                onSubmit={(value) => {
                  // Held outside React state until the application exists, then written and dropped.
                  secretValues.set(row.id, value);
                  patch((x) => ({
                    ...x,
                    config: {
                      ...x.config,
                      secrets: x.config.secrets.map((r) =>
                        r.id === row.id ? { ...r, staged: true } : r,
                      ),
                    },
                  }));
                }}
              />
            )}
          </div>
        ))}
        <div>
          <Button
            size="sm"
            onClick={() =>
              patch((x) => ({
                ...x,
                config: {
                  ...x.config,
                  secrets: [...x.config.secrets, { id: uuid(), key: '', staged: false }],
                },
              }))
            }
          >
            + {t('wiz.cfg.addSecret')}
          </Button>
        </div>
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="vol-title">
        <h3 id="vol-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.cfg.volumes')}
        </h3>
        <Notice tone="neutral" role="note">
          {t('wiz.cfg.volHint')}
        </Notice>
        {c.volumes.map((v) => {
          const err = (v.name || v.mountPath) && volumeError(v);
          return (
            <div key={v.id} className="flex flex-col gap-1" data-testid="volume-row">
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  aria-label={t('wiz.cfg.volName')}
                  value={v.name}
                  aria-invalid={err ? true : undefined}
                  onChange={(e) =>
                    patch((x) => ({
                      ...x,
                      config: {
                        ...x.config,
                        volumes: x.config.volumes.map((r) =>
                          r.id === v.id ? { ...r, name: e.target.value } : r,
                        ),
                      },
                    }))
                  }
                  placeholder="uploads"
                  className="w-[200px] font-mono text-[13px]"
                />
                <span aria-hidden="true" className="text-fg-muted">
                  →
                </span>
                <Input
                  aria-label={t('wiz.cfg.volMount')}
                  value={v.mountPath}
                  aria-invalid={err ? true : undefined}
                  onChange={(e) =>
                    patch((x) => ({
                      ...x,
                      config: {
                        ...x.config,
                        volumes: x.config.volumes.map((r) =>
                          r.id === v.id ? { ...r, mountPath: e.target.value } : r,
                        ),
                      },
                    }))
                  }
                  placeholder="/app/uploads"
                  className="min-w-[200px] flex-1 font-mono text-[13px]"
                />
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={t('wiz.cfg.remove', { key: v.name || '…' })}
                  onClick={() =>
                    patch((x) => ({
                      ...x,
                      config: {
                        ...x.config,
                        volumes: x.config.volumes.filter((r) => r.id !== v.id),
                      },
                    }))
                  }
                >
                  ✕
                </Button>
              </div>
              {err && (
                <span role="alert" className="text-[12px] text-crit">
                  {t(err)}
                </span>
              )}
            </div>
          );
        })}
        <div>
          <Button
            size="sm"
            onClick={() =>
              patch((x) => ({
                ...x,
                config: {
                  ...x.config,
                  volumes: [...x.config.volumes, { id: uuid(), name: '', mountPath: '' }],
                },
              }))
            }
          >
            + {t('wiz.cfg.addVolume')}
          </Button>
        </div>
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="reg-title">
        <h3 id="reg-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.cfg.registry')}{' '}
          <span className="text-[12px] font-normal text-fg-muted">({t('common.optional')})</span>
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('wiz.cfg.regServer')}>
            {(p) => (
              <Input
                {...p}
                value={c.registry.serveraddress}
                onChange={(e) =>
                  patch((x) => ({
                    ...x,
                    config: {
                      ...x.config,
                      registry: { ...x.config.registry, serveraddress: e.target.value.trim() },
                    },
                  }))
                }
                placeholder="registry.example.lab"
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.cfg.regUser')}>
            {(p) => (
              <Input
                {...p}
                value={c.registry.username}
                autoComplete="off"
                onChange={(e) =>
                  patch((x) => ({
                    ...x,
                    config: {
                      ...x.config,
                      registry: { ...x.config.registry, username: e.target.value.trim() },
                    },
                  }))
                }
                className="font-mono"
              />
            )}
          </Field>
        </div>
        <SecretInput
          secretKey="registry-password"
          label={t('wiz.cfg.regPassword')}
          status={{ set: false, staged: c.registry.passwordStaged }}
          submitLabel={c.registry.passwordStaged ? t('secret.replace') : t('wiz.cfg.stage')}
          onSubmit={(value) => {
            registryPassword.current = value;
            patch((x) => ({
              ...x,
              config: { ...x.config, registry: { ...x.config.registry, passwordStaged: true } },
            }));
          }}
        />
      </section>
    </div>
  );
}

// ---------------------------------------------------------------- Domain

export function DomainStep({
  w,
  patch,
  inventory,
  app,
}: {
  w: WizardState;
  patch: Patch;
  inventory: Application[] | undefined;
  app: Application | null;
}) {
  const { t } = useI18n();
  if (w.mode === 'existing') {
    return (
      <div className="flex flex-col gap-3">
        <Notice tone="neutral" role="note">
          {t('wiz.dom.existing')}
        </Notice>
        <DefList
          keyWidth={140}
          rows={[
            [t('wiz.dom.domains'), (app?.domains ?? []).join(', '), { mono: true }],
            [
              t('wiz.dom.tls'),
              app?.container?.tls ? `${app.container.tls.certPath}` : t('wiz.dom.tls.http'),
              { mono: true },
            ],
          ]}
        />
      </div>
    );
  }
  const d = w.domain;
  const setDomains = (fn: (ds: string[]) => string[]) =>
    patch((x) => ({ ...x, domain: { ...x.domain, domains: fn(x.domain.domains) } }));
  return (
    <div className="flex flex-col gap-4">
      <section className="flex flex-col gap-2">
        <SubTitle>{t('wiz.dom.domains')}</SubTitle>
        {d.domains.map((dom, i) => {
          const err = dom.trim() ? hostnameError(dom) : null;
          const owners =
            !err && dom.trim()
              ? (inventory ?? []).filter((a) => a.domains.includes(dom.trim()))
              : [];
          return (
            <div key={i} className="flex flex-col gap-1" data-testid="domain-row">
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  aria-label={t('wiz.dom.hostname', { n: i + 1 })}
                  value={dom}
                  aria-invalid={err ? true : undefined}
                  onChange={(e) =>
                    setDomains((ds) =>
                      ds.map((x, j) => (j === i ? e.target.value.trim().toLowerCase() : x)),
                    )
                  }
                  placeholder="shop.example.com"
                  className="max-w-[420px] font-mono"
                />
                {d.domains.length > 1 && (
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={t('wiz.cfg.remove', { key: dom || '…' })}
                    onClick={() => setDomains((ds) => ds.filter((_, j) => j !== i))}
                  >
                    ✕
                  </Button>
                )}
                {!err &&
                  dom.trim() &&
                  inventory &&
                  (owners.length ? (
                    <ToneBadge tone="crit" size="sm">
                      <span data-testid="domain-conflict">
                        {t('wiz.dom.conflictWith', { app: owners.map((o) => o.name).join(', ') })}
                      </span>
                    </ToneBadge>
                  ) : (
                    <ToneBadge tone="ok" size="sm">
                      {t('wiz.dom.noConflict')}
                    </ToneBadge>
                  ))}
              </div>
              {err && (
                <span role="alert" className="text-[12px] text-crit">
                  {t(err)}
                </span>
              )}
            </div>
          );
        })}
        <div>
          <Button
            size="sm"
            disabled={d.domains.length >= 10}
            onClick={() => setDomains((ds) => [...ds, ''])}
          >
            + {t('wiz.dom.add')}
          </Button>
        </div>
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.dom.precheckNote')}</p>
      </section>

      <section className="flex flex-col gap-2">
        <SubTitle>{t('wiz.dom.tls')}</SubTitle>
        <div
          role="radiogroup"
          aria-label={t('wiz.dom.tls')}
          className="flex flex-col gap-1.5 text-[13px]"
        >
          <label className="flex items-start gap-2">
            <input
              type="radio"
              name="tls"
              checked={d.tls === 'http'}
              onChange={() => patch((x) => ({ ...x, domain: { ...x.domain, tls: 'http' } }))}
              className="mt-1"
            />
            <span>
              <b className="font-medium">{t('wiz.dom.tls.http')}</b>
              <span className="block text-fg-muted">{t('wiz.dom.tls.httpDesc')}</span>
            </span>
          </label>
          <label className="flex items-start gap-2">
            <input
              type="radio"
              name="tls"
              checked={d.tls === 'existing'}
              onChange={() => patch((x) => ({ ...x, domain: { ...x.domain, tls: 'existing' } }))}
              className="mt-1"
            />
            <span>
              <b className="font-medium">{t('wiz.dom.tls.existing')}</b>
              <span className="block text-fg-muted">{t('wiz.dom.tls.existingDesc')}</span>
            </span>
          </label>
          <label
            className="flex cursor-not-allowed items-start gap-2 text-fg-muted"
            aria-describedby="acme-reason"
          >
            <input type="radio" name="tls" disabled className="mt-1" />
            <span>
              <b className="font-medium">{t('wiz.dom.tls.acme')}</b>{' '}
              <ToneBadge tone="crit" size="sm" glyph={false}>
                BLOCKED
              </ToneBadge>
              <span id="acme-reason" className="block">
                {t('wiz.dom.tls.acmeBlocked')}
              </span>
            </span>
          </label>
        </div>
        {d.tls === 'existing' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label={t('wiz.dom.tls.cert')}
              error={
                d.certPath && tlsPathError(d.certPath) ? t(tlsPathError(d.certPath)!) : undefined
              }
            >
              {(p) => (
                <Input
                  {...p}
                  value={d.certPath}
                  onChange={(e) =>
                    patch((x) => ({
                      ...x,
                      domain: { ...x.domain, certPath: e.target.value.trim() },
                    }))
                  }
                  placeholder="/etc/letsencrypt/live/shop.example.com/fullchain.pem"
                  className="font-mono text-[12.5px]"
                />
              )}
            </Field>
            <Field
              label={t('wiz.dom.tls.key')}
              error={d.keyPath && tlsPathError(d.keyPath) ? t(tlsPathError(d.keyPath)!) : undefined}
            >
              {(p) => (
                <Input
                  {...p}
                  value={d.keyPath}
                  onChange={(e) =>
                    patch((x) => ({
                      ...x,
                      domain: { ...x.domain, keyPath: e.target.value.trim() },
                    }))
                  }
                  placeholder="/etc/letsencrypt/live/shop.example.com/privkey.pem"
                  className="font-mono text-[12.5px]"
                />
              )}
            </Field>
          </div>
        )}
      </section>
    </div>
  );
}
