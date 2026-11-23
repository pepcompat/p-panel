'use client';

import { useQueryClient } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { GIT_HOST_ALLOWLIST } from '@/lib/config';
import type { Application } from '@/lib/api/p3-types';
import { buildConfigApi } from '@/lib/api/p4b-endpoints';
import { DOCKERFILE_TEMPLATES, type DockerfileTemplate } from '@/lib/api/p4b-types';
import {
  SECRET_LIKE_RE,
  branchError,
  buildArgIssues,
  buildNodeBlockReason,
  commitShaError,
  dockerfileError,
  gitUrlCheck,
  limitsError,
  pushRepoError,
  subdirError,
  type GitSourceState,
} from '@/lib/p4b-gates';
import type { WizardState } from '@/lib/p4-gates';
import { p4bk, useGitAuth } from '@/lib/p4b-queries';
import { envBadgeKey, statusKey } from '@/lib/servers';
import { cn, uuid } from '@/lib/utils';
import { EnvBadge, STATUS_TONE, ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Field, Input, Select } from '@/components/ui/form';
import { Segmented } from '@/components/ui/segmented';
import { Notice } from '@/components/ui/states';
import { SecretInput } from './secret-input';
import type { MessageKey } from '@/i18n/en';

type Patch = (fn: (w: WizardState) => WizardState) => void;

function Sub({ children }: { children: React.ReactNode }) {
  return <h3 className="m-0 text-[14px] font-semibold">{children}</h3>;
}

/**
 * Git source (§8.1): repo + commit, Dockerfile path XOR built-in template, non-secret build args,
 * build node, push repository, write-only git token, build network and limits.
 */
export function GitSourceForm({
  w,
  patch,
  servers,
  app,
  gitToken,
  settingsMode = false,
}: {
  w: WizardState;
  patch: Patch;
  servers: Server[];
  app: Application | null;
  /** Token typed for a not-yet-created app; written right after creation, then dropped. */
  gitToken: { current: string | null };
  /** Build settings editor: no commit / branch (chosen per build). */
  settingsMode?: boolean;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const g = w.git;
  const set = (p: Partial<GitSourceState>) => patch((x) => ({ ...x, git: { ...x.git, ...p } }));
  const url = gitUrlCheck(g.repoUrl, GIT_HOST_ALLOWLIST);
  const sha = g.commitSha ? commitShaError(g.commitSha) : null;
  const argIssues = buildArgIssues(g.buildArgs);
  const existingApp = w.mode === 'existing' && app ? app : null;
  const gitAuth = useGitAuth(existingApp?.id ?? null, !!existingApp);
  const nodes = servers;
  const lim = limitsError(g);

  return (
    <div className="flex flex-col gap-5" data-testid="git-source">
      {!settingsMode && (
        <Notice tone="info" glyph="◆" role="note" title={t('wiz.git.flowTitle')}>
          {t('wiz.git.flowBody')}
        </Notice>
      )}

      <section className="flex flex-col gap-3">
        <Sub>{t('wiz.git.repoTitle')}</Sub>
        <Field
          label={t('wiz.git.repoUrl')}
          hint={t('wiz.git.repoUrlHint')}
          error={g.repoUrl && url.error ? t(url.error) : undefined}
        >
          {(p) => (
            <Input
              {...p}
              value={g.repoUrl}
              onChange={(e) => set({ repoUrl: e.target.value.trim() })}
              placeholder="https://github.com/w3co/shop-api.git"
              className="font-mono text-[13px]"
              spellCheck={false}
            />
          )}
        </Field>
        {url.host && (
          <p
            className="m-0 flex flex-wrap items-center gap-2 text-[12.5px]"
            data-testid="git-allowlist"
            data-allow={url.allow}
          >
            {url.allow === 'allowed' ? (
              <ToneBadge tone="ok" size="sm">
                {t('wiz.git.allow.allowed', { host: url.host })}
              </ToneBadge>
            ) : url.allow === 'not_listed' ? (
              <ToneBadge tone="warn" size="sm">
                {t('wiz.git.allow.notListed', { host: url.host })}
              </ToneBadge>
            ) : (
              <ToneBadge tone="off" size="sm">
                {t('wiz.git.allow.unknown', { host: url.host })}
              </ToneBadge>
            )}
            <span className="text-fg-muted">{t('wiz.git.allow.note')}</span>
          </p>
        )}
        <div
          className={cn(
            'grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]',
            settingsMode && 'hidden',
          )}
        >
          <Field
            label={t('wiz.git.branch')}
            hint={t('wiz.git.branchHint')}
            error={branchError(g.branch) ? t('wiz.git.err.branch') : undefined}
          >
            {(p) => (
              <Input
                {...p}
                value={g.branch}
                onChange={(e) => set({ branch: e.target.value.trim() })}
                className="font-mono text-[13px]"
                spellCheck={false}
              />
            )}
          </Field>
          <Field
            label={t('wiz.git.sha')}
            hint={t('wiz.git.shaHint')}
            error={sha ? t(sha) : undefined}
          >
            {(p) => (
              <Input
                {...p}
                value={g.commitSha}
                onChange={(e) => set({ commitSha: e.target.value.trim() })}
                placeholder="40 hex, e.g. 3f9c2a…"
                className="font-mono text-[13px]"
                spellCheck={false}
                maxLength={64}
              />
            )}
          </Field>
        </div>
        <Field
          label={t('wiz.git.subdir')}
          hint={t('wiz.git.subdirHint')}
          error={subdirError(g.subdir) ? t('wiz.git.err.subdir') : undefined}
          className="max-w-[420px]"
        >
          {(p) => (
            <Input
              {...p}
              value={g.subdir}
              onChange={(e) => set({ subdir: e.target.value.trim() })}
              placeholder="apps/api"
              className="font-mono text-[13px]"
            />
          )}
        </Field>
      </section>

      <section className="flex flex-col gap-3">
        <Sub>{t('wiz.git.methodTitle')}</Sub>
        <Segmented<GitSourceState['method']>
          label={t('wiz.git.method')}
          value={g.method}
          onChange={(m) => set({ method: m })}
          className="self-start"
          options={[
            { value: 'template', label: t('wiz.git.method.template') },
            { value: 'dockerfile', label: t('wiz.git.method.dockerfile') },
          ]}
        />
        <p className="m-0 text-[12px] text-fg-muted">{t('wiz.git.methodExclusive')}</p>
        {g.method === 'template' ? (
          <Field
            label={t('wiz.git.template')}
            hint={t('wiz.git.templateHint')}
            className="max-w-[320px]"
          >
            {(p) => (
              <Select
                {...p}
                value={g.template}
                onChange={(e) => set({ template: e.target.value as DockerfileTemplate | '' })}
              >
                <option value="">{t('wiz.git.templatePick')}</option>
                {DOCKERFILE_TEMPLATES.map((x) => (
                  <option key={x} value={x}>
                    {t(`build.template.${x}` as MessageKey)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : (
          <Field
            label={t('wiz.git.dockerfile')}
            hint={t('wiz.git.dockerfileHint')}
            error={dockerfileError(g.dockerfile) ? t(dockerfileError(g.dockerfile)!) : undefined}
            className="max-w-[420px]"
          >
            {(p) => (
              <Input
                {...p}
                value={g.dockerfile}
                onChange={(e) => set({ dockerfile: e.target.value.trim() })}
                className="font-mono text-[13px]"
              />
            )}
          </Field>
        )}
        <Field label={t('wiz.git.target')} hint={t('wiz.git.targetHint')} className="max-w-[320px]">
          {(p) => (
            <Input
              {...p}
              value={g.target}
              onChange={(e) => set({ target: e.target.value.trim() })}
              placeholder="runtime"
              className="font-mono text-[13px]"
            />
          )}
        </Field>
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="build-args-title">
        <h3 id="build-args-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.git.args')}
        </h3>
        <Notice tone="warn" glyph="▲" role="note">
          <span data-testid="secret-args-note">{t('wiz.git.argsNoSecrets')}</span>
        </Notice>
        {g.buildArgs.map((r, i) => (
          <div key={r.id} className="flex flex-wrap items-end gap-2" data-testid="build-arg-row">
            <Field
              label={t('wiz.git.argKey', { n: i + 1 })}
              error={SECRET_LIKE_RE.test(r.key) ? t('wiz.git.issue.secretArg') : undefined}
            >
              {(p) => (
                <Input
                  {...p}
                  value={r.key}
                  onChange={(e) =>
                    set({
                      buildArgs: g.buildArgs.map((x) =>
                        x.id === r.id ? { ...x, key: e.target.value.toUpperCase().trim() } : x,
                      ),
                    })
                  }
                  className="w-[220px] font-mono"
                />
              )}
            </Field>
            <Field label={t('wiz.git.argValue', { n: i + 1 })} className="min-w-[220px] flex-1">
              {(p) => (
                <Input
                  {...p}
                  value={r.value}
                  maxLength={1024}
                  onChange={(e) =>
                    set({
                      buildArgs: g.buildArgs.map((x) =>
                        x.id === r.id ? { ...x, value: e.target.value } : x,
                      ),
                    })
                  }
                  className="font-mono"
                />
              )}
            </Field>
            <Button
              size="sm"
              onClick={() => set({ buildArgs: g.buildArgs.filter((x) => x.id !== r.id) })}
              aria-label={t('wiz.git.argRemove', { n: i + 1 })}
            >
              {t('wiz.git.argRemoveShort')}
            </Button>
          </div>
        ))}
        {argIssues.length > 0 && (
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px] text-crit">
            {argIssues.map((k) => (
              <li key={k}>✕ {t(k)}</li>
            ))}
          </ul>
        )}
        <div>
          <Button
            size="sm"
            onClick={() => set({ buildArgs: [...g.buildArgs, { id: uuid(), key: '', value: '' }] })}
          >
            + {t('wiz.git.argAdd')}
          </Button>
        </div>
      </section>

      <section className="flex flex-col gap-2" aria-labelledby="build-node-title">
        <h3 id="build-node-title" className="m-0 text-[14px] font-semibold">
          {t('wiz.git.node')}
        </h3>
        <p className="m-0 text-[12.5px] text-fg-muted">{t('wiz.git.nodeHint')}</p>
        {g.buildServerId && !nodes.some((s) => s.id === g.buildServerId) && (
          <p className="m-0 text-[12.5px]" data-testid="build-node-hidden">
            {t('wiz.git.nodeOutOfScope', { id: g.buildServerId.slice(0, 8) })}
          </p>
        )}
        <div role="radiogroup" aria-label={t('wiz.git.node')} className="flex flex-col gap-1.5">
          {nodes
            .filter((s) => s.status !== 'revoked')
            .map((s) => {
              const reason = buildNodeBlockReason(s);
              const checked = g.buildServerId === s.id;
              return (
                <label
                  key={s.id}
                  data-testid="build-node"
                  data-server={s.name}
                  data-eligible={reason ? 'false' : 'true'}
                  className={cn(
                    'flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border px-3 py-2 text-[13px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent-strong',
                    checked ? 'border-accent-strong bg-info-bg' : 'border-line bg-surface',
                    reason
                      ? 'cursor-not-allowed opacity-70'
                      : 'cursor-pointer hover:bg-surface-hover',
                  )}
                >
                  <input
                    type="radio"
                    name="build-node"
                    checked={checked}
                    disabled={!!reason}
                    onChange={() => set({ buildServerId: s.id })}
                    aria-label={`${t('wiz.git.node')}: ${s.name}`}
                    aria-describedby={reason ? `bn-reason-${s.id}` : undefined}
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
                  {s.buildNode && !reason && (
                    <ToneBadge tone="info" size="sm">
                      {t('bn.badge')}
                    </ToneBadge>
                  )}
                  {reason && (
                    <span
                      id={`bn-reason-${s.id}`}
                      className="basis-full pl-6 text-[12px] text-fg-muted"
                    >
                      {t(reason)}
                    </span>
                  )}
                </label>
              );
            })}
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2">
        <Field
          label={t('wiz.git.push')}
          hint={t('wiz.git.pushHint')}
          error={
            g.pushRepo && pushRepoError(g.pushRepo) ? t(pushRepoError(g.pushRepo)!) : undefined
          }
        >
          {(p) => (
            <Input
              {...p}
              value={g.pushRepo}
              onChange={(e) => set({ pushRepo: e.target.value.trim() })}
              placeholder="registry.example.lab/w3/shop-api"
              className="font-mono text-[13px]"
              spellCheck={false}
            />
          )}
        </Field>
        <div className="flex flex-col gap-1" data-testid="git-token">
          {existingApp ? (
            <SecretInput
              secretKey="git-token"
              label={t('wiz.git.token')}
              status={{ set: !!(gitAuth.data?.set ?? existingApp.build?.config.gitAuth.set) }}
              onSubmit={async (v) => {
                await buildConfigApi.putGitAuth(existingApp.id, v);
                void qc.invalidateQueries({ queryKey: p4bk.gitAuth(existingApp.id) });
              }}
            />
          ) : (
            <SecretInput
              secretKey="git-token"
              label={t('wiz.git.token')}
              status={{ set: false, staged: g.tokenStaged }}
              submitLabel={g.tokenStaged ? t('secret.replace') : t('wiz.cfg.stage')}
              onSubmit={(v) => {
                gitToken.current = v;
                set({ tokenStaged: true });
              }}
            />
          )}
          <span className="text-[11.5px] text-fg-muted">{t('wiz.git.tokenHint')}</span>
        </div>
      </section>

      <section className="flex flex-col gap-2">
        <Sub>{t('wiz.git.sandbox')}</Sub>
        <div className="flex flex-col gap-1">
          <span className="text-[12.5px] text-fg-3">{t('wiz.git.network')}</span>
          <Segmented<GitSourceState['network']>
            label={t('wiz.git.network')}
            value={g.network}
            onChange={(n) => set({ network: n })}
            className="self-start"
            options={[
              { value: 'default', label: t('wiz.git.network.on') },
              { value: 'none', label: t('wiz.git.network.off') },
            ]}
          />
          <span className="text-[12px] text-fg-muted">{t('wiz.git.networkHint')}</span>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t('wiz.git.memory')}>
            {(p) => (
              <Input
                {...p}
                inputMode="numeric"
                value={g.memoryMb}
                onChange={(e) => set({ memoryMb: e.target.value.replace(/\D/g, '') })}
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.git.cpus')}>
            {(p) => (
              <Input
                {...p}
                inputMode="decimal"
                value={g.cpus}
                onChange={(e) => set({ cpus: e.target.value.replace(/[^\d.]/g, '') })}
                className="font-mono"
              />
            )}
          </Field>
          <Field label={t('wiz.git.timeout')}>
            {(p) => (
              <Input
                {...p}
                inputMode="numeric"
                value={g.timeoutSec}
                onChange={(e) => set({ timeoutSec: e.target.value.replace(/\D/g, '') })}
                className="font-mono"
              />
            )}
          </Field>
        </div>
        {lim && <p className="m-0 text-[12.5px] text-crit">✕ {t(lim)}</p>}
      </section>
    </div>
  );
}
