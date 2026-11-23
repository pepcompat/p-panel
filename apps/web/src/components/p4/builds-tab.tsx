'use client';

import Link from 'next/link';
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { GIT_HOST_ALLOWLIST } from '@/lib/config';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { Application } from '@/lib/api/p3-types';
import { buildConfigApi } from '@/lib/api/p4b-endpoints';
import type { BuildConfig } from '@/lib/api/p4b-types';
import { initialWizard, type WizardState } from '@/lib/p4-gates';
import { gitSourceIssues, toBuildConfig, type GitSourceState } from '@/lib/p4b-gates';
import { evaluateGate } from '@/lib/permissions';
import { useBuilds, useGitAuth } from '@/lib/p4b-queries';
import { useServers } from '@/lib/queries';
import { formatDateTime, formatDuration } from '@/lib/time';
import { cn, uuid } from '@/lib/utils';
import { useToast } from '@/components/providers/toast';
import { Card, DefList } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { Sha } from '@/components/p3/bits';
import { ImageRef } from './bits';
import { BuildLog, BuildStatusBadge } from './build-execution';
import { GitSourceForm } from './git-source';
import type { MessageKey } from '@/i18n/en';

function gitFromConfig(c: BuildConfig | null | undefined): GitSourceState {
  const w = initialWizard('existing').git;
  if (!c) return w;
  return {
    ...w,
    repoUrl: c.repoUrl,
    subdir: c.subdir ?? '',
    method: c.dockerfile ? 'dockerfile' : 'template',
    dockerfile: c.dockerfile ?? 'Dockerfile',
    template: (c.template ?? '') as GitSourceState['template'],
    buildArgs: Object.entries(c.buildArgs ?? {}).map(([key, value]) => ({
      id: uuid(),
      key,
      value,
    })),
    target: c.target ?? '',
    buildServerId: c.buildServerId,
    pushRepo: c.pushRepo,
    network: c.network ?? 'default',
    memoryMb: String(c.limits?.memoryMb ?? 2048),
    cpus: String(c.limits?.cpus ?? 2),
    timeoutSec: String(c.limits?.timeoutSec ?? 900),
  };
}

const SETTINGS_IGNORED: readonly MessageKey[] = [
  'wiz.git.issue.sha',
  'wiz.git.err.shaShort',
  'wiz.git.err.shaCase',
  'wiz.git.err.sha',
  'wiz.git.err.branch',
];

/** Build settings (§8.1): view / edit the build config, git token status (write-only). */
export function BuildSettings({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const servers = useServers();
  const cfg = app.build?.config ?? null;
  const gitAuth = useGitAuth(app.id);
  const [editing, setEditing] = useState(false);
  const [w, setW] = useState<WizardState>(() => ({
    ...initialWizard('existing'),
    appId: app.id,
    git: gitFromConfig(cfg),
  }));
  const gitToken = useRef<string | null>(null);
  const serverList = useMemo(() => servers.data?.items ?? [], [servers.data]);
  const issues = gitSourceIssues(w.git, serverList, GIT_HOST_ALLOWLIST, {
    allowUnknownNode: !!cfg && w.git.buildServerId === cfg.buildServerId,
  }).filter((k) => !SETTINGS_IGNORED.includes(k));
  const gate = evaluateGate({
    permissions: me?.permissions,
    perm: 'apps.deploy',
    action: 'manage_build_config',
    allowedActions: app.allowedActions,
  });
  const save = useMutation<BuildConfig, ApiError>({
    mutationFn: async () => {
      try {
        return await buildConfigApi.put(app.id, toBuildConfig(w.git), cfg?.version);
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: () => {
      setEditing(false);
      toast(t('builds.settings.saved'), 'ok');
      void qc.invalidateQueries({ queryKey: ['applications', 'one', app.id], exact: false });
    },
  });
  const node = serverList.find((s) => s.id === cfg?.buildServerId);
  const tokenSet = gitAuth.data?.set ?? cfg?.gitAuth?.set ?? false;

  return (
    <Card className="flex flex-col gap-3 p-4" data-testid="build-settings">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('builds.settings')}</h2>
        {!editing && (
          <GatedButton
            size="sm"
            perm="apps.deploy"
            action="manage_build_config"
            allowedActions={app.allowedActions}
            onClick={() => {
              setW((x) => ({ ...x, git: gitFromConfig(cfg) }));
              setEditing(true);
            }}
            data-testid="build-settings-edit"
          >
            {cfg ? t('builds.settings.edit') : t('builds.settings.configure')}
          </GatedButton>
        )}
      </div>
      {!editing &&
        (cfg ? (
          <DefList
            keyWidth={150}
            rows={[
              [
                t('wiz.git.repoUrl'),
                cfg.repoUrl + (cfg.subdir ? ` · ${cfg.subdir}` : ''),
                { mono: true },
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
              [t('wiz.git.node'), node?.name ?? cfg.buildServerId.slice(0, 8), { mono: true }],
              [t('wiz.git.push'), cfg.pushRepo, { mono: true }],
              [
                t('wiz.git.sandbox'),
                `${cfg.network === 'none' ? t('wiz.git.network.off') : t('wiz.git.network.on')} · ${cfg.limits.memoryMb} MiB · ${cfg.limits.cpus} vCPU · ${cfg.limits.timeoutSec}s`,
              ],
              [
                t('wiz.git.token'),
                <span key="tok" data-testid="git-token-status">
                  {tokenSet ? (
                    <ToneBadge tone="ok" glyph="✓" size="sm">
                      {t('builds.token.set')}
                    </ToneBadge>
                  ) : (
                    <ToneBadge tone="warn" size="sm">
                      {t('builds.token.notSet')}
                    </ToneBadge>
                  )}
                </span>,
              ],
              [
                t('app.updated'),
                cfg.updatedAt ? formatDateTime(cfg.updatedAt, locale) : t('common.dash'),
              ],
            ]}
          />
        ) : (
          <p className="m-0 text-[13px] text-fg-muted">{t('builds.settings.none')}</p>
        ))}
      {!gate.allowed && gate.reason && !editing && (
        <p className="m-0 text-[12px] text-fg-muted">{t(gate.reason.key, gate.reason.vars)}</p>
      )}
      {editing && (
        <div className="flex flex-col gap-3">
          <GitSourceForm
            w={w}
            patch={(fn) => setW((x) => fn(x))}
            servers={serverList}
            app={app}
            gitToken={gitToken}
            settingsMode
          />
          {issues.length > 0 && (
            <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px] text-warn">
              {issues.map((k) => (
                <li key={k}>▲ {t(k)}</li>
              ))}
            </ul>
          )}
          {save.error && <ErrorState error={save.error} />}
          <div className="flex gap-2">
            <Button
              variant="primary"
              disabled={issues.length > 0 || save.isPending}
              onClick={() => save.mutate()}
              data-testid="build-settings-save"
            >
              {save.isPending ? t('common.saving') : t('builds.settings.save')}
            </Button>
            <Button onClick={() => setEditing(false)}>{t('common.cancel')}</Button>
          </div>
        </div>
      )}
    </Card>
  );
}

/** Builds tab: history with commit, method, node, duration, digest, linked deployment and log. */
export function BuildsTab({ app }: { app: Application }) {
  const { t, locale } = useI18n();
  const q = useBuilds(app.id);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => {
    const b = new URLSearchParams(window.location.search).get('build');
    if (b) setOpen(b);
  }, []);
  const cfg = app.build?.config;

  return (
    <div className="flex flex-col gap-4" data-testid="builds-tab">
      <Card className="flex flex-wrap items-center gap-3 p-4">
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <h2 className="m-0 text-[15px] font-semibold">{t('builds.title')}</h2>
          <span className="text-[12.5px] text-fg-muted">
            {cfg ? (
              <>
                <span className="font-mono">{cfg.repoUrl}</span> →{' '}
                <span className="font-mono">{cfg.pushRepo}</span>
              </>
            ) : (
              t('builds.settings.none')
            )}
          </span>
        </div>
        <Link href={`/applications/${app.id}/settings`} className="text-[13px]">
          {t('builds.settings')} →
        </Link>
        <GatedButton
          variant="primary"
          size="sm"
          perm="apps.deploy"
          action="build"
          allowedActions={app.allowedActions}
          blockedReason={cfg ? undefined : { key: 'builds.block.noConfig' }}
          onClick={() => (window.location.href = `/deployments/new?app=${app.id}&source=git`)}
          data-testid="builds-new"
        >
          {t('builds.new')}
        </GatedButton>
      </Card>
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : q.isError && !q.data ? (
        isApiError(q.error) && q.error.status === 403 ? (
          <ForbiddenState perm="apps.read" requestId={q.error.requestId} />
        ) : (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        )
      ) : (q.data?.items ?? []).length === 0 ? (
        <EmptyState title={t('builds.empty')} body={t('builds.emptyBody')} />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line bg-surface">
          <table className="w-full border-collapse text-[13px]" style={{ minWidth: 900 }}>
            <caption className="sr-only">{t('builds.title')}</caption>
            <thead>
              <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
                {(
                  [
                    'status',
                    'commit',
                    'method',
                    'node',
                    'duration',
                    'image',
                    'deployment',
                    'started',
                    'log',
                  ] as const
                ).map((c) => (
                  <th key={c} scope="col" className="px-2 py-2 font-medium first:pl-4 last:pr-4">
                    {t(`builds.col.${c}` as MessageKey)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.data!.items.map((b) => {
                const expanded = open === b.id;
                return (
                  <Fragment key={b.id}>
                    <tr
                      className={cn('border-t border-line-subtle', expanded && 'bg-surface-2')}
                      data-testid="build-row"
                      data-status={b.status}
                    >
                      <td className="px-2 py-2 pl-4">
                        <BuildStatusBadge status={b.status} />
                      </td>
                      <td className="px-2 py-2">
                        <Sha value={b.commitSha} />
                        {b.branch && (
                          <span className="ml-1.5 font-mono text-[11.5px] text-fg-muted">
                            {b.branch}
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-2 text-[12.5px]">
                        {b.template
                          ? t(`build.template.${b.template}` as MessageKey)
                          : (b.dockerfile ?? 'Dockerfile')}
                      </td>
                      <td className="px-2 py-2 font-mono text-[12px]">
                        {b.buildServerName ?? b.buildServerId.slice(0, 8)}
                      </td>
                      <td className="px-2 py-2 font-mono text-[12px]">
                        {b.durationMs != null ? formatDuration(b.durationMs) : t('common.dash')}
                      </td>
                      <td className="px-2 py-2">
                        {b.image ? <ImageRef image={b.image} /> : t('common.dash')}
                      </td>
                      <td className="px-2 py-2">
                        {b.deploymentId ? (
                          <Link href={`/deployments/${b.deploymentId}`} className="font-mono">
                            #{b.deploymentNumber ?? b.deploymentId.slice(0, 8)}
                          </Link>
                        ) : b.deployError ? (
                          <span className="text-[12px] text-warn">{b.deployError.code}</span>
                        ) : b.status === 'failed' ? (
                          <span className="text-[12px] text-fg-muted">
                            {t('builds.noDeployment')}
                          </span>
                        ) : (
                          t('common.dash')
                        )}
                      </td>
                      <td className="px-2 py-2 text-[12px] text-fg-muted">
                        {formatDateTime(b.createdAt, locale)}
                      </td>
                      <td className="px-2 py-2 pr-4">
                        <Button
                          size="sm"
                          aria-expanded={expanded}
                          aria-controls={`build-log-${b.id}`}
                          onClick={() => setOpen(expanded ? null : b.id)}
                        >
                          {expanded ? t('builds.hideLog') : t('builds.showLog')}
                        </Button>
                      </td>
                    </tr>
                    {expanded && (
                      <tr id={`build-log-${b.id}`}>
                        <td colSpan={9} className="px-4 pb-3">
                          {b.status === 'failed' && (
                            <Notice tone="crit" glyph="✕" role="note" className="mb-2">
                              {b.error?.code}: {b.error?.message} —{' '}
                              {t('build.failed.liveUntouched')}
                            </Notice>
                          )}
                          <BuildLog build={b} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
