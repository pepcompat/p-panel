'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { type ApiError } from '@/lib/api/errors';
import { sshEndpointsApi, sshHostKeysApi } from '@/lib/api/p10-endpoints';
import { SSH_USER_RE, type SshEndpoint, type SshHostKey, type SshPath } from '@/lib/api/p10-types';
import { hostKeyState } from '@/lib/p10-gates';
import { p10k, useHostKeys, useSshEndpoints } from '@/lib/p10-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { ActionDialog, wrap } from '@/components/p3/action-dialog';
import { PATH_ORDER, pathKey } from '@/components/p9/net-bits';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { EnvBadge, OutlineTag } from '@/components/ui/badge';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { AgentMatch, Fingerprint, HostKeyStatusBadge, SectionTitle } from './bits';

const MANAGE = 'credentials.manage' as const;

/** Prominent, non-dismissible block: a different host key was presented on connect. */
export function MismatchBanner({
  server,
  path,
  trusted,
  seen,
}: {
  server: string;
  path: SshPath;
  trusted: SshHostKey;
  seen: SshHostKey;
}) {
  const { t, locale } = useI18n();
  return (
    <div
      role="alert"
      data-testid="host-key-mismatch"
      className="flex flex-col gap-2 rounded-lg border-2 border-crit bg-crit-bg p-4 text-[13.5px]"
    >
      <div className="flex items-center gap-2 text-[15px] font-semibold text-crit">
        <span aria-hidden="true">✕</span>
        {t('p10.hk.mismatch.title', { server, path: t(pathKey(path)) })}
      </div>
      <p className="m-0">{t('p10.hk.mismatch.body')}</p>
      <dl className="m-0 grid grid-cols-[minmax(0,140px)_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
        <dt className="text-fg-muted">{t('p10.hk.mismatch.trusted')}</dt>
        <dd className="m-0 min-w-0">
          <Fingerprint value={trusted.fingerprintSha256} />
        </dd>
        <dt className="text-fg-muted">{t('p10.hk.mismatch.presented')}</dt>
        <dd className="m-0 min-w-0">
          <Fingerprint value={seen.fingerprintSha256} />
        </dd>
        <dt className="text-fg-muted">{t('p10.hk.mismatch.seen')}</dt>
        <dd className="m-0">{formatDateTime(seen.lastSeenAt, locale)}</dd>
        <dt className="text-fg-muted">{t('p10.hk.agent')}</dt>
        <dd className="m-0">
          <AgentMatch value={seen.agentMatch} />
        </dd>
      </dl>
      <p className="m-0 text-[12.5px] text-fg-2">
        {seen.agentMatch === false
          ? t('p10.hk.mismatch.agentDisagrees')
          : t('p10.hk.mismatch.verify')}
      </p>
    </div>
  );
}

function EndpointEditor({ server, current }: { server: Server; current: SshEndpoint[] }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const init = () =>
    Object.fromEntries(
      PATH_ORDER.map((p) => {
        const e = current.find((x) => x.path === p);
        return [
          p,
          {
            on: !!e,
            host: e?.host ?? server.addresses.find((a) => a.scope === p)?.address ?? '',
            port: String(e?.port ?? 22),
            users: (e?.allowedUsers ?? []).join(', '),
          },
        ];
      }),
    ) as Record<SshPath, { on: boolean; host: string; port: string; users: string }>;
  const [draft, setDraft] = useState(init);
  const set = (p: SshPath, patch: Partial<(typeof draft)[SshPath]>) =>
    setDraft((d) => ({ ...d, [p]: { ...d[p], ...patch } }));
  const body: SshEndpoint[] = PATH_ORDER.filter((p) => draft[p].on).map((p) => ({
    path: p,
    host: draft[p].host,
    port: Number(draft[p].port),
    allowedUsers: draft[p].users
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean),
  }));
  const problems = body.flatMap((e) => {
    const out: string[] = [];
    if (!e.host) out.push(t('p10.ep.err.host', { path: t(pathKey(e.path)) }));
    if (!Number.isInteger(e.port) || e.port < 1 || e.port > 65535)
      out.push(t('p10.ep.err.port', { path: t(pathKey(e.path)) }));
    if (!e.allowedUsers.length || e.allowedUsers.some((u) => !SSH_USER_RE.test(u)))
      out.push(t('p10.ep.err.users', { path: t(pathKey(e.path)) }));
    if (e.allowedUsers.includes('root')) out.push(t('p10.err.root'));
    return out;
  });
  const m = useMutation<SshEndpoint[], ApiError>({
    mutationFn: wrap(() => sshEndpointsApi.put(server.id, body)),
    onSuccess: () => qc.invalidateQueries({ queryKey: p10k.endpoints(server.id) }),
  });
  return (
    <form
      noValidate
      className="flex flex-col gap-3 border-t border-line-soft pt-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!problems.length) m.mutate();
      }}
      data-testid="endpoint-editor"
    >
      {PATH_ORDER.map((p) => {
        const addrs = server.addresses.filter((a) => a.scope === p);
        return (
          <fieldset key={p} className="m-0 flex flex-col gap-2 rounded-md border border-line p-3">
            <legend className="px-1 text-[12.5px] font-medium">
              <label className="inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={draft[p].on}
                  onChange={(e) => set(p, { on: e.target.checked })}
                />
                {t(pathKey(p))}
              </label>
            </legend>
            {draft[p].on && (
              <div className="grid gap-2 sm:grid-cols-[minmax(0,1.4fr)_90px_minmax(0,1fr)]">
                <Field label={t('p10.ep.host')} hint={t('p10.ep.hostHint')}>
                  {(f) => (
                    <Select
                      {...f}
                      value={draft[p].host}
                      onChange={(e) => set(p, { host: e.target.value })}
                      className="font-mono"
                    >
                      <option value="">—</option>
                      {addrs.map((a) => (
                        <option key={a.address} value={a.address}>
                          {a.address}
                        </option>
                      ))}
                      {draft[p].host && !addrs.some((a) => a.address === draft[p].host) && (
                        <option value={draft[p].host}>{draft[p].host}</option>
                      )}
                    </Select>
                  )}
                </Field>
                <Field label={t('p10.ep.port')}>
                  {(f) => (
                    <Input
                      {...f}
                      inputMode="numeric"
                      value={draft[p].port}
                      onChange={(e) =>
                        set(p, { port: e.target.value.replace(/\D/g, '').slice(0, 5) })
                      }
                      className="font-mono"
                    />
                  )}
                </Field>
                <Field label={t('p10.ep.users')} hint={t('p10.ep.usersHint')}>
                  {(f) => (
                    <Input
                      {...f}
                      value={draft[p].users}
                      onChange={(e) => set(p, { users: e.target.value })}
                      className="font-mono"
                      placeholder="ops, deploy"
                    />
                  )}
                </Field>
              </div>
            )}
          </fieldset>
        );
      })}
      {problems.length > 0 && (
        <ul className="m-0 pl-5 text-[12px] text-crit" role="alert">
          {problems.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      )}
      {m.error && <ErrorState error={m.error} />}
      {m.isSuccess && !m.isPending && (
        <span role="status" className="text-[12px] text-ok">
          ● {t('p10.ep.saved')}
        </span>
      )}
      <div>
        <GatedButton
          type="submit"
          variant="primary"
          perm={MANAGE}
          disabled={!!problems.length || m.isPending}
        >
          {m.isPending ? t('common.saving') : t('p10.ep.save')}
        </GatedButton>
      </div>
    </form>
  );
}

function KeyRow({ k, serverName }: { k: SshHostKey; serverName: string }) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<'trust' | 'reject' | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: p10k.hostKeys(k.serverId) });
  const pending = k.status === 'pending';
  return (
    <tr data-testid="host-key-row" data-status={k.status} data-seen={k.seenVia}>
      <td className="px-2 py-2 pl-4 align-top">
        {k.endpointPath ? t(pathKey(k.endpointPath)) : '—'}
      </td>
      <td className="px-2 py-2 align-top font-mono text-[12px]">{k.algorithm}</td>
      <td className="max-w-[340px] px-2 py-2 align-top">
        <Fingerprint value={k.fingerprintSha256} />
      </td>
      <td className="px-2 py-2 align-top">
        <HostKeyStatusBadge status={k.status} />
      </td>
      <td className="px-2 py-2 align-top text-[12px]">{t(`p10.hk.seen.${k.seenVia}`)}</td>
      <td className="px-2 py-2 align-top">
        <AgentMatch value={k.agentMatch} />
      </td>
      <td className="px-2 py-2 align-top text-[12px] text-fg-muted">
        {formatDateTime(k.lastSeenAt, locale)}
        {k.trustedAt && (
          <div>
            {t('p10.hk.trustedBy', {
              who: k.trustedByLabel ?? k.trustedBy ?? '—',
              when: formatDateTime(k.trustedAt, locale),
            })}
          </div>
        )}
      </td>
      <td className="px-2 py-2 pr-4 align-top">
        {pending && (
          <span className="inline-flex flex-wrap gap-1.5">
            <GatedButton
              size="xs"
              variant="primary"
              perm={MANAGE}
              onClick={() => setDialog('trust')}
              aria-label={t('p10.hk.trust.aria', { fp: k.fingerprintSha256 })}
            >
              {t('p10.hk.trust')}
            </GatedButton>
            <GatedButton
              size="xs"
              perm={MANAGE}
              onClick={() => setDialog('reject')}
              aria-label={t('p10.hk.reject.aria', { fp: k.fingerprintSha256 })}
            >
              {t('p10.hk.reject')}
            </GatedButton>
          </span>
        )}
        <ActionDialog
          open={dialog === 'trust'}
          onOpenChange={(o) => setDialog(o ? 'trust' : null)}
          title={t('p10.hk.trust.title', { server: serverName })}
          body={t('p10.hk.trust.body')}
          confirmLabel={t('p10.hk.trust')}
          danger={k.agentMatch === false}
          needsStepUp
          onConfirm={async (token) => {
            await sshHostKeysApi.trust(k.id, token!);
            await refresh();
          }}
        >
          <div className="flex flex-col gap-1.5 rounded-md bg-chip px-3 py-2 text-[12.5px]">
            <code className="font-mono text-[11.5px] break-all">{k.fingerprintSha256}</code>
            <AgentMatch value={k.agentMatch} />
            {k.agentMatch === false && (
              <span className="text-crit">▲ {t('p10.hk.trust.agentWarn')}</span>
            )}
          </div>
        </ActionDialog>
        <ActionDialog
          open={dialog === 'reject'}
          onOpenChange={(o) => setDialog(o ? 'reject' : null)}
          danger
          title={t('p10.hk.reject.title', { server: serverName })}
          body={t('p10.hk.reject.body')}
          confirmLabel={t('p10.hk.reject')}
          needsStepUp={false}
          onConfirm={async () => {
            await sshHostKeysApi.reject(k.id);
            await refresh();
          }}
        />
      </td>
    </tr>
  );
}

function ServerHostKeys({ server }: { server: Server }) {
  const { t } = useI18n();
  const { can } = useAuth();
  const qc = useQueryClient();
  const eps = useSshEndpoints(server.id);
  const keys = useHostKeys(server.id);
  const [editing, setEditing] = useState(false);
  const scan = useMutation<SshHostKey[], ApiError, SshPath>({
    mutationFn: (p) => wrap(() => sshHostKeysApi.scan(server.id, p))(),
    onSuccess: (list) => qc.setQueryData(p10k.hostKeys(server.id), list),
  });
  const endpoints = eps.data ?? [];
  const list = keys.data ?? [];
  return (
    <div className="flex flex-col gap-4">
      {endpoints.map((e) => {
        const hk = hostKeyState(list, e.path);
        return hk.mismatch && hk.trusted ? (
          <MismatchBanner
            key={e.path}
            server={server.name}
            path={e.path}
            trusted={hk.trusted}
            seen={hk.mismatch}
          />
        ) : null;
      })}
      <Card className="flex flex-col gap-3 p-4" aria-labelledby="ep-h">
        <div className="flex flex-wrap items-center gap-2">
          <SectionTitle id="ep-h">{t('p10.ep.title')}</SectionTitle>
          <span className="flex-1" />
          {can(MANAGE) && (
            <Button size="sm" onClick={() => setEditing((v) => !v)} aria-expanded={editing}>
              {editing ? t('common.close') : t('p10.ep.edit')}
            </Button>
          )}
        </div>
        <p className="m-0 text-[12.5px] text-fg-muted">{t('p10.ep.intro')}</p>
        {eps.isPending ? (
          <TableSkeleton rows={2} label={t('common.loading')} />
        ) : eps.isError ? (
          <ErrorState error={eps.error} onRetry={() => void eps.refetch()} />
        ) : endpoints.length === 0 ? (
          <EmptyState title={t('p10.ep.empty')} body={t('p10.ep.emptyBody')} />
        ) : (
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {endpoints.map((e) => {
              const hk = hostKeyState(list, e.path);
              return (
                <li
                  key={e.path}
                  className="flex flex-wrap items-center gap-2 rounded-md border border-line px-3 py-2 text-[13px]"
                  data-testid="ssh-endpoint"
                >
                  <b className="min-w-[90px]">{t(pathKey(e.path))}</b>
                  <code className="font-mono text-[12.5px]">
                    {e.host}:{e.port}
                  </code>
                  {e.allowedUsers.map((u) => (
                    <OutlineTag key={u}>{u}</OutlineTag>
                  ))}
                  <span className="text-[12px]">
                    {hk.mismatch ? (
                      <span className="text-crit">✕ {t('p10.hk.state.mismatch')}</span>
                    ) : hk.trusted ? (
                      <span className="text-ok">● {t('p10.hk.state.trusted')}</span>
                    ) : (
                      <span className="text-warn">▲ {t('p10.hk.state.untrusted')}</span>
                    )}
                  </span>
                  <span className="flex-1" />
                  <GatedButton
                    size="sm"
                    perm={MANAGE}
                    disabled={scan.isPending}
                    onClick={() => scan.mutate(e.path)}
                    aria-label={t('p10.hk.scan.aria', { path: t(pathKey(e.path)) })}
                  >
                    {scan.isPending && scan.variables === e.path
                      ? t('p10.hk.scanning')
                      : t('p10.hk.scan')}
                  </GatedButton>
                </li>
              );
            })}
          </ul>
        )}
        {scan.error && <ErrorState error={scan.error} />}
        {editing && (
          <EndpointEditor key={JSON.stringify(endpoints)} server={server} current={endpoints} />
        )}
      </Card>
      <Card aria-labelledby="hk-h">
        <div className="border-b border-line-soft px-4 py-3">
          <SectionTitle id="hk-h">{t('p10.hk.title')}</SectionTitle>
          <p className="m-0 mt-1 text-[12.5px] text-fg-muted">{t('p10.hk.intro')}</p>
        </div>
        {keys.isPending ? (
          <TableSkeleton label={t('common.loading')} />
        ) : keys.isError ? (
          <div className="p-4">
            <ErrorState error={keys.error} onRetry={() => void keys.refetch()} />
          </div>
        ) : list.length === 0 ? (
          <p className="m-0 px-4 py-3 text-[13px] text-fg-muted">{t('p10.hk.empty')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] border-collapse text-[13px]">
              <thead>
                <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
                  <th scope="col" className="px-2 py-2 pl-4 font-medium">
                    {t('p10.hk.col.path')}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t('p10.hk.col.algorithm')}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t('p10.fingerprint')}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t('p10.col.status')}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t('p10.hk.col.seenVia')}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t('p10.hk.agent')}
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">
                    {t('p10.hk.col.lastSeen')}
                  </th>
                  <th scope="col" className="px-2 py-2 pr-4 font-medium">
                    <span className="sr-only">{t('p10.col.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody className="[&>tr]:border-t [&>tr]:border-line-subtle">
                {list.map((k) => (
                  <KeyRow key={k.id} k={k} serverName={server.name} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

export function HostKeysView({
  serverId,
  onServerChange,
}: {
  serverId: string | null;
  onServerChange: (id: string) => void;
}) {
  const { t } = useI18n();
  const servers = useServers();
  const items = (servers.data?.items ?? []).filter((s) => s.status !== 'revoked');
  const server = items.find((s) => s.id === serverId) ?? items[0];
  return (
    <div className="flex flex-col gap-4">
      <Card className="flex flex-wrap items-end gap-3 p-4">
        <Field label={t('p10.server')} className="min-w-[260px]">
          {(p) => (
            <Select
              {...p}
              value={server?.id ?? ''}
              onChange={(e) => onServerChange(e.target.value)}
              data-testid="hk-server"
            >
              {items.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} · {s.environment}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {server && (
          <EnvBadge
            env={server.environment}
            label={t(envBadgeKey(server.environment))}
            className="mb-2"
          />
        )}
        <Notice tone="neutral" role="note" className="min-w-[260px] flex-1">
          {t('p10.hk.neverTofu')}
        </Notice>
      </Card>
      {servers.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : servers.isError ? (
        <ErrorState error={servers.error} onRetry={() => void servers.refetch()} />
      ) : server ? (
        <ServerHostKeys key={server.id} server={server} />
      ) : (
        <EmptyState title={t('p10.hk.noServers')} />
      )}
    </div>
  );
}
