'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError, type ApiError } from '@/lib/api/errors';
import { sshGrantsApi } from '@/lib/api/p10-endpoints';
import {
  GRANT_DEFAULT_DURATION,
  GRANT_DURATIONS,
  REASON_MAX,
  REASON_MIN,
  type SshGrant,
  type SshPath,
} from '@/lib/api/p10-types';
import { allowedPaths, grantLive, installedUsers, minutesLeft } from '@/lib/p10-gates';
import { p10k, useCredentials, useGrants, useSshEndpoints } from '@/lib/p10-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { ActionDialog, wrap } from '@/components/p3/action-dialog';
import { pathKey } from '@/components/p9/net-bits';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { EnvBadge, OutlineTag } from '@/components/ui/badge';
import { Field, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { Tip } from '@/components/ui/tooltip';
import { GrantStatusBadge, SectionTitle } from './bits';

export interface GrantPrefill {
  serverId?: string | null;
  path?: string | null;
  user?: string | null;
}

function RequestForm({ prefill }: { prefill: GrantPrefill }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const servers = useServers();
  const creds = useCredentials();
  const [serverId, setServerId] = useState(prefill.serverId ?? '');
  const [path, setPath] = useState<SshPath | ''>(
    prefill.path === 'private' || prefill.path === 'public' ? prefill.path : '',
  );
  const [sshUser, setSshUser] = useState(prefill.user ?? '');
  const [duration, setDuration] = useState<number>(GRANT_DEFAULT_DURATION);
  const [reason, setReason] = useState('');
  const [done, setDone] = useState<SshGrant | null>(null);

  useEffect(() => {
    if (prefill.serverId) setServerId(prefill.serverId);
  }, [prefill.serverId]);

  const server = (servers.data?.items ?? []).find((s) => s.id === serverId);
  const eps = useSshEndpoints(serverId);
  const paths = useMemo(
    () => (server ? allowedPaths(server.connectionPolicy, eps.data ?? []) : []),
    [server, eps.data],
  );
  // default / repair the path when the server or its endpoints change
  useEffect(() => {
    if (!paths.length) return;
    if (!path || !paths.includes(path)) setPath(paths[0]!);
  }, [paths, path]);
  const endpoint = (eps.data ?? []).find((e) => e.path === path);
  const users = useMemo(() => endpoint?.allowedUsers ?? [], [endpoint]);
  useEffect(() => {
    if (users.length && !users.includes(sshUser)) setSshUser(users[0]!);
  }, [users, sshUser]);
  const installed = serverId ? installedUsers(serverId, creds.data ?? []) : [];
  const noKey = !!sshUser && !!creds.data && !installed.includes(sshUser);
  const prod = server?.environment === 'production';
  const reasonOk = reason.trim().length >= REASON_MIN && reason.trim().length <= REASON_MAX;

  const m = useMutation<SshGrant, ApiError>({
    mutationFn: wrap(() =>
      sshGrantsApi.create({
        serverId,
        sshUser,
        endpointPath: path as SshPath,
        durationMinutes: duration,
        reason: reason.trim(),
      }),
    ),
    onSuccess: async (g) => {
      setDone(g);
      setReason('');
      await qc.invalidateQueries({ queryKey: p10k.grants });
    },
  });
  const fe = m.error?.fieldErrors ?? {};
  const ready = !!serverId && !!path && !!sshUser && reasonOk && !m.isPending;
  return (
    <Card
      className="flex flex-col gap-3 p-4"
      aria-labelledby="grant-new-h"
      data-testid="grant-form"
    >
      <SectionTitle id="grant-new-h">{t('p10.grant.request')}</SectionTitle>
      <p className="m-0 text-[12.5px] text-fg-muted">{t('p10.grant.requestIntro')}</p>
      <form
        noValidate
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) {
            setDone(null);
            m.mutate();
          }
        }}
      >
        <Field label={t('p10.server')} error={fe.serverId}>
          {(p) => (
            <Select
              {...p}
              value={serverId}
              onChange={(e) => {
                setServerId(e.target.value);
                setPath('');
                setSshUser('');
                setDone(null);
              }}
            >
              <option value="">{t('p10.pickServer')}</option>
              {(servers.data?.items ?? [])
                .filter((s) => s.status !== 'revoked')
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} · {s.environment}
                  </option>
                ))}
            </Select>
          )}
        </Field>
        <Field
          label={t('p10.grant.path')}
          hint={
            server
              ? t('p10.grant.pathHint', { policy: t(`policy.${server.connectionPolicy}`) })
              : undefined
          }
          error={fe.endpointPath}
        >
          {(p) => (
            <Select
              {...p}
              value={path}
              disabled={!paths.length}
              onChange={(e) => setPath(e.target.value as SshPath)}
            >
              {!paths.length && (
                <option value="">
                  {serverId && !eps.isPending ? t('p10.grant.noEndpoint') : '—'}
                </option>
              )}
              {paths.map((x) => {
                const e = eps.data?.find((y) => y.path === x);
                return (
                  <option key={x} value={x}>
                    {t(pathKey(x))} · {e?.host}:{e?.port}
                  </option>
                );
              })}
            </Select>
          )}
        </Field>
        <Field label={t('p10.sshUser')} error={fe.sshUser}>
          {(p) => (
            <Select
              {...p}
              value={sshUser}
              disabled={!users.length}
              onChange={(e) => setSshUser(e.target.value)}
              className="font-mono"
            >
              {!users.length && <option value="">—</option>}
              {users.map((x) => (
                <option key={x} value={x}>
                  {x}
                  {installed.includes(x) ? '' : ` (${t('p10.grant.noKeyShort')})`}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('p10.grant.duration')} error={fe.durationMinutes}>
          {(p) => (
            <Select {...p} value={duration} onChange={(e) => setDuration(Number(e.target.value))}>
              {GRANT_DURATIONS.map((d) => (
                <option key={d} value={d}>
                  {t('p10.minutes', { n: d })}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field
          label={t('p10.grant.reason')}
          hint={t('p10.grant.reasonHint', { min: REASON_MIN, max: REASON_MAX })}
          error={fe.reason}
          className="sm:col-span-2"
        >
          {(p) => (
            <textarea
              {...p}
              rows={2}
              maxLength={REASON_MAX}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 text-[14px] text-fg"
            />
          )}
        </Field>
        <div className="flex flex-col gap-2 sm:col-span-2">
          {server && (
            <Notice tone={prod ? 'warn' : 'info'} glyph={prod ? '▲' : '◆'} role="note">
              {prod ? t('p10.grant.prodNote') : t('p10.grant.nonProdNote')}
            </Notice>
          )}
          {noKey && (
            <Notice tone="warn" glyph="▲" role="note">
              {t('p10.grant.noKey', { user: sshUser })}
            </Notice>
          )}
          {m.error && Object.keys(fe).length === 0 && <ErrorState error={m.error} />}
          {done && (
            <Notice tone="ok" glyph="●" role="status">
              <span data-testid="grant-created">
                {done.status === 'awaiting_approval'
                  ? t('p10.grant.createdPending', { server: done.serverName })
                  : t('p10.grant.createdActive', { server: done.serverName })}
              </span>
            </Notice>
          )}
          <div>
            <GatedButton type="submit" variant="primary" perm="ssh.connect" disabled={!ready}>
              {m.isPending ? t('common.saving') : t('p10.grant.submit')}
            </GatedButton>
          </div>
        </div>
      </form>
    </Card>
  );
}

function GrantRow({
  g,
  me,
  now,
  canManage,
  canDecide,
  onOpenTerminal,
}: {
  g: SshGrant;
  me: string | undefined;
  now: number;
  canManage: boolean;
  canDecide: boolean;
  onOpenTerminal?: (g: SshGrant) => void;
}) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<'approve' | 'reject' | 'revoke' | null>(null);
  const mine = g.userId === me;
  const live = grantLive(g, now);
  const left = minutesLeft(g.expiresAt, now);
  const pending = g.status === 'awaiting_approval';
  const refresh = () => qc.invalidateQueries({ queryKey: p10k.all });
  return (
    <li
      className="flex flex-col gap-1.5 border-t border-line-subtle px-4 py-3 text-[13px] first:border-0"
      data-testid="grant-row"
      data-grant={g.id}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-medium">{g.serverName}</span>
        <EnvBadge
          env={g.environment}
          label={t(envBadgeKey(g.environment))}
          className="px-1.5 py-0 text-[10.5px]"
        />
        <OutlineTag>
          {g.sshUser}@{t(pathKey(g.endpointPath))}
        </OutlineTag>
        <GrantStatusBadge status={g.status} />
        {live && left !== null && (
          <span className="text-[12px] text-fg-muted">{t('p10.grant.left', { n: left })}</span>
        )}
        <span className="flex-1" />
        {live && mine && onOpenTerminal && (
          <Button size="sm" variant="dark" onClick={() => onOpenTerminal(g)}>
            {t('p10.openTerminal')}
          </Button>
        )}
        {pending &&
          canDecide &&
          (mine ? (
            <Tip content={t('p10.grant.selfApproval')}>
              <span
                tabIndex={0}
                className="inline-flex rounded-md"
                aria-describedby={`self-${g.id}`}
              >
                <Button size="sm" variant="primary" disabled data-testid="approve-self">
                  {t('p10.grant.approve')}
                </Button>
                <span id={`self-${g.id}`} className="sr-only">
                  {t('p10.grant.selfApproval')}
                </span>
              </span>
            </Tip>
          ) : (
            <>
              <Button size="sm" variant="primary" onClick={() => setDialog('approve')}>
                {t('p10.grant.approve')}
              </Button>
              <Button size="sm" onClick={() => setDialog('reject')}>
                {t('p10.grant.reject')}
              </Button>
            </>
          ))}
        {(live || pending) && (mine || canManage) && (
          <Button size="sm" variant="ghost" onClick={() => setDialog('revoke')}>
            {pending && mine ? t('p10.grant.withdraw') : t('p10.grant.revoke')}
          </Button>
        )}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[12px] text-fg-muted">
        <span>{t('p10.grant.by', { who: g.userLabel ?? g.userId })}</span>
        <span>{formatDateTime(g.requestedAt, locale)}</span>
        <span>{t('p10.minutes', { n: g.durationMin })}</span>
        {g.approvedByLabel && <span>{t('p10.grant.approvedBy', { who: g.approvedByLabel })}</span>}
        {g.expiresAt && !live && g.status === 'expired' && (
          <span>{t('p10.grant.expiredAt', { when: formatDateTime(g.expiresAt, locale) })}</span>
        )}
      </div>
      <div className="text-[12.5px] text-fg-3">“{g.reason}”</div>
      {pending && mine && (
        <span className="text-[12px] text-warn" data-testid="self-approval-note">
          ▲ {t('p10.grant.waitingOther')}
        </span>
      )}
      <ActionDialog
        open={dialog === 'approve'}
        onOpenChange={(o) => setDialog(o ? 'approve' : null)}
        title={t('p10.grant.approve.title', { server: g.serverName })}
        body={t('p10.grant.approve.body', {
          who: g.userLabel ?? g.userId,
          user: g.sshUser,
          path: t(pathKey(g.endpointPath)),
          n: g.durationMin,
        })}
        confirmLabel={t('p10.grant.approve')}
        needsStepUp
        onConfirm={async (token) => {
          await sshGrantsApi.approve(g, token!);
          await refresh();
        }}
      >
        <div className="rounded-md bg-chip px-3 py-2 text-[12.5px]">“{g.reason}”</div>
      </ActionDialog>
      <ActionDialog
        open={dialog === 'reject'}
        onOpenChange={(o) => setDialog(o ? 'reject' : null)}
        danger
        title={t('p10.grant.reject.title', { server: g.serverName })}
        body={t('p10.grant.reject.body', { who: g.userLabel ?? g.userId })}
        confirmLabel={t('p10.grant.reject')}
        needsStepUp={false}
        onConfirm={async () => {
          await sshGrantsApi.reject(g.id);
          await refresh();
        }}
      />
      <ActionDialog
        open={dialog === 'revoke'}
        onOpenChange={(o) => setDialog(o ? 'revoke' : null)}
        danger
        title={t('p10.grant.revoke.title', { server: g.serverName })}
        body={t('p10.grant.revoke.body')}
        confirmLabel={pending && mine ? t('p10.grant.withdraw') : t('p10.grant.revoke')}
        needsStepUp={false}
        onConfirm={async () => {
          await sshGrantsApi.revoke(g.id);
          await refresh();
        }}
      />
    </li>
  );
}

function GrantList({
  title,
  id,
  items,
  empty,
  ...row
}: {
  title: string;
  id: string;
  items: SshGrant[];
  empty: string;
} & Omit<Parameters<typeof GrantRow>[0], 'g'>) {
  return (
    <Card aria-labelledby={id} data-testid={id}>
      <div className="border-b border-line-soft px-4 py-3">
        <SectionTitle id={id}>{title}</SectionTitle>
      </div>
      {items.length === 0 ? (
        <p className="m-0 px-4 py-3 text-[13px] text-fg-muted">{empty}</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {items.map((g) => (
            <GrantRow key={g.id} g={g} {...row} />
          ))}
        </ul>
      )}
    </Card>
  );
}

export function GrantsView({
  prefill,
  onOpenTerminal,
}: {
  prefill: GrantPrefill;
  onOpenTerminal: (g: SshGrant) => void;
}) {
  const { t } = useI18n();
  const { me, can } = useAuth();
  const now = useNow(15_000);
  const q = useGrants();
  const myId = me?.user.id;
  const canDecide = can('approvals.decide');
  const canManage = can('credentials.manage');
  const all = q.data ?? [];
  const approvals = all.filter((g) => g.status === 'awaiting_approval');
  const mine = all.filter((g) => g.userId === myId);
  const others = all.filter((g) => g.userId !== myId && g.status !== 'awaiting_approval');
  const row = { me: myId, now, canManage, canDecide, onOpenTerminal };
  return (
    <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <RequestForm prefill={prefill} />
      <div className="flex flex-col gap-4">
        {q.isPending ? (
          <TableSkeleton label={t('common.loading')} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <>
            {canDecide && (
              <GrantList
                id="grant-approvals"
                title={t('p10.grant.approvals', { n: approvals.length })}
                items={approvals}
                empty={t('p10.grant.approvalsEmpty')}
                {...row}
              />
            )}
            <GrantList
              id="grant-mine"
              title={t('p10.grant.mine')}
              items={mine.filter((g) => !canDecide || g.status !== 'awaiting_approval')}
              empty={t('p10.grant.mineEmpty')}
              {...row}
            />
            {(canManage || canDecide) && others.length > 0 && (
              <GrantList
                id="grant-others"
                title={t('p10.grant.others')}
                items={others}
                empty=""
                {...row}
              />
            )}
          </>
        )}
        {isApiError(q.error) && q.error.status === 403 && (
          <EmptyState title={t('state.forbidden.title')} body={t('p10.grant.forbidden')} />
        )}
      </div>
    </div>
  );
}
