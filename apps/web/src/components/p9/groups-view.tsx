'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ENVIRONMENTS, type Environment, type Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { groupsApi, serverNetApi } from '@/lib/api/p9-endpoints';
import { isApiError, type ApiError } from '@/lib/api/errors';
import type { ServerGroup } from '@/lib/api/p9-types';
import { useAuth } from '@/lib/auth/auth-provider';
import { P9_PERM } from '@/lib/p9-gates';
import { p9k, useGroups } from '@/lib/p9-queries';
import { qk, useServers } from '@/lib/queries';
import { envBadgeKey, envLabelKey } from '@/lib/servers';
import { cn } from '@/lib/utils';
import { wrap } from '@/components/p3/action-dialog';
import { useToast } from '@/components/providers/toast';
import { Card, Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog } from '@/components/ui/dialog';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { CardTitle } from './net-bits';

interface Draft {
  name: string;
  description: string;
  environment: Environment | '';
}

function GroupForm({
  initial,
  onDone,
  group,
}: {
  initial: Draft;
  group?: ServerGroup;
  onDone: () => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const [d, setD] = useState<Draft>(initial);
  const m = useMutation<ServerGroup, ApiError>({
    mutationFn: wrap(() =>
      group
        ? groupsApi.update(group.id, {
            name: d.name.trim(),
            description: d.description.trim() || null,
            environment: d.environment || null,
          })
        : groupsApi.create({
            name: d.name.trim(),
            ...(d.description.trim() ? { description: d.description.trim() } : {}),
            ...(d.environment ? { environment: d.environment } : {}),
          }),
    ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: p9k.groups });
      void qc.invalidateQueries({ queryKey: qk.servers, exact: true });
      toast(t(group ? 'p9.groups.saved' : 'p9.groups.created'), 'ok');
      if (!group) setD({ name: '', description: '', environment: '' });
      onDone();
    },
  });
  const fe = m.error?.fieldErrors ?? {};
  const nameErr = d.name.trim().length > 63 ? t('p9.groups.err.name') : fe.name;
  return (
    <form
      noValidate
      className="flex flex-col gap-3"
      data-testid={group ? 'group-edit-form' : 'group-create-form'}
      onSubmit={(e) => {
        e.preventDefault();
        if (d.name.trim() && !nameErr) m.mutate();
      }}
    >
      <Field label={t('p9.groups.name')} error={nameErr}>
        {(p) => (
          <Input
            {...p}
            value={d.name}
            maxLength={63}
            onChange={(e) => setD({ ...d, name: e.target.value })}
          />
        )}
      </Field>
      <Field label={t('p9.groups.description')} hint={t('common.optional')} error={fe.description}>
        {(p) => (
          <Input
            {...p}
            value={d.description}
            maxLength={500}
            onChange={(e) => setD({ ...d, description: e.target.value })}
          />
        )}
      </Field>
      <Field label={t('p9.groups.environment')} hint={t('p9.groups.environmentHint')}>
        {(p) => (
          <Select
            {...p}
            value={d.environment}
            onChange={(e) => setD({ ...d, environment: e.target.value as Draft['environment'] })}
          >
            <option value="">{t('p9.groups.anyEnv')}</option>
            {ENVIRONMENTS.map((x) => (
              <option key={x} value={x}>
                {t(envLabelKey(x))}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {m.error && Object.keys(fe).length === 0 && <ErrorState error={m.error} />}
      <div className="flex gap-2">
        <GatedButton
          type="submit"
          variant="primary"
          perm={P9_PERM.groups}
          disabled={!d.name.trim() || m.isPending}
        >
          {m.isPending ? t('common.saving') : t(group ? 'common.save' : 'p9.groups.create')}
        </GatedButton>
      </div>
    </form>
  );
}

function Members({ group, servers }: { group: ServerGroup; servers: Server[] }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const members = servers.filter((s) => s.groupId === group.id);
  const candidates = servers.filter(
    (s) => s.groupId !== group.id && (!group.environment || s.environment === group.environment),
  );
  const [pick, setPick] = useState('');
  const m = useMutation<unknown, ApiError, { server: Server; groupId: string | null }>({
    mutationFn: ({ server, groupId }) =>
      wrap(() => serverNetApi.setGroup(server.id, groupId, server.version))(),
    onSuccess: (_r, v) => {
      void qc.invalidateQueries({ queryKey: qk.servers, exact: true });
      void qc.invalidateQueries({ queryKey: qk.server(v.server.id) });
      void qc.invalidateQueries({ queryKey: p9k.groups });
      setPick('');
      toast(
        t(v.groupId ? 'p9.groups.assigned' : 'p9.groups.unassigned', { name: v.server.name }),
        'ok',
      );
    },
  });
  return (
    <div className="flex flex-col gap-2.5" data-testid="group-members">
      <h3 className="m-0 text-[13.5px] font-semibold">
        {t('p9.groups.members', { n: members.length })}
      </h3>
      {members.length === 0 ? (
        <p className="m-0 text-[13px] text-fg-muted">{t('p9.groups.noMembers')}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1 p-0">
          {members.map((s) => (
            <li
              key={s.id}
              className="flex items-center gap-2 rounded bg-chip px-2 py-1 text-[12.5px]"
            >
              <Link href={`/servers/${s.id}/network`} className="flex-1 font-mono">
                {s.name}
              </Link>
              <EnvBadge
                env={s.environment}
                label={t(envBadgeKey(s.environment))}
                className="px-1.5 py-0 text-[10px]"
              />
              <GatedButton
                size="sm"
                variant="ghost"
                perm={P9_PERM.serversManage}
                action="edit"
                allowedActions={s.allowedActions}
                disabled={m.isPending}
                aria-label={t('p9.groups.removeServer', { name: s.name })}
                onClick={() => m.mutate({ server: s, groupId: null })}
              >
                {t('p9.groups.remove')}
              </GatedButton>
            </li>
          ))}
        </ul>
      )}
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          const s = servers.find((x) => x.id === pick);
          if (s) m.mutate({ server: s, groupId: group.id });
        }}
      >
        <Field label={t('p9.groups.addServer')} className="min-w-[220px] flex-1">
          {(p) => (
            <Select
              {...p}
              value={pick}
              onChange={(e) => setPick(e.target.value)}
              data-testid="assign-server"
            >
              <option value="">{t('p9.groups.pickServer')}</option>
              {candidates.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                  {s.groupName ? ` (${t('p9.groups.movesFrom', { group: s.groupName })})` : ''}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <GatedButton type="submit" perm={P9_PERM.serversManage} disabled={!pick || m.isPending}>
          {t('p9.groups.assign')}
        </GatedButton>
      </form>
      {group.environment && (
        <p className="m-0 text-[12px] text-fg-muted">
          {t('p9.groups.envScoped', { env: t(envLabelKey(group.environment)) })}
        </p>
      )}
      {m.error && <ErrorState error={m.error} />}
    </div>
  );
}

function DeleteGroupDialog({ group, onClose }: { group: ServerGroup | null; onClose: () => void }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const toast = useToast();
  const m = useMutation<unknown, ApiError, string>({
    mutationFn: (id) => wrap(() => groupsApi.remove(id))(),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: p9k.groups });
      toast(t('p9.groups.deleted'), 'ok');
      close();
    },
  });
  const close = () => {
    m.reset();
    onClose();
  };
  const notEmpty = m.error?.code === 'GROUP_NOT_EMPTY';
  return (
    <Dialog
      open={!!group}
      onOpenChange={(o) => !o && close()}
      closeLabel={t('common.close')}
      title={t('p9.groups.deleteTitle', { name: group?.name ?? '' })}
      description={t('p9.groups.deleteBody')}
      footer={
        <>
          <Button onClick={close}>{t('common.cancel')}</Button>
          <Button
            variant="danger"
            disabled={m.isPending || notEmpty}
            onClick={() => group && m.mutate(group.id)}
            data-testid="confirm-delete-group"
          >
            {m.isPending ? t('common.saving') : t('p9.groups.delete')}
          </Button>
        </>
      }
    >
      {notEmpty ? (
        <Notice tone="warn" glyph="▲" role="alert" title={t('p9.groups.notEmpty.title')}>
          <span data-testid="group-not-empty">{t('p9.groups.notEmpty.body')}</span>{' '}
          <span className="font-mono text-[11.5px] text-fg-muted">
            {m.error?.code} · {m.error?.requestId}
          </span>
        </Notice>
      ) : (
        m.error && <ErrorState error={m.error} />
      )}
    </Dialog>
  );
}

export function GroupsView() {
  const { t } = useI18n();
  const { can } = useAuth();
  const q = useGroups();
  const servers = useServers();
  const [sel, setSel] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState<ServerGroup | null>(null);
  const groups = q.data ?? [];
  const g = groups.find((x) => x.id === sel) ?? groups[0] ?? null;
  const all = servers.data?.items ?? [];
  const forbidden = !can('fleet.read') || (isApiError(q.error) && q.error.status === 403);
  const ungrouped = all.filter((s) => !s.groupId).length;

  return (
    <Page>
      <Link href="/servers" className="self-start text-[13px]">
        {t('p9.groups.back')}
      </Link>
      <PageHeader title={t('p9.groups.title')} subtitle={t('p9.groups.subtitle')} />
      <Notice tone="info" glyph="◆" role="note">
        {t('p9.groups.note')}
      </Notice>
      {forbidden ? (
        <ForbiddenState
          perm="fleet.read"
          requestId={isApiError(q.error) ? q.error.requestId : null}
        />
      ) : q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <div className="flex flex-col gap-4">
            <Card className="overflow-hidden">
              <div className="border-b border-line-soft px-4 py-3">
                <CardTitle>{t('p9.groups.list', { n: groups.length })}</CardTitle>
              </div>
              {groups.length === 0 ? (
                <div className="p-4">
                  <EmptyState title={t('p9.groups.empty')} body={t('p9.groups.emptyBody')} />
                </div>
              ) : (
                <ul className="m-0 list-none p-0">
                  {groups.map((x) => (
                    <li key={x.id} className="border-t border-line-subtle first:border-t-0">
                      <button
                        type="button"
                        aria-pressed={x.id === g?.id}
                        data-testid="group-row"
                        onClick={() => {
                          setSel(x.id);
                          setEditing(false);
                        }}
                        className={cn(
                          'flex w-full flex-col gap-0.5 border-0 px-4 py-2.5 text-left',
                          x.id === g?.id ? 'bg-info-bg' : 'bg-surface hover:bg-surface-hover',
                        )}
                      >
                        <span className="flex flex-wrap items-center gap-2">
                          <b className="flex-1 font-mono text-[13px]">{x.name}</b>
                          {x.environment && (
                            <EnvBadge
                              env={x.environment}
                              label={t(envBadgeKey(x.environment))}
                              className="px-1.5 py-0 text-[10px]"
                            />
                          )}
                          <span
                            className="font-mono text-[12px] text-fg-muted"
                            data-testid="group-count"
                          >
                            {t('p9.groups.count', { n: x.serverCount })}
                          </span>
                        </span>
                        {x.description && (
                          <span className="text-[12px] text-fg-muted">{x.description}</span>
                        )}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <p className="m-0 border-t border-line-subtle px-4 py-2 text-[12px] text-fg-muted">
                {t('p9.groups.ungrouped', { n: ungrouped })}{' '}
                <Link href="/servers?group=__none">{t('p9.groups.showUngrouped')}</Link>
              </p>
            </Card>
            <Card className="flex flex-col gap-3 p-4">
              <CardTitle>{t('p9.groups.new')}</CardTitle>
              <GroupForm
                initial={{ name: '', description: '', environment: '' }}
                onDone={() => {}}
              />
            </Card>
          </div>
          {g && (
            <Card className="flex flex-col gap-3 p-4" data-testid="group-detail">
              <CardTitle
                actions={
                  <div className="flex gap-2">
                    <Link
                      href={`/servers?group=${g.id}`}
                      className="inline-flex min-h-8 items-center rounded-md border border-line-strong px-3 text-[12.5px] text-fg no-underline hover:no-underline"
                    >
                      {t('p9.groups.viewServers')}
                    </Link>
                    <GatedButton
                      size="sm"
                      perm={P9_PERM.groups}
                      onClick={() => setEditing((e) => !e)}
                      aria-expanded={editing}
                    >
                      {t('p9.groups.edit')}
                    </GatedButton>
                    <GatedButton
                      size="sm"
                      variant="secondary"
                      className="border-crit text-crit"
                      perm={P9_PERM.groups}
                      onClick={() => setDeleting(g)}
                      data-testid="delete-group"
                    >
                      {t('p9.groups.delete')}
                    </GatedButton>
                  </div>
                }
              >
                <span className="font-mono">{g.name}</span>
              </CardTitle>
              {editing && (
                <GroupForm
                  key={g.id}
                  group={g}
                  initial={{
                    name: g.name,
                    description: g.description ?? '',
                    environment: g.environment ?? '',
                  }}
                  onDone={() => setEditing(false)}
                />
              )}
              <Members group={g} servers={all} />
            </Card>
          )}
        </div>
      )}
      <DeleteGroupDialog group={deleting} onClose={() => setDeleting(null)} />
    </Page>
  );
}
