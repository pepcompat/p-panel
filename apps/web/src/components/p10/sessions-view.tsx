'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { sshSessionsApi } from '@/lib/api/p10-endpoints';
import type { SshSession } from '@/lib/api/p10-types';
import { endReasonKey } from '@/lib/ssh/close-codes';
import { formatBytes, formatSeconds } from '@/lib/p10-gates';
import { p10k, useSshSessions } from '@/lib/p10-queries';
import { formatDateTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { ActionDialog } from '@/components/p3/action-dialog';
import { pathKey } from '@/components/p9/net-bits';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { OutlineTag } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, Notice } from '@/components/ui/states';
import { SectionTitle, SessionStatusBadge } from './bits';

const live = (x: SshSession) => x.status === 'open' || x.status === 'pending';

function Row({ x, now, canTerminate }: { x: SshSession; now: number; canTerminate: boolean }) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const start = Date.parse(x.openedAt ?? x.createdAt);
  const end = x.closedAt ? Date.parse(x.closedAt) : now;
  return (
    <tr data-testid="session-row" data-status={x.status}>
      <td className="px-2 py-2 pl-4 align-top">
        <SessionStatusBadge status={x.status} />
      </td>
      <td className="px-2 py-2 align-top">
        <div className="font-mono">{x.serverName ?? x.serverId}</div>
        <div className="text-[12px] text-fg-muted">
          <OutlineTag>{x.sshUser}</OutlineTag> {t(pathKey(x.endpointPath))} ·{' '}
          <span className="font-mono">
            {x.endpointHost}:{x.endpointPort}
          </span>
        </div>
      </td>
      <td className="px-2 py-2 align-top">{x.userLabel ?? x.userId}</td>
      <td className="px-2 py-2 align-top text-[12px]">{formatDateTime(x.createdAt, locale)}</td>
      <td className="px-2 py-2 align-top font-mono text-[12px]">
        {x.openedAt ? formatSeconds((end - start) / 1000) : '—'}
      </td>
      <td className="px-2 py-2 align-top font-mono text-[12px]">
        ↑ {formatBytes(x.bytesIn)}
        <br />↓ {formatBytes(x.bytesOut)}
      </td>
      <td className="px-2 py-2 align-top text-[12px]" data-testid="end-reason">
        {x.endReason ? t(endReasonKey(x.endReason)) : live(x) ? t('p10.session.running') : '—'}
        {x.exitCode !== null && (
          <div className="font-mono text-fg-muted">
            {t('p10.session.exit', { code: x.exitCode })}
          </div>
        )}
      </td>
      <td className="px-2 py-2 pr-4 align-top">
        {live(x) && canTerminate && (
          <Button size="xs" variant="danger" onClick={() => setOpen(true)}>
            {t('p10.session.terminate')}
          </Button>
        )}
        <ActionDialog
          open={open}
          onOpenChange={setOpen}
          danger
          needsStepUp={false}
          title={t('p10.session.terminate.title', { server: x.serverName ?? x.serverId })}
          body={t('p10.session.terminate.body', { who: x.userLabel ?? x.userId })}
          confirmLabel={t('p10.session.terminate')}
          onConfirm={async () => {
            await sshSessionsApi.terminate(x.id);
            await qc.invalidateQueries({ queryKey: p10k.sessions });
          }}
        />
      </td>
    </tr>
  );
}

export function SessionsView() {
  const { t } = useI18n();
  const { me, can } = useAuth();
  const now = useNow(5000);
  const q = useSshSessions();
  const items = q.data ?? [];
  const active = items.filter(live);
  const recent = items.filter((x) => !live(x));
  const table = (rows: SshSession[]) => (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[920px] border-collapse text-[13px]">
        <thead>
          <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
            <th scope="col" className="px-2 py-2 pl-4 font-medium">
              {t('p10.col.status')}
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              {t('p10.server')}
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              {t('p10.session.col.user')}
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              {t('p10.session.col.started')}
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              {t('p10.session.col.duration')}
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              {t('p10.session.col.bytes')}
            </th>
            <th scope="col" className="px-2 py-2 font-medium">
              {t('p10.session.col.end')}
            </th>
            <th scope="col" className="px-2 py-2 pr-4 font-medium">
              <span className="sr-only">{t('p10.col.actions')}</span>
            </th>
          </tr>
        </thead>
        <tbody className="[&>tr]:border-t [&>tr]:border-line-subtle">
          {rows.map((x) => (
            <Row
              key={x.id}
              x={x}
              now={now}
              canTerminate={x.userId === me?.user.id || can('credentials.manage')}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
  return (
    <div className="flex flex-col gap-4">
      <Notice tone="info" glyph="◆" role="note">
        {t('p10.session.auditNote')}
      </Notice>
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title={t('p10.session.empty')} body={t('p10.session.emptyBody')} />
      ) : (
        <>
          <Card aria-labelledby="sess-active-h" data-testid="sessions-active">
            <div className="border-b border-line-soft px-4 py-3">
              <SectionTitle id="sess-active-h">
                {t('p10.session.active', { n: active.length })}
              </SectionTitle>
            </div>
            {active.length ? (
              table(active)
            ) : (
              <p className="m-0 px-4 py-3 text-[13px] text-fg-muted">
                {t('p10.session.noneActive')}
              </p>
            )}
          </Card>
          <Card aria-labelledby="sess-recent-h" data-testid="sessions-recent">
            <div className="border-b border-line-soft px-4 py-3">
              <SectionTitle id="sess-recent-h">{t('p10.session.recent')}</SectionTitle>
            </div>
            {recent.length ? (
              table(recent)
            ) : (
              <p className="m-0 px-4 py-3 text-[13px] text-fg-muted">
                {t('p10.session.noneRecent')}
              </p>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
