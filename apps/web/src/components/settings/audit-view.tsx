'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { auditApi } from '@/lib/api/endpoints';
import { isApiError } from '@/lib/api/errors';
import { qk } from '@/lib/queries';
import { formatDateTime } from '@/lib/time';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Field, Input } from '@/components/ui/form';
import { ToneBadge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState } from '@/components/ui/states';
import type { MessageKey } from '@/i18n/en';

const LIMIT = 20;
interface Filters {
  action: string;
  actor_id: string;
  target_id: string;
  since: string; // datetime-local value (local time); sent as ISO-8601 UTC
}

export function AuditView() {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const router = useRouter();
  const params = useSearchParams();
  const initial: Filters = {
    action: params.get('action') ?? '',
    actor_id: params.get('actor_id') ?? '',
    target_id: params.get('target_id') ?? '',
    since: '',
  };
  const [draft, setDraft] = useState<Filters>(initial);
  const [applied, setApplied] = useState<Filters>(initial);
  const [page, setPage] = useState(Number(params.get('page') ?? 1) || 1);
  const allowed = can('audit.read');

  const query = {
    page,
    limit: LIMIT,
    sort: 'createdAt',
    order: 'desc',
    'action[prefix]': applied.action.trim() || undefined,
    actor_id: applied.actor_id.trim() || undefined,
    target_id: applied.target_id.trim() || undefined,
    'created_at[gte]': applied.since ? new Date(applied.since).toISOString() : undefined,
  };
  const q = useQuery({
    queryKey: qk.audit(query),
    queryFn: () => auditApi.list(query),
    enabled: allowed,
    placeholderData: keepPreviousData,
  });

  if (!allowed || (isApiError(q.error) && q.error.status === 403)) {
    return (
      <ForbiddenState
        perm="audit.read"
        requestId={isApiError(q.error) ? q.error.requestId : null}
      />
    );
  }

  const apply = (f: Filters) => {
    setApplied(f);
    setPage(1);
    const sp = new URLSearchParams();
    if (f.action) sp.set('action', f.action);
    if (f.actor_id) sp.set('actor_id', f.actor_id);
    if (f.target_id) sp.set('target_id', f.target_id);
    router.replace(`/settings/audit${sp.toString() ? `?${sp}` : ''}`, { scroll: false });
  };
  const total = q.data?.paginate.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / LIMIT));
  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setDraft((d) => ({ ...d, [k]: e.target.value }));

  return (
    <div className="flex flex-col gap-4">
      <p className="m-0 text-[13px] text-fg-muted">{t('audit.subtitle')}</p>
      <form
        className="grid grid-cols-[repeat(auto-fit,minmax(180px,1fr))] items-end gap-3 rounded-lg border border-line bg-surface p-4"
        onSubmit={(e) => {
          e.preventDefault();
          apply(draft);
        }}
      >
        <Field label={t('audit.filter.action')}>
          {(p) => (
            <Input
              {...p}
              value={draft.action}
              onChange={set('action')}
              placeholder="server."
              className="font-mono text-[13px]"
            />
          )}
        </Field>
        <Field label={t('audit.filter.actor')}>
          {(p) => (
            <Input
              {...p}
              value={draft.actor_id}
              onChange={set('actor_id')}
              className="font-mono text-[13px]"
            />
          )}
        </Field>
        <Field label={t('audit.filter.target')}>
          {(p) => (
            <Input
              {...p}
              value={draft.target_id}
              onChange={set('target_id')}
              className="font-mono text-[13px]"
            />
          )}
        </Field>
        <Field label={t('audit.filter.since')}>
          {(p) => (
            <Input {...p} type="datetime-local" value={draft.since} onChange={set('since')} />
          )}
        </Field>
        <div className="flex gap-2">
          <Button type="submit" variant="primary">
            {t('audit.apply')}
          </Button>
          <Button
            onClick={() => {
              const empty = { action: '', actor_id: '', target_id: '', since: '' };
              setDraft(empty);
              apply(empty);
            }}
          >
            {t('audit.clear')}
          </Button>
        </div>
      </form>
      <Card className="overflow-x-auto">
        {q.isPending ? (
          <TableSkeleton rows={8} label={t('common.loading')} />
        ) : q.isError && !q.data ? (
          <div className="p-4">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} />
          </div>
        ) : q.data.items.length === 0 ? (
          <div className="p-4">
            <EmptyState title={t('audit.empty')} />
          </div>
        ) : (
          <table
            className="w-full min-w-[900px] border-collapse text-[13px]"
            aria-busy={q.isFetching}
          >
            <thead>
              <tr className="bg-surface-2 text-left text-[12px] text-fg-muted">
                <th scope="col" className="px-4 py-[9px] font-medium">
                  {t('audit.col.time')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('audit.col.actor')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('audit.col.action')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('audit.col.target')}
                </th>
                <th scope="col" className="px-2 py-[9px] font-medium">
                  {t('audit.col.result')}
                </th>
                <th scope="col" className="px-4 py-[9px] font-medium">
                  {t('audit.col.requestId')}
                </th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((e) => (
                <tr key={e.id} className="border-t border-line-subtle">
                  <td className="px-4 py-2 font-mono text-[12px] whitespace-nowrap">
                    {formatDateTime(e.createdAt, locale)}
                  </td>
                  <td className="px-2 py-2">
                    <div>{e.actorLabel ?? e.actorType ?? '—'}</div>
                    {e.actorId && (
                      <div className="font-mono text-[11px] text-fg-subtle">{e.actorId}</div>
                    )}
                  </td>
                  <td className="px-2 py-2 font-mono text-[12.5px]">{e.action}</td>
                  <td className="px-2 py-2">
                    <div>{e.targetLabel ?? e.targetType ?? '—'}</div>
                    {e.targetId && (
                      <div className="font-mono text-[11px] text-fg-subtle">{e.targetId}</div>
                    )}
                  </td>
                  <td className="px-2 py-2">
                    <ToneBadge
                      tone={e.result === 'success' ? 'ok' : e.result === 'denied' ? 'crit' : 'warn'}
                    >
                      {['success', 'denied', 'failure'].includes(e.result)
                        ? t(`audit.result.${e.result}` as MessageKey)
                        : e.result}
                    </ToneBadge>
                  </td>
                  <td className="px-4 py-2 font-mono text-[11.5px] break-all text-fg-muted">
                    {e.requestId ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {q.data && total > 0 && (
        <nav aria-label="Pagination" className="flex items-center gap-3 text-[13px]">
          <Button size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            ← {t('common.previous')}
          </Button>
          <span aria-live="polite">
            {t('common.page', { page, pages })} · {t('audit.total', { total })}
          </span>
          <Button size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
            {t('common.next')} →
          </Button>
        </nav>
      )}
    </div>
  );
}
