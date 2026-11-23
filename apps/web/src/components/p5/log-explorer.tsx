'use client';

import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useInfiniteQuery } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError, toApiError } from '@/lib/api/errors';
import { logsApi } from '@/lib/api/p5-endpoints';
import {
  LOG_LEVELS,
  LOG_Q_MAX,
  LOG_SOURCES,
  TAIL_BUFFER_MAX,
  type LogDirection,
  type LogEntry,
  type LogLevel,
  type LogQueryParams,
  type LogSource,
  type LogTailParams,
} from '@/lib/api/p5-types';
import { hasGlobalPerm, validateLogRange } from '@/lib/p5-gates';
import { useLogTail, type TailLine } from '@/lib/log-tail';
import { useServers } from '@/lib/queries';
import { useApplications } from '@/lib/p3-queries';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { ToneBadge } from '@/components/ui/badge';
import { LevelBadge, RateLimitNotice } from './bits';
import type { MessageKey } from '@/i18n/en';

const PRESETS = ['15m', '1h', '6h', '24h', '7d', 'custom'] as const;
type Preset = (typeof PRESETS)[number];
const PRESET_MS: Record<Exclude<Preset, 'custom'>, number> = {
  '15m': 15 * 60e3,
  '1h': 3600e3,
  '6h': 6 * 3600e3,
  '24h': 864e5,
  '7d': 7 * 864e5,
};

interface Draft {
  serverId: string;
  appId: string;
  source: '' | LogSource;
  level: '' | LogLevel;
  q: string;
  preset: Preset;
  from: string; // datetime-local
  to: string;
  direction: LogDirection;
}

/** `datetime-local` value in the browser's zone. */
function toLocalInput(ms: number) {
  const d = new Date(ms - new Date(ms).getTimezoneOffset() * 60e3);
  return d.toISOString().slice(0, 16);
}
function fromLocalInput(v: string) {
  const ms = new Date(v).getTime();
  return Number.isFinite(ms) ? ms : NaN;
}
export function tzLabel(ms = Date.now()) {
  const off = -new Date(ms).getTimezoneOffset() / 60;
  return `UTC${off >= 0 ? '+' : ''}${off}`;
}
function logTime(ts: string, locale: string) {
  const d = new Date(ts);
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${formatDateTime(ts, locale)}.${ms}`;
}

function rangeOf(d: Draft, now = Date.now()): { from: number; to: number } {
  if (d.preset === 'custom') return { from: fromLocalInput(d.from), to: fromLocalInput(d.to) };
  return { from: now - PRESET_MS[d.preset], to: now };
}

function draftFromUrl(sp: URLSearchParams, fixed: Fixed): Draft {
  const preset = (PRESETS as readonly string[]).includes(sp.get('range') ?? '')
    ? (sp.get('range') as Preset)
    : sp.get('from') && sp.get('to')
      ? 'custom'
      : '1h';
  const fromMs = Date.parse(sp.get('from') ?? '');
  const toMs = Date.parse(sp.get('to') ?? '');
  const src = sp.get('source') ?? '';
  const lvl = sp.get('level') ?? '';
  return {
    serverId: fixed.serverId ?? sp.get('serverId') ?? '',
    appId: fixed.appId ?? sp.get('appId') ?? '',
    source: (LOG_SOURCES as readonly string[]).includes(src) ? (src as LogSource) : '',
    level: (LOG_LEVELS as readonly string[]).includes(lvl) ? (lvl as LogLevel) : '',
    q: (sp.get('q') ?? '').slice(0, LOG_Q_MAX),
    preset,
    from: toLocalInput(Number.isFinite(fromMs) ? fromMs : Date.now() - 3600e3),
    to: toLocalInput(Number.isFinite(toMs) ? toMs : Date.now()),
    direction: sp.get('direction') === 'forward' ? 'forward' : 'backward',
  };
}

interface Fixed {
  serverId?: string;
  appId?: string;
}

type EmptyKind = 'none' | 'retention' | 'offline';

/**
 * Central log explorer (§9.3): typed filters only (never LogQL), cursor "load more", retention and
 * offline-aware empty states, 429 countdown, and live tail. With `fixed` it is embedded in a server
 * or application tab and the scope pickers are locked.
 */
export function LogExplorer({ fixed = {}, syncUrl = false }: { fixed?: Fixed; syncUrl?: boolean }) {
  const { t, locale } = useI18n();
  const { me, can } = useAuth();
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const servers = useServers();
  const apps = useApplications();
  const now = useNow(30_000);
  const globalRead = hasGlobalPerm(me, 'fleet.read');

  const [draft, setDraft] = useState<Draft>(() =>
    draftFromUrl(syncUrl ? new URLSearchParams(sp.toString()) : new URLSearchParams(), fixed),
  );
  const [applied, setApplied] = useState<LogQueryParams | null>(null);
  const [formError, setFormError] = useState<MessageKey | null>(null);
  const [tailOn, setTailOn] = useState(false);
  const autoRan = useRef(false);

  const serverList = useMemo(() => servers.data?.items ?? [], [servers.data]);
  const serverById = useMemo(() => new Map(serverList.map((s) => [s.id, s])), [serverList]);
  const appItems = useMemo(
    () => (apps.data?.items ?? []).filter((a) => a.kind === 'container' || a.kind === 'compose'),
    [apps.data],
  );
  const appById = useMemo(
    () => new Map((apps.data?.items ?? []).map((a) => [a.id, a])),
    [apps.data],
  );
  const fixedApp = fixed.appId ? appById.get(fixed.appId) : undefined;
  const scopeServerId = fixed.serverId ?? fixedApp?.serverId ?? (draft.serverId || undefined);
  const scopeServer = scopeServerId ? serverById.get(scopeServerId) : undefined;
  const appsForServer = appItems.filter((a) => !draft.serverId || a.serverId === draft.serverId);
  const needsScope = !globalRead && !draft.serverId && !draft.appId;

  function buildParams(d: Draft): LogQueryParams | MessageKey {
    const { from, to } = rangeOf(d);
    const err = validateLogRange(from, to, d.q);
    if (err) return err;
    if (!globalRead && !d.serverId && !d.appId) return 'logs.err.scope';
    return {
      serverId: d.serverId || undefined,
      appId: d.appId || undefined,
      source: d.source || undefined,
      level: d.level || undefined,
      q: d.q.trim() || undefined,
      from: new Date(from).toISOString(),
      to: new Date(to).toISOString(),
      limit: 200,
      direction: d.direction,
    };
  }

  function run(d = draft) {
    const p = buildParams(d);
    if (typeof p === 'string') {
      setFormError(p);
      return;
    }
    setFormError(null);
    setApplied(p);
    if (syncUrl) {
      const qs = new URLSearchParams();
      if (!fixed.serverId && d.serverId) qs.set('serverId', d.serverId);
      if (!fixed.appId && d.appId) qs.set('appId', d.appId);
      if (d.source) qs.set('source', d.source);
      if (d.level) qs.set('level', d.level);
      if (d.q.trim()) qs.set('q', d.q.trim());
      if (d.preset === 'custom') {
        qs.set('from', p.from);
        qs.set('to', p.to);
      } else if (d.preset !== '1h') qs.set('range', d.preset);
      if (d.direction === 'forward') qs.set('direction', 'forward');
      const s = qs.toString();
      router.replace(`${pathname}${s ? `?${s}` : ''}`, { scroll: false });
    }
  }

  // First query runs automatically once the scope is known (or immediately for global readers).
  useEffect(() => {
    if (autoRan.current || !me) return;
    if (!globalRead && !draft.serverId && !draft.appId) return;
    autoRan.current = true;
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me, globalRead]);

  const q = useInfiniteQuery({
    queryKey: ['logs', 'query', applied],
    queryFn: ({ pageParam }) => logsApi.query({ ...applied!, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => (last.hasMore && last.nextCursor ? last.nextCursor : undefined),
    enabled: !!applied,
    retry: (n, e) => n < 1 && !(isApiError(e) && [403, 404, 422, 429].includes(e.status)),
    staleTime: Infinity,
  });

  const items: LogEntry[] = q.data?.pages.flatMap((p) => p.items) ?? [];
  const retentionDays = q.data?.pages[0]?.retentionDays ?? null;
  const retentionStart = retentionDays ? now - retentionDays * 864e5 : null;
  const appliedFrom = applied ? Date.parse(applied.from) : null;
  const appliedTo = applied ? Date.parse(applied.to) : null;
  const partialRetention =
    retentionStart !== null && appliedFrom !== null && appliedFrom < retentionStart;
  const emptyKind: EmptyKind | null =
    q.isSuccess && items.length === 0
      ? retentionStart !== null && appliedTo !== null && appliedTo < retentionStart
        ? 'retention'
        : scopeServer && (scopeServer.status === 'offline' || scopeServer.status === 'stale')
          ? 'offline'
          : 'none'
      : null;

  const tailParams: LogTailParams = useMemo(
    () => ({
      serverId: (applied?.serverId ?? draft.serverId) || undefined,
      appId: (applied?.appId ?? draft.appId) || undefined,
      source: applied?.source,
      level: applied?.level,
      q: applied?.q,
    }),
    [applied, draft.serverId, draft.appId],
  );

  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    run();
  };

  if (!can('fleet.read') && !can('apps.read')) return <ForbiddenState perm="fleet.read" />;

  return (
    <div className="flex flex-col gap-3" data-testid="log-explorer">
      <form
        onSubmit={onSubmit}
        className="flex flex-col gap-3 rounded-lg border border-line bg-surface p-3.5"
        aria-label={t('logs.form')}
        data-testid="log-query-form"
      >
        <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,180px),1fr))] gap-3">
          {!fixed.serverId && !fixed.appId && (
            <Field label={t('logs.f.server')}>
              {(p) => (
                <Select
                  {...p}
                  value={draft.serverId}
                  onChange={(e) => setDraft((d) => ({ ...d, serverId: e.target.value, appId: '' }))}
                >
                  <option value="">
                    {globalRead ? t('logs.f.allInScope') : t('logs.f.pickServer')}
                  </option>
                  {serverList.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
          {!fixed.appId && (
            <Field label={t('logs.f.app')}>
              {(p) => (
                <Select {...p} value={draft.appId} onChange={(e) => set('appId', e.target.value)}>
                  <option value="">{t('logs.f.allApps')}</option>
                  {appsForServer.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
          <Field label={t('logs.f.source')}>
            {(p) => (
              <Select
                {...p}
                value={draft.source}
                onChange={(e) => set('source', e.target.value as Draft['source'])}
              >
                <option value="">{t('common.all')}</option>
                {LOG_SOURCES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t('logs.f.level')}>
            {(p) => (
              <Select
                {...p}
                value={draft.level}
                onChange={(e) => set('level', e.target.value as Draft['level'])}
              >
                <option value="">{t('common.all')}</option>
                {LOG_LEVELS.map((s) => (
                  <option key={s} value={s}>
                    ≥ {s}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t('logs.f.contains')} hint={t('logs.f.containsHint', { n: LOG_Q_MAX })}>
            {(p) => (
              <Input
                {...p}
                value={draft.q}
                maxLength={LOG_Q_MAX}
                spellCheck={false}
                className="font-mono"
                onChange={(e) => set('q', e.target.value)}
              />
            )}
          </Field>
          <Field label={t('logs.f.range', { tz: tzLabel() })}>
            {(p) => (
              <Select
                {...p}
                value={draft.preset}
                onChange={(e) => set('preset', e.target.value as Preset)}
              >
                {PRESETS.map((r) => (
                  <option key={r} value={r}>
                    {t(`logs.preset.${r}` as MessageKey)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {draft.preset === 'custom' && (
            <>
              <Field label={t('logs.f.from')}>
                {(p) => (
                  <Input
                    {...p}
                    type="datetime-local"
                    value={draft.from}
                    onChange={(e) => set('from', e.target.value)}
                  />
                )}
              </Field>
              <Field label={t('logs.f.to')}>
                {(p) => (
                  <Input
                    {...p}
                    type="datetime-local"
                    value={draft.to}
                    onChange={(e) => set('to', e.target.value)}
                  />
                )}
              </Field>
            </>
          )}
          <Field label={t('logs.f.direction')}>
            {(p) => (
              <Select
                {...p}
                value={draft.direction}
                onChange={(e) => set('direction', e.target.value as LogDirection)}
              >
                <option value="backward">{t('logs.dir.backward')}</option>
                <option value="forward">{t('logs.dir.forward')}</option>
              </Select>
            )}
          </Field>
        </div>
        {formError && (
          <span role="alert" className="text-[12.5px] text-crit" data-testid="log-form-error">
            {t(formError)}
          </span>
        )}
        {needsScope && !formError && (
          <span className="text-[12.5px] text-fg-muted">{t('logs.scopeHint')}</span>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary" disabled={q.isFetching && !q.isFetchingNextPage}>
            {q.isFetching && !q.isFetchingNextPage ? t('common.loading') : t('logs.run')}
          </Button>
          <Button
            variant={tailOn ? 'dark' : 'secondary'}
            aria-pressed={tailOn}
            onClick={() => setTailOn((v) => !v)}
            disabled={needsScope}
            data-testid="tail-toggle"
          >
            {tailOn ? t('tail.hide') : t('tail.show')}
          </Button>
          <span className="text-[12px] text-fg-muted">{t('logs.typedOnly')}</span>
        </div>
      </form>

      <Notice tone="neutral" glyph="◆" role="note">
        <span data-testid="retention-notice">
          {retentionDays
            ? t('logs.retention', {
                days: retentionDays,
                date: formatDateTime(new Date(retentionStart!).toISOString(), locale),
              })
            : t('logs.retentionUnknown')}
        </span>
      </Notice>

      {tailOn && (
        <LiveTail
          params={tailParams}
          serverById={serverById}
          appName={(id) => (id ? (appById.get(id)?.name ?? id.slice(0, 8)) : null)}
        />
      )}

      {q.isError && !q.data ? (
        isApiError(q.error) && q.error.status === 429 ? (
          <RateLimitNotice error={q.error} onReady={() => void q.refetch()} />
        ) : isApiError(q.error) && q.error.status === 403 ? (
          <ForbiddenState
            perm={fixed.appId ? 'apps.read' : 'fleet.read'}
            requestId={q.error.requestId}
          />
        ) : (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        )
      ) : !applied ? (
        <EmptyState title={t('logs.idle')} body={t('logs.idleBody')} />
      ) : q.isPending ? (
        <div
          role="status"
          aria-busy="true"
          aria-label={t('common.loading')}
          className="flex flex-col gap-1.5"
        >
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-6 w-full" />
          ))}
        </div>
      ) : emptyKind ? (
        <div data-testid="logs-empty" data-kind={emptyKind}>
          {emptyKind === 'retention' ? (
            <EmptyState
              title={t('logs.empty.retention')}
              body={t('logs.empty.retentionBody', { days: retentionDays ?? '—' })}
            />
          ) : emptyKind === 'offline' ? (
            <EmptyState
              title={t('logs.empty.offline', { name: scopeServer!.name })}
              body={t('logs.empty.offlineBody', {
                ago: relativeTime(scopeServer!.lastHeartbeatAt, t, now),
              })}
            />
          ) : (
            <EmptyState title={t('logs.empty.none')} body={t('logs.empty.noneBody')} />
          )}
        </div>
      ) : (
        <Card className="overflow-hidden">
          <div className="flex flex-wrap items-center gap-2 border-b border-line-soft bg-surface-2 px-3.5 py-2 text-[12px] text-fg-muted">
            <span data-testid="logs-count">{t('logs.count', { n: items.length })}</span>
            <span>·</span>
            <span>
              {applied.direction === 'forward' ? t('logs.dir.forward') : t('logs.dir.backward')}
            </span>
            {partialRetention && (
              <ToneBadge tone="stale" size="sm">
                {t('logs.partialRetention')}
              </ToneBadge>
            )}
            {scopeServer &&
              (scopeServer.status === 'offline' || scopeServer.status === 'stale') && (
                <ToneBadge tone="off" size="sm">
                  {t('logs.serverOfflineTag', { name: scopeServer.name })}
                </ToneBadge>
              )}
          </div>
          <LogTable
            items={items}
            serverById={serverById}
            appName={(id) => (id ? (appById.get(id)?.name ?? id.slice(0, 8)) : null)}
          />
          <div className="flex items-center gap-2 border-t border-line-soft px-3.5 py-2">
            {q.hasNextPage ? (
              <Button
                size="sm"
                onClick={() => void q.fetchNextPage()}
                disabled={q.isFetchingNextPage}
                data-testid="logs-load-more"
              >
                {q.isFetchingNextPage ? t('common.loading') : t('logs.loadMore')}
              </Button>
            ) : (
              <span className="text-[12px] text-fg-muted">{t('logs.end')}</span>
            )}
            {q.isFetchNextPageError && (
              <span className="text-[12px] text-crit">{toApiError(q.error).message}</span>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

/** Log rows. Lines are plain text children (React escapes them) — never HTML. */
function LogTable({
  items,
  serverById,
  appName,
}: {
  items: Array<LogEntry & { id?: string }>;
  serverById: Map<string, Server>;
  appName: (id: string | null) => string | null;
}) {
  const { t, locale } = useI18n();
  return (
    <div className="max-h-[560px] overflow-auto" tabIndex={0} aria-label={t('logs.results')}>
      <table className="w-full border-collapse text-[12px]" data-testid="log-table">
        <thead className="sticky top-0 bg-surface-2 text-left text-[11.5px] text-fg-muted">
          <tr>
            <th scope="col" className="px-3 py-1.5 font-medium whitespace-nowrap">
              {t('logs.col.time', { tz: tzLabel() })}
            </th>
            <th scope="col" className="px-2 py-1.5 font-medium">
              {t('logs.col.level')}
            </th>
            <th scope="col" className="px-2 py-1.5 font-medium">
              {t('logs.col.source')}
            </th>
            <th scope="col" className="px-2 py-1.5 font-medium">
              {t('logs.col.origin')}
            </th>
            <th scope="col" className="px-3 py-1.5 font-medium">
              {t('logs.col.line')}
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((e, i) => (
            <tr
              key={`${e.ts}-${e.serverId}-${i}`}
              className="border-t border-line-subtle align-top"
              data-testid="log-row"
            >
              <td className="px-3 py-1 font-mono text-[11.5px] whitespace-nowrap text-fg-muted">
                <time dateTime={e.ts}>{logTime(e.ts, locale)}</time>
              </td>
              <td className="px-2 py-1">
                <LevelBadge level={e.level} />
              </td>
              <td className="px-2 py-1 font-mono text-[11.5px]">{e.source}</td>
              <td className="px-2 py-1 font-mono text-[11.5px] whitespace-nowrap">
                {serverById.get(e.serverId)?.name ?? e.serverId.slice(0, 8)}
                {e.appId && <span className="text-fg-muted"> / {appName(e.appId)}</span>}
              </td>
              <td
                lang="en"
                className="px-3 py-1 font-mono text-[12px] break-all whitespace-pre-wrap"
                data-testid="log-line"
              >
                {e.line}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LiveTail({
  params,
  serverById,
  appName,
}: {
  params: LogTailParams;
  serverById: Map<string, Server>;
  appName: (id: string | null) => string | null;
}) {
  const { t, locale } = useI18n();
  const tail = useLogTail(params);
  const [autoScroll, setAutoScroll] = useState(true);
  const boxRef = useRef<HTMLDivElement>(null);
  const key = JSON.stringify(params);
  const { start, stop } = tail;

  // (Re)start whenever the filter changes; stop on unmount.
  useEffect(() => {
    start();
    return () => stop('stopped');
  }, [key, start, stop]);

  useEffect(() => {
    const el = boxRef.current;
    if (el && autoScroll && !tail.paused) el.scrollTop = el.scrollHeight;
  }, [tail.lines, autoScroll, tail.paused]);

  const statusView = (() => {
    switch (tail.status) {
      case 'live':
        return <ToneBadge tone="ok">{t('tail.live')}</ToneBadge>;
      case 'connecting':
        return <ToneBadge tone="info">{t('tail.connecting')}</ToneBadge>;
      case 'reconnecting':
        return <ToneBadge tone="warn">{t('tail.reconnecting')}</ToneBadge>;
      case 'closed':
        return <ToneBadge tone="off">{t('tail.closed')}</ToneBadge>;
      case 'error':
        return <ToneBadge tone="crit">{t('tail.error')}</ToneBadge>;
      default:
        return null;
    }
  })();

  return (
    <Card
      className="overflow-hidden"
      data-testid="live-tail"
      data-status={tail.status}
      data-paused={tail.paused ? 'true' : 'false'}
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-line-soft bg-surface-2 px-3.5 py-2 text-[12.5px]">
        <span data-testid="tail-status">{statusView}</span>
        <span className="text-fg-muted" data-testid="tail-count">
          {t('tail.count', { n: tail.lines.length, max: TAIL_BUFFER_MAX })}
          {tail.dropped > 0 && ` · ${t('tail.dropped', { n: tail.dropped })}`}
        </span>
        <span className="flex-1" />
        <label className="flex items-center gap-1.5 text-[12.5px]">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            data-testid="tail-autoscroll"
          />
          {t('tail.autoScroll')}
        </label>
        {tail.status === 'closed' || tail.status === 'error' ? (
          <Button size="sm" onClick={() => tail.start()} data-testid="tail-restart">
            {t('tail.restart')}
          </Button>
        ) : (
          <>
            <Button
              size="sm"
              onClick={() => tail.setPaused(!tail.paused)}
              aria-pressed={tail.paused}
              data-testid="tail-pause"
            >
              {tail.paused ? t('tail.resume') : t('tail.pause')}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => tail.stop('stopped')}>
              {t('tail.stop')}
            </Button>
          </>
        )}
        <Button size="sm" variant="ghost" onClick={tail.clear}>
          {t('tail.clear')}
        </Button>
      </div>
      {tail.paused && (
        <div
          className="border-b border-line-soft bg-notice-bg px-3.5 py-1.5 text-[12.5px]"
          role="status"
          data-testid="tail-paused"
        >
          {t('tail.pausedNote', { n: tail.held })}
        </div>
      )}
      {tail.closeReason === 'timeout' && (
        <Notice tone="info" glyph="◆" role="status" className="m-3">
          <span data-testid="tail-timeout">{t('tail.timeout')}</span>
        </Notice>
      )}
      {(tail.closeReason === 'forbidden' ||
        tail.closeReason === 'backend_unavailable' ||
        tail.closeReason === 'server_shutdown') && (
        <Notice tone="warn" glyph="▲" role="status" className="m-3">
          <span data-testid="tail-ended">{t(`tail.end.${tail.closeReason}` as MessageKey)}</span>
        </Notice>
      )}
      {tail.status === 'error' && (
        <div className="p-3">
          {tail.error?.status === 429 ? (
            <RateLimitNotice error={tail.error} />
          ) : tail.error ? (
            <ErrorState error={tail.error} />
          ) : (
            <Notice tone="crit" glyph="✕" role="alert">
              {t('tail.failed')}
            </Notice>
          )}
        </div>
      )}
      <div
        ref={boxRef}
        role="log"
        aria-live="off"
        aria-label={t('tail.aria')}
        tabIndex={0}
        lang="en"
        className="h-[320px] overflow-auto bg-terminal px-3 py-2 font-mono text-[12px] leading-[1.6] text-terminal-fg"
        data-testid="tail-lines"
      >
        {tail.lines.length === 0 ? (
          <div className="opacity-60">{t('tail.waiting')}</div>
        ) : (
          tail.lines.map((l: TailLine, i) => (
            <div
              key={`${l.id}-${i}`}
              className={cn('break-all whitespace-pre-wrap')}
              data-testid="tail-line"
            >
              <span className="opacity-60">{logTime(l.ts, locale)}</span>{' '}
              <span
                className={
                  l.level === 'error'
                    ? 'text-red-400'
                    : l.level === 'warn'
                      ? 'text-amber-300'
                      : 'text-sky-300'
                }
              >
                {(l.level ?? '-').toUpperCase().padEnd(5)}
              </span>{' '}
              <span className="opacity-80">
                {serverById.get(l.serverId)?.name ?? l.serverId.slice(0, 8)}
                {l.appId ? `/${appName(l.appId)}` : ''}
              </span>{' '}
              <span className="opacity-70">[{l.source}]</span> {l.line}
            </div>
          ))
        )}
      </div>
    </Card>
  );
}
