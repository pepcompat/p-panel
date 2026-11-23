'use client';

import Link from 'next/link';
import { useEffect, useMemo, useRef, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ENVIRONMENTS } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import { alertRulesApi, channelsApi, incidentsApi } from '@/lib/api/p5-endpoints';
import {
  CHANNEL_TYPES,
  CREATABLE_RULE_KINDS,
  RULE_KINDS,
  SEVERITIES,
  THRESHOLD_METRICS,
  type AlertRule,
  type AlertRuleInput,
  type ChannelInput,
  type ChannelTestResult,
  type ChannelType,
  type Incident,
  type IncidentStatus,
  type IncidentTimelineEntry,
  type NotificationChannel,
  type RuleKind,
  type Severity,
  type ThresholdParams,
  type LogDroppedParams,
  channelFields,
  eventDetailText,
} from '@/lib/api/p5-types';
import {
  EMAIL_RE,
  TELEGRAM_CHAT_RE,
  TELEGRAM_TOKEN_RE,
  canAckIncident,
  canCommentIncident,
  scopeTypesFor,
  validateRule,
  webhookUrlHints,
  type RuleFormErrors,
} from '@/lib/p5-gates';
import { p5k, useAlertRules, useChannels, useIncident, useIncidents } from '@/lib/p5-queries';
import { useServers } from '@/lib/queries';
import { useApplications } from '@/lib/p3-queries';
import { envLabelKey } from '@/lib/servers';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, Page, PageHeader } from '@/components/ui/card';
import { Dialog } from '@/components/ui/dialog';
import { Field, Input, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { OutlineTag, ToneBadge } from '@/components/ui/badge';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { SecretInput } from '@/components/p4/secret-input';
import { LocalTabs, Table, Td, Th } from '@/components/preview/shared';
import { IncidentStatusBadge, SeverityBadge } from './bits';
import type { MessageKey } from '@/i18n/en';

const TABS = ['incidents', 'rules', 'channels'] as const;
type Tab = (typeof TABS)[number];
const textarea =
  'w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 text-[13.5px] text-fg placeholder:text-fg-subtle';

const actorName = (a: IncidentTimelineEntry['actor'] | Incident['acknowledgedBy']) =>
  !a ? null : typeof a === 'string' ? a : (a.displayName ?? null);

function useTabParam(): [Tab, (t: Tab) => void] {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const raw = sp.get('tab');
  const tab: Tab = (TABS as readonly string[]).includes(raw ?? '') ? (raw as Tab) : 'incidents';
  return [
    tab,
    (t) => {
      const next = new URLSearchParams(sp.toString());
      if (t === 'incidents') next.delete('tab');
      else next.set('tab', t);
      next.delete('incident');
      const qs = next.toString();
      router.replace(`${pathname}${qs ? `?${qs}` : ''}`, { scroll: false });
    },
  ];
}

export function AlertsView() {
  const { t } = useI18n();
  const [tab, setTab] = useTabParam();
  const incidents = useIncidents();
  const firing = (incidents.data ?? []).filter((i) => i.status === 'firing').length;
  return (
    <Page>
      <PageHeader title={t('alerts.title')} subtitle={t('alerts.subtitle')} />
      <LocalTabs
        label={t('alerts.sections')}
        value={tab}
        onChange={setTab}
        tabs={[
          [
            'incidents',
            <span key="i" className="inline-flex items-center gap-1.5">
              {t('alerts.tab.incidents')}
              {firing > 0 && (
                <ToneBadge tone="crit" size="sm" glyph={false}>
                  {firing}
                </ToneBadge>
              )}
            </span>,
          ],
          ['rules', t('alerts.tab.rules')],
          ['channels', t('alerts.tab.channels')],
        ]}
      />
      {tab === 'incidents' && <IncidentsTab />}
      {tab === 'rules' && <RulesTab />}
      {tab === 'channels' && <ChannelsTab />}
    </Page>
  );
}

// ---------------------------------------------------------------- incidents

type StatusFilter = 'active' | IncidentStatus | 'all';

function IncidentsTab() {
  const { t } = useI18n();
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const now = useNow(15_000);
  const [status, setStatus] = useState<StatusFilter>('active');
  const [severity, setSeverity] = useState<'' | Severity>('');
  const [targetType, setTargetType] = useState<'' | 'server' | 'app'>('');
  const q = useIncidents({
    status: status === 'active' || status === 'all' ? undefined : status,
    severity: severity || undefined,
    target_type: targetType || undefined,
  });
  const items = (q.data ?? []).filter((i) => status !== 'active' || i.status !== 'resolved');
  const selectedId = sp.get('incident');
  const selected = (q.data ?? []).find((i) => i.id === selectedId) ?? null;
  const select = (id: string | null) => {
    const next = new URLSearchParams(sp.toString());
    if (id) next.set('incident', id);
    else next.delete('incident');
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t('inc.f.status')} className="w-[170px]">
          {(p) => (
            <Select
              {...p}
              value={status}
              onChange={(e) => setStatus(e.target.value as StatusFilter)}
            >
              {(['active', 'firing', 'acknowledged', 'resolved', 'all'] as const).map((s) => (
                <option key={s} value={s}>
                  {t(`inc.f.status.${s}` as MessageKey)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('inc.f.severity')} className="w-[150px]">
          {(p) => (
            <Select
              {...p}
              value={severity}
              onChange={(e) => setSeverity(e.target.value as '' | Severity)}
            >
              <option value="">{t('common.all')}</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {t(`sev.${s}` as MessageKey)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('inc.f.target')} className="w-[150px]">
          {(p) => (
            <Select
              {...p}
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as '' | 'server' | 'app')}
            >
              <option value="">{t('common.all')}</option>
              <option value="server">{t('inc.target.server')}</option>
              <option value="app">{t('inc.target.app')}</option>
            </Select>
          )}
        </Field>
      </div>
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_440px]">
        <Card className="overflow-hidden">
          {q.isPending ? (
            <TableSkeleton label={t('common.loading')} />
          ) : q.isError ? (
            <div className="p-3">
              {isApiError(q.error) && q.error.status === 403 ? (
                <ForbiddenState perm="fleet.read" requestId={q.error.requestId} />
              ) : (
                <ErrorState error={q.error} onRetry={() => void q.refetch()} />
              )}
            </div>
          ) : items.length === 0 ? (
            <div className="p-3">
              <EmptyState
                title={status === 'active' ? t('inc.empty.active') : t('inc.empty')}
                body={t('inc.emptyBody')}
              />
            </div>
          ) : (
            <ul className="m-0 list-none p-0" aria-label={t('alerts.tab.incidents')}>
              {items.map((i) => (
                <li key={i.id} className="border-t border-line-subtle first:border-0">
                  <button
                    type="button"
                    onClick={() => select(i.id === selectedId ? null : i.id)}
                    aria-pressed={i.id === selectedId}
                    data-testid="incident-row"
                    data-status={i.status}
                    className={cn(
                      'flex w-full flex-wrap items-center gap-x-3 gap-y-1 border-0 px-4 py-2.5 text-left',
                      i.id === selectedId ? 'bg-info-bg' : 'bg-transparent hover:bg-surface-hover',
                    )}
                  >
                    <SeverityBadge severity={i.severity} />
                    <span className="min-w-0 flex-1">
                      <span className="block text-[13.5px]">
                        <span className="font-mono">
                          {i.ruleName || (i.ruleId ?? '').slice(0, 8)}
                        </span>
                        {' · '}
                        <span className="font-mono">{i.target.name}</span>
                      </span>
                      <span className="block text-[12px] text-fg-muted">
                        {t('inc.started', { ago: relativeTime(i.startedAt, t, now) })}
                        {i.lastValue !== null &&
                          ` · ${t('inc.lastValue', { v: String(i.lastValue) })}`}
                        {i.acknowledgedBy &&
                          ` · ${t('inc.ackBy', { name: actorName(i.acknowledgedBy) ?? '' })}`}
                      </span>
                    </span>
                    <IncidentStatusBadge status={i.status} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
        {selected ? (
          <IncidentDetail incident={selected} onClose={() => select(null)} />
        ) : (
          <Card className="p-4 text-[13px] text-fg-muted">{t('inc.pick')}</Card>
        )}
      </div>
    </div>
  );
}

const TL_GLYPH: Record<string, [string, string]> = {
  fired: ['✕', 'text-crit'],
  notified: ['●', 'text-ok'],
  notify_failed: ['▲', 'text-warn'],
  acknowledged: ['◆', 'text-info'],
  resolved: ['●', 'text-ok'],
  comment: ['›', 'text-fg-muted'],
};

function IncidentDetail({
  incident: listItem,
  onClose,
}: {
  incident: Incident;
  onClose: () => void;
}) {
  const { t, locale } = useI18n();
  // List items omit the timeline; GET /incidents/:id carries it.
  const one = useIncident(listItem.id);
  const incident = one.data ?? listItem;
  const { me } = useAuth();
  const qc = useQueryClient();
  const [ackOpen, setAckOpen] = useState(false);
  const [ackComment, setAckComment] = useState('');
  const [comment, setComment] = useState('');
  const canAck = canAckIncident(me, incident);
  const canComment = canCommentIncident(me, incident);
  const refresh = () => qc.invalidateQueries({ queryKey: ['incidents'] });

  const ack = useMutation({
    mutationFn: () => incidentsApi.acknowledge(incident.id, ackComment.trim() || undefined),
    onSuccess: () => {
      setAckOpen(false);
      setAckComment('');
      void refresh();
    },
  });
  const addComment = useMutation({
    mutationFn: () => incidentsApi.comment(incident.id, comment.trim()),
    onSuccess: () => {
      setComment('');
      void refresh();
    },
  });

  const serverId = incident.serverId;
  const fromMs = new Date(incident.startedAt).getTime() - 15 * 60e3;
  const toMs = Math.min(
    Date.now(),
    incident.resolvedAt ? new Date(incident.resolvedAt).getTime() + 5 * 60e3 : Date.now(),
  );
  const logsHref = `/logs?${new URLSearchParams({
    ...(incident.target.type === 'app'
      ? { appId: incident.target.id }
      : serverId
        ? { serverId }
        : {}),
    from: new Date(fromMs).toISOString(),
    to: new Date(toMs).toISOString(),
  }).toString()}`;
  const timeline = [...(incident.timeline ?? [])].sort((a, b) => a.at.localeCompare(b.at));

  return (
    <Card as="aside" className="flex flex-col gap-3 p-4" data-testid="incident-detail">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={incident.severity} />
        <IncidentStatusBadge status={incident.status} />
        <span className="flex-1" />
        <Button size="sm" variant="ghost" onClick={onClose}>
          {t('common.close')}
        </Button>
      </div>
      <h2 className="m-0 text-[16px] font-semibold">
        <span className="font-mono">
          {incident.ruleName || (incident.ruleId ?? '').slice(0, 8)}
        </span>
        {' · '}
        <span className="font-mono">{incident.target.name}</span>
      </h2>
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[12.5px]">
        {serverId && (
          <Link href={`/servers/${serverId}/monitoring`}>{t('inc.link.monitoring')}</Link>
        )}
        {incident.target.type === 'app' && (
          <Link href={`/applications/${incident.target.id}/overview`}>{t('inc.link.app')}</Link>
        )}
        <Link href={logsHref} data-testid="incident-logs-link">
          {t('inc.link.logs')}
        </Link>
      </div>
      <div className="flex flex-wrap gap-2">
        <GatedButton
          variant="primary"
          size="sm"
          perm="fleet.read"
          action="acknowledge"
          allowedActions={canAck ? ['acknowledge'] : []}
          blockedReason={incident.status !== 'firing' ? { key: 'inc.ackNotFiring' } : undefined}
          onClick={() => setAckOpen(true)}
          data-testid="incident-ack"
        >
          {t('inc.ack')}
        </GatedButton>
      </div>
      <Notice tone="neutral" glyph="◆" role="note">
        {t('inc.autoResolve')}
      </Notice>
      <section aria-labelledby="tl-h" className="flex flex-col gap-2">
        <h3 id="tl-h" className="m-0 text-[13.5px] font-semibold">
          {t('inc.timeline')}
        </h3>
        <ol className="m-0 flex list-none flex-col gap-2 p-0" data-testid="incident-timeline">
          {timeline.map((e, i) => {
            const [g, c] = TL_GLYPH[e.type] ?? ['·', 'text-fg-muted'];
            const who = actorName(e.actor);
            return (
              <li
                key={`${e.at}-${i}`}
                className="grid grid-cols-[16px_minmax(0,1fr)] gap-x-2"
                data-testid="timeline-entry"
                data-type={e.type}
              >
                <span aria-hidden="true" className={cn('font-bold', c)}>
                  {g}
                </span>
                <div className="min-w-0">
                  <div className="text-[13px]">
                    <b>{t(`inc.tl.${e.type}` as MessageKey)}</b>
                    {who && (
                      <span className="text-fg-2" data-testid="timeline-actor">
                        {' '}
                        · {t('inc.tl.by', { name: who })}
                      </span>
                    )}
                  </div>
                  {eventDetailText(e.detail) && (
                    <div className="text-[12.5px] break-words text-fg-2">
                      {eventDetailText(e.detail)}
                    </div>
                  )}
                  <time dateTime={e.at} className="text-[11.5px] text-fg-muted">
                    {formatDateTime(e.at, locale)}
                  </time>
                </div>
              </li>
            );
          })}
        </ol>
      </section>
      {canComment && (
        <form
          className="flex flex-col gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (comment.trim()) addComment.mutate();
          }}
        >
          <label htmlFor="inc-comment" className="text-[12.5px] text-fg-3">
            {t('inc.comment')}
          </label>
          <textarea
            id="inc-comment"
            className={textarea}
            rows={2}
            maxLength={1000}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
          {addComment.isError && <ErrorState error={addComment.error} />}
          <Button
            type="submit"
            size="sm"
            className="self-start"
            disabled={!comment.trim() || addComment.isPending}
          >
            {addComment.isPending ? t('common.saving') : t('inc.addComment')}
          </Button>
        </form>
      )}
      <Dialog
        open={ackOpen}
        onOpenChange={setAckOpen}
        title={t('inc.ackTitle', { name: incident.target.name })}
        description={t('inc.ackBody')}
        closeLabel={t('common.close')}
        footer={
          <>
            <Button onClick={() => setAckOpen(false)}>{t('common.cancel')}</Button>
            <Button
              variant="primary"
              onClick={() => ack.mutate()}
              disabled={ack.isPending}
              data-testid="incident-ack-confirm"
            >
              {ack.isPending ? t('common.saving') : t('inc.ack')}
            </Button>
          </>
        }
      >
        <label htmlFor="ack-comment" className="text-[12.5px] text-fg-3">
          {t('inc.ackComment')}
        </label>
        <textarea
          id="ack-comment"
          className={textarea}
          rows={3}
          maxLength={1000}
          value={ackComment}
          onChange={(e) => setAckComment(e.target.value)}
        />
        {ack.isError && <ErrorState error={ack.error} />}
      </Dialog>
    </Card>
  );
}

// ---------------------------------------------------------------- rules

function conditionText(
  r: Pick<AlertRule, 'kind' | 'params' | 'forSec'>,
  t: (k: MessageKey, v?: Record<string, string | number>) => string,
) {
  const dur = t('rule.forSec', { sec: r.forSec });
  if (r.kind === 'metric_threshold') {
    const p = r.params as Partial<ThresholdParams>;
    const unit = p.metric === 'load1' ? '' : '%';
    return `${p.metric ?? '?'} ${p.op === 'lt' ? '<' : '>'} ${p.value ?? '?'}${unit} · ${dur}`;
  }
  return `${t(`rule.kind.${r.kind}` as MessageKey)} · ${dur}`;
}

function RulesTab() {
  const { t } = useI18n();
  const q = useAlertRules();
  const channels = useChannels();
  const servers = useServers();
  const apps = useApplications();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<AlertRule | 'new' | null>(null);
  const [del, setDel] = useState<AlertRule | null>(null);
  const remove = useMutation({
    mutationFn: (r: AlertRule) => alertRulesApi.remove(r.id, r.version),
    onSuccess: () => {
      setDel(null);
      void qc.invalidateQueries({ queryKey: p5k.rules });
    },
  });
  const chName = (id: string) => channels.data?.find((c) => c.id === id)?.name ?? id.slice(0, 8);
  const scopeName = (r: AlertRule) => {
    if (r.scopeType === 'global') return t('rule.scope.global');
    if (r.scopeType === 'environment') return t(envLabelKey(r.scopeId as never));
    if (r.scopeType === 'server')
      return servers.data?.items.find((s) => s.id === r.scopeId)?.name ?? r.scopeId?.slice(0, 8);
    return apps.data?.items.find((a) => a.id === r.scopeId)?.name ?? r.scopeId?.slice(0, 8);
  };

  if (q.isError && isApiError(q.error) && q.error.status === 403)
    return (
      <div className="flex flex-col gap-3" data-testid="rules-forbidden">
        <ForbiddenState perm="policies.manage" requestId={q.error.requestId} />
        <div>
          <GatedButton perm="policies.manage" variant="primary">
            {t('rule.new')}
          </GatedButton>
        </div>
      </div>
    );

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex-1 text-[12.5px] text-fg-muted">{t('rule.intro')}</span>
        <GatedButton
          perm="policies.manage"
          variant="primary"
          onClick={() => setEditing('new')}
          data-testid="rule-new"
        >
          {t('rule.new')}
        </GatedButton>
      </div>
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (q.data ?? []).length === 0 ? (
        <EmptyState title={t('rule.empty')} />
      ) : (
        <Table
          minWidth={820}
          head={
            <>
              <Th>{t('rule.col.name')}</Th>
              <Th>{t('rule.col.condition')}</Th>
              <Th>{t('rule.col.scope')}</Th>
              <Th>{t('rule.col.severity')}</Th>
              <Th>{t('rule.col.channels')}</Th>
              <Th>{t('rule.col.state')}</Th>
              <Th />
            </>
          }
        >
          {(q.data ?? []).map((r) => (
            <tr key={r.id} data-testid="rule-row" data-name={r.name}>
              <Td className="font-mono text-[12.5px]">{r.name}</Td>
              <Td className="font-mono text-[12px]">{conditionText(r, t)}</Td>
              <Td className="text-[12.5px]">{scopeName(r)}</Td>
              <Td>
                <SeverityBadge severity={r.severity} />
              </Td>
              <Td className="text-[12.5px]">
                {r.channelIds.length ? (
                  r.channelIds.map(chName).join(', ')
                ) : (
                  <span className="text-fg-subtle">—</span>
                )}
              </Td>
              <Td>
                {r.kind === 'backup_failed' ? (
                  <OutlineTag>{t('rule.reserved')}</OutlineTag>
                ) : (
                  <ToneBadge tone={r.enabled ? 'ok' : 'off'} size="sm">
                    {r.enabled ? t('rule.enabled') : t('rule.disabled')}
                  </ToneBadge>
                )}
              </Td>
              <Td className="text-right whitespace-nowrap">
                <GatedButton size="sm" perm="policies.manage" onClick={() => setEditing(r)}>
                  {t('rule.edit')}
                </GatedButton>{' '}
                <GatedButton
                  size="sm"
                  variant="ghost"
                  perm="policies.manage"
                  onClick={() => setDel(r)}
                >
                  {t('rule.delete')}
                </GatedButton>
              </Td>
            </tr>
          ))}
        </Table>
      )}
      {editing && (
        <RuleDialog
          rule={editing === 'new' ? null : editing}
          channels={channels.data ?? []}
          onClose={() => setEditing(null)}
        />
      )}
      <Dialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={t('rule.deleteTitle', { name: del?.name ?? '' })}
        description={t('rule.deleteBody')}
        closeLabel={t('common.close')}
        footer={
          <>
            <Button onClick={() => setDel(null)}>{t('common.cancel')}</Button>
            <Button
              variant="danger"
              onClick={() => del && remove.mutate(del)}
              disabled={remove.isPending}
            >
              {t('rule.delete')}
            </Button>
          </>
        }
      >
        {remove.isError && <ErrorState error={remove.error} />}
      </Dialog>
    </div>
  );
}

const EMPTY_RULE: AlertRuleInput = {
  name: '',
  enabled: true,
  scopeType: 'global',
  scopeId: null,
  kind: 'metric_threshold',
  params: { metric: 'disk', op: 'gt', value: 90 },
  severity: 'warning',
  forSec: 300,
  channelIds: [],
};

function RuleDialog({
  rule,
  channels,
  onClose,
}: {
  rule: AlertRule | null;
  channels: NotificationChannel[];
  onClose: () => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const servers = useServers();
  const apps = useApplications();
  const [form, setForm] = useState<AlertRuleInput>(() =>
    rule
      ? {
          name: rule.name,
          enabled: rule.enabled,
          scopeType: rule.scopeType,
          scopeId: rule.scopeId ?? null,
          kind: rule.kind,
          params: rule.params,
          severity: rule.severity,
          forSec: rule.forSec,
          channelIds: rule.channelIds,
        }
      : EMPTY_RULE,
  );
  const [errors, setErrors] = useState<RuleFormErrors>({});
  const save = useMutation({
    mutationFn: (body: AlertRuleInput) =>
      rule ? alertRulesApi.update(rule.id, body, rule.version) : alertRulesApi.create(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: p5k.rules });
      onClose();
    },
  });
  const apiErr = save.error ? toApiError(save.error) : null;
  const fieldErr = apiErr?.fieldErrors ?? {};
  const th = form.params as Partial<ThresholdParams>;
  const set = (patch: Partial<AlertRuleInput>) => setForm((f) => ({ ...f, ...patch }));
  const setKind = (kind: RuleKind) =>
    set({
      kind,
      params:
        kind === 'metric_threshold'
          ? { metric: 'disk', op: 'gt', value: 90 }
          : kind === 'log_dropped'
            ? { windowSec: 300, minEntries: 1 }
            : {},
      scopeType: scopeTypesFor(kind).includes(form.scopeType) ? form.scopeType : 'global',
      scopeId: scopeTypesFor(kind).includes(form.scopeType) ? form.scopeId : null,
    });
  const submit = () => {
    const body: AlertRuleInput = {
      ...form,
      name: form.name.trim(),
      scopeId: form.scopeType === 'global' ? null : form.scopeId,
    };
    const e = validateRule(body);
    setErrors(e);
    if (Object.keys(e).length) return;
    save.mutate(body);
  };

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={rule ? t('rule.editTitle', { name: rule.name }) : t('rule.newTitle')}
      closeLabel={t('common.close')}
      className="max-w-[620px]"
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            onClick={submit}
            disabled={save.isPending}
            data-testid="rule-save"
          >
            {save.isPending ? t('common.saving') : t('common.save')}
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2" data-testid="rule-form" data-kind={form.kind}>
        <Field
          label={t('rule.f.name')}
          error={errors.name ? t(errors.name) : fieldErr.name}
          className="sm:col-span-2"
        >
          {(p) => (
            <Input
              {...p}
              value={form.name}
              maxLength={80}
              className="font-mono"
              onChange={(e) => set({ name: e.target.value })}
            />
          )}
        </Field>
        <Field
          label={t('rule.f.kind')}
          className="sm:col-span-2"
          hint={t(`rule.kindHint.${form.kind}` as MessageKey)}
        >
          {(p) => (
            <Select {...p} value={form.kind} onChange={(e) => setKind(e.target.value as RuleKind)}>
              {RULE_KINDS.map((k) => (
                <option key={k} value={k} disabled={!CREATABLE_RULE_KINDS.includes(k)}>
                  {t(`rule.kind.${k}` as MessageKey)}
                  {!CREATABLE_RULE_KINDS.includes(k) ? ` (${t('rule.reserved')})` : ''}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {form.kind === 'metric_threshold' && (
          <div className="grid gap-3 sm:col-span-2 sm:grid-cols-3" data-testid="threshold-fields">
            <Field
              label={t('rule.f.metric')}
              error={errors.metric ? t(errors.metric) : fieldErr['params.metric']}
            >
              {(p) => (
                <Select
                  {...p}
                  value={th.metric ?? 'disk'}
                  onChange={(e) =>
                    set({ params: { ...th, metric: e.target.value } as ThresholdParams })
                  }
                >
                  {THRESHOLD_METRICS.map((m) => (
                    <option key={m} value={m}>
                      {t(`metric.name.${m}` as MessageKey)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('rule.f.op')}>
              {(p) => (
                <Select
                  {...p}
                  value={th.op ?? 'gt'}
                  onChange={(e) =>
                    set({ params: { ...th, op: e.target.value } as ThresholdParams })
                  }
                >
                  <option value="gt">{t('rule.op.gt')}</option>
                  <option value="lt">{t('rule.op.lt')}</option>
                </Select>
              )}
            </Field>
            <Field
              label={th.metric === 'load1' ? t('rule.f.valueLoad') : t('rule.f.valuePct')}
              error={errors.value ? t(errors.value) : fieldErr['params.value']}
            >
              {(p) => (
                <Input
                  {...p}
                  type="number"
                  inputMode="decimal"
                  step="any"
                  value={Number.isFinite(th.value) ? String(th.value) : ''}
                  onChange={(e) =>
                    set({
                      params: {
                        ...th,
                        value: e.target.value === '' ? NaN : Number(e.target.value),
                      } as ThresholdParams,
                    })
                  }
                />
              )}
            </Field>
            <p className="m-0 text-[12px] text-fg-muted sm:col-span-3">{t('rule.thresholdNote')}</p>
          </div>
        )}
        {form.kind === 'log_dropped' && (
          <div className="grid gap-3 sm:col-span-2 sm:grid-cols-2" data-testid="log-dropped-fields">
            <Field label={t('rule.f.windowSec')} hint={t('rule.f.windowSecHint')}>
              {(p) => (
                <Input
                  {...p}
                  type="number"
                  min={60}
                  max={86400}
                  value={String((form.params as LogDroppedParams).windowSec ?? 300)}
                  onChange={(e) =>
                    set({ params: { ...form.params, windowSec: Number(e.target.value) } })
                  }
                />
              )}
            </Field>
            <Field label={t('rule.f.minEntries')}>
              {(p) => (
                <Input
                  {...p}
                  type="number"
                  min={1}
                  value={String((form.params as LogDroppedParams).minEntries ?? 1)}
                  onChange={(e) =>
                    set({ params: { ...form.params, minEntries: Number(e.target.value) } })
                  }
                />
              )}
            </Field>
          </div>
        )}
        <Field label={t('rule.f.scopeType')}>
          {(p) => (
            <Select
              {...p}
              value={form.scopeType}
              onChange={(e) =>
                set({ scopeType: e.target.value as AlertRuleInput['scopeType'], scopeId: null })
              }
            >
              {scopeTypesFor(form.kind).map((s) => (
                <option key={s} value={s}>
                  {t(`rule.scope.${s}` as MessageKey)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {form.scopeType !== 'global' ? (
          <Field
            label={t('rule.f.scopeId')}
            error={errors.scopeId ? t(errors.scopeId) : fieldErr.scopeId}
          >
            {(p) => (
              <Select
                {...p}
                value={form.scopeId ?? ''}
                onChange={(e) => set({ scopeId: e.target.value || null })}
              >
                <option value="">{t('rule.f.pick')}</option>
                {form.scopeType === 'environment' &&
                  ENVIRONMENTS.map((e) => (
                    <option key={e} value={e}>
                      {t(envLabelKey(e))}
                    </option>
                  ))}
                {form.scopeType === 'server' &&
                  (servers.data?.items ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                {form.scopeType === 'app' &&
                  (apps.data?.items ?? [])
                    .filter((a) => a.kind === 'container' || a.kind === 'compose')
                    .map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name}
                      </option>
                    ))}
              </Select>
            )}
          </Field>
        ) : (
          <div />
        )}
        <Field label={t('rule.f.severity')}>
          {(p) => (
            <Select
              {...p}
              value={form.severity}
              onChange={(e) => set({ severity: e.target.value as Severity })}
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {t(`sev.${s}` as MessageKey)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field
          label={t('rule.f.forSec')}
          hint={t('rule.f.forSecHint')}
          error={errors.forSec ? t(errors.forSec) : fieldErr.forSec}
        >
          {(p) => (
            <Input
              {...p}
              type="number"
              min={0}
              max={86400}
              step={15}
              value={Number.isFinite(form.forSec) ? String(form.forSec) : ''}
              onChange={(e) =>
                set({ forSec: e.target.value === '' ? NaN : Number(e.target.value) })
              }
            />
          )}
        </Field>
        <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0 sm:col-span-2">
          <legend className="mb-1 text-[12.5px] text-fg-3">{t('rule.f.channels')}</legend>
          {channels.length === 0 ? (
            <span className="text-[12.5px] text-fg-muted">{t('rule.f.noChannels')}</span>
          ) : (
            channels.map((c) => (
              <label key={c.id} className="flex items-center gap-2 text-[13px]">
                <input
                  type="checkbox"
                  checked={form.channelIds.includes(c.id)}
                  onChange={(e) =>
                    set({
                      channelIds: e.target.checked
                        ? [...form.channelIds, c.id]
                        : form.channelIds.filter((x) => x !== c.id),
                    })
                  }
                />
                <span className="font-mono">{c.name}</span>
                <span className="text-fg-muted">· {t(`ch.type.${c.type}` as MessageKey)}</span>
              </label>
            ))
          )}
        </fieldset>
        <label className="flex items-center gap-2 text-[13px] sm:col-span-2">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => set({ enabled: e.target.checked })}
          />
          {t('rule.f.enabled')}
        </label>
      </div>
      {apiErr &&
        (apiErr.status === 409 ? (
          <Notice tone="warn" glyph="▲" role="alert">
            {t('rule.conflict')}
          </Notice>
        ) : (
          <ErrorState error={apiErr} />
        ))}
    </Dialog>
  );
}

// ---------------------------------------------------------------- channels

function ChannelsTab() {
  const { t, locale } = useI18n();
  const q = useChannels();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [results, setResults] = useState<Record<string, ChannelTestResult | ApiError>>({});
  const test = useMutation({
    mutationFn: (id: string) => channelsApi.test(id),
    onSuccess: (r, id) => {
      setResults((x) => ({ ...x, [id]: r }));
      void qc.invalidateQueries({ queryKey: p5k.channels });
    },
    onError: (e, id) => setResults((x) => ({ ...x, [id]: toApiError(e) })),
  });
  const patch = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<ChannelInput> }) =>
      channelsApi.update(id, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: p5k.channels }),
  });

  if (q.isError && isApiError(q.error) && q.error.status === 403)
    return (
      <div className="flex flex-col gap-3" data-testid="channels-forbidden">
        <ForbiddenState perm="policies.manage" requestId={q.error.requestId} />
      </div>
    );

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex-1 text-[12.5px] text-fg-muted">{t('ch.intro')}</span>
        <GatedButton
          perm="policies.manage"
          variant="primary"
          onClick={() => setCreating(true)}
          data-testid="channel-new"
        >
          {t('ch.new')}
        </GatedButton>
      </div>
      <Notice tone="info" glyph="◆" role="note">
        {t('ch.telegramNote')}
      </Notice>
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (q.data ?? []).length === 0 ? (
        <EmptyState title={t('ch.empty')} />
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,360px),1fr))] gap-3">
          {(q.data ?? []).map((c) => {
            const r = results[c.id];
            const f = channelFields(c);
            const dest =
              c.type === 'webhook'
                ? f.url
                : c.type === 'email'
                  ? (f.to ?? []).join(', ')
                  : f.chatId;
            return (
              <Card
                key={c.id}
                as="article"
                className="flex flex-col gap-2.5 p-4"
                data-testid="channel-card"
                data-name={c.name}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <b className="flex-1 font-mono text-[14px]">{c.name}</b>
                  <OutlineTag>{t(`ch.type.${c.type}` as MessageKey)}</OutlineTag>
                  <ToneBadge tone={c.enabled ? 'ok' : 'off'} size="sm">
                    {c.enabled ? t('rule.enabled') : t('rule.disabled')}
                  </ToneBadge>
                </div>
                <div className="font-mono text-[12.5px] break-all text-fg-2">{dest || '—'}</div>
                {c.type === 'webhook' && (
                  <SecretInput
                    secretKey="signingSecret"
                    label={t('ch.f.signingSecret')}
                    status={{ set: f.signingSecretSet }}
                    onSubmit={(v) =>
                      patch.mutateAsync({ id: c.id, body: { config: { signingSecret: v } } })
                    }
                  />
                )}
                {c.type === 'telegram' && (
                  <SecretInput
                    secretKey="botToken"
                    label={t('ch.f.botToken')}
                    status={{ set: f.botTokenSet }}
                    onSubmit={(v) =>
                      patch.mutateAsync({ id: c.id, body: { config: { botToken: v } } })
                    }
                  />
                )}
                <div className="flex flex-wrap items-center gap-2">
                  <GatedButton
                    size="sm"
                    perm="policies.manage"
                    onClick={() => test.mutate(c.id)}
                    disabled={test.isPending && test.variables === c.id}
                    data-testid="channel-test"
                  >
                    {test.isPending && test.variables === c.id ? t('ch.testing') : t('ch.test')}
                  </GatedButton>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => patch.mutate({ id: c.id, body: { enabled: !c.enabled } })}
                  >
                    {c.enabled ? t('ch.disable') : t('ch.enable')}
                  </Button>
                  {c.lastDelivery && !r && (
                    <span className="text-[12px] text-fg-muted">
                      {t('ch.lastTest', { time: formatDateTime(c.lastDelivery.at, locale) })}{' '}
                      {c.lastDelivery.status === 'delivered' ? '✓' : '✕'}
                    </span>
                  )}
                </div>
                {r && (
                  <div
                    role="status"
                    data-testid="channel-test-result"
                    data-delivered={'delivered' in r ? String(r.delivered) : 'false'}
                  >
                    {'delivered' in r ? (
                      r.delivered ? (
                        <Notice tone="ok" glyph="●">
                          {t('ch.test.ok')}
                        </Notice>
                      ) : (
                        <Notice tone="crit" glyph="✕">
                          {t('ch.test.fail')}{' '}
                          <span className="font-mono text-[12.5px]">{r.error ?? ''}</span>
                        </Notice>
                      )
                    ) : (
                      <ErrorState error={r} />
                    )}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
      {creating && <ChannelDialog onClose={() => setCreating(false)} />}
    </div>
  );
}

function ChannelDialog({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [type, setType] = useState<ChannelType>('webhook');
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [to, setTo] = useState('');
  const [chatId, setChatId] = useState('');
  const [local, setLocal] = useState<Record<string, MessageKey>>({});
  // Write-only secrets: read from the DOM once at submit, never kept in React state.
  const secretRef = useRef<HTMLInputElement>(null);
  const hints = useMemo(() => (type === 'webhook' ? webhookUrlHints(url) : []), [type, url]);
  const create = useMutation({
    mutationFn: (body: ChannelInput) => channelsApi.create(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: p5k.channels });
      onClose();
    },
  });
  useEffect(() => {
    if (secretRef.current) secretRef.current.value = '';
  }, [type]);
  const apiErr = create.error ? toApiError(create.error) : null;
  const fe = apiErr?.fieldErrors ?? {};

  const submit = () => {
    const errs: Record<string, MessageKey> = {};
    if (!name.trim() || name.trim().length > 120) errs.name = 'ch.err.name';
    const toList = to
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    if (type === 'webhook' && hints.some((h) => h.level === 'error'))
      errs.url = 'ch.hint.invalidUrl';
    if (type === 'webhook' && !url.trim()) errs.url = 'ch.err.url';
    if (type === 'email' && (toList.length === 0 || toList.some((x) => !EMAIL_RE.test(x))))
      errs.to = 'ch.err.to';
    if (type === 'telegram' && !TELEGRAM_CHAT_RE.test(chatId.trim())) errs.chatId = 'ch.err.chatId';
    const secret = secretRef.current?.value ?? '';
    if (type === 'telegram' && !secret) errs.secret = 'ch.err.botToken';
    else if (type === 'telegram' && !TELEGRAM_TOKEN_RE.test(secret))
      errs.secret = 'ch.err.botTokenFormat';
    if (type === 'webhook' && secret.length < 16) errs.secret = 'ch.err.signingSecret';
    setLocal(errs);
    if (Object.keys(errs).length) return;
    const body: ChannelInput = {
      name: name.trim(),
      type,
      enabled: true,
      config:
        type === 'webhook'
          ? { url: url.trim(), ...(secret ? { signingSecret: secret } : {}) }
          : type === 'email'
            ? { to: toList }
            : { chatId: chatId.trim(), botToken: secret },
    };
    create.mutate(body, {
      onSettled: () => {
        if (secretRef.current) secretRef.current.value = '';
      },
    });
  };

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={t('ch.newTitle')}
      closeLabel={t('common.close')}
      className="max-w-[560px]"
      footer={
        <>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            onClick={submit}
            disabled={create.isPending}
            data-testid="channel-save"
          >
            {create.isPending ? t('common.saving') : t('ch.create')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3" data-testid="channel-form">
        <div role="radiogroup" aria-label={t('ch.f.type')} className="flex flex-wrap gap-2">
          {CHANNEL_TYPES.map((ct) => (
            <label
              key={ct}
              className={cn(
                'flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-[13px]',
                type === ct ? 'border-accent-strong bg-info-bg' : 'border-line',
              )}
            >
              <input
                type="radio"
                name="ch-type"
                value={ct}
                checked={type === ct}
                onChange={() => setType(ct)}
              />
              {t(`ch.type.${ct}` as MessageKey)}
            </label>
          ))}
        </div>
        <Field label={t('ch.f.name')} error={local.name ? t(local.name) : fe.name}>
          {(p) => (
            <Input
              {...p}
              value={name}
              className="font-mono"
              onChange={(e) => setName(e.target.value)}
            />
          )}
        </Field>
        {type === 'webhook' && (
          <>
            <Field
              label={t('ch.f.url')}
              error={local.url ? t(local.url) : fe['config.url']}
              hint={t('ch.f.urlHint')}
            >
              {(p) => (
                <Input
                  {...p}
                  value={url}
                  type="url"
                  className="font-mono"
                  spellCheck={false}
                  onChange={(e) => setUrl(e.target.value)}
                />
              )}
            </Field>
            {hints.length > 0 && (
              <ul
                className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px]"
                data-testid="url-hints"
              >
                {hints.map((h) => (
                  <li
                    key={h.key}
                    data-level={h.level}
                    className={
                      h.level === 'error'
                        ? 'text-crit'
                        : h.level === 'warn'
                          ? 'text-warn'
                          : 'text-ok'
                    }
                  >
                    <span aria-hidden="true">
                      {h.level === 'ok' ? '● ' : h.level === 'warn' ? '▲ ' : '✕ '}
                    </span>
                    {t(h.key)}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
        {type === 'email' && (
          <Field
            label={t('ch.f.to')}
            hint={t('ch.f.toHint')}
            error={local.to ? t(local.to) : fe['config.to']}
          >
            {(p) => <Input {...p} value={to} onChange={(e) => setTo(e.target.value)} />}
          </Field>
        )}
        {type === 'telegram' && (
          <Field
            label={t('ch.f.chatId')}
            error={local.chatId ? t(local.chatId) : fe['config.chatId']}
          >
            {(p) => (
              <Input
                {...p}
                value={chatId}
                className="font-mono"
                onChange={(e) => setChatId(e.target.value)}
              />
            )}
          </Field>
        )}
        {(type === 'webhook' || type === 'telegram') && (
          <Field
            label={type === 'webhook' ? t('ch.f.signingSecret') : t('ch.f.botToken')}
            hint={t('secret.writeOnly')}
            error={
              local.secret ? t(local.secret) : (fe['config.botToken'] ?? fe['config.signingSecret'])
            }
          >
            {(p) => (
              <input
                {...p}
                ref={secretRef}
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                data-1p-ignore
                data-lpignore="true"
                data-testid="channel-secret"
                className="w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[13px] text-fg"
              />
            )}
          </Field>
        )}
        {type === 'telegram' && (
          <Notice tone="info" glyph="◆" role="note">
            {t('ch.telegramNote')}
          </Notice>
        )}
        {type === 'email' && <p className="m-0 text-[12px] text-fg-muted">{t('ch.emailNote')}</p>}
        {apiErr && Object.keys(fe).length === 0 && <ErrorState error={apiErr} />}
      </div>
    </Dialog>
  );
}
