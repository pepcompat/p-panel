'use client';

import { useMemo, useState, type ReactNode } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { MessageKey } from '@/i18n/en';
import { diagnosticsApi } from '@/lib/api/p9-endpoints';
import type { ApiError } from '@/lib/api/errors';
import {
  TEST_ACTIVE,
  type DiagnoseResult,
  type NetworkConnectivityTest,
  type ServerView,
  type TestStatus,
} from '@/lib/api/p9-types';
import { centerHosts, P9_PERM, validateDiagnose } from '@/lib/p9-gates';
import { p9k, useDiagnostics, useTest } from '@/lib/p9-queries';
import { isLive } from '@/lib/servers';
import { formatDateTime, relativeTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { wrap } from '@/components/p3/action-dialog';
import { Card } from '@/components/ui/card';
import { ToneBadge, type Tone } from '@/components/ui/badge';
import { Field } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { ErrorState, Notice } from '@/components/ui/states';
import { CardTitle, pathKey } from './net-bits';

export const textareaCls =
  'w-full rounded-md border border-line-strong bg-surface px-2.5 py-2 font-mono text-[12.5px] text-fg placeholder:text-fg-subtle aria-[invalid=true]:border-crit';

const TEST_TONE: Record<TestStatus, Tone> = {
  queued: 'info',
  running: 'info',
  succeeded: 'ok',
  failed: 'crit',
  expired: 'off',
  cancelled: 'off',
};

export function TestStatusBadge({ status }: { status: TestStatus }) {
  const { t } = useI18n();
  return (
    <ToneBadge
      tone={TEST_TONE[status]}
      size="sm"
      glyph={TEST_ACTIVE.includes(status) ? '◌' : undefined}
    >
      <span data-testid="test-status" data-status={status}>
        {t(`p9.test.status.${status}` as MessageKey)}
      </span>
    </ToneBadge>
  );
}

export function OkCell({ ok, error }: { ok: boolean; error?: string | null }) {
  const { t } = useI18n();
  return (
    <ToneBadge tone={ok ? 'ok' : 'crit'} size="sm">
      {ok ? t('p9.result.ok') : (error ?? t('p9.result.failed'))}
    </ToneBadge>
  );
}

export function MiniTable({
  caption,
  head,
  rows,
  empty,
  testId,
}: {
  caption: string;
  head: string[];
  rows: ReactNode[][];
  empty?: string;
  testId?: string;
}) {
  const { t } = useI18n();
  return (
    <div className="overflow-x-auto rounded-md border border-line" data-testid={testId}>
      <table className="w-full border-collapse text-[12.5px]">
        <caption className="bg-surface-2 px-3 py-1.5 text-left text-[12px] font-semibold text-fg-3">
          {caption}
        </caption>
        <thead>
          <tr className="text-left text-[11.5px] text-fg-muted">
            {head.map((h) => (
              <th
                key={h}
                scope="col"
                className="border-t border-line-subtle px-3 py-1.5 font-medium"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={head.length}
                className="border-t border-line-subtle px-3 py-2 text-fg-muted"
              >
                {empty ?? t('common.noData')}
              </td>
            </tr>
          ) : (
            rows.map((r, i) => (
              <tr key={i} className="border-t border-line-subtle">
                {r.map((c, j) => (
                  <td key={j} className="px-3 py-1.5 align-top">
                    {c}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

/** Read-only `network.diagnose` result: Center endpoints, interfaces, routes, DNS, TCP. */
export function DiagnoseResultView({ result, now }: { result: DiagnoseResult; now: number }) {
  const { t } = useI18n();
  const mono = (v: ReactNode) => <span className="font-mono">{v}</span>;
  const ms = (v: number | null) => (v == null ? t('common.dash') : `${v} ms`);
  return (
    <div className="flex flex-col gap-3" data-testid="diag-result">
      <MiniTable
        testId="diag-center"
        caption={t('p9.diag.center')}
        head={[
          t('p9.col.path'),
          t('p9.col.url'),
          t('p9.col.result'),
          t('p9.col.latency'),
          t('p9.col.checked'),
        ]}
        rows={result.centerEndpoints.map((e) => [
          t(pathKey(e.path)),
          mono(e.url),
          <OkCell key="o" ok={e.ok} error={e.error} />,
          ms(e.latencyMs),
          relativeTime(e.checkedAt, t, now),
        ])}
      />
      <MiniTable
        testId="diag-tcp"
        caption={t('p9.diag.tcp')}
        head={[t('p9.col.target'), t('p9.col.result'), t('p9.col.latency')]}
        empty={t('p9.diag.noneRequested')}
        rows={result.tcp.map((x) => [
          mono(`${x.host}:${x.port}`),
          <OkCell key="o" ok={x.ok} error={x.error} />,
          ms(x.latencyMs),
        ])}
      />
      <MiniTable
        testId="diag-dns"
        caption={t('p9.diag.dns')}
        head={[t('p9.col.host'), t('p9.col.addresses')]}
        empty={t('p9.diag.noneRequested')}
        rows={result.dns.map((d) => [
          mono(d.host),
          d.error ? (
            <ToneBadge key="e" tone="crit" size="sm">
              {d.error}
            </ToneBadge>
          ) : (
            mono(d.addresses.join(', ') || t('common.dash'))
          ),
        ])}
      />
      <MiniTable
        testId="diag-interfaces"
        caption={t('p9.diag.interfaces')}
        head={[t('p9.col.iface'), t('p9.col.state'), 'MTU', t('p9.col.addresses')]}
        rows={result.interfaces.map((i) => [
          mono(i.name),
          <ToneBadge key="s" tone={i.up ? 'ok' : 'crit'} size="sm">
            {i.up ? t('p9.iface.up') : t('p9.iface.down')}
          </ToneBadge>,
          mono(i.mtu),
          mono(i.addresses.join(', ')),
        ])}
      />
      <MiniTable
        testId="diag-routes"
        caption={t('p9.diag.routes')}
        head={[t('p9.col.dst'), t('p9.col.gateway'), t('p9.col.iface'), t('p9.col.metric')]}
        empty={t('p9.diag.routesNotRequested')}
        rows={result.routes.map((r) => [
          mono(r.dst),
          mono(r.gateway || '—'),
          mono(r.iface),
          mono(r.metric),
        ])}
      />
    </div>
  );
}

/** Shows one test (polled while queued/running). */
export function TestView({ testId, now }: { testId: string; now: number }) {
  const { t } = useI18n();
  const q = useTest(testId);
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const x = q.data;
  if (!x)
    return (
      <p role="status" className="m-0 text-[13px] text-fg-muted">
        {t('common.loading')}
      </p>
    );
  return (
    <div className="flex flex-col gap-2.5" data-testid="test-view">
      <div
        className="flex flex-wrap items-center gap-2 text-[12.5px]"
        role="status"
        aria-live="polite"
      >
        <TestStatusBadge status={x.status} />
        <span className="text-fg-muted">
          {t('p9.diag.requested', { ago: relativeTime(x.createdAt, t, now) })}
        </span>
        {x.jobId && (
          <span className="font-mono text-[11.5px] text-fg-subtle">job {x.jobId.slice(0, 8)}</span>
        )}
      </div>
      {x.error && (
        <Notice tone="crit" glyph="✕" role="alert" title={x.error.code}>
          {x.error.message}
        </Notice>
      )}
      {x.result && <DiagnoseResultView result={x.result} now={now} />}
    </div>
  );
}

export function DiagnosticsPanel({ server, now }: { server: ServerView; now: number }) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const list = useDiagnostics(server.id);
  const latestCenter = useMemo(
    () => (list.data ?? []).find((x) => x.result)?.result?.centerEndpoints ?? [],
    [list.data],
  );
  const hosts = centerHosts(latestCenter);
  const [resolve, setResolve] = useState('');
  const [tcp, setTcp] = useState('');
  const [routes, setRoutes] = useState(true);
  const [touched, setTouched] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const v = validateDiagnose(resolve, tcp, routes, hosts);
  const run = useMutation<{ testId: string }, ApiError>({
    mutationFn: wrap(() => diagnosticsApi.run(server.id, v.params!)),
    onSuccess: (r) => {
      setSelected(r.testId);
      void qc.invalidateQueries({ queryKey: p9k.diagnostics(server.id) });
    },
  });
  const shown = selected ?? list.data?.[0]?.id ?? null;
  const err = (k?: MessageKey, vars?: Record<string, string>) =>
    touched && k ? t(k, vars) : undefined;
  return (
    <Card className="flex flex-col gap-3 p-4" aria-labelledby="diag-h" data-testid="diagnostics">
      <CardTitle
        id="diag-h"
        actions={
          <ToneBadge tone="ok" glyph={false} size="sm" className="font-mono">
            read-only
          </ToneBadge>
        }
      >
        {t('net.diag')}
      </CardTitle>
      <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.diag.intro')}</p>
      <form
        noValidate
        className="grid gap-3 md:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (v.params) run.mutate();
        }}
      >
        <Field
          label={t('p9.diag.resolve')}
          hint={t('p9.diag.resolveHint')}
          error={err(v.errors.resolve)}
        >
          {(p) => (
            <textarea
              {...p}
              rows={3}
              value={resolve}
              onChange={(e) => setResolve(e.target.value)}
              spellCheck={false}
              placeholder="center.ppanel.internal"
              className={textareaCls}
            />
          )}
        </Field>
        <Field
          label={t('p9.diag.tcpLabel')}
          hint={t('p9.diag.tcpHint')}
          error={err(v.errors.tcp, v.errors.tcpVars)}
        >
          {(p) => (
            <textarea
              {...p}
              rows={3}
              value={tcp}
              onChange={(e) => setTcp(e.target.value)}
              spellCheck={false}
              placeholder={'10.104.0.12:5432\n10.104.0.5:4444'}
              className={textareaCls}
            />
          )}
        </Field>
        <div className="flex flex-wrap items-center gap-3 md:col-span-2">
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={routes} onChange={(e) => setRoutes(e.target.checked)} />
            {t('p9.diag.includeRoutes')}
          </label>
          {v.errors.portWarning && (
            <span className="text-[12px] text-warn" role="status">
              ▲ {t('p9.diag.portWarning', { ports: v.errors.portWarning.join(', ') })}
            </span>
          )}
          <span className="flex-1" />
          <GatedButton
            type="submit"
            variant="primary"
            perm={P9_PERM.serversManage}
            blockedReason={isLive(server) ? undefined : { key: 'perm.offline' }}
            disabled={run.isPending || (touched && !v.params)}
            data-testid="run-diagnostics"
          >
            {run.isPending ? t('common.saving') : t('net.runDiag')}
          </GatedButton>
        </div>
      </form>
      {run.error && <ErrorState error={run.error} />}
      {shown && <TestView testId={shown} now={now} />}
      {(list.data ?? []).length > 0 && (
        <details className="rounded-md border border-line px-3 py-2">
          <summary className="cursor-pointer text-[13px] font-medium">
            {t('p9.diag.history', { n: list.data!.length })}
          </summary>
          <ul className="m-0 mt-2 flex list-none flex-col gap-1 p-0">
            {list.data!.map((x: NetworkConnectivityTest) => (
              <li key={x.id}>
                <button
                  type="button"
                  onClick={() => setSelected(x.id)}
                  aria-pressed={x.id === shown}
                  className={cn(
                    'flex w-full flex-wrap items-center gap-2 rounded border-0 px-2 py-1 text-left text-[12.5px]',
                    x.id === shown ? 'bg-info-bg' : 'bg-transparent hover:bg-surface-hover',
                  )}
                >
                  <TestStatusBadge status={x.status} />
                  <span>
                    {t(x.kind === 'pair' ? 'p9.test.kind.pair' : 'p9.test.kind.diagnose')}
                  </span>
                  <span className="text-fg-muted">{formatDateTime(x.createdAt, locale)}</span>
                </button>
              </li>
            ))}
          </ul>
        </details>
      )}
    </Card>
  );
}
