'use client';

import { useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import type { ApiError } from '@/lib/api/errors';
import { networkApi } from '@/lib/api/p9-endpoints';
import { DIAG_PORTS, type ServerView, type TestAccepted } from '@/lib/api/p9-types';
import { P9_PERM, vpcDisplay } from '@/lib/p9-gates';
import { useTest } from '@/lib/p9-queries';
import { useServers } from '@/lib/queries';
import { useNow } from '@/lib/use-now';
import { wrap } from '@/components/p3/action-dialog';
import { Card } from '@/components/ui/card';
import { ToneBadge } from '@/components/ui/badge';
import { Field, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { ErrorState, Notice } from '@/components/ui/states';
import { DiagnoseResultView, TestStatusBadge } from './diagnostics';
import { CardTitle, VpcLabel } from './net-bits';

interface Run {
  testId: string;
  from: ServerView;
  to: ServerView;
  port: number;
}

function vpcRelation(a: ServerView, b: ServerView): 'same' | 'different' | 'unknown' {
  const x = vpcDisplay(a);
  const y = vpcDisplay(b);
  if (!x.known || !y.known) return 'unknown';
  return x.uuid === y.uuid ? 'same' : 'different';
}

function PairResult({ run, now }: { run: Run; now: number }) {
  const { t } = useI18n();
  const q = useTest(run.testId);
  const x = q.data;
  const rel = vpcRelation(run.from, run.to);
  const target = `${run.to.privateIpv4 ?? '?'}:${run.port}`;
  return (
    <li className="flex flex-col gap-2 rounded-md border border-line p-3" data-testid="pair-result">
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <b className="font-mono">{run.from.name}</b>
        <span aria-hidden="true">→</span>
        <span className="sr-only">{t('p9.pair.to')}</span>
        <b className="font-mono">{run.to.name}</b>
        <span className="font-mono text-[12px] text-fg-muted">{target}</span>
        <span className="flex-1" />
        {x && <TestStatusBadge status={x.status} />}
      </div>
      {q.isError && <ErrorState error={q.error} />}
      {x?.status === 'succeeded' && (
        <Notice
          tone={x.reachable ? 'ok' : 'crit'}
          glyph={x.reachable ? '●' : '✕'}
          role="status"
          title={x.reachable ? t('p9.pair.reachable') : t('p9.pair.unreachable')}
        >
          <span data-testid="pair-verdict" data-reachable={String(!!x.reachable)}>
            {x.reachable
              ? t('p9.pair.reachableBody')
              : t(
                  rel === 'different'
                    ? 'p9.pair.unreachableDifferent'
                    : rel === 'unknown'
                      ? 'p9.pair.unreachableUnknown'
                      : 'p9.pair.unreachableSame',
                )}
          </span>
          {x.reachable && rel === 'unknown' && (
            <span className="mt-1 block text-[12px] text-fg-muted">
              {t('p9.pair.unknownButReachable')}
            </span>
          )}
        </Notice>
      )}
      {x?.error && (
        <Notice tone="crit" glyph="✕" role="alert" title={x.error.code}>
          {x.error.message}
        </Notice>
      )}
      {x?.result && (
        <details>
          <summary className="cursor-pointer text-[12.5px]">{t('p9.pair.details')}</summary>
          <div className="mt-2">
            <DiagnoseResultView result={x.result} now={now} />
          </div>
        </details>
      )}
    </li>
  );
}

export function ConnectivityView() {
  const { t } = useI18n();
  const params = useSearchParams();
  const now = useNow(5000);
  const servers = useServers();
  const all = servers.data?.items ?? [];
  const [from, setFrom] = useState(params.get('from') ?? '');
  const [to, setTo] = useState(params.get('to') ?? '');
  const [port, setPort] = useState('22');
  const [runs, setRuns] = useState<Run[]>([]);
  const a = all.find((s) => s.id === from);
  const b = all.find((s) => s.id === to);
  const m = useMutation<TestAccepted, ApiError>({
    mutationFn: wrap(() =>
      networkApi.pairTest({ fromServerId: from, toServerId: to, port: Number(port) }),
    ),
    onSuccess: (r) => {
      if (a && b) setRuns((x) => [{ testId: r.testId, from: a, to: b, port: Number(port) }, ...x]);
    },
  });
  const rel = a && b ? vpcRelation(a, b) : null;
  const ready = !!a && !!b && from !== to && !m.isPending;
  return (
    <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
      <Card className="flex flex-col gap-3 p-4" aria-labelledby="pair-h" data-testid="pair-form">
        <CardTitle id="pair-h">{t('p9.pair.title')}</CardTitle>
        <p className="m-0 text-[12.5px] text-fg-muted">{t('p9.pair.intro')}</p>
        <form
          noValidate
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) m.mutate();
          }}
        >
          <Field label={t('p9.pair.from')}>
            {(p) => (
              <Select {...p} value={from} onChange={(e) => setFrom(e.target.value)}>
                <option value="">{t('p9.groups.pickServer')}</option>
                {all.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field
            label={t('p9.pair.toLabel')}
            hint={
              b ? t('p9.pair.toHint', { ip: b.privateIpv4 ?? t('p9.pair.noPrivate') }) : undefined
            }
            error={
              from && from === to
                ? t('p9.pair.err.same')
                : b && !b.privateIpv4
                  ? t('p9.pair.noPrivateErr')
                  : undefined
            }
          >
            {(p) => (
              <Select {...p} value={to} onChange={(e) => setTo(e.target.value)}>
                <option value="">{t('p9.groups.pickServer')}</option>
                {all.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} {s.privateIpv4 ? `· ${s.privateIpv4}` : ''}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t('p9.pair.port')} hint={t('p9.pair.portHint')}>
            {(p) => (
              <Select {...p} value={port} onChange={(e) => setPort(e.target.value)}>
                {DIAG_PORTS.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          {a && b && (
            <div
              className="flex flex-col gap-1 rounded-md bg-chip-2 px-3 py-2 text-[12.5px]"
              data-testid="pair-vpcs"
            >
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{a.name}</span> <VpcLabel server={a} />
              </span>
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{b.name}</span> <VpcLabel server={b} />
              </span>
              <ToneBadge
                tone={rel === 'same' ? 'ok' : rel === 'different' ? 'warn' : 'off'}
                size="sm"
                className="self-start"
              >
                {t(`p9.pair.rel.${rel ?? 'unknown'}`)}
              </ToneBadge>
            </div>
          )}
          {m.error && <ErrorState error={m.error} />}
          <div>
            <GatedButton
              type="submit"
              variant="primary"
              perm={P9_PERM.serversManage}
              disabled={!ready}
              data-testid="run-pair"
            >
              {m.isPending ? t('common.saving') : t('p9.pair.run')}
            </GatedButton>
          </div>
        </form>
      </Card>
      <Card className="flex flex-col gap-3 p-4" aria-labelledby="pair-res-h">
        <CardTitle id="pair-res-h">{t('p9.pair.results')}</CardTitle>
        {runs.length === 0 ? (
          <p className="m-0 text-[13px] text-fg-muted">{t('p9.pair.noRuns')}</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-2 p-0" aria-live="polite">
            {runs.map((r) => (
              <PairResult key={r.testId} run={r} now={now} />
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
