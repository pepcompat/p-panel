'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { discoveryApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import {
  FINDING_KINDS,
  type Application,
  type DiscoveryFinding,
  type DiscoveryScan,
  type ImportMode,
} from '@/lib/api/p3-types';
import { useFindings, useScan } from '@/lib/p3-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { Card, CardHeader } from '@/components/ui/card';
import { EnvBadge, OutlineTag, ToneBadge } from '@/components/ui/badge';
import { GatedButton } from '@/components/ui/gated-button';
import { Skeleton, TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { useSetPageEnv } from '@/components/shell/page-env';
import { LocalTabs, Table, Td, Th } from '@/components/preview/shared';
import { ConfidenceBadge, OwnershipBadge, ScanStatusBadge, Sha } from './bits';
import type { MessageKey } from '@/i18n/en';

function provenanceText(f: DiscoveryFinding): { at: string; from: string | null } | null {
  if (!f.provenance?.file) return null;
  const chain = f.provenance.includeChain?.length
    ? f.provenance.includeChain.join(' → ')
    : f.provenance.includedFrom;
  return {
    at: f.provenance.line ? `${f.provenance.file}:${f.provenance.line}` : f.provenance.file,
    from: chain || null,
  };
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="flex min-w-[110px] flex-col rounded-md border border-line bg-surface px-3 py-2">
      <span className="text-[12px] text-fg-muted">{label}</span>
      <span className={cn('font-mono text-[20px] font-semibold', value > 0 && tone)}>{value}</span>
    </div>
  );
}

function FindingCard({
  f,
  all,
  selected,
  onToggle,
  selectable,
}: {
  f: DiscoveryFinding;
  all: DiscoveryFinding[];
  selected: boolean;
  onToggle: () => void;
  selectable: boolean;
}) {
  const { t } = useI18n();
  const prov = provenanceText(f);
  const dupWith = f.conflicts
    .filter((c) => c.type === 'duplicate_server_name')
    .flatMap((c) => c.with)
    .map((id) => all.find((x) => x.id === id))
    .filter((x): x is DiscoveryFinding => !!x);
  const dupDomains = new Set(
    dupWith.flatMap((d) => d.domains.filter((x) => f.domains.includes(x))),
  );
  const checkboxId = `finding-${f.id}`;
  const links: Array<[MessageKey, string | null | undefined]> = [
    ['finding.link.upstream', f.links.upstream],
    ['finding.link.fastcgi', f.links.fastcgiPass],
    ['finding.link.root', f.links.root],
    ['finding.link.processes', f.links.processes?.length ? f.links.processes.join(', ') : null],
  ];
  return (
    <article
      data-testid="finding"
      data-finding-title={f.title}
      className={cn(
        'flex gap-3 border-t border-line-subtle px-4 py-3 first:border-t-0',
        dupWith.length > 0 && !selected && 'bg-crit-bg/40',
        selected && 'bg-info-bg',
      )}
    >
      {selectable ? (
        <input
          id={checkboxId}
          type="checkbox"
          className="mt-1 h-4 w-4 shrink-0"
          checked={selected}
          onChange={onToggle}
          aria-label={t('finding.select', { title: f.title })}
        />
      ) : (
        <span className="w-4 shrink-0" aria-hidden="true" />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="m-0 font-mono text-[13.5px] font-semibold break-all">{f.title}</h3>
          <ConfidenceBadge c={f.confidence} />
          {f.manualReviewRequired && (
            <ToneBadge tone="warn" size="sm">
              {t('flag.manualReview')}
            </ToneBadge>
          )}
          {dupWith.length > 0 && (
            <ToneBadge tone="crit" size="sm">
              {t('finding.duplicateAlso', {
                file: dupWith
                  .map((d) => d.provenance?.file?.split('/').pop() ?? d.title)
                  .join(', '),
              })}
            </ToneBadge>
          )}
          {f.applicationId && (
            <Link href={`/applications/${f.applicationId}/overview`} className="text-[12px]">
              {t('finding.imported')} →
            </Link>
          )}
        </div>
        {f.domains.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {f.domains.map((d) => (
              <span
                key={d}
                className={cn(
                  'rounded-[3px] px-1.5 font-mono text-[12px] break-all',
                  dupDomains.has(d) ? 'bg-crit-bg font-semibold text-crit' : 'bg-chip',
                )}
              >
                {dupDomains.has(d) && <span aria-hidden="true">✕ </span>}
                {d}
                {dupDomains.has(d) && <span className="sr-only"> ({t('finding.duplicate')})</span>}
              </span>
            ))}
          </div>
        )}
        <dl className="m-0 grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
          {f.listen.length > 0 && (
            <>
              <dt className="text-fg-muted">{t('finding.listen')}</dt>
              <dd className="m-0 flex flex-wrap gap-1">
                {f.listen.map((l) => (
                  <OutlineTag key={l}>{l}</OutlineTag>
                ))}
              </dd>
            </>
          )}
          {prov && (
            <>
              <dt className="text-fg-muted">{t('finding.provenance')}</dt>
              <dd className="m-0 font-mono text-[12px] break-all">
                {prov.at}
                {prov.from && (
                  <span className="block text-fg-muted">
                    {t('finding.includedFrom', { from: prov.from })}
                  </span>
                )}
              </dd>
            </>
          )}
          {links
            .filter(([, v]) => !!v)
            .map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-fg-muted">{t(k)}</dt>
                <dd className="m-0 font-mono text-[12px] break-all">{v}</dd>
              </div>
            ))}
        </dl>
        {f.reasons.length > 0 && (
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0 text-[12.5px]">
            {f.reasons.map((r) => (
              <li key={r} className="text-warn">
                <span aria-hidden="true">▲ </span>
                {r}
              </li>
            ))}
          </ul>
        )}
        {f.unsupportedDirectives.length > 0 && (
          <div className="flex flex-wrap items-center gap-1 text-[12px]">
            <span className="text-fg-muted">{t('finding.unsupported')}</span>
            {f.unsupportedDirectives.map((d) => (
              <ToneBadge key={d} tone="info" glyph="◆" size="sm" className="font-mono">
                {d}
              </ToneBadge>
            ))}
          </div>
        )}
        {dupWith.length > 0 && (
          <div className="text-[12.5px] text-crit">
            {t('finding.duplicateWith')}{' '}
            {dupWith.map((d) => (
              <span key={d.id} className="font-mono">
                {d.provenance?.file ? `${d.provenance.file}:${d.provenance.line}` : d.title}
              </span>
            ))}
          </div>
        )}
      </div>
    </article>
  );
}

function ImportPanel({
  scan,
  selected,
  findings,
  onDone,
}: {
  scan: DiscoveryScan;
  selected: string[];
  findings: DiscoveryFinding[];
  onDone: () => void;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [mode, setMode] = useState<ImportMode>('observed');
  const m = useMutation<{ applications: Application[] }, ApiError>({
    mutationFn: async () => {
      try {
        return await discoveryApi.import(scan.id, selected, mode);
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['discovery-scans', 'one', scan.id] });
      void qc.invalidateQueries({ queryKey: ['applications'] });
      onDone();
    },
  });
  const modes: Array<[ImportMode, MessageKey, MessageKey]> = [
    ['observed', 'own.mode.observed', 'import.mode.observedDesc'],
    ['discovered', 'own.mode.discovered', 'import.mode.discoveredDesc'],
  ];
  const sel = findings.filter((f) => selected.includes(f.id));
  return (
    <Card className="flex flex-col gap-3 p-4 lg:sticky lg:top-4" aria-labelledby="import-title">
      <h2 id="import-title" className="m-0 text-[15px] font-semibold">
        {t('import.title')}
      </h2>
      <p className="m-0 text-[13px] text-fg-2">
        {sel.length ? t('import.selected', { n: sel.length }) : t('import.selectHint')}
      </p>
      <div role="radiogroup" aria-label={t('import.modeLabel')} className="flex flex-col gap-2">
        {modes.map(([v, label, desc]) => (
          <label
            key={v}
            className={cn(
              'flex cursor-pointer items-start gap-2 rounded-md border p-2.5 text-[13px]',
              mode === v ? 'border-accent-strong bg-info-bg' : 'border-line bg-surface',
            )}
          >
            <input
              type="radio"
              name="import-mode"
              className="mt-0.5"
              checked={mode === v}
              onChange={() => setMode(v)}
            />
            <span className="flex flex-col">
              <b>
                {t(label)}
                {v === 'observed' && (
                  <span className="ml-1.5 font-normal text-fg-muted">({t('import.default')})</span>
                )}
              </b>
              <span className="text-[12px] text-fg-muted">{t(desc)}</span>
            </span>
          </label>
        ))}
      </div>
      <Notice tone="warn" glyph="▲" role="note">
        {t('import.notOwnership')}
      </Notice>
      {sel.some((f) => f.manualReviewRequired) && (
        <Notice tone="info" glyph="◆" role="note">
          {t('import.manualReviewCarried')}
        </Notice>
      )}
      <GatedButton
        variant="primary"
        perm="servers.operate"
        disabled={!sel.length || m.isPending || scan.status !== 'completed'}
        onClick={() => m.mutate()}
      >
        {m.isPending
          ? t('import.importing')
          : t(mode === 'observed' ? 'import.confirmObserve' : 'import.confirmDiscover', {
              n: sel.length,
            })}
      </GatedButton>
      {m.error && <ErrorState error={m.error} />}
      {m.data && (
        <Notice tone="ok" glyph="●" role="status">
          <span data-testid="import-result">
            {t('import.done', { n: m.data.applications.length })}
          </span>
          <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0">
            {m.data.applications.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2">
                <Link href={`/applications/${a.id}/overview`} className="font-mono text-[12.5px]">
                  {a.name}
                </Link>
                <OwnershipBadge mode={a.ownershipMode} />
              </li>
            ))}
          </ul>
          <span className="mt-1 block text-[12.5px] text-fg-2">{t('import.noHostChange')}</span>
        </Notice>
      )}
    </Card>
  );
}

type DetailTab = 'findings' | 'files' | 'drift';

export function ScanDetail({ id }: { id: string }) {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const q = useScan(id);
  const servers = useServers();
  const scan = q.data;
  const fq = useFindings(id, scan?.status === 'completed');
  const srv = servers.data?.items.find((s) => s.id === scan?.serverId);
  useSetPageEnv(srv?.environment);
  const [tab, setTab] = useState<DetailTab>('findings');
  const [selected, setSelected] = useState<string[]>([]);
  const [manualOnly, setManualOnly] = useState(false);
  const findings = useMemo(() => fq.data?.items ?? [], [fq.data]);
  const grouped = useMemo(
    () =>
      FINDING_KINDS.map((k) => ({
        kind: k,
        items: findings.filter((f) => f.kind === k && (!manualOnly || f.manualReviewRequired)),
      })).filter((g) => g.items.length > 0),
    [findings, manualOnly],
  );

  let body: React.ReactNode = null;
  if (q.isPending) {
    body = (
      <div
        role="status"
        aria-busy="true"
        aria-label={t('common.loading')}
        className="flex flex-col gap-3"
      >
        <Skeleton className="h-7 w-72" />
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  } else if (q.isError && !scan) {
    const e = q.error;
    body =
      isApiError(e) && e.status === 404 ? (
        <EmptyState title={t('scan.notFound')} />
      ) : isApiError(e) && e.status === 403 ? (
        <ForbiddenState perm="fleet.read" requestId={e.requestId} />
      ) : (
        <ErrorState error={e} onRetry={() => void q.refetch()} />
      );
  }

  return (
    <div className="flex max-w-[1440px] flex-col gap-4 p-4 sm:p-6">
      <Link href="/imports" className="self-start text-[13px]">
        ← {t('imports.title')}
      </Link>
      {body}
      {scan && (
        <>
          <div className="flex flex-wrap items-start gap-3">
            <div className="flex min-w-[260px] flex-1 flex-col gap-1">
              <div className="font-mono text-[12px] text-fg-muted">
                {t('scan.crumb', { id: scan.id.slice(0, 8) })}
              </div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h1 className="m-0 text-[22px] font-semibold">
                  {t('scan.heading', { server: srv?.name ?? scan.serverId.slice(0, 8) })}
                </h1>
                {srv && <EnvBadge env={srv.environment} label={t(envBadgeKey(srv.environment))} />}
                <ScanStatusBadge status={scan.status} />
              </div>
              <div className="text-[13px] text-fg-muted">
                {t('scan.meta', {
                  started: formatDateTime(scan.startedAt, locale),
                  sources: (scan.sources ?? []).join(', ') || t('common.all'),
                })}
              </div>
            </div>
            <ToneBadge tone="ok">{t('scan.readOnlyBadge')}</ToneBadge>
          </div>
          {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
          {scan.status === 'running' && (
            <Notice tone="info" glyph="◌" role="status">
              <span data-testid="scan-running">
                {t('scan.runningBody', { job: scan.jobId.slice(0, 8) })}
              </span>
            </Notice>
          )}
          {(scan.status === 'failed' || scan.status === 'expired') && (
            <Notice
              tone="crit"
              glyph="✕"
              role="alert"
              title={t(`scan.status.${scan.status}` as MessageKey)}
            >
              {scan.error?.message ?? t('scan.failedBody')}
              {scan.error?.code && (
                <span className="ml-1 font-mono text-[12px]">({scan.error.code})</span>
              )}
            </Notice>
          )}
          {scan.summary && (
            <>
              <div className="flex flex-wrap gap-2" aria-label={t('scan.summaryLabel')}>
                <Stat label={t('scan.stat.nginx')} value={scan.summary.nginxServers} />
                <Stat label={t('scan.stat.upstreams')} value={scan.summary.upstreams} />
                <Stat
                  label={t('scan.stat.duplicates')}
                  value={scan.summary.duplicates}
                  tone="text-crit"
                />
                <Stat
                  label={t('scan.stat.manual')}
                  value={scan.summary.manualReview}
                  tone="text-warn"
                />
                <Stat label={t('scan.stat.php')} value={scan.summary.phpFpmPools} />
                <Stat label={t('scan.stat.listeners')} value={scan.summary.listeners} />
                <Stat label={t('scan.stat.containers')} value={scan.summary.containers} />
              </div>
              <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
                <span className="text-fg-muted">{t('scan.sources')}</span>
                {Object.entries(scan.summary.sourceStatus).map(([k, v]) => (
                  <ToneBadge
                    key={k}
                    tone={v === 'ok' ? 'ok' : v === 'error' ? 'crit' : 'off'}
                    size="sm"
                  >
                    <span className="font-mono">{k}</span> · {v}
                  </ToneBadge>
                ))}
              </div>
            </>
          )}
          {scan.drift.length > 0 && (
            <Notice
              tone={scan.drift.some((d) => d.changedBy === 'external') ? 'crit' : 'info'}
              glyph="≠"
              role="status"
            >
              {t('scan.driftNotice', { n: scan.drift.length })}{' '}
              <button
                type="button"
                className="border-0 bg-transparent p-0 text-link underline"
                onClick={() => setTab('drift')}
              >
                {t('scan.viewDrift')}
              </button>
            </Notice>
          )}
          <LocalTabs<DetailTab>
            label={t('scan.sections')}
            value={tab}
            onChange={setTab}
            tabs={[
              ['findings', `${t('scan.tab.findings')} (${findings.length})`],
              ['files', `${t('scan.tab.files')} (${scan.configFiles.length})`],
              ['drift', `${t('scan.tab.drift')} (${scan.drift.length})`],
            ]}
          />
          {tab === 'findings' && (
            <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <div className="flex flex-col gap-3">
                {scan.status !== 'completed' ? (
                  <EmptyState title={t('scan.noFindingsYet')} />
                ) : !can('nginx.read') ? (
                  <ForbiddenState perm="nginx.read" />
                ) : fq.isPending ? (
                  <TableSkeleton label={t('common.loading')} />
                ) : fq.isError ? (
                  <ErrorState error={fq.error} onRetry={() => void fq.refetch()} />
                ) : (
                  <>
                    <label className="inline-flex items-center gap-2 self-start text-[13px]">
                      <input
                        type="checkbox"
                        checked={manualOnly}
                        onChange={(e) => setManualOnly(e.target.checked)}
                      />
                      {t('scan.manualOnly')}
                    </label>
                    {grouped.length === 0 && <EmptyState title={t('scan.noFindings')} />}
                    {grouped.map((g) => (
                      <Card key={g.kind} className="overflow-hidden">
                        <CardHeader
                          title={t(`finding.kind.${g.kind}` as MessageKey)}
                          actions={
                            <span className="text-[12px] text-fg-muted">
                              {t('scan.items', { n: g.items.length })}
                            </span>
                          }
                        />
                        {g.items.map((f) => (
                          <FindingCard
                            key={f.id}
                            f={f}
                            all={findings}
                            selectable={f.kind === 'nginx_server'}
                            selected={selected.includes(f.id)}
                            onToggle={() =>
                              setSelected((cur) =>
                                cur.includes(f.id) ? cur.filter((x) => x !== f.id) : [...cur, f.id],
                              )
                            }
                          />
                        ))}
                      </Card>
                    ))}
                  </>
                )}
              </div>
              <ImportPanel
                scan={scan}
                selected={selected}
                findings={findings}
                onDone={() => setSelected([])}
              />
            </div>
          )}
          {tab === 'files' &&
            (scan.configFiles.length === 0 ? (
              <EmptyState title={t('scan.noFiles')} />
            ) : (
              <Table
                minWidth={640}
                head={
                  <>
                    <Th>{t('scan.col.path')}</Th>
                    <Th>{t('scan.col.sha')}</Th>
                    <Th>{t('scan.col.drift')}</Th>
                  </>
                }
              >
                {scan.configFiles.map((f) => {
                  const drifted = scan.drift.some((d) => d.path === f.path);
                  return (
                    <tr key={f.path}>
                      <Td className="font-mono text-[12px] break-all">{f.path}</Td>
                      <Td>
                        <Sha value={f.sha256} />
                      </Td>
                      <Td>
                        {drifted ? (
                          <ToneBadge tone="crit" glyph="≠" size="sm">
                            {t('flag.drift')}
                          </ToneBadge>
                        ) : (
                          <span className="text-[12px] text-fg-muted">{t('scan.unchanged')}</span>
                        )}
                      </Td>
                    </tr>
                  );
                })}
              </Table>
            ))}
          {tab === 'drift' &&
            (scan.drift.length === 0 ? (
              <EmptyState title={t('scan.noDrift')} body={t('scan.noDriftBody')} />
            ) : (
              <Table
                minWidth={760}
                head={
                  <>
                    <Th>{t('scan.col.path')}</Th>
                    <Th>{t('drift.col.change')}</Th>
                    <Th>{t('drift.col.by')}</Th>
                  </>
                }
              >
                {scan.drift.map((d) => (
                  <tr key={d.path}>
                    <Td className="font-mono text-[12px] break-all">{d.path}</Td>
                    <Td>
                      <span className="inline-flex items-center gap-1">
                        <Sha value={d.previousSha256} />
                        <span aria-hidden="true">→</span>
                        <span className="sr-only">{t('diff.to')}</span>
                        <Sha value={d.currentSha256} />
                      </span>
                    </Td>
                    <Td>
                      {d.changedBy === 'external' ? (
                        <ToneBadge tone="crit" glyph="≠">
                          {t('drift.external')}
                        </ToneBadge>
                      ) : (
                        <ToneBadge tone="ok">{t('drift.ppanel')}</ToneBadge>
                      )}
                    </Td>
                  </tr>
                ))}
              </Table>
            ))}
        </>
      )}
    </div>
  );
}
