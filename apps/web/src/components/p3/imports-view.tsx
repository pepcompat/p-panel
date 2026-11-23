'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { DISCOVERY_SOURCES, type Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { discoveryApi } from '@/lib/api/endpoints';
import { isApiError, toApiError, type ApiError } from '@/lib/api/errors';
import type { DiscoveryScan, DiscoverySource } from '@/lib/api/p3-types';
import { useScans } from '@/lib/p3-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey, isLive } from '@/lib/servers';
import { formatDateTime, relativeTime } from '@/lib/time';
import { useNow } from '@/lib/use-now';
import { Page, PageHeader } from '@/components/ui/card';
import { EnvBadge, ToneBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog } from '@/components/ui/dialog';
import { Field, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { Table, Td, Th } from '@/components/preview/shared';
import { ScanStatusBadge } from './bits';
import type { MessageKey } from '@/i18n/en';

export function serverLabel(servers: Server[] | undefined, id: string) {
  return servers?.find((s) => s.id === id);
}

function SummaryCell({ scan }: { scan: DiscoveryScan }) {
  const { t } = useI18n();
  if (!scan.summary)
    return (
      <span className="text-[12px] text-fg-muted">
        {scan.error?.code ?? (scan.status === 'running' ? t('scan.running') : t('common.dash'))}
      </span>
    );
  const s = scan.summary;
  return (
    <span className="flex flex-wrap gap-1.5 text-[12px]">
      <span>{t('scan.sum.nginx', { n: s.nginxServers })}</span>
      <span aria-hidden="true">·</span>
      <span className={s.manualReview ? 'text-warn' : undefined}>
        {t('scan.sum.manual', { n: s.manualReview })}
      </span>
      <span aria-hidden="true">·</span>
      <span className={s.duplicates ? 'text-crit' : undefined}>
        {t('scan.sum.dup', { n: s.duplicates })}
      </span>
      {scan.drift.length > 0 && (
        <>
          <span aria-hidden="true">·</span>
          <span className="text-crit">{t('scan.sum.drift', { n: scan.drift.length })}</span>
        </>
      )}
    </span>
  );
}

export function RunScanDialog({
  open,
  onOpenChange,
  defaultServerId,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  defaultServerId?: string;
}) {
  const { t } = useI18n();
  const router = useRouter();
  const qc = useQueryClient();
  const servers = useServers();
  const candidates = (servers.data?.items ?? []).filter((s) => s.status !== 'revoked');
  const [serverId, setServerId] = useState(defaultServerId ?? '');
  const [sources, setSources] = useState<DiscoverySource[]>([...DISCOVERY_SOURCES]);
  const selected = candidates.find((s) => s.id === serverId);

  const m = useMutation<{ scanId: string }, ApiError>({
    mutationFn: async () => {
      try {
        return await discoveryApi.run(serverId, sources);
      } catch (e) {
        throw toApiError(e);
      }
    },
    onSuccess: ({ scanId }) => {
      void qc.invalidateQueries({ queryKey: ['discovery-scans'] });
      onOpenChange(false);
      router.push(`/imports/${scanId}`);
    },
  });

  const toggle = (s: DiscoverySource) =>
    setSources((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) m.reset();
        onOpenChange(o);
      }}
      closeLabel={t('common.close')}
      className="max-w-[520px]"
      badge={
        <ToneBadge tone="ok" className="self-start">
          {t('scan.readOnlyBadge')}
        </ToneBadge>
      }
      title={t('scan.run.title')}
      description={t('scan.run.body')}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            disabled={!serverId || !sources.length || m.isPending}
            onClick={() => m.mutate()}
          >
            {m.isPending ? t('scan.run.starting') : t('scan.run.confirm')}
          </Button>
        </>
      }
    >
      <Field label={t('scan.run.server')}>
        {(p) => (
          <Select {...p} value={serverId} onChange={(e) => setServerId(e.target.value)}>
            <option value="">{t('scan.run.pickServer')}</option>
            {candidates.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} · {t(envBadgeKey(s.environment))} · {t(`status.${s.status}` as MessageKey)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0">
        <legend className="mb-1 text-[12.5px] text-fg-3">{t('scan.run.sources')}</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-1.5">
          {DISCOVERY_SOURCES.map((s) => (
            <label key={s} className="inline-flex items-center gap-1.5 text-[13px]">
              <input type="checkbox" checked={sources.includes(s)} onChange={() => toggle(s)} />
              <span className="font-mono">{s}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <Notice tone="ok" glyph="●" role="note">
        {t('scan.run.readOnly')}
      </Notice>
      {selected && !isLive(selected) && (
        <Notice tone="warn" glyph="◐" role="status">
          {t('scan.run.offline', { name: selected.name })}
        </Notice>
      )}
      {m.error && <ErrorState error={m.error} />}
    </Dialog>
  );
}

export function ImportsView() {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const now = useNow(10_000);
  const [serverFilter, setServerFilter] = useState('');
  const [open, setOpen] = useState(false);
  const servers = useServers();
  const q = useScans(serverFilter ? { server_id: serverFilter } : {});
  const forbidden = !can('fleet.read') || (isApiError(q.error) && q.error.status === 403);
  const items = q.data?.items ?? [];

  return (
    <Page>
      <PageHeader
        title={t('imports.title')}
        subtitle={t('imports.subtitle')}
        actions={
          <GatedButton variant="primary" perm="nginx.read" onClick={() => setOpen(true)}>
            {t('scan.run.open')}
          </GatedButton>
        }
      />
      <Notice tone="info" glyph="◆" role="note">
        {t('imports.principle')}
      </Notice>
      {forbidden ? (
        <ForbiddenState
          perm="fleet.read"
          requestId={isApiError(q.error) ? q.error.requestId : null}
        />
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-3">
            <Field label={t('imports.filterServer')} className="w-[260px]">
              {(p) => (
                <Select
                  {...p}
                  value={serverFilter}
                  onChange={(e) => setServerFilter(e.target.value)}
                >
                  <option value="">{t('common.all')}</option>
                  {(servers.data?.items ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {q.dataUpdatedAt > 0 && (
              <span className="pb-2 text-[12px] text-fg-muted">
                {t('common.lastUpdated', {
                  time: relativeTime(new Date(q.dataUpdatedAt).toISOString(), t, now),
                })}
              </span>
            )}
          </div>
          {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
          {q.isPending ? (
            <TableSkeleton label={t('common.loading')} />
          ) : items.length === 0 && !q.isError ? (
            <EmptyState
              title={t('imports.empty')}
              body={t('imports.emptyBody')}
              action={
                <GatedButton size="sm" perm="nginx.read" onClick={() => setOpen(true)}>
                  {t('scan.run.open')}
                </GatedButton>
              }
            />
          ) : items.length > 0 ? (
            <Table
              minWidth={860}
              head={
                <>
                  <Th>{t('scan.col.server')}</Th>
                  <Th>{t('scan.col.status')}</Th>
                  <Th>{t('scan.col.started')}</Th>
                  <Th>{t('scan.col.completed')}</Th>
                  <Th>{t('scan.col.summary')}</Th>
                  <Th>
                    <span className="sr-only">{t('scan.col.open')}</span>
                  </Th>
                </>
              }
            >
              {items.map((scan) => {
                const srv = serverLabel(servers.data?.items, scan.serverId);
                return (
                  <tr key={scan.id} className="hover:bg-surface-hover" data-testid="scan-row">
                    <Td>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[12.5px]">
                          {srv?.name ?? scan.serverId.slice(0, 8)}
                        </span>
                        {srv && (
                          <EnvBadge
                            env={srv.environment}
                            label={t(envBadgeKey(srv.environment))}
                            className="px-1.5 text-[10.5px]"
                          />
                        )}
                      </div>
                    </Td>
                    <Td>
                      <ScanStatusBadge status={scan.status} />
                    </Td>
                    <Td className="text-[12px] whitespace-nowrap">
                      <time
                        dateTime={scan.startedAt}
                        title={formatDateTime(scan.startedAt, locale)}
                      >
                        {relativeTime(scan.startedAt, t, now)}
                      </time>
                    </Td>
                    <Td className="text-[12px] whitespace-nowrap">
                      {scan.completedAt
                        ? formatDateTime(scan.completedAt, locale)
                        : t('common.dash')}
                    </Td>
                    <Td>
                      <SummaryCell scan={scan} />
                    </Td>
                    <Td className="text-right">
                      <Link href={`/imports/${scan.id}`} className="text-[13px] whitespace-nowrap">
                        {t('scan.open')}
                      </Link>
                    </Td>
                  </tr>
                );
              })}
            </Table>
          ) : null}
        </>
      )}
      {open && <RunScanDialog open={open} onOpenChange={setOpen} />}
    </Page>
  );
}
