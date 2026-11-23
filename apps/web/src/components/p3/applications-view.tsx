'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { ENVIRONMENTS, type Environment } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { isApiError } from '@/lib/api/errors';
import { OWNERSHIP_ORDER, type Application, type OwnershipMode } from '@/lib/api/p3-types';
import { useApplications } from '@/lib/p3-queries';
import { useServers } from '@/lib/queries';
import { envBadgeKey, envLabelKey } from '@/lib/servers';
import { Page, PageHeader } from '@/components/ui/card';
import { EnvBadge } from '@/components/ui/badge';
import { Field, Input, Select } from '@/components/ui/form';
import { TableSkeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState, ForbiddenState, Notice } from '@/components/ui/states';
import { Table, Td, Th } from '@/components/preview/shared';
import { FlagBadges, OwnershipBadge, ownKey } from './bits';
import type { MessageKey } from '@/i18n/en';

type FlagFilter = '' | 'manualReview' | 'conflict' | 'unsupported' | 'driftDetected';

export function ApplicationsTable({
  apps,
  showServer = true,
}: {
  apps: Application[];
  showServer?: boolean;
}) {
  const { t } = useI18n();
  const servers = useServers();
  return (
    <Table
      minWidth={860}
      head={
        <>
          <Th>{t('apps.col.app')}</Th>
          <Th>{t('apps.col.ownership')}</Th>
          <Th>{t('apps.col.flags')}</Th>
          {showServer && <Th>{t('apps.col.server')}</Th>}
          <Th>{t('apps.col.env')}</Th>
          <Th>{t('apps.col.domains')}</Th>
        </>
      }
    >
      {apps.map((a) => {
        const srvName = a.serverName ?? servers.data?.items.find((s) => s.id === a.serverId)?.name;
        return (
          <tr key={a.id} className="hover:bg-surface-hover" data-testid="app-row">
            <Td>
              <Link
                href={`/applications/${a.id}/overview`}
                className="font-mono text-[12.5px] font-medium"
              >
                {a.name}
              </Link>
              <div className="text-[12px] text-fg-muted">
                {t(`apps.kind.${a.kind}` as MessageKey)}
              </div>
            </Td>
            <Td>
              <OwnershipBadge mode={a.ownershipMode} />
            </Td>
            <Td>
              <FlagBadges flags={a.flags} compact />
            </Td>
            {showServer && (
              <Td>
                <Link
                  href={`/servers/${a.serverId}/overview`}
                  className="font-mono text-[12px] text-fg"
                >
                  {srvName ?? a.serverId.slice(0, 8)}
                </Link>
              </Td>
            )}
            <Td>
              <EnvBadge
                env={a.environment}
                label={t(envBadgeKey(a.environment))}
                className="px-1.5 text-[10.5px]"
              />
            </Td>
            <Td className="font-mono text-[12px] break-all">
              {a.domains.slice(0, 3).join(', ')}
              {a.domains.length > 3 && (
                <span className="text-fg-muted"> +{a.domains.length - 3}</span>
              )}
            </Td>
          </tr>
        );
      })}
    </Table>
  );
}

export function ApplicationsView() {
  const { t } = useI18n();
  const { can } = useAuth();
  const servers = useServers();
  const [q, setQ] = useState('');
  const [mode, setMode] = useState<'' | OwnershipMode>('');
  const [env, setEnv] = useState<'' | Environment>('');
  const [serverId, setServerId] = useState('');
  const [flag, setFlag] = useState<FlagFilter>('');
  const query = useApplications({
    ownership_mode: mode || undefined,
    environment: env || undefined,
    server_id: serverId || undefined,
    q: q.trim() || undefined,
  });
  const forbidden = !can('apps.read') || (isApiError(query.error) && query.error.status === 403);
  const items = useMemo(
    () => (query.data?.items ?? []).filter((a) => !flag || a.flags[flag]),
    [query.data, flag],
  );
  const drifted = items.filter((a) => a.flags.driftDetected).length;

  return (
    <Page>
      <PageHeader
        title={t('apps.title')}
        subtitle={
          query.data
            ? t('apps.subtitle', { shown: items.length, total: query.data.paginate.total })
            : t('apps.subtitleLoading')
        }
        actions={
          <Link href="/imports" className="text-[13px]">
            {t('apps.toImports')}
          </Link>
        }
      />
      {forbidden ? (
        <ForbiddenState
          perm="apps.read"
          requestId={isApiError(query.error) ? query.error.requestId : null}
        />
      ) : (
        <>
          <div
            className="flex flex-wrap items-end gap-3"
            role="search"
            aria-label={t('apps.filters')}
          >
            <Field label={t('apps.search')} className="w-[220px]">
              {(p) => (
                <Input
                  {...p}
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="app.example.lab"
                />
              )}
            </Field>
            <Field label={t('apps.col.ownership')} className="w-[160px]">
              {(p) => (
                <Select
                  {...p}
                  value={mode}
                  onChange={(e) => setMode(e.target.value as OwnershipMode | '')}
                >
                  <option value="">{t('common.all')}</option>
                  {OWNERSHIP_ORDER.map((m) => (
                    <option key={m} value={m}>
                      {t(ownKey(m))}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('apps.col.env')} className="w-[150px]">
              {(p) => (
                <Select
                  {...p}
                  value={env}
                  onChange={(e) => setEnv(e.target.value as Environment | '')}
                >
                  <option value="">{t('common.all')}</option>
                  {ENVIRONMENTS.map((e) => (
                    <option key={e} value={e}>
                      {t(envLabelKey(e))}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('apps.col.server')} className="w-[180px]">
              {(p) => (
                <Select {...p} value={serverId} onChange={(e) => setServerId(e.target.value)}>
                  <option value="">{t('common.all')}</option>
                  {(servers.data?.items ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t('apps.col.flags')} className="w-[170px]">
              {(p) => (
                <Select {...p} value={flag} onChange={(e) => setFlag(e.target.value as FlagFilter)}>
                  <option value="">{t('common.all')}</option>
                  <option value="manualReview">{t('flag.manualReview')}</option>
                  <option value="conflict">{t('flag.conflict')}</option>
                  <option value="unsupported">{t('flag.unsupported')}</option>
                  <option value="driftDetected">{t('flag.drift')}</option>
                </Select>
              )}
            </Field>
          </div>
          <Notice tone="neutral" role="note">
            {t('apps.ownershipNote')}
          </Notice>
          {drifted > 0 && (
            <Notice tone="crit" glyph="≠" role="status">
              {t('apps.driftWarning', { n: drifted })}
            </Notice>
          )}
          {query.isError && <ErrorState error={query.error} onRetry={() => void query.refetch()} />}
          {query.isPending ? (
            <TableSkeleton label={t('common.loading')} />
          ) : items.length === 0 && !query.isError ? (
            <EmptyState
              title={t('apps.empty')}
              body={t('apps.emptyBody')}
              action={<Link href="/imports">{t('apps.toImports')}</Link>}
            />
          ) : items.length > 0 ? (
            <ApplicationsTable apps={items} />
          ) : null}
        </>
      )}
    </Page>
  );
}
