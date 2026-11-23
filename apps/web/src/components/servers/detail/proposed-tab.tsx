'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import type { Server } from '@ppanel/shared-contracts';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { auditApi } from '@/lib/api/endpoints';
import { address, isLive, type ServerTab } from '@/lib/servers';
import { formatDateTime } from '@/lib/time';
import { useDesignData, type DesignTone } from '@/mocks/use-design-data';
import { Card } from '@/components/ui/card';
import { ToneBadge, OutlineTag } from '@/components/ui/badge';
import { GatedButton } from '@/components/ui/gated-button';
import { TableSkeleton } from '@/components/ui/skeleton';
import { ErrorState, ForbiddenState, ProposedBanner } from '@/components/ui/states';
import { ServerMeters } from '../server-bits';
import type { MessageKey } from '@/i18n/en';

function SampleLabel() {
  const { t } = useI18n();
  return <span className="font-mono text-[11px] text-info">◆ {t('state.preview.title')}</span>;
}

function Rows({ rows }: { rows: Array<{ tone?: DesignTone; cells: React.ReactNode[] }> }) {
  return (
    <ul className="m-0 list-none p-0">
      {rows.map((r, i) => (
        <li
          key={i}
          className="flex flex-wrap items-center gap-3 border-t border-line-subtle px-4 py-2.5 text-[13px] first:border-0"
        >
          {r.cells.map((c, j) => (
            <span key={j} className={j === 0 ? 'min-w-[150px] font-medium' : 'text-fg-3'}>
              {c}
            </span>
          ))}
        </li>
      ))}
    </ul>
  );
}

function EventsTab({ server }: { server: Server }) {
  const { t, locale } = useI18n();
  const { can } = useAuth();
  const q = useQuery({
    queryKey: ['audit', { target_id: server.id }],
    queryFn: () => auditApi.list({ target_id: server.id, limit: 20 }),
    enabled: can('audit.read'),
  });
  if (!can('audit.read')) return <ForbiddenState perm="audit.read" />;
  return (
    <Card>
      <div className="flex items-center gap-2 border-b border-line-soft px-4 py-3">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">{t('tab.events')}</h2>
        <Link href={`/settings/audit?target_id=${server.id}`} className="text-[13px]">
          {t('audit.title')} →
        </Link>
      </div>
      {q.isPending ? (
        <TableSkeleton label={t('common.loading')} />
      ) : q.isError ? (
        <div className="p-4">
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        </div>
      ) : q.data.items.length === 0 ? (
        <p className="m-0 p-4 text-[13px] text-fg-muted">{t('audit.empty')}</p>
      ) : (
        <Rows
          rows={q.data.items.map((e) => ({
            cells: [
              <span key="t" className="font-mono text-[12px]">
                {formatDateTime(e.createdAt, locale)}
              </span>,
              <span key="a" className="font-mono">
                {e.action}
              </span>,
              e.actorLabel ?? e.actorId ?? 'system',
              <ToneBadge
                key="r"
                tone={e.result === 'success' ? 'ok' : e.result === 'denied' ? 'crit' : 'warn'}
              >
                {t(`audit.result.${e.result}` as MessageKey)}
              </ToneBadge>,
            ],
          }))}
        />
      )}
    </Card>
  );
}

export function ProposedTab({
  server,
  tab,
  now,
}: {
  server: Server;
  tab: Exclude<ServerTab, 'overview' | 'network' | 'settings'>;
  now: number;
}) {
  const { t } = useI18n();
  const d = useDesignData();
  const name = server.name;
  const blocked = isLive(server)
    ? ({ key: 'perm.proposed' } as const)
    : ({ key: 'perm.offline' } as const);

  let sample: React.ReactNode = null;
  switch (tab) {
    case 'applications': {
      const apps = d.APPS.filter((a) => a.server === name);
      sample = apps.length ? (
        <Rows
          rows={apps.map((a) => ({
            cells: [
              a.id,
              `${a.type} · ${a.domain}`,
              <OutlineTag key="o">{a.own}</OutlineTag>,
              <ToneBadge key="h" tone={a.t as DesignTone}>
                {a.health}
              </ToneBadge>,
            ],
          }))}
        />
      ) : (
        <p className="m-0 px-4 py-5 text-[13px] text-fg-muted">
          No applications discovered on this server. Run a read-only discovery scan to populate
          inventory.
        </p>
      );
      break;
    }
    case 'terminal': {
      const priv = address(server, 'private');
      sample = (
        <div className="flex flex-col gap-3 p-4">
          <div className="flex flex-wrap gap-x-5 gap-y-1 font-mono text-[12px]">
            {[
              ['server', name],
              ['endpoint', priv?.address ?? '—'],
              ['user', 'deploy'],
              ['port', '22'],
              ['auth', 'ED25519 · Center secret store'],
              [
                'scope',
                server.environment === 'production' ? 'step-up MFA + JIT approval' : 'role binding',
              ],
            ].map(([k, v]) => (
              <span key={k}>
                <span className="text-fg-muted">{k}</span> {v}
              </span>
            ))}
          </div>
          <div className="h-48 rounded-md bg-terminal p-3 font-mono text-[12.5px] text-terminal-fg/60">
            $ _
          </div>
          <GatedButton
            variant="dark"
            className="self-start"
            perm="ssh.connect"
            action="open_terminal"
            allowedActions={server.allowedActions}
            blockedReason={blocked}
          >
            {t('detail.openTerminal')}
          </GatedButton>
        </div>
      );
      break;
    }
    case 'firewall': {
      const pols = d.FW_POL.filter(
        (p) => !('draft' in p && p.draft) && (p.scope === 'all' || server.tags.includes(p.scope)),
      );
      const local =
        (
          d.FW_LOCAL as Record<
            string,
            Array<{ a: string; dir: string; port: string; src: string; note: string }>
          >
        )[name] ?? [];
      const rules = [
        ...pols.flatMap((p) => p.rules.map((r) => ({ ...r, origin: `shared · ${p.name}` }))),
        ...local.map((r) => ({ ...r, origin: 'local' })),
      ];
      sample = (
        <Rows
          rows={rules.map((r) => ({
            cells: [
              <ToneBadge key="a" tone={r.a === 'ALLOW' ? 'ok' : 'crit'} glyph={false}>
                {r.a}
              </ToneBadge>,
              <span key="p" className="font-mono">{`${r.dir} ${r.port}`}</span>,
              <span key="s" className="font-mono">
                {r.src}
              </span>,
              <OutlineTag key="o">{r.origin}</OutlineTag>,
              r.note,
            ],
          }))}
        />
      );
      break;
    }
    case 'software':
      sample = (
        <Rows
          rows={d.INSTALLED.filter((i) => i[1] === name).map((i) => ({
            cells: [
              i[0],
              <span key="v" className="font-mono">
                {i[2]}
              </span>,
              i[3],
              <ToneBadge key="s" tone={i[4] as DesignTone}>
                {i[5]}
              </ToneBadge>,
            ],
          }))}
        />
      );
      break;
    case 'runtimes': {
      const groups =
        (
          d.RT as unknown as Record<
            string,
            Array<[string, Array<[string, string, string, string, boolean?]>]>
          >
        )[name] ?? [];
      sample = groups.length ? (
        <Rows
          rows={groups.flatMap(([g, items]) =>
            items.map((i) => ({
              cells: [`${g} · ${i[0]}`, <OutlineTag key="s">{i[1]}</OutlineTag>, i[2], i[3]],
            })),
          )}
        />
      ) : (
        <p className="m-0 px-4 py-5 text-[13px] text-fg-muted">{t('common.noData')}</p>
      );
      break;
    }
    case 'databases':
      sample = (
        <Rows
          rows={d.DBS.filter((x) => x.server === name).map((x) => ({
            cells: [
              x.name,
              x.engine,
              <span key="b" className="font-mono">
                {x.bind}
              </span>,
              <ToneBadge key="s" tone={x.t as DesignTone}>
                {x.state}
              </ToneBadge>,
              x.backup,
            ],
          }))}
        />
      );
      break;
    case 'monitoring':
      sample = (
        <div className="flex max-w-[520px] flex-col gap-2 p-4">
          <ServerMeters server={server} size="md" now={now} />
          <Link href="/monitoring" className="text-[13px]">
            {t('nav.monitoring')} →
          </Link>
        </div>
      );
      break;
    case 'logs':
      sample = (
        <div className="overflow-x-auto bg-terminal p-3 font-mono text-[12px] leading-relaxed text-terminal-fg">
          {d.LOGT.filter((l) => l[1] === name).map((l, i) => (
            <div key={i}>
              <span
                className={
                  l[0] === 'error'
                    ? 'text-red-400'
                    : l[0] === 'warn'
                      ? 'text-amber-300'
                      : 'text-sky-300'
                }
              >
                {(l[0] ?? '').toUpperCase().padEnd(5)}
              </span>{' '}
              {l[2]} · {l[3]}
            </div>
          ))}
          {d.LOGT.every((l) => l[1] !== name) && (
            <div className="opacity-60">— no sample lines for this server —</div>
          )}
        </div>
      );
      break;
    case 'backups':
      sample = (
        <p className="m-0 px-4 py-5 text-[13px]">
          <Link href="/backups">{t('nav.backups')} →</Link>
        </p>
      );
      break;
    case 'events':
      return <EventsTab server={server} />;
  }

  return (
    <div className="flex flex-col gap-4">
      <ProposedBanner body={t(`proposed.${tab}` as MessageKey)} />
      <Card>
        <div className="flex items-center gap-2 border-b border-line-soft px-4 py-3">
          <h2 className="m-0 flex-1 text-[15px] font-semibold">{t(`tab.${tab}`)}</h2>
          <SampleLabel />
        </div>
        {sample}
      </Card>
    </div>
  );
}
