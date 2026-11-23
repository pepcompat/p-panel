'use client';

import { useMemo, useState } from 'react';
import { useT } from '@/i18n/provider';
import { useDesignData, type DesignTone } from '@/mocks/use-design-data';
import { Card, CardHeader, DefList } from '@/components/ui/card';
import { OutlineTag, ToneBadge } from '@/components/ui/badge';
import { Input } from '@/components/ui/form';
import { Segmented } from '@/components/ui/segmented';
import { Notice } from '@/components/ui/states';
import { cn } from '@/lib/utils';
import { GlyphRow } from './operate';
import { LocalTabs, PreviewAction, PreviewPage, Table, Td, Th, riskTone } from './shared';

const hash = (s: string) => [...s].reduce((a, c) => (a * 31 + c.charCodeAt(0)) | 0, 7);

export function MonitoringPreview() {
  const t = useT();
  const d = useDesignData();
  const [range, setRange] = useState<'1h' | '6h' | '24h'>('1h');
  return (
    <PreviewPage
      title={t('preview.monitoring.title')}
      subtitle={t('preview.monitoring.subtitle')}
      actions={
        <Segmented
          label="Range"
          value={range}
          onChange={setRange}
          options={[
            { value: '1h', label: '1h' },
            { value: '6h', label: '6h' },
            { value: '24h', label: '24h' },
          ]}
        />
      }
    >
      <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,300px),1fr))] gap-3">
        {d.SERVERS.map((s) => {
          const base = parseInt(s.cpu, 10);
          const offline = 'offline' in s && s.offline;
          const bars = Array.from({ length: 30 }, (_, i) => {
            if ('stale' in s && s.stale && i > 22) return null; // gap, never 0
            const h = Math.abs(hash(`${s.name}${range}${i}`)) % 25;
            return Math.max(3, Math.min(100, (Number.isFinite(base) ? base : 30) + h - 12));
          });
          return (
            <Card key={s.name} className="flex flex-col gap-2 p-3.5">
              <div className="flex items-center gap-2">
                <span className="flex-1 font-mono text-[13px]">{s.name}</span>
                <ToneBadge tone={s.t as DesignTone}>{s.status}</ToneBadge>
              </div>
              {offline ? (
                <div className="grid h-16 place-items-center rounded bg-chip text-[12px] text-fg-muted">
                  agent offline · no samples
                </div>
              ) : (
                <div className="flex h-16 items-end gap-[2px]" aria-label={`CPU ${s.name}`}>
                  {bars.map((b, i) => (
                    <div
                      key={i}
                      className={cn(
                        'flex-1 rounded-t-[1px]',
                        b === null
                          ? 'bg-transparent'
                          : b >= 90
                            ? 'bg-crit'
                            : b >= 70
                              ? 'bg-warn'
                              : 'bg-accent',
                      )}
                      style={{ height: b === null ? 0 : `${b}%` }}
                    />
                  ))}
                </div>
              )}
              <span className="text-[12px] text-fg-muted">
                CPU now {s.cpu} · heartbeat {s.hb}
              </span>
            </Card>
          );
        })}
      </div>
    </PreviewPage>
  );
}

export function LogsPreview() {
  const t = useT();
  const d = useDesignData();
  const [sev, setSev] = useState<'all' | 'info' | 'warn' | 'error'>('all');
  const lines = useMemo(
    () =>
      Array.from({ length: 14 }, (_, i) => {
        const [s, srv, app, msg] = d.LOGT[(i * 5 + 3) % d.LOGT.length]!;
        const sec = i * 3;
        return {
          sev: s,
          srv,
          app,
          msg,
          time: `14:${String(20 + Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`,
        };
      }).reverse(),
    [d.LOGT],
  );
  const view = lines.filter((l) => sev === 'all' || l.sev === sev);
  return (
    <PreviewPage
      title={t('preview.logs.title')}
      subtitle={t('preview.logs.subtitle')}
      actions={<PreviewAction>Pause tail</PreviewAction>}
    >
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <span className="rounded-md border border-line-strong bg-surface px-3 py-1.5">
          <span className="text-fg-muted">Server:</span> All in scope ▾
        </span>
        <span className="rounded-md border border-line-strong bg-surface px-3 py-1.5">
          <span className="text-fg-muted">App:</span> All ▾
        </span>
        <span className="rounded-md border border-line-strong bg-surface px-3 py-1.5">
          <span className="text-fg-muted">Time:</span> Last 15 min ▾
        </span>
        <Segmented
          label="Severity"
          value={sev}
          onChange={setSev}
          options={[
            { value: 'all', label: 'all' },
            { value: 'info', label: 'info' },
            { value: 'warn', label: 'warn' },
            { value: 'error', label: 'error' },
          ]}
        />
      </div>
      <div className="overflow-hidden rounded-lg border border-line">
        <div className="flex justify-between bg-surface-2 px-4 py-2 text-[12px] text-fg-muted">
          <span>● live tail (sample)</span>
          <span>{view.length} lines · max 200 · newest first</span>
        </div>
        {/* host log lines are never translated */}
        <div
          lang="en"
          className="overflow-x-auto bg-terminal p-3 font-mono text-[12px] leading-relaxed text-terminal-fg"
        >
          {view.map((l, i) => (
            <div key={i} className="whitespace-nowrap">
              <span className="opacity-60">{l.time}</span>{' '}
              <span
                className={
                  l.sev === 'error'
                    ? 'text-red-400'
                    : l.sev === 'warn'
                      ? 'text-amber-300'
                      : 'text-sky-300'
                }
              >
                {(l.sev ?? '').toUpperCase().padEnd(5)}
              </span>{' '}
              <span className="opacity-80">{l.srv}</span>{' '}
              <span className="opacity-80">{l.app}</span> {l.msg}
            </div>
          ))}
        </div>
      </div>
    </PreviewPage>
  );
}

export function BackupsPreview() {
  const t = useT();
  const [target, setTarget] = useState<'sandbox' | 'prod'>('sandbox');
  const [confirm, setConfirm] = useState('');
  const snaps: Array<[string, string, DesignTone, string, string, string, string]> = [
    ['snap-1117', '17 Nov 02:00 ICT', 'stale', 'Snapshot OK', '4.2 GB', 'copied', 'b7e2…19af'],
    ['snap-1116', '16 Nov 02:00 ICT', 'ok', 'Restore verified', '4.1 GB', 'copied', '5c90…aa01'],
    ['snap-1115', '15 Nov 02:00 ICT', 'ok', 'Restore verified', '4.1 GB', 'copied', '1d2e…7b3c'],
    ['snap-1114', '14 Nov 02:00 ICT', 'crit', 'Failed · disk full', '—', '—', '—'],
  ];
  return (
    <PreviewPage
      title={t('preview.backups.title')}
      crumb={t('preview.backups.crumb')}
      subtitle={t('preview.backups.subtitle')}
    >
      <div className="flex flex-wrap gap-4 text-[12.5px]">
        <span>
          <b className="text-ok">●</b> Restore verified = restore tested
        </span>
        <span>
          <b className="text-stale">◐</b> Snapshot OK = backup succeeded, restore never tested
        </span>
      </div>
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Table
          head={
            <>
              <Th>Snapshot</Th>
              <Th>Status</Th>
              <Th>Size</Th>
              <Th>Offsite</Th>
              <Th>Checksum</Th>
              <Th />
            </>
          }
        >
          {snaps.map(([id, time, tone, st, size, off, sum]) => (
            <tr key={id}>
              <Td>
                <div className="font-mono text-[12.5px]">{id}</div>
                <div className="text-[12px] text-fg-muted">{time}</div>
              </Td>
              <Td>
                <ToneBadge tone={tone}>{st}</ToneBadge>
              </Td>
              <Td className="font-mono text-[12px]">{size}</Td>
              <Td className="text-[12.5px]">{off}</Td>
              <Td className="font-mono text-[12px]">{sum}</Td>
              <Td>
                <PreviewAction size="sm">Restore…</PreviewAction>
              </Td>
            </tr>
          ))}
        </Table>
        <Card as="aside" className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[16px] font-semibold">Restore snap-1117</h2>
          <Notice tone="warn" glyph="▲">
            Data restore ≠ config rollback or app rollback
          </Notice>
          <div role="radiogroup" aria-label="Restore target" className="flex flex-col gap-2">
            {(
              [
                ['sandbox', 'Isolated target (default)', 'restore-sandbox-01 / shop_db_verify'],
                ['prod', 'Overwrite production', 'destructive · approval required'],
              ] as const
            ).map(([k, a, b]) => (
              <button
                key={k}
                type="button"
                role="radio"
                aria-checked={target === k}
                onClick={() => setTarget(k)}
                className={cn(
                  'flex flex-col items-start rounded-md border p-2.5 text-left text-[13px]',
                  target === k ? 'border-accent-strong bg-info-bg' : 'border-line bg-surface',
                )}
              >
                <b>
                  {target === k ? '◉' : '○'} {a}
                </b>
                <span className="text-[12px] text-fg-muted">{b}</span>
              </button>
            ))}
          </div>
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[12.5px]">
            <li>
              <span className="text-ok">●</span> checksum matches manifest
            </li>
            <li>
              <span className="text-ok">●</span> 48 tables · 2.31M rows
            </li>
            {target === 'prod' && (
              <li>
                <span className="text-crit">✕</span> Data after 02:00 ICT will be lost (~3,420
                orders)
              </li>
            )}
          </ul>
          {target === 'prod' && (
            <label className="flex flex-col gap-1 text-[12.5px]">
              Type <code>shop-db</code> to confirm · the request goes to Platform Owner for approval
              <Input
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="font-mono"
              />
            </label>
          )}
          <PreviewAction variant={target === 'prod' ? 'danger' : 'primary'}>
            {target === 'prod' ? 'Request approval' : 'Restore to sandbox'}
          </PreviewAction>
        </Card>
      </div>
    </PreviewPage>
  );
}

export function AlertsPreview() {
  const t = useT();
  const d = useDesignData();
  return (
    <PreviewPage title={t('preview.alerts.title')}>
      <Card>
        <CardHeader title="Incidents" />
        {d.INC.map((i) => (
          <GlyphRow
            key={i.id}
            tone={i.t as DesignTone}
            title={i.title}
            meta={i.meta}
            right={
              <div className="flex gap-1.5">
                <PreviewAction size="sm">Acknowledge</PreviewAction>
                <PreviewAction size="sm">Resolve</PreviewAction>
              </div>
            }
          />
        ))}
      </Card>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-4">
        <Table
          head={
            <>
              <Th>Rule</Th>
              <Th>Condition</Th>
              <Th>Scope</Th>
              <Th>Channel</Th>
            </>
          }
          minWidth={480}
        >
          {[
            ['disk-high', 'disk > 90% for 5 min', 'all servers', 'ops-line'],
            ['agent-lost', 'heartbeat > 5 min', 'prod, uat', 'ops-line, email'],
            ['tls-expiry', 'cert < 14 days', 'all domains', 'email'],
          ].map((r) => (
            <tr key={r[0]}>
              <Td className="font-mono text-[12.5px]">{r[0]}</Td>
              <Td className="font-mono text-[12px]">{r[1]}</Td>
              <Td>{r[2]}</Td>
              <Td>{r[3]}</Td>
            </tr>
          ))}
        </Table>
        <Card>
          <CardHeader title="Channels" />
          {[
            ['ops-line', 'LINE Notify · #ops'],
            ['email', 'ops@w3.co'],
          ].map(([n, dest]) => (
            <div
              key={n}
              className="flex items-center gap-3 border-t border-line-subtle px-4 py-2.5 text-[13px] first:border-0"
            >
              <b className="min-w-[90px]">{n}</b>
              <span className="flex-1 text-fg-muted">{dest}</span>
              <PreviewAction size="sm">Test</PreviewAction>
            </div>
          ))}
        </Card>
      </div>
    </PreviewPage>
  );
}

type Tool = [string, string, string, string, string, string];

export function AiMcpPreview() {
  const t = useT();
  const d = useDesignData();
  const [tab, setTab] = useState<'conn' | 'agents' | 'tools' | 'jobs'>('conn');
  const [q, setQ] = useState('');
  const tools = (d.TOOLS as unknown as Tool[]).filter(
    (x) =>
      x[0].includes(q.trim().toLowerCase()) || x[1].toLowerCase().includes(q.trim().toLowerCase()),
  );
  return (
    <PreviewPage title={t('preview.ai.title')} subtitle={t('preview.ai.subtitle')}>
      <LocalTabs
        label="AI & MCP sections"
        value={tab}
        onChange={setTab}
        tabs={[
          ['conn', 'MCP connection'],
          ['agents', 'AI agents'],
          ['tools', 'Tool catalog'],
          ['jobs', 'AI jobs'],
        ]}
      />
      {tab === 'conn' && (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,380px),1fr))] items-start gap-4">
          <Card className="flex flex-col gap-2.5 p-4">
            <div className="flex items-center">
              <h2 className="m-0 flex-1 text-[15px] font-semibold">MCP endpoint</h2>
              <ToneBadge tone="off">not deployed</ToneBadge>
            </div>
            <DefList
              rows={[
                ['Endpoint', 'https://center.w3.local/mcp', { mono: true }],
                ['Transport', 'Streamable HTTP'],
                ['Authorization', 'OAuth 2.1 + PKCE · audience w3-mcp'],
                ['Limits', '60 req/min per client · 256 KB request'],
              ]}
            />
          </Card>
          <Card className="flex flex-col gap-2.5 p-4">
            <h2 className="m-0 text-[15px] font-semibold">Connect a client</h2>
            <pre className="m-0 rounded-md bg-terminal p-3 font-mono text-[12px] whitespace-pre-wrap text-terminal-fg">
              claude mcp add --transport http w3 https://center.w3.local/mcp
            </pre>
            <span className="text-[12px] text-fg-muted">
              Sign-in happens in the browser through OAuth. This snippet contains no token or
              credential.
            </span>
          </Card>
        </div>
      )}
      {tab === 'agents' && (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,320px),1fr))] gap-3">
          {d.INIT_AGENTS.map((a) => (
            <Card as="article" key={a.id} className="flex flex-col gap-2 p-4">
              <div className="flex items-center gap-2">
                <b className="flex-1">{a.name}</b>
                <ToneBadge
                  tone={a.state === 'active' ? 'ok' : a.state === 'revoked' ? 'crit' : 'off'}
                >
                  {a.state}
                </ToneBadge>
              </div>
              <DefList
                keyWidth={90}
                rows={[
                  ['Owner', a.owner],
                  ['Environments', a.envs],
                  ['Groups', a.groups],
                  ['Scopes', a.scopes, { mono: true }],
                  ['Last activity', a.last],
                ]}
              />
              <div className="flex gap-2">
                <PreviewAction size="sm">Disable</PreviewAction>
                <PreviewAction size="sm">Revoke</PreviewAction>
              </div>
            </Card>
          ))}
        </div>
      )}
      {tab === 'tools' && (
        <>
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search tools…"
            aria-label="Search tools"
            className="max-w-[320px]"
          />
          <Table
            head={
              <>
                <Th>Tool</Th>
                <Th>Area</Th>
                <Th>Risk</Th>
                <Th>Claude Code</Th>
                <Th>Codex</Th>
                <Th>Hermes</Th>
              </>
            }
          >
            {tools.map((x) => (
              <tr key={x[0]}>
                <Td className="font-mono text-[12.5px]">{x[0]}</Td>
                <Td>{x[1]}</Td>
                <Td>
                  <ToneBadge tone={riskTone(x[2])} glyph={false} size="sm">
                    {x[2]}
                  </ToneBadge>
                </Td>
                <Td className="text-[12.5px]">{x[3]}</Td>
                <Td className="text-[12.5px]">{x[4]}</Td>
                <Td className="text-[12.5px]">{x[5]}</Td>
              </tr>
            ))}
          </Table>
          <span className="text-[12px] text-fg-muted">
            No tool exposes an interactive shell or arbitrary command.
          </span>
        </>
      )}
      {tab === 'jobs' && (
        <Card className="flex flex-col gap-3 p-4">
          <h2 className="m-0 text-[15px] font-semibold">
            ai-772 · Production deploy shop-frontend
          </h2>
          <ol className="m-0 flex list-none flex-col gap-1.5 p-0">
            {(d.AI_STAGES as readonly string[]).map((s, i) => (
              <li key={s} className="flex items-center gap-3 text-[13px]">
                <span
                  aria-hidden="true"
                  className={i < 3 ? 'text-ok' : i === 3 ? 'text-warn' : 'text-off'}
                >
                  {i < 3 ? '●' : i === 3 ? '◆' : '○'}
                </span>
                <span className="min-w-[150px]">{s}</span>
                <OutlineTag>{(d.AI_ACTOR as readonly string[])[i]}</OutlineTag>
              </li>
            ))}
          </ol>
          <Notice tone="info" glyph="◆">
            AI proposed · awaiting human approval in Approvals. Only the Center authorizes, executes
            and verifies.
          </Notice>
        </Card>
      )}
    </PreviewPage>
  );
}
