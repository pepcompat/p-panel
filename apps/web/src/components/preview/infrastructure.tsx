'use client';

import { useState } from 'react';
import { useT } from '@/i18n/provider';
import { useDesignData, type DesignTone } from '@/mocks/use-design-data';
import { Card, CardHeader, DefList } from '@/components/ui/card';
import { OutlineTag, ToneBadge } from '@/components/ui/badge';
import { Input } from '@/components/ui/form';
import { Notice } from '@/components/ui/states';
import { cn } from '@/lib/utils';
import { LocalTabs, PreviewAction, PreviewPage, Table, Td, Th, riskTone } from './shared';

export function FirewallPreview() {
  const t = useT();
  const d = useDesignData();
  const [tab, setTab] = useState<'shared' | 'server'>('shared');
  const [pid, setPid] = useState(d.FW_POL[0]!.id);
  const pol = d.FW_POL.find((p) => p.id === pid) ?? d.FW_POL[0]!;
  const lockout = 'lockout' in pol && pol.lockout;
  return (
    <PreviewPage title={t('preview.firewall.title')} subtitle={t('preview.firewall.subtitle')}>
      <LocalTabs
        label="Firewall views"
        value={tab}
        onChange={setTab}
        tabs={[
          ['shared', 'Shared policies'],
          ['server', 'Per server'],
        ]}
      />
      {tab === 'shared' ? (
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,300px)_minmax(0,1fr)]">
          <Card className="overflow-hidden">
            <CardHeader
              title="Shared policies"
              actions={<PreviewAction size="sm">+ New policy</PreviewAction>}
            />
            {d.FW_POL.map((p) => (
              <button
                key={p.id}
                type="button"
                aria-pressed={p.id === pid}
                onClick={() => setPid(p.id)}
                className={cn(
                  'flex w-full items-center gap-2 border-0 border-t border-line-subtle px-4 py-2.5 text-left first:border-t-0',
                  p.id === pid ? 'bg-info-bg' : 'bg-surface hover:bg-surface-hover',
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-[12.5px]">{p.name}</div>
                  <div className="text-[12px] text-fg-muted">
                    {p.scopeLabel} · {p.rules.length} rules
                  </div>
                </div>
                <ToneBadge tone={'draft' in p && p.draft ? 'warn' : 'ok'}>
                  {'draft' in p && p.draft ? 'draft' : `rev ${p.rev}`}
                </ToneBadge>
              </button>
            ))}
          </Card>
          <div className="flex flex-col gap-4">
            <Table
              head={
                <>
                  <Th>Action</Th>
                  <Th>Direction</Th>
                  <Th>Proto/Port</Th>
                  <Th>Source / Dest</Th>
                  <Th>Notes</Th>
                </>
              }
              minWidth={560}
            >
              {pol.rules.map((r, i) => (
                <tr key={i}>
                  <Td>
                    <ToneBadge tone={r.a === 'ALLOW' ? 'ok' : 'crit'} glyph={false}>
                      {r.a}
                    </ToneBadge>
                  </Td>
                  <Td>{r.dir}</Td>
                  <Td className="font-mono text-[12px]">{r.port}</Td>
                  <Td className="font-mono text-[12px]">{r.src}</Td>
                  <Td className="text-[12.5px] text-fg-muted">{r.note}</Td>
                </tr>
              ))}
            </Table>
            {lockout && (
              <Notice
                tone="crit"
                glyph="✕"
                role="alert"
                title="Apply blocked: this policy would lock out management access"
              >
                Fix the rules or register a safe recovery mechanism, then request Platform Owner
                approval. There is no override button.
              </Notice>
            )}
            <div className="flex gap-2">
              <PreviewAction>+ Add rule</PreviewAction>
              <PreviewAction variant="primary">Push policy…</PreviewAction>
            </div>
            <p className="m-0 text-[12px] text-fg-muted">
              Rollout order: dev → uat → (approval) → production · an agent that loses connection
              within 60 s after apply rolls back automatically.
            </p>
          </div>
        </div>
      ) : (
        <Table
          head={
            <>
              <Th>Server</Th>
              <Th>Backend</Th>
              <Th>Rules</Th>
              <Th>Status</Th>
            </>
          }
        >
          {d.SERVERS.map((s) => (
            <tr key={s.name}>
              <Td className="font-mono text-[12.5px]">{s.name}</Td>
              <Td>
                <OutlineTag>nftables</OutlineTag> <OutlineTag>DO Cloud Firewall</OutlineTag>
              </Td>
              <Td className="font-mono text-[12px]">
                {(d.FW_LOCAL as Record<string, unknown[]>)[s.name]?.length ?? 0} local + shared
              </Td>
              <Td>
                <ToneBadge tone={s.t as DesignTone}>{s.status}</ToneBadge>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </PreviewPage>
  );
}

export function SshPreview() {
  const t = useT();
  const d = useDesignData();
  const [tab, setTab] = useState<'terminal' | 'keys' | 'hosts' | 'grants'>('keys');
  return (
    <PreviewPage title={t('preview.ssh.title')} subtitle={t('preview.ssh.subtitle')}>
      <LocalTabs
        label="SSH sections"
        value={tab}
        onChange={setTab}
        tabs={[
          ['terminal', 'Terminal'],
          ['keys', 'Keys'],
          ['hosts', 'Host keys'],
          ['grants', 'Access grants'],
        ]}
      />
      {tab === 'terminal' && (
        <Card className="flex flex-col gap-3 p-4">
          <b className="text-[13.5px]">Pick a server to open a session</b>
          <div className="flex flex-wrap gap-2">
            {d.SERVERS.map((s) => (
              <PreviewAction key={s.name} size="sm" className="font-mono">
                {s.name}
              </PreviewAction>
            ))}
          </div>
          <div className="h-40 rounded-md bg-terminal p-3 font-mono text-[12.5px] text-terminal-fg/60">
            no session
          </div>
        </Card>
      )}
      {tab === 'keys' && (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <PreviewAction variant="primary">Generate key pair</PreviewAction>
            <PreviewAction>Upload private key</PreviewAction>
            <span className="text-[12px] text-fg-muted">
              Private keys are stored only in the Center secret store and are never shown again.
            </span>
          </div>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,340px),1fr))] gap-3">
            {d.INIT_KEYS.map((k) => (
              <Card as="article" key={k.name} className="flex flex-col gap-2 p-4">
                <div className="flex items-center gap-2">
                  <b className="flex-1 font-mono text-[13.5px]">{k.name}</b>
                  <ToneBadge tone={k.state === 'active' ? 'ok' : 'warn'}>{k.state}</ToneBadge>
                </div>
                <span className="font-mono text-[11.5px] break-all text-fg-muted">{k.fp}</span>
                <DefList
                  keyWidth={90}
                  rows={[
                    ['Storage', k.store],
                    ['Assigned', k.assigned],
                    ['Last used', k.last],
                  ]}
                />
                <div className="flex gap-2">
                  <PreviewAction size="sm">Rotate…</PreviewAction>
                  <PreviewAction size="sm">Revoke…</PreviewAction>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}
      {tab === 'hosts' && (
        <Table
          head={
            <>
              <Th>Server</Th>
              <Th>Algorithm</Th>
              <Th>Fingerprint</Th>
              <Th>Status</Th>
            </>
          }
        >
          {d.SERVERS.slice(0, 5).map((s, i) => (
            <tr key={s.name}>
              <Td className="font-mono text-[12.5px]">{s.name}</Td>
              <Td>ED25519</Td>
              <Td className="font-mono text-[11.5px]">
                SHA256:{(s.name + 'q2vX1n7Lw0yPpR4dJk9fT3mZ').slice(0, 24)}…
              </Td>
              <Td>
                <ToneBadge tone={i === 2 ? 'crit' : 'ok'}>
                  {i === 2 ? 'Changed · connection blocked' : 'Approved (TOFU)'}
                </ToneBadge>
              </Td>
            </tr>
          ))}
        </Table>
      )}
      {tab === 'grants' && (
        <Card>
          {[
            ['Somchai W.', 'deploy@app-prod-01:22', '30 min', 'ok', 'active'],
            ['Nat K.', 'deploy@app-uat-01:22', 'expired 13:10', 'off', 'expired'],
          ].map(([u, s, e, tone, st]) => (
            <div
              key={s}
              className="flex flex-wrap items-center gap-3 border-t border-line-subtle px-4 py-2.5 text-[13px] first:border-0"
            >
              <span className="min-w-[110px]">{u}</span>
              <span className="flex-1 font-mono text-[12px]">{s}</span>
              <span className="text-fg-muted">{e}</span>
              <ToneBadge tone={tone as DesignTone}>{st}</ToneBadge>
            </div>
          ))}
        </Card>
      )}
    </PreviewPage>
  );
}

type Plugin = [
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string[]?,
];

export function PluginsPreview() {
  const t = useT();
  const d = useDesignData();
  const plugins = d.PLUGINS as unknown as Plugin[];
  const [tab, setTab] = useState<'catalog' | 'installed'>('catalog');
  const [cat, setCat] = useState('All');
  const [sel, setSel] = useState<string | null>(null);
  const cats = ['All', ...new Set(plugins.map((p) => p[2]))];
  const list = plugins.filter((p) => cat === 'All' || p[2] === cat);
  const p = plugins.find((x) => x[0] === sel);
  const inst = d.PL_INST as Record<string, string>;
  return (
    <PreviewPage title={t('preview.plugins.title')} subtitle={t('preview.plugins.subtitle')}>
      <LocalTabs
        label="Plugin views"
        value={tab}
        onChange={setTab}
        tabs={[
          ['catalog', 'Catalog'],
          ['installed', 'Installed'],
        ]}
      />
      {tab === 'catalog' ? (
        <>
          <div className="flex flex-wrap gap-1.5">
            {cats.map((c) => (
              <button
                key={c}
                type="button"
                aria-pressed={c === cat}
                onClick={() => setCat(c)}
                className={cn(
                  'min-h-8 rounded-full border px-3 text-[12.5px]',
                  c === cat
                    ? 'border-sidebar bg-sidebar text-sidebar-fg-strong'
                    : 'border-line-strong bg-surface',
                )}
              >
                {c}{' '}
                <span className="font-mono text-[11px] opacity-70">
                  {c === 'All' ? plugins.length : plugins.filter((x) => x[2] === c).length}
                </span>
              </button>
            ))}
          </div>
          <div className={cn('grid items-start gap-4', p && 'lg:grid-cols-[minmax(0,1fr)_360px]')}>
            <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,240px),1fr))] gap-3">
              {list.map((x) => (
                <button
                  key={x[0]}
                  type="button"
                  aria-pressed={x[0] === sel}
                  onClick={() => setSel(x[0])}
                  className={cn(
                    'flex flex-col gap-1.5 rounded-lg border bg-surface p-3.5 text-left',
                    x[0] === sel ? 'border-accent-strong' : 'border-line',
                  )}
                >
                  <div className="flex items-center gap-2">
                    <b className="flex-1 text-[14px]">{x[1]}</b>
                    <span className="font-mono text-[11px] text-fg-muted">{x[4]}</span>
                  </div>
                  <span className="text-[12.5px] text-fg-3">{x[3]}</span>
                  <div className="flex flex-wrap gap-1.5">
                    <ToneBadge tone={x[5] === 'verified' ? 'ok' : 'off'} size="sm">
                      {x[5] === 'verified' ? 'verified adapter' : 'catalog only'}
                    </ToneBadge>
                    <ToneBadge tone={riskTone(x[6])} glyph={false} size="sm">
                      {x[6]}
                    </ToneBadge>
                    {inst[x[0]] && <OutlineTag>{inst[x[0]]}</OutlineTag>}
                  </div>
                </button>
              ))}
            </div>
            {p && (
              <Card as="aside" className="flex flex-col gap-2.5 p-4">
                <div className="flex items-center">
                  <h2 className="m-0 flex-1 text-[16px] font-semibold">{p[1]}</h2>
                  <button
                    type="button"
                    aria-label={t('common.close')}
                    onClick={() => setSel(null)}
                    className="h-8 w-8 border-0 bg-transparent"
                  >
                    ✕
                  </button>
                </div>
                <span className="text-[13px] text-fg-3">{p[3]}</span>
                <DefList
                  keyWidth={110}
                  rows={[
                    ['Support', p[5]],
                    ['OS', 'Ubuntu 22.04/24.04 · Debian 12 · amd64/arm64'],
                    ['Versions', p[4]],
                    ['Dependencies', p[7]],
                    ['Risk', p[6]],
                    ['Actions', p[8]],
                    ['Verification', p[9]],
                    ['Manifest', `signed · ${p[0]}.manifest.json`],
                  ]}
                />
                {p[5] !== 'verified' ? (
                  <Notice tone="neutral" glyph="○">
                    Not installable — no verified adapter yet (PROPOSED). Listed for planning only.
                  </Notice>
                ) : (
                  <PreviewAction variant="primary">Install…</PreviewAction>
                )}
              </Card>
            )}
          </div>
        </>
      ) : (
        <Table
          head={
            <>
              <Th>Plugin</Th>
              <Th>Server</Th>
              <Th>Version</Th>
              <Th>Managed by</Th>
              <Th>State</Th>
            </>
          }
        >
          {d.INSTALLED.map((i, n) => (
            <tr key={n}>
              <Td>{i[0]}</Td>
              <Td className="font-mono text-[12.5px]">{i[1]}</Td>
              <Td className="font-mono text-[12px]">{i[2]}</Td>
              <Td className="text-[12.5px]">{i[3]}</Td>
              <Td>
                <ToneBadge tone={i[4] as DesignTone}>{i[5]}</ToneBadge>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </PreviewPage>
  );
}

type RtGroups = Array<[string, Array<[string, string, string, string, boolean?]>]>;

export function RuntimesPreview() {
  const t = useT();
  const d = useDesignData();
  const rt = d.RT as unknown as Record<string, RtGroups>;
  const names = Object.keys(rt);
  const [srv, setSrv] = useState(names[0]!);
  return (
    <PreviewPage title={t('preview.runtimes.title')} subtitle={t('preview.runtimes.subtitle')}>
      <div className="flex flex-wrap gap-1.5">
        {d.SERVERS.map((s) => (
          <button
            key={s.name}
            type="button"
            aria-pressed={s.name === srv}
            onClick={() => setSrv(s.name)}
            className={cn(
              'min-h-8 rounded-md border px-3 font-mono text-[12.5px]',
              s.name === srv ? 'border-accent-strong bg-info-bg' : 'border-line-strong bg-surface',
            )}
          >
            {s.name}
          </button>
        ))}
      </div>
      {rt[srv] ? (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] items-start gap-4">
          {rt[srv]!.map(([g, items]) => (
            <Card key={g} className="flex flex-col gap-2 p-4">
              <h2 className="m-0 text-[15px] font-semibold">{g}</h2>
              {items.length === 0 && <span className="text-[12.5px] text-fg-muted">—</span>}
              {items.map((i) => (
                <div key={i[0]} className="flex flex-col gap-1 rounded-md border border-line p-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <b className="flex-1 font-mono text-[13px]">{i[0]}</b>
                    <OutlineTag>{i[1]}</OutlineTag>
                    <ToneBadge
                      tone={
                        i[2] === 'Running' || i[2] === 'In use' || i[2] === 'Default' ? 'ok' : 'off'
                      }
                      size="sm"
                    >
                      {i[2]}
                    </ToneBadge>
                  </div>
                  <span className="text-[12px] text-fg-muted">{i[3]}</span>
                  {i[4] && (
                    <div className="flex gap-2">
                      <PreviewAction size="sm">Restart</PreviewAction>
                      <PreviewAction size="sm">Reload</PreviewAction>
                    </div>
                  )}
                </div>
              ))}
            </Card>
          ))}
        </div>
      ) : (
        <Notice tone="neutral" glyph="○">
          No runtime inventory for {srv} in the sample data.
        </Notice>
      )}
    </PreviewPage>
  );
}

export function DatabasesPreview() {
  const t = useT();
  const d = useDesignData();
  const [name, setName] = useState('');
  return (
    <PreviewPage
      title={t('preview.databases.title')}
      subtitle={t('preview.databases.subtitle')}
      actions={<PreviewAction variant="primary">+ Create database</PreviewAction>}
    >
      <Table
        head={
          <>
            <Th>Name</Th>
            <Th>Engine</Th>
            <Th>Host · bind</Th>
            <Th>Databases</Th>
            <Th>Status</Th>
            <Th>Backup</Th>
          </>
        }
        minWidth={860}
      >
        {d.DBS.map((x) => (
          <tr key={x.name}>
            <Td className="font-mono text-[12.5px]">{x.name}</Td>
            <Td>{x.engine}</Td>
            <Td className="font-mono text-[12px]">
              {x.server} · {x.bind}
            </Td>
            <Td className="text-[12.5px]">{x.dbs}</Td>
            <Td>
              <ToneBadge tone={x.t as DesignTone}>{x.state}</ToneBadge>
            </Td>
            <Td>
              <ToneBadge tone={x.bt as DesignTone}>{x.backup}</ToneBadge>
            </Td>
          </tr>
        ))}
      </Table>
      <Card className="flex max-w-[560px] flex-col gap-3 p-4">
        <h2 className="m-0 text-[15px] font-semibold">Create PostgreSQL database</h2>
        <label className="flex flex-col gap-1 text-[12.5px] text-fg-3">
          Database name
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="font-mono"
            placeholder="shop_reports"
          />
        </label>
        <span className="font-mono text-[12px] text-fg-muted">
          owner password: •••••••• generated · secret://db/{name || '…'}/owner
        </span>
        <PreviewAction variant="primary">Create</PreviewAction>
      </Card>
    </PreviewPage>
  );
}
