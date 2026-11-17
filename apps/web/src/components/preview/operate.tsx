'use client';

import { useState } from 'react';
import { useT } from '@/i18n/provider';
import { useDesignData, type DesignTone } from '@/mocks/use-design-data';
import { Card, CardHeader, DefList } from '@/components/ui/card';
import { OutlineTag, ToneBadge, TONE_GLYPH, toneText } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Notice } from '@/components/ui/states';
import { cn } from '@/lib/utils';
import { LocalTabs, PreviewAction, PreviewPage, Table, Td, Th, riskTone } from './shared';

export function ApplicationsPreview() {
  const t = useT();
  const d = useDesignData();
  const [sel, setSel] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'deployments' | 'env'>('overview');
  const app = d.APPS.find((a) => a.id === sel);
  if (app) {
    return (
      <PreviewPage
        title={app.id}
        crumb={
          <Button variant="link" className="font-sans text-[13px]" onClick={() => setSel(null)}>
            ← {t('nav.applications')}
          </Button>
        }
        subtitle={`${app.type} · ${app.env} · ${app.server} · ${app.domain}`}
        actions={
          <div className="flex gap-2">
            <OutlineTag>{app.own}</OutlineTag>
            <ToneBadge tone={app.t as DesignTone}>{app.health}</ToneBadge>
          </div>
        }
      >
        <LocalTabs label="Application sections" value={tab} onChange={setTab} tabs={[['overview', 'Overview'], ['deployments', 'Deployments'], ['env', 'Env & Secrets']]} />
        {tab === 'overview' && (
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,380px),1fr))] items-start gap-4">
            <Card className="p-4">
              <DefList rows={[['Last deploy', app.dep], ['Health check', 'GET /api/health · 200 · every 30 s'], ['Proxy', 'Existing Nginx · managed include'], [t('nav.backups'), 'shop-prod-daily · latest snapshot not verified']]} />
            </Card>
            <Card className="flex flex-col gap-2 p-4">
              <h2 className="m-0 text-[15px] font-semibold">Actions</h2>
              {d.ACTIONS.map((a) => (
                <div key={a.k} className="flex items-start gap-3 border-t border-line-subtle pt-2 first:border-0 first:pt-0">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <b className="text-[13.5px]">{a.label}</b>
                      <ToneBadge tone={a.t as DesignTone} glyph={false} size="sm" className="font-mono">
                        {a.cls}
                      </ToneBadge>
                    </div>
                    <div className="text-[12.5px] text-fg-muted">{a.effect}</div>
                  </div>
                  <PreviewAction size="sm">{a.label}…</PreviewAction>
                </div>
              ))}
            </Card>
          </div>
        )}
        {tab === 'deployments' && (
          <Card>
            {['a41f9c2 · checkout v2', 'f02b8e1 · cart fixes', '9c1e7d0 · deps bump'].map((r, i) => (
              <div key={r} className="flex items-center gap-3 border-t border-line-subtle px-4 py-2.5 text-[13px] first:border-0">
                <span className="flex-1 font-mono">{r}</span>
                <ToneBadge tone={i === 0 ? 'ok' : 'off'}>{i === 0 ? 'Live' : 'Superseded'}</ToneBadge>
              </div>
            ))}
          </Card>
        )}
        {tab === 'env' && (
          <Card>
            {[
              ['NEXT_PUBLIC_API_URL', 'https://api.shop.w3.co', 'env'],
              ['DATABASE_URL', '•••••••• · rotated Nov 3', 'secret'],
              ['STRIPE_SECRET_KEY', '•••••••• · set today', 'secret'],
            ].map(([k, v, ty]) => (
              <div key={k} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_70px] gap-3 border-t border-line-subtle px-4 py-2.5 font-mono text-[12.5px] first:border-0">
                <span>{k}</span>
                <span className="text-fg-muted">{v}</span>
                <OutlineTag>{ty}</OutlineTag>
              </div>
            ))}
          </Card>
        )}
      </PreviewPage>
    );
  }
  return (
    <PreviewPage title={t('preview.applications.title')} subtitle={t('preview.applications.subtitle')} actions={<PreviewAction variant="primary">{t('overview.newDeploy')}</PreviewAction>}>
      <Table head={<><Th>App</Th><Th>Env · Server</Th><Th>Domain</Th><Th>Ownership</Th><Th>Health</Th><Th>Last deploy</Th></>}>
        {d.APPS.map((a) => (
          <tr key={a.id} className="hover:bg-surface-hover">
            <Td>
              <Button variant="link" onClick={() => setSel(a.id)} className="font-medium">
                {a.id}
              </Button>
              <div className="text-[12px] text-fg-muted">{a.type}</div>
            </Td>
            <Td>
              {a.env} · <span className="font-mono text-[12px]">{a.server}</span>
            </Td>
            <Td className="font-mono text-[12px]">{a.domain}</Td>
            <Td>
              <OutlineTag>{a.own}</OutlineTag>
            </Td>
            <Td>
              <ToneBadge tone={a.t as DesignTone}>{a.health}</ToneBadge>
            </Td>
            <Td className="font-mono text-[12px]">{a.dep}</Td>
          </tr>
        ))}
      </Table>
    </PreviewPage>
  );
}

export function DeploymentsPreview() {
  const t = useT();
  const d = useDesignData();
  const [step, setStep] = useState(0);
  const steps = d.STEPS;
  const cur = steps[step]![0];
  return (
    <PreviewPage title={t('preview.deployments.title')} crumb={t('preview.deployments.crumb')}>
      <ol className="m-0 flex list-none flex-wrap gap-1.5 p-0">
        {steps.map(([k, label], i) => (
          <li key={k}>
            <button
              type="button"
              aria-current={i === step ? 'step' : undefined}
              onClick={() => setStep(i)}
              className={cn('flex min-h-9 items-center gap-2 rounded-md border px-3 text-[13px]', i === step ? 'border-accent-strong bg-info-bg' : 'border-line bg-surface')}
            >
              <span className="font-mono text-[11px] text-fg-muted">
                {i + 1} {i < step ? '●' : i === step ? '◆' : '○'}
              </span>
              {label}
            </button>
          </li>
        ))}
      </ol>
      <Card className="flex flex-col gap-3 p-5">
        {cur === 'source' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Source</h2>
            <div className="grid grid-cols-[repeat(auto-fit,minmax(180px,1fr))] gap-2.5">
              {[['◉ GitHub', 'Repos connected via GitHub App'], ['○ Image@digest', 'Registry, pinned by sha256'], ['○ Compose', 'YAML validated before use'], ['○ Existing app', 'From Discovery']].map(([a, b], i) => (
                <div key={a} className={cn('rounded-md border p-3 text-[13px]', i === 0 ? 'border-accent-strong' : 'border-line')}>
                  <b>{a}</b>
                  <div className="text-fg-muted">{b}</div>
                </div>
              ))}
            </div>
            <DefList rows={[['Repository', 'w3co/shop-frontend', { mono: true }], ['Branch', 'main', { mono: true }], ['Commit (pin)', 'a41f9c2 · “checkout v2”', { mono: true }]]} />
          </>
        )}
        {cur === 'detect' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Runtime detection</h2>
            <Notice tone="ok" glyph="●" title="Next.js 14">
              96% confidence · from package.json, next.config.mjs · Build: generated Dockerfile (node:20-alpine)
            </Notice>
            <p className="m-0 text-[13px] text-fg-muted">Not right? Choose runtime manually · builds run on a separate builder, never on Center</p>
          </>
        )}
        {cur === 'target' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Target</h2>
            {[['◉ app-prod-01', 'docker · nginx · 41% disk', 'recommended'], ['○ app-prod-02', 'docker · nginx', ''], ['○ db-prod-01', 'no docker capability', 'not eligible']].map(([a, b, c]) => (
              <div key={a} className="flex flex-wrap gap-3 rounded-md border border-line px-3 py-2 text-[13px]">
                <b className="font-mono">{a}</b>
                <span className="text-fg-muted">{b}</span>
                <span className="text-fg-subtle">{c}</span>
              </div>
            ))}
            <p className="m-0 text-[12.5px] text-fg-muted">Resource limit: 1 vCPU · 1 GiB RAM · host mounts / privileged not allowed</p>
          </>
        )}
        {cur === 'configure' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Configure</h2>
            <DefList rows={[['Port', '3000', { mono: true }], ['Health check', 'GET /api/health · 200', { mono: true }], ['STRIPE_SECRET_KEY', 'not set — secret required', { className: 'text-crit' }]]} />
          </>
        )}
        {cur === 'domain' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Domain &amp; Proxy</h2>
            <DefList rows={[['Hostname', 'shop.w3.co', { mono: true }], ['TLS', 'Let’s Encrypt (HTTP-01)']]} />
            <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[13px]">
              <li><span className="text-ok">●</span> DNS A record points to 203.0.113.24 (app-prod-01)</li>
              <li><span className="text-ok">●</span> No conflict with other server_name in existing Nginx</li>
              <li><span className="text-warn">▲</span> Ports 80/443 are owned by existing Nginx · route added via managed include, no new proxy started</li>
            </ul>
          </>
        )}
        {cur === 'review' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Review plan</h2>
            <ol className="m-0 flex flex-col gap-1 pl-5 text-[13px]">
              <li>Build image from <code>a41f9c2</code> → push with digest</li>
              <li>Start candidate container on app-prod-01 (current container untouched)</li>
              <li>Health check 5 times within 60 seconds</li>
              <li>Switch Nginx route (<code>nginx -t</code> before reload) · reversible</li>
              <li>Stop old container after 10 minutes</li>
            </ol>
            <Notice tone="crit" glyph="✕" title="Deploy blocked by 1 item">
              · set <code>STRIPE_SECRET_KEY</code> and preflight will re-run
            </Notice>
          </>
        )}
        {cur === 'run' && (
          <>
            <h2 className="m-0 text-[16px] font-semibold">Execution</h2>
            <p className="m-0 text-[13px] text-fg-muted">No job is running — jobs are not implemented in the Center yet.</p>
            <div className="rounded-md bg-terminal p-3 font-mono text-[12px] text-terminal-fg opacity-70">— live tail · press Pause to stop scrolling —</div>
          </>
        )}
        <div className="flex justify-between gap-2 border-t border-line-subtle pt-3">
          <Button disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
            {t('common.back')}
          </Button>
          {step < steps.length - 1 ? (
            <Button variant="primary" onClick={() => setStep((s) => s + 1)}>
              {t('common.next')}
            </Button>
          ) : (
            <PreviewAction variant="primary">Start deploy</PreviewAction>
          )}
        </div>
      </Card>
    </PreviewPage>
  );
}

export function ApprovalsPreview() {
  const t = useT();
  const d = useDesignData();
  const [sel, setSel] = useState(d.INIT_APR[0]!.id);
  const apr = d.INIT_APR.find((a) => a.id === sel) ?? d.INIT_APR[0]!;
  const stTone = (s: string): DesignTone => (s === 'pending' ? 'warn' : s === 'approved' ? 'ok' : 'off');
  return (
    <PreviewPage title={t('preview.approvals.title')} subtitle={t('preview.approvals.subtitle')}>
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
        <Card className="overflow-hidden">
          {d.INIT_APR.map((a) => (
            <button
              key={a.id}
              type="button"
              aria-pressed={a.id === sel}
              onClick={() => setSel(a.id)}
              className={cn('flex w-full flex-col gap-0.5 border-0 border-t border-line-subtle px-4 py-3 text-left first:border-t-0', a.id === sel ? 'bg-info-bg' : 'bg-surface hover:bg-surface-hover')}
            >
              <div className="flex items-center gap-2">
                <span className="flex-1 font-mono text-[12px]">
                  {a.id} · <span className={toneText[riskTone(a.risk)]}>{a.risk}</span>
                </span>
                <ToneBadge tone={stTone(a.state)}>{a.state}</ToneBadge>
              </div>
              <span className="text-[13.5px] font-medium">{a.title}</span>
              <span className="text-[12px] text-fg-muted">{a.by}</span>
            </button>
          ))}
        </Card>
        <Card className="flex flex-col gap-3 p-4">
          <div className="flex items-center gap-2">
            <h2 className="m-0 flex-1 text-[16px] font-semibold">{apr.title}</h2>
            <ToneBadge tone={stTone(apr.state)}>{apr.state}</ToneBadge>
          </div>
          <DefList rows={apr.fields.map(([k, v]) => [k, v, { mono: true }] as [string, string, { mono: boolean }])} />
          {'self' in apr && apr.self && (
            <Notice tone="warn" glyph="▲">
              Requesters cannot approve their own requests.
            </Notice>
          )}
          {apr.state === 'pending' && (
            <div className="flex flex-wrap gap-2">
              <PreviewAction>Reject</PreviewAction>
              <PreviewAction variant="primary">Approve with 2FA</PreviewAction>
            </div>
          )}
        </Card>
      </div>
    </PreviewPage>
  );
}

export function ImportsPreview() {
  const t = useT();
  const d = useDesignData();
  const [sel, setSel] = useState(d.FINDINGS[0]!.id);
  const [mode, setMode] = useState('observe');
  const f = d.FINDINGS.find((x) => x.id === sel) ?? d.FINDINGS[0]!;
  const writes = mode === 'adopt' || mode === 'managed';
  return (
    <PreviewPage
      title={t('preview.imports.title')}
      crumb={t('preview.imports.crumb')}
      subtitle={t('preview.imports.subtitle')}
      actions={<ToneBadge tone="ok">read-only · no changes made</ToneBadge>}
    >
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
        <Card className="overflow-hidden">
          <CardHeader title="Server blocks found" actions={<span className="text-[12px] text-fg-muted">{d.FINDINGS.length} items</span>} />
          {d.FINDINGS.map((x) => (
            <button
              key={x.id}
              type="button"
              aria-pressed={x.id === sel}
              onClick={() => setSel(x.id)}
              className={cn('flex w-full items-center gap-2 border-0 border-t border-line-subtle px-4 py-2.5 text-left first:border-t-0', x.id === sel ? 'bg-info-bg' : 'bg-surface hover:bg-surface-hover')}
            >
              <div className="min-w-0 flex-1">
                <div className="font-mono text-[12.5px]">{x.domain}</div>
                <div className="text-[12px] text-fg-muted">
                  {x.kind} · confidence {x.conf}
                </div>
              </div>
              <ToneBadge tone={x.t as DesignTone}>{x.flag}</ToneBadge>
            </button>
          ))}
        </Card>
        <div className="flex flex-col gap-4">
          <Card className="flex flex-col gap-2.5 p-4">
            <div className="flex items-center gap-2">
              <h2 className="m-0 flex-1 font-mono text-[15px] font-semibold">{f.domain}</h2>
              <ToneBadge tone={f.t as DesignTone}>{f.flag}</ToneBadge>
            </div>
            <DefList rows={[['Provenance', f.file, { mono: true }], ['Upstream', f.upstream, { mono: true }], ['Linked to', f.linked], ['TLS', f.tls], ['Notes', f.note]]} />
          </Card>
          <Card className="flex flex-col gap-2.5 p-4">
            <h2 className="m-0 text-[15px] font-semibold">Ownership level</h2>
            <div role="radiogroup" aria-label="Ownership level" className="grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-2">
              {d.MODES.map(([k, label, desc]) => (
                <button
                  key={k}
                  type="button"
                  role="radio"
                  aria-checked={mode === k}
                  onClick={() => setMode(k ?? 'observe')}
                  className={cn('flex flex-col items-start gap-0.5 rounded-md border p-2.5 text-left text-[13px]', mode === k ? 'border-accent-strong bg-info-bg' : 'border-line bg-surface')}
                >
                  <b>
                    {mode === k ? '◉' : '○'} {label}
                  </b>
                  <span className="text-[12px] text-fg-muted">{desc}</span>
                </button>
              ))}
            </div>
            {writes && (
              <Notice tone="crit" glyph="✕" title="Privileged">
                · requires <code>nginx.write</code> + 2FA + Platform Owner approval because this is PRODUCTION · importing into inventory is separate from taking ownership
              </Notice>
            )}
            <div className="flex gap-2">
              <PreviewAction>Send to manual review</PreviewAction>
              <PreviewAction variant="primary">{writes ? 'Request approval & apply + reload' : 'Import as Observe'}</PreviewAction>
            </div>
          </Card>
        </div>
      </div>
    </PreviewPage>
  );
}

export function GlyphRow({ tone, title, meta, right }: { tone: DesignTone; title: string; meta?: string; right?: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 border-t border-line-subtle px-4 py-2.5 first:border-0">
      <span aria-hidden="true" className={cn('w-3.5 font-bold', toneText[tone])}>
        {TONE_GLYPH[tone]}
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[13.5px]">{title}</div>
        {meta && <div className="text-[12px] text-fg-subtle">{meta}</div>}
      </div>
      {right}
    </div>
  );
}
