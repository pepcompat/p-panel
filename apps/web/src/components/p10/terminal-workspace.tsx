'use client';

import { useEffect, useRef, useState } from 'react';
import { useI18n } from '@/i18n/provider';
import type { SshGrant } from '@/lib/api/p10-types';
import { minutesLeft } from '@/lib/p10-gates';
import { useMyActiveGrants } from '@/lib/p10-queries';
import { pathKey } from '@/components/p9/net-bits';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Field, Select } from '@/components/ui/form';
import { GatedButton } from '@/components/ui/gated-button';
import { EmptyState, Notice } from '@/components/ui/states';
import { cn } from '@/lib/utils';
import { TerminalPane, type PanePhase } from './terminal-pane';

interface Tab {
  key: string;
  grant: SshGrant;
  phase: PanePhase;
}

const DOT: Record<PanePhase, string> = {
  stepup: 'text-warn',
  creating: 'text-info',
  connecting: 'text-info',
  authenticating: 'text-info',
  ready: 'text-ok',
  closed: 'text-off',
  failed: 'text-crit',
};

/** Tabbed terminal sessions. Each tab is one SSH session through the Center gateway. */
export function TerminalWorkspace({
  openRequest,
  onRequestGrant,
}: {
  /** ask to open a session for this grant id (nonce makes repeats distinct) */
  openRequest: { grantId: string; nonce: number } | null;
  onRequestGrant: () => void;
}) {
  const { t } = useI18n();
  const grants = useMyActiveGrants();
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [pick, setPick] = useState('');
  const [missing, setMissing] = useState(false);
  const seq = useRef(0);
  const handled = useRef<number | null>(null);
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const open = (g: SshGrant) => {
    const key = `t${++seq.current}`;
    setTabs((ts) => [...ts, { key, grant: g, phase: 'creating' }]);
    setActive(key);
  };

  useEffect(() => {
    if (!openRequest || grants.isPending || handled.current === openRequest.nonce) return;
    handled.current = openRequest.nonce;
    const g = grants.data.find((x) => x.id === openRequest.grantId);
    setMissing(!g);
    if (g) {
      const key = `t${++seq.current}`;
      setTabs((ts) => [...ts, { key, grant: g, phase: 'creating' }]);
      setActive(key);
    }
  }, [openRequest, grants.isPending, grants.data]);

  const closeTab = (key: string) => {
    setTabs((ts) => {
      const idx = ts.findIndex((x) => x.key === key);
      const next = ts.filter((x) => x.key !== key);
      if (active === key) setActive(next[Math.max(0, idx - 1)]?.key ?? null);
      return next;
    });
  };

  const onTabKey = (e: React.KeyboardEvent, i: number) => {
    let n = -1;
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Delete') {
      e.preventDefault();
      closeTab(tabs[i]!.key);
      return;
    }
    if (n < 0) return;
    e.preventDefault();
    setActive(tabs[n]!.key);
    tabRefs.current[tabs[n]!.key]?.focus();
  };

  const picked = grants.data.find((g) => g.id === pick) ?? grants.data[0];
  return (
    <div className="flex flex-col gap-3">
      <Card className="flex flex-wrap items-end gap-3 p-4">
        <Field label={t('p10.term.newSession')} className="min-w-[280px] flex-1">
          {(p) => (
            <Select
              {...p}
              value={picked?.id ?? ''}
              disabled={!grants.data.length}
              onChange={(e) => setPick(e.target.value)}
              data-testid="session-grant"
            >
              {!grants.data.length && <option value="">{t('p10.term.noGrants')}</option>}
              {grants.data.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.sshUser}@{g.serverName} · {t(pathKey(g.endpointPath))} ·{' '}
                  {t('p10.grant.left', { n: minutesLeft(g.expiresAt) ?? 0 })}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <GatedButton
          variant="dark"
          perm="ssh.connect"
          disabled={!picked}
          onClick={() => picked && open(picked)}
          className="min-h-[38px]"
        >
          {t('p10.term.connect')}
        </GatedButton>
        <Button onClick={onRequestGrant}>{t('p10.grant.request')}</Button>
        <p className="m-0 w-full text-[12px] text-fg-muted">{t('p10.term.gatewayNote')}</p>
      </Card>
      {missing && (
        <Notice tone="warn" glyph="▲" role="alert">
          {t('p10.term.grantMissing')}
        </Notice>
      )}
      {tabs.length === 0 ? (
        <EmptyState title={t('p10.term.empty')} body={t('p10.term.emptyBody')} />
      ) : (
        <div className="flex flex-col gap-2">
          <div
            role="tablist"
            aria-label={t('p10.term.tabs')}
            className="flex gap-1 overflow-x-auto border-b border-line"
          >
            {tabs.map((tb, i) => {
              const on = tb.key === active;
              const name = `${tb.grant.sshUser}@${tb.grant.serverName}`;
              return (
                <div
                  key={tb.key}
                  className={cn(
                    'flex shrink-0 items-center rounded-t-md border border-b-0',
                    on ? 'border-line bg-surface' : 'border-transparent',
                  )}
                >
                  <button
                    ref={(el) => {
                      tabRefs.current[tb.key] = el;
                    }}
                    id={`term-tab-${tb.key}`}
                    role="tab"
                    type="button"
                    aria-selected={on}
                    aria-controls={`term-panel-${tb.key}`}
                    tabIndex={on ? 0 : -1}
                    onClick={() => setActive(tb.key)}
                    onKeyDown={(e) => onTabKey(e, i)}
                    className="flex min-h-9 items-center gap-1.5 border-0 bg-transparent pr-1 pl-3 font-mono text-[12.5px]"
                    data-testid="terminal-tab"
                  >
                    <span aria-hidden="true" className={DOT[tb.phase]}>
                      ●
                    </span>
                    {name}
                    <span className="sr-only">· {t(`p10.term.state.${tb.phase}`)}</span>
                  </button>
                  <button
                    type="button"
                    aria-label={t('p10.term.closeTabNamed', { name })}
                    onClick={() => closeTab(tb.key)}
                    className="mr-1 h-7 w-7 rounded border-0 bg-transparent text-[13px] text-fg-muted hover:text-fg"
                  >
                    ✕
                  </button>
                </div>
              );
            })}
          </div>
          {tabs.map((tb) => (
            <div
              key={tb.key}
              id={`term-panel-${tb.key}`}
              role="tabpanel"
              aria-labelledby={`term-tab-${tb.key}`}
              hidden={tb.key !== active}
            >
              <TerminalPane
                grant={tb.grant}
                active={tb.key === active}
                onPhase={(p) =>
                  setTabs((ts) => ts.map((x) => (x.key === tb.key ? { ...x, phase: p } : x)))
                }
                onCloseTab={() => closeTab(tb.key)}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
