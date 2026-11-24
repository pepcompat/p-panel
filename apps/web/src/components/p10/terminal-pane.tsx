'use client';

import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useI18n } from '@/i18n/provider';
import { useAuth } from '@/lib/auth/auth-provider';
import { authApi } from '@/lib/api/endpoints';
import { toApiError, type ApiError } from '@/lib/api/errors';
import { sshSessionsApi } from '@/lib/api/p10-endpoints';
import type { SshGrant } from '@/lib/api/p10-types';
import { describeCreateError, type CloseInfo } from '@/lib/ssh/close-codes';
import { SshConnection, type ReadyInfo, type SshPhase } from '@/lib/ssh/connection';
import { resolveSocketFactory } from '@/lib/ssh/socket';
import { stepUpCache } from '@/lib/ssh/step-up-cache';
import { formatSeconds, hostKeysHref } from '@/lib/p10-gates';
import { p10k } from '@/lib/p10-queries';
import { envBadgeKey } from '@/lib/servers';
import { cn } from '@/lib/utils';
import { pathKey } from '@/components/p9/net-bits';
import { StepUpField } from '@/components/p3/bits';
import { Button } from '@/components/ui/button';
import { EnvBadge, OutlineTag, ToneBadge } from '@/components/ui/badge';
import { ErrorState } from '@/components/ui/states';
import type { XtermHandle } from './xterm-host';

const XtermHost = dynamic(() => import('./xterm-host'), {
  ssr: false,
  loading: () => <div className="h-full w-full bg-terminal" />,
});

export type PanePhase = 'stepup' | 'creating' | SshPhase | 'failed';

interface Meta {
  idleTimeoutSec: number;
  maxDurationSec: number;
  startedAt: number;
}

export function TerminalPane({
  grant,
  active,
  onPhase,
  onCloseTab,
}: {
  grant: SshGrant;
  active: boolean;
  onPhase: (p: PanePhase) => void;
  onCloseTab: () => void;
}) {
  const { t } = useI18n();
  const { me } = useAuth();
  const qc = useQueryClient();
  const prod = grant.environment === 'production';
  const [phase, setPhaseState] = useState<PanePhase>('creating');
  const [ready, setReady] = useState<ReadyInfo | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [closeInfo, setCloseInfo] = useState<CloseInfo | null>(null);
  const [exit, setExit] = useState<{ code: number | null; signal: string | null } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [otp, setOtp] = useState('');
  const [full, setFull] = useState(false);
  const [sr, setSr] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const conn = useRef<SshConnection | null>(null);
  const term = useRef<XtermHandle | null>(null);
  const toolbar = useRef<HTMLDivElement>(null);
  const started = useRef(false);
  const onPhaseRef = useRef(onPhase);
  onPhaseRef.current = onPhase;
  const activeRef = useRef(active);
  activeRef.current = active;

  const setPhase = useCallback((p: PanePhase) => {
    setPhaseState(p);
    onPhaseRef.current(p);
  }, []);

  const start = useCallback(
    async (fresh?: string) => {
      conn.current?.close();
      conn.current = null;
      setError(null);
      setCloseInfo(null);
      setExit(null);
      setReady(null);
      const token = prod ? (fresh ?? stepUpCache.get()) : undefined;
      if (prod && !token) {
        setPhase('stepup');
        return;
      }
      setPhase('creating');
      const size = term.current?.size() ?? { cols: 80, rows: 24 };
      try {
        const res = await sshSessionsApi.create({ grantId: grant.id, ...size }, token ?? undefined);
        const factory = await resolveSocketFactory();
        setMeta({
          idleTimeoutSec: res.idleTimeoutSec,
          maxDurationSec: res.maxDurationSec,
          startedAt: Date.now(),
        });
        term.current?.clear();
        const c = new SshConnection({
          wsUrl: res.wsUrl,
          sessionId: res.sessionId,
          ticket: res.ticket,
          cols: size.cols,
          rows: size.rows,
          factory,
          pingMs: 20_000,
          onPhase: (p) => setPhase(p),
          onReady: (info) => {
            setReady(info);
            if (activeRef.current) term.current?.focus();
          },
          onData: (b) => term.current?.write(b),
          onExit: (code, signal) => setExit({ code, signal }),
          onClose: (info) => {
            setCloseInfo(info);
            void qc.invalidateQueries({ queryKey: p10k.sessions });
            if (info.action === 'hostKeys')
              void qc.invalidateQueries({ queryKey: p10k.hostKeys(grant.serverId) });
          },
        });
        // drop our copy of the single-use ticket; only the connection holds it until the auth frame
        res.ticket = '';
        conn.current = c;
        c.start();
        void qc.invalidateQueries({ queryKey: p10k.sessions });
      } catch (e) {
        const err = toApiError(e);
        if (err.code === 'STEP_UP_REQUIRED') {
          stepUpCache.clear();
          setPhase('stepup');
          return;
        }
        setError(err);
        setCloseInfo(describeCreateError(err.status, err.code));
        setPhase('failed');
      }
    },
    [grant.id, grant.serverId, prod, qc, setPhase],
  );

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void start();
  }, [start]);

  // close the SSH session when the tab goes away
  useEffect(
    () => () => {
      conn.current?.close();
      conn.current = null;
    },
    [],
  );

  useEffect(() => {
    if (!active) return;
    // the pane just became visible: re-measure and take focus
    const id = requestAnimationFrame(() => {
      term.current?.fit();
      if (phase === 'ready') term.current?.focus();
    });
    return () => cancelAnimationFrame(id);
  }, [active, full, phase]);

  useEffect(() => {
    if (phase !== 'ready') return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [phase]);

  const verify = async () => {
    try {
      const r = await authApi.stepUp(otp);
      stepUpCache.set(r.stepUpToken, r.expiresAt);
      setOtp('');
      await start(r.stepUpToken);
    } catch (e) {
      setError(toApiError(e));
    }
  };

  const focusToolbar = () => toolbar.current?.querySelector<HTMLButtonElement>('button')?.focus();
  const label = t('p10.term.region', { user: grant.sshUser, server: grant.serverName });
  const remaining =
    meta && phase === 'ready'
      ? Math.max(0, meta.maxDurationSec - Math.floor((now - meta.startedAt) / 1000))
      : null;
  const statusText =
    phase === 'ready'
      ? t('p10.term.state.ready')
      : phase === 'closed' || phase === 'failed'
        ? closeInfo
          ? t(closeInfo.titleKey)
          : t('p10.term.state.closed')
        : t(`p10.term.state.${phase}`);

  return (
    <div
      className={cn(
        'flex flex-col gap-2',
        full && 'fixed inset-0 z-50 bg-surface p-3',
        !active && 'hidden',
      )}
      data-testid="terminal-pane"
      data-phase={phase}
    >
      {/* session facts */}
      <div
        className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px]"
        data-testid="terminal-info"
      >
        <span className="font-mono font-medium">{grant.serverName}</span>
        <EnvBadge
          env={grant.environment}
          label={t(envBadgeKey(grant.environment))}
          className="px-1.5 py-0 text-[10.5px]"
        />
        <span>
          <span className="text-fg-muted">{t('p10.sshUser')}: </span>
          <span className="font-mono" data-testid="term-user">
            {ready?.sshUser ?? grant.sshUser}
          </span>
        </span>
        <span>
          <span className="text-fg-muted">{t('p10.term.endpoint')}: </span>
          {t(pathKey(ready?.endpoint.path ?? grant.endpointPath))}
          {ready && (
            <span className="font-mono" data-testid="term-endpoint">
              {' '}
              {ready.endpoint.host}:{ready.endpoint.port}
            </span>
          )}
        </span>
        <span className="text-fg-muted">{t('p10.term.auth')}</span>
        {ready && (
          <span title={ready.hostKeyFingerprint}>
            <span className="text-fg-muted">{t('p10.term.hostKey')}: </span>
            <code className="font-mono text-[11.5px]" data-testid="term-hostkey">
              {ready.hostKeyFingerprint}
            </code>
          </span>
        )}
        {meta && (
          <span className="text-fg-muted">
            {t('p10.term.idle', { n: Math.round(meta.idleTimeoutSec / 60) })}
            {remaining !== null &&
              ` · ${t('p10.term.remaining', { time: formatSeconds(remaining) })}`}
          </span>
        )}
      </div>

      {/* toolbar */}
      <div
        ref={toolbar}
        role="toolbar"
        aria-label={t('p10.term.toolbar', { server: grant.serverName })}
        className="flex flex-wrap items-center gap-1.5"
      >
        <span
          role="status"
          aria-live="polite"
          className="mr-1 text-[12.5px]"
          data-testid="term-status"
        >
          <ToneBadge
            tone={
              phase === 'ready'
                ? 'ok'
                : phase === 'closed' || phase === 'failed'
                  ? (closeInfo?.tone ?? 'off')
                  : 'info'
            }
            glyph={
              phase === 'creating' || phase === 'connecting' || phase === 'authenticating'
                ? '◌'
                : undefined
            }
            size="sm"
          >
            {statusText}
          </ToneBadge>
        </span>
        <Button size="sm" onClick={() => term.current?.focus()} disabled={phase !== 'ready'}>
          {t('p10.term.focus')}
        </Button>
        <Button
          size="sm"
          onClick={() => void start()}
          disabled={phase === 'creating' || phase === 'connecting' || phase === 'authenticating'}
        >
          {t('p10.term.reconnect')}
        </Button>
        <Button
          size="sm"
          onClick={() => conn.current?.close()}
          disabled={phase !== 'ready' && phase !== 'connecting' && phase !== 'authenticating'}
        >
          {t('p10.term.disconnect')}
        </Button>
        <Button size="sm" aria-pressed={full} onClick={() => setFull((v) => !v)}>
          {full ? t('p10.term.exitFull') : t('p10.term.full')}
        </Button>
        <label className="inline-flex items-center gap-1.5 text-[12px] text-fg-muted">
          <input
            type="checkbox"
            checked={sr}
            onChange={(e) => {
              setSr(e.target.checked);
              term.current?.setScreenReader(e.target.checked);
            }}
          />
          {t('p10.term.screenReader')}
        </label>
        <span className="flex-1" />
        <span className="text-[11.5px] text-fg-subtle">{t('p10.term.f6')}</span>
        {full && (
          <Button size="sm" variant="ghost" onClick={onCloseTab}>
            {t('p10.term.closeTab')}
          </Button>
        )}
      </div>

      {/* terminal + state overlay */}
      <div
        role="region"
        aria-label={label}
        className={cn(
          'relative overflow-hidden rounded-md bg-terminal p-2',
          full ? 'min-h-0 flex-1' : 'h-[460px]',
        )}
        onClick={() => phase === 'ready' && term.current?.focus()}
      >
        <XtermHost
          label={label}
          onHandle={(h) => (term.current = h)}
          onInput={(d) => conn.current?.write(d)}
          onResize={(c, r) => conn.current?.resize(c, r)}
          onEscapeFocus={focusToolbar}
        />
        {phase !== 'ready' && (
          <div className="absolute inset-0 flex items-center justify-center bg-terminal/85 p-4">
            <div
              className="flex w-full max-w-[520px] flex-col gap-2.5 rounded-lg border border-line bg-surface p-4 text-[13.5px] text-fg"
              data-testid="terminal-overlay"
            >
              {phase === 'stepup' ? (
                <form
                  className="flex flex-col gap-2.5"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (/^\d{6}$/.test(otp)) void verify();
                  }}
                >
                  <b>{t('p10.term.stepUp.title')}</b>
                  <span className="text-fg-2">{t('p10.term.stepUp.body')}</span>
                  <StepUpField value={otp} onChange={setOtp} />
                  {error && <ErrorState error={error} />}
                  <div>
                    <Button
                      type="submit"
                      variant="primary"
                      disabled={!me?.mfaEnabled || !/^\d{6}$/.test(otp)}
                    >
                      {t('p10.term.stepUp.confirm')}
                    </Button>
                  </div>
                </form>
              ) : phase === 'closed' || phase === 'failed' ? (
                <>
                  <b data-testid="close-title" data-code={closeInfo?.code}>
                    {closeInfo ? t(closeInfo.titleKey) : t('p10.term.state.closed')}
                  </b>
                  {closeInfo && <span className="text-fg-2">{t(closeInfo.bodyKey)}</span>}
                  {exit && (
                    <span className="font-mono text-[12.5px]" data-testid="exit-status">
                      {exit.signal
                        ? t('p10.term.exitSignal', { signal: exit.signal })
                        : t('p10.term.exitCode', { code: exit.code ?? '?' })}
                    </span>
                  )}
                  {closeInfo && (
                    <span className="font-mono text-[11.5px] text-fg-muted">
                      {t('p10.term.closeCode', { code: closeInfo.code })}
                      {closeInfo.reason ? ` · ${closeInfo.reason}` : ''}
                    </span>
                  )}
                  {error && <ErrorState error={error} />}
                  <div className="flex flex-wrap gap-2">
                    {closeInfo?.canReconnect !== false && (
                      <Button variant="primary" onClick={() => void start()}>
                        {t('p10.term.reconnect')}
                      </Button>
                    )}
                    {closeInfo?.action === 'hostKeys' && (
                      <Link
                        href={hostKeysHref(grant.serverId)}
                        className="inline-flex min-h-9 items-center rounded-md border border-crit px-3.5 text-[13.5px] text-crit no-underline hover:no-underline"
                      >
                        {t('p10.term.toHostKeys')}
                      </Link>
                    )}
                    {closeInfo?.action === 'grants' && (
                      <Link
                        href={`/ssh?tab=grants&server=${encodeURIComponent(grant.serverId)}`}
                        className="inline-flex min-h-9 items-center rounded-md border border-line-strong px-3.5 text-[13.5px] text-fg no-underline hover:no-underline"
                      >
                        {t('p10.term.toGrants')}
                      </Link>
                    )}
                    {closeInfo?.action === 'sessions' && (
                      <Link
                        href="/ssh?tab=sessions"
                        className="inline-flex min-h-9 items-center rounded-md border border-line-strong px-3.5 text-[13.5px] text-fg no-underline hover:no-underline"
                      >
                        {t('p10.term.toSessions')}
                      </Link>
                    )}
                    <Button onClick={onCloseTab}>{t('p10.term.closeTab')}</Button>
                  </div>
                </>
              ) : (
                <span role="status" className="flex items-center gap-2">
                  <span aria-hidden="true" className="animate-pulse text-info">
                    ◌
                  </span>
                  {t(`p10.term.state.${phase}`)}
                  <OutlineTag className="ml-auto">
                    {grant.sshUser}@{grant.serverName}
                  </OutlineTag>
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
