'use client';

/**
 * Live tail over Server-Sent Events (§9.3). Each (re)connect obtains a fresh single-use tail token
 * (EventSource cannot send headers), resumes after the last received event id, and keeps at most
 * TAIL_BUFFER_MAX lines in memory. The Center closes a tail after 15 minutes; the client does not
 * silently reopen it then — the user restarts it explicitly.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { API_MOCK } from './config';
import { logsApi } from './api/p5-endpoints';
import { toApiError, type ApiError } from './api/errors';
import { TAIL_BUFFER_MAX, TAIL_MAX_MS, type LogEntry, type LogTailParams } from './api/p5-types';

export interface TailLine extends LogEntry {
  /** SSE event id (= ts), used for Last-Event-ID resume and React keys. */
  id: string;
}

/** Ring-ish buffer: appends, then drops the oldest lines beyond `max`. */
export class TailBuffer {
  private items: TailLine[] = [];
  dropped = 0;
  constructor(readonly max = TAIL_BUFFER_MAX) {}
  push(lines: readonly TailLine[]): void {
    if (lines.length === 0) return;
    this.items.push(...lines);
    const over = this.items.length - this.max;
    if (over > 0) {
      this.items.splice(0, over);
      this.dropped += over;
    }
  }
  clear(): void {
    this.items = [];
    this.dropped = 0;
  }
  get size(): number {
    return this.items.length;
  }
  get lastId(): string | null {
    return this.items.length ? this.items[this.items.length - 1]!.id : null;
  }
  snapshot(): TailLine[] {
    return this.items.slice();
  }
}

/** Minimal EventSource surface we rely on (the mock implements the same). */
export interface TailSourceLike {
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: string; lastEventId: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  addEventListener(type: string, fn: (ev: { data: string; lastEventId?: string }) => void): void;
  close(): void;
}

async function openSource(url: string): Promise<TailSourceLike> {
  if (API_MOCK) {
    const m = await import('@/mocks/mock-event-source');
    return new m.MockEventSource(url) as TailSourceLike;
  }
  return new EventSource(url, { withCredentials: false }) as unknown as TailSourceLike;
}

/** Parse one SSE `data` payload (a LogEntry or an array of them). Never evaluates markup. */
export function parseTailData(data: string, eventId: string): TailLine[] {
  let raw: unknown;
  try {
    raw = JSON.parse(data);
  } catch {
    return [];
  }
  const arr = Array.isArray(raw) ? raw : [raw];
  const out: TailLine[] = [];
  for (const r of arr) {
    if (!r || typeof r !== 'object') continue;
    const e = r as Partial<LogEntry> & { id?: string };
    if (typeof e.line !== 'string' || typeof e.ts !== 'string') continue;
    out.push({
      ts: e.ts,
      serverId: String(e.serverId ?? ''),
      appId: e.appId ?? null,
      source: String(e.source ?? '') as LogEntry['source'],
      level: (e.level ?? null) as LogEntry['level'],
      line: e.line,
      id: String(e.id ?? (arr.length === 1 && eventId ? eventId : e.ts)),
    });
  }
  return out;
}

export type TailStatus = 'idle' | 'connecting' | 'live' | 'reconnecting' | 'closed' | 'error';
/** `timeout` = the Center's 15-min limit; other server reasons come from `event: end`. */
export type TailCloseReason =
  'timeout' | 'stopped' | 'failed' | 'forbidden' | 'backend_unavailable' | 'server_shutdown' | null;

const BACKOFF_MS = [1000, 2000, 5000, 10000];

export function useLogTail(params: LogTailParams, opts: { maxMs?: number } = {}) {
  const maxMs = opts.maxMs ?? TAIL_MAX_MS;
  const bufRef = useRef(new TailBuffer());
  const pendingRef = useRef<TailLine[]>([]);
  const srcRef = useRef<TailSourceLike | null>(null);
  const timers = useRef<{ flush?: number; retry?: number; max?: number }>({});
  const attempt = useRef(0);
  const pausedRef = useRef(false);
  const runRef = useRef(0);
  const paramsKey = JSON.stringify(params);

  const [lines, setLines] = useState<TailLine[]>([]);
  const [dropped, setDropped] = useState(0);
  const [held, setHeld] = useState(0);
  const [status, setStatus] = useState<TailStatus>('idle');
  const [closeReason, setCloseReason] = useState<TailCloseReason>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [paused, setPausedState] = useState(false);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [reconnects, setReconnects] = useState(0);

  const publish = useCallback(() => {
    timers.current.flush = undefined;
    if (pausedRef.current) {
      setHeld(pendingRef.current.length);
      return;
    }
    if (pendingRef.current.length) {
      bufRef.current.push(pendingRef.current);
      pendingRef.current = [];
    }
    setLines(bufRef.current.snapshot());
    setDropped(bufRef.current.dropped);
    setHeld(0);
  }, []);

  const schedule = useCallback(() => {
    if (timers.current.flush === undefined) timers.current.flush = window.setTimeout(publish, 120);
  }, [publish]);

  const teardown = useCallback(() => {
    srcRef.current?.close();
    srcRef.current = null;
    window.clearTimeout(timers.current.retry);
    timers.current.retry = undefined;
  }, []);

  const connect = useCallback(
    async (run: number, resume: boolean) => {
      setStatus(resume ? 'reconnecting' : 'connecting');
      try {
        const p = JSON.parse(paramsKey) as LogTailParams;
        const tok = await logsApi.tailToken(p);
        if (run !== runRef.current) return;
        const lastId = pendingRef.current.at(-1)?.id ?? bufRef.current.lastId ?? null;
        const src = await openSource(logsApi.tailUrlFor(tok, p, resume ? lastId : null));
        if (run !== runRef.current) {
          src.close();
          return;
        }
        srcRef.current = src;
        src.onopen = () => {
          attempt.current = 0;
          setError(null);
          setStatus('live');
        };
        const onLog = (ev: { data: string; lastEventId?: string }) => {
          const parsed = parseTailData(ev.data, ev.lastEventId ?? '');
          if (!parsed.length) return;
          pendingRef.current.push(...parsed);
          // Never hold more than the cap while paused either.
          if (pendingRef.current.length > TAIL_BUFFER_MAX) {
            const over = pendingRef.current.length - TAIL_BUFFER_MAX;
            pendingRef.current.splice(0, over);
            bufRef.current.dropped += over;
          }
          schedule();
        };
        // The Center sends named `log` events; plain `message` events are accepted too.
        src.addEventListener('log', onLog);
        src.onmessage = onLog;
        src.addEventListener('dropped', (ev) => {
          // Lines skipped by the Center's 200 lines/s cap.
          try {
            const n = Number((JSON.parse(ev.data) as { count?: unknown }).count);
            if (Number.isFinite(n) && n > 0) {
              bufRef.current.dropped += n;
              schedule();
            }
          } catch {
            /* ignore malformed */
          }
        });
        src.addEventListener('end', (ev) => {
          // Server-side close: don't reconnect automatically.
          let reason: TailCloseReason = 'timeout';
          try {
            const rr = (JSON.parse(ev.data) as { reason?: string }).reason;
            if (rr === 'forbidden' || rr === 'backend_unavailable' || rr === 'server_shutdown')
              reason = rr;
          } catch {
            /* default: max_duration */
          }
          teardown();
          setStatus('closed');
          setCloseReason(reason);
          publish();
        });
        src.onerror = () => {
          // Tokens are single-use: never let EventSource auto-retry with the spent token.
          teardown();
          if (run !== runRef.current) return;
          const i = attempt.current++;
          if (i >= BACKOFF_MS.length) {
            setStatus('error');
            setCloseReason('failed');
            return;
          }
          setStatus('reconnecting');
          setReconnects((n) => n + 1);
          timers.current.retry = window.setTimeout(() => void connect(run, true), BACKOFF_MS[i]);
        };
      } catch (e) {
        if (run !== runRef.current) return;
        const err = toApiError(e);
        setError(err);
        setStatus('error');
        setCloseReason('failed');
      }
    },
    [paramsKey, publish, schedule, teardown],
  );

  const stop = useCallback(
    (reason: TailCloseReason = 'stopped') => {
      runRef.current++;
      teardown();
      window.clearTimeout(timers.current.max);
      publish();
      setStatus((s) => (s === 'idle' ? s : 'closed'));
      setCloseReason(reason);
    },
    [publish, teardown],
  );

  const start = useCallback(() => {
    const run = ++runRef.current;
    teardown();
    bufRef.current.clear();
    pendingRef.current = [];
    attempt.current = 0;
    pausedRef.current = false;
    setPausedState(false);
    setLines([]);
    setDropped(0);
    setHeld(0);
    setError(null);
    setCloseReason(null);
    setReconnects(0);
    setStartedAt(Date.now());
    window.clearTimeout(timers.current.max);
    timers.current.max = window.setTimeout(() => {
      if (run === runRef.current) stop('timeout');
    }, maxMs + 5000);
    void connect(run, false);
  }, [connect, maxMs, stop, teardown]);

  const setPaused = useCallback(
    (p: boolean) => {
      pausedRef.current = p;
      setPausedState(p);
      if (!p) publish();
    },
    [publish],
  );

  // Params changed or unmount → close the stream.
  useEffect(
    () => () => {
      runRef.current++;
      srcRef.current?.close();
      srcRef.current = null;
      const t = timers.current;
      window.clearTimeout(t.retry);
      window.clearTimeout(t.flush);
      window.clearTimeout(t.max);
      t.flush = undefined;
    },
    [paramsKey],
  );

  return {
    lines,
    dropped,
    held,
    status,
    closeReason,
    error,
    paused,
    startedAt,
    reconnects,
    start,
    stop,
    setPaused,
    clear: () => {
      bufRef.current.clear();
      setLines([]);
      setDropped(0);
    },
  };
}
