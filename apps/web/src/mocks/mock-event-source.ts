/**
 * In-browser stand-in for `EventSource` against the mock `/logs/tail` (mock mode only). It validates
 * the single-use tail token like the Center, streams generated (redacted) lines every ~600 ms with
 * `lastEventId = ts`, and sends an `end` event when the max duration elapses.
 *
 * Test knobs (sessionStorage): `ppanel.mock.tailMaxMs` (default 15 min) and
 * `ppanel.mock.tailDropAfterMs` (simulate one dropped connection after N ms).
 */
import { p5Internals } from './p5-routes';

type Listener = (ev: { data: string; lastEventId?: string }) => void;

function knob(key: string): number | null {
  try {
    const v = window.sessionStorage.getItem(key);
    return v ? Number(v) : null;
  } catch {
    return null;
  }
}

let dropDone = false;

export class MockEventSource {
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string; lastEventId: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  readyState = 0;
  private listeners: Record<string, Listener[]> = {};
  private timer: number | undefined;
  private endTimer: number | undefined;
  private dropTimer: number | undefined;
  private userId: string | null = null;
  private seq = 0;

  constructor(readonly url: string) {
    const params = new URL(url).searchParams;
    window.setTimeout(() => this.boot(params), 80);
  }

  private boot(params: URLSearchParams) {
    if (this.readyState === 2) return;
    const res = p5Internals.consumeTail(params.get('token') ?? '', params);
    if (!res.ok) {
      this.readyState = 2;
      this.onerror?.({ type: 'error', code: res.code });
      return;
    }
    this.userId = res.user.id;
    this.readyState = 1;
    this.onopen?.({ type: 'open' });
    const tick = () => {
      const lines = p5Internals.liveLines(res.user, params, this.seq++);
      // Center contract: `event: log`, `id: <unix ns>`, `data: LogEntry`.
      for (const e of lines) {
        const id = (BigInt(Date.parse(e.ts)) * BigInt(1_000_000) + BigInt(this.seq)).toString();
        this.emit('log', JSON.stringify(e), id);
      }
    };
    tick();
    this.timer = window.setInterval(tick, 600);
    const maxMs = knob('ppanel.mock.tailMaxMs') ?? 15 * 60e3;
    this.endTimer = window.setTimeout(() => {
      this.emit('end', JSON.stringify({ reason: 'max_duration' }));
      this.close();
    }, maxMs);
    const dropMs = knob('ppanel.mock.tailDropAfterMs');
    if (dropMs && !dropDone) {
      this.dropTimer = window.setTimeout(() => {
        dropDone = true;
        this.close();
        this.onerror?.({ type: 'error' });
      }, dropMs);
    }
  }

  private emit(type: string, data: string, lastEventId?: string) {
    for (const fn of this.listeners[type] ?? []) fn({ data, lastEventId });
  }

  addEventListener(type: string, fn: Listener) {
    (this.listeners[type] ??= []).push(fn);
  }

  close() {
    if (this.readyState === 2) return;
    this.readyState = 2;
    window.clearInterval(this.timer);
    window.clearTimeout(this.endTimer);
    window.clearTimeout(this.dropTimer);
    if (this.userId) p5Internals.releaseTail(this.userId);
  }
}
