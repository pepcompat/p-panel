/**
 * Browser side of the Center SSH gateway WebSocket (docs/P10_SSH_CONTRACT.md §5), framework-free so the
 * state machine is unit-testable with a fake socket.
 *
 * Ticket handling: the single-use ticket is held in one private field only until the socket opens, sent
 * once as the first text frame `{ type: 'auth', ticket, sessionId }`, then dropped. It is never put in
 * the URL (query/hash are stripped from `wsUrl`), never logged, never stored.
 */
import { CLOSE, describeClose, isEndReason, type CloseInfo } from './close-codes';

export interface SshSocketLike {
  binaryType: string;
  readonly readyState: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code: number; reason?: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}
export type SocketFactory = (url: string) => SshSocketLike;

export type SshPhase = 'connecting' | 'authenticating' | 'ready' | 'closed';

export interface ReadyInfo {
  sessionId: string;
  hostKeyFingerprint: string;
  endpoint: { path: 'private' | 'public'; host: string; port: number };
  sshUser: string;
}

export interface SshConnectionEvents {
  onPhase?: (p: SshPhase) => void;
  onReady?: (info: ReadyInfo) => void;
  onData?: (bytes: Uint8Array) => void;
  onExit?: (code: number | null, signal: string | null) => void;
  onError?: (code: string, message: string) => void;
  onClose?: (info: CloseInfo) => void;
}

export interface SshConnectionOptions extends SshConnectionEvents {
  wsUrl: string;
  sessionId: string;
  ticket: string;
  cols: number;
  rows: number;
  factory: SocketFactory;
  /** application-level ping interval (ms); 0 disables */
  pingMs?: number;
}

const OPEN = 1;
export const clampCols = (n: number) => Math.min(500, Math.max(1, Math.floor(n) || 1));
export const clampRows = (n: number) => Math.min(200, Math.max(1, Math.floor(n) || 1));

/** ws(s)://host/path only: any query string or fragment is dropped so a ticket can never ride in the URL. */
export function sanitizeWsUrl(raw: string): string {
  const u = new URL(raw);
  if (u.protocol !== 'ws:' && u.protocol !== 'wss:')
    throw new Error('SSH stream URL must be ws:// or wss://');
  u.search = '';
  u.hash = '';
  u.username = '';
  u.password = '';
  return u.toString();
}

export class SshConnection {
  private ws: SshSocketLike | null = null;
  private ticket: string | null;
  private readonly sessionId: string;
  private phase: SshPhase = 'connecting';
  private cols: number;
  private rows: number;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private closingReason: string | null = null;
  private closed = false;
  private readonly enc = new TextEncoder();

  constructor(private readonly o: SshConnectionOptions) {
    this.ticket = o.ticket;
    this.sessionId = o.sessionId;
    this.cols = clampCols(o.cols);
    this.rows = clampRows(o.rows);
  }

  /** true until the ticket has been sent (or the attempt was abandoned) */
  get hasTicket(): boolean {
    return this.ticket !== null;
  }
  get state(): SshPhase {
    return this.phase;
  }

  start(): void {
    if (this.ws || this.closed) return;
    let url: string;
    try {
      url = sanitizeWsUrl(this.o.wsUrl);
    } catch {
      this.ticket = null;
      this.finish(CLOSE.internal);
      return;
    }
    const ws = this.o.factory(url);
    this.ws = ws;
    ws.binaryType = 'arraybuffer';
    this.setPhase('connecting');
    ws.onopen = () => {
      const ticket = this.ticket;
      this.ticket = null; // single use: drop it before anything else can observe it
      if (!ticket) {
        ws.close(CLOSE.normal);
        return;
      }
      this.setPhase('authenticating');
      ws.send(JSON.stringify({ type: 'auth', ticket, sessionId: this.sessionId }));
    };
    ws.onmessage = (ev) => this.handle(ev.data);
    ws.onerror = () => {
      /* the close event follows with the code */
    };
    ws.onclose = (ev) => {
      this.ticket = null;
      this.finish(ev.code);
    };
  }

  private handle(data: unknown) {
    if (typeof data === 'string') {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(data) as Record<string, unknown>;
      } catch {
        return;
      }
      switch (msg.type) {
        case 'ready': {
          this.setPhase('ready');
          this.o.onReady?.({
            sessionId: String(msg.sessionId ?? this.sessionId),
            hostKeyFingerprint: String(msg.hostKeyFingerprint ?? ''),
            endpoint: (msg.endpoint as ReadyInfo['endpoint']) ?? {
              path: 'private',
              host: '',
              port: 22,
            },
            sshUser: String(msg.sshUser ?? ''),
          });
          // apply any resize that happened while connecting
          this.sendResize();
          if (this.o.pingMs)
            this.pingTimer = setInterval(() => this.sendJson({ type: 'ping' }), this.o.pingMs);
          return;
        }
        case 'exit':
          this.o.onExit?.(
            typeof msg.code === 'number' ? msg.code : null,
            typeof msg.signal === 'string' ? msg.signal : null,
          );
          return;
        case 'closing':
          this.closingReason = typeof msg.reason === 'string' ? msg.reason : null;
          return;
        case 'error':
          this.o.onError?.(String(msg.code ?? 'ERROR'), String(msg.message ?? ''));
          if (isEndReason(msg.reason)) this.closingReason = msg.reason;
          return;
        default:
          return; // pong and unknown frames are ignored
      }
    }
    // tag check instead of instanceof: frames may come from another realm (worker / test env)
    if (Object.prototype.toString.call(data) === '[object ArrayBuffer]')
      this.o.onData?.(new Uint8Array(data as ArrayBuffer));
    else if (ArrayBuffer.isView(data))
      this.o.onData?.(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  }

  private sendJson(v: unknown) {
    if (this.ws && this.ws.readyState === OPEN && this.phase === 'ready')
      this.ws.send(JSON.stringify(v));
  }
  private sendResize() {
    this.sendJson({ type: 'resize', cols: this.cols, rows: this.rows });
  }

  /** stdin: always a binary frame */
  write(data: string | Uint8Array): void {
    if (!this.ws || this.ws.readyState !== OPEN || this.phase !== 'ready') return;
    this.ws.send(typeof data === 'string' ? this.enc.encode(data) : data);
  }

  resize(cols: number, rows: number): void {
    const c = clampCols(cols);
    const r = clampRows(rows);
    if (c === this.cols && r === this.rows) return;
    this.cols = c;
    this.rows = r;
    this.sendResize();
  }

  /** User-initiated disconnect. */
  close(): void {
    this.ticket = null;
    if (!this.ws) {
      this.finish(CLOSE.normal);
      return;
    }
    if (this.ws.readyState === OPEN && this.phase === 'ready') this.sendJson({ type: 'close' });
    try {
      this.ws.close(CLOSE.normal);
    } catch {
      /* already closing */
    }
    this.closingReason ??= 'client_closed';
  }

  private setPhase(p: SshPhase) {
    if (this.phase === p) return;
    this.phase = p;
    this.o.onPhase?.(p);
  }

  private finish(code: number) {
    if (this.closed) return;
    this.closed = true;
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    if (this.ws) {
      this.ws.onopen = this.ws.onmessage = this.ws.onerror = null;
      this.ws.onclose = null;
    }
    this.setPhase('closed');
    this.o.onClose?.(describeClose(code, this.closingReason));
  }
}
