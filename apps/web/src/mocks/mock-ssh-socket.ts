/**
 * In-process fake of the Center SSH gateway WebSocket (docs/P10_SSH_CONTRACT.md §5) for mock mode.
 * Speaks the same protocol as the real gateway: first text frame `auth` (ticket checked + consumed by
 * the mock API), then `ready`; binary stdin/stdout; `resize`, `ping` → `pong`, `close`; `exit`,
 * `closing` and the contract close codes. A tiny line-mode "shell" answers echo / id -un / whoami /
 * hostname / stty size / exit [n]; `__idle` simulates the idle timeout (4408).
 */
import type { SshSocketLike } from '@/lib/ssh/connection';
import type { EndReason } from '@/lib/api/p10-types';
import { mockSshAuth, mockSshClosed, mockSshRegister } from './p10-routes';

const CONNECTING = 0;
const OPEN = 1;
const CLOSED = 3;

export class MockSshSocket implements SshSocketLike {
  binaryType = 'blob';
  readyState = CONNECTING;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number; reason?: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  private authed = false;
  private sessionId: string | null = null;
  private user = 'ops';
  private host = 'server';
  private line = '';
  private cols = 80;
  private rows = 24;
  private bytesIn = 0;
  private bytesOut = 0;
  private exitCode: number | null = null;
  private readonly enc = new TextEncoder();
  private readonly dec = new TextDecoder();
  private authTimer: ReturnType<typeof setTimeout>;

  constructor(readonly url: string) {
    setTimeout(() => {
      if (this.readyState !== CONNECTING) return;
      this.readyState = OPEN;
      this.onopen?.({});
    }, 120);
    // first message must arrive within 5 s
    this.authTimer = setTimeout(() => {
      if (!this.authed) this.end(4401, null);
    }, 5000);
  }

  send(data: string | ArrayBuffer | Uint8Array): void {
    if (this.readyState !== OPEN) return;
    if (typeof data === 'string') {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(data) as Record<string, unknown>;
      } catch {
        this.end(4400, null);
        return;
      }
      if (!this.authed) {
        if (
          msg.type !== 'auth' ||
          typeof msg.ticket !== 'string' ||
          typeof msg.sessionId !== 'string'
        ) {
          this.end(4401, null);
          return;
        }
        clearTimeout(this.authTimer);
        const r = mockSshAuth(msg.sessionId, msg.ticket);
        if (!r.ok) {
          this.end(r.code, r.reason ?? null, false);
          return;
        }
        this.authed = true;
        this.sessionId = r.ready.sessionId;
        this.user = r.ready.sshUser;
        this.host = r.serverName;
        mockSshRegister(this.sessionId, (code, reason) => this.end(code, reason));
        setTimeout(() => {
          this.text({ type: 'ready', ...r.ready });
          this.out(
            `Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n` +
              `Last login: ${new Date(Date.now() - 86_400_000).toUTCString()} from 10.104.0.5\r\n`,
          );
          this.prompt();
        }, 250);
        return;
      }
      switch (msg.type) {
        case 'resize':
          this.cols = Number(msg.cols) || this.cols;
          this.rows = Number(msg.rows) || this.rows;
          return;
        case 'ping':
          this.text({ type: 'pong' });
          return;
        case 'close':
          this.end(1000, 'client_closed');
          return;
        default:
          this.end(4400, null);
          return;
      }
    }
    if (!this.authed) {
      this.end(4401, null);
      return;
    }
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    this.bytesIn += bytes.byteLength;
    for (const ch of this.dec.decode(bytes)) this.key(ch);
  }

  close(code = 1000): void {
    if (this.readyState === CLOSED) return;
    this.end(code === 1000 ? 1000 : code, 'client_closed');
  }

  // ---------------------------------------------------------------- fake shell

  private prompt() {
    this.out(`${this.user}@${this.host}:~$ `);
  }

  private key(ch: string) {
    if (ch === '\r' || ch === '\n') {
      this.out('\r\n');
      const cmd = this.line.trim();
      this.line = '';
      this.run(cmd);
      return;
    }
    if (ch === '\x7f' || ch === '\b') {
      if (this.line.length) {
        this.line = this.line.slice(0, -1);
        this.out('\b \b');
      }
      return;
    }
    if (ch === '\x03') {
      this.line = '';
      this.out('^C\r\n');
      this.prompt();
      return;
    }
    if (ch === '\x04' && !this.line) {
      this.out('logout\r\n');
      this.exit(0);
      return;
    }
    if (ch === '\x1b' || ch < ' ') return;
    this.line += ch;
    this.out(ch);
  }

  private run(cmd: string) {
    if (!cmd) return this.prompt();
    const [name, ...args] = cmd.split(/\s+/);
    switch (name) {
      case 'echo':
        this.out(`${args.join(' ')}\r\n`);
        break;
      case 'whoami':
        this.out(`${this.user}\r\n`);
        break;
      case 'id':
        this.out(
          args.includes('-un')
            ? `${this.user}\r\n`
            : `uid=1001(${this.user}) gid=1001(${this.user}) groups=1001(${this.user})\r\n`,
        );
        break;
      case 'hostname':
        this.out(`${this.host}\r\n`);
        break;
      case 'stty':
        this.out(args[0] === 'size' ? `${this.rows} ${this.cols}\r\n` : '\r\n');
        break;
      case 'exit':
        this.out('logout\r\n');
        this.exit(Number(args[0] ?? 0) || 0);
        return;
      case '__idle':
        this.end(4408, 'idle_timeout');
        return;
      default:
        this.out(`-bash: ${name}: command not found\r\n`);
    }
    this.prompt();
  }

  private exit(code: number) {
    this.exitCode = code;
    this.text({ type: 'exit', code });
    setTimeout(() => this.end(1000, 'server_closed'), 60);
  }

  // ---------------------------------------------------------------- frames

  private text(v: unknown) {
    if (this.readyState !== OPEN) return;
    const data = JSON.stringify(v);
    setTimeout(() => this.onmessage?.({ data }), 0);
  }

  private out(s: string) {
    if (this.readyState !== OPEN) return;
    const b = this.enc.encode(s);
    this.bytesOut += b.byteLength;
    const buf = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    setTimeout(() => this.onmessage?.({ data: buf }), 0);
  }

  private end(code: number, reason: EndReason | null, record = true) {
    if (this.readyState === CLOSED) return;
    clearTimeout(this.authTimer);
    if (reason && this.readyState === OPEN && code !== 1000) this.text({ type: 'closing', reason });
    if (reason && code === 1000 && this.authed) this.text({ type: 'closing', reason });
    // let queued frames flush before the close event
    setTimeout(() => {
      this.readyState = CLOSED;
      if (record && this.sessionId)
        mockSshClosed(
          this.sessionId,
          reason ?? 'server_closed',
          this.exitCode,
          this.bytesIn,
          this.bytesOut,
        );
      this.onclose?.({ code });
    }, 20);
  }
}
