import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { CLOSE, describeClose, describeCreateError } from '@/lib/ssh/close-codes';
import {
  SshConnection,
  sanitizeWsUrl,
  type SshConnectionOptions,
  type SshSocketLike,
} from '@/lib/ssh/connection';
import { apiWsOrigin, buildCsp } from '@/lib/security-headers';
import { hostKeyState, terminalGate } from '@/lib/p10-gates';
import type { SshCredential, SshGrant, SshHostKey } from '@/lib/api/p10-types';
import { ApiError } from '@/lib/api/errors';
import { makeServer, meWithRole, renderWith } from './test-utils';

// ---------------------------------------------------------------- module mocks (import dialog)
const createCredential = vi.fn();
const stepUp = vi.fn();
vi.mock('@/lib/api/p10-endpoints', async (orig) => {
  const m = await orig<typeof import('@/lib/api/p10-endpoints')>();
  return {
    ...m,
    sshCredentialsApi: {
      ...m.sshCredentialsApi,
      create: (...a: unknown[]) => createCredential(...a),
    },
  };
});
vi.mock('@/lib/api/endpoints', async (orig) => {
  const m = await orig<typeof import('@/lib/api/endpoints')>();
  return { ...m, authApi: { ...m.authApi, stepUp: (...a: unknown[]) => stepUp(...a) } };
});

// ---------------------------------------------------------------- close codes

describe('P10 close-code mapping', () => {
  it('maps every contract close code to a state, an action and whether reconnect can help', () => {
    const auth = describeClose(4401);
    expect([auth.titleKey, auth.action, auth.canReconnect]).toEqual([
      'p10.close.auth.title',
      'reconnect',
      true,
    ]);
    const forbidden = describeClose(4403, 'credential_revoked');
    expect(forbidden.action).toBe('grants');
    expect(forbidden.canReconnect).toBe(false);
    expect(forbidden.bodyKey).toBe('p10.end.credential_revoked');
    expect(describeClose(4403, 'grant_revoked').bodyKey).toBe('p10.end.grant_revoked');

    const idle = describeClose(4408, 'idle_timeout');
    expect([idle.titleKey, idle.bodyKey, idle.canReconnect]).toEqual([
      'p10.close.expired.title',
      'p10.end.idle_timeout',
      true,
    ]);
    const grantExpired = describeClose(4408, 'grant_expired');
    expect([grantExpired.action, grantExpired.canReconnect]).toEqual(['grants', false]);

    const hk = describeClose(4409, 'host_key_mismatch');
    expect([hk.tone, hk.action, hk.canReconnect]).toEqual(['crit', 'hostKeys', false]);
    expect(describeClose(4429).action).toBe('sessions');
    expect(describeClose(4400).titleKey).toBe('p10.close.protocol.title');
    expect(describeClose(4500, 'connect_failed').bodyKey).toBe('p10.end.connect_failed');
    expect(describeClose(1000, 'client_closed').bodyKey).toBe('p10.end.client_closed');
    expect(describeClose(1006).titleKey).toBe('p10.close.lost.title');
    // unknown reasons are ignored, never rendered raw
    expect(describeClose(4408, '<script>').reason).toBeNull();
  });

  it('maps POST /ssh/sessions errors to the same vocabulary', () => {
    expect(describeCreateError(422, 'SSH_HOST_KEY_MISMATCH').code).toBe(CLOSE.hostKey);
    expect(describeCreateError(422, 'SSH_HOST_KEY_UNTRUSTED').bodyKey).toBe(
      'p10.close.hostKeyUntrusted.body',
    );
    expect(describeCreateError(429, 'SSH_SESSION_LIMIT').code).toBe(CLOSE.limit);
    expect(describeCreateError(403, 'SSH_GRANT_INVALID').action).toBe('grants');
    expect(describeCreateError(502, 'SSH_CONNECT_FAILED').code).toBe(CLOSE.internal);
  });
});

// ---------------------------------------------------------------- connection + ticket handling

class FakeSocket implements SshSocketLike {
  static last: FakeSocket | null = null;
  binaryType = 'blob';
  readyState = 0;
  sent: Array<string | Uint8Array | ArrayBuffer> = [];
  closedWith: number | null = null;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number; reason?: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  constructor(readonly url: string) {
    FakeSocket.last = this;
  }
  send(d: string | Uint8Array | ArrayBuffer) {
    this.sent.push(d);
  }
  close(code?: number) {
    this.closedWith = code ?? 1000;
  }
  // test helpers
  open() {
    this.readyState = 1;
    this.onopen?.({});
  }
  text(v: unknown) {
    this.onmessage?.({ data: JSON.stringify(v) });
  }
  bytes(s: string) {
    this.onmessage?.({ data: new TextEncoder().encode(s).buffer });
  }
  serverClose(code: number) {
    this.readyState = 3;
    this.onclose?.({ code });
  }
  get texts() {
    return this.sent.filter((x): x is string => typeof x === 'string').map((x) => JSON.parse(x));
  }
}

const TICKET = 'tKt_9f8e7d6c5b4a39281706f5e4d3c2b1a0_ZZ';

function connect(over: Partial<SshConnectionOptions> = {}) {
  const ev = {
    onPhase: vi.fn(),
    onReady: vi.fn(),
    onData: vi.fn(),
    onExit: vi.fn(),
    onClose: vi.fn(),
  };
  const c = new SshConnection({
    wsUrl: 'wss://center.example.test/api/v1/ssh/stream',
    sessionId: 'sess-1',
    ticket: TICKET,
    cols: 120,
    rows: 40,
    factory: (u) => new FakeSocket(u),
    ...ev,
    ...over,
  });
  c.start();
  return { c, ws: FakeSocket.last!, ev };
}

const ready = {
  type: 'ready',
  sessionId: 'sess-1',
  hostKeyFingerprint: 'SHA256:abc',
  endpoint: { path: 'private', host: '10.0.0.5', port: 22 },
  sshUser: 'ops',
};

describe('SshConnection (contract §5)', () => {
  let logs: ReturnType<typeof vi.spyOn>[] = [];
  beforeEach(() => {
    logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(() => {}),
    );
  });
  afterEach(() => logs.forEach((l) => l.mockRestore()));

  it('sends the ticket only in the first auth text frame, never in the URL, and drops it after use', () => {
    const { c, ws } = connect({
      wsUrl: `wss://center.example.test/api/v1/ssh/stream?ticket=${TICKET}#${TICKET}`,
    });
    expect(ws.url).toBe('wss://center.example.test/api/v1/ssh/stream');
    expect(ws.url).not.toContain(TICKET);
    expect(ws.binaryType).toBe('arraybuffer');
    expect(c.hasTicket).toBe(true);
    ws.open();
    expect(c.hasTicket).toBe(false);
    expect(ws.sent).toHaveLength(1);
    expect(ws.texts[0]).toEqual({ type: 'auth', ticket: TICKET, sessionId: 'sess-1' });
    ws.text(ready);
    c.write('id -un\r');
    c.resize(132, 50);
    c.close();
    // the ticket appears exactly once across all frames, and never in logs
    const all = ws.sent.map((x) => (typeof x === 'string' ? x : new TextDecoder().decode(x)));
    expect(all.filter((x) => x.includes(TICKET))).toHaveLength(1);
    for (const l of logs)
      for (const call of l.mock.calls) expect(JSON.stringify(call)).not.toContain(TICKET);
  });

  it('a socket that closes before opening clears the ticket and never sends it', () => {
    const { c, ws, ev } = connect();
    ws.serverClose(1006);
    expect(c.hasTicket).toBe(false);
    expect(ws.sent).toHaveLength(0);
    expect(ev.onClose).toHaveBeenCalledWith(expect.objectContaining({ code: 1006 }));
  });

  it('refuses non-websocket URLs without sending anything', () => {
    expect(() => sanitizeWsUrl('https://x.test/api/v1/ssh/stream')).toThrow();
    const { c, ev } = connect({ wsUrl: 'http://x.test/stream' });
    expect(c.hasTicket).toBe(false);
    expect(ev.onClose).toHaveBeenCalledWith(expect.objectContaining({ code: 4500 }));
  });

  it('ready → binary stdin/stdout, clamped resize, ping, exit status and close reason', () => {
    vi.useFakeTimers();
    try {
      const { c, ws, ev } = connect({ pingMs: 20_000 });
      ws.open();
      expect(ev.onPhase).toHaveBeenLastCalledWith('authenticating');
      c.write('ignored before ready');
      expect(ws.sent).toHaveLength(1);
      ws.text(ready);
      expect(ev.onPhase).toHaveBeenLastCalledWith('ready');
      expect(ev.onReady).toHaveBeenCalledWith(
        expect.objectContaining({ hostKeyFingerprint: 'SHA256:abc', sshUser: 'ops' }),
      );
      // initial size is re-sent once ready
      expect(ws.texts.at(-1)).toEqual({ type: 'resize', cols: 120, rows: 40 });
      c.write('echo hi\r');
      const stdin = ws.sent.at(-1);
      expect(typeof stdin).not.toBe('string'); // binary frame
      expect(ArrayBuffer.isView(stdin)).toBe(true);
      expect(new TextDecoder().decode(stdin as Uint8Array)).toBe('echo hi\r');
      c.resize(9999, 0);
      expect(ws.texts.at(-1)).toEqual({ type: 'resize', cols: 500, rows: 1 });
      vi.advanceTimersByTime(20_000);
      expect(ws.texts.at(-1)).toEqual({ type: 'ping' });
      ws.bytes('hi\r\n');
      expect(new TextDecoder().decode(ev.onData.mock.calls[0]![0])).toBe('hi\r\n');
      ws.text({ type: 'exit', code: 3 });
      expect(ev.onExit).toHaveBeenCalledWith(3, null);
      ws.text({ type: 'closing', reason: 'idle_timeout' });
      ws.serverClose(4408);
      expect(ev.onClose).toHaveBeenCalledWith(
        expect.objectContaining({ code: 4408, reason: 'idle_timeout', canReconnect: true }),
      );
      expect(c.state).toBe('closed');
      // no more pings after close
      const n = ws.sent.length;
      vi.advanceTimersByTime(60_000);
      expect(ws.sent).toHaveLength(n);
    } finally {
      vi.useRealTimers();
    }
  });

  it('user disconnect sends {type:"close"} then closes 1000', () => {
    const { c, ws } = connect();
    ws.open();
    ws.text(ready);
    c.close();
    expect(ws.texts.at(-1)).toEqual({ type: 'close' });
    expect(ws.closedWith).toBe(1000);
  });

  it('host-key mismatch close maps to the Host keys action', () => {
    const { ws, ev } = connect();
    ws.open();
    ws.text({ type: 'closing', reason: 'host_key_mismatch' });
    ws.serverClose(4409);
    expect(ev.onClose).toHaveBeenCalledWith(
      expect.objectContaining({ code: 4409, action: 'hostKeys', canReconnect: false }),
    );
  });
});

// ---------------------------------------------------------------- CSP

describe('CSP allows the API WebSocket origin', () => {
  it('derives ws/wss from the API base', () => {
    expect(apiWsOrigin('http://localhost:4000/api/v1')).toBe('ws://localhost:4000');
    expect(apiWsOrigin('https://center.example.test/api/v1')).toBe('wss://center.example.test');
    expect(apiWsOrigin('ftp://x')).toBeNull();
    expect(apiWsOrigin(undefined)).toBeNull();
  });
  it('production connect-src has only self, the API origin and its wss origin (no blanket ws:)', () => {
    const csp = buildCsp({ nonce: 'n', dev: false, apiBase: 'https://center.example.test/api/v1' });
    const connect = /connect-src ([^;]+)/.exec(csp)![1]!.split(' ');
    expect(connect).toEqual(["'self'", 'https://center.example.test', 'wss://center.example.test']);
    const http = buildCsp({ nonce: 'n', dev: false, apiBase: 'http://10.0.0.2:4000/api/v1' });
    expect(/connect-src ([^;]+)/.exec(http)![1]).toContain('ws://10.0.0.2:4000');
  });
});

// ---------------------------------------------------------------- terminal gate

const grant = (over: Partial<SshGrant> = {}): SshGrant => ({
  id: 'g1',
  userId: 'u1',
  userLabel: 'Test User',
  serverId: 's1',
  serverName: 'app-prod-01',
  environment: 'production',
  sshUser: 'ops',
  endpointPath: 'private',
  reason: 'x',
  durationMin: 60,
  status: 'active',
  grantHash: 'h',
  requestedAt: new Date().toISOString(),
  approvedBy: null,
  approvedByLabel: null,
  approvedAt: null,
  startsAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 3600e3).toISOString(),
  revokedAt: null,
  ...over,
});
const cred: SshCredential = {
  id: 'c1',
  name: 'k',
  kind: 'generated',
  algorithm: 'ssh-ed25519',
  publicKey: 'ssh-ed25519 AAAA k',
  fingerprintSha256: 'SHA256:k',
  status: 'active',
  rotatedFromId: null,
  createdAt: '',
  createdByLabel: null,
  revokedAt: null,
  deployments: [
    { id: 'd1', serverId: 's1', serverName: 'app-prod-01', sshUser: 'ops', status: 'installed' },
  ],
};
const key = (over: Partial<SshHostKey>): SshHostKey => ({
  id: 'k',
  serverId: 's1',
  endpointId: 'e',
  endpointPath: 'private',
  algorithm: 'ssh-ed25519',
  fingerprintSha256: 'SHA256:trusted',
  publicKey: '',
  status: 'trusted',
  seenVia: 'scan',
  agentMatch: true,
  firstSeenAt: '',
  lastSeenAt: '',
  trustedBy: null,
  trustedAt: null,
  ...over,
});

describe('terminal gate', () => {
  const base = {
    server: makeServer(),
    permissions: ['ssh.connect'],
    userId: 'u1',
    grants: [grant()],
    credentials: [cred],
    hostKeys: [key({})],
  };
  it('is open only with permission, a live server, an installed key, an active grant and a trusted host key', () => {
    expect(terminalGate(base).block).toBeNull();
    expect(terminalGate({ ...base, permissions: [] }).block).toBe('perm');
    expect(terminalGate({ ...base, server: makeServer({ status: 'offline' }) }).block).toBe(
      'offline',
    );
    expect(terminalGate({ ...base, credentials: [{ ...cred, status: 'revoked' }] }).block).toBe(
      'noCredential',
    );
    expect(terminalGate({ ...base, grants: [] }).block).toBe('noGrant');
    expect(terminalGate({ ...base, grants: [grant({ status: 'awaiting_approval' })] }).block).toBe(
      'pendingApproval',
    );
    expect(terminalGate({ ...base, grants: [grant({ userId: 'someone-else' })] }).block).toBe(
      'noGrant',
    );
    expect(
      terminalGate({
        ...base,
        grants: [grant({ expiresAt: new Date(Date.now() - 1000).toISOString() })],
      }).block,
    ).toBe('noGrant');
    expect(terminalGate({ ...base, hostKeys: [key({ status: 'pending' })] }).block).toBe(
      'noHostKey',
    );
    expect(
      terminalGate({
        ...base,
        hostKeys: [
          key({}),
          key({
            id: 'k2',
            status: 'pending',
            seenVia: 'connect',
            fingerprintSha256: 'SHA256:other',
          }),
        ],
      }).block,
    ).toBe('hostKeyMismatch');
    // card variant (no host keys fetched) does not block on host keys
    expect(terminalGate({ ...base, hostKeys: undefined }).block).toBeNull();
  });
  it('a pending scanned key next to a trusted one is not a mismatch', () => {
    const s = hostKeyState(
      [
        key({}),
        key({ id: 'k2', status: 'pending', seenVia: 'scan', fingerprintSha256: 'SHA256:n' }),
      ],
      'private',
    );
    expect(s.trusted?.id).toBe('k');
    expect(s.mismatch).toBeNull();
    expect(s.pending).toHaveLength(1);
  });
});

// ---------------------------------------------------------------- private key import

describe('ImportKeyDialog', () => {
  const PRIVATE =
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----';
  beforeEach(() => {
    createCredential.mockReset();
    stepUp.mockReset();
    stepUp.mockResolvedValue({
      stepUpToken: 'su',
      expiresAt: new Date(Date.now() + 60e3).toISOString(),
    });
    localStorage.clear();
    sessionStorage.clear();
  });

  async function fillAndSubmit() {
    const { ImportKeyDialog } = await import('@/components/p10/credentials-view');
    const onOpenChange = vi.fn();
    const r = renderWith(<ImportKeyDialog open onOpenChange={onOpenChange} />, {
      me: meWithRole('platform_owner', true),
    });
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'imported-key' } });
    const ta = screen.getByTestId('private-key-input') as HTMLTextAreaElement;
    fireEvent.input(ta, { target: { value: PRIVATE } });
    fireEvent.change(screen.getByLabelText('Passphrase'), { target: { value: 'hunter2-secret' } });
    fireEvent.change(screen.getByLabelText('2FA code'), {
      target: { value: '123456' },
    });
    const submit = screen.getByTestId('import-submit');
    expect(submit).toBeEnabled();
    await act(async () => {
      fireEvent.click(submit);
    });
    return { r, ta, onOpenChange };
  }

  it('POSTs the key once, clears the field immediately and keeps it nowhere', async () => {
    let fieldAtSend: string | null = null;
    createCredential.mockImplementation(async () => {
      fieldAtSend = (screen.getByTestId('private-key-input') as HTMLTextAreaElement).value;
      return { ...cred, name: 'imported-key' };
    });
    const { r, onOpenChange } = await fillAndSubmit();
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
    expect(createCredential).toHaveBeenCalledTimes(1);
    const [body, token] = createCredential.mock.calls[0]!;
    expect(body).toEqual({
      name: 'imported-key',
      mode: 'import',
      privateKey: PRIVATE,
      passphrase: 'hunter2-secret',
    });
    expect(token).toBe('su');
    expect(fieldAtSend).toBe(''); // already cleared while the request was in flight
    expect(r.container.innerHTML).not.toContain('PRIVATE KEY-----\nb3Bl');
    expect(document.body.innerHTML).not.toContain('b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ');
    expect(document.body.innerHTML).not.toContain('hunter2-secret');
    expect(JSON.stringify({ ...localStorage })).not.toContain('b3Bl');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('b3Bl');
  });

  it('on a 422 the field stays empty and asks to paste again (no re-send, no echo)', async () => {
    createCredential.mockRejectedValue(
      new ApiError({
        status: 422,
        code: 'SSH_KEY_ENCRYPTED',
        message: 'The key is encrypted',
        requestId: 'r1',
      }),
    );
    const { ta } = await fillAndSubmit();
    await screen.findByTestId('key-cleared');
    expect(ta.value).toBe('');
    expect(createCredential).toHaveBeenCalledTimes(1);
    expect(screen.getByText('SSH_KEY_ENCRYPTED · HTTP 422', { exact: false })).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain('b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ');
    // nothing to submit until a key is pasted again
    expect(screen.getByTestId('import-submit')).toBeDisabled();
  });
});
