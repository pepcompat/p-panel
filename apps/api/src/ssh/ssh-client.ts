/**
 * ssh2 client helpers. Every connection: ssh2's default (secure) algorithm set, readyTimeout 10 s,
 * SSH + TCP keepalive, strict host key verification during KEX (before any authentication), no agent,
 * no agent forwarding, no X11, no port forwarding (never requested; unsolicited channels refused).
 */
import type { Socket } from 'node:net';
import { Client, type ClientChannel, type ConnectConfig } from 'ssh2';
import { blobKeyType, fingerprintOf, publicLine } from './ssh-keys';

export const SSH_READY_TIMEOUT_MS = 10_000;
export const SSH_KEEPALIVE_MS = 15_000;

export interface PresentedHostKey {
  algorithm: string;
  fingerprintSha256: string;
  publicKey: string;
}

export function presentedKey(blob: Buffer): PresentedHostKey {
  return {
    algorithm: blobKeyType(blob) ?? 'unknown',
    fingerprintSha256: fingerprintOf(blob),
    publicKey: publicLine(blob),
  };
}

function baseConfig(host: string, port: number): ConnectConfig {
  return {
    host,
    port,
    readyTimeout: SSH_READY_TIMEOUT_MS,
    keepaliveInterval: SSH_KEEPALIVE_MS,
    keepaliveCountMax: 3,
    agent: undefined,
    agentForward: false,
    tryKeyboard: false,
  };
}

function tcpKeepalive(client: Client): void {
  const sock = (client as unknown as { _sock?: Socket })._sock;
  try {
    sock?.setKeepAlive?.(true, SSH_KEEPALIVE_MS);
  } catch {
    /* best effort */
  }
}

/**
 * Host key scan: TCP + SSH handshake, record the offered host key in `hostVerifier`, then refuse it
 * so the connection aborts before authentication.
 */
export function scanHostKey(host: string, port: number): Promise<PresentedHostKey> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let seen: PresentedHostKey | null = null;
    let done = false;
    const finish = (err: Error | null) => {
      if (done) return;
      done = true;
      client.removeAllListeners();
      client.on('error', () => undefined);
      client.end();
      if (seen) resolve(seen);
      else reject(err ?? new Error('no host key offered'));
    };
    client.on('error', (e) => finish(e));
    client.on('close', () => finish(null));
    client.on('ready', () => finish(null)); // never reached: the verifier always refuses
    client.connect({
      ...baseConfig(host, port),
      username: 'ppanel-host-key-scan',
      hostVerifier: (key: Buffer) => {
        seen = presentedKey(key);
        setImmediate(() => finish(null));
        return false;
      },
    });
    tcpKeepalive(client);
  });
}

export type ConnectFailure =
  | { kind: 'host_key'; presented: PresentedHostKey }
  | { kind: 'auth'; message: string }
  | { kind: 'connect'; message: string };

export interface ConnectedShell {
  client: Client;
  stream: ClientChannel;
  hostKey: PresentedHostKey;
}

/**
 * Connects with public-key auth after a strict host key check (`acceptHostKey` decides during KEX;
 * a refused key aborts before authentication), then opens an interactive shell with a PTY.
 */
export function connectShell(opts: {
  host: string;
  port: number;
  username: string;
  privateKey: Buffer;
  acceptHostKey: (k: PresentedHostKey) => boolean;
  pty: { cols: number; rows: number };
  onClient?: (client: Client) => void;
}): Promise<ConnectedShell> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    opts.onClient?.(client);
    let hostKey: PresentedHostKey | null = null;
    let refused: PresentedHostKey | null = null;
    let settled = false;
    const fail = (f: ConnectFailure) => {
      if (settled) return;
      settled = true;
      client.end();
      reject(f);
    };
    client.on('error', (e: Error & { level?: string }) => {
      if (refused) return fail({ kind: 'host_key', presented: refused });
      if (e.level === 'client-authentication')
        return fail({ kind: 'auth', message: 'authentication failed' });
      fail({
        kind: 'connect',
        message: e.level === 'client-timeout' ? 'timed out' : 'connection failed',
      });
    });
    client.on('close', () => {
      if (refused) return fail({ kind: 'host_key', presented: refused });
      fail({ kind: 'connect', message: 'connection closed' });
    });
    client.on('ready', () => {
      client.shell(
        { term: 'xterm-256color', cols: opts.pty.cols, rows: opts.pty.rows, width: 0, height: 0 },
        (err, stream) => {
          if (err || !hostKey) return fail({ kind: 'connect', message: 'shell refused' });
          if (settled) {
            stream.close();
            return;
          }
          settled = true;
          resolve({ client, stream, hostKey });
        },
      );
    });
    client.connect({
      ...baseConfig(opts.host, opts.port),
      username: opts.username,
      privateKey: opts.privateKey,
      hostVerifier: (key: Buffer) => {
        const k = presentedKey(key);
        if (opts.acceptHostKey(k)) {
          hostKey = k;
          return true;
        }
        refused = k;
        return false;
      },
    });
    tcpKeepalive(client);
  });
}
