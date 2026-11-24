/**
 * P10 §5 WebSocket gateway `GET /api/v1/ssh/stream` (browser ↔ Center ↔ sshd).
 *
 * The upgrade is handled on the API HTTP server before Nest/Express (which never see upgrades):
 * Origin allowlist → 403 before the handshake; the WebSocket carries no credentials, so the first
 * text frame must present a single-use 30 s ticket within 5 s (→ 4401 otherwise). Only then is the
 * Center's private key decrypted (in memory) and an ssh2 connection opened with a strict host-key
 * check. Every exit path ends the SSH channel and connection and closes the session row.
 */
import type { IncomingMessage, Server as HttpServer } from 'node:http';
import type { Duplex } from 'node:stream';
import {
  Inject,
  Injectable,
  type BeforeApplicationShutdown,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import {
  ERROR_CODES,
  SSH_AUTH_TIMEOUT_SEC,
  SSH_BACKPRESSURE_BYTES,
  SSH_STREAM_PATH,
  SSH_WS_CLOSE,
  SSH_WS_MAX_PAYLOAD,
  SSH_WS_PING_SEC,
  type SshEndReason,
  type SshEndpointPath,
  type SshWsServerMessage,
  sshWsClientMessageSchema,
} from '@ppanel/shared-contracts';
import type { SshSession as SessionRow } from '@prisma/client';
import type { Client, ClientChannel } from 'ssh2';
import { type RawData, WebSocket, WebSocketServer } from 'ws';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { scopeOf } from '../servers/servers.service';
import { SshCredentialsService } from './credentials.service';
import { SshEndpointsService } from './endpoints.service';
import { type ConnectFailure, connectShell, type PresentedHostKey } from './ssh-client';
import { agentMatchOf, compareHostKey } from './ssh-keys';
import { SshSessionRegistry } from './ssh-registry';
import { SshSessionsService } from './sessions.service';

/** Max wait for the session row update before the WebSocket is closed anyway. */
const CLOSE_BOOKKEEPING_WAIT_MS = 2000;

const RESUME_BELOW = SSH_BACKPRESSURE_BYTES / 2;
const MAX_TEXT_FRAME = 4096;

function rejectUpgrade(socket: Duplex, status: number, code: string, message: string): void {
  const body = JSON.stringify({ error: { code, message } });
  const text = status === 403 ? 'Forbidden' : status === 404 ? 'Not Found' : 'Bad Request';
  try {
    socket.write(
      `HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Type: application/json\r\n` +
        `Cache-Control: no-store\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
  } catch {
    /* peer gone */
  }
  socket.destroy();
}

@Injectable()
export class SshGatewayService implements OnApplicationBootstrap, BeforeApplicationShutdown {
  private wss: WebSocketServer | undefined;
  private httpServer: HttpServer | undefined;
  private readonly onUpgradeBound = (req: IncomingMessage, socket: Duplex, head: Buffer) =>
    this.onUpgrade(req, socket, head);

  constructor(
    private readonly adapterHost: HttpAdapterHost,
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly sessions: SshSessionsService,
    private readonly credentials: SshCredentialsService,
    private readonly endpoints: SshEndpointsService,
    private readonly registry: SshSessionRegistry,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onApplicationBootstrap(): void {
    this.wss = new WebSocketServer({
      noServer: true,
      maxPayload: SSH_WS_MAX_PAYLOAD,
      perMessageDeflate: false,
      clientTracking: true,
    });
    this.httpServer = this.adapterHost.httpAdapter?.getHttpServer() as HttpServer | undefined;
    this.httpServer?.on('upgrade', this.onUpgradeBound);
  }

  /** Center shutdown: every live session closes with `center_shutdown` before the DB disconnects. */
  async beforeApplicationShutdown(): Promise<void> {
    this.httpServer?.off('upgrade', this.onUpgradeBound);
    await this.registry.closeWhere(() => true, 'center_shutdown', 1001, 'center shutdown');
    for (const ws of this.wss?.clients ?? []) ws.terminate();
    await new Promise<void>((r) => (this.wss ? this.wss.close(() => r()) : r()));
  }

  private onUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    socket.on('error', () => undefined);
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://center.invalid');
    } catch {
      return rejectUpgrade(socket, 400, ERROR_CODES.BAD_REQUEST, 'Bad request');
    }
    if (url.pathname !== SSH_STREAM_PATH)
      return rejectUpgrade(socket, 404, ERROR_CODES.NOT_FOUND, 'Not found');
    const origin = req.headers.origin;
    if (!origin || !this.config.webOrigins.includes(origin)) {
      void this.audit.record({
        action: 'ssh.session.denied',
        targetType: 'ssh_stream',
        result: 'denied',
        metadata: { reason: 'origin', origin: origin?.slice(0, 200) ?? null },
      });
      return rejectUpgrade(socket, 403, ERROR_CODES.FORBIDDEN, 'Origin not allowed');
    }
    // the ticket travels only in the first frame — a URL ticket would end up in proxy/access logs
    if (url.search)
      return rejectUpgrade(
        socket,
        400,
        ERROR_CODES.BAD_REQUEST,
        'Query parameters are not accepted',
      );
    this.wss!.handleUpgrade(req, socket, head, (ws) => this.onConnection(ws, req));
  }

  private onConnection(ws: WebSocket, req: IncomingMessage): void {
    const bridge = new Bridge(ws, this, req.socket.remoteAddress ?? null);
    bridge.start();
  }

  // ---------------------------------------------------------------- used by Bridge

  /** @internal */
  async authorize(
    bridge: Bridge,
    raw: string,
  ): Promise<{ ok: true; row: SessionRow } | { ok: false }> {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      msg = null;
    }
    const p = sshWsClientMessageSchema.safeParse(msg);
    if (!p.success || p.data.type !== 'auth') {
      await this.denyAnonymous(bridge, 'first_frame_not_auth');
      return { ok: false };
    }
    const row = await this.sessions.consumeTicket(p.data.sessionId, p.data.ticket);
    if (!row) {
      await this.denyAnonymous(bridge, 'ticket_invalid', p.data.sessionId);
      return { ok: false };
    }
    return { ok: true, row };
  }

  private async denyAnonymous(bridge: Bridge, reason: string, sessionId?: string): Promise<void> {
    await this.audit.record({
      action: 'ssh.session.denied',
      targetType: 'ssh_session',
      targetId: sessionId && /^[0-9a-f-]{36}$/i.test(sessionId) ? sessionId : null,
      result: 'denied',
      metadata: { reason, clientIp: bridge.remoteIp },
    });
  }

  /** Re-checks everything at connect time (a ticket is only proof of an earlier POST). */
  async preflight(row: SessionRow): Promise<
    | {
        ok: true;
        endpointId: string;
        keys: Array<{ fingerprintSha256: string; status: string }>;
        privateKey: Buffer;
        grantExpiresAt: Date;
        sshFacts: unknown;
      }
    | { ok: false; reason: SshEndReason; wsCode: number; code: string; message: string }
  > {
    const now = new Date();
    const forbidden = (reason: SshEndReason, code: string, message: string) =>
      ({ ok: false, reason, wsCode: SSH_WS_CLOSE.FORBIDDEN, code, message }) as const;
    const [user, grant, server] = await Promise.all([
      this.prisma.user.findUnique({
        where: { id: row.userId },
        select: { id: true, email: true, status: true, roleBindings: true },
      }),
      this.prisma.sshAccessGrant.findUnique({ where: { id: row.grantId } }),
      this.prisma.server.findUnique({
        where: { id: row.serverId },
        select: { id: true, environment: true, status: true, sshFacts: true },
      }),
    ]);
    if (!user || user.status !== 'active' || !server || server.status === 'revoked')
      return forbidden('grant_revoked', ERROR_CODES.SSH_GRANT_INVALID, 'Access is no longer valid');
    const principal = {
      id: user.id,
      email: user.email,
      sessionId: '',
      amr: [],
      bindings: user.roleBindings,
    };
    if (!this.authz.can(principal, 'ssh.connect', scopeOf(server)))
      return forbidden('grant_revoked', ERROR_CODES.SSH_GRANT_INVALID, 'Access is no longer valid');
    if (!grant || grant.userId !== row.userId)
      return forbidden('grant_revoked', ERROR_CODES.SSH_GRANT_INVALID, 'Grant is not valid');
    if (grant.status === 'revoked')
      return forbidden('grant_revoked', ERROR_CODES.SSH_GRANT_INVALID, 'Grant was revoked');
    if (grant.status !== 'active' || !grant.expiresAt || grant.expiresAt <= now)
      return forbidden('grant_expired', ERROR_CODES.SSH_GRANT_INVALID, 'Grant is not active');
    const hit = await this.sessions.limitHit(row.userId, row.serverId, row.id);
    if (hit)
      return {
        ok: false,
        reason: 'limit',
        wsCode: SSH_WS_CLOSE.LIMIT,
        code: ERROR_CODES.SSH_SESSION_LIMIT,
        message: `SSH session limit reached (${hit})`,
      };
    const ep = await this.prisma.sshEndpoint.findUnique({
      where: { serverId_path: { serverId: row.serverId, path: row.endpointPath } },
      include: { hostKeys: { select: { fingerprintSha256: true, status: true } } },
    });
    if (
      !ep ||
      ep.host !== row.endpointHost ||
      ep.port !== row.endpointPort ||
      !ep.allowedUsers.includes(row.sshUser)
    )
      return forbidden('grant_revoked', ERROR_CODES.SSH_GRANT_INVALID, 'The endpoint changed');
    if (!ep.hostKeys.some((k) => k.status === 'trusted'))
      return {
        ok: false,
        reason: 'host_key_mismatch',
        wsCode: SSH_WS_CLOSE.HOST_KEY,
        code: ERROR_CODES.SSH_HOST_KEY_UNTRUSTED,
        message: 'No trusted host key for this endpoint',
      };
    const installed = await this.prisma.sshKeyDeployment.findFirst({
      where: {
        serverId: row.serverId,
        sshUser: row.sshUser,
        status: 'installed',
        credential: { fingerprintSha256: row.credentialFingerprint, status: 'active' },
      },
      select: { id: true },
    });
    const key = installed ? await this.credentials.privateKeyFor(row.credentialFingerprint) : null;
    if (!key)
      return forbidden(
        'credential_revoked',
        ERROR_CODES.SSH_NO_CREDENTIAL,
        'The credential is no longer usable',
      );
    return {
      ok: true,
      endpointId: ep.id,
      keys: ep.hostKeys,
      privateKey: key.key,
      grantExpiresAt: grant.expiresAt,
      sshFacts: server.sshFacts,
    };
  }

  async onHostKeyMismatch(
    row: SessionRow,
    endpointId: string,
    k: PresentedHostKey,
    facts: unknown,
  ): Promise<void> {
    const agentMatch = agentMatchOf(k.fingerprintSha256, facts);
    const stored = await this.endpoints.recordObserved(
      row.serverId,
      endpointId,
      k,
      'connect',
      agentMatch,
    );
    await this.audit.record({
      actorId: row.userId,
      action: 'ssh.host_key.mismatch',
      targetType: 'ssh_host_key',
      targetId: stored.id,
      result: 'denied',
      metadata: {
        ...this.sessions.auditMeta(row),
        sessionId: row.id,
        algorithm: k.algorithm,
        presentedFingerprint: k.fingerprintSha256,
        agentMatch,
      },
    });
  }

  get cfg(): AppConfig {
    return this.config;
  }
  get sessionsSvc(): SshSessionsService {
    return this.sessions;
  }
  get registrySvc(): SshSessionRegistry {
    return this.registry;
  }
  get auditSvc(): AuditService {
    return this.audit;
  }
}

type State = 'auth' | 'connecting' | 'open' | 'closed';

/** One WebSocket ↔ SSH shell bridge. `close()` is the single, idempotent exit path. */
class Bridge {
  private state: State = 'auth';
  private row: SessionRow | null = null;
  private client: Client | null = null;
  private stream: ClientChannel | null = null;
  private hostKeyFp: string | null = null;
  private bytesIn = 0;
  private bytesOut = 0;
  private exitCode: number | null = null;
  private lastActivity = Date.now();
  private alive = true;
  private paused = false;
  private timers: NodeJS.Timeout[] = [];
  private closing: Promise<void> | null = null;
  private wsGone = false;

  constructor(
    private readonly ws: WebSocket,
    private readonly gw: SshGatewayService,
    readonly remoteIp: string | null,
  ) {}

  start(): void {
    const authTimer = setTimeout(() => {
      if (this.state === 'auth') this.closeSocket(SSH_WS_CLOSE.AUTH, 'auth timeout');
    }, SSH_AUTH_TIMEOUT_SEC * 1000);
    this.timers.push(authTimer);
    this.ws.on('message', (data, isBinary) => void this.onMessage(data, isBinary));
    this.ws.on('close', () => {
      this.wsGone = true;
      if (this.row) void this.close('client_closed', SSH_WS_CLOSE.NORMAL);
      else this.clearTimers();
    });
    this.ws.on('error', () => undefined);
    this.ws.on('pong', () => {
      this.alive = true;
    });
    const ping = setInterval(() => {
      if (!this.alive) {
        this.ws.terminate();
        return;
      }
      this.alive = false;
      try {
        this.ws.ping();
      } catch {
        /* closed */
      }
    }, SSH_WS_PING_SEC * 1000);
    this.timers.push(ping);
  }

  private send(msg: SshWsServerMessage): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  private closeSocket(code: number, reason: string): void {
    this.clearTimers();
    if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
      try {
        this.ws.close(code, reason.slice(0, 120));
      } catch {
        this.ws.terminate();
      }
      // a peer that never completes the closing handshake is dropped
      setTimeout(() => this.ws.terminate(), 5000).unref();
    }
  }

  private clearTimers(): void {
    for (const t of this.timers) clearTimeout(t);
    this.timers = [];
  }

  private async onMessage(data: RawData, isBinary: boolean): Promise<void> {
    if (this.state === 'closed') return;
    // frames that arrive while the ticket is being checked are ignored (client must await `ready`)
    if (this.state === 'connecting' && !this.row) return;
    const buf = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
    if (this.state === 'auth') {
      this.state = 'connecting';
      if (isBinary || buf.length > MAX_TEXT_FRAME) {
        await this.gwDeny('first_frame_not_auth');
        return;
      }
      const r = await this.gw.authorize(this, buf.toString('utf8'));
      if (!r.ok) {
        this.state = 'closed';
        this.closeSocket(SSH_WS_CLOSE.AUTH, 'unauthorized');
        return;
      }
      this.row = r.row;
      await this.connect();
      return;
    }
    if (isBinary) {
      if (this.state !== 'open' || !this.stream) return; // stdin before `ready` is dropped
      this.bytesIn += buf.length;
      this.lastActivity = Date.now();
      this.stream.write(buf);
      return;
    }
    let msg: unknown;
    try {
      msg = buf.length <= MAX_TEXT_FRAME ? JSON.parse(buf.toString('utf8')) : null;
    } catch {
      msg = null;
    }
    const p = sshWsClientMessageSchema.safeParse(msg);
    if (!p.success || p.data.type === 'auth') {
      this.send({ type: 'error', code: ERROR_CODES.BAD_REQUEST, message: 'Protocol violation' });
      await this.close('client_closed', SSH_WS_CLOSE.PROTOCOL, 'protocol violation');
      return;
    }
    switch (p.data.type) {
      case 'ping':
        this.send({ type: 'pong' });
        return;
      case 'close':
        await this.close('client_closed', SSH_WS_CLOSE.NORMAL);
        return;
      case 'resize':
        this.stream?.setWindow(p.data.rows, p.data.cols, 0, 0);
        return;
    }
  }

  private async gwDeny(reason: string): Promise<void> {
    await this.gw.auditSvc.record({
      action: 'ssh.session.denied',
      targetType: 'ssh_stream',
      result: 'denied',
      metadata: { reason, clientIp: this.remoteIp },
    });
    this.state = 'closed';
    this.closeSocket(SSH_WS_CLOSE.AUTH, 'unauthorized');
  }

  private async connect(): Promise<void> {
    const row = this.row!;
    const registry = this.gw.registrySvc;
    registry.add({
      sessionId: row.id,
      userId: row.userId,
      serverId: row.serverId,
      grantId: row.grantId,
      credentialFingerprint: row.credentialFingerprint,
      close: (reason, code, message) => this.close(reason, code, message),
    });
    if (this.wsGone) return this.close('client_closed', SSH_WS_CLOSE.NORMAL);
    let pre: Awaited<ReturnType<SshGatewayService['preflight']>>;
    try {
      pre = await this.gw.preflight(row);
    } catch (err) {
      logger.emit('error', 'ssh session preflight failed', { sessionId: row.id, err });
      this.send({ type: 'error', code: ERROR_CODES.INTERNAL_ERROR, message: 'Internal error' });
      return this.close('connect_failed', SSH_WS_CLOSE.INTERNAL, 'internal error', true);
    }
    if (!pre.ok) {
      this.send({ type: 'error', code: pre.code, message: pre.message });
      return this.close(pre.reason, pre.wsCode, pre.message, true);
    }
    if (this.isClosed()) {
      pre.privateKey.fill(0);
      return;
    }
    const pty = this.gw.sessionsSvc.ptyOf(row.id);
    let shell: Awaited<ReturnType<typeof connectShell>>;
    try {
      shell = await connectShell({
        host: row.endpointHost,
        port: row.endpointPort,
        username: row.sshUser,
        privateKey: pre.privateKey,
        pty,
        acceptHostKey: (k) => compareHostKey(k.fingerprintSha256, pre.keys) === 'trusted',
        onClient: (c) => {
          this.client = c;
        },
      });
    } catch (e) {
      const f = e as ConnectFailure;
      if (f.kind === 'host_key') {
        await this.gw
          .onHostKeyMismatch(row, pre.endpointId, f.presented, pre.sshFacts)
          .catch((err: unknown) =>
            logger.emit('error', 'host key mismatch record failed', { err }),
          );
        this.hostKeyFp = f.presented.fingerprintSha256;
        this.send({
          type: 'error',
          code: ERROR_CODES.SSH_HOST_KEY_MISMATCH,
          message:
            'The server presented a host key that is not trusted; no authentication was attempted',
        });
        return this.close('host_key_mismatch', SSH_WS_CLOSE.HOST_KEY, 'host key mismatch', true);
      }
      if (this.isClosed()) return;
      if (f.kind === 'auth') {
        this.send({
          type: 'error',
          code: ERROR_CODES.SSH_AUTH_FAILED,
          message: 'The server refused the key',
        });
        return this.close('auth_failed', SSH_WS_CLOSE.FORBIDDEN, 'authentication failed', true);
      }
      this.send({
        type: 'error',
        code: ERROR_CODES.SSH_CONNECT_FAILED,
        message: 'Could not connect to the server',
      });
      return this.close('connect_failed', SSH_WS_CLOSE.INTERNAL, 'connect failed', true);
    } finally {
      pre.privateKey.fill(0);
    }
    this.client = shell.client;
    this.stream = shell.stream;
    this.hostKeyFp = shell.hostKey.fingerprintSha256;
    if (this.isClosed()) {
      this.teardownSsh();
      return;
    }
    this.state = 'open';
    this.wireStream(shell.stream, shell.client, pre.grantExpiresAt);
    try {
      await this.gw.sessionsSvc.markOpen(row.id, this.hostKeyFp);
      await this.gw.auditSvc.record({
        actorId: row.userId,
        action: 'ssh.session.open',
        targetType: 'ssh_session',
        targetId: row.id,
        result: 'success',
        metadata: this.gw.sessionsSvc.auditMeta(row, { hostKeyFingerprint: this.hostKeyFp }),
      });
    } catch (err) {
      logger.emit('error', 'ssh session open bookkeeping failed', { sessionId: row.id, err });
    }
    this.send({
      type: 'ready',
      sessionId: row.id,
      hostKeyFingerprint: this.hostKeyFp,
      endpoint: {
        path: row.endpointPath as SshEndpointPath,
        host: row.endpointHost,
        port: row.endpointPort,
      },
      sshUser: row.sshUser,
    });
  }

  private wireStream(stream: ClientChannel, client: Client, grantExpiresAt: Date): void {
    const out = (chunk: Buffer) => {
      if (this.ws.readyState !== WebSocket.OPEN) return;
      this.bytesOut += chunk.length;
      this.lastActivity = Date.now();
      this.ws.send(chunk, { binary: true });
      if (!this.paused && this.ws.bufferedAmount > SSH_BACKPRESSURE_BYTES) {
        this.paused = true;
        stream.pause();
        const t = setInterval(() => {
          if (this.ws.bufferedAmount < RESUME_BELOW || this.ws.readyState !== WebSocket.OPEN) {
            clearInterval(t);
            this.paused = false;
            stream.resume();
          }
        }, 25);
        this.timers.push(t);
      }
    };
    stream.on('data', out);
    stream.stderr.on('data', out);
    stream.on('exit', (code: number | null, signal?: string) => {
      this.exitCode = typeof code === 'number' ? code : null;
      this.send({ type: 'exit', code: this.exitCode, ...(signal ? { signal } : {}) });
    });
    stream.on('close', () => void this.close('server_closed', SSH_WS_CLOSE.NORMAL));
    client.on('close', () => void this.close('server_closed', SSH_WS_CLOSE.NORMAL));
    client.on('error', () => void this.close('server_closed', SSH_WS_CLOSE.NORMAL));

    const cfg = this.gw.cfg;
    const idleMs = cfg.SSH_IDLE_TIMEOUT_SEC * 1000;
    const idle = setInterval(
      () => {
        if (Date.now() - this.lastActivity >= idleMs)
          void this.close('idle_timeout', SSH_WS_CLOSE.TIMEOUT, 'idle timeout');
      },
      Math.max(100, Math.min(1000, Math.floor(idleMs / 4))),
    );
    this.timers.push(idle);
    const untilGrant = grantExpiresAt.getTime() - Date.now();
    const maxMs = cfg.SSH_MAX_SESSION_SEC * 1000;
    const byGrant = untilGrant <= maxMs;
    const t = setTimeout(
      () =>
        void this.close(
          byGrant ? 'grant_expired' : 'max_duration',
          SSH_WS_CLOSE.TIMEOUT,
          byGrant ? 'grant expired' : 'maximum duration',
        ),
      Math.max(0, Math.min(untilGrant, maxMs)),
    );
    this.timers.push(t);
  }

  private isClosed(): boolean {
    return this.closing !== null;
  }

  private teardownSsh(): void {
    const stream = this.stream;
    const client = this.client;
    this.stream = null;
    try {
      stream?.removeAllListeners('data');
      stream?.close();
    } catch {
      /* already closed */
    }
    if (client) {
      try {
        client.end();
      } catch {
        /* already closed */
      }
      // a peer that ignores the disconnect is cut at the TCP level
      setTimeout(() => {
        try {
          client.destroy();
        } catch {
          /* gone */
        }
      }, 2000).unref();
    }
  }

  /** Single exit path: SSH channel + connection ended, socket closed, row closed, audit written. */
  close(reason: SshEndReason, wsCode: number, message?: string, failed = false): Promise<void> {
    if (this.closing) return this.closing;
    this.closing = (async () => {
      this.state = 'closed';
      this.clearTimers();
      this.teardownSsh();
      if (this.ws.readyState === WebSocket.OPEN && reason !== 'client_closed')
        this.send({ type: 'closing', reason });
      const row = this.row;
      if (row) {
        this.gw.registrySvc.remove(row.id);
        // Persist before closing the socket so a client that re-reads the session after the close sees the
        // final state. Bounded: a slow DB must not keep the socket open.
        const bookkeeping = this.gw.sessionsSvc
          .markClosed(row, {
            reason,
            failed,
            bytesIn: this.bytesIn,
            bytesOut: this.bytesOut,
            exitCode: this.exitCode,
            hostKeyFingerprint: this.hostKeyFp,
          })
          .catch((err: unknown) => {
            logger.emit('error', 'ssh session close bookkeeping failed', {
              sessionId: row.id,
              err,
            });
          });
        await Promise.race([
          bookkeeping,
          new Promise<void>((r) => setTimeout(r, CLOSE_BOOKKEEPING_WAIT_MS).unref()),
        ]);
      }
      this.closeSocket(wsCode, message ?? reason);
    })();
    return this.closing;
  }
}
