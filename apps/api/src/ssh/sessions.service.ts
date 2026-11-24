import { Inject, Injectable, type OnApplicationBootstrap } from '@nestjs/common';
import {
  type CreateSshSessionInput,
  ERROR_CODES,
  SSH_STREAM_PATH,
  SSH_TICKET_TTL_SEC,
  SSH_WS_CLOSE,
  type SshEndReason,
  type SshSession,
  type SshSessionCreated,
  type SshSettings,
} from '@ppanel/shared-contracts';
import type { Prisma, SshSession as SessionRow } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { sha256Hex } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, type FieldMap, paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { scopeOf } from '../servers/servers.service';
import { SshCredentialsService } from './credentials.service';
import { serverNames, toSessionView, userLabels } from './ssh-common';
import { newTicket } from './ssh-keys';
import { SshSessionRegistry } from './ssh-registry';

export const SESSION_FIELDS: FieldMap = {
  status: { prop: 'status', type: 'string' },
  server_id: { prop: 'serverId', type: 'uuid' },
  user_id: { prop: 'userId', type: 'uuid' },
  grant_id: { prop: 'grantId', type: 'uuid' },
  end_reason: { prop: 'endReason', type: 'string' },
  created_at: { prop: 'createdAt', type: 'date' },
};

export interface SessionMeta {
  ip?: string | null;
  userAgent?: string | null;
}

const grantInvalid = (message: string) => new AppError(403, ERROR_CODES.SSH_GRANT_INVALID, message);

/** §5 session rows: create (single-use ticket), consume, open/close bookkeeping, list, terminate. */
@Injectable()
export class SshSessionsService implements OnApplicationBootstrap {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly credentials: SshCredentialsService,
    private readonly registry: SshSessionRegistry,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** Center restart: no socket survives a process, so every pending/open row is closed. */
  async onApplicationBootstrap(): Promise<void> {
    try {
      const r = await this.prisma.sshSession.updateMany({
        where: { status: { in: ['pending', 'open'] } },
        data: {
          status: 'closed',
          endReason: 'center_restart',
          closedAt: new Date(),
          ticketHash: null,
          ticketExpiresAt: null,
        },
      });
      if (r.count) logger.emit('warn', 'ssh sessions closed at startup', { count: r.count });
    } catch (err) {
      logger.emit('error', 'ssh startup sweep failed', { err });
    }
  }

  settings(): SshSettings {
    return {
      recording: 'disabled',
      idleTimeoutSec: this.config.SSH_IDLE_TIMEOUT_SEC,
      maxSessionSec: this.config.SSH_MAX_SESSION_SEC,
      maxSessionsPerUser: this.config.SSH_MAX_SESSIONS_PER_USER,
      maxSessionsPerServer: this.config.SSH_MAX_SESSIONS_PER_SERVER,
      maxSessionsGlobal: this.config.SSH_MAX_SESSIONS_GLOBAL,
    };
  }

  wsUrl(): string {
    const u = new URL(this.config.PPANEL_PUBLIC_API_URL);
    u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
    u.pathname = SSH_STREAM_PATH;
    u.search = '';
    u.hash = '';
    return u.toString();
  }

  /** Sessions that hold (or may soon hold) an SSH connection. */
  activeWhere(now = new Date()): Prisma.SshSessionWhereInput {
    return {
      OR: [
        { status: 'open' },
        { status: 'pending', OR: [{ ticketExpiresAt: { gt: now } }, { ticketHash: null }] },
      ],
    };
  }

  /** Which limit (if any) a new session would exceed. */
  async limitHit(
    userId: string,
    serverId: string,
    excludeId?: string,
  ): Promise<'user' | 'server' | 'global' | null> {
    const base: Prisma.SshSessionWhereInput = {
      ...this.activeWhere(),
      ...(excludeId ? { id: { not: excludeId } } : {}),
    };
    const [u, s, g] = await Promise.all([
      this.prisma.sshSession.count({ where: { AND: [base, { userId }] } }),
      this.prisma.sshSession.count({ where: { AND: [base, { serverId }] } }),
      this.prisma.sshSession.count({ where: base }),
    ]);
    if (u >= this.config.SSH_MAX_SESSIONS_PER_USER) return 'user';
    if (s >= this.config.SSH_MAX_SESSIONS_PER_SERVER) return 'server';
    if (g >= this.config.SSH_MAX_SESSIONS_GLOBAL) return 'global';
    return null;
  }

  async create(
    user: AuthUser,
    input: CreateSshSessionInput,
    stepUp: string | undefined,
    meta: SessionMeta,
  ): Promise<SshSessionCreated> {
    const g = await this.prisma.sshAccessGrant.findUnique({
      where: { id: input.grantId },
      include: { server: { select: { id: true, environment: true, status: true } } },
    });
    const denied = async (reason: string, err: AppError) => {
      await this.audit.record({
        actorId: user.id,
        action: 'ssh.session.denied',
        targetType: 'ssh_grant',
        targetId: input.grantId,
        result: 'denied',
        metadata: { reason, clientIp: meta.ip ?? null },
      });
      return err;
    };
    if (!g || g.userId !== user.id)
      throw await denied('not_owner', grantInvalid('Grant not found or not yours'));
    await this.authz.enforce(user, 'ssh.connect', scopeOf(g.server), {
      action: 'ssh.session.denied',
      targetType: 'ssh_grant',
      targetId: g.id,
    });
    const now = new Date();
    if (g.status !== 'active' || !g.expiresAt || g.expiresAt <= now)
      throw await denied(
        'grant_' + (g.status === 'active' ? 'expired' : g.status),
        grantInvalid(`Grant is not active`),
      );
    if (g.server.environment === 'production') {
      try {
        this.auth.assertStepUp(user, stepUp);
      } catch (e) {
        throw await denied('step_up_required', e as AppError);
      }
    }
    const ep = await this.prisma.sshEndpoint.findUnique({
      where: { serverId_path: { serverId: g.serverId, path: g.endpointPath } },
      include: { hostKeys: { where: { status: 'trusted' }, select: { id: true } } },
    });
    if (!ep || !ep.allowedUsers.includes(g.sshUser))
      throw await denied(
        'no_endpoint',
        grantInvalid('The grant endpoint no longer allows this user'),
      );
    if (ep.hostKeys.length === 0)
      throw await denied(
        'host_key_untrusted',
        new AppError(
          422,
          ERROR_CODES.SSH_HOST_KEY_UNTRUSTED,
          'No trusted host key for this endpoint',
        ),
      );
    const cred = await this.credentials.usableCredential(this.prisma, g.serverId, g.sshUser);
    if (!cred)
      throw await denied(
        'no_credential',
        new AppError(
          422,
          ERROR_CODES.SSH_NO_CREDENTIAL,
          'No installed key of an active credential',
        ),
      );
    const hit = await this.limitHit(user.id, g.serverId);
    if (hit) {
      await this.audit.record({
        actorId: user.id,
        action: 'ssh.session.denied',
        targetType: 'ssh_grant',
        targetId: g.id,
        result: 'denied',
        metadata: { reason: 'limit', limit: hit },
      });
      throw new AppError(429, ERROR_CODES.SSH_SESSION_LIMIT, `SSH session limit reached (${hit})`, {
        limit: hit,
      });
    }
    const { ticket, hash } = newTicket();
    const id = uuidv7();
    const expiresAt = new Date(now.getTime() + SSH_TICKET_TTL_SEC * 1000);
    await this.prisma.sshSession.create({
      data: {
        id,
        grantId: g.id,
        userId: user.id,
        serverId: g.serverId,
        sshUser: g.sshUser,
        endpointPath: g.endpointPath,
        endpointHost: ep.host,
        endpointPort: ep.port,
        credentialFingerprint: cred.fingerprintSha256,
        status: 'pending',
        clientIp: meta.ip ?? null,
        userAgent: meta.userAgent?.slice(0, 256) ?? null,
        ticketHash: hash,
        ticketExpiresAt: expiresAt,
        createdAt: now,
      },
    });
    const maxDurationSec = Math.max(
      1,
      Math.min(
        this.config.SSH_MAX_SESSION_SEC,
        Math.floor((g.expiresAt.getTime() - now.getTime()) / 1000),
      ),
    );
    pendingPty.set(id, { cols: input.cols, rows: input.rows });
    setTimeout(() => pendingPty.delete(id), (SSH_TICKET_TTL_SEC + 5) * 1000).unref();
    return {
      sessionId: id,
      ticket,
      wsUrl: this.wsUrl(),
      expiresAt: expiresAt.toISOString(),
      idleTimeoutSec: this.config.SSH_IDLE_TIMEOUT_SEC,
      maxDurationSec,
    };
  }

  /** Atomic single-use consume: valid, unexpired, unused ticket of exactly that session. */
  async consumeTicket(sessionId: string, ticket: string): Promise<SessionRow | null> {
    if (!/^[0-9a-f-]{36}$/i.test(sessionId) || ticket.length > 128) return null;
    const hash = sha256Hex(ticket);
    const now = new Date();
    const r = await this.prisma.sshSession.updateMany({
      where: { id: sessionId, ticketHash: hash, ticketExpiresAt: { gt: now }, status: 'pending' },
      data: { ticketHash: null, ticketExpiresAt: null },
    });
    if (r.count !== 1) return null;
    return this.prisma.sshSession.findUnique({ where: { id: sessionId } });
  }

  ptyOf(sessionId: string): { cols: number; rows: number } {
    const p = pendingPty.get(sessionId);
    pendingPty.delete(sessionId);
    return p ?? { cols: 80, rows: 24 };
  }

  async markOpen(id: string, hostKeyFingerprint: string): Promise<void> {
    await this.prisma.sshSession.update({
      where: { id },
      data: { status: 'open', openedAt: new Date(), hostKeyFingerprint },
    });
  }

  /** Close bookkeeping (idempotent: only a pending/open row is closed). */
  async markClosed(
    row: SessionRow,
    out: {
      reason: SshEndReason;
      failed: boolean;
      bytesIn: number;
      bytesOut: number;
      exitCode: number | null;
      hostKeyFingerprint: string | null;
    },
  ): Promise<void> {
    const closedAt = new Date();
    const r = await this.prisma.sshSession.updateMany({
      where: { id: row.id, status: { in: ['pending', 'open'] } },
      data: {
        status: out.failed ? 'failed' : 'closed',
        endReason: out.reason,
        exitCode: out.exitCode,
        bytesIn: BigInt(out.bytesIn),
        bytesOut: BigInt(out.bytesOut),
        closedAt,
        ticketHash: null,
        ticketExpiresAt: null,
        ...(out.hostKeyFingerprint ? { hostKeyFingerprint: out.hostKeyFingerprint } : {}),
      },
    });
    if (r.count !== 1) return;
    const opened = await this.prisma.sshSession.findUnique({
      where: { id: row.id },
      select: { openedAt: true },
    });
    await this.audit.record({
      actorId: row.userId,
      action: out.failed ? 'ssh.session.denied' : 'ssh.session.close',
      targetType: 'ssh_session',
      targetId: row.id,
      result: out.failed ? 'failure' : 'success',
      metadata: this.auditMeta(row, {
        endReason: out.reason,
        bytesIn: out.bytesIn,
        bytesOut: out.bytesOut,
        exitCode: out.exitCode,
        hostKeyFingerprint: out.hostKeyFingerprint,
        durationSec: opened?.openedAt
          ? Math.round((closedAt.getTime() - opened.openedAt.getTime()) / 1000)
          : 0,
      }),
    });
  }

  auditMeta(row: SessionRow, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      serverId: row.serverId,
      grantId: row.grantId,
      sshUser: row.sshUser,
      endpoint: { path: row.endpointPath, host: row.endpointHost, port: row.endpointPort },
      // (key named so the audit redaction keeps it: fingerprints are public)
      keyFingerprint: row.credentialFingerprint,
      clientIp: row.clientIp,
      ...extra,
    };
  }

  // ---------------------------------------------------------------- list / terminate

  async list(user: AuthUser, pq: ParsedQuery): Promise<Paginated<SshSession>> {
    const visibility: Prisma.SshSessionWhereInput[] = [{ userId: user.id }];
    const sw = this.authz.serverWhere(user, 'credentials.manage');
    // An empty relation filter (global scope) matches nothing inside OR in Prisma: drop the clause instead.
    const global = !!sw && Object.keys(sw).length === 0;
    if (sw && !global) visibility.push({ server: sw });
    const filters = buildWhere(pq, SESSION_FIELDS) as Prisma.SshSessionWhereInput;
    const where: Prisma.SshSessionWhereInput = global
      ? filters
      : { AND: [{ OR: visibility }, filters] };
    const [total, rows] = await Promise.all([
      this.prisma.sshSession.count({ where }),
      this.prisma.sshSession.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    const labels = await userLabels(
      this.prisma,
      rows.map((r) => r.userId),
    );
    const names = await serverNames(
      this.prisma,
      rows.map((r) => r.serverId),
    );
    return new Paginated(
      rows.map((r) => toSessionView(r, labels, names)),
      paginate(pq, total),
    );
  }

  async terminate(user: AuthUser, id: string): Promise<SshSession> {
    const s = await this.prisma.sshSession.findUnique({
      where: { id },
      include: { server: { select: { id: true, environment: true } } },
    });
    if (!s) throw AppError.notFound('SSH session');
    const scope = scopeOf(s.server);
    if (s.userId !== user.id) {
      if (!this.authz.can(user, 'fleet.read', scope)) throw AppError.notFound('SSH session');
      await this.authz.enforce(user, 'credentials.manage', scope, {
        action: 'ssh.session.terminate',
        targetType: 'ssh_session',
        targetId: id,
      });
    }
    if (s.status === 'pending' || s.status === 'open') {
      const live = this.registry.get(id);
      if (live) await live.close('terminated', SSH_WS_CLOSE.FORBIDDEN, 'terminated');
      else
        await this.markClosed(s, {
          reason: 'terminated',
          failed: false,
          bytesIn: Number(s.bytesIn),
          bytesOut: Number(s.bytesOut),
          exitCode: s.exitCode,
          hostKeyFingerprint: s.hostKeyFingerprint,
        });
      await this.audit.record({
        actorId: user.id,
        action: 'ssh.session.terminate',
        targetType: 'ssh_session',
        targetId: id,
        result: 'success',
        metadata: { ownerId: s.userId, serverId: s.serverId },
      });
    }
    const row = await this.prisma.sshSession.findUniqueOrThrow({ where: { id } });
    const labels = await userLabels(this.prisma, [row.userId]);
    const names = await serverNames(this.prisma, [row.serverId]);
    return toSessionView(row, labels, names);
  }
}

/** Requested PTY size between POST /ssh/sessions and the WebSocket auth (not persisted). */
const pendingPty = new Map<string, { cols: number; rows: number }>();
