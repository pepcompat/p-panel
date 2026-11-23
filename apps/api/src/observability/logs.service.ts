/**
 * §9.3 Logs API: typed query → LogQL with an enforced `server_id` matcher of allowed ids (never raw
 * LogQL), read-time re-redaction, cursor pagination; SSE live tail authorised by a single-use,
 * user + params bound tail token (EventSource cannot send headers).
 */
import { Inject, Injectable, type OnApplicationShutdown } from '@nestjs/common';
import {
  ERROR_CODES,
  LOG_QUERY_MAX_SPAN_SEC,
  LOG_TAIL_MAX_LINES_PER_SEC,
  LOG_TAIL_MAX_PER_USER,
  LOG_TAIL_TOKEN_TTL_SEC,
  type LogEntry,
  type LogLevel,
  type LogSource,
  type LogsQuery,
  type LogsTailParams,
  type LogTailEndReason,
  redactLine,
  type TailTokenResponse,
} from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import { createHash } from 'node:crypto';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { CursorPaginated } from '../common/envelope';
import { randomToken, sha256Hex, stableHash } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { RateLimiter } from '../common/rate-limiter';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { BackendUnavailableError, LokiClient, type LokiStream, logsUnavailable } from './backends';
import { LogIngestService } from './log-ingest.service';
import { buildLogQL, msToNs, nsToIso } from './query-templates';
import { TelemetryService } from './telemetry.service';

export const LOGS_RATE_LIMIT = 30;
const KEEPALIVE_MS = 15_000;
const REAUTH_MS = 60_000;
const TAIL_WINDOW_MS = 30_000;
const MAX_SCOPE_IDS = 2000;

interface Scope {
  serverIds: string[];
  appId?: string;
}

interface RawEntry {
  ns: bigint;
  labels: Record<string, string>;
  line: string;
}

interface TailConn {
  userId: string;
  close: (reason: LogTailEndReason) => void;
}

export function tailParamsHash(p: LogsTailParams): string {
  return stableHash({
    serverId: p.serverId ?? null,
    appId: p.appId ?? null,
    source: p.source ?? null,
    level: p.level ?? null,
    q: p.q ?? null,
  });
}

function mergeStreams(streams: LokiStream[], allowed: Set<string>): RawEntry[] {
  const out: RawEntry[] = [];
  for (const s of streams) {
    // defence in depth: never return a stream outside the computed scope
    if (!allowed.has(s.stream.server_id ?? '')) continue;
    for (const [ns, line] of s.values) out.push({ ns: BigInt(ns), labels: s.stream, line });
  }
  return out;
}

@Injectable()
export class LogsService implements OnApplicationShutdown {
  private readonly tails = new Set<TailConn>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly limiter: RateLimiter,
    private readonly loki: LokiClient,
    private readonly ingest: LogIngestService,
    private readonly telemetry: TelemetryService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onApplicationShutdown(): void {
    for (const t of [...this.tails]) t.close('server_shutdown');
  }

  activeTails(userId?: string): number {
    return [...this.tails].filter((t) => !userId || t.userId === userId).length;
  }

  /** Resolves the server-id scope; out-of-scope ids look like missing ones (404). */
  async resolveScope(user: AuthUser, p: { serverId?: string; appId?: string }): Promise<Scope> {
    if (p.appId) {
      const app = await this.prisma.application.findUnique({
        where: { id: p.appId },
        select: { id: true, server: { select: { id: true, environment: true } } },
      });
      if (
        !app ||
        (p.serverId && p.serverId !== app.server.id) ||
        !this.authz.can(user, 'apps.read', {
          serverId: app.server.id,
          environment: app.server.environment,
        })
      )
        throw AppError.notFound('Application');
      return { serverIds: [app.server.id], appId: app.id };
    }
    if (p.serverId) {
      const s = await this.prisma.server.findUnique({
        where: { id: p.serverId },
        select: { id: true, environment: true },
      });
      if (!s || !this.authz.can(user, 'fleet.read', { serverId: s.id, environment: s.environment }))
        throw AppError.notFound('Server');
      return { serverIds: [s.id] };
    }
    if (!this.authz.can(user, 'fleet.read'))
      throw AppError.validation(
        [{ path: 'serverId', message: 'serverId or appId is required for scoped roles' }],
        'serverId or appId is required',
      );
    const where = this.authz.serverWhere(user, 'fleet.read') ?? { id: { in: [] } };
    const rows = await this.prisma.server.findMany({
      where,
      select: { id: true },
      orderBy: { lastHeartbeatAt: { sort: 'desc', nulls: 'last' } },
      take: MAX_SCOPE_IDS,
    });
    return { serverIds: rows.map((r) => r.id) };
  }

  private async toEntries(raw: RawEntry[]): Promise<LogEntry[]> {
    const secretsByServer = new Map<string, string[]>();
    for (const sid of new Set(raw.map((r) => r.labels.server_id!))) {
      const apps = await this.telemetry.managedApps(sid);
      secretsByServer.set(sid, await this.ingest.serverSecrets(sid, apps));
    }
    return raw.map((r) => ({
      ts: nsToIso(r.ns),
      serverId: r.labels.server_id!,
      appId: r.labels.app_id ?? null,
      source: r.labels.source as LogSource,
      level: (r.labels.level as LogLevel | undefined) ?? null,
      // defence in depth: redact again on read (incl. current known secret values)
      line: redactLine(r.line, secretsByServer.get(r.labels.server_id!) ?? []),
    }));
  }

  async query(user: AuthUser, q: LogsQuery, now = Date.now()) {
    this.limiter.hit(`logs:${user.id}`, LOGS_RATE_LIMIT, 60_000);
    const toMs = q.to ? Date.parse(q.to) : now;
    const fromMs = q.from ? Date.parse(q.from) : toMs - 3_600_000;
    if (!(fromMs < toMs))
      throw AppError.validation([{ path: 'from', message: 'from must be before to' }]);
    if (toMs - fromMs > LOG_QUERY_MAX_SPAN_SEC * 1000)
      throw AppError.validation([{ path: 'from', message: 'span must be ≤ 7 days' }]);
    const scope = await this.resolveScope(user, q);
    const meta = { retention: { days: this.config.lokiRetentionDays } };
    if (scope.serverIds.length === 0)
      return new CursorPaginated([], { limit: q.limit, hasMore: false, nextCursor: null }, meta);
    let startNs = msToNs(fromMs);
    let endNs = msToNs(toMs) + 1n; // Loki `end` is exclusive
    if (q.cursor) {
      const c = BigInt(q.cursor);
      if (q.direction === 'backward') endNs = c < endNs ? c : endNs;
      else startNs = c + 1n > startNs ? c + 1n : startNs;
    }
    if (startNs >= endNs)
      return new CursorPaginated([], { limit: q.limit, hasMore: false, nextCursor: null }, meta);
    const logql = buildLogQL({ ...scope, source: q.source, level: q.level, q: q.q });
    let streams: LokiStream[];
    try {
      streams = await this.loki.queryRange(logql, startNs, endNs, q.limit + 1, q.direction);
    } catch (err) {
      if (err instanceof BackendUnavailableError) throw logsUnavailable();
      throw err;
    }
    const raw = mergeStreams(streams, new Set(scope.serverIds)).sort((a, b) =>
      q.direction === 'backward'
        ? a.ns > b.ns
          ? -1
          : a.ns < b.ns
            ? 1
            : 0
        : a.ns < b.ns
          ? -1
          : a.ns > b.ns
            ? 1
            : 0,
    );
    const hasMore = raw.length > q.limit;
    const page = raw.slice(0, q.limit);
    const nextCursor = hasMore && page.length ? page[page.length - 1]!.ns.toString() : null;
    return new CursorPaginated(
      await this.toEntries(page),
      { limit: q.limit, hasMore, nextCursor },
      meta,
    );
  }

  // ------------------------------------------------------------------------------- live tail

  async createTailToken(user: AuthUser, p: LogsTailParams): Promise<TailTokenResponse> {
    this.limiter.hit(`logs:${user.id}`, LOGS_RATE_LIMIT, 60_000);
    await this.resolveScope(user, p); // authorise now (and again on connect)
    const token = `ptt_${randomToken(32)}`;
    const expiresAt = new Date(Date.now() + LOG_TAIL_TOKEN_TTL_SEC * 1000);
    await this.prisma.logTailToken.create({
      data: {
        id: uuidv7(),
        tokenHash: sha256Hex(token),
        userId: user.id,
        sessionId: user.sessionId,
        paramsHash: tailParamsHash(p),
        expiresAt,
      },
    });
    const qs = new URLSearchParams();
    for (const k of ['serverId', 'appId', 'source', 'level', 'q'] as const)
      if (p[k] !== undefined) qs.set(k, String(p[k]));
    qs.set('token', token);
    return { token, expiresAt: expiresAt.toISOString(), url: `/api/v1/logs/tail?${qs}` };
  }

  /** Consumes a tail token (single use) and rebuilds the user from the DB. */
  async consumeTailToken(token: string, p: LogsTailParams): Promise<AuthUser> {
    const invalid = () =>
      AppError.unauthenticated('Tail token is invalid or expired', ERROR_CODES.TAIL_TOKEN_INVALID);
    const rows = await this.prisma.$queryRaw<
      Array<{ user_id: string; session_id: string; params_hash: string }>
    >`
      UPDATE log_tail_tokens SET used_at = now()
       WHERE token_hash = ${sha256Hex(token)} AND used_at IS NULL AND expires_at > now()
   RETURNING user_id, session_id, params_hash`;
    const row = rows[0];
    if (!row || row.params_hash !== tailParamsHash(p)) throw invalid();
    const user = await this.loadUser(row.user_id, row.session_id);
    if (!user) throw invalid();
    return user;
  }

  private async loadUser(userId: string, sessionId: string): Promise<AuthUser | null> {
    const [session, user] = await Promise.all([
      this.prisma.session.findUnique({
        where: { id: sessionId },
        select: { revokedAt: true, expiresAt: true, userId: true },
      }),
      this.prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, email: true, status: true, roleBindings: true },
      }),
    ]);
    if (!session || session.revokedAt || session.userId !== userId) return null;
    if (!user || user.status !== 'active') return null;
    return { id: user.id, email: user.email, sessionId, amr: [], bindings: user.roleBindings };
  }

  async tail(
    req: Request,
    res: Response,
    token: string,
    p: LogsTailParams,
    lastEventId?: string,
  ): Promise<void> {
    const user = await this.consumeTailToken(token, p);
    let scope = await this.resolveScope(user, p);
    if (this.activeTails(user.id) >= LOG_TAIL_MAX_PER_USER)
      throw new AppError(
        429,
        ERROR_CODES.TAIL_LIMIT_REACHED,
        `At most ${LOG_TAIL_MAX_PER_USER} concurrent live tails per user`,
        { max: LOG_TAIL_MAX_PER_USER },
        { 'Retry-After': '5' },
      );

    res.status(200);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    res.write('retry: 5000\n\n');

    const pollMs = this.config.PPANEL_LOG_TAIL_POLL_MS;
    const budgetPerPoll = Math.max(1, Math.floor((LOG_TAIL_MAX_LINES_PER_SEC * pollMs) / 1000));
    const startedAt = Date.now();
    let cursorNs = lastEventId ? BigInt(lastEventId) : msToNs(startedAt - 5000);
    const seen = new Map<string, bigint>();
    let closed = false;
    let failures = 0;
    let lastAuth = Date.now();
    let pollTimer: NodeJS.Timeout | undefined;

    const send = (event: string, data: unknown, id?: string) => {
      if (closed) return;
      res.write(`${id ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };
    const keepalive = setInterval(() => !closed && res.write(': keepalive\n\n'), KEEPALIVE_MS);
    const maxTimer = setTimeout(
      () => conn.close('max_duration'),
      this.config.PPANEL_LOG_TAIL_MAX_SEC * 1000,
    );
    const conn: TailConn = {
      userId: user.id,
      close: (reason) => {
        if (closed) return;
        send('end', { reason });
        closed = true;
        clearInterval(keepalive);
        clearTimeout(maxTimer);
        if (pollTimer) clearTimeout(pollTimer);
        this.tails.delete(conn);
        res.end();
      },
    };
    this.tails.add(conn);
    req.on('close', () => {
      if (closed) return;
      closed = true;
      clearInterval(keepalive);
      clearTimeout(maxTimer);
      if (pollTimer) clearTimeout(pollTimer);
      this.tails.delete(conn);
    });

    const logql = buildLogQL({ ...scope, source: p.source, level: p.level, q: p.q });
    const poll = async () => {
      if (closed) return;
      try {
        if (Date.now() - lastAuth > REAUTH_MS) {
          lastAuth = Date.now();
          const fresh = await this.loadUser(user.id, user.sessionId);
          if (!fresh) return conn.close('forbidden');
          try {
            scope = await this.resolveScope(fresh, p);
          } catch {
            return conn.close('forbidden');
          }
        }
        const nowNs = msToNs(Date.now());
        const winStart = nowNs - msToNs(TAIL_WINDOW_MS);
        const startNs = cursorNs + 1n > winStart ? winStart : cursorNs + 1n;
        const streams = await this.loki.queryRange(logql, startNs, nowNs + 1n, 1000, 'backward');
        failures = 0;
        const fresh = mergeStreams(streams, new Set(scope.serverIds))
          .filter((e) => e.ns > (lastEventId ? BigInt(lastEventId) : 0n))
          .filter((e) => !seen.has(`${e.ns}:${e.labels.server_id}:${hashLine(e.line)}`))
          .sort((a, b) => (a.ns < b.ns ? -1 : a.ns > b.ns ? 1 : 0));
        const toSend = fresh.slice(0, budgetPerPoll);
        for (const e of fresh) seen.set(`${e.ns}:${e.labels.server_id}:${hashLine(e.line)}`, e.ns);
        if (fresh.length > toSend.length) send('dropped', { count: fresh.length - toSend.length });
        const entries = await this.toEntries(toSend);
        entries.forEach((entry, i) => send('log', entry, toSend[i]!.ns.toString()));
        if (toSend.length) {
          const last = toSend[toSend.length - 1]!.ns;
          if (last > cursorNs) cursorNs = last;
        }
        for (const [k, ns] of seen) if (ns < winStart - msToNs(5000)) seen.delete(k);
      } catch (err) {
        failures++;
        if (!(err instanceof BackendUnavailableError))
          logger.emit('error', 'log tail poll failed', { component: 'observability', err });
        if (failures >= 3) return conn.close('backend_unavailable');
      }
      if (!closed) pollTimer = setTimeout(() => void poll(), pollMs);
    };
    void poll();
  }
}

function hashLine(line: string): string {
  return createHash('sha1').update(line).digest('base64url').slice(0, 12);
}
