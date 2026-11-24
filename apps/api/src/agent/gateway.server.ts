import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import {
  AGENT_PROTOCOL_VERSION,
  certificateRotateSchema,
  type ConnectionPath,
  ERROR_CODES,
  heartbeatSchema,
  policyAllowsPath,
  taskAckSchema,
  taskResultSchema,
} from '@ppanel/shared-contracts';
import express, { type NextFunction, type Request, type Response } from 'express';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { RateLimiter } from '../common/rate-limiter';
import { successEnvelope } from '../common/envelope';
import { toErrorResponse } from '../common/exception.filter';
import { UUID_RE } from '../common/ids';
import { logger } from '../common/logger';
import { requestIdMiddleware } from '../common/request-id.middleware';
import { parseWith } from '../common/zod.pipe';
import { APP_CONFIG, type AppConfig, type GatewayListener } from '../config/config';
import { JobNotifier } from '../jobs/job-notifier';
import { JobsService } from '../jobs/jobs.service';
import { SecretsService } from '../deploy/secrets.service';
import { CaService } from '../pki/ca.service';
import { LogIngestService, readLogBody } from '../observability/log-ingest.service';
import { type AgentIdentity, AgentService } from './agent.service';

type AgentRequest = Request & { agent?: AgentIdentity };
const MAX_WAIT_SEC = 25;
const DAY_MS = 86_400_000;
/** F-13: the gateway certificate (90 days) is re-issued when fewer than this many days remain. */
export const GATEWAY_CERT_RENEW_BEFORE_DAYS = 30;
/** Below this, every failed renewal attempt is logged at `fatal` (agents would all drop at expiry). */
export const GATEWAY_CERT_ALERT_DAYS = 14;
/** How often the gateway checks its certificate's remaining lifetime. */
export const GATEWAY_CERT_CHECK_INTERVAL_MS = 6 * 3_600_000;
/** P9: a forbidden-path request is audited at most once per server+path per window. */
export const PATH_DENIED_AUDIT_WINDOW_MS = 10 * 60_000;

/**
 * mTLS Agent Gateway: separate HTTPS listener(s) in the API process — one per management path
 * (P9: `PPANEL_GATEWAY_LISTENERS`). The path of a request is the label of the listener it arrived
 * on, never a client claim.
 * TLS layer: requestCert + rejectUnauthorized against the internal CA only (spoofed CAs fail the handshake).
 * App layer: serial/revocation/CN check against agent_certificates on every request, then the
 * server's connection policy must allow the listener's path (403 CONNECTION_PATH_NOT_ALLOWED).
 */
@Injectable()
export class AgentGatewayServer implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly servers = new Map<ConnectionPath, https.Server>();
  private tlsMaterial: { keyPem: string; certPem: string; caPem: string } | undefined;
  private readonly pathDeniedAt = new Map<string, number>();
  private renewTimer: NodeJS.Timeout | undefined;
  private renewing = false;
  /** notAfter of the certificate currently served (F-13). */
  certNotAfter: Date | undefined;

  constructor(
    private readonly agent: AgentService,
    private readonly jobs: JobsService,
    private readonly notifier: JobNotifier,
    private readonly ca: CaService,
    private readonly secrets: SecretsService,
    private readonly logIngest: LogIngestService,
    private readonly audit: AuditService,
    private readonly limiter: RateLimiter,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (this.config.PPANEL_DISABLE_GATEWAY) return;
    await this.startAll(this.config.gatewayListeners);
  }

  /** Starts every configured listener (on failure the ones already started are stopped). */
  async startAll(listeners: GatewayListener[]): Promise<Record<string, number>> {
    const out: Record<string, number> = {};
    try {
      for (const l of listeners) out[l.label] = await this.start(l.port, l.host, l.label);
    } catch (e) {
      await this.stop();
      throw e;
    }
    return out;
  }

  async onApplicationShutdown(): Promise<void> {
    await this.stop();
  }

  /** Port of the `public` listener (or the first one started). */
  get port(): number | undefined {
    return this.portOf('public') ?? this.portOf('private');
  }

  portOf(label: ConnectionPath): number | undefined {
    return (this.servers.get(label)?.address() as AddressInfo | null)?.port;
  }

  async start(port: number, host: string, label: ConnectionPath = 'public'): Promise<number> {
    if (this.servers.has(label)) throw new Error(`gateway listener ${label} already started`);
    if (!this.tlsMaterial) {
      const issued = await this.ca.issueGatewayCert(this.config.gatewayHostnames);
      this.tlsMaterial = issued;
      this.certNotAfter = issued.notAfter;
    }
    const tls = this.tlsMaterial;
    const server = https.createServer(
      {
        key: tls.keyPem,
        cert: tls.certPem,
        ca: [tls.caPem],
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
      },
      this.buildApp(label),
    );
    server.requestTimeout = 60_000;
    server.headersTimeout = 30_000;
    server.keepAliveTimeout = 65_000;
    server.on('tlsClientError', (err) =>
      logger.emit('warn', 'agent gateway TLS handshake rejected', {
        component: 'gateway',
        path: label,
        reason: err.message,
      }),
    );
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve());
    });
    this.servers.set(label, server);
    logger.emit('info', 'agent gateway listening (mTLS)', {
      component: 'gateway',
      path: label,
      port: this.portOf(label),
      host,
      certNotAfter: this.certNotAfter?.toISOString() ?? null,
    });
    if (!this.renewTimer) {
      this.renewTimer = setInterval(() => void this.renewIfDue(), GATEWAY_CERT_CHECK_INTERVAL_MS);
      this.renewTimer.unref();
    }
    return this.portOf(label)!;
  }

  /**
   * F-13: re-issue the gateway server certificate when < GATEWAY_CERT_RENEW_BEFORE_DAYS remain and
   * hot-swap it with `setSecureContext` — new handshakes get the new certificate, established
   * connections (long polls) are not dropped. Returns true when a new certificate was installed.
   */
  async renewIfDue(now = new Date(), force = false): Promise<boolean> {
    if (this.servers.size === 0 || this.renewing) return false;
    const remainingMs = (this.certNotAfter?.getTime() ?? 0) - now.getTime();
    if (!force && remainingMs > GATEWAY_CERT_RENEW_BEFORE_DAYS * DAY_MS) return false;
    this.renewing = true;
    try {
      const tls = await this.ca.issueGatewayCert(this.config.gatewayHostnames);
      for (const server of this.servers.values())
        server.setSecureContext({
          key: tls.keyPem,
          cert: tls.certPem,
          ca: [tls.caPem],
          minVersion: 'TLSv1.2',
        });
      this.tlsMaterial = tls;
      const previous = this.certNotAfter;
      this.certNotAfter = tls.notAfter;
      logger.emit('info', 'agent gateway certificate renewed', {
        component: 'gateway',
        previousNotAfter: previous?.toISOString() ?? null,
        notAfter: tls.notAfter.toISOString(),
      });
      return true;
    } catch (err) {
      const daysLeft = Math.floor(remainingMs / DAY_MS);
      logger.emit(
        daysLeft < GATEWAY_CERT_ALERT_DAYS ? 'fatal' : 'error',
        'agent gateway certificate renewal failed',
        { component: 'gateway', daysLeft, err },
      );
      return false;
    } finally {
      this.renewing = false;
    }
  }

  async stop(): Promise<void> {
    if (this.renewTimer) clearInterval(this.renewTimer);
    this.renewTimer = undefined;
    const all = [...this.servers.values()];
    this.servers.clear();
    this.tlsMaterial = undefined;
    await Promise.all(
      all.map((s) => {
        s.closeAllConnections();
        return new Promise<void>((resolve) => s.close(() => resolve()));
      }),
    );
  }

  /**
   * P9: the server's policy forbids this listener's path → 403 CONNECTION_PATH_NOT_ALLOWED. Audited
   * once per server+path per PATH_DENIED_AUDIT_WINDOW_MS; a misbehaving agent is throttled (429).
   */
  private async denyPath(id: AgentIdentity, path: ConnectionPath): Promise<never> {
    const key = `${id.serverId}:${path}`;
    const now = Date.now();
    const last = this.pathDeniedAt.get(key);
    if (last === undefined || now - last >= PATH_DENIED_AUDIT_WINDOW_MS) {
      this.pathDeniedAt.set(key, now);
      if (this.pathDeniedAt.size > 10_000)
        for (const [k, at] of this.pathDeniedAt)
          if (now - at >= PATH_DENIED_AUDIT_WINDOW_MS) this.pathDeniedAt.delete(k);
      await this.audit.record({
        actorId: id.serverId,
        actorType: 'agent',
        action: 'agent.connection_path_denied',
        targetType: 'server',
        targetId: id.serverId,
        result: 'denied',
        metadata: { path, policy: id.connectionPolicy },
      });
      logger.emit('warn', 'agent request on a forbidden management path', {
        component: 'gateway',
        serverId: id.serverId,
        path,
        policy: id.connectionPolicy,
      });
    }
    this.limiter.hit(`gateway-path-denied:${key}`, 60, 60_000);
    throw new AppError(
      403,
      ERROR_CODES.CONNECTION_PATH_NOT_ALLOWED,
      `The ${path} management path is not allowed by this server's connection policy`,
      { path, policy: id.connectionPolicy },
    );
  }

  buildApp(label: ConnectionPath = 'public'): express.Express {
    const app = express();
    app.disable('x-powered-by');
    app.set('trust proxy', false);
    app.use(requestIdMiddleware('gateway'));

    app.use((req: Request, _res: Response, next: NextFunction) => {
      const v = req.header('x-agent-protocol');
      if (v !== undefined && v.split('.')[0] !== AGENT_PROTOCOL_VERSION) {
        return next(
          new AppError(
            426,
            ERROR_CODES.AGENT_PROTOCOL_UNSUPPORTED,
            `Unsupported agent protocol ${v}; supported: ${AGENT_PROTOCOL_VERSION}`,
          ),
        );
      }
      next();
    });

    // Identity: TLS already verified the chain; now check DB revocation + CN binding.
    app.use(async (req: AgentRequest, _res: Response, next: NextFunction) => {
      try {
        const socket = req.socket as TLSSocket;
        if (!socket.authorized)
          throw AppError.unauthenticated(
            'Client certificate required',
            ERROR_CODES.AGENT_CERT_REVOKED,
          );
        const peer = socket.getPeerCertificate();
        const cn = Array.isArray(peer?.subject?.CN) ? peer.subject.CN[0] : peer?.subject?.CN;
        req.agent = await this.agent.identify(peer?.serialNumber, cn);
        next();
      } catch (e) {
        next(e);
      }
    });

    const ok = (res: Response, data: unknown, status = 200) =>
      res.status(status).json(successEnvelope(data));

    /**
     * P9 endpoint probe: TLS + identity only (DB read, no write), answered on every path so the agent
     * can measure reachability even where its policy forbids traffic (`policyAllows` tells it).
     */
    app.get('/agent/v1/ping', (req: AgentRequest, res: Response) => {
      res.setHeader('Cache-Control', 'no-store');
      ok(res, {
        path: label,
        serverTime: new Date().toISOString(),
        policyAllows: policyAllowsPath(req.agent!.connectionPolicy, label),
      });
    });

    // P9: fail-closed path enforcement for everything else
    app.use(async (req: AgentRequest, _res: Response, next: NextFunction) => {
      try {
        if (!policyAllowsPath(req.agent!.connectionPolicy, label))
          await this.denyPath(req.agent!, label);
        next();
      } catch (e) {
        next(e);
      }
    });

    /** P5 log batches: own body reader (gzip, ≤ 1 MiB compressed / 8 MiB decompressed → 413). */
    app.post('/agent/v1/logs', async (req: AgentRequest, res: Response) => {
      const body = await readLogBody(req);
      ok(res, await this.logIngest.ingest(req.agent!.serverId, body));
    });

    app.use(express.json({ limit: this.config.BODY_LIMIT }));
    const jobIdParam = (req: Request): string => {
      const id = String(req.params.jobId);
      if (!UUID_RE.test(id))
        throw AppError.conflict('Task is not leased to this agent', ERROR_CODES.TASK_NOT_LEASED);
      return id;
    };

    app.post('/agent/v1/heartbeat', async (req: AgentRequest, res: Response) => {
      ok(res, await this.agent.heartbeat(req.agent!, parseWith(heartbeatSchema, req.body)));
    });

    app.get('/agent/v1/tasks', async (req: AgentRequest, res: Response) => {
      const raw = req.query.waitSec;
      const waitSec = raw === undefined ? MAX_WAIT_SEC : Number(raw);
      if (!Number.isFinite(waitSec) || waitSec < 0)
        throw AppError.badRequest('waitSec must be >= 0');
      const deadline = Date.now() + Math.min(waitSec, MAX_WAIT_SEC) * 1000;
      const abort = new AbortController();
      res.on('close', () => abort.abort());
      const serverId = req.agent!.serverId;
      for (;;) {
        if (abort.signal.aborted) return;
        const tasks = await this.jobs.lease(serverId);
        const remaining = deadline - Date.now();
        if (tasks.length > 0 || remaining <= 0) return ok(res, { tasks });
        await this.notifier.wait(serverId, Math.min(1000, remaining), abort.signal);
      }
    });

    app.post('/agent/v1/tasks/:jobId/ack', async (req: AgentRequest, res: Response) => {
      const body = parseWith(taskAckSchema, req.body);
      ok(res, await this.jobs.ack(req.agent!.serverId, jobIdParam(req), body.leaseToken));
    });

    app.post('/agent/v1/tasks/:jobId/result', async (req: AgentRequest, res: Response) => {
      const body = parseWith(taskResultSchema, req.body);
      ok(res, await this.jobs.result(req.agent!.serverId, jobIdParam(req), body));
    });

    /** P4 fetch-once secrets for a leased container.run_candidate task (values never logged). */
    app.post('/agent/v1/tasks/:jobId/secrets', async (req: AgentRequest, res: Response) => {
      const body = parseWith(taskAckSchema, req.body);
      res.setHeader('Cache-Control', 'no-store');
      ok(
        res,
        await this.secrets.fetchForJob(req.agent!.serverId, jobIdParam(req), body.leaseToken),
      );
    });

    app.post('/agent/v1/certificate/rotate', async (req: AgentRequest, res: Response) => {
      const body = parseWith(certificateRotateSchema, req.body);
      ok(res, await this.agent.rotate(req.agent!, body.csrPem));
    });

    app.use((_req: Request, _res: Response, next: NextFunction) =>
      next(AppError.notFound('Route')),
    );
    app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
      const { status, body, headers } = toErrorResponse(err);
      if (headers) for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      if (!res.headersSent) res.status(status).json(body);
    });
    return app;
  }
}
