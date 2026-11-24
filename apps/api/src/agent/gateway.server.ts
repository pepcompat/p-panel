import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import {
  AGENT_PROTOCOL_VERSION,
  certificateRotateSchema,
  ERROR_CODES,
  heartbeatSchema,
  taskAckSchema,
  taskResultSchema,
} from '@ppanel/shared-contracts';
import express, { type NextFunction, type Request, type Response } from 'express';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { AppError } from '../common/app-error';
import { successEnvelope } from '../common/envelope';
import { toErrorResponse } from '../common/exception.filter';
import { UUID_RE } from '../common/ids';
import { logger } from '../common/logger';
import { requestIdMiddleware } from '../common/request-id.middleware';
import { parseWith } from '../common/zod.pipe';
import { APP_CONFIG, type AppConfig } from '../config/config';
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

/**
 * mTLS Agent Gateway: separate HTTPS listener in the API process.
 * TLS layer: requestCert + rejectUnauthorized against the internal CA only (spoofed CAs fail the handshake).
 * App layer: serial/revocation/CN check against agent_certificates on every request.
 */
@Injectable()
export class AgentGatewayServer implements OnApplicationBootstrap, OnApplicationShutdown {
  private server: https.Server | undefined;
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
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (this.config.PPANEL_DISABLE_GATEWAY) return;
    await this.start(this.config.AGENT_GATEWAY_PORT, this.config.AGENT_GATEWAY_HOST);
  }

  async onApplicationShutdown(): Promise<void> {
    await this.stop();
  }

  get port(): number | undefined {
    return (this.server?.address() as AddressInfo | null)?.port;
  }

  async start(port: number, host: string): Promise<number> {
    const tls = await this.ca.issueGatewayCert(this.config.gatewayHostnames);
    const server = https.createServer(
      {
        key: tls.keyPem,
        cert: tls.certPem,
        ca: [tls.caPem],
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
      },
      this.buildApp(),
    );
    this.certNotAfter = tls.notAfter;
    server.requestTimeout = 60_000;
    server.headersTimeout = 30_000;
    server.keepAliveTimeout = 65_000;
    server.on('tlsClientError', (err) =>
      logger.emit('warn', 'agent gateway TLS handshake rejected', {
        component: 'gateway',
        reason: err.message,
      }),
    );
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve());
    });
    this.server = server;
    logger.emit('info', 'agent gateway listening (mTLS)', {
      component: 'gateway',
      port: this.port,
      host,
      certNotAfter: tls.notAfter.toISOString(),
    });
    this.renewTimer = setInterval(() => void this.renewIfDue(), GATEWAY_CERT_CHECK_INTERVAL_MS);
    this.renewTimer.unref();
    return this.port!;
  }

  /**
   * F-13: re-issue the gateway server certificate when < GATEWAY_CERT_RENEW_BEFORE_DAYS remain and
   * hot-swap it with `setSecureContext` — new handshakes get the new certificate, established
   * connections (long polls) are not dropped. Returns true when a new certificate was installed.
   */
  async renewIfDue(now = new Date(), force = false): Promise<boolean> {
    const server = this.server;
    if (!server || this.renewing) return false;
    const remainingMs = (this.certNotAfter?.getTime() ?? 0) - now.getTime();
    if (!force && remainingMs > GATEWAY_CERT_RENEW_BEFORE_DAYS * DAY_MS) return false;
    this.renewing = true;
    try {
      const tls = await this.ca.issueGatewayCert(this.config.gatewayHostnames);
      server.setSecureContext({
        key: tls.keyPem,
        cert: tls.certPem,
        ca: [tls.caPem],
        minVersion: 'TLSv1.2',
      });
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
    const s = this.server;
    this.server = undefined;
    if (!s) return;
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }

  buildApp(): express.Express {
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
