import { Inject, Injectable, type OnApplicationBootstrap, type OnApplicationShutdown } from '@nestjs/common';
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
import { CaService } from '../pki/ca.service';
import { type AgentIdentity, AgentService } from './agent.service';

type AgentRequest = Request & { agent?: AgentIdentity };
const MAX_WAIT_SEC = 25;

/**
 * mTLS Agent Gateway: separate HTTPS listener in the API process.
 * TLS layer: requestCert + rejectUnauthorized against the internal CA only (spoofed CAs fail the handshake).
 * App layer: serial/revocation/CN check against agent_certificates on every request.
 */
@Injectable()
export class AgentGatewayServer implements OnApplicationBootstrap, OnApplicationShutdown {
  private server: https.Server | undefined;

  constructor(
    private readonly agent: AgentService,
    private readonly jobs: JobsService,
    private readonly notifier: JobNotifier,
    private readonly ca: CaService,
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
    server.requestTimeout = 60_000;
    server.headersTimeout = 30_000;
    server.keepAliveTimeout = 65_000;
    server.on('tlsClientError', (err) => logger.emit('warn', 'agent gateway TLS handshake rejected', { component: 'gateway', reason: err.message }));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => resolve());
    });
    this.server = server;
    logger.emit('info', 'agent gateway listening (mTLS)', { component: 'gateway', port: this.port, host });
    return this.port!;
  }

  async stop(): Promise<void> {
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
        return next(new AppError(426, ERROR_CODES.AGENT_PROTOCOL_UNSUPPORTED, `Unsupported agent protocol ${v}; supported: ${AGENT_PROTOCOL_VERSION}`));
      }
      next();
    });

    // Identity: TLS already verified the chain; now check DB revocation + CN binding.
    app.use(async (req: AgentRequest, _res: Response, next: NextFunction) => {
      try {
        const socket = req.socket as TLSSocket;
        if (!socket.authorized) throw AppError.unauthenticated('Client certificate required', ERROR_CODES.AGENT_CERT_REVOKED);
        const peer = socket.getPeerCertificate();
        const cn = Array.isArray(peer?.subject?.CN) ? peer.subject.CN[0] : peer?.subject?.CN;
        req.agent = await this.agent.identify(peer?.serialNumber, cn);
        next();
      } catch (e) {
        next(e);
      }
    });

    app.use(express.json({ limit: this.config.BODY_LIMIT }));

    const ok = (res: Response, data: unknown, status = 200) => res.status(status).json(successEnvelope(data));
    const jobIdParam = (req: Request): string => {
      const id = String(req.params.jobId);
      if (!UUID_RE.test(id)) throw AppError.conflict('Task is not leased to this agent', ERROR_CODES.TASK_NOT_LEASED);
      return id;
    };

    app.post('/agent/v1/heartbeat', async (req: AgentRequest, res: Response) => {
      ok(res, await this.agent.heartbeat(req.agent!, parseWith(heartbeatSchema, req.body)));
    });

    app.get('/agent/v1/tasks', async (req: AgentRequest, res: Response) => {
      const raw = req.query.waitSec;
      const waitSec = raw === undefined ? MAX_WAIT_SEC : Number(raw);
      if (!Number.isFinite(waitSec) || waitSec < 0) throw AppError.badRequest('waitSec must be >= 0');
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

    app.post('/agent/v1/certificate/rotate', async (req: AgentRequest, res: Response) => {
      const body = parseWith(certificateRotateSchema, req.body);
      ok(res, await this.agent.rotate(req.agent!, body.csrPem));
    });

    app.use((_req: Request, _res: Response, next: NextFunction) => next(AppError.notFound('Route')));
    app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
      const { status, body, headers } = toErrorResponse(err);
      if (headers) for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      if (!res.headersSent) res.status(status).json(body);
    });
    return app;
  }
}
