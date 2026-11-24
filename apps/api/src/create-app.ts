import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import express, { type NextFunction, type Request, type Response } from 'express';
import { AppModule } from './app.module';
import { toErrorResponse } from './common/exception.filter';
import { logger } from './common/logger';
import { requestIdMiddleware } from './common/request-id.middleware';
import type { AppConfig } from './config/config';
import { ScrapeService } from './observability/scrape.service';

export const API_PREFIX = 'api/v1';

/** Builds (but does not listen) the Center API with all cross-cutting middleware. */
export async function createApp(config: AppConfig): Promise<NestExpressApplication> {
  logger.setLevel(config.LOG_LEVEL);
  const app = await NestFactory.create<NestExpressApplication>(AppModule.forRoot(config), {
    bodyParser: false,
    logger,
    abortOnError: false,
  });
  app.disable('x-powered-by');
  app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);
  app.set('query parser', 'simple');

  app.use(requestIdMiddleware('api'));
  const hsts = config.isProduction || config.COOKIE_SECURE;
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    // P7.01: the API only serves JSON / SSE — nothing may execute, embed or frame a response.
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    if (hsts) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
  // P5: Prometheus scrape endpoint (static bearer, outside /api/v1 and the user AuthGuard)
  app.use('/internal/metrics', app.get(ScrapeService).handler());
  app.use(cookieParser());
  // GitHub webhooks: keep the exact raw bytes for HMAC verification (parsed later by the handler).
  app.use(`/${API_PREFIX}/webhooks`, express.raw({ type: () => true, limit: '1mb' }));
  // P10: SSH credential bodies (imported private keys) are capped at 16 KiB → 413
  app.use(
    `/${API_PREFIX}/ssh/credentials`,
    express.json({ limit: '16kb', type: ['application/json', 'application/*+json'] }),
  );
  app.use(
    express.json({
      limit: config.BODY_LIMIT,
      type: ['application/json', 'application/*+json'],
      // SEC-P7-06: PostgreSQL text cannot store NUL → would surface as a 500 deep in a handler
      verify: (_req, _res, buf) => {
        if (buf.includes('\\u0000'))
          throw Object.assign(new Error('NUL bytes are not allowed'), { status: 400 });
      },
    }),
  );
  // body-parser errors (too large / malformed JSON) → standard error envelope
  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (!err) return next();
    const { status, body } = toErrorResponse(err);
    res.status(status).json(body);
  });
  app.enableCors({
    origin: config.webOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Accept',
      'Authorization',
      'X-Request-ID',
      'X-Client-Version',
      'X-CSRF',
      'X-Step-Up',
      'If-Match',
      'Idempotency-Key',
    ],
    exposedHeaders: ['X-Request-ID', 'ETag', 'Retry-After'],
    maxAge: 600,
  });
  app.setGlobalPrefix(API_PREFIX);
  app.enableShutdownHooks();
  return app;
}

export type { INestApplication };
