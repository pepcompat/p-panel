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
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(cookieParser());
  app.use(express.json({ limit: config.BODY_LIMIT, type: ['application/json', 'application/*+json'] }));
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
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Request-ID', 'X-Client-Version', 'X-CSRF', 'X-Step-Up', 'If-Match', 'Idempotency-Key'],
    exposedHeaders: ['X-Request-ID', 'ETag', 'Retry-After'],
    maxAge: 600,
  });
  app.setGlobalPrefix(API_PREFIX);
  app.enableShutdownHooks();
  return app;
}

export type { INestApplication };
