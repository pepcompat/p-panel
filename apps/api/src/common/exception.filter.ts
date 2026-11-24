import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ERROR_CODES, type ErrorEnvelope } from '@ppanel/shared-contracts';
import { Prisma } from '@prisma/client';
import { ZodError } from 'zod';
import { AppError } from './app-error';
import { logger } from './logger';
import { currentRequestId } from './request-context';

const STATUS_CODES: Record<number, string> = {
  400: ERROR_CODES.BAD_REQUEST,
  401: ERROR_CODES.UNAUTHENTICATED,
  403: ERROR_CODES.FORBIDDEN,
  404: ERROR_CODES.NOT_FOUND,
  409: ERROR_CODES.CONFLICT,
  413: ERROR_CODES.PAYLOAD_TOO_LARGE,
  422: ERROR_CODES.VALIDATION_FAILED,
  429: ERROR_CODES.RATE_LIMITED,
};

export function zodDetails(err: ZodError): Array<{ path: string; message: string }> {
  return err.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
}

/** Prisma codes for "database unreachable / connection dropped / pool exhausted" (transient). */
const DB_UNAVAILABLE_CODES = new Set([
  'P1001', // can't reach database server
  'P1002', // database server timed out
  'P1008', // operations timed out
  'P1017', // server has closed the connection
  'P2024', // timed out fetching a connection from the pool
]);
const NET_ERRNOS = /\b(ECONNREFUSED|ECONNRESET|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN)\b/;
export const DB_RETRY_AFTER_SEC = 5;

/**
 * F-11: true when `err` means Postgres is (temporarily) unreachable — answered with 503 + Retry-After
 * instead of 500 so load balancers, the UI and agents treat it as transient.
 */
export function isDatabaseUnavailable(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientInitializationError) return true;
  if (err instanceof Prisma.PrismaClientRustPanicError) return false;
  const e = err as { code?: unknown; errorCode?: unknown; message?: unknown; name?: unknown };
  if (err instanceof Prisma.PrismaClientKnownRequestError)
    return DB_UNAVAILABLE_CODES.has(err.code);
  if (typeof e?.errorCode === 'string' && DB_UNAVAILABLE_CODES.has(e.errorCode)) return true;
  if (err instanceof Prisma.PrismaClientUnknownRequestError)
    return (
      NET_ERRNOS.test(err.message) ||
      /Can't reach database server|Connection refused|connection (closed|terminated)|Server has closed the connection/i.test(
        err.message,
      )
    );
  return false;
}

/** Converts any thrown value into `{ status, body }` using the standard error envelope. */
export function toErrorResponse(err: unknown): {
  status: number;
  body: ErrorEnvelope;
  headers?: Record<string, string>;
} {
  const meta = { requestId: currentRequestId() ?? '' };
  if (err instanceof AppError) {
    return {
      status: err.status,
      headers: err.headers,
      body: {
        error: {
          code: err.code,
          message: err.message,
          ...(err.details !== undefined ? { details: err.details } : {}),
        },
        meta,
      },
    };
  }
  if (err instanceof ZodError) {
    return {
      status: 422,
      body: {
        error: {
          code: ERROR_CODES.VALIDATION_FAILED,
          message: 'Validation failed',
          details: zodDetails(err),
        },
        meta,
      },
    };
  }
  if (err instanceof HttpException) {
    const status = err.getStatus();
    const message =
      status === 404 ? 'Route not found' : status >= 500 ? 'Internal server error' : err.message;
    return {
      status,
      body: {
        error: {
          code:
            STATUS_CODES[status] ??
            (status >= 500 ? ERROR_CODES.INTERNAL_ERROR : ERROR_CODES.BAD_REQUEST),
          message,
        },
        meta,
      },
    };
  }
  // body-parser / express errors carry `status` + `type`
  const e = err as { status?: number; statusCode?: number; type?: string; expose?: boolean };
  const status = e?.status ?? e?.statusCode;
  if (typeof status === 'number' && status >= 400 && status < 500) {
    const code =
      e.type === 'entity.too.large'
        ? ERROR_CODES.PAYLOAD_TOO_LARGE
        : e.type === 'entity.parse.failed'
          ? ERROR_CODES.BAD_REQUEST
          : (STATUS_CODES[status] ?? ERROR_CODES.BAD_REQUEST);
    const message =
      code === ERROR_CODES.PAYLOAD_TOO_LARGE
        ? 'Request body too large'
        : code === ERROR_CODES.BAD_REQUEST
          ? 'Malformed request body'
          : 'Bad request';
    return { status, body: { error: { code, message }, meta } };
  }
  if (isDatabaseUnavailable(err)) {
    logger.emit('error', 'database unavailable', { err });
    return {
      status: 503,
      headers: { 'Retry-After': String(DB_RETRY_AFTER_SEC) },
      body: {
        error: {
          code: ERROR_CODES.SERVICE_UNAVAILABLE,
          message: 'Service temporarily unavailable, retry later',
          details: { retryAfterSec: DB_RETRY_AFTER_SEC },
        },
        meta,
      },
    };
  }
  logger.emit('error', 'unhandled error', { err });
  return {
    status: 500,
    body: { error: { code: ERROR_CODES.INTERNAL_ERROR, message: 'Internal server error' }, meta },
  };
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();
    const { status, body, headers } = toErrorResponse(exception);
    if (status >= 500)
      logger.emit('error', 'request failed', {
        path: req.path,
        method: req.method,
        status,
        err: exception,
      });
    if (res.headersSent) return;
    if (headers) for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.status(status).json(body);
  }
}
