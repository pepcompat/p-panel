import type { NextFunction, Request, Response } from 'express';
import { uuidv7 } from './ids';
import { logger } from './logger';
import { requestContext } from './request-context';

const SAFE_ID = /^[A-Za-z0-9._:-]{8,64}$/;

/** Assigns/echoes X-Request-ID, binds it to AsyncLocalStorage, and writes one access log line. */
export function requestIdMiddleware(component: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const incoming = req.header('x-request-id');
    const requestId = incoming && SAFE_ID.test(incoming) ? incoming : uuidv7();
    res.setHeader('X-Request-ID', requestId);
    const started = process.hrtime.bigint();
    res.on('finish', () => {
      logger.emit(res.statusCode >= 500 ? 'error' : 'info', 'http request', {
        requestId,
        component,
        method: req.method,
        path: req.path, // never the query string (may carry filters only, but keep logs minimal)
        status: res.statusCode,
        durationMs: Number((process.hrtime.bigint() - started) / 1_000_000n),
      });
    });
    requestContext.run({ requestId, ip: req.ip }, () => next());
  };
}
