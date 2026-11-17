import { ERROR_CODES, type ErrorCode } from '@ppanel/shared-contracts';

export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: ErrorCode | string,
    message: string,
    public readonly details?: unknown,
    public readonly headers?: Record<string, string>,
  ) {
    super(message);
    this.name = 'AppError';
  }

  static badRequest(message = 'Bad request', details?: unknown) {
    return new AppError(400, ERROR_CODES.BAD_REQUEST, message, details);
  }
  static validation(details: unknown, message = 'Validation failed') {
    return new AppError(422, ERROR_CODES.VALIDATION_FAILED, message, details);
  }
  static unauthenticated(message = 'Authentication required', code: string = ERROR_CODES.UNAUTHENTICATED) {
    return new AppError(401, code, message);
  }
  static forbidden(message = 'You do not have permission to perform this action', code: string = ERROR_CODES.FORBIDDEN) {
    return new AppError(403, code, message);
  }
  static notFound(what = 'Resource') {
    return new AppError(404, ERROR_CODES.NOT_FOUND, `${what} not found`);
  }
  static conflict(message: string, code: string = ERROR_CODES.CONFLICT, details?: unknown) {
    return new AppError(409, code, message, details);
  }
  static rateLimited(retryAfterSec: number) {
    return new AppError(429, ERROR_CODES.RATE_LIMITED, 'Too many requests, slow down', { retryAfterSec }, {
      'Retry-After': String(retryAfterSec),
    });
  }
}
