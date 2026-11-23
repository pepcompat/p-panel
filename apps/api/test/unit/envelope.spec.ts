import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { AppError } from '../../src/common/app-error';
import { Paginated, wrap } from '../../src/common/envelope';
import { toErrorResponse } from '../../src/common/exception.filter';
import { requestContext } from '../../src/common/request-context';

const inCtx = <T>(fn: () => T) => requestContext.run({ requestId: 'rid-1' }, fn);

describe('envelopes', () => {
  it('success', () => {
    expect(inCtx(() => wrap({ a: 1 }))).toEqual({
      success: true,
      statusCode: 0,
      message: 'ok',
      data: { a: 1 },
      meta: { requestId: 'rid-1' },
    });
  });
  it('list with sibling paginate', () => {
    expect(inCtx(() => wrap(new Paginated([1, 2], { page: 1, limit: 20, total: 2 })))).toEqual({
      success: true,
      statusCode: 0,
      message: 'ok',
      data: [1, 2],
      paginate: { page: 1, limit: 20, total: 2 },
      meta: { requestId: 'rid-1' },
    });
  });
  it('error from AppError (with details + headers)', () => {
    const r = inCtx(() => toErrorResponse(AppError.rateLimited(30)));
    expect(r.status).toBe(429);
    expect(r.headers).toEqual({ 'Retry-After': '30' });
    expect(r.body).toEqual({
      error: { code: 'RATE_LIMITED', message: expect.any(String), details: { retryAfterSec: 30 } },
      meta: { requestId: 'rid-1' },
    });
  });
  it('error from ZodError → 422 with path details', () => {
    const err = z.object({ a: z.string() }).safeParse({ a: 1 }).error!;
    const r = inCtx(() => toErrorResponse(err));
    expect(r.status).toBe(422);
    expect(r.body.error).toEqual({
      code: 'VALIDATION_FAILED',
      message: 'Validation failed',
      details: [{ path: 'a', message: expect.any(String) }],
    });
  });
  it('body-parser errors and unknown errors never leak internals', () => {
    expect(
      toErrorResponse(Object.assign(new Error('x'), { status: 413, type: 'entity.too.large' })).body
        .error.code,
    ).toBe('PAYLOAD_TOO_LARGE');
    expect(
      toErrorResponse(Object.assign(new Error('x'), { status: 400, type: 'entity.parse.failed' }))
        .body.error.code,
    ).toBe('BAD_REQUEST');
    const r = toErrorResponse(new Error('connection string postgres://user:secret@host'));
    expect(r.status).toBe(500);
    expect(r.body.error).toEqual({ code: 'INTERNAL_ERROR', message: 'Internal server error' });
  });
});
