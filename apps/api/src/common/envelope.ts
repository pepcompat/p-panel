import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
} from '@nestjs/common';
import type { Response } from 'express';
import type { ListEnvelope, Paginate, SuccessEnvelope } from '@ppanel/shared-contracts';
import { map, type Observable } from 'rxjs';
import { currentRequestId } from './request-context';

/** Return from a controller to produce a list envelope with `paginate`. */
export class Paginated<T> {
  constructor(
    public readonly items: T[],
    public readonly paginate: Paginate,
  ) {}
}

/** Cursor-paginated list (`paginate: { limit, hasMore, nextCursor }`) with optional extra `meta`. */
export class CursorPaginated<T> {
  constructor(
    public readonly items: T[],
    public readonly paginate: { limit: number; hasMore: boolean; nextCursor: string | null },
    public readonly meta: Record<string, unknown> = {},
  ) {}
}

export function successEnvelope<T>(data: T, message = 'ok'): SuccessEnvelope<T> {
  return {
    success: true,
    statusCode: 0,
    message,
    data,
    meta: { requestId: currentRequestId() ?? '' },
  };
}

export function listEnvelope<T>(items: T[], paginate: Paginate, message = 'ok'): ListEnvelope<T> {
  return { ...successEnvelope(items, message), paginate };
}

export function wrap(value: unknown): unknown {
  if (value instanceof Paginated) return listEnvelope(value.items, value.paginate);
  if (value instanceof CursorPaginated) {
    const base = successEnvelope(value.items);
    return { ...base, paginate: value.paginate, meta: { ...value.meta, ...base.meta } };
  }
  return successEnvelope(value ?? null);
}

@Injectable()
export class EnvelopeInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const res = context.switchToHttp().getResponse<Response>();
    return next.handle().pipe(
      map((value) => {
        if (res.statusCode === 204) return undefined;
        return wrap(value);
      }),
    );
  }
}
