export type UiErrorKind =
  | 'auth'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'validation'
  | 'rate_limited'
  | 'server'
  | 'network'
  | 'bad_request';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly requestId: string | null;

  constructor(opts: { status: number; code: string; message: string; details?: unknown; requestId?: string | null }) {
    super(opts.message);
    this.name = 'ApiError';
    this.status = opts.status;
    this.code = opts.code;
    this.details = opts.details;
    this.requestId = opts.requestId ?? null;
  }

  get kind(): UiErrorKind {
    if (this.status === 0) return 'network';
    if (this.status === 401) return 'auth';
    if (this.status === 403) return 'forbidden';
    if (this.status === 404) return 'not_found';
    if (this.status === 409) return 'conflict';
    if (this.status === 422) return 'validation';
    if (this.status === 429) return 'rate_limited';
    if (this.status >= 500) return 'server';
    return 'bad_request';
  }

  /** Field errors from a 422 `details` payload, if it is shaped like [{ field, message }] or { field: message }. */
  get fieldErrors(): Record<string, string> {
    const d = this.details;
    const out: Record<string, string> = {};
    if (Array.isArray(d)) {
      for (const item of d) {
        if (item && typeof item === 'object') {
          const rec = item as Record<string, unknown>;
          const field = (rec.field ?? rec.path ?? rec.property) as unknown;
          const msg = (rec.message ?? rec.msg) as unknown;
          const key = Array.isArray(field) ? field.join('.') : typeof field === 'string' ? field : null;
          if (key && typeof msg === 'string') out[key] = msg;
        }
      }
    } else if (d && typeof d === 'object') {
      for (const [k, v] of Object.entries(d as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
    }
    return out;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** Normalise anything thrown into an ApiError so views can always show code + requestId. */
export function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  const message = e instanceof Error ? e.message : String(e);
  return new ApiError({ status: 0, code: 'CLIENT_ERROR', message });
}
