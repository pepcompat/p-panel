import type { Meta, Paginate } from '@ppanel/shared-contracts';
import { ApiError } from './errors';
import { tokenStore as defaultTokenStore } from './token-store';
import { omitNullish, uuid } from '../utils';

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue | QueryValue[]>;

export interface RequestOptions {
  query?: Query;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Attach bearer token (default true). */
  auth?: boolean;
  /** Use a caller-provided X-Request-ID (otherwise a fresh UUID is generated). */
  requestId?: string;
  /**
   * Keep explicit `null` values in the body (default: null keys are omitted per COMPATTANA). Only for
   * fields where null has a meaning, e.g. PATCH /servers/:id { groupId: null } = remove from group.
   */
  keepNulls?: boolean;
}

export interface ApiResult<T> {
  data: T;
  meta: Meta | null;
  paginate?: Paginate;
  status: number;
  /** Request id echoed by the server (falls back to the one we sent). */
  requestId: string;
  headers: Headers;
}

export interface TokenStoreLike {
  get(): string | null;
  set(token: string | null): void;
}

export interface ApiClientOptions {
  baseUrl: string;
  clientVersion: string;
  fetch?: typeof fetch;
  tokenStore?: TokenStoreLike;
  /** Called once when a 401 cannot be recovered by a refresh (e.g. redirect to /login). */
  onAuthFailure?: () => void;
}

/** Endpoints whose 401 means "bad credentials", not "expired access token". */
const NO_REFRESH_PATHS = [
  '/auth/login',
  '/auth/refresh',
  '/auth/mfa/verify',
  '/auth/logout',
  '/setup/',
];

function buildQuery(query?: Query): string {
  if (!query) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    const values = Array.isArray(v) ? v : [v];
    for (const item of values) {
      if (item === undefined || item === null || item === '') continue;
      p.append(k, String(item));
    }
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function readJson(res: Response): Promise<unknown> {
  if (res.status === 204) return undefined;
  const text = await res.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** `Retry-After` as seconds (delta-seconds or HTTP-date); null when absent/invalid. */
export function parseRetryAfter(v: string | null, now = Date.now()): number | null {
  if (!v) return null;
  const n = Number(v);
  if (Number.isFinite(n)) return Math.max(0, Math.ceil(n));
  const d = Date.parse(v);
  return Number.isFinite(d) ? Math.max(0, Math.ceil((d - now) / 1000)) : null;
}

export function createApiClient(opts: ApiClientOptions) {
  const store = opts.tokenStore ?? defaultTokenStore;
  const doFetch: typeof fetch = (input, init) => (opts.fetch ?? globalThis.fetch)(input, init);
  let refreshInFlight: Promise<boolean> | null = null;

  /** Single-flight refresh: concurrent 401s share one POST /auth/refresh. */
  function refresh(): Promise<boolean> {
    if (!refreshInFlight) {
      refreshInFlight = (async () => {
        try {
          const res = await doFetch(`${opts.baseUrl}/auth/refresh`, {
            method: 'POST',
            credentials: 'include',
            headers: {
              Accept: 'application/json',
              'X-CSRF': '1',
              'X-Request-ID': uuid(),
              'X-Client-Version': opts.clientVersion,
            },
          });
          if (!res.ok) {
            store.set(null);
            return false;
          }
          const json = (await readJson(res)) as { data?: { accessToken?: string } } | undefined;
          const token = json?.data?.accessToken;
          if (!token) {
            store.set(null);
            return false;
          }
          store.set(token);
          return true;
        } catch {
          store.set(null);
          return false;
        } finally {
          // allow a later refresh once this one settled
          setTimeout(() => (refreshInFlight = null), 0);
        }
      })();
    }
    return refreshInFlight;
  }

  async function send(
    method: string,
    path: string,
    o: RequestOptions,
    requestId: string,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'X-Request-ID': requestId,
      'X-Client-Version': opts.clientVersion,
      ...o.headers,
    };
    let body: string | undefined;
    if (o.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(o.keepNulls ? o.body : omitNullish(o.body));
    }
    const token = o.auth === false ? null : store.get();
    if (token) headers.Authorization = `Bearer ${token}`;
    try {
      return await doFetch(`${opts.baseUrl}${path}${buildQuery(o.query)}`, {
        method,
        headers,
        body,
        credentials: 'include',
        signal: o.signal,
      });
    } catch (e) {
      if ((e as Error)?.name === 'AbortError') throw e;
      throw new ApiError({
        status: 0,
        code: 'NETWORK_ERROR',
        message:
          'Cannot reach the pPanel API. Check your connection or that the Center is running.',
        requestId,
      });
    }
  }

  async function request<T>(
    method: string,
    path: string,
    o: RequestOptions = {},
  ): Promise<ApiResult<T>> {
    const requestId = o.requestId ?? uuid();
    let res = await send(method, path, o, requestId);

    const canRefresh = o.auth !== false && !NO_REFRESH_PATHS.some((p) => path.startsWith(p));
    if (res.status === 401 && canRefresh) {
      const ok = await refresh();
      if (ok) {
        res = await send(method, path, o, requestId); // retry exactly once
      }
      if (!ok || res.status === 401) {
        store.set(null);
        opts.onAuthFailure?.();
      }
    }

    const json = (await readJson(res)) as Record<string, unknown> | undefined;
    const meta = (json?.meta as Meta | undefined) ?? null;
    const echoedId = meta?.requestId ?? res.headers.get('X-Request-ID') ?? requestId;

    if (!res.ok) {
      const err = (json?.error ?? null) as {
        code?: string;
        message?: string;
        details?: unknown;
      } | null;
      throw new ApiError({
        status: res.status,
        code: err?.code ?? `HTTP_${res.status}`,
        message: err?.message ?? (res.statusText || `Request failed with status ${res.status}`),
        details: err?.details,
        requestId: echoedId,
        retryAfterSec: parseRetryAfter(res.headers.get('Retry-After')),
      });
    }

    if (res.status === 204 || json === undefined) {
      return {
        data: undefined as T,
        meta,
        status: res.status,
        requestId: echoedId,
        headers: res.headers,
      };
    }
    if (json.success !== true || !('data' in json)) {
      throw new ApiError({
        status: res.status,
        code: 'MALFORMED_ENVELOPE',
        message: 'The API returned a response that does not match the pPanel envelope.',
        requestId: echoedId,
      });
    }
    return {
      data: json.data as T,
      meta,
      paginate: json.paginate as Paginate | undefined,
      status: res.status,
      requestId: echoedId,
      headers: res.headers,
    };
  }

  return {
    request,
    refresh,
    get: <T>(path: string, o?: RequestOptions) => request<T>('GET', path, o).then((r) => r.data),
    list: <T>(path: string, o?: RequestOptions) =>
      request<T[]>('GET', path, o).then((r) => ({
        items: r.data,
        paginate: r.paginate ?? { page: 1, limit: r.data.length, total: r.data.length },
        requestId: r.requestId,
      })),
    post: <T>(path: string, body?: unknown, o?: RequestOptions) =>
      request<T>('POST', path, { ...o, body }).then((r) => r.data),
    patch: <T>(path: string, body?: unknown, o?: RequestOptions) =>
      request<T>('PATCH', path, { ...o, body }).then((r) => r.data),
    del: <T = void>(path: string, o?: RequestOptions) =>
      request<T>('DELETE', path, o).then((r) => r.data),
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
