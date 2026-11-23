import { describe, expect, it, vi } from 'vitest';
import { createApiClient } from '@/lib/api/client';
import { ApiError } from '@/lib/api/errors';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
const okEnv = (data: unknown, extra: Record<string, unknown> = {}) => ({
  success: true,
  statusCode: 0,
  message: 'ok',
  data,
  meta: { requestId: 'srv-req-1' },
  ...extra,
});

function setup(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
  token: string | null = 'access-1',
) {
  let current = token;
  const store = { get: () => current, set: (t: string | null) => (current = t) };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    handler(String(input), init ?? {}),
  );
  const onAuthFailure = vi.fn();
  const client = createApiClient({
    baseUrl: 'http://api.test/api/v1',
    clientVersion: '9.9.9',
    fetch: fetchMock as unknown as typeof fetch,
    tokenStore: store,
    onAuthFailure,
  });
  return { client, fetchMock, onAuthFailure, store };
}
const headersOf = (init: RequestInit) => init.headers as Record<string, string>;

describe('api client — envelope handling', () => {
  it('unwraps data, sends bearer, X-Request-ID (uuid) and X-Client-Version', async () => {
    const { client, fetchMock } = setup(() => json(200, okEnv({ a: 1 })));
    const res = await client.request<{ a: number }>('GET', '/servers/1');
    expect(res.data).toEqual({ a: 1 });
    expect(res.requestId).toBe('srv-req-1');
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('http://api.test/api/v1/servers/1');
    const h = headersOf(init!);
    expect(h.Authorization).toBe('Bearer access-1');
    expect(h['X-Request-ID']).toMatch(UUID_RE);
    expect(h['X-Client-Version']).toBe('9.9.9');
    expect(h.Accept).toBe('application/json');
    expect(init!.credentials).toBe('include');
  });

  it('serialises query params, drops empty ones, and omits null body keys', async () => {
    const { client, fetchMock } = setup(() => json(200, okEnv({})));
    await client.patch(
      '/servers/1',
      { name: 'x', groupId: null, tags: undefined },
      { query: { a: 1, b: '', c: null, 'created_at[gte]': '2026-01-01' } },
    );
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('http://api.test/api/v1/servers/1?a=1&created_at%5Bgte%5D=2026-01-01');
    expect(JSON.parse(String(init!.body))).toEqual({ name: 'x' });
    expect(headersOf(init!)['Content-Type']).toBe('application/json');
  });

  it('returns items + paginate for list envelopes', async () => {
    const { client } = setup(() =>
      json(200, okEnv([1, 2], { paginate: { page: 2, limit: 2, total: 9 } })),
    );
    const res = await client.list<number>('/servers');
    expect(res.items).toEqual([1, 2]);
    expect(res.paginate).toEqual({ page: 2, limit: 2, total: 9 });
  });

  it('maps the error envelope to ApiError with code, details and requestId', async () => {
    const { client } = setup(() =>
      json(422, {
        error: {
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: [{ field: 'name', message: 'bad' }],
        },
        meta: { requestId: 'req-err-7' },
      }),
    );
    const err = (await client.get('/x').catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({
      status: 422,
      code: 'VALIDATION_FAILED',
      message: 'Validation failed',
      requestId: 'req-err-7',
    });
    expect(err.kind).toBe('validation');
    expect(err.fieldErrors).toEqual({ name: 'bad' });
  });

  it('falls back to the response X-Request-ID / sent id when the body is not JSON', async () => {
    const { client } = setup(
      () =>
        new Response('<html>bad gateway</html>', {
          status: 502,
          headers: { 'X-Request-ID': 'edge-1' },
        }),
    );
    const err = (await client.get('/x').catch((e: unknown) => e)) as ApiError;
    expect(err).toMatchObject({ status: 502, code: 'HTTP_502', requestId: 'edge-1' });
    expect(err.kind).toBe('server');
  });

  it('reports network failures as NETWORK_ERROR with the request id that was sent', async () => {
    const { client, fetchMock } = setup(() => {
      throw new TypeError('Failed to fetch');
    });
    const err = (await client.get('/x').catch((e: unknown) => e)) as ApiError;
    expect(err).toMatchObject({ status: 0, code: 'NETWORK_ERROR' });
    expect(err.requestId).toBe(headersOf(fetchMock.mock.calls[0]![1]!)['X-Request-ID']);
  });

  it('treats 204 as no content', async () => {
    const { client } = setup(() => new Response(null, { status: 204 }));
    await expect(client.del('/role-bindings/1')).resolves.toBeUndefined();
  });

  it('rejects a 2xx body that is not a pPanel envelope', async () => {
    const { client } = setup(() => json(200, { hello: 'world' }));
    await expect(client.get('/x')).rejects.toMatchObject({ code: 'MALFORMED_ENVELOPE' });
  });
});

describe('api client — 401 → refresh once → retry', () => {
  it('refreshes with X-CSRF: 1 then retries the original request with the new token and same request id', async () => {
    const { client, fetchMock, store, onAuthFailure } = setup((url, init) => {
      if (url.endsWith('/auth/refresh'))
        return json(200, okEnv({ accessToken: 'access-2', expiresIn: 900 }));
      return headersOf(init).Authorization === 'Bearer access-2'
        ? json(200, okEnv('ok'))
        : json(401, { error: { code: 'UNAUTHENTICATED', message: 'expired' } });
    });
    await expect(client.get('/auth/me')).resolves.toBe('ok');
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const refreshCall = fetchMock.mock.calls[1]!;
    expect(String(refreshCall[0])).toBe('http://api.test/api/v1/auth/refresh');
    expect(refreshCall[1]!.method).toBe('POST');
    expect(refreshCall[1]!.credentials).toBe('include');
    expect(headersOf(refreshCall[1]!)['X-CSRF']).toBe('1');
    expect(headersOf(fetchMock.mock.calls[2]![1]!)['X-Request-ID']).toBe(
      headersOf(fetchMock.mock.calls[0]![1]!)['X-Request-ID'],
    );
    expect(store.get()).toBe('access-2');
    expect(onAuthFailure).not.toHaveBeenCalled();
  });

  it('shares one refresh between concurrent 401s', async () => {
    let refreshes = 0;
    const { client } = setup(async (url, init) => {
      if (url.endsWith('/auth/refresh')) {
        refreshes++;
        await new Promise((r) => setTimeout(r, 10));
        return json(200, okEnv({ accessToken: 'access-2', expiresIn: 900 }));
      }
      return headersOf(init).Authorization === 'Bearer access-2'
        ? json(200, okEnv(url))
        : json(401, { error: { code: 'UNAUTHENTICATED', message: 'x' } });
    });
    const out = await Promise.all([client.get('/a'), client.get('/b'), client.get('/c')]);
    expect(out).toHaveLength(3);
    expect(refreshes).toBe(1);
  });

  it('calls onAuthFailure, clears the token and throws 401 when refresh fails', async () => {
    const { client, fetchMock, store, onAuthFailure } = setup((url) =>
      url.endsWith('/auth/refresh')
        ? json(401, { error: { code: 'NO_SESSION', message: 'no' } })
        : json(401, {
            error: { code: 'UNAUTHENTICATED', message: 'expired' },
            meta: { requestId: 'r-401' },
          }),
    );
    const err = (await client.get('/servers').catch((e: unknown) => e)) as ApiError;
    expect(err).toMatchObject({ status: 401, code: 'UNAUTHENTICATED', requestId: 'r-401' });
    expect(fetchMock).toHaveBeenCalledTimes(2); // original + refresh, no retry loop
    expect(store.get()).toBeNull();
    expect(onAuthFailure).toHaveBeenCalledTimes(1);
  });

  it('does not refresh when the retried request is still 401 more than once', async () => {
    const { client, fetchMock, onAuthFailure } = setup((url) =>
      url.endsWith('/auth/refresh')
        ? json(200, okEnv({ accessToken: 'access-2', expiresIn: 900 }))
        : json(401, { error: { code: 'UNAUTHENTICATED', message: 'x' } }),
    );
    await expect(client.get('/servers')).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(onAuthFailure).toHaveBeenCalledTimes(1);
  });

  it('never refreshes for bad credentials on /auth/login', async () => {
    const { client, fetchMock, onAuthFailure } = setup(
      () => json(401, { error: { code: 'INVALID_CREDENTIALS', message: 'nope' } }),
      null,
    );
    await expect(
      client.post('/auth/login', { email: 'a', password: 'b' }, { auth: false }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(onAuthFailure).not.toHaveBeenCalled();
    expect(headersOf(fetchMock.mock.calls[0]![1]!).Authorization).toBeUndefined();
  });
});
