import { beforeEach, describe, expect, it } from 'vitest';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import type { Server } from '@ppanel/shared-contracts';
import type { LoginSuccess } from '@/lib/api/types';

function client() {
  let tok: string | null = null;
  const c = createApiClient({ baseUrl: 'http://mock/api/v1', clientVersion: 't', fetch: mockFetch as typeof fetch, tokenStore: { get: () => tok, set: (t) => (tok = t) } });
  return { c, setToken: (t: string) => (tok = t) };
}

describe('mock adapter (contract-shaped)', () => {
  beforeEach(() => resetMockState());

  it('enforces If-Match on PATCH /servers/:id with 409 VERSION_CONFLICT', async () => {
    const { c, setToken } = client();
    const login = await c.post<LoginSuccess>('/auth/login', { email: 'admin@ppanel.local', password: 'password' }, { auth: false });
    setToken(login.accessToken);
    const { items } = await c.list<Server>('/servers');
    const prod = items.find((s) => s.environment === 'production')!;
    const updated = await c.patch<Server>(`/servers/${prod.id}`, { connectionPolicy: 'private_only' }, { headers: { 'If-Match': String(prod.version) } });
    expect(updated.version).toBe(prod.version + 1);
    await expect(c.patch(`/servers/${prod.id}`, { tags: ['x'] }, { headers: { 'If-Match': String(prod.version) } })).rejects.toMatchObject({ status: 409, code: 'VERSION_CONFLICT' });
  });

  it('requires step-up for production revoke and scopes allowedActions by role', async () => {
    const { c, setToken } = client();
    const viewer = await c.post<LoginSuccess>('/auth/login', { email: 'user1', password: 'password' }, { auth: false });
    setToken(viewer.accessToken);
    const { items } = await c.list<Server>('/servers');
    expect(items.every((s) => s.allowedActions.length === 0)).toBe(true);
    await expect(c.post(`/servers/${items[0]!.id}/revoke`)).rejects.toMatchObject({ status: 403, code: 'FORBIDDEN' });
  });
});
