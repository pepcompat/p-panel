import { beforeEach, describe, expect, it } from 'vitest';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import { isApiError } from '@/lib/api/errors';
import type { LoginSuccess } from '@/lib/api/types';
import type { Server } from '@ppanel/shared-contracts';
import type { FleetServerSummary, Incident, LogEntry, MetricSeries } from '@/lib/api/p5-types';

function client() {
  let tok: string | null = null;
  const c = createApiClient({
    baseUrl: 'http://mock/api/v1',
    clientVersion: 't',
    fetch: mockFetch as typeof fetch,
    tokenStore: { get: () => tok, set: (t) => (tok = t) },
  });
  return {
    c,
    async login(email: string) {
      const r = await c.post<LoginSuccess | { mfaRequired: true; mfaToken: string }>(
        '/auth/login',
        { email, password: 'password' },
        { auth: false },
      );
      if ('mfaToken' in r) {
        const v = await c.post<LoginSuccess>(
          '/auth/mfa/verify',
          { mfaToken: r.mfaToken, code: '123456' },
          { auth: false },
        );
        tok = v.accessToken;
      } else tok = r.accessToken;
    },
  };
}
const fail = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => (isApiError(e) ? e : null),
  );

beforeEach(() => resetMockState());

describe('mock P5 (contract §9)', () => {
  it('fleet: offline / stale / no-metrics are distinct and never 0', async () => {
    const { c, login } = client();
    await login('superadmin');
    const { items } = await c.list<FleetServerSummary>('/metrics/fleet');
    const by = (n: string) => items.find((x) => x.name === n)!;
    expect(by('worker-uat-01').status).toBe('offline');
    expect(by('worker-uat-01').sample).toBeNull();
    expect(by('db-prod-01').stale).toBe(true);
    expect(by('dev-sandbox-02').sample).toBeNull();
    expect(by('dev-sandbox-02').status).toBe('online');
    const s = await c.get<MetricSeries>('/metrics/series', {
      query: { scope: 'server', id: by('db-prod-01').serverId, metric: 'cpu', range: '1h' },
    });
    expect(s.stale).toBe(true);
    expect(s.points.at(-1)![1]).toBeNull();
    expect(s.points.some(([, v]) => v === 0)).toBe(false);
    expect(s.gaps.length).toBeGreaterThan(0);
  }, 20_000);

  it('logs: scope, redaction, retention and raw-query rejection', async () => {
    const { c, login } = client();
    await login('superadmin');
    const servers = (await c.list<Server>('/servers', { query: { limit: 100 } })).items;
    const prod = servers.find((s) => s.name === 'web-legacy-02')!;
    const to = new Date().toISOString();
    const from = new Date(Date.now() - 6 * 3600e3).toISOString();
    const r = await c.request<LogEntry[]>('GET', '/logs/query', {
      query: { serverId: prod.id, from, to, limit: 1000, q: 'api_key' },
    });
    expect(r.data.length).toBeGreaterThan(0);
    for (const e of r.data) expect(e.line).toContain('api_key=[REDACTED]');
    expect((r.meta as unknown as { retention: { days: number } }).retention.days).toBe(7);
    const old = await c.request<LogEntry[]>('GET', '/logs/query', {
      query: {
        serverId: prod.id,
        from: new Date(Date.now() - 10 * 864e5).toISOString(),
        to: new Date(Date.now() - 8 * 864e5).toISOString(),
      },
    });
    expect(old.data).toEqual([]);
    const raw = await fail(
      c.get('/logs/query', { query: { serverId: prod.id, from, to, query: '{a="b"}' } }),
    );
    expect(raw?.status).toBe(422);
    const rl = await fail(
      c.get('/logs/query', { query: { serverId: prod.id, from, to, q: 'simulate-429' } }),
    );
    expect(rl?.status).toBe(429);
    expect(rl?.retryAfterSec).toBe(3);
  }, 20_000);

  it('incident ack records the actor; viewer cannot ack or manage rules', async () => {
    const admin = client();
    await admin.login('superadmin');
    const list = (await admin.c.list<Incident>('/incidents', { query: { status: 'firing' } }))
      .items;
    const target = list[0]!;
    const viewer = client();
    await viewer.login('user1');
    expect((await fail(viewer.c.post(`/incidents/${target.id}/acknowledge`, {})))?.status).toBe(
      403,
    );
    expect((await fail(viewer.c.get('/alert-rules')))?.status).toBe(403);
    const acked = await admin.c.post<Incident>(`/incidents/${target.id}/acknowledge`, {
      comment: 'on it',
    });
    expect(acked.status).toBe('acknowledged');
    const last = acked.timeline!.at(-1)!;
    expect(last.type).toBe('acknowledged');
    expect(last.actor).toMatchObject({ displayName: 'Super Admin' });
    expect(last.detail).toEqual({ comment: 'on it' });
    expect((await fail(admin.c.post(`/incidents/${target.id}/acknowledge`, {})))?.status).toBe(409);
  }, 20_000);
});
