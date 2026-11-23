import { beforeEach, describe, expect, it, vi } from 'vitest';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import type { LoginSuccess } from '@/lib/api/types';
import type {
  Application,
  DiscoveryFinding,
  DiscoveryScan,
  NginxRevision,
} from '@/lib/api/p3-types';

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
      const r = await c.post<LoginSuccess>(
        '/auth/login',
        { email, password: 'password' },
        { auth: false },
      );
      tok = r.accessToken;
    },
  };
}

describe('mock P3 (contract §6)', () => {
  beforeEach(() => resetMockState());

  it('lab scan: 9 nginx server blocks, duplicate pair and 5 manual review', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const scans = await c.list<DiscoveryScan>('/discovery-scans');
    const lab = scans.items.find((s) => s.summary?.nginxServers === 9)!;
    expect(lab.summary).toMatchObject({
      duplicates: 1,
      manualReview: 5,
      upstreams: 1,
      phpFpmPools: 1,
    });
    const f = await c.list<DiscoveryFinding>(`/discovery-scans/${lab.id}/findings`);
    const nginx = f.items.filter((x) => x.kind === 'nginx_server');
    expect(nginx).toHaveLength(9);
    expect(nginx.filter((x) => x.manualReviewRequired)).toHaveLength(5);
    const dups = nginx.filter((x) => x.domains.includes('dup.example.lab'));
    expect(dups[0]!.conflicts[0]!.with).toEqual([dups[1]!.id]);
  });

  it('import is observe-only and idempotent; adopted/managed rejected', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const lab = (await c.list<DiscoveryScan>('/discovery-scans')).items.find(
      (s) => s.summary?.nginxServers === 9,
    )!;
    const php = (await c.list<DiscoveryFinding>(`/discovery-scans/${lab.id}/findings`)).items.find(
      (x) => x.title === 'php.example.lab',
    )!;
    await expect(
      c.post(`/discovery-scans/${lab.id}/import`, { findingIds: [php.id], mode: 'adopted' }),
    ).rejects.toMatchObject({ code: 'IMPORT_MODE_NOT_ALLOWED' });
    const r1 = await c.post<{ applications: Application[] }>(`/discovery-scans/${lab.id}/import`, {
      findingIds: [php.id],
      mode: 'observed',
    });
    expect(r1.applications[0]!.ownershipMode).toBe('observed');
    const r2 = await c.post<{ applications: Application[] }>(`/discovery-scans/${lab.id}/import`, {
      findingIds: [php.id],
      mode: 'discovered',
    });
    expect(r2.applications[0]!.id).toBe(r1.applications[0]!.id);
    expect(r2.applications[0]!.ownershipMode).toBe('observed');
  });

  it('ownership: no skip, ack required, approver ≠ creator, invalid nginx -t blocks', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { c, login } = client();
      await login('admin@ppanel.local');
      const apps = await c.list<Application>('/applications');
      const api = apps.items.find((a) => a.name === 'api-example-lab')!;
      await expect(
        c.post(
          `/applications/${api.id}/ownership`,
          { toMode: 'managed', reason: 'x' },
          { headers: { 'If-Match': String(api.version) } },
        ),
      ).rejects.toMatchObject({ code: 'OWNERSHIP_STEP_INVALID' });
      await expect(
        c.post(
          `/applications/${api.id}/ownership`,
          { toMode: 'adopted', reason: 'x' },
          { headers: { 'If-Match': String(api.version) } },
        ),
      ).rejects.toMatchObject({ code: 'MANUAL_REVIEW_REQUIRED' });
      const adopted = await c.post<Application>(
        `/applications/${api.id}/ownership`,
        { toMode: 'adopted', reason: 'x', acknowledgeReasons: true },
        { headers: { 'If-Match': String(api.version) } },
      );
      expect(adopted.ownershipMode).toBe('adopted');
      expect(adopted.allowedActions).not.toContain('manage'); // unsupported blocks managed
      const path = adopted.nginxFiles[0]!.path;
      const bad = await c.post<NginxRevision>(`/applications/${api.id}/nginx/revisions`, {
        files: [{ path, content: 'server {\n  listen 80\n}\n' }],
      });
      expect(bad.approval.required).toBe(true);
      await c.post(`/nginx-revisions/${bad.id}/validate`);
      await vi.advanceTimersByTimeAsync(2000);
      const after = await c.get<NginxRevision>(`/nginx-revisions/${bad.id}`);
      expect(after.status).toBe('invalid');
      expect(after.validation?.valid).toBe(false);
      await expect(c.post(`/nginx-revisions/${bad.id}/apply`)).rejects.toMatchObject({
        status: 409,
      });
      const good = await c.post<NginxRevision>(`/applications/${api.id}/nginx/revisions`, {
        files: [{ path, content: 'server {\n  listen 80;\n}\n' }],
      });
      await c.post(`/nginx-revisions/${good.id}/validate`);
      await vi.advanceTimersByTimeAsync(2000);
      const g2 = await c.get<NginxRevision>(`/nginx-revisions/${good.id}`);
      expect(g2.status).toBe('awaiting_approval');
      // admin (creator, no MFA) cannot approve own revision
      await expect(
        c.post(`/nginx-revisions/${good.id}/approve`, { planHash: g2.planHash }),
      ).rejects.toMatchObject({ code: 'APPROVER_IS_CREATOR' });
      // superadmin (other user, MFA) approves with step-up
      const other = client();
      const mfa = await other.c.post<{ mfaToken: string }>(
        '/auth/login',
        { email: 'superadmin@ppanel.local', password: 'password' },
        { auth: false },
      );
      const sess = await other.c.post<LoginSuccess>(
        '/auth/mfa/verify',
        { mfaToken: mfa.mfaToken, code: '123456' },
        { auth: false },
      );
      const oc = createApiClient({
        baseUrl: 'http://mock/api/v1',
        clientVersion: 't',
        fetch: mockFetch as typeof fetch,
        tokenStore: { get: () => sess.accessToken, set: () => {} },
      });
      await expect(
        oc.post(`/nginx-revisions/${good.id}/approve`, { planHash: g2.planHash }),
      ).rejects.toMatchObject({ code: 'STEP_UP_REQUIRED' });
      const su = await oc.post<{ stepUpToken: string }>('/auth/step-up', { code: '123456' });
      await expect(
        oc.post(
          `/nginx-revisions/${good.id}/approve`,
          { planHash: 'x' },
          { headers: { 'X-Step-Up': su.stepUpToken } },
        ),
      ).rejects.toMatchObject({ code: 'PLAN_HASH_MISMATCH' });
      const approved = await oc.post<NginxRevision>(
        `/nginx-revisions/${good.id}/approve`,
        { planHash: g2.planHash },
        { headers: { 'X-Step-Up': su.stepUpToken } },
      );
      expect(approved.status).toBe('approved');
      await c.post(`/nginx-revisions/${good.id}/apply`);
      await vi.advanceTimersByTimeAsync(2500);
      expect((await c.get<NginxRevision>(`/nginx-revisions/${good.id}`)).status).toBe('applied');
      await c.post(`/nginx-revisions/${good.id}/revert`);
      await vi.advanceTimersByTimeAsync(2000);
      expect((await c.get<NginxRevision>(`/nginx-revisions/${good.id}`)).status).toBe('reverted');
    } finally {
      vi.useRealTimers();
    }
  }, 30_000);
});
