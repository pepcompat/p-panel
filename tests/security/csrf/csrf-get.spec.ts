/**
 * P7.01 CSRF + "GET is side-effect free" (threat TB1-T).
 *
 * The only cookie-authenticated endpoint family is `/api/v1/auth/*` (refresh/logout); everything else
 * requires `Authorization: Bearer`, which a cross-site form/image/fetch cannot attach. Refresh must
 * additionally carry `X-CSRF: 1` (a non-simple header → CORS preflight, refused for foreign origins).
 */
import {
  bearer,
  bootApp,
  login,
  resetDb,
  type TestApp,
} from '../../../apps/api/test/integration/helpers';
import { diff, snapshot } from '../lib/db-snapshot';
import { buildWorld, type World } from '../lib/world';
import { PROBES } from '../authz/probes';

function cookieOf(res: { headers: Record<string, unknown> }): string {
  const raw = res.headers['set-cookie'] as string[] | string | undefined;
  return (Array.isArray(raw) ? raw : raw ? [raw] : []).join('\n');
}

describe('refresh cookie + CSRF', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await bootApp();
  });
  afterAll(async () => t.close());
  beforeEach(async () => {
    t.limiter.reset();
    await resetDb(t.prisma);
  });

  it('refresh cookie is HttpOnly, SameSite=Strict, Path=/api/v1/auth and never in the body', async () => {
    const res = await t.http
      .post('/api/v1/auth/login')
      .send({ email: 'superadmin@ppanel.local', password: 'password' });
    const c = cookieOf(res);
    expect(c).toMatch(/ppanel_rt=/);
    expect(c).toMatch(/HttpOnly/i);
    expect(c).toMatch(/SameSite=Strict/i);
    expect(c).toMatch(/Path=\/api\/v1\/auth/);
    const token = /ppanel_rt=([^;]+)/.exec(c)![1]!;
    expect(JSON.stringify(res.body)).not.toContain(token);
  });

  it('refresh without X-CSRF is 403 CSRF_REQUIRED and does not rotate the session', async () => {
    const res = await t.http
      .post('/api/v1/auth/login')
      .send({ email: 'superadmin@ppanel.local', password: 'password' });
    const cookie = /ppanel_rt=[^;]+/.exec(cookieOf(res))![0];
    const before = await snapshot(t.prisma);
    for (const csrf of [undefined, '0', 'true', '']) {
      let req = t.http.post('/api/v1/auth/refresh').set('Cookie', cookie);
      if (csrf !== undefined) req = req.set('X-CSRF', csrf);
      const r = await req;
      expect(r.status).toBe(403);
      expect(r.body.error.code).toBe('CSRF_REQUIRED');
    }
    expect(diff(before, await snapshot(t.prisma))).toEqual([]);
    const ok = await t.http.post('/api/v1/auth/refresh').set('Cookie', cookie).set('X-CSRF', '1');
    expect(ok.status).toBe(200);
  });

  it('CORS: a foreign Origin gets no Access-Control-Allow-Origin (preflight for X-CSRF fails)', async () => {
    const pre = await t.http
      .options('/api/v1/auth/refresh')
      .set('Origin', 'https://evil.example')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'x-csrf');
    expect(pre.headers['access-control-allow-origin']).toBeUndefined();
    const good = await t.http
      .options('/api/v1/auth/refresh')
      .set('Origin', 'http://localhost:3100')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'x-csrf');
    expect(good.headers['access-control-allow-origin']).toBe('http://localhost:3100');
    expect(good.headers['access-control-allow-credentials']).toBe('true');
  });

  it('the refresh cookie alone never authenticates a non-auth API route', async () => {
    const res = await t.http
      .post('/api/v1/auth/login')
      .send({ email: 'superadmin@ppanel.local', password: 'password' });
    const cookie = /ppanel_rt=[^;]+/.exec(cookieOf(res))![0];
    for (const path of ['/api/v1/servers', '/api/v1/users', '/api/v1/auth/me']) {
      const r = await t.http.get(path).set('Cookie', cookie);
      expect(r.status).toBe(401);
    }
    const r = await t.http
      .post('/api/v1/enrollments')
      .set('Cookie', cookie)
      .send({ name: 'x', environment: 'development' });
    expect(r.status).toBe(401);
  });

  it('production config marks the refresh cookie Secure', async () => {
    const p = await bootApp({ COOKIE_SECURE: '1' });
    try {
      const res = await p.http
        .post('/api/v1/auth/login')
        .send({ email: 'superadmin@ppanel.local', password: 'password' });
      expect(cookieOf(res)).toMatch(/;\s*Secure/i);
    } finally {
      await p.close();
    }
  });
});

describe('GET handlers are side-effect free', () => {
  let w: World;
  beforeAll(async () => {
    w = await buildWorld();
  });
  afterAll(async () => w.t.close());

  /**
   * Accepted exceptions (documented in SECURITY_TEST_REPORT.md): they enqueue a *read-only* agent job
   * (the answer comes from the host) or consume a single-use token. None is reachable cross-site:
   * the job-creating ones need a Bearer header, the tail token is unguessable and single-use.
   */
  const SIDE_EFFECT_OK: Record<string, string[]> = {
    'GET /api/v1/applications/:id/logs': ['jobs'],
    'GET /api/v1/servers/:id/snapshots': ['jobs'],
    'GET /api/v1/logs/tail': ['log_tail_tokens'],
  };
  /** sensitive reads that are audited on purpose */
  const AUDITED_READS = new Set(['GET /api/v1/backup-repositories/:id/recovery-export']);
  const OBSERVABILITY_BACKED = new Set(['GET /api/v1/logs/query', 'GET /api/v1/metrics/series']);

  it('every GET (as platform owner) leaves every table unchanged and writes no audit row', async () => {
    const bad: string[] = [];
    for (const p of PROBES.filter((x) => x.route.startsWith('GET '))) {
      const before = await snapshot(w.t.prisma, []);
      const auditBefore = await w.t.prisma.auditEvent.count();
      const res = await w.t.http.get(p.path(w.ids)).set(bearer(w.p.owner));
      // routes backed by Loki/Prometheus answer 503 when that backend is not running (CI has none);
      // the side-effect checks below still apply to them
      if (!(OBSERVABILITY_BACKED.has(p.route) && res.status === 503)) {
        expect(res.status, p.route).toBeLessThan(500);
      }
      const changed = diff(before, await snapshot(w.t.prisma, [])).filter(
        (t) => t !== 'audit_events' && !(SIDE_EFFECT_OK[p.route] ?? []).includes(t),
      );
      if (changed.length) bad.push(`${p.route} changed ${changed.join(',')}`);
      const audits = (await w.t.prisma.auditEvent.count()) - auditBefore;
      if (audits > 0 && !AUDITED_READS.has(p.route) && !SIDE_EFFECT_OK[p.route])
        bad.push(`${p.route} wrote ${audits} audit row(s)`);
    }
    expect(bad).toEqual([]);
  });

  it('job-creating GETs dedupe instead of growing the job table per request', async () => {
    const jobs0 = await w.t.prisma.job.count();
    for (let i = 0; i < 5; i++)
      await w.t.http.get(`/api/v1/applications/${w.ids.appA}/logs`).set(bearer(w.p.owner));
    const grown = (await w.t.prisma.job.count()) - jobs0;
    // documented behaviour: at most one pending read job per (app, tail) is reused
    expect(grown).toBeLessThanOrEqual(1);
  });
});

void login;
