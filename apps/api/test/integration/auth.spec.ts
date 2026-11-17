import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { bearer, bootApp, login, resetDb, type TestApp, TEST_SETUP_TOKEN, totpNow } from './helpers';

let t: TestApp;

beforeAll(async () => {
  t = await bootApp();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
});

function refreshCookie(res: { headers: Record<string, unknown> }): string {
  const set = (res.headers['set-cookie'] as string[] | undefined) ?? [];
  const c = set.find((s) => s.startsWith('ppanel_rt='));
  if (!c) throw new Error('no refresh cookie');
  return c.split(';')[0]!;
}

describe('envelope shapes', () => {
  it('success envelope + X-Request-ID echo', async () => {
    const res = await t.http.get('/api/v1/setup/status').set('X-Request-ID', 'req-test-12345678');
    expect(res.status).toBe(200);
    expect(res.headers['x-request-id']).toBe('req-test-12345678');
    expect(res.body).toEqual({ success: true, statusCode: 0, message: 'ok', data: { bootstrapped: true }, meta: { requestId: 'req-test-12345678' } });
  });

  it('generates a request id when absent', async () => {
    const res = await t.http.get('/api/v1/setup/status');
    expect(res.body.meta.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.headers['x-request-id']).toBe(res.body.meta.requestId);
  });

  it('list envelope has data[] + sibling paginate', async () => {
    const token = await login(t, 'superadmin');
    const res = await t.http.get('/api/v1/users?page=1&limit=2&sort=email&order=asc').set(bearer(token));
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.statusCode).toBe(0);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data).toHaveLength(2);
    expect(res.body.paginate).toEqual({ page: 1, limit: 2, total: 4 });
    expect(res.body.meta.requestId).toBeTruthy();
    expect(res.body.data[0]).not.toHaveProperty('passwordHash');
  });

  it('error envelope: 401, 404, 422, 400 malformed, 413 too large, 400 bad query', async () => {
    const r401 = await t.http.get('/api/v1/auth/me');
    expect(r401.status).toBe(401);
    expect(r401.body).toEqual({ error: { code: 'UNAUTHENTICATED', message: expect.any(String) }, meta: { requestId: expect.any(String) } });
    expect(r401.body).not.toHaveProperty('success');

    const r404 = await t.http.get('/api/v1/does-not-exist');
    expect(r404.status).toBe(404);
    expect(r404.body.error.code).toBe('NOT_FOUND');

    const r422 = await t.http.post('/api/v1/auth/login').send({ email: 'not-an-email' });
    expect(r422.status).toBe(422);
    expect(r422.body.error.code).toBe('VALIDATION_FAILED');
    expect(Array.isArray(r422.body.error.details)).toBe(true);

    const r400 = await t.http.post('/api/v1/auth/login').set('Content-Type', 'application/json').send('{"email":');
    expect(r400.status).toBe(400);
    expect(r400.body.error.code).toBe('BAD_REQUEST');

    const big = 'x'.repeat(300 * 1024);
    const r413 = await t.http.post('/api/v1/auth/login').send({ email: 'a@b.co', password: big });
    expect(r413.status).toBe(413);
    expect(r413.body.error.code).toBe('PAYLOAD_TOO_LARGE');

    const token = await login(t, 'superadmin');
    const rq = await t.http.get('/api/v1/audit-events?limit=1000').set(bearer(token));
    expect(rq.status).toBe(400);
    expect(rq.body.error.code).toBe('BAD_REQUEST');
  });

  it('CORS allows only WEB_ORIGIN with credentials', async () => {
    const ok = await t.http.options('/api/v1/auth/login').set('Origin', 'http://localhost:3100').set('Access-Control-Request-Method', 'POST');
    expect(ok.headers['access-control-allow-origin']).toBe('http://localhost:3100');
    expect(ok.headers['access-control-allow-credentials']).toBe('true');
    const bad = await t.http.options('/api/v1/auth/login').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST');
    expect(bad.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('setup/bootstrap', () => {
  it('bootstraps first admin once with the setup token', async () => {
    await resetDb(t.prisma, { seedUsers: false });
    expect((await t.http.get('/api/v1/setup/status')).body.data).toEqual({ bootstrapped: false });
    const body = { email: 'owner@example.com', password: 'correct horse battery', displayName: 'Owner' };
    const bad = await t.http.post('/api/v1/setup/bootstrap').send({ ...body, setupToken: 'wrong' });
    expect(bad.status).toBe(401);
    expect(bad.body.error.code).toBe('SETUP_TOKEN_INVALID');
    const ok = await t.http.post('/api/v1/setup/bootstrap').send({ ...body, setupToken: TEST_SETUP_TOKEN });
    expect(ok.status).toBe(201);
    expect(ok.body.data.user.email).toBe('owner@example.com');
    const again = await t.http.post('/api/v1/setup/bootstrap').send({ ...body, email: 'x@example.com', setupToken: TEST_SETUP_TOKEN });
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe('ALREADY_BOOTSTRAPPED');
    const me = await t.http.get('/api/v1/auth/me').set(bearer(await loginEmail('owner@example.com', 'correct horse battery')));
    expect(me.body.data.bindings).toEqual([expect.objectContaining({ roleKey: 'platform_owner', scopeType: 'global' })]);
  });
});

async function loginEmail(email: string, password: string): Promise<string> {
  const r = await t.http.post('/api/v1/auth/login').send({ email, password });
  return r.body.data.accessToken;
}

describe('login', () => {
  it('logs in, sets HttpOnly SameSite=Strict refresh cookie, never returns secrets', async () => {
    const res = await t.http.post('/api/v1/auth/login').send({ email: 'superadmin@ppanel.local', password: 'password' });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ accessToken: expect.any(String), expiresIn: 900, user: { email: 'superadmin@ppanel.local', mfaEnabled: false } });
    const cookie = (res.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith('ppanel_rt='))!;
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Strict/);
    expect(cookie).toMatch(/Path=\/api\/v1\/auth/);
    expect(JSON.stringify(res.body)).not.toMatch(/argon2|passwordHash/);
    const session = await t.prisma.session.findFirstOrThrow();
    expect(session.refreshTokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(cookie).not.toContain(session.refreshTokenHash);
  });

  it('wrong password and unknown user produce the identical uniform error', async () => {
    const a = await t.http.post('/api/v1/auth/login').send({ email: 'superadmin@ppanel.local', password: 'nope' });
    const b = await t.http.post('/api/v1/auth/login').send({ email: 'ghost@ppanel.local', password: 'nope' });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body.error).toEqual(b.body.error);
    expect(a.body.error.code).toBe('INVALID_CREDENTIALS');
    const audits = await t.prisma.auditEvent.count({ where: { action: 'auth.login', result: 'failure' } });
    expect(audits).toBe(2);
  });

  it('rate limits login to 5/min per IP+email → 429', async () => {
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) {
      codes.push((await t.http.post('/api/v1/auth/login').send({ email: 'admin@ppanel.local', password: 'bad' })).status);
    }
    expect(codes).toEqual([401, 401, 401, 401, 401, 429]);
    const last = await t.http.post('/api/v1/auth/login').send({ email: 'admin@ppanel.local', password: 'password' });
    expect(last.status).toBe(429);
    expect(last.body.error.code).toBe('RATE_LIMITED');
    expect(last.headers['retry-after']).toBeDefined();
  });

  it('/auth/me returns user, permissions, bindings, mfaEnabled', async () => {
    const token = await login(t, 'user1');
    const res = await t.http.get('/api/v1/auth/me').set(bearer(token));
    expect(res.status).toBe(200);
    expect(res.body.data.permissions).toEqual(['apps.read', 'audit.read', 'fleet.read', 'nginx.read']);
    expect(res.body.data.bindings).toEqual([expect.objectContaining({ roleKey: 'viewer', scopeType: 'global' })]);
    expect(res.body.data.mfaEnabled).toBe(false);
  });

  it('rejects tampered / wrong-audience tokens', async () => {
    const token = await login(t, 'user1');
    const tampered = token.slice(0, -3) + (token.endsWith('aaa') ? 'bbb' : 'aaa');
    expect((await t.http.get('/api/v1/auth/me').set(bearer(tampered))).status).toBe(401);
  });
});

describe('refresh rotation', () => {
  it('requires X-CSRF header', async () => {
    const res = await t.http.post('/api/v1/auth/login').send({ email: 'dev@ppanel.local', password: 'password' });
    const r = await t.http.post('/api/v1/auth/refresh').set('Cookie', refreshCookie(res));
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('CSRF_REQUIRED');
  });

  it('rotates; reusing an old refresh token revokes the whole family', async () => {
    const res = await t.http.post('/api/v1/auth/login').send({ email: 'dev@ppanel.local', password: 'password' });
    const c1 = refreshCookie(res);
    const r1 = await t.http.post('/api/v1/auth/refresh').set('Cookie', c1).set('X-CSRF', '1');
    expect(r1.status).toBe(200);
    expect(r1.body.data).toEqual({ accessToken: expect.any(String), expiresIn: 900 });
    const c2 = refreshCookie(r1);
    expect(c2).not.toBe(c1);
    const access2 = r1.body.data.accessToken as string;
    expect((await t.http.get('/api/v1/auth/me').set(bearer(access2))).status).toBe(200);

    // reuse of rotated token → family revoked
    const reuse = await t.http.post('/api/v1/auth/refresh').set('Cookie', c1).set('X-CSRF', '1');
    expect(reuse.status).toBe(401);
    expect(reuse.body.error.code).toBe('REFRESH_REUSED');
    // the legitimately rotated token is now dead too, and so is its access token
    const after = await t.http.post('/api/v1/auth/refresh').set('Cookie', c2).set('X-CSRF', '1');
    expect(after.status).toBe(401);
    expect((await t.http.get('/api/v1/auth/me').set(bearer(access2))).status).toBe(401);
    expect(await t.prisma.auditEvent.count({ where: { action: 'auth.refresh.reuse_detected' } })).toBe(1);
  });

  it('logout revokes the session and clears the cookie', async () => {
    const res = await t.http.post('/api/v1/auth/login').send({ email: 'dev@ppanel.local', password: 'password' });
    const access = res.body.data.accessToken as string;
    const out = await t.http.post('/api/v1/auth/logout').set('Cookie', refreshCookie(res)).set(bearer(access));
    expect(out.status).toBe(204);
    expect(out.text).toBe('');
    expect((out.headers['set-cookie'] as unknown as string[]).some((c) => c.startsWith('ppanel_rt=;'))).toBe(true);
    expect((await t.http.get('/api/v1/auth/me').set(bearer(access))).status).toBe(401);
    expect((await t.http.post('/api/v1/auth/refresh').set('Cookie', refreshCookie(res)).set('X-CSRF', '1')).status).toBe(401);
  });
});

describe('MFA (TOTP + recovery codes + step-up)', () => {
  it('setup → confirm → login requires MFA → verify; recovery code single-use; step-up', async () => {
    const token = await login(t, 'admin');
    const setup = await t.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(token));
    expect(setup.status).toBe(200);
    expect(setup.body.data.otpauthUrl).toMatch(/^otpauth:\/\/totp\//);
    expect(setup.body.data.secretMasked).toContain('•');
    const factor = await t.prisma.mfaFactor.findFirstOrThrow();
    const secret = new URL(setup.body.data.otpauthUrl).searchParams.get('secret')!;
    expect(factor.secretEnc).not.toContain(secret); // encrypted at rest

    const bad = await t.http.post('/api/v1/auth/mfa/totp/confirm').set(bearer(token)).send({ code: '000000' });
    expect(bad.status).toBe(401);
    const conf = await t.http.post('/api/v1/auth/mfa/totp/confirm').set(bearer(token)).send({ code: totpNow(setup.body.data.otpauthUrl) });
    expect(conf.status).toBe(200);
    const codes = conf.body.data.recoveryCodes as string[];
    expect(codes).toHaveLength(10);
    const stored = await t.prisma.recoveryCode.findMany();
    expect(stored.every((r) => /^[0-9a-f]{64}$/.test(r.codeHash))).toBe(true);

    // login now requires MFA
    const l = await t.http.post('/api/v1/auth/login').send({ email: 'admin@ppanel.local', password: 'password' });
    expect(l.status).toBe(200);
    expect(l.body.data).toEqual({ mfaRequired: true, mfaToken: expect.any(String) });
    expect(l.headers['set-cookie']).toBeUndefined();
    // mfa token is not an access token
    expect((await t.http.get('/api/v1/auth/me').set(bearer(l.body.data.mfaToken))).status).toBe(401);

    // TOTP step already consumed by confirm → replay rejected; use a recovery code instead
    const replay = await t.http.post('/api/v1/auth/mfa/verify').send({ mfaToken: l.body.data.mfaToken, code: totpNow(setup.body.data.otpauthUrl) });
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('MFA_INVALID');
    const rc = await t.http.post('/api/v1/auth/mfa/verify').send({ mfaToken: l.body.data.mfaToken, recoveryCode: codes[0] });
    expect(rc.status).toBe(200);
    expect(rc.body.data.accessToken).toBeTruthy();
    expect(rc.body.data.user.mfaEnabled).toBe(true);
    const rc2 = await t.http.post('/api/v1/auth/mfa/verify').send({ mfaToken: l.body.data.mfaToken, recoveryCode: codes[0] });
    expect(rc2.status).toBe(401);

    // step-up needs a fresh TOTP step: simulate the next window by rewinding last_used_step
    await t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
    const su = await t.http.post('/api/v1/auth/step-up').set(bearer(rc.body.data.accessToken)).send({ code: totpNow(setup.body.data.otpauthUrl) });
    expect(su.status).toBe(200);
    expect(su.body.data).toEqual({ stepUpToken: expect.any(String), expiresAt: expect.any(String) });
  });

  it('step-up is refused without MFA enrolled', async () => {
    const token = await login(t, 'superadmin');
    const r = await t.http.post('/api/v1/auth/step-up').set(bearer(token)).send({ code: '123456' });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('MFA_REQUIRED');
  });
});
