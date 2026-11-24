/**
 * P7.01 auth / session (threat TB1-S, A3/A4): JWT algorithm confusion and forgery, token-kind
 * confusion, refresh reuse, session fixation, MFA brute force / recovery-code reuse, step-up
 * binding, self-approval through a second session, user enumeration.
 */
import { createHmac } from 'node:crypto';
import { bearer, login, totpNow } from '../../../apps/api/test/integration/helpers';
import { nestRoutes } from '../lib/routes';
import { buildWorld, type World } from '../lib/world';

let w: World;
beforeAll(async () => {
  w = await buildWorld();
});
afterAll(async () => w.t.close());

const b64u = (v: unknown) =>
  Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

function jwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: string | null,
  hash: 'sha256' | 'sha384' | 'sha512' = 'sha256',
): string {
  const head = `${b64u(header)}.${b64u(payload)}`;
  if (key === null) return `${head}.`;
  return `${head}.${createHmac(hash, key).update(head).digest('base64url')}`;
}

function claimsOf(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8'));
}

const me = (token: string) => w.t.http.get('/api/v1/auth/me').set(bearer(token));
const cookieOf = (res: { headers: Record<string, unknown> }) => {
  const raw = res.headers['set-cookie'] as string[] | string | undefined;
  return /ppanel_rt=[^;]+/.exec((Array.isArray(raw) ? raw : [raw ?? '']).join('\n'))?.[0] ?? '';
};

describe('JWT validation', () => {
  it('rejects alg confusion, forged / expired / wrong-audience tokens; accepts only the genuine one', async () => {
    const good = await login(w.t, 'superadmin');
    expect((await me(good)).status).toBe(200);
    const c = claimsOf(good);
    const now = Math.floor(Date.now() / 1000);
    const secret = w.t.config.JWT_ACCESS_SECRET;
    const forged = [
      jwt({ alg: 'none', typ: 'JWT' }, c, null),
      jwt({ alg: 'None', typ: 'JWT' }, c, null),
      jwt({ alg: 'HS256', typ: 'JWT' }, c, 'not-the-secret'),
      jwt({ alg: 'HS384', typ: 'JWT' }, c, secret, 'sha384'),
      jwt({ alg: 'HS512', typ: 'JWT' }, c, secret, 'sha512'),
      // RS256 header signed with HMAC (classic RS/HS swap when the verifier trusts the header)
      jwt({ alg: 'RS256', typ: 'JWT' }, c, secret),
      jwt({ alg: 'HS256', typ: 'JWT' }, { ...c, exp: now - 10, iat: now - 1000 }, secret),
      jwt({ alg: 'HS256', typ: 'JWT' }, { ...c, aud: 'ppanel:mfa' }, secret),
      jwt({ alg: 'HS256', typ: 'JWT' }, { ...c, aud: 'ppanel:step_up' }, secret),
      jwt({ alg: 'HS256', typ: 'JWT' }, { ...c, iss: 'evil' }, secret),
      jwt({ alg: 'HS256', typ: 'JWT', kid: '../../dev/null' }, { ...c, aud: undefined }, secret),
      jwt(
        { alg: 'HS256', typ: 'JWT' },
        { ...c, sid: '01a207ea-0000-7000-8000-000000000000' },
        secret,
      ),
      `${good.split('.')[0]}.${b64u({ ...c, sub: '01a207ea-0000-7000-8000-000000000000' })}.${good.split('.')[2]}`,
    ];
    for (const tok of forged) {
      const r = await me(tok);
      expect(r.status, tok.slice(0, 60)).toBe(401);
    }
  });

  it('a validly-signed token whose sid belongs to another user is refused', async () => {
    const a = claimsOf(await login(w.t, 'superadmin'));
    const b = claimsOf(await login(w.t, 'user1'));
    const tok = jwt(
      { alg: 'HS256', typ: 'JWT' },
      { ...a, sid: b.sid },
      w.t.config.JWT_ACCESS_SECRET,
    );
    expect((await me(tok)).status).toBe(401);
  });

  it('access tokens die with the session: logout, disable, binding changes apply immediately', async () => {
    const tok = await login(w.t, 'user1');
    expect((await me(tok)).status).toBe(200);
    expect((await w.t.http.post('/api/v1/auth/logout').set(bearer(tok))).status).toBe(204);
    expect((await me(tok)).status).toBe(401);

    const tok2 = await login(w.t, 'dev');
    await w.t.prisma.user.update({
      where: { email: 'dev@ppanel.local' },
      data: { status: 'disabled' },
    });
    expect((await me(tok2)).status).toBe(401);
    await w.t.prisma.user.update({
      where: { email: 'dev@ppanel.local' },
      data: { status: 'active' },
    });
  });
});

describe('refresh tokens', () => {
  it('reuse of a rotated refresh token revokes the whole family (incl. live access tokens)', async () => {
    w.t.limiter.reset();
    const res = await w.t.http
      .post('/api/v1/auth/login')
      .send({ email: 'user1@ppanel.local', password: 'password' });
    const c1 = cookieOf(res);
    const r1 = await w.t.http.post('/api/v1/auth/refresh').set('Cookie', c1).set('X-CSRF', '1');
    expect(r1.status).toBe(200);
    const c2 = cookieOf(r1);
    const access2 = r1.body.data.accessToken as string;
    expect((await me(access2)).status).toBe(200);
    // attacker replays the stolen first cookie
    const replay = await w.t.http.post('/api/v1/auth/refresh').set('Cookie', c1).set('X-CSRF', '1');
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('REFRESH_REUSED');
    // the legitimate rotated chain is dead too
    expect((await me(access2)).status).toBe(401);
    expect(
      (await w.t.http.post('/api/v1/auth/refresh').set('Cookie', c2).set('X-CSRF', '1')).status,
    ).toBe(401);
  });

  it('session fixation: login ignores a presented cookie and always mints a fresh session', async () => {
    w.t.limiter.reset();
    const victim = await w.t.http
      .post('/api/v1/auth/login')
      .send({ email: 'user1@ppanel.local', password: 'password' });
    const planted = cookieOf(victim);
    const res = await w.t.http
      .post('/api/v1/auth/login')
      .set('Cookie', planted)
      .send({ email: 'superadmin@ppanel.local', password: 'password' });
    const fresh = cookieOf(res);
    expect(fresh).not.toBe(planted);
    // the planted cookie is still bound to its own user, not upgraded to the new login
    const r = await w.t.http.post('/api/v1/auth/refresh').set('Cookie', planted).set('X-CSRF', '1');
    const who = await me(r.body.data.accessToken);
    expect(who.body.data.user.email).toBe('user1@ppanel.local');
  });

  it('a forged / random refresh cookie is 401 and the refresh endpoint is rate limited', async () => {
    w.t.limiter.reset();
    for (let i = 0; i < 60; i++) {
      const r = await w.t.http
        .post('/api/v1/auth/refresh')
        .set('Cookie', `ppanel_rt=${'x'.repeat(43)}${i}`)
        .set('X-CSRF', '1');
      expect(r.status).toBe(401);
    }
    const r = await w.t.http
      .post('/api/v1/auth/refresh')
      .set('Cookie', 'ppanel_rt=y')
      .set('X-CSRF', '1');
    expect(r.status).toBe(429);
    w.t.limiter.reset();
  });
});

describe('MFA', () => {
  let otpUrl: string;
  let session1: string;

  beforeAll(async () => {
    w.t.limiter.reset();
    session1 = await login(w.t, 'admin');
    const setup = await w.t.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(session1));
    otpUrl = setup.body.data.otpauthUrl as string;
    const conf = await w.t.http
      .post('/api/v1/auth/mfa/totp/confirm')
      .set(bearer(session1))
      .send({ code: totpNow(otpUrl) });
    expect(conf.status).toBe(200);
    (globalThis as { __recovery?: string[] }).__recovery = conf.body.data.recoveryCodes;
  });

  async function mfaToken(): Promise<string> {
    const r = await w.t.http
      .post('/api/v1/auth/login')
      .send({ email: 'admin@ppanel.local', password: 'password' });
    expect(r.body.data.mfaRequired).toBe(true);
    return r.body.data.mfaToken as string;
  }

  it('password alone never yields an access token once MFA is on', async () => {
    w.t.limiter.reset();
    const r = await w.t.http
      .post('/api/v1/auth/login')
      .send({ email: 'admin@ppanel.local', password: 'password' });
    expect(r.body.data.accessToken).toBeUndefined();
    expect(cookieOf(r)).toBe('');
    // the mfa token is not an access token
    expect((await me(r.body.data.mfaToken)).status).toBe(401);
  });

  it('verify is brute-force limited (429 after 5 attempts per user)', async () => {
    w.t.limiter.reset();
    const tok = await mfaToken();
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) {
      const r = await w.t.http
        .post('/api/v1/auth/mfa/verify')
        .send({ mfaToken: tok, code: String(100000 + i) });
      codes.push(r.status);
    }
    expect(codes.slice(0, 5).every((s) => s === 401)).toBe(true);
    expect(codes[5]).toBe(429);
    // a fresh mfa token does not reset the per-user window
    const tok2 = await mfaToken();
    const r = await w.t.http
      .post('/api/v1/auth/mfa/verify')
      .send({ mfaToken: tok2, code: totpNow(otpUrl) });
    expect(r.status).toBe(429);
    w.t.limiter.reset();
  });

  it('a TOTP code and a recovery code are single use', async () => {
    w.t.limiter.reset();
    await w.t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
    const code = totpNow(otpUrl);
    const ok = await w.t.http
      .post('/api/v1/auth/mfa/verify')
      .send({ mfaToken: await mfaToken(), code });
    expect(ok.status).toBe(200);
    const replay = await w.t.http
      .post('/api/v1/auth/mfa/verify')
      .send({ mfaToken: await mfaToken(), code });
    expect(replay.status).toBe(401);

    const rc = (globalThis as { __recovery?: string[] }).__recovery![0]!;
    const r1 = await w.t.http
      .post('/api/v1/auth/mfa/verify')
      .send({ mfaToken: await mfaToken(), recoveryCode: rc });
    expect(r1.status).toBe(200);
    expect(claimsOf(r1.body.data.accessToken).amr).toContain('recovery');
    const r2 = await w.t.http
      .post('/api/v1/auth/mfa/verify')
      .send({ mfaToken: await mfaToken(), recoveryCode: rc.toUpperCase() });
    expect(r2.status).toBe(401);
  });

  it('TOTP cannot be re-enrolled (secret swap) by a stolen access token once confirmed', async () => {
    const r = await w.t.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(session1));
    expect(r.status).toBe(409);
  });

  it('step-up tokens are bound to user + session; approvals reject the creator in any session', async () => {
    w.t.limiter.reset();
    await w.t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
    const su = await w.t.http
      .post('/api/v1/auth/step-up')
      .set(bearer(session1))
      .send({ code: totpNow(otpUrl) });
    expect(su.status).toBe(200);
    const stepUp = su.body.data.stepUpToken as string;
    // second session of the same user (MFA login)
    await w.t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
    const s2 = await w.t.http
      .post('/api/v1/auth/mfa/verify')
      .send({ mfaToken: await mfaToken(), code: totpNow(otpUrl) });
    expect(s2.status).toBe(200);
    const session2 = s2.body.data.accessToken as string;
    const exportPath = `/api/v1/backup-repositories/${w.ids.repo}/recovery-export`;
    const cross = await w.t.http.get(exportPath).set(bearer(session2)).set('X-Step-Up', stepUp);
    expect(cross.status).toBe(403);
    expect(cross.body.error.code).toBe('STEP_UP_REQUIRED');
    const other = await w.t.http
      .get(exportPath)
      .set(bearer(await login(w.t, 'superadmin')))
      .set('X-Step-Up', stepUp);
    expect(other.body.error?.code).toBe('STEP_UP_REQUIRED');
    // a step-up token is not an access token either
    expect((await me(stepUp)).status).toBe(401);
    const same = await w.t.http.get(exportPath).set(bearer(session1)).set('X-Step-Up', stepUp);
    expect(same.body.error?.code).not.toBe('STEP_UP_REQUIRED');

    // self-approval through a second session of the creator
    const adminId = claimsOf(session1).sub as string;
    await w.t.prisma.deployment.update({
      where: { id: w.ids.deploymentPendingA },
      data: { createdBy: adminId },
    });
    const ap = await w.t.http
      .post(`/api/v1/deployments/${w.ids.deploymentPendingA}/approve`)
      .set(bearer(session2))
      .set('X-Step-Up', stepUp)
      .send({ planHash: 'f'.repeat(64) });
    expect(ap.status).toBe(403);
    expect(ap.body.error.code).toBe('APPROVER_IS_CREATOR');
    expect(totpNow).toBeTypeOf('function');
  });
});

describe('user enumeration', () => {
  it('unknown user and wrong password are indistinguishable (status, code, message, timing)', async () => {
    w.t.limiter.reset();
    const t = async (email: string) => {
      const s = process.hrtime.bigint();
      const r = await w.t.http
        .post('/api/v1/auth/login')
        .send({ email, password: 'wrong-password-1' });
      return { r, ms: Number(process.hrtime.bigint() - s) / 1e6 };
    };
    const known: number[] = [];
    const unknown: number[] = [];
    for (let i = 0; i < 4; i++) {
      const k = await t('user1@ppanel.local');
      const u = await t(`ghost${i}@ppanel.local`);
      expect(k.r.status).toBe(401);
      expect(u.r.status).toBe(401);
      expect(u.r.body.error).toEqual(k.r.body.error);
      known.push(k.ms);
      unknown.push(u.ms);
    }
    const med = (a: number[]) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)]!;
    // both paths run one argon2id verification; medians within 2× of each other
    const ratio = med(known) / med(unknown);
    expect(ratio).toBeGreaterThan(0.5);
    expect(ratio).toBeLessThan(2);
    w.t.limiter.reset();
  });

  it('there is no password-reset / forgot-password endpoint (documented absence)', () => {
    expect(nestRoutes(w.t).filter((r) => /reset|forgot|recover-password/i.test(r.path))).toEqual(
      [],
    );
  });
});

describe('password spraying', () => {
  it('one IP cannot try more than 30 logins per minute across different accounts', async () => {
    w.t.limiter.reset();
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) {
      const r = await w.t.http
        .post('/api/v1/auth/login')
        .send({ email: `spray${i}@ppanel.local`, password: 'Password1!' });
      statuses.push(r.status);
    }
    expect(statuses.slice(0, 30).every((s) => s === 401)).toBe(true);
    expect(statuses[30]).toBe(429);
    w.t.limiter.reset();
  });
});
