import { beforeEach, describe, expect, it } from 'vitest';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { MockSshSocket } from '@/mocks/mock-ssh-socket';
import { createApiClient } from '@/lib/api/client';
import { isApiError } from '@/lib/api/errors';
import type { LoginSuccess } from '@/lib/api/types';
import type {
  SessionTicket,
  SshCredential,
  SshGrant,
  SshHostKey,
  SshSession,
} from '@/lib/api/p10-types';
import { SshConnection } from '@/lib/ssh/connection';
import type { CloseInfo } from '@/lib/ssh/close-codes';

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
    async stepUp() {
      return (await c.post<{ stepUpToken: string }>('/auth/step-up', { code: '123456' }))
        .stepUpToken;
    },
  };
}
const fail = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => (isApiError(e) ? e : null),
  );
const su = (token: string) => ({ headers: { 'X-Step-Up': token } });

/** Drive a session through the in-process gateway with the real SshConnection. */
function runSession(t: SessionTicket, input?: string) {
  return new Promise<{ out: string; close: CloseInfo; ready: boolean; exit: number | null }>(
    (resolve) => {
      let out = '';
      let ready = false;
      let exit: number | null = null;
      const conn = new SshConnection({
        wsUrl: t.wsUrl,
        sessionId: t.sessionId,
        ticket: t.ticket,
        cols: 100,
        rows: 30,
        factory: (u) => new MockSshSocket(u),
        onReady: () => {
          ready = true;
          if (input) setTimeout(() => conn.write(input), 300);
        },
        onData: (b) => (out += new TextDecoder().decode(b)),
        onExit: (code) => (exit = code),
        onClose: (close) => resolve({ out, close, ready, exit }),
      });
      conn.start();
    },
  );
}

beforeEach(() => resetMockState());

describe('mock P10 (docs/P10_SSH_CONTRACT.md)', () => {
  it('credentials: metadata only; generate/import need step-up; import validates and never stores the key', async () => {
    const { c, login, stepUp } = client();
    await login('superadmin');
    const list = await c.get<SshCredential[]>('/ssh/credentials');
    expect(list.length).toBeGreaterThan(0);
    expect(JSON.stringify(list)).not.toMatch(/privateKey|PRIVATE KEY/);
    expect(list[0]!.fingerprintSha256).toMatch(/^SHA256:/);

    const noStep = await fail(c.post('/ssh/credentials', { name: 'k1', mode: 'generate' }));
    expect(noStep?.code).toBe('STEP_UP_REQUIRED');
    const token = await stepUp();
    const created = await c.post<SshCredential>(
      '/ssh/credentials',
      { name: 'k1', mode: 'generate' },
      su(token),
    );
    expect(created.algorithm).toBe('ssh-ed25519');
    expect(created.kind).toBe('generated');

    const key =
      '-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET-MATERIAL-XYZ\n-----END OPENSSH PRIVATE KEY-----';
    const enc = await fail(
      c.post(
        '/ssh/credentials',
        { name: 'k2', mode: 'import', privateKey: `${key}\nbcrypt aes256-ctr` },
        su(token),
      ),
    );
    expect(enc?.code).toBe('SSH_KEY_ENCRYPTED');
    const rsa = await fail(
      c.post(
        '/ssh/credentials',
        { name: 'k3', mode: 'import', privateKey: '-----BEGIN RSA PRIVATE KEY-----\nshort\n' },
        su(token),
      ),
    );
    expect(rsa?.code).toBe('SSH_KEY_UNSUPPORTED');
    const big = await fail(
      c.post(
        '/ssh/credentials',
        { name: 'k4', mode: 'import', privateKey: `${key}${'A'.repeat(17_000)}` },
        su(token),
      ),
    );
    expect(big?.status).toBe(413);
    const imported = await c.post<SshCredential>(
      '/ssh/credentials',
      { name: 'k5', mode: 'import', privateKey: key },
      su(token),
    );
    expect(imported.kind).toBe('imported');
    expect(JSON.stringify(imported)).not.toContain('SECRET-MATERIAL');
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('SECRET-MATERIAL');

    // viewer cannot manage
    const v = client();
    await v.login('user1');
    expect((await fail(v.c.post('/ssh/credentials/x/deploy', {})))?.status).toBeGreaterThanOrEqual(
      403,
    );
  });

  it('grants: non-prod active now; prod waits; self-approval 403; another approver needs step-up', async () => {
    const sa = client();
    await sa.login('superadmin');
    const admin = client();
    await admin.login('admin');
    const grants = await sa.c.get<SshGrant[]>('/ssh/grants');
    const own = grants.find((g) => g.id === 'grant-self-prod')!;
    expect(own.status).toBe('awaiting_approval');
    const token = await sa.stepUp();
    const self = await fail(
      sa.c.post(`/ssh/grants/${own.id}/approve`, { grantHash: own.grantHash }, su(token)),
    );
    expect(self?.code).toBe('SELF_APPROVAL_FORBIDDEN');
    const theirs = grants.find((g) => g.id === 'grant-admin-prod')!;
    expect(
      (await fail(sa.c.post(`/ssh/grants/${theirs.id}/approve`, { grantHash: theirs.grantHash })))
        ?.code,
    ).toBe('STEP_UP_REQUIRED');
    const approved = await sa.c.post<SshGrant>(
      `/ssh/grants/${theirs.id}/approve`,
      { grantHash: theirs.grantHash },
      su(token),
    );
    expect(approved.status).toBe('active');
    expect(approved.approvedByLabel).toBe('Super Admin');

    // admin (scoped to production + uat) requests prod access: awaiting approval
    const servers = await admin.c.get<Array<{ id: string; name: string }>>('/servers');
    const prod2 = servers.find((s) => s.name === 'app-prod-01')!;
    const g = await admin.c.post<SshGrant>('/ssh/grants', {
      serverId: prod2.id,
      sshUser: 'deploy',
      endpointPath: 'private',
      durationMinutes: 30,
      reason: 'check logs',
    });
    expect(g.status).toBe('awaiting_approval');
    const noKey = await fail(
      admin.c.post('/ssh/grants', {
        serverId: servers.find((s) => s.name === 'web-legacy-02')!.id,
        sshUser: 'deploy',
        endpointPath: 'public',
        durationMinutes: 30,
        reason: 'check logs',
      }),
    );
    expect(noKey?.code).toBe('SSH_NO_CREDENTIAL');
    // admin only sees own grants + those in scope; cannot see dev-only grants of superadmin
    const adminList = await admin.c.get<SshGrant[]>('/ssh/grants');
    expect(adminList.some((x) => x.id === 'grant-dev01')).toBe(false);
  });

  it('session: single-use ticket over the gateway, shell round-trip, exit status; reused ticket → 4401', async () => {
    const { c, login } = client();
    await login('superadmin');
    const t = await c.post<SessionTicket>('/ssh/sessions', {
      grantId: 'grant-dev01',
      cols: 100,
      rows: 30,
    });
    expect(t.wsUrl).toBe('ws://mock/api/v1/ssh/stream');
    expect(t.wsUrl).not.toContain(t.ticket);
    const r = await runSession(t, 'id -un\rexit 0\r');
    expect(r.ready).toBe(true);
    expect(r.out).toContain('ops@dev-01:~$ ');
    expect(r.out).toContain('id -un\r\nops\r\n');
    expect(r.exit).toBe(0);
    expect(r.close.code).toBe(1000);
    const again = await runSession(t);
    expect(again.ready).toBe(false);
    expect(again.close.code).toBe(4401);
    const sessions = await c.get<SshSession[]>('/ssh/sessions');
    const row = sessions.find((s) => s.id === t.sessionId)!;
    expect(row.status).toBe('closed');
    expect(row.exitCode).toBe(0);
    expect(row.bytesIn).toBeGreaterThan(0);
    expect(JSON.stringify(sessions)).not.toContain(t.ticket);
  }, 15_000);

  it('host key mismatch closes 4409 before auth; trusting the new key (step-up) fixes it; idle hook → 4408', async () => {
    const { c, login, stepUp } = client();
    await login('superadmin');
    const t = await c.post<SessionTicket>('/ssh/sessions', {
      grantId: 'grant-sandbox',
      cols: 80,
      rows: 24,
    });
    const r = await runSession(t);
    expect(r.ready).toBe(false);
    expect(r.close.code).toBe(4409);
    expect(r.close.reason).toBe('host_key_mismatch');
    const servers = await c.get<Array<{ id: string; name: string }>>('/servers');
    const sandbox = servers.find((s) => s.name === 'dev-sandbox-02')!;
    const keys = await c.get<SshHostKey[]>(`/servers/${sandbox.id}/ssh/host-keys`);
    const seen = keys.find((k) => k.status === 'pending' && k.seenVia === 'connect')!;
    expect(seen.agentMatch).toBe(false);
    expect((await fail(c.post(`/ssh/host-keys/${seen.id}/trust`)))?.code).toBe('STEP_UP_REQUIRED');
    await c.post(`/ssh/host-keys/${seen.id}/trust`, undefined, su(await stepUp()));
    const after = await c.get<SshHostKey[]>(`/servers/${sandbox.id}/ssh/host-keys`);
    expect(after.filter((k) => k.status === 'trusted')).toHaveLength(1);
    expect(after.some((k) => k.status === 'superseded')).toBe(true);
    const t2 = await c.post<SessionTicket>('/ssh/sessions', {
      grantId: 'grant-sandbox',
      cols: 80,
      rows: 24,
    });
    const r2 = await runSession(t2, '__idle\r');
    expect(r2.ready).toBe(true);
    expect(r2.close.code).toBe(4408);
    expect(r2.close.reason).toBe('idle_timeout');
  }, 15_000);

  it('production step-up and grant ownership are enforced at POST /ssh/sessions', async () => {
    const { c, login, stepUp } = client();
    await login('superadmin');
    const admin = client();
    await admin.login('admin');
    // approve admin's prod grant, then admin needs step-up (and has no MFA → refused)
    const g = (await c.get<SshGrant[]>('/ssh/grants')).find((x) => x.id === 'grant-admin-prod')!;
    await c.post(`/ssh/grants/${g.id}/approve`, { grantHash: g.grantHash }, su(await stepUp()));
    const denied = await fail(admin.c.post('/ssh/sessions', { grantId: g.id, cols: 80, rows: 24 }));
    expect(denied?.code).toBe('STEP_UP_REQUIRED');
    // someone else's grant
    const other = await fail(c.post('/ssh/sessions', { grantId: g.id, cols: 80, rows: 24 }));
    expect(other?.code).toBe('SSH_GRANT_INVALID');
  });
});
