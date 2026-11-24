/**
 * P7-T03 secret leakage (threat "All-I", TB3-I): every secret-bearing flow runs with unique canary
 * values; afterwards EVERY text/json/array column of EVERY table, every captured structured log line
 * (debug level), every audit row and every API response (bodies + headers) is scanned for the
 * canaries in raw, base64 (3 alignments, std + url alphabets), URL-encoded and hex form.
 *
 * Intended one-time disclosures are excluded explicitly (the response that hands a secret to its
 * owner: enrollment token, TOTP otpauth URL, recovery codes, login/refresh tokens, step-up token,
 * tail token, the step-up-gated recovery export). Encrypted columns hold AES-256-GCM envelopes, so
 * a canary found anywhere in the database is a finding.
 */
import { randomBytes } from 'node:crypto';
import { bearer, enrollAgent, totpNow } from '../../../apps/api/test/integration/helpers';
import { logger } from '../../../apps/api/src/common/logger';
import { buildWorld, type World } from '../lib/world';

const C = (label: string) => `CANARY${label}${randomBytes(9).toString('hex')}`;

interface Captured {
  where: string;
  text: string;
}

function encodings(secret: string): string[] {
  const out = new Set<string>([
    secret,
    encodeURIComponent(secret),
    Buffer.from(secret).toString('hex'),
  ]);
  for (const pad of ['', 'x', 'xx']) {
    for (const enc of ['base64', 'base64url'] as const) {
      const b = Buffer.from(pad + secret)
        .toString(enc)
        .replace(/=+$/, '');
      // drop the chars that depend on the unknown neighbours
      const core = b.slice(pad ? 4 : 0, b.length - 4);
      if (core.length >= 12) out.add(core);
    }
  }
  return [...out];
}

let w: World;
const logs: string[] = [];
const responses: Captured[] = [];
const canaries: Record<string, string> = {};
/** canary → response "where" labels in which it may legitimately appear (one-time disclosure) */
const disclosure: Record<string, Set<string>> = {};

function allow(label: string, where: string) {
  (disclosure[label] ??= new Set()).add(where);
}

async function rec(
  where: string,
  p: PromiseLike<{ status: number; body: unknown; headers: Record<string, unknown> }>,
) {
  const r = await p;
  responses.push({ where, text: JSON.stringify({ body: r.body, headers: r.headers }) });
  return r as unknown as { status: number; body: any; headers: Record<string, unknown> };
}

beforeAll(async () => {
  w = await buildWorld(undefined, { LOG_LEVEL: 'debug' });
  const sink = { write: (l: string) => void logs.push(l) };
  (logger as unknown as { sink: typeof sink }).sink = sink;
  logger.setLevel('debug');
});
afterAll(async () => {
  (logger as unknown as { sink: NodeJS.WritableStream }).sink = process.stdout;
  logger.setLevel('fatal');
  await w.t.close();
});

describe('P7-T03 canary secret scan', () => {
  it('runs every secret-bearing flow with canaries', async () => {
    const { t, p, ids } = w;
    const owner = p.owner;

    // ---- user password (create + failed login with a canary password)
    canaries.password = C('pw');
    const u = await rec(
      'users.create',
      t.http
        .post('/api/v1/users')
        .set(bearer(owner))
        .send({
          email: 'canary@ppanel.local',
          password: canaries.password,
          displayName: 'Canary',
          bindings: [{ roleKey: 'viewer', scopeType: 'global' }],
        }),
    );
    expect(u.status).toBe(201);
    canaries.wrongPassword = C('wrongpw');
    await rec(
      'login.fail',
      t.http
        .post('/api/v1/auth/login')
        .send({ email: 'canary@ppanel.local', password: canaries.wrongPassword }),
    );

    // ---- login / refresh tokens
    const li = await rec(
      'login',
      t.http
        .post('/api/v1/auth/login')
        .send({ email: 'canary@ppanel.local', password: canaries.password }),
    );
    canaries.access = li.body.data.accessToken;
    allow('access', 'login');
    const cookie = /ppanel_rt=([^;]+)/.exec(String(li.headers['set-cookie']))![1]!;
    canaries.refresh = decodeURIComponent(cookie);
    allow('refresh', 'login');
    const rf = await rec(
      'refresh',
      t.http.post('/api/v1/auth/refresh').set('Cookie', `ppanel_rt=${cookie}`).set('X-CSRF', '1'),
    );
    expect(rf.status).toBe(200);
    allow('refresh', 'refresh');
    canaries.refresh2 = decodeURIComponent(
      /ppanel_rt=([^;]+)/.exec(String(rf.headers['set-cookie']))![1]!,
    );
    allow('refresh2', 'refresh');
    canaries.access2 = rf.body.data.accessToken;
    allow('access2', 'refresh');

    // ---- TOTP secret + recovery codes + step-up token (owner)
    const setup = await rec(
      'totp.setup',
      t.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(owner)),
    );
    const url = setup.body.data.otpauthUrl as string;
    canaries.totpSecret = new URL(url).searchParams.get('secret')!;
    allow('totpSecret', 'totp.setup');
    const conf = await rec(
      'totp.confirm',
      t.http
        .post('/api/v1/auth/mfa/totp/confirm')
        .set(bearer(owner))
        .send({ code: totpNow(url) }),
    );
    expect(conf.status).toBe(200);
    (conf.body.data.recoveryCodes as string[]).forEach((c, i) => {
      canaries[`recovery${i}`] = c;
      allow(`recovery${i}`, 'totp.confirm');
    });
    await t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
    const su = await rec(
      'step-up',
      t.http
        .post('/api/v1/auth/step-up')
        .set(bearer(owner))
        .send({ code: totpNow(url) }),
    );
    expect(su.status).toBe(200);
    canaries.stepUp = su.body.data.stepUpToken;
    allow('stepUp', 'step-up');
    const SU = { 'X-Step-Up': canaries.stepUp };

    // ---- enrollment token (+ a real enrollment through it)
    const en = await rec(
      'enrollment.create',
      t.http
        .post('/api/v1/enrollments')
        .set(bearer(owner))
        .send({ name: 'canary-node', environment: 'development' }),
    );
    canaries.enrollment = en.body.data.token;
    allow('enrollment', 'enrollment.create');
    await enrollAgent(t, owner, { name: 'canary-node-2' });

    // ---- app secret, git token, registry password
    canaries.appSecret = C('appsecret');
    expect(
      (
        await rec(
          'secret.put',
          t.http
            .put(`/api/v1/applications/${ids.appA}/secrets/DB_PASSWORD`)
            .set(bearer(owner))
            .set(SU)
            .send({ value: canaries.appSecret }),
        )
      ).status,
    ).toBeLessThan(300);
    canaries.gitToken = C('gittoken');
    expect(
      (
        await rec(
          'git.put',
          t.http
            .put(`/api/v1/applications/${ids.appA}/git-auth`)
            .set(bearer(owner))
            .set(SU)
            .send({ token: canaries.gitToken }),
        )
      ).status,
    ).toBeLessThan(300);
    canaries.registryPassword = C('regpw');
    expect(
      (
        await rec(
          'registry.put',
          t.http
            .put(`/api/v1/applications/${ids.appA}/registry-auth`)
            .set(bearer(owner))
            .set(SU)
            .send({
              serveraddress: 'registry.example.test',
              username: 'puller',
              password: canaries.registryPassword,
            }),
        )
      ).status,
    ).toBeLessThan(300);
    // a rejected secret write must not echo the value either
    await rec(
      'secret.put.bad',
      t.http
        .put(`/api/v1/applications/${ids.appA}/secrets/bad-key`)
        .set(bearer(owner))
        .set(SU)
        .send({ value: canaries.appSecret }),
    );

    // ---- integration webhook secret + a signed delivery
    canaries.webhookSecret = C('whsecret');
    const ig = await rec(
      'integration.create',
      t.http
        .post('/api/v1/integrations/github')
        .set(bearer(owner))
        .send({ name: 'canary', webhookSecret: canaries.webhookSecret }),
    );
    expect(ig.status).toBe(201);
    const igId = ig.body.data.integration?.id ?? ig.body.data.id;
    const { createHmac } = await import('node:crypto');
    const body = JSON.stringify({
      ref: 'refs/heads/main',
      after: 'c'.repeat(40),
      repository: { full_name: 'org/x' },
    });
    await rec(
      'webhook',
      t.http
        .post(`/api/v1/webhooks/github/${igId}`)
        .set('Content-Type', 'application/json')
        .set('X-GitHub-Event', 'push')
        .set('X-GitHub-Delivery', 'canary-1')
        .set(
          'X-Hub-Signature-256',
          `sha256=${createHmac('sha256', canaries.webhookSecret).update(body).digest('hex')}`,
        )
        .send(body),
    );

    // ---- notification channel secrets
    canaries.signingSecret = C('signing');
    expect(
      (
        await rec(
          'channel.webhook',
          t.http
            .post('/api/v1/notification-channels')
            .set(bearer(owner))
            .send({
              type: 'webhook',
              name: 'canary-wh',
              config: {
                url: 'https://hooks.example.test/c',
                signingSecret: canaries.signingSecret,
              },
            }),
        )
      ).status,
    ).toBe(201);
    canaries.botToken = `123456789:${C('bot').slice(0, 40)}`;
    const tg = await rec(
      'channel.telegram',
      t.http
        .post('/api/v1/notification-channels')
        .set(bearer(owner))
        .send({
          type: 'telegram',
          name: 'canary-tg',
          config: { botToken: canaries.botToken, chatId: '42' },
        }),
    );
    expect(tg.status).toBe(201);
    const tgId = tg.body.data.channel?.id ?? tg.body.data.id;
    // a failing send (no Telegram reachable) must not leak the token in delivery errors / logs
    await rec(
      'channel.test',
      t.http.post(`/api/v1/notification-channels/${tgId}/test`).set(bearer(owner)).send({}),
    );

    // ---- backup repo credentials
    canaries.restPassword = C('restpw');
    canaries.repoPassword = C('repopw');
    const ra = await rec(
      'repo.access',
      t.http
        .put(`/api/v1/backup-repositories/${ids.repo}/servers/${ids.serverB}`)
        .set(bearer(owner))
        .set(SU)
        .send({
          restUser: 'canary-b',
          restPassword: canaries.restPassword,
          repoPassword: canaries.repoPassword,
        }),
    );
    expect(ra.status).toBeLessThan(300);
    const exp = await rec(
      'repo.recovery-export',
      t.http
        .get(`/api/v1/backup-repositories/${ids.repo}/recovery-export`)
        .set(bearer(owner))
        .set(SU),
    );
    if (exp.status === 200) {
      allow('restPassword', 'repo.recovery-export');
      allow('repoPassword', 'repo.recovery-export');
    }

    // ---- log tail token
    const tt = await rec(
      'tail-token',
      t.http.post('/api/v1/logs/tail-token').set(bearer(owner)).send({ serverId: ids.serverA }),
    );
    if (tt.status === 201) {
      canaries.tailToken = tt.body.data.token;
      allow('tailToken', 'tail-token');
    }

    // ---- read every GET route as owner (the read side must only ever show { set: true })
    const { PROBES } = await import('../authz/probes');
    for (const pr of PROBES.filter(
      (x) => x.route.startsWith('GET ') && !x.route.includes('/logs/tail'),
    ))
      await rec(`read:${pr.route}`, t.http.get(pr.path(ids)).set(bearer(owner)).set(SU));
    await rec(
      'read:secrets',
      t.http.get(`/api/v1/applications/${ids.appA}/secrets`).set(bearer(owner)),
    );
    await rec('read:channels', t.http.get('/api/v1/notification-channels').set(bearer(owner)));
    await rec('read:integrations', t.http.get('/api/v1/integrations').set(bearer(owner)));
    await rec('read:audit', t.http.get('/api/v1/audit-events?limit=100').set(bearer(owner)));
    expect(Object.keys(canaries).length).toBeGreaterThan(20);
  });

  it('no canary in any table / column (raw, base64, url-encoded, hex)', async () => {
    const cols = await w.t.prisma.$queryRaw<
      Array<{ table_name: string; column_name: string; data_type: string }>
    >`
      SELECT table_name, column_name, data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'
         AND data_type IN ('text', 'character varying', 'jsonb', 'json', 'ARRAY', 'bytea')`;
    expect(cols.length).toBeGreaterThan(100);
    const hits: string[] = [];
    for (const c of cols) {
      // identifiers come from information_schema (not user input)
      const rows = await w.t.prisma.$queryRawUnsafe<Array<{ v: string | null }>>(
        `SELECT "${c.column_name}"::text AS v FROM "${c.table_name}" WHERE "${c.column_name}" IS NOT NULL`,
      );
      const blob = rows.map((r) => r.v ?? '').join('\n');
      for (const [label, secret] of Object.entries(canaries))
        for (const e of encodings(secret))
          if (blob.includes(e)) hits.push(`${c.table_name}.${c.column_name} ⊃ ${label}`);
    }
    expect([...new Set(hits)]).toEqual([]);
  });

  it('no canary in structured logs (debug level, every request)', () => {
    expect(logs.length).toBeGreaterThan(50);
    const blob = logs.join('');
    const hits = Object.entries(canaries)
      .filter(([, s]) => encodings(s).some((e) => blob.includes(e)))
      .map(([k]) => k);
    expect(hits).toEqual([]);
    // every line is structured JSON with level/message/timestamp
    for (const l of logs.slice(0, 200)) {
      const j = JSON.parse(l);
      expect(j).toMatchObject({ level: expect.any(String), timestamp: expect.any(String) });
    }
  });

  it('no canary in any API response except its own one-time disclosure', () => {
    const hits: string[] = [];
    for (const r of responses)
      for (const [label, secret] of Object.entries(canaries)) {
        if (disclosure[label]?.has(r.where)) continue;
        if (encodings(secret).some((e) => r.text.includes(e))) hits.push(`${r.where} ⊃ ${label}`);
      }
    expect(hits).toEqual([]);
  });
});
