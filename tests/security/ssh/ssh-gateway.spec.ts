/**
 * P10-T2/T3 security cases for the SSH gateway (threats: WebSocket hijack, ticket leakage via URL,
 * cross-site request forgery, private key exposure, missing authorization on SSH routes).
 * The per-route authorization matrix (401 / role / IDOR) covers every SSH route via authz/probes.ts.
 */
import type { AddressInfo } from 'node:net';
import { sshUtils, WebSocket } from '../../../apps/api/test/support/p10-deps';
import { bearer, stepUpToken } from '../../../apps/api/test/integration/helpers';
import { PROBES } from '../authz/probes';
import { nestRoutes } from '../lib/routes';
import { buildWorld, type World } from '../lib/world';

const ORIGIN = 'http://localhost:3100';
let w: World;
let port: number;

beforeAll(async () => {
  w = await buildWorld();
  await w.t.app.listen(0, '127.0.0.1');
  port = (w.t.app.getHttpServer().address() as AddressInfo).port;
});
afterAll(async () => w.t.close());

function upgrade(path: string, headers: Record<string, string>): Promise<number> {
  const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`, { headers });
  ws.on('error', () => undefined);
  return new Promise((resolve) => {
    ws.on('unexpected-response', (_req, res) => {
      resolve(res.statusCode ?? 0);
      res.resume();
      ws.terminate();
    });
    ws.on('open', () => {
      resolve(101);
      ws.terminate();
    });
  });
}

async function newSession(): Promise<{ sessionId: string; ticket: string }> {
  const r = await w.t.http
    .post('/api/v1/ssh/sessions')
    .set(bearer(w.p.owner))
    .send({ grantId: w.ids.sshGrantA, cols: 80, rows: 24 });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body.data;
}

const ticketUnused = async (id: string) =>
  (await w.t.prisma.sshSession.findUniqueOrThrow({ where: { id } })).ticketHash !== null;

describe('P10 WebSocket hijack (cross-site WebSocket)', () => {
  it('foreign, null, look-alike and missing Origin are refused with 403 before the upgrade', async () => {
    const s = await newSession();
    for (const origin of [
      'https://evil.example',
      'null',
      'http://localhost:3100.evil.example',
      'http://localhost:31000',
      'HTTP://LOCALHOST:3100x',
    ])
      expect(await upgrade('/api/v1/ssh/stream', { Origin: origin }), origin).toBe(403);
    expect(await upgrade('/api/v1/ssh/stream', {})).toBe(403);
    // nothing was consumed: the refused handshakes never reached the ticket check
    expect(await ticketUnused(s.sessionId)).toBe(true);
  });

  it('a ticket in the query string is refused (400) and never consumed', async () => {
    const s = await newSession();
    for (const q of [`?ticket=${s.ticket}`, `?sessionId=${s.sessionId}&ticket=${s.ticket}`, '?x=1'])
      expect(await upgrade(`/api/v1/ssh/stream${q}`, { Origin: ORIGIN })).toBe(400);
    expect(await ticketUnused(s.sessionId)).toBe(true);
    // the bearer token in a header does not authenticate the stream either: only the ticket frame does
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/v1/ssh/stream`, {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${w.p.owner}` },
    });
    const code = await new Promise<number>((r) => {
      ws.on('open', () => ws.send(JSON.stringify({ type: 'ping' })));
      ws.on('close', (c) => r(c));
    });
    expect(code).toBe(4401);
    expect(await ticketUnused(s.sessionId)).toBe(true);
  });

  it('a principal scoped to server B cannot mint a ticket for server A', async () => {
    const r = await w.t.http
      .post('/api/v1/ssh/sessions')
      .set(bearer(w.p.scopedB))
      .send({ grantId: w.ids.sshGrantA });
    expect(r.status).toBe(403);
    expect(JSON.stringify(r.body)).not.toMatch(/ticket/);
  });
});

describe('P10 CSRF: cross-origin POSTs cannot drive the SSH API', () => {
  it('cookie-only requests (what a cross-site form can send) are 401 on every SSH POST', async () => {
    const login = await w.t.http
      .post('/api/v1/auth/login')
      .send({ email: 'superadmin@ppanel.local', password: 'password' });
    const raw = login.headers['set-cookie'] as unknown as string[] | string;
    const cookie = /ppanel_rt=[^;]+/.exec(Array.isArray(raw) ? raw.join(';') : raw)![0];
    const ssh = PROBES.filter((p) =>
      /^(POST|PUT|DELETE) \/api\/v1\/(ssh\/|servers\/:id\/ssh\/)/.test(p.route),
    );
    expect(ssh.length).toBeGreaterThanOrEqual(15);
    for (const p of ssh) {
      const [method] = p.route.split(' ') as [string];
      const res = await w.t.http[method.toLowerCase() as 'post'](p.path(w.ids))
        .set('Cookie', cookie)
        .set('Origin', 'https://evil.example')
        .set('Content-Type', 'text/plain')
        .send(JSON.stringify(p.body?.(w.ids) ?? {}));
      expect(res.status, p.route).toBe(401);
    }
  });

  it('CORS preflight from a foreign origin is not allowed', async () => {
    const res = await w.t.http
      .options('/api/v1/ssh/sessions')
      .set('Origin', 'https://evil.example')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'authorization,content-type');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('P10 private key material is never exposed', () => {
  it('import → list → deploy → rotate → revoke: no response, audit row, job param or column but the envelope holds key material', async () => {
    const su = await stepUpToken(w.t, w.p.owner);
    const passphrase = 'CANARYSSHPASS' + Math.random().toString(36).slice(2);
    const kp = sshUtils.generateKeyPairSync('ed25519', {
      passphrase,
      cipher: 'aes256-ctr',
      rounds: 4,
    });
    const responses: string[] = [];
    const rec = (b: unknown) => {
      responses.push(JSON.stringify(b));
      return b as any;
    };
    const created = rec(
      (
        await w.t.http
          .post('/api/v1/ssh/credentials')
          .set(bearer(w.p.owner))
          .set('X-Step-Up', su)
          .send({ name: 'imported', mode: 'import', privateKey: kp.private, passphrase })
      ).body,
    );
    expect(created.data.kind).toBe('imported');
    const id = created.data.id as string;
    rec((await w.t.http.get('/api/v1/ssh/credentials').set(bearer(w.p.owner))).body);
    rec(
      (
        await w.t.http
          .post(`/api/v1/ssh/credentials/${id}/deploy`)
          .set(bearer(w.p.owner))
          .send({ serverId: w.ids.serverB, sshUser: 'ops' })
      ).body,
    );
    const rotated = rec(
      (
        await w.t.http
          .post(`/api/v1/ssh/credentials/${id}/rotate`)
          .set(bearer(w.p.owner))
          .set('X-Step-Up', su)
      ).body,
    );
    rec(
      (
        await w.t.http
          .post(`/api/v1/ssh/credentials/${rotated.data.id}/revoke`)
          .set(bearer(w.p.owner))
          .set('X-Step-Up', su)
      ).body,
    );
    rec((await w.t.http.get('/api/v1/audit-events?limit=100').set(bearer(w.p.owner))).body);
    rec((await w.t.http.get(`/api/v1/servers/${w.ids.serverB}/jobs`).set(bearer(w.p.owner))).body);
    const body = kp.private.split('\n').slice(1, -2).join('');
    const needles = ['PRIVATE KEY', 'privateKey', passphrase, body.slice(0, 40), body.slice(-40)];
    for (const r of responses) for (const n of needles) expect(r.includes(n), n).toBe(false);
    // database: every text/json column of every table except the AES-GCM envelope column
    const cols = await w.t.prisma.$queryRaw<Array<{ table_name: string; column_name: string }>>`
      SELECT table_name, column_name FROM information_schema.columns
       WHERE table_schema = 'public' AND data_type IN ('text', 'jsonb', 'ARRAY')`;
    const hits: string[] = [];
    for (const c of cols) {
      const rows = await w.t.prisma.$queryRawUnsafe<Array<{ v: string | null }>>(
        `SELECT "${c.column_name}"::text AS v FROM "${c.table_name}" WHERE "${c.column_name}" IS NOT NULL`,
      );
      const blob = rows.map((r) => r.v ?? '').join('\n');
      for (const n of ['PRIVATE KEY', passphrase, body.slice(0, 40), body.slice(-40)])
        if (blob.includes(n)) hits.push(`${c.table_name}.${c.column_name}`);
    }
    expect(hits).toEqual([]);
    const enc = await w.t.prisma.sshCredential.findUniqueOrThrow({ where: { id } });
    expect(enc.privateKeyEnc.startsWith('v1.')).toBe(true);
  });
});

describe('P10 route coverage', () => {
  it('every SSH route has a security probe and a coarse permission or explicit service check', () => {
    const routes = nestRoutes(w.t).filter((r) => r.path.includes('/ssh'));
    expect(routes.length).toBe(21);
    for (const r of routes) {
      expect(r.isPublic, r.path).toBe(false);
      const p = PROBES.find((x) => x.route === `${r.method} ${r.path}`);
      expect(p, `${r.method} ${r.path}`).toBeDefined();
      if (!r.permission) expect(p!.allowViewer, r.path).toBeDefined();
    }
  });
});
