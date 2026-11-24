/**
 * P10 SSH gateway against real Postgres and an in-process ssh2 Server acting as sshd (public-key
 * auth, fixed host key, PTY shell with a tiny command set). The browser side is a real `ws` client
 * with an Origin header. Covers credentials → deploy job → endpoints → host-key scan/trust → grants
 * (incl. production approval) → sessions over WebSocket, and every denial path of §5.
 */
import type { AddressInfo } from 'node:net';
import { Server as SshServer, utils as sshUtils, type Connection } from 'ssh2';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import { uuidv7 } from '../../src/common/ids';
import { SshGrantsService } from '../../src/ssh/grants.service';
import { bearer, bootApp, login, resetDb, stepUpToken, type TestApp } from './helpers';

const ORIGIN = 'http://localhost:3100';
const SECRET_MARKERS = ['PRIVATE KEY', 'privateKey', 'private_key'];

// ---------------------------------------------------------------- fake sshd

interface FakeSshd {
  server: SshServer;
  port: number;
  hostPrivate: string;
  authorized: Set<string>;
  authAttempts: number;
  liveConnections: number;
  liveChannels: number;
  resizes: Array<{ cols: number; rows: number }>;
  pty: { cols: number; rows: number } | null;
  requests: string[];
}

function startSshd(port = 0, hostPrivate?: string): Promise<FakeSshd> {
  const key = hostPrivate ?? sshUtils.generateKeyPairSync('ed25519').private;
  const f: FakeSshd = {
    server: null as unknown as SshServer,
    port: 0,
    hostPrivate: key,
    authorized: new Set(),
    authAttempts: 0,
    liveConnections: 0,
    liveChannels: 0,
    resizes: [],
    pty: null,
    requests: [],
  };
  f.server = new SshServer({ hostKeys: [key] }, (client: Connection) => {
    f.liveConnections++;
    client.on('close', () => f.liveConnections--);
    client.on('error', () => undefined);
    client.on('authentication', (ctx) => {
      f.authAttempts++;
      if (ctx.method !== 'publickey' || ctx.username !== 'ops') return ctx.reject(['publickey']);
      const b64 = ctx.key.data.toString('base64');
      if (!f.authorized.has(b64)) return ctx.reject(['publickey']);
      if (!ctx.signature) return ctx.accept();
      const pub = sshUtils.parseKey(`${ctx.key.algo} ${b64}`);
      if (pub instanceof Error || !pub.verify(ctx.blob!, ctx.signature, ctx.hashAlgo))
        return ctx.reject(['publickey']);
      ctx.accept();
    });
    client.on('request', (_accept, reject, name) => {
      f.requests.push(name);
      reject?.();
    });
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (ok, _rej, info) => {
          f.pty = { cols: info.cols, rows: info.rows };
          ok?.();
        });
        session.on('window-change', (ok, _rej, info) => {
          f.resizes.push({ cols: info.cols, rows: info.rows });
          ok?.();
        });
        session.on('x11', (_ok, rej) => {
          f.requests.push('x11');
          rej?.();
        });
        session.on('auth-agent', (_ok, rej) => {
          f.requests.push('auth-agent');
          rej?.();
        });
        session.on('shell', (ok) => {
          const stream = ok();
          f.liveChannels++;
          stream.on('close', () => f.liveChannels--);
          let line = '';
          stream.on('data', (d: Buffer) => {
            for (const ch of d.toString('utf8')) {
              if (ch !== '\r' && ch !== '\n') {
                line += ch;
                continue;
              }
              const cmd = line.trim();
              line = '';
              if (cmd === 'id -un') stream.write('ops\r\n');
              else if (cmd.startsWith('echo ')) stream.write(cmd.slice(5) + '\r\n');
              else if (cmd.startsWith('exit')) {
                stream.exit(Number(cmd.split(' ')[1] ?? 0));
                stream.end();
              } else if (cmd) stream.write(`sh: ${cmd}: not found\r\n`);
            }
          });
        });
      });
    });
  });
  return new Promise((resolve) => {
    f.server.listen(port, '127.0.0.1', () => {
      f.port = (f.server.address() as AddressInfo).port;
      resolve(f);
    });
  });
}

const stopSshd = (f: FakeSshd) => new Promise<void>((r) => f.server.close(() => r()));

// ---------------------------------------------------------------- harness

let sshd: FakeSshd;
let t: TestApp;
let apiPort: number;
let owner: string;
let admin: string;
let viewer: string;
const bodies: string[] = [];

async function api(
  method: 'get' | 'post' | 'put' | 'delete',
  path: string,
  token: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  let req = t.http[method](`/api/v1${path}`).set(bearer(token));
  for (const [k, v] of Object.entries(headers)) req = req.set(k, v);
  const res = body === undefined ? await req : await req.send(body as object);
  bodies.push(JSON.stringify(res.body ?? null));
  return res;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(fn: () => boolean | Promise<boolean>, ms = 5000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await sleep(25);
  }
  throw new Error('condition not met in time');
}

interface WsConn {
  ws: WebSocket;
  texts: Array<Record<string, any>>;
  output: () => string;
  closed: Promise<{ code: number; reason: string }>;
  opened: Promise<void>;
}

function openWs(opts: { origin?: string | null; path?: string } = {}): WsConn {
  const headers: Record<string, string> = {};
  if (opts.origin !== null) headers.Origin = opts.origin ?? ORIGIN;
  const ws = new WebSocket(`ws://127.0.0.1:${apiPort}${opts.path ?? '/api/v1/ssh/stream'}`, {
    headers,
  });
  const texts: Array<Record<string, any>> = [];
  const chunks: Buffer[] = [];
  ws.on('message', (data, isBinary) => {
    if (isBinary) chunks.push(Buffer.from(data as Buffer));
    else texts.push(JSON.parse(String(data)));
  });
  ws.on('error', () => undefined);
  const closed = new Promise<{ code: number; reason: string }>((r) =>
    ws.on('close', (code, reason) => r({ code, reason: String(reason) })),
  );
  const opened = new Promise<void>((resolve, reject) => {
    ws.on('open', () => resolve());
    ws.on('unexpected-response', (_req, res) => reject(new Error(`HTTP ${res.statusCode}`)));
  });
  return { ws, texts, output: () => Buffer.concat(chunks).toString('utf8'), closed, opened };
}

function upgradeStatus(opts: { origin?: string | null; path?: string }): Promise<number> {
  const headers: Record<string, string> = {};
  if (opts.origin !== null) headers.Origin = opts.origin ?? ORIGIN;
  const ws = new WebSocket(`ws://127.0.0.1:${apiPort}${opts.path ?? '/api/v1/ssh/stream'}`, {
    headers,
  });
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

async function authed(ticket: string, sessionId: string): Promise<WsConn> {
  const c = openWs();
  await c.opened;
  c.ws.send(JSON.stringify({ type: 'auth', ticket, sessionId }));
  return c;
}

async function runSyncJobs(serverId: string, ok = true): Promise<number> {
  const grants = await t.jobs.lease(serverId);
  for (const g of grants) {
    expect(g.type).toBe('ssh.keys.sync');
    expect(JSON.stringify(g.params)).not.toMatch(/PRIVATE KEY/);
    await t.jobs.ack(serverId, g.jobId, g.leaseToken);
    const p = g.params as { user: string; keys: Array<{ fingerprint: string; publicKey: string }> };
    await t.jobs.result(
      serverId,
      g.jobId,
      ok
        ? {
            leaseToken: g.leaseToken,
            status: 'succeeded',
            output: {
              user: p.user,
              managedFingerprints: p.keys.map((k) => k.fingerprint),
              preservedLines: 1,
              fileSha256: 'f'.repeat(64),
            },
          }
        : { leaseToken: g.leaseToken, status: 'failed', error: { code: 'SSH_USER_INVALID' } },
    );
    // the fake sshd authorizes exactly what the agent would install
    sshd.authorized.clear();
    for (const k of p.keys) sshd.authorized.add(k.publicKey.split(' ')[1]!);
  }
  return grants.length;
}

async function createServer(environment = 'development'): Promise<string> {
  const id = uuidv7();
  await t.prisma.server.create({
    data: {
      id,
      name: `ssh-${environment}-${id.slice(-4)}`,
      hostname: 'lab-node-s',
      environment,
      status: 'online',
      lastHeartbeatAt: new Date(),
      agentVersion: '0.1.0',
      addresses: {
        create: [
          {
            id: uuidv7(),
            family: 'ipv4',
            scope: 'private',
            address: '10.99.0.5',
            source: 'detected',
          },
        ],
      },
    },
  });
  return id;
}

interface Ready {
  serverId: string;
  credentialId: string;
  fingerprint: string;
  hostKeyId: string;
  ownerStepUp: string;
}

/** Server with endpoint, deployed credential and trusted host key (owner = credentials admin). */
async function ready(environment = 'development'): Promise<Ready> {
  const serverId = await createServer(environment);
  const ownerStepUp = await stepUpToken(t, owner);
  let r = await api('put', `/servers/${serverId}/ssh/endpoints`, owner, [
    { path: 'private', host: '127.0.0.1', port: sshd.port, allowedUsers: ['ops'] },
  ]);
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  r = await api(
    'post',
    '/ssh/credentials',
    owner,
    { name: 'lab key', mode: 'generate' },
    {
      'X-Step-Up': ownerStepUp,
    },
  );
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  const credentialId = r.body.data.id as string;
  const fingerprint = r.body.data.fingerprintSha256 as string;
  r = await api('post', `/ssh/credentials/${credentialId}/deploy`, owner, {
    serverId,
    sshUser: 'ops',
  });
  expect(r.status).toBe(202);
  expect(await runSyncJobs(serverId)).toBe(1);
  // host keys: facts from the agent (mTLS channel) allow the agentMatch cross-check
  const hostBlob = (
    sshUtils.parseKey(sshd.hostPrivate) as { getPublicSSH(): Buffer }
  ).getPublicSSH();
  const { fingerprintOf } = await import('../../src/ssh/ssh-keys');
  await t.prisma.server.update({
    where: { id: serverId },
    data: {
      sshFacts: {
        hostKeys: [{ algorithm: 'ssh-ed25519', fingerprintSha256: fingerprintOf(hostBlob) }],
        port: 22,
      },
    },
  });
  r = await api('post', `/servers/${serverId}/ssh/host-keys/scan`, owner, { path: 'private' });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  expect(sshd.authAttempts).toBe(0); // scan aborts before authentication
  const key = r.body.data[0];
  expect(key).toMatchObject({ status: 'pending', seenVia: 'scan', agentMatch: true });
  r = await api('post', `/ssh/host-keys/${key.id}/trust`, owner, {}, { 'X-Step-Up': ownerStepUp });
  expect(r.status).toBe(200);
  return { serverId, credentialId, fingerprint, hostKeyId: key.id, ownerStepUp };
}

async function grantFor(token: string, serverId: string, extra: Record<string, unknown> = {}) {
  const r = await api('post', '/ssh/grants', token, {
    serverId,
    sshUser: 'ops',
    endpointPath: 'private',
    durationMinutes: 30,
    reason: 'debug the lab node',
    ...extra,
  });
  return r;
}

async function sessionFor(token: string, grantId: string, headers: Record<string, string> = {}) {
  return api('post', '/ssh/sessions', token, { grantId, cols: 100, rows: 30 }, headers);
}

/** Opens an authenticated, `ready` terminal for `admin`. */
async function liveTerminal(env = 'development') {
  const rd = await ready(env);
  const g = await grantFor(admin, rd.serverId);
  expect(g.status, JSON.stringify(g.body)).toBe(201);
  const s = await sessionFor(admin, g.body.data.id);
  expect(s.status, JSON.stringify(s.body)).toBe(201);
  const c = await authed(s.body.data.ticket, s.body.data.sessionId);
  await until(() => c.texts.some((m) => m.type === 'ready' || m.type === 'error'));
  return {
    ...rd,
    grantId: g.body.data.id as string,
    sessionId: s.body.data.sessionId as string,
    c,
  };
}

beforeAll(async () => {
  sshd = await startSshd();
  t = await bootApp({ PPANEL_SSH_LAB_ENDPOINTS: `127.0.0.1:${sshd.port}` });
  await t.app.listen(0, '127.0.0.1');
  apiPort = (t.app.getHttpServer().address() as AddressInfo).port;
});
afterAll(async () => {
  await t.close();
  await stopSshd(sshd);
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  admin = await login(t, 'admin');
  viewer = await login(t, 'user1');
  sshd.authorized.clear();
  sshd.authAttempts = 0;
  sshd.resizes = [];
  sshd.pty = null;
  sshd.requests = [];
  t.config.SSH_IDLE_TIMEOUT_SEC = 900;
  t.config.SSH_MAX_SESSIONS_PER_USER = 3;
});

// ---------------------------------------------------------------- tests

describe('P10 credentials, deployments, endpoints, host keys', () => {
  it('generate/import need credentials.manage + step-up; metadata only; deploy → installed', async () => {
    let r = await api('post', '/ssh/credentials', owner, { name: 'k', mode: 'generate' });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    r = await api('post', '/ssh/credentials', viewer, { name: 'k', mode: 'generate' });
    expect(r.status).toBe(403);
    const rd = await ready();
    r = await api('get', '/ssh/credentials', viewer);
    expect(r.status).toBe(200);
    expect(r.body.data[0]).toMatchObject({
      id: rd.credentialId,
      kind: 'generated',
      algorithm: 'ssh-ed25519',
      status: 'active',
      createdByLabel: 'Super Admin',
    });
    expect(r.body.data[0].deployments[0]).toMatchObject({ sshUser: 'ops', status: 'installed' });
    expect(Object.keys(r.body.data[0])).not.toContain('privateKeyEnc');
    // import: encrypted without passphrase, RSA 2048, too large body
    const enc = sshUtils.generateKeyPairSync('ed25519', {
      passphrase: 'pw',
      cipher: 'aes256-ctr',
      rounds: 4,
    });
    r = await api(
      'post',
      '/ssh/credentials',
      owner,
      { name: 'i', mode: 'import', privateKey: enc.private },
      {
        'X-Step-Up': rd.ownerStepUp,
      },
    );
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('SSH_KEY_ENCRYPTED');
    r = await api(
      'post',
      '/ssh/credentials',
      owner,
      { name: 'i', mode: 'import', privateKey: enc.private, passphrase: 'pw' },
      { 'X-Step-Up': rd.ownerStepUp },
    );
    expect(r.status).toBe(201);
    expect(r.body.data.kind).toBe('imported');
    const weak = sshUtils.generateKeyPairSync('rsa', { bits: 2048 });
    r = await api(
      'post',
      '/ssh/credentials',
      owner,
      { name: 'w', mode: 'import', privateKey: weak.private },
      {
        'X-Step-Up': rd.ownerStepUp,
      },
    );
    expect(r.body.error.code).toBe('SSH_KEY_UNSUPPORTED');
    r = await api(
      'post',
      '/ssh/credentials',
      owner,
      { name: 'big', mode: 'import', privateKey: 'x'.repeat(17_000) },
      { 'X-Step-Up': rd.ownerStepUp },
    );
    expect(r.status).toBe(413);
    // stored encrypted (AES-256-GCM envelope), never as PEM
    const rows = await t.prisma.$queryRaw<
      Array<{ private_key_enc: string }>
    >`SELECT private_key_enc FROM ssh_credentials`;
    for (const row of rows) {
      expect(row.private_key_enc.startsWith('v1.')).toBe(true);
      expect(row.private_key_enc).not.toContain('PRIVATE');
    }
    // the deploy job carries public keys only; POST /jobs cannot create it
    r = await api('post', `/servers/${rd.serverId}/jobs`, owner, {
      type: 'ssh.keys.sync',
      params: { user: 'ops', keys: [], managedBlockId: 'ppanel' },
    });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('JOB_TYPE_RESTRICTED');
    const actions = (await t.prisma.auditEvent.findMany({ select: { action: true } })).map(
      (a) => a.action,
    );
    expect(actions).toEqual(
      expect.arrayContaining([
        'ssh.credential.create',
        'ssh.credential.import',
        'ssh.key.deploy',
        'ssh.endpoint.update',
        'ssh.host_key.scan',
        'ssh.host_key.trust',
      ]),
    );
  });

  it('endpoints: unverified host 422, root forbidden, verified private address accepted', async () => {
    const serverId = await createServer();
    let r = await api('put', `/servers/${serverId}/ssh/endpoints`, owner, [
      { path: 'private', host: '10.1.2.3', port: 22, allowedUsers: ['ops'] },
    ]);
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('SSH_ENDPOINT_UNVERIFIED');
    r = await api('put', `/servers/${serverId}/ssh/endpoints`, owner, [
      { path: 'private', host: '127.0.0.1', port: 2222, allowedUsers: ['ops'] },
    ]);
    expect(r.body.error.code).toBe('SSH_ENDPOINT_UNVERIFIED'); // lab entry is host:port exact
    r = await api('put', `/servers/${serverId}/ssh/endpoints`, owner, [
      { path: 'private', host: '10.99.0.5', port: 22, allowedUsers: ['ops', 'root'] },
    ]);
    expect(r.body.error.code).toBe('SSH_ROOT_FORBIDDEN');
    r = await api('put', `/servers/${serverId}/ssh/endpoints`, owner, [
      { path: 'private', host: '10.99.0.5', port: 22, allowedUsers: ['ops'] },
    ]);
    expect(r.status).toBe(200);
    expect(r.body.data).toEqual([
      expect.objectContaining({
        path: 'private',
        host: '10.99.0.5',
        port: 22,
        allowedUsers: ['ops'],
      }),
    ]);
    r = await api('put', `/servers/${serverId}/ssh/endpoints`, viewer, []);
    expect(r.status).toBe(403);
    r = await api('get', `/servers/${serverId}`, viewer);
    expect(r.body.data.ssh).toEqual({
      endpoints: [{ path: 'private', host: '10.99.0.5', port: 22 }],
      trustedHostKey: false,
      hasCredential: false,
    });
  });

  it('grant needs an installed deployment of an active credential (SSH_NO_CREDENTIAL)', async () => {
    const serverId = await createServer();
    await api('put', `/servers/${serverId}/ssh/endpoints`, owner, [
      { path: 'private', host: '10.99.0.5', port: 22, allowedUsers: ['ops'] },
    ]);
    const r = await grantFor(admin, serverId);
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('SSH_NO_CREDENTIAL');
    const v = await grantFor(viewer, serverId);
    expect(v.status).toBe(403);
  });
});

describe('P10 sessions over the WebSocket gateway', () => {
  it('happy path: ready → stdin/stdout → resize → exit code; row + audit; no orphan', async () => {
    const { c, sessionId, serverId, fingerprint } = await liveTerminal();
    const readyMsg = c.texts.find((m) => m.type === 'ready')!;
    // a global credentials admin sees another user's session (regression: empty relation filter inside OR)
    const all = await api('get', '/ssh/sessions', owner);
    expect(all.body.data.map((x: { id: string }) => x.id)).toContain(sessionId);
    expect(readyMsg).toMatchObject({
      type: 'ready',
      sessionId,
      sshUser: 'ops',
      endpoint: { path: 'private', host: '127.0.0.1', port: sshd.port },
    });
    expect(readyMsg.hostKeyFingerprint).toMatch(/^SHA256:/);
    expect(sshd.pty).toEqual({ cols: 100, rows: 30 });
    c.ws.send(Buffer.from('id -un\r'));
    await until(() => c.output().includes('ops'));
    c.ws.send(JSON.stringify({ type: 'resize', cols: 132, rows: 40 }));
    await until(() => sshd.resizes.length > 0);
    expect(sshd.resizes[0]).toEqual({ cols: 132, rows: 40 });
    c.ws.send(JSON.stringify({ type: 'ping' }));
    await until(() => c.texts.some((m) => m.type === 'pong'));
    c.ws.send(Buffer.from('echo hello-p10\r'));
    await until(() => c.output().includes('hello-p10'));
    c.ws.send(Buffer.from('exit 3\r'));
    const closed = await c.closed;
    expect(closed.code).toBe(1000);
    expect(c.texts.find((m) => m.type === 'exit')).toMatchObject({ code: 3 });
    await until(
      async () =>
        (await t.prisma.sshSession.findUnique({ where: { id: sessionId } }))?.status === 'closed',
    );
    const row = await t.prisma.sshSession.findUniqueOrThrow({ where: { id: sessionId } });
    expect(row).toMatchObject({
      status: 'closed',
      endReason: 'server_closed',
      exitCode: 3,
      credentialFingerprint: fingerprint,
      ticketHash: null,
    });
    expect(Number(row.bytesIn)).toBeGreaterThan(10);
    expect(Number(row.bytesOut)).toBeGreaterThan(5);
    await until(() => sshd.liveChannels === 0 && sshd.liveConnections === 0);
    // no forwarding of any kind was requested by the Center
    expect(sshd.requests).toEqual([]);
    const audit = await t.prisma.auditEvent.findMany({
      where: { action: { in: ['ssh.session.open', 'ssh.session.close'] } },
    });
    expect(audit.map((a) => a.action).sort()).toEqual(['ssh.session.close', 'ssh.session.open']);
    const meta = audit.find((a) => a.action === 'ssh.session.close')!.metadata as Record<
      string,
      any
    >;
    expect(meta).toMatchObject({
      endReason: 'server_closed',
      exitCode: 3,
      serverId,
      keyFingerprint: fingerprint,
    });
    // metadata only: no keystrokes, no output
    expect(JSON.stringify(audit)).not.toContain('hello-p10');
    const list = await api('get', `/ssh/sessions?server_id=${serverId}`, admin);
    expect(list.body.data[0]).toMatchObject({
      id: sessionId,
      status: 'closed',
      serverName: expect.any(String),
      userLabel: 'Ops Admin',
    });
  });

  it('Origin: foreign / missing → 403 before upgrade; query string → 400; other path → 404', async () => {
    expect(await upgradeStatus({ origin: 'https://evil.example' })).toBe(403);
    expect(await upgradeStatus({ origin: null })).toBe(403);
    expect(await upgradeStatus({ path: '/api/v1/ssh/stream?ticket=abc' })).toBe(400);
    expect(await upgradeStatus({ path: '/api/v1/other' })).toBe(404);
    expect(await upgradeStatus({})).toBe(101);
    const denied = await t.prisma.auditEvent.count({
      where: { action: 'ssh.session.denied', result: 'denied' },
    });
    expect(denied).toBeGreaterThanOrEqual(2);
  });

  it('tickets: missing / wrong / reused / other session / expired → 4401; single use', async () => {
    const rd = await ready();
    const g = await grantFor(admin, rd.serverId);
    const s1 = (await sessionFor(admin, g.body.data.id)).body.data;
    const s2 = (await sessionFor(admin, g.body.data.id)).body.data;
    expect(s1.wsUrl).toBe('ws://localhost:4000/api/v1/ssh/stream');
    expect(s1.wsUrl).not.toContain(s1.ticket);
    // binary first frame
    let c = openWs();
    await c.opened;
    c.ws.send(Buffer.from('x'));
    expect((await c.closed).code).toBe(4401);
    // wrong ticket
    c = await authed('A'.repeat(43), s1.sessionId);
    expect((await c.closed).code).toBe(4401);
    // ticket of session 1 presented for session 2
    c = await authed(s1.ticket, s2.sessionId);
    expect((await c.closed).code).toBe(4401);
    // valid use
    c = await authed(s1.ticket, s1.sessionId);
    await until(() => c.texts.some((m) => m.type === 'ready'));
    // reuse of the same ticket
    const again = await authed(s1.ticket, s1.sessionId);
    expect((await again.closed).code).toBe(4401);
    c.ws.send(JSON.stringify({ type: 'close' }));
    expect((await c.closed).code).toBe(1000);
    // expired ticket
    await t.prisma.sshSession.update({
      where: { id: s2.sessionId },
      data: { ticketExpiresAt: new Date(Date.now() - 1000) },
    });
    c = await authed(s2.ticket, s2.sessionId);
    expect((await c.closed).code).toBe(4401);
    // no auth frame within 5 s
    c = openWs();
    await c.opened;
    const t0 = Date.now();
    expect((await c.closed).code).toBe(4401);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(4500);
    // an unknown frame type after ready is a protocol error
    const s3 = (await sessionFor(admin, g.body.data.id)).body.data;
    c = await authed(s3.ticket, s3.sessionId);
    await until(() => c.texts.some((m) => m.type === 'ready'));
    c.ws.send(JSON.stringify({ type: 'exec', cmd: 'id' }));
    expect((await c.closed).code).toBe(4400);
  }, 30_000);

  it('another user cannot use or terminate my grant/session; viewer cannot connect', async () => {
    const rd = await ready();
    const g = await grantFor(admin, rd.serverId);
    let r = await sessionFor(owner, g.body.data.id, { 'X-Step-Up': rd.ownerStepUp });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('SSH_GRANT_INVALID');
    r = await sessionFor(viewer, g.body.data.id);
    expect(r.status).toBe(403);
    const s = (await sessionFor(admin, g.body.data.id)).body.data;
    r = await api('post', `/ssh/sessions/${s.sessionId}/terminate`, viewer);
    expect([403, 404]).toContain(r.status);
    r = await api('get', '/ssh/sessions', viewer);
    expect(r.body.data).toEqual([]);
    r = await api('get', '/ssh/grants', viewer);
    expect(r.body.data).toEqual([]);
    r = await api('post', `/ssh/grants/${g.body.data.id}/revoke`, viewer);
    expect([403, 404]).toContain(r.status);
  });

  it('revoking the credential closes the live session (4403 credential_revoked) and blocks new ones', async () => {
    const { c, sessionId, credentialId, ownerStepUp, grantId } = await liveTerminal();
    let r = await api('post', `/ssh/credentials/${credentialId}/revoke`, owner, {}, {});
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    r = await api(
      'post',
      `/ssh/credentials/${credentialId}/revoke`,
      owner,
      {},
      { 'X-Step-Up': ownerStepUp },
    );
    expect(r.status).toBe(200);
    expect(r.body.data.status).toBe('revoked');
    expect(r.body.data.jobIds).toHaveLength(1);
    expect((await c.closed).code).toBe(4403);
    expect(c.texts.find((m) => m.type === 'closing')?.reason).toBe('credential_revoked');
    const row = await t.prisma.sshSession.findUniqueOrThrow({ where: { id: sessionId } });
    expect(row.endReason).toBe('credential_revoked');
    await until(() => sshd.liveConnections === 0);
    r = await sessionFor(admin, grantId);
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('SSH_NO_CREDENTIAL');
    const dep = await t.prisma.sshKeyDeployment.findFirstOrThrow({ where: { credentialId } });
    expect(dep.status).toBe('removing');
    await runSyncJobs(dep.serverId);
    expect(
      (await t.prisma.sshKeyDeployment.findFirstOrThrow({ where: { credentialId } })).status,
    ).toBe('removed');
  });

  it('rotate: new ed25519 key deployed, old key rotated + removing in the same sync job', async () => {
    const rd = await ready();
    const r = await api(
      'post',
      `/ssh/credentials/${rd.credentialId}/rotate`,
      owner,
      {},
      {
        'X-Step-Up': rd.ownerStepUp,
      },
    );
    expect(r.status).toBe(201);
    expect(r.body.data.rotatedFromId).toBe(rd.credentialId);
    expect(r.body.data.fingerprintSha256).not.toBe(rd.fingerprint);
    const [job] = await t.jobs.lease(rd.serverId);
    const keys = (job!.params as { keys: Array<{ fingerprint: string }> }).keys.map(
      (k) => k.fingerprint,
    );
    expect(keys).toEqual([r.body.data.fingerprintSha256]);
    const old = await t.prisma.sshCredential.findUniqueOrThrow({ where: { id: rd.credentialId } });
    expect(old.status).toBe('rotated');
  });

  it('expired grant: POST /ssh/sessions 403, WS 4403 SSH_GRANT_INVALID; sweeper closes live session 4408', async () => {
    const rd = await ready();
    const g = await grantFor(admin, rd.serverId);
    const s = (await sessionFor(admin, g.body.data.id)).body.data;
    await t.prisma.sshAccessGrant.update({
      where: { id: g.body.data.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    const c = await authed(s.ticket, s.sessionId);
    expect((await c.closed).code).toBe(4403);
    expect(c.texts.find((m) => m.type === 'error')?.code).toBe('SSH_GRANT_INVALID');
    expect(sshd.authAttempts).toBe(0);
    const r = await sessionFor(admin, g.body.data.id);
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('SSH_GRANT_INVALID');
    // live session + sweeper
    const g2 = await grantFor(admin, rd.serverId);
    const s2 = (await sessionFor(admin, g2.body.data.id)).body.data;
    const c2 = await authed(s2.ticket, s2.sessionId);
    await until(() => c2.texts.some((m) => m.type === 'ready'));
    await t.prisma.sshAccessGrant.update({
      where: { id: g2.body.data.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect(await t.app.get(SshGrantsService).sweep()).toBeGreaterThanOrEqual(1);
    expect((await c2.closed).code).toBe(4408);
    const row = await t.prisma.sshSession.findUniqueOrThrow({ where: { id: s2.sessionId } });
    expect(row.endReason).toBe('grant_expired');
    expect(
      (await t.prisma.sshAccessGrant.findUniqueOrThrow({ where: { id: g2.body.data.id } })).status,
    ).toBe('expired');
    await until(() => sshd.liveConnections === 0);
  });

  it('revoking a grant closes its session (4403 grant_revoked)', async () => {
    const { c, grantId, sessionId } = await liveTerminal();
    const r = await api('post', `/ssh/grants/${grantId}/revoke`, admin);
    expect(r.status).toBe(200);
    expect((await c.closed).code).toBe(4403);
    expect(
      (await t.prisma.sshSession.findUniqueOrThrow({ where: { id: sessionId } })).endReason,
    ).toBe('grant_revoked');
  });

  it('production: approval by another user with step-up, self-approval 403, session needs step-up', async () => {
    const rd = await ready('production');
    const g = await grantFor(admin, rd.serverId);
    expect(g.status).toBe(201);
    expect(g.body.data).toMatchObject({
      status: 'awaiting_approval',
      environment: 'production',
      expiresAt: null,
    });
    let r = await sessionFor(admin, g.body.data.id);
    expect(r.body.error.code).toBe('SSH_GRANT_INVALID');
    const adminStepUp = await stepUpToken(t, admin);
    r = await api(
      'post',
      `/ssh/grants/${g.body.data.id}/approve`,
      admin,
      {},
      { 'X-Step-Up': adminStepUp },
    );
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('SELF_APPROVAL_FORBIDDEN');
    r = await api('post', `/ssh/grants/${g.body.data.id}/approve`, owner, {});
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    r = await api(
      'post',
      `/ssh/grants/${g.body.data.id}/approve`,
      owner,
      { grantHash: 'a'.repeat(64) },
      {
        'X-Step-Up': rd.ownerStepUp,
      },
    );
    expect(r.status).toBe(409);
    r = await api(
      'post',
      `/ssh/grants/${g.body.data.id}/approve`,
      owner,
      { grantHash: g.body.data.grantHash },
      {
        'X-Step-Up': rd.ownerStepUp,
      },
    );
    expect(r.status).toBe(200);
    expect(r.body.data).toMatchObject({ status: 'active', approvedByLabel: 'Super Admin' });
    expect(r.body.data.expiresAt).not.toBeNull();
    r = await api(
      'post',
      `/ssh/grants/${g.body.data.id}/approve`,
      owner,
      {},
      { 'X-Step-Up': rd.ownerStepUp },
    );
    expect(r.status).toBe(409); // single use
    r = await sessionFor(admin, g.body.data.id);
    expect(r.body.error.code).toBe('STEP_UP_REQUIRED');
    r = await sessionFor(admin, g.body.data.id, { 'X-Step-Up': adminStepUp });
    expect(r.status).toBe(201);
    // unused-approval expiry: approved 31 min ago with no session → expired by the sweeper
    const g2 = await grantFor(admin, rd.serverId);
    await api(
      'post',
      `/ssh/grants/${g2.body.data.id}/approve`,
      owner,
      {},
      { 'X-Step-Up': rd.ownerStepUp },
    );
    await t.prisma.sshAccessGrant.update({
      where: { id: g2.body.data.id },
      data: { approvedAt: new Date(Date.now() - 31 * 60_000) },
    });
    await t.app.get(SshGrantsService).sweep();
    expect(
      (await t.prisma.sshAccessGrant.findUniqueOrThrow({ where: { id: g2.body.data.id } })).status,
    ).toBe('expired');
    // reject path
    const g3 = await grantFor(admin, rd.serverId);
    // a global approver sees other users' pending grants (regression: empty relation filter inside OR)
    const pending = await api('get', '/ssh/grants?status=awaiting_approval', owner);
    expect(pending.body.data.map((x: { id: string }) => x.id)).toContain(g3.body.data.id);
    r = await api('post', `/ssh/grants/${g3.body.data.id}/reject`, owner);
    expect(r.body.data.status).toBe('rejected');
    const list = await api('get', '/ssh/grants?status=awaiting_approval', owner);
    expect(list.body.data).toEqual([]);
    const audit = (
      await t.prisma.auditEvent.findMany({ where: { action: { startsWith: 'ssh.grant.' } } })
    ).map((a) => `${a.action}:${a.result}`);
    expect(audit).toEqual(
      expect.arrayContaining([
        'ssh.grant.request:success',
        'ssh.grant.approve:denied',
        'ssh.grant.approve:success',
        'ssh.grant.reject:success',
        'ssh.grant.expire:success',
      ]),
    );
  });

  it('host key mismatch: 4409 SSH_HOST_KEY_MISMATCH, no authentication attempted, key recorded pending', async () => {
    const rd = await ready();
    const g = await grantFor(admin, rd.serverId);
    const s = (await sessionFor(admin, g.body.data.id)).body.data;
    // "rekey": same address, new host key
    const port = sshd.port;
    const authorized = new Set(sshd.authorized);
    await stopSshd(sshd);
    sshd = await startSshd(port);
    sshd.authorized = authorized;
    try {
      const c = await authed(s.ticket, s.sessionId);
      expect((await c.closed).code).toBe(4409);
      expect(c.texts.find((m) => m.type === 'error')?.code).toBe('SSH_HOST_KEY_MISMATCH');
      expect(sshd.authAttempts).toBe(0);
      const keys = await t.prisma.sshHostKey.findMany({ where: { serverId: rd.serverId } });
      expect(keys.map((k) => `${k.status}:${k.seenVia}`).sort()).toEqual([
        'pending:connect',
        'trusted:scan',
      ]);
      expect(keys.find((k) => k.status === 'pending')?.agentMatch).toBe(false);
      const row = await t.prisma.sshSession.findUniqueOrThrow({ where: { id: s.sessionId } });
      expect(row).toMatchObject({ status: 'failed', endReason: 'host_key_mismatch' });
      expect(await t.prisma.auditEvent.count({ where: { action: 'ssh.host_key.mismatch' } })).toBe(
        1,
      );
      await until(() => sshd.liveConnections === 0);
      // trusting the new key (step-up) supersedes the old one and connects again
      const pending = keys.find((k) => k.status === 'pending')!;
      const r = await api(
        'post',
        `/ssh/host-keys/${pending.id}/trust`,
        owner,
        {},
        { 'X-Step-Up': rd.ownerStepUp },
      );
      expect(r.body.data.find((k: { id: string }) => k.id === rd.hostKeyId).status).toBe(
        'superseded',
      );
      const s2 = (await sessionFor(admin, g.body.data.id)).body.data;
      const c2 = await authed(s2.ticket, s2.sessionId);
      await until(() => c2.texts.some((m) => m.type === 'ready'));
      c2.ws.close();
      await c2.closed;
    } finally {
      await until(() => sshd.liveConnections === 0);
    }
  });

  it('untrusted endpoint: session refused (SSH_HOST_KEY_UNTRUSTED); rejected key cannot connect', async () => {
    const rd = await ready();
    const g = await grantFor(admin, rd.serverId);
    const r0 = await api('post', `/ssh/host-keys/${rd.hostKeyId}/reject`, owner);
    expect(r0.status).toBe(200);
    const r = await sessionFor(admin, g.body.data.id);
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('SSH_HOST_KEY_UNTRUSTED');
  });

  it('idle timeout closes the session; the fake sshd sees channel and connection closed', async () => {
    const { c, sessionId } = await liveTerminal();
    expect(sshd.liveChannels).toBe(1);
    t.config.SSH_IDLE_TIMEOUT_SEC = 1; // applies to the next session
    const s = await sessionFor(
      admin,
      (await t.prisma.sshSession.findUniqueOrThrow({ where: { id: sessionId } })).grantId,
    );
    c.ws.send(JSON.stringify({ type: 'close' }));
    await c.closed;
    await until(() => sshd.liveChannels === 0 && sshd.liveConnections === 0);
    const c2 = await authed(s.body.data.ticket, s.body.data.sessionId);
    await until(() => c2.texts.some((m) => m.type === 'ready'));
    await until(() => sshd.liveChannels === 1);
    const closed = await c2.closed;
    expect(closed.code).toBe(4408);
    expect(c2.texts.find((m) => m.type === 'closing')?.reason).toBe('idle_timeout');
    await until(() => sshd.liveChannels === 0 && sshd.liveConnections === 0);
    await until(
      async () =>
        (await t.prisma.sshSession.findUniqueOrThrow({ where: { id: s.body.data.sessionId } }))
          .status === 'closed',
    );
    const row = await t.prisma.sshSession.findUniqueOrThrow({
      where: { id: s.body.data.sessionId },
    });
    expect(row).toMatchObject({ status: 'closed', endReason: 'idle_timeout' });
    expect(row.closedAt).not.toBeNull();
  });

  it('limits: per-user limit → 429 SSH_SESSION_LIMIT', async () => {
    const rd = await ready();
    t.config.SSH_MAX_SESSIONS_PER_USER = 1;
    const g = await grantFor(admin, rd.serverId);
    expect((await sessionFor(admin, g.body.data.id)).status).toBe(201);
    const r = await sessionFor(admin, g.body.data.id);
    expect(r.status).toBe(429);
    expect(r.body.error.code).toBe('SSH_SESSION_LIMIT');
  });

  it('terminate by credentials.manage closes the session (terminated)', async () => {
    const { c, sessionId } = await liveTerminal();
    const r = await api('post', `/ssh/sessions/${sessionId}/terminate`, owner);
    expect(r.status).toBe(200);
    expect(r.body.data).toMatchObject({ status: 'closed', endReason: 'terminated' });
    expect((await c.closed).code).toBe(4403);
    await until(() => sshd.liveConnections === 0);
  });

  it('center restart closes stale rows; center shutdown closes live sessions (center_shutdown)', async () => {
    const { c, sessionId } = await liveTerminal();
    // a second Center instance: startup sweep closes rows it cannot own (center_restart)
    const t2 = await bootApp({ PPANEL_SSH_LAB_ENDPOINTS: `127.0.0.1:${sshd.port}` });
    try {
      expect(
        (await t.prisma.sshSession.findUniqueOrThrow({ where: { id: sessionId } })).endReason,
      ).toBe('center_restart');
    } finally {
      await t2.close();
    }
    c.ws.close();
    await c.closed;
    // shutdown of a Center with a live session
    const t3 = await bootApp({ PPANEL_SSH_LAB_ENDPOINTS: `127.0.0.1:${sshd.port}` });
    await t3.app.listen(0, '127.0.0.1');
    const port3 = (t3.app.getHttpServer().address() as AddressInfo).port;
    const g = await grantFor(admin, (await t.prisma.server.findFirstOrThrow()).id);
    const s = (await sessionFor(admin, g.body.data.id)).body.data;
    const ws = new WebSocket(`ws://127.0.0.1:${port3}/api/v1/ssh/stream`, {
      headers: { Origin: ORIGIN },
    });
    const texts: Array<Record<string, any>> = [];
    ws.on('message', (d, bin) => !bin && texts.push(JSON.parse(String(d))));
    const closed = new Promise<number>((r) => ws.on('close', (code) => r(code)));
    await new Promise((r) => ws.on('open', r));
    ws.send(JSON.stringify({ type: 'auth', ticket: s.ticket, sessionId: s.sessionId }));
    await until(() => texts.some((m) => m.type === 'ready'));
    await t3.close();
    expect(await closed).toBe(1001);
    expect(
      (await t.prisma.sshSession.findUniqueOrThrow({ where: { id: s.sessionId } })).endReason,
    ).toBe('center_shutdown');
    await until(() => sshd.liveConnections === 0);
  });
});

describe('P10 leakage', () => {
  it('no API response in this suite contained private key material', () => {
    expect(bodies.length).toBeGreaterThan(50);
    const hits = bodies.filter((b) => SECRET_MARKERS.some((m) => b.includes(m)));
    expect(hits).toEqual([]);
  });
});
