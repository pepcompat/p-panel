/**
 * Mock routes for docs/P10_SSH_CONTRACT.md: SSH credentials (generate / import / deploy / rotate /
 * revoke), endpoints, host keys (scan / trust / reject, never TOFU), access grants (production needs a
 * second person with step-up; self-approval refused), sessions with single-use tickets. The fake gateway
 * the terminal talks to lives in ./mock-ssh-socket.ts and uses the `mockSsh*` helpers exported here.
 *
 * Private keys sent to the import route are parsed for their header only and discarded: they are never
 * stored (not even in this mock's sessionStorage state).
 *
 * Fixtures (users: superadmin has MFA + every permission; admin = ops_admin on production + uat, no MFA):
 * - key `ops-ed25519` (active) installed for `ops` on app-prod-01/02, app-uat-01, dev-01, dev-sandbox-02;
 *   `ops-ed25519-2025` was rotated into it; `legacy-deploy-rsa` (imported) failed on web-legacy-02.
 * - host keys: trusted on app-prod-01/02, app-uat-01, dev-01. dev-sandbox-02 now presents a DIFFERENT key
 *   than the trusted one (seen on connect, agent facts disagree) → connections close 4409.
 *   web-legacy-02 has only a scanned, untrusted key → POST /ssh/sessions 422 SSH_HOST_KEY_UNTRUSTED.
 * - grants: superadmin active on dev-01 and dev-sandbox-02; admin awaiting approval on app-prod-01
 *   (superadmin may approve); superadmin awaiting approval on app-prod-02 (self-approval blocked).
 * Hooks: deploying to ssh user `nobody` fails (SSH_USER_INVALID); typing `__idle` in a mock terminal
 * ends the session with idle_timeout (4408).
 */
import type { Environment, Server } from '@ppanel/shared-contracts';
import {
  PRIVATE_KEY_MAX_BYTES,
  REASON_MAX,
  REASON_MIN,
  SSH_USER_RE,
  type CredentialDeployment,
  type EndReason,
  type SessionTicket,
  type SshCredential,
  type SshEndpoint,
  type SshGrant,
  type SshHostKey,
  type SshPath,
  type SshSession,
} from '@/lib/api/p10-types';
import type { P3Ctx } from './p3-routes';

const KEY = 'ppanel.mock.p10';
const DEPLOY_MS = 1200;
const TICKET_TTL_MS = 30_000;
const IDLE_TIMEOUT_SEC = 900;
const MAX_SESSION_SEC = 28_800;
const MAX_PER_USER = 3;

type CredRec = Omit<SshCredential, 'deployments' | 'createdByLabel'> & { createdBy: string };
type DeployRec = {
  id: string;
  credentialId: string;
  serverId: string;
  sshUser: string;
  status: CredentialDeployment['status'];
  lastError: string | null;
  until: number | null;
};
type GrantRec = Omit<SshGrant, 'userLabel' | 'serverName' | 'environment' | 'approvedByLabel'>;
type SessionRec = Omit<SshSession, 'userLabel' | 'serverName'>;
interface P10State {
  credentials: CredRec[];
  deployments: DeployRec[];
  endpoints: Record<string, SshEndpoint[]>;
  hostKeys: SshHostKey[];
  /** what each endpoint's sshd presents right now: `${serverId}:${path}` → fingerprint */
  presented: Record<string, string>;
  grants: GrantRec[];
  sessions: SessionRec[];
}

let st: P10State | null = null;
let ctx: P3Ctx;
/** single-use tickets: memory only, never persisted */
const tickets = new Map<string, { ticket: string; exp: number; used: boolean }>();
/** live mock sockets by session id, so revoke / terminate / expiry can close them */
const live = new Map<string, (code: number, reason: EndReason) => void>();

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}
function save() {
  try {
    storage()?.setItem(KEY, JSON.stringify(st));
  } catch {
    /* memory only */
  }
}
export function resetP10State() {
  st = null;
  tickets.clear();
  live.clear();
  storage()?.removeItem(KEY);
}

const iso = (ms: number) => new Date(ms).toISOString();
const ago = (sec: number) => iso(Date.now() - sec * 1000);
const later = (sec: number) => iso(Date.now() + sec * 1000);
const byName = (n: string) => ctx.servers().find((x) => x.name === n);
const srvOf = (id: string) => ctx.servers().find((x) => x.id === id);
const userByName = (n: string) => ctx.users().find((x) => x.displayName === n);
const userLabel = (id: string | null) => ctx.users().find((x) => x.id === id)?.displayName ?? null;
const err = (status: number, code: string, message: string, details?: unknown) =>
  new ctx.HttpError(status, code, message, details);
const invalid = (details: Array<{ field: string; message: string }>) =>
  err(422, 'VALIDATION_FAILED', 'Validation failed', details);
const need = (u: { id: string }, perm: Parameters<P3Ctx['requirePerm']>[1], srv?: Server) =>
  ctx.requirePerm(u as never, perm, srv);
const can = (u: { id: string }, perm: Parameters<P3Ctx['hasPermFor']>[1], srv?: Server) =>
  ctx.hasPermFor(u as never, perm, srv);

/** Deterministic base64-ish fingerprint body. */
function fp(seed: string): string {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let x = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    x ^= seed.charCodeAt(i);
    x = Math.imul(x, 16777619) >>> 0;
  }
  let out = '';
  for (let i = 0; i < 43; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out += abc[x % 64];
  }
  return `SHA256:${out}`;
}
function randToken(n = 43) {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (v) => abc[v % 64]).join('');
}
const pubKey = (algo: string, seed: string, comment: string) =>
  `${algo === 'rsa-sha2-512' ? 'ssh-rsa' : algo} AAAA${fp(seed).slice(7).replace(/[+/]/g, 'x')}${fp(`${seed}2`).slice(7, 30).replace(/[+/]/g, 'y')} ${comment}`;

const epId = (serverId: string, path: SshPath) => `${serverId}:${path}`;

function seed() {
  const sa = userByName('Super Admin')!;
  const adm = userByName('Ops Admin')!;
  const S = (n: string) => byName(n)!;
  const cred = (
    id: string,
    name: string,
    kind: CredRec['kind'],
    algorithm: CredRec['algorithm'],
    status: CredRec['status'],
    ageSec: number,
    extra: Partial<CredRec> = {},
  ): CredRec => ({
    id,
    name,
    kind,
    algorithm,
    publicKey: pubKey(algorithm, id, `${name}@ppanel`),
    fingerprintSha256: fp(id),
    status,
    rotatedFromId: null,
    createdAt: ago(ageSec),
    createdBy: sa.id,
    revokedAt: null,
    ...extra,
  });
  const credentials = [
    cred('cred-ops-2026', 'ops-ed25519', 'generated', 'ssh-ed25519', 'active', 86400 * 12, {
      rotatedFromId: 'cred-ops-2025',
    }),
    cred('cred-ops-2025', 'ops-ed25519-2025', 'generated', 'ssh-ed25519', 'rotated', 86400 * 200),
    cred('cred-legacy', 'legacy-deploy-rsa', 'imported', 'rsa-sha2-512', 'active', 86400 * 40),
  ];
  const dep = (
    credentialId: string,
    server: string,
    sshUser: string,
    status: DeployRec['status'],
    lastError: string | null = null,
  ): DeployRec => ({
    id: `dep-${credentialId}-${server}-${sshUser}`,
    credentialId,
    serverId: S(server).id,
    sshUser,
    status,
    lastError,
    until: null,
  });
  const deployments = [
    ...['app-prod-01', 'app-prod-02', 'app-uat-01', 'dev-01', 'dev-sandbox-02'].map((n) =>
      dep('cred-ops-2026', n, 'ops', 'installed'),
    ),
    dep('cred-ops-2026', 'app-prod-01', 'deploy', 'installed'),
    dep(
      'cred-legacy',
      'web-legacy-02',
      'deploy',
      'failed',
      'SSH_USER_INVALID: user deploy does not exist on this host',
    ),
  ];
  const ep = (host: string, path: SshPath, users: string[]): SshEndpoint => ({
    path,
    host,
    port: 22,
    allowedUsers: users,
  });
  const endpoints: Record<string, SshEndpoint[]> = {
    [S('app-prod-01').id]: [
      ep('10.104.0.11', 'private', ['ops', 'deploy']),
      ep('159.89.201.14', 'public', ['ops']),
    ],
    [S('app-prod-02').id]: [ep('10.104.0.12', 'private', ['ops'])],
    [S('web-legacy-02').id]: [ep('128.199.77.90', 'public', ['deploy'])],
    [S('db-prod-01').id]: [ep('10.104.0.30', 'private', ['ops'])],
    [S('app-uat-01').id]: [ep('10.110.0.5', 'private', ['ops'])],
    [S('dev-01').id]: [ep('178.128.40.2', 'public', ['ops'])],
    [S('dev-sandbox-02').id]: [ep('178.128.40.7', 'public', ['ops'])],
  };
  const hk = (
    server: string,
    path: SshPath,
    status: SshHostKey['status'],
    seenVia: SshHostKey['seenVia'],
    agentMatch: boolean | null,
    seedKey: string,
    firstSeenSec: number,
  ): SshHostKey => {
    const srv = S(server);
    const trusted = status === 'trusted' || status === 'superseded';
    return {
      id: `hk-${server}-${path}-${seedKey}`,
      serverId: srv.id,
      endpointId: epId(srv.id, path),
      endpointPath: path,
      algorithm: 'ssh-ed25519',
      fingerprintSha256: fp(`host-${server}-${seedKey}`),
      publicKey: pubKey('ssh-ed25519', `host-${server}-${seedKey}`, `root@${server}`),
      status,
      seenVia,
      agentMatch,
      firstSeenAt: ago(firstSeenSec),
      lastSeenAt: ago(seenVia === 'connect' ? 600 : 3600),
      trustedBy: trusted ? sa.id : null,
      trustedAt: trusted ? ago(firstSeenSec - 60) : null,
    };
  };
  const hostKeys = [
    hk('app-prod-01', 'private', 'trusted', 'scan', true, 'a', 86400 * 30),
    hk('app-prod-01', 'public', 'trusted', 'scan', true, 'a', 86400 * 30),
    hk('app-prod-02', 'private', 'trusted', 'scan', true, 'a', 86400 * 30),
    hk('app-uat-01', 'private', 'trusted', 'scan', true, 'a', 86400 * 20),
    hk('dev-01', 'public', 'trusted', 'scan', true, 'a', 86400 * 10),
    hk('dev-sandbox-02', 'public', 'trusted', 'scan', true, 'a', 86400 * 10),
    hk('dev-sandbox-02', 'public', 'pending', 'connect', false, 'b', 900),
    hk('web-legacy-02', 'public', 'pending', 'scan', null, 'a', 7200),
  ];
  const presented: Record<string, string> = {};
  for (const k of hostKeys)
    if (k.status === 'trusted') presented[k.endpointId] = k.fingerprintSha256;
  presented[epId(S('dev-sandbox-02').id, 'public')] = fp('host-dev-sandbox-02-b');
  presented[epId(S('web-legacy-02').id, 'public')] = fp('host-web-legacy-02-a');

  const grant = (
    id: string,
    userId: string,
    server: string,
    sshUser: string,
    endpointPath: SshPath,
    status: GrantRec['status'],
    reason: string,
    over: Partial<GrantRec> = {},
  ): GrantRec => {
    const srv = S(server);
    const durationMin = 60;
    return {
      id,
      userId,
      serverId: srv.id,
      sshUser,
      endpointPath,
      reason,
      durationMin,
      status,
      grantHash: grantHash(userId, srv.id, sshUser, endpointPath, durationMin),
      requestedAt: ago(600),
      approvedBy: null,
      approvedAt: null,
      startsAt: status === 'active' ? ago(600) : null,
      expiresAt: status === 'active' ? later(50 * 60) : null,
      revokedAt: null,
      ...over,
    };
  };
  const grants = [
    grant(
      'grant-dev01',
      sa.id,
      'dev-01',
      'ops',
      'public',
      'active',
      'Check disk usage after deploy',
    ),
    grant(
      'grant-sandbox',
      sa.id,
      'dev-sandbox-02',
      'ops',
      'public',
      'active',
      'Debug sandbox container networking',
    ),
    grant(
      'grant-admin-prod',
      adm.id,
      'app-prod-01',
      'ops',
      'private',
      'awaiting_approval',
      'INC-482: inspect nginx worker memory',
    ),
    grant(
      'grant-self-prod',
      sa.id,
      'app-prod-02',
      'ops',
      'private',
      'awaiting_approval',
      'Rotate local log files',
    ),
    grant('grant-uat-old', sa.id, 'app-uat-01', 'ops', 'private', 'expired', 'UAT smoke check', {
      requestedAt: ago(86400),
      startsAt: ago(86400),
      expiresAt: ago(86400 - 3600),
    }),
  ];
  const sess = (
    id: string,
    g: GrantRec,
    status: SessionRec['status'],
    endReason: EndReason | null,
    startSec: number,
    durSec: number,
    bytes: [number, number],
    exitCode: number | null = null,
  ): SessionRec => {
    const e = endpoints[g.serverId]!.find((x) => x.path === g.endpointPath)!;
    const key = hostKeys.find((k) => k.endpointId === epId(g.serverId, g.endpointPath));
    return {
      id,
      grantId: g.id,
      userId: g.userId,
      serverId: g.serverId,
      sshUser: g.sshUser,
      endpointPath: g.endpointPath,
      endpointHost: e.host,
      endpointPort: e.port,
      credentialFingerprint: fp('cred-ops-2026'),
      hostKeyFingerprint:
        endReason === 'host_key_mismatch' ? null : (key?.fingerprintSha256 ?? null),
      status,
      endReason,
      exitCode,
      clientIp: '203.0.113.24',
      userAgent: 'Mozilla/5.0 (mock)',
      bytesIn: bytes[0],
      bytesOut: bytes[1],
      createdAt: ago(startSec),
      openedAt: status === 'failed' ? null : ago(startSec - 1),
      closedAt: ago(startSec - durSec),
    };
  };
  const sessions = [
    sess('sess-1', grants[0]!, 'closed', 'idle_timeout', 7200, 1500, [812, 48_331]),
    sess('sess-2', grants[1]!, 'failed', 'host_key_mismatch', 900, 1, [0, 0]),
    sess('sess-3', grants[4]!, 'closed', 'client_closed', 86_000, 420, [2_140, 96_002], 0),
  ];
  st = { credentials, deployments, endpoints, hostKeys, presented, grants, sessions };
}

function grantHash(u: string, s: string, user: string, path: string, d: number) {
  return fp(`${u}|${s}|${user}|${path}|${d}`).slice(7, 39);
}

function s(): P10State {
  if (!st) {
    const raw = storage()?.getItem(KEY);
    if (raw)
      try {
        st = JSON.parse(raw) as P10State;
      } catch {
        st = null;
      }
    if (!st) {
      seed();
      save();
    }
  }
  tick();
  return st!;
}

/** Async job completion + grant expiry sweeper. */
function tick() {
  if (!st) return;
  const now = Date.now();
  let dirty = false;
  for (const d of st.deployments) {
    if (d.until && d.until <= now) {
      d.until = null;
      if (d.status === 'pending') {
        if (d.sshUser === 'nobody') {
          d.status = 'failed';
          d.lastError = 'SSH_USER_INVALID: uid < 1000 and not in ssh.allowedUsers';
        } else d.status = 'installed';
      } else if (d.status === 'removing') d.status = 'removed';
      dirty = true;
    }
  }
  for (const g of st.grants) {
    if (g.status === 'active' && g.expiresAt && Date.parse(g.expiresAt) <= now) {
      g.status = 'expired';
      dirty = true;
      killByGrant(g.id, 4408, 'grant_expired');
    }
  }
  if (dirty) save();
}

function killByGrant(grantId: string, code: number, reason: EndReason) {
  for (const x of st?.sessions ?? [])
    if (x.grantId === grantId && (x.status === 'open' || x.status === 'pending'))
      live.get(x.id)?.(code, reason);
}

// ---------------------------------------------------------------- views

function credView(c: CredRec): SshCredential {
  const { createdBy, ...rest } = c;
  return {
    ...rest,
    createdByLabel: userLabel(createdBy),
    deployments: s()
      .deployments.filter((d) => d.credentialId === c.id && d.status !== 'removed')
      .map((d) => ({
        id: d.id,
        serverId: d.serverId,
        serverName: srvOf(d.serverId)?.name ?? d.serverId,
        sshUser: d.sshUser,
        status: d.status,
        lastError: d.lastError,
      })),
  };
}
function grantView(g: GrantRec): SshGrant {
  const srv = srvOf(g.serverId);
  return {
    ...g,
    userLabel: userLabel(g.userId),
    serverName: srv?.name ?? g.serverId,
    environment: (srv?.environment ?? 'development') as Environment,
    approvedByLabel: userLabel(g.approvedBy),
  };
}
function sessionView(x: SessionRec): SshSession {
  return { ...x, userLabel: userLabel(x.userId), serverName: srvOf(x.serverId)?.name ?? null };
}
function hostKeyView(k: SshHostKey): SshHostKey {
  return { ...k, trustedByLabel: userLabel(k.trustedBy) };
}

function findServer(id: string) {
  const srv = srvOf(id);
  if (!srv) throw err(404, 'NOT_FOUND', 'Server not found');
  return srv;
}
function findCred(id: string) {
  const c = s().credentials.find((x) => x.id === id);
  if (!c) throw err(404, 'NOT_FOUND', 'Credential not found');
  return c;
}
function findGrant(id: string) {
  const g = s().grants.find((x) => x.id === id);
  if (!g) throw err(404, 'NOT_FOUND', 'Grant not found');
  return g;
}
const installedFor = (serverId: string, sshUser: string) =>
  s().deployments.some(
    (d) =>
      d.serverId === serverId &&
      d.sshUser === sshUser &&
      d.status === 'installed' &&
      s().credentials.find((c) => c.id === d.credentialId)?.status === 'active',
  );
const trustedKey = (serverId: string, path: SshPath) =>
  s().hostKeys.find((k) => k.endpointId === epId(serverId, path) && k.status === 'trusted');
const ipScope = (srv: Server, path: SshPath) =>
  srv.addresses.filter((a) => a.scope === path).map((a) => a.address);

function requireStepUp(
  req: Request,
  u: { id: string; displayName: string },
  srv: Server | null,
  action: string,
  requestId: string,
) {
  if (!ctx.checkStepUp(req, u)) {
    if (srv) ctx.audit(u, action, srv, 'denied', requestId);
    throw err(403, 'STEP_UP_REQUIRED', 'This action requires a fresh 2FA confirmation');
  }
}

function resync(
  serverId: string,
  sshUser: string,
  credentialId: string,
  status: DeployRec['status'],
) {
  const all = s().deployments;
  let d = all.find(
    (x) => x.serverId === serverId && x.sshUser === sshUser && x.credentialId === credentialId,
  );
  if (!d) {
    d = {
      id: `dep-${credentialId}-${ctx.rid().slice(0, 8)}`,
      credentialId,
      serverId,
      sshUser,
      status,
      lastError: null,
      until: null,
    };
    all.push(d);
  }
  d.status = status;
  d.lastError = null;
  d.until = Date.now() + DEPLOY_MS;
  return d;
}

// ---------------------------------------------------------------- gateway helpers (mock socket)

export type MockAuthResult =
  | { ok: false; code: number; reason?: EndReason }
  | {
      ok: true;
      serverName: string;
      ready: {
        sessionId: string;
        hostKeyFingerprint: string;
        endpoint: { path: SshPath; host: string; port: number };
        sshUser: string;
      };
    };

/** Consume the single-use ticket and connect (strict host key check, active grant + credential). */
export function mockSshAuth(sessionId: string, ticket: string): MockAuthResult {
  const t = tickets.get(sessionId);
  const sess = st?.sessions.find((x) => x.id === sessionId);
  if (!t || !sess || t.used || t.exp < Date.now() || t.ticket !== ticket) {
    if (t) t.used = true;
    return { ok: false, code: 4401 };
  }
  t.used = true;
  tickets.delete(sessionId);
  const end = (status: SessionRec['status'], reason: EndReason, code: number): MockAuthResult => {
    sess.status = status;
    sess.endReason = reason;
    sess.closedAt = iso(Date.now());
    save();
    return { ok: false, code, reason };
  };
  const g = s().grants.find((x) => x.id === sess.grantId);
  if (!g || g.status !== 'active') return end('failed', 'grant_expired', 4403);
  if (!installedFor(sess.serverId, sess.sshUser)) return end('failed', 'credential_revoked', 4403);
  const eid = epId(sess.serverId, sess.endpointPath);
  const trusted = trustedKey(sess.serverId, sess.endpointPath);
  const presented = s().presented[eid];
  if (!trusted || trusted.fingerprintSha256 !== presented) {
    // store the observed key as pending (seenVia connect) and refuse — never TOFU
    if (
      presented &&
      !s().hostKeys.some((k) => k.endpointId === eid && k.fingerprintSha256 === presented)
    ) {
      s().hostKeys.push({
        ...(trusted ?? s().hostKeys.find((k) => k.endpointId === eid)!),
        id: `hk-${ctx.rid().slice(0, 8)}`,
        fingerprintSha256: presented,
        status: 'pending',
        seenVia: 'connect',
        agentMatch: false,
        firstSeenAt: iso(Date.now()),
        lastSeenAt: iso(Date.now()),
        trustedBy: null,
        trustedAt: null,
      });
    }
    const srv = srvOf(sess.serverId);
    if (srv)
      ctx.audit(
        { id: sess.userId, displayName: '' },
        'ssh.host_key.mismatch',
        srv,
        'denied',
        ctx.rid(),
      );
    return end('failed', 'host_key_mismatch', 4409);
  }
  sess.status = 'open';
  sess.openedAt = iso(Date.now());
  sess.hostKeyFingerprint = trusted.fingerprintSha256;
  save();
  return {
    ok: true,
    serverName: srvOf(sess.serverId)?.name ?? sess.serverId,
    ready: {
      sessionId,
      hostKeyFingerprint: trusted.fingerprintSha256,
      endpoint: { path: sess.endpointPath, host: sess.endpointHost, port: sess.endpointPort },
      sshUser: sess.sshUser,
    },
  };
}

export function mockSshRegister(
  sessionId: string,
  kill: (code: number, reason: EndReason) => void,
) {
  live.set(sessionId, kill);
}

export function mockSshClosed(
  sessionId: string,
  reason: EndReason,
  exitCode: number | null,
  bytesIn: number,
  bytesOut: number,
) {
  live.delete(sessionId);
  tickets.delete(sessionId);
  const x = st?.sessions.find((y) => y.id === sessionId);
  if (!x || x.status === 'closed' || x.status === 'failed') return;
  x.status = 'closed';
  x.endReason = reason;
  x.exitCode = exitCode;
  x.bytesIn = bytesIn;
  x.bytesOut = bytesOut;
  x.closedAt = iso(Date.now());
  save();
}

// ---------------------------------------------------------------- routes

export function registerP10Routes(c: P3Ctx) {
  ctx = c;
  const { on, ok } = c;

  // ---------- credentials ----------
  on('GET', '/ssh/credentials', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'fleet.read');
    const items = s()
      .credentials.map(credView)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/ssh/credentials', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'credentials.manage');
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const details: Array<{ field: string; message: string }> = [];
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$/.test(name))
      details.push({ field: 'name', message: 'Letters, digits, dot, dash, underscore; max 63' });
    else if (s().credentials.some((x) => x.name === name))
      details.push({ field: 'name', message: 'A credential with this name already exists' });
    if (body.mode !== 'generate' && body.mode !== 'import')
      details.push({ field: 'mode', message: 'generate or import' });
    if (details.length) throw invalid(details);
    requireStepUp(req, u, null, 'ssh.credential.create', requestId);
    let algorithm: CredRec['algorithm'] = 'ssh-ed25519';
    if (body.mode === 'import') {
      // parse the header only; the key itself is discarded right here
      let pk = typeof body.privateKey === 'string' ? body.privateKey : '';
      const hasPass = typeof body.passphrase === 'string' && body.passphrase.length > 0;
      body.privateKey = undefined;
      body.passphrase = undefined;
      if (new TextEncoder().encode(pk).length > PRIVATE_KEY_MAX_BYTES)
        throw err(413, 'PAYLOAD_TOO_LARGE', 'The private key is larger than 16 KiB');
      const m = /-----BEGIN (OPENSSH|RSA|EC) PRIVATE KEY-----/.exec(pk);
      const encrypted = /ENCRYPTED|aes256-ctr|bcrypt/.test(pk);
      const short = pk.length < 1600;
      pk = '';
      if (!m)
        throw err(422, 'SSH_KEY_UNSUPPORTED', 'Not a supported private key (OpenSSH, PEM RSA/EC)');
      if (encrypted && !hasPass)
        throw err(422, 'SSH_KEY_ENCRYPTED', 'The key is encrypted; enter its passphrase');
      if (m[1] === 'RSA' && short)
        throw err(422, 'SSH_KEY_UNSUPPORTED', 'RSA keys must be at least 3072 bits');
      algorithm =
        m[1] === 'RSA' ? 'rsa-sha2-512' : m[1] === 'EC' ? 'ecdsa-sha2-nistp256' : 'ssh-ed25519';
    }
    const id = `cred-${ctx.rid().slice(0, 8)}`;
    const rec: CredRec = {
      id,
      name,
      kind: body.mode === 'import' ? 'imported' : 'generated',
      algorithm,
      publicKey: pubKey(algorithm, id, `${name}@ppanel`),
      fingerprintSha256: fp(id),
      status: 'active',
      rotatedFromId: null,
      createdAt: iso(Date.now()),
      createdBy: u.id,
      revokedAt: null,
    };
    s().credentials.push(rec);
    save();
    return ok(requestId, credView(rec), 201);
  });
  on('POST', '/ssh/credentials/:id/deploy', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const cred = findCred(params[0]!);
    const srv = findServer(String(body.serverId ?? ''));
    need(u, 'credentials.manage', srv);
    const sshUser = String(body.sshUser ?? '').trim();
    if (!SSH_USER_RE.test(sshUser))
      throw invalid([{ field: 'sshUser', message: 'Lowercase POSIX user name (max 32)' }]);
    if (sshUser === 'root') throw err(422, 'SSH_ROOT_FORBIDDEN', 'root is not allowed');
    if (cred.status !== 'active')
      throw err(409, 'CREDENTIAL_NOT_ACTIVE', 'Only an active credential can be deployed');
    if (srv.status === 'revoked') throw err(409, 'SERVER_REVOKED', 'Server is revoked');
    resync(srv.id, sshUser, cred.id, 'pending');
    ctx.audit(u, 'ssh.key.deploy', srv, 'success', requestId);
    save();
    return ok(requestId, { jobId: ctx.rid() }, 202);
  });
  on('DELETE', '/ssh/credentials/:id/deployments/:dep', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    findCred(params[0]!);
    const d = s().deployments.find((x) => x.id === params[1] && x.credentialId === params[0]);
    if (!d) throw err(404, 'NOT_FOUND', 'Deployment not found');
    const srv = findServer(d.serverId);
    need(u, 'credentials.manage', srv);
    resync(d.serverId, d.sshUser, d.credentialId, 'removing');
    ctx.audit(u, 'ssh.key.remove', srv, 'success', requestId);
    save();
    return ok(requestId, { jobId: ctx.rid() }, 202);
  });
  on('POST', '/ssh/credentials/:id/rotate', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'credentials.manage');
    const old = findCred(params[0]!);
    if (old.status !== 'active')
      throw err(409, 'CREDENTIAL_NOT_ACTIVE', 'Only an active credential can be rotated');
    requireStepUp(req, u, null, 'ssh.credential.rotate', requestId);
    const id = `cred-${ctx.rid().slice(0, 8)}`;
    const base = old.name.replace(/-r\d+$/, '');
    const n = s().credentials.filter((x) => x.name.startsWith(base)).length + 1;
    const rec: CredRec = {
      ...old,
      id,
      name: `${base}-r${n}`,
      kind: 'generated',
      algorithm: 'ssh-ed25519',
      publicKey: pubKey('ssh-ed25519', id, `${base}@ppanel`),
      fingerprintSha256: fp(id),
      rotatedFromId: old.id,
      createdAt: iso(Date.now()),
      createdBy: u.id,
    };
    s().credentials.push(rec);
    for (const d of s().deployments.filter(
      (x) => x.credentialId === old.id && x.status === 'installed',
    )) {
      resync(d.serverId, d.sshUser, rec.id, 'pending');
      resync(d.serverId, d.sshUser, old.id, 'removing');
    }
    old.status = 'rotated';
    save();
    return ok(requestId, credView(rec), 201);
  });
  on('POST', '/ssh/credentials/:id/revoke', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'credentials.manage');
    const cred = findCred(params[0]!);
    if (cred.status === 'revoked') throw err(409, 'ALREADY_REVOKED', 'Already revoked');
    requireStepUp(req, u, null, 'ssh.credential.revoke', requestId);
    cred.status = 'revoked';
    cred.revokedAt = iso(Date.now());
    for (const d of s().deployments.filter(
      (x) => x.credentialId === cred.id && x.status !== 'removed',
    )) {
      resync(d.serverId, d.sshUser, cred.id, 'removing');
      for (const x of s().sessions)
        if (
          x.serverId === d.serverId &&
          x.sshUser === d.sshUser &&
          x.credentialFingerprint === cred.fingerprintSha256 &&
          x.status === 'open'
        )
          live.get(x.id)?.(4403, 'credential_revoked');
    }
    save();
    return ok(requestId, credView(cred));
  });

  // ---------- endpoints ----------
  on('GET', '/servers/:id/ssh/endpoints', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const srv = findServer(params[0]!);
    need(u, 'fleet.read', srv);
    return ok(requestId, s().endpoints[srv.id] ?? []);
  });
  on('PUT', '/servers/:id/ssh/endpoints', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const srv = findServer(params[0]!);
    need(u, 'credentials.manage', srv);
    const list = Array.isArray(body) ? (body as unknown[]) : [];
    const out: SshEndpoint[] = [];
    const details: Array<{ field: string; message: string }> = [];
    list.forEach((raw, i) => {
      const e = (raw ?? {}) as Record<string, unknown>;
      const path = e.path === 'private' || e.path === 'public' ? e.path : null;
      const port = Number(e.port ?? 22);
      const users = Array.isArray(e.allowedUsers) ? e.allowedUsers.map(String) : [];
      if (!path) details.push({ field: `${i}.path`, message: 'private or public' });
      if (!Number.isInteger(port) || port < 1 || port > 65535)
        details.push({ field: `${i}.port`, message: '1–65535' });
      if (!users.length || users.some((x) => !SSH_USER_RE.test(x)))
        details.push({ field: `${i}.allowedUsers`, message: 'One or more POSIX user names' });
      if (details.length || !path) return;
      if (users.includes('root'))
        throw err(422, 'SSH_ROOT_FORBIDDEN', 'root cannot be an allowed SSH user', [
          { field: `${i}.allowedUsers`, message: 'root is not allowed' },
        ]);
      const host = String(e.host ?? '');
      if (!ipScope(srv, path).includes(host))
        throw err(
          422,
          'SSH_ENDPOINT_UNVERIFIED',
          `${host} is not a known ${path} address of ${srv.name}`,
          [{ field: `${i}.host`, message: `Not a known ${path} address of this server` }],
        );
      out.push({ path, host, port, allowedUsers: users });
    });
    if (details.length) throw invalid(details);
    if (new Set(out.map((x) => x.path)).size !== out.length)
      throw invalid([{ field: 'path', message: 'One endpoint per path' }]);
    s().endpoints[srv.id] = out;
    ctx.audit(u, 'ssh.endpoint.update', srv, 'success', requestId);
    save();
    return ok(requestId, out);
  });

  // ---------- host keys ----------
  on('GET', '/servers/:id/ssh/host-keys', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const srv = findServer(params[0]!);
    need(u, 'fleet.read', srv);
    return ok(
      requestId,
      s()
        .hostKeys.filter((k) => k.serverId === srv.id)
        .map(hostKeyView),
    );
  });
  on('POST', '/servers/:id/ssh/host-keys/scan', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const srv = findServer(params[0]!);
    need(u, 'credentials.manage', srv);
    const path = body.path === 'public' ? 'public' : body.path === 'private' ? 'private' : null;
    if (!path) throw invalid([{ field: 'path', message: 'private or public' }]);
    const e = (s().endpoints[srv.id] ?? []).find((x) => x.path === path);
    if (!e) throw err(422, 'SSH_ENDPOINT_MISSING', `No ${path} SSH endpoint configured`);
    if (srv.status === 'offline' || srv.status === 'revoked')
      throw err(502, 'SSH_CONNECT_FAILED', `${e.host}:${e.port} did not answer (connect timeout)`);
    const eid = epId(srv.id, path);
    const presented = (s().presented[eid] ??= fp(`host-${srv.name}-scan-${path}`));
    const existing = s().hostKeys.find(
      (k) => k.endpointId === eid && k.fingerprintSha256 === presented,
    );
    if (existing) existing.lastSeenAt = iso(Date.now());
    else
      s().hostKeys.push({
        id: `hk-${ctx.rid().slice(0, 8)}`,
        serverId: srv.id,
        endpointId: eid,
        endpointPath: path,
        algorithm: 'ssh-ed25519',
        fingerprintSha256: presented,
        publicKey: pubKey('ssh-ed25519', presented, `root@${srv.name}`),
        status: 'pending',
        seenVia: 'scan',
        agentMatch: srv.status === 'stale' ? null : true,
        firstSeenAt: iso(Date.now()),
        lastSeenAt: iso(Date.now()),
        trustedBy: null,
        trustedAt: null,
      });
    ctx.audit(u, 'ssh.host_key.scan', srv, 'success', requestId);
    save();
    return ok(
      requestId,
      s()
        .hostKeys.filter((k) => k.serverId === srv.id)
        .map(hostKeyView),
    );
  });
  const findKey = (id: string) => {
    const k = s().hostKeys.find((x) => x.id === id);
    if (!k) throw err(404, 'NOT_FOUND', 'Host key not found');
    return k;
  };
  on('POST', '/ssh/host-keys/:id/trust', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const k = findKey(params[0]!);
    const srv = findServer(k.serverId);
    need(u, 'credentials.manage', srv);
    requireStepUp(req, u, srv, 'ssh.host_key.trust', requestId);
    if (k.status !== 'pending')
      throw err(409, 'HOST_KEY_NOT_PENDING', 'Only a pending key can be trusted');
    for (const o of s().hostKeys)
      if (o.endpointId === k.endpointId && o.algorithm === k.algorithm && o.status === 'trusted')
        o.status = 'superseded';
    k.status = 'trusted';
    k.trustedBy = u.id;
    k.trustedAt = iso(Date.now());
    ctx.audit(u, 'ssh.host_key.trust', srv, 'success', requestId);
    save();
    return ok(requestId, hostKeyView(k));
  });
  on('POST', '/ssh/host-keys/:id/reject', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const k = findKey(params[0]!);
    const srv = findServer(k.serverId);
    need(u, 'credentials.manage', srv);
    if (k.status !== 'pending')
      throw err(409, 'HOST_KEY_NOT_PENDING', 'Only a pending key can be rejected');
    k.status = 'rejected';
    ctx.audit(u, 'ssh.host_key.reject', srv, 'success', requestId);
    save();
    return ok(requestId, hostKeyView(k));
  });

  // ---------- grants ----------
  on('GET', '/ssh/grants', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    const all = can(u, 'credentials.manage') || can(u, 'approvals.decide');
    const status = url.searchParams.get('status');
    const serverId = url.searchParams.get('server_id');
    const userId = url.searchParams.get('user_id');
    const items = s()
      .grants.filter((g) => {
        if (g.userId === u.id) return true;
        if (!all) return false;
        const srv = srvOf(g.serverId);
        return can(u, 'credentials.manage', srv) || can(u, 'approvals.decide', srv);
      })
      .filter((g) => !status || status.split(',').includes(g.status))
      .filter((g) => !serverId || g.serverId === serverId)
      .filter((g) => !userId || g.userId === userId)
      .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt))
      .map(grantView);
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/ssh/grants', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    const srv = findServer(String(body.serverId ?? ''));
    need(u, 'ssh.connect', srv);
    const sshUser = String(body.sshUser ?? '');
    const path =
      body.endpointPath === 'public'
        ? 'public'
        : body.endpointPath === 'private'
          ? 'private'
          : null;
    const duration = Number(body.durationMinutes ?? 60);
    const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    const details: Array<{ field: string; message: string }> = [];
    if (!path) details.push({ field: 'endpointPath', message: 'private or public' });
    if (!SSH_USER_RE.test(sshUser)) details.push({ field: 'sshUser', message: 'Required' });
    if (!Number.isInteger(duration) || duration < 15 || duration > 480)
      details.push({ field: 'durationMinutes', message: '15–480 minutes' });
    if (reason.length < REASON_MIN || reason.length > REASON_MAX)
      details.push({ field: 'reason', message: `${REASON_MIN}–${REASON_MAX} characters` });
    if (details.length || !path) throw invalid(details);
    if (srv.status === 'revoked') throw err(409, 'SERVER_REVOKED', 'Server is revoked');
    const policy = srv.connectionPolicy;
    if (
      (policy === 'private_only' && path !== 'private') ||
      (policy === 'public_only' && path !== 'public')
    )
      throw invalid([
        {
          field: 'endpointPath',
          message: `Connection policy ${policy} does not allow the ${path} path`,
        },
      ]);
    const e = (s().endpoints[srv.id] ?? []).find((x) => x.path === path);
    if (!e)
      throw err(422, 'SSH_ENDPOINT_MISSING', `No ${path} SSH endpoint configured for ${srv.name}`);
    if (!e.allowedUsers.includes(sshUser))
      throw invalid([{ field: 'sshUser', message: `${sshUser} is not allowed on this endpoint` }]);
    if (!installedFor(srv.id, sshUser))
      throw err(
        422,
        'SSH_NO_CREDENTIAL',
        `No active key is installed for ${sshUser} on ${srv.name}. Deploy a credential first.`,
      );
    const prod = srv.environment === 'production';
    const now = Date.now();
    const rec: GrantRec = {
      id: `grant-${ctx.rid().slice(0, 8)}`,
      userId: u.id,
      serverId: srv.id,
      sshUser,
      endpointPath: path,
      reason,
      durationMin: duration,
      status: prod ? 'awaiting_approval' : 'active',
      grantHash: grantHash(u.id, srv.id, sshUser, path, duration),
      requestedAt: iso(now),
      approvedBy: null,
      approvedAt: null,
      startsAt: prod ? null : iso(now),
      expiresAt: prod ? null : iso(now + duration * 60e3),
      revokedAt: null,
    };
    s().grants.push(rec);
    ctx.audit(u, 'ssh.grant.request', srv, 'success', requestId);
    save();
    return ok(requestId, grantView(rec), 201);
  });
  on('POST', '/ssh/grants/:id/approve', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const g = findGrant(params[0]!);
    const srv = findServer(g.serverId);
    need(u, 'approvals.decide', srv);
    if (g.userId === u.id) {
      ctx.audit(u, 'ssh.grant.approve', srv, 'denied', requestId);
      throw err(403, 'SELF_APPROVAL_FORBIDDEN', 'You cannot approve your own access request');
    }
    requireStepUp(req, u, srv, 'ssh.grant.approve', requestId);
    if (g.status !== 'awaiting_approval')
      throw err(409, 'GRANT_NOT_PENDING', 'This request is no longer pending');
    if (body.grantHash !== g.grantHash)
      throw err(409, 'GRANT_HASH_MISMATCH', 'The request changed since you opened it. Reload.');
    const now = Date.now();
    g.status = 'active';
    g.approvedBy = u.id;
    g.approvedAt = iso(now);
    g.startsAt = iso(now);
    g.expiresAt = iso(now + g.durationMin * 60e3);
    ctx.audit(u, 'ssh.grant.approve', srv, 'success', requestId);
    save();
    return ok(requestId, grantView(g));
  });
  on('POST', '/ssh/grants/:id/reject', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const g = findGrant(params[0]!);
    const srv = findServer(g.serverId);
    need(u, 'approvals.decide', srv);
    if (g.status !== 'awaiting_approval')
      throw err(409, 'GRANT_NOT_PENDING', 'This request is no longer pending');
    g.status = 'rejected';
    ctx.audit(u, 'ssh.grant.reject', srv, 'success', requestId);
    save();
    return ok(requestId, grantView(g));
  });
  on('POST', '/ssh/grants/:id/revoke', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const g = findGrant(params[0]!);
    const srv = findServer(g.serverId);
    if (g.userId !== u.id) need(u, 'credentials.manage', srv);
    if (g.status !== 'active' && g.status !== 'awaiting_approval')
      throw err(409, 'GRANT_NOT_ACTIVE', 'Only an active or pending grant can be revoked');
    g.status = 'revoked';
    g.revokedAt = iso(Date.now());
    killByGrant(g.id, 4403, 'grant_revoked');
    ctx.audit(u, 'ssh.grant.revoke', srv, 'success', requestId);
    save();
    return ok(requestId, grantView(g));
  });

  // ---------- sessions ----------
  on('GET', '/ssh/sessions', ({ req, url, requestId }) => {
    const u = c.currentUser(req);
    const all = can(u, 'credentials.manage');
    const status = url.searchParams.get('status');
    const items = s()
      .sessions.filter(
        (x) => x.userId === u.id || (all && can(u, 'credentials.manage', srvOf(x.serverId))),
      )
      .filter((x) => !status || status.split(',').includes(x.status))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(sessionView);
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });
  on('POST', '/ssh/sessions', ({ req, url, body, requestId }) => {
    const u = c.currentUser(req);
    const g = s().grants.find((x) => x.id === body.grantId);
    const srv = g ? srvOf(g.serverId) : undefined;
    if (!g || !srv || g.userId !== u.id || g.status !== 'active')
      throw err(403, 'SSH_GRANT_INVALID', 'The access grant is not active or not yours');
    need(u, 'ssh.connect', srv);
    if (srv.environment === 'production') requireStepUp(req, u, srv, 'ssh.session.open', requestId);
    const mine = s().sessions.filter(
      (x) => x.userId === u.id && (x.status === 'open' || x.status === 'pending'),
    );
    // pending sessions whose ticket was never used do not count after the ticket TTL
    const counted = mine.filter((x) => x.status === 'open' || tickets.has(x.id));
    if (counted.length >= MAX_PER_USER)
      throw err(429, 'SSH_SESSION_LIMIT', `At most ${MAX_PER_USER} open sessions per user`, {
        retryAfterSec: 10,
      });
    const e = (s().endpoints[srv.id] ?? []).find((x) => x.path === g.endpointPath);
    if (!e) throw err(422, 'SSH_ENDPOINT_MISSING', 'The endpoint for this grant no longer exists');
    if (!trustedKey(srv.id, g.endpointPath))
      throw err(
        422,
        'SSH_HOST_KEY_UNTRUSTED',
        `No trusted host key for ${srv.name} (${g.endpointPath}). Scan and trust it first.`,
      );
    const cred = s().credentials.find(
      (cr) =>
        cr.status === 'active' &&
        s().deployments.some(
          (d) =>
            d.credentialId === cr.id &&
            d.serverId === srv.id &&
            d.sshUser === g.sshUser &&
            d.status === 'installed',
        ),
    );
    const id = `sess-${ctx.rid().slice(0, 8)}`;
    const now = Date.now();
    const ticket = randToken();
    tickets.set(id, { ticket, exp: now + TICKET_TTL_MS, used: false });
    s().sessions.push({
      id,
      grantId: g.id,
      userId: u.id,
      serverId: srv.id,
      sshUser: g.sshUser,
      endpointPath: g.endpointPath,
      endpointHost: e.host,
      endpointPort: e.port,
      credentialFingerprint: cred?.fingerprintSha256 ?? '',
      hostKeyFingerprint: null,
      status: 'pending',
      endReason: null,
      exitCode: null,
      clientIp: '203.0.113.24',
      userAgent: req.headers.get('User-Agent') ?? 'browser',
      bytesIn: 0,
      bytesOut: 0,
      createdAt: iso(now),
      openedAt: null,
      closedAt: null,
    });
    save();
    const remaining = g.expiresAt
      ? Math.floor((Date.parse(g.expiresAt) - now) / 1000)
      : MAX_SESSION_SEC;
    const res: SessionTicket = {
      sessionId: id,
      ticket,
      wsUrl: `${url.protocol === 'https:' ? 'wss' : 'ws'}://${url.host}/api/v1/ssh/stream`,
      expiresAt: iso(now + TICKET_TTL_MS),
      idleTimeoutSec: IDLE_TIMEOUT_SEC,
      maxDurationSec: Math.max(0, Math.min(remaining, MAX_SESSION_SEC)),
    };
    return ok(requestId, res, 201);
  });
  on('POST', '/ssh/sessions/:id/terminate', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const x = s().sessions.find((y) => y.id === params[0]);
    if (!x) throw err(404, 'NOT_FOUND', 'Session not found');
    const srv = findServer(x.serverId);
    if (x.userId !== u.id) need(u, 'credentials.manage', srv);
    if (x.status !== 'open' && x.status !== 'pending')
      throw err(409, 'SSH_STATE_INVALID', 'The session is already closed');
    const kill = live.get(x.id);
    if (kill) kill(1000, 'terminated');
    else {
      x.status = 'closed';
      x.endReason = 'terminated';
      x.closedAt = iso(Date.now());
    }
    tickets.delete(x.id);
    ctx.audit(u, 'ssh.session.close', srv, 'success', requestId);
    save();
    return ok(requestId, sessionView(x));
  });
}
