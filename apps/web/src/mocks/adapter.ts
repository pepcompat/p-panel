/**
 * In-process mock adapter for NEXT_PUBLIC_API_MOCK=1. Implements the subset of docs/API_CONTRACTS.md the
 * web uses, returning contract-shaped envelopes with requestIds, error envelopes, If-Match/409,
 * step-up and RBAC (403) so UI states can be exercised without the NestJS API.
 *
 * The "refresh cookie" is simulated with sessionStorage (the real one is HttpOnly and invisible to JS).
 */
import {
  BUILTIN_ROLES,
  CONNECTION_POLICIES,
  ENVIRONMENTS,
  PERMISSIONS,
  ROLE_KEYS,
  createEnrollmentSchema,
  type Permission,
  type RoleBinding,
  type Server,
  type UserPublic,
} from '@ppanel/shared-contracts';
import { seedAudit, seedServers, seedUsers, type MockUser } from './seed';
import type { AuditEvent } from '@/lib/api/types';
import { registerP3Routes, resetP3State } from './p3-routes';
import { registerP4Routes, resetP4State } from './p4-routes';
import { registerP4bRoutes, resetP4bState } from './p4b-routes';
import { registerP5Routes, resetP5State } from './p5-routes';
import { registerP6Routes, resetP6State } from './p6-routes';

const SESSION_KEY = 'ppanel.mock.session';
const NOT_BOOTSTRAPPED_KEY = 'ppanel.mock.notBootstrapped';

interface State {
  users: MockUser[];
  servers: Server[];
  audit: AuditEvent[];
  accessTokens: Map<string, { userId: string; exp: number; amr: string }>;
  mfaTokens: Map<string, string>;
  stepUpTokens: Map<string, { userId: string; exp: number }>;
  pendingTotp: Map<string, string>;
  bootstrapped: boolean;
}

let state: State | null = null;
function db(): State {
  if (!state) {
    const users = seedUsers();
    const servers = seedServers();
    state = {
      users,
      servers,
      audit: seedAudit(users, servers),
      accessTokens: new Map(),
      mfaTokens: new Map(),
      stepUpTokens: new Map(),
      pendingTotp: new Map(),
      bootstrapped: safeSession()?.getItem(NOT_BOOTSTRAPPED_KEY) !== '1',
    };
  }
  return state;
}

/** Test hook: reset all mock state. */
export function resetMockState() {
  state = null;
  resetP3State();
  resetP4State();
  resetP4bState();
  resetP5State();
  resetP6State();
  safeSession()?.removeItem(SESSION_KEY);
}

function safeSession(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

const rid = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `mock-${Math.random().toString(16).slice(2)}`;
const rand = (n = 24) =>
  Array.from(
    { length: n },
    () => 'abcdefghijkmnpqrstuvwxyz23456789'[Math.floor(Math.random() * 32)],
  ).join('');

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

function ok(
  requestId: string,
  data: unknown,
  status = 200,
  paginate?: { page: number; limit: number; total: number },
) {
  const body: Record<string, unknown> = {
    success: true,
    statusCode: 0,
    message: 'ok',
    data,
    meta: { requestId },
  };
  if (paginate) body.paginate = paginate;
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId },
  });
}

function fail(requestId: string, e: HttpError) {
  const retryAfter = (e.details as { retryAfterSec?: unknown } | undefined)?.retryAfterSec;
  return new Response(
    JSON.stringify({
      error: { code: e.code, message: e.message, details: e.details },
      meta: { requestId },
    }),
    {
      status: e.status,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': requestId,
        ...(e.status === 429 && typeof retryAfter === 'number'
          ? { 'Retry-After': String(retryAfter) }
          : {}),
      },
    },
  );
}

function permissionsOf(u: MockUser): Permission[] {
  const set = new Set<Permission>();
  for (const b of u.bindings) BUILTIN_ROLES[b.roleKey].forEach((p) => set.add(p));
  return PERMISSIONS.filter((p) => set.has(p));
}

function hasPermFor(u: MockUser, perm: Permission, s?: Server): boolean {
  return u.bindings.some((b) => {
    if (!BUILTIN_ROLES[b.roleKey].includes(perm)) return false;
    if (b.scopeType === 'global' || !s) return true;
    if (b.scopeType === 'environment') return b.scopeId === s.environment;
    if (b.scopeType === 'server') return b.scopeId === s.id;
    return false;
  });
}

/** Server-side computed per-resource action list (the UI only mirrors it). */
function withAllowedActions(u: MockUser, s: Server): Server {
  const actions: string[] = [];
  const live = s.status === 'online' || s.status === 'degraded';
  if (s.status !== 'revoked') {
    if (hasPermFor(u, 'servers.operate', s)) {
      actions.push('edit', 'create_job', 'restart_service', 'cancel_job');
    }
    if (hasPermFor(u, 'servers.revoke', s)) actions.push('revoke');
    if (live && hasPermFor(u, 'ssh.connect', s)) actions.push('open_terminal');
  }
  return { ...s, allowedActions: actions };
}

function currentUser(req: Request): MockUser {
  const h = req.headers.get('Authorization');
  const token = h?.startsWith('Bearer ') ? h.slice(7) : null;
  const rec = token ? db().accessTokens.get(token) : undefined;
  if (!rec || rec.exp < Date.now())
    throw new HttpError(401, 'UNAUTHENTICATED', 'Access token missing or expired');
  const u = db().users.find((x) => x.id === rec.userId);
  if (!u) throw new HttpError(401, 'UNAUTHENTICATED', 'Session user no longer exists');
  return u;
}

function requirePerm(u: MockUser, perm: Permission, s?: Server) {
  if (!hasPermFor(u, perm, s))
    throw new HttpError(403, 'FORBIDDEN', `Missing permission ${perm} for this scope`, {
      required: perm,
    });
}

function issueSession(u: MockUser, amr: string) {
  const token = `mock_at_${rand(32)}`;
  db().accessTokens.set(token, { userId: u.id, exp: Date.now() + 15 * 60e3, amr });
  safeSession()?.setItem(SESSION_KEY, u.id);
  u.lastLoginAt = new Date().toISOString();
  return { accessToken: token, expiresIn: 900, user: publicUser(u) };
}

const publicUser = (u: MockUser): UserPublic => ({
  id: u.id,
  email: u.email,
  displayName: u.displayName,
  status: 'active',
  mfaEnabled: u.mfaEnabled,
  lastLoginAt: u.lastLoginAt,
  createdAt: u.createdAt,
  updatedAt: u.createdAt,
});

function audit(
  actor: MockUser | null,
  action: string,
  target: Server | null,
  result: AuditEvent['result'],
  requestId: string,
) {
  db().audit.unshift({
    id: rid(),
    actorId: actor?.id ?? null,
    actorType: actor ? 'user' : 'system',
    actorLabel: actor?.displayName ?? 'system',
    action,
    targetType: target ? 'server' : null,
    targetId: target?.id ?? null,
    targetLabel: target?.name ?? null,
    result,
    requestId,
    diffHash: null,
    createdAt: new Date().toISOString(),
  });
}

const isSixDigits = (c: unknown) => typeof c === 'string' && /^\d{6}$/.test(c);

function paginate<T>(items: T[], url: URL) {
  const page = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') ?? 20) || 20));
  return {
    slice: items.slice((page - 1) * limit, page * limit),
    paginate: { page, limit, total: items.length },
  };
}

type Handler = (ctx: {
  req: Request;
  url: URL;
  params: string[];
  body: Record<string, unknown>;
  requestId: string;
}) => Response | Promise<Response>;
const routes: Array<[string, RegExp, Handler]> = [];
const on = (method: string, pattern: string, h: Handler) =>
  routes.push([method, new RegExp(`^${pattern.replace(/:[a-zA-Z]+/g, '([^/]+)')}$`), h]);

// ---------- setup ----------
on('GET', '/setup/status', ({ requestId }) => ok(requestId, { bootstrapped: db().bootstrapped }));
on('POST', '/setup/bootstrap', ({ body, requestId }) => {
  if (db().bootstrapped)
    throw new HttpError(409, 'ALREADY_BOOTSTRAPPED', 'An administrator already exists');
  const details: Array<{ field: string; message: string }> = [];
  if (typeof body.email !== 'string' || !body.email.includes('@'))
    details.push({ field: 'email', message: 'Enter a valid email' });
  if (typeof body.password !== 'string' || body.password.length < 12)
    details.push({ field: 'password', message: 'At least 12 characters' });
  if (typeof body.displayName !== 'string' || !body.displayName.trim())
    details.push({ field: 'displayName', message: 'Required' });
  if (details.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', details);
  if (body.setupToken !== 'dev-setup-token')
    throw new HttpError(
      401,
      'SETUP_TOKEN_INVALID',
      'Setup token is invalid (mock: dev-setup-token)',
    );
  const u: MockUser = {
    id: rid(),
    email: String(body.email).trim(),
    username: String(body.email).split('@')[0]!,
    displayName: String(body.displayName).trim(),
    password: String(body.password),
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
    bindings: [],
  };
  u.bindings = [{ id: rid(), userId: u.id, roleKey: 'platform_owner', scopeType: 'global' }];
  db().users.push(u);
  db().bootstrapped = true;
  safeSession()?.removeItem(NOT_BOOTSTRAPPED_KEY);
  return ok(requestId, { user: publicUser(u) }, 201);
});

// ---------- auth ----------
on('POST', '/auth/login', ({ body, requestId }) => {
  const login = String(body.email ?? '')
    .trim()
    .toLowerCase();
  const u = db().users.find((x) => x.email === login || x.username === login);
  if (!u || u.password !== body.password)
    throw new HttpError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect');
  if (u.mfaEnabled) {
    const mfaToken = `mock_mfa_${rand()}`;
    db().mfaTokens.set(mfaToken, u.id);
    return ok(requestId, { mfaRequired: true, mfaToken });
  }
  audit(u, 'auth.login', null, 'success', requestId);
  return ok(requestId, issueSession(u, 'pwd'));
});
on('POST', '/auth/mfa/verify', ({ body, requestId }) => {
  const userId = db().mfaTokens.get(String(body.mfaToken));
  const u = db().users.find((x) => x.id === userId);
  if (!u) throw new HttpError(401, 'UNAUTHENTICATED', 'Sign-in challenge expired. Sign in again.');
  const good = body.recoveryCode
    ? /^[a-z0-9]{4}-[a-z0-9]{4}$/i.test(String(body.recoveryCode))
    : isSixDigits(body.code) && body.code !== '000000';
  if (!good) throw new HttpError(401, 'MFA_INVALID', 'The code is incorrect or expired');
  db().mfaTokens.delete(String(body.mfaToken));
  audit(u, 'auth.login', null, 'success', requestId);
  return ok(requestId, issueSession(u, 'mfa'));
});
on('POST', '/auth/refresh', ({ req, requestId }) => {
  if (req.headers.get('X-CSRF') !== '1')
    throw new HttpError(403, 'CSRF_REQUIRED', 'Missing X-CSRF header');
  const userId = safeSession()?.getItem(SESSION_KEY);
  const u = db().users.find((x) => x.id === userId);
  if (!u) throw new HttpError(401, 'REFRESH_INVALID', 'No refresh session');
  const { accessToken, expiresIn } = issueSession(u, 'pwd');
  return ok(requestId, { accessToken, expiresIn });
});
on('POST', '/auth/logout', ({ req }) => {
  const h = req.headers.get('Authorization');
  if (h?.startsWith('Bearer ')) db().accessTokens.delete(h.slice(7));
  safeSession()?.removeItem(SESSION_KEY);
  return new Response(null, { status: 204 });
});
on('GET', '/auth/me', ({ req, requestId }) => {
  const u = currentUser(req);
  return ok(requestId, {
    user: publicUser(u),
    permissions: permissionsOf(u),
    bindings: u.bindings,
    mfaEnabled: u.mfaEnabled,
  });
});
on('POST', '/auth/mfa/totp/setup', ({ req, requestId }) => {
  const u = currentUser(req);
  const secret =
    'JBSWY3DPEHPK3PXP' +
    rand(8)
      .toUpperCase()
      .replace(/[^A-Z2-7]/g, 'Q');
  db().pendingTotp.set(u.id, secret);
  const otpauthUrl = `otpauth://totp/pPanel:${encodeURIComponent(u.email)}?secret=${secret}&issuer=pPanel&algorithm=SHA1&digits=6&period=30`;
  return ok(requestId, {
    otpauthUrl,
    secretMasked: `${secret.slice(0, 4)}••••••••${secret.slice(-4)}`,
  });
});
on('POST', '/auth/mfa/totp/confirm', ({ req, body, requestId }) => {
  const u = currentUser(req);
  if (!db().pendingTotp.has(u.id))
    throw new HttpError(409, 'MFA_NOT_PENDING', 'Start TOTP setup first');
  if (!isSixDigits(body.code) || body.code === '000000')
    throw new HttpError(422, 'MFA_INVALID', 'The code is incorrect', [
      { field: 'code', message: 'Code does not match' },
    ]);
  db().pendingTotp.delete(u.id);
  u.mfaEnabled = true;
  audit(u, 'auth.mfa.enable', null, 'success', requestId);
  return ok(requestId, {
    recoveryCodes: Array.from({ length: 10 }, () => `${rand(4)}-${rand(4)}`),
  });
});
on('POST', '/auth/step-up', ({ req, body, requestId }) => {
  const u = currentUser(req);
  if (!u.mfaEnabled)
    throw new HttpError(
      403,
      'MFA_REQUIRED',
      'Enable two-factor authentication before privileged production actions',
    );
  if (!isSixDigits(body.code) || body.code === '000000')
    throw new HttpError(401, 'MFA_INVALID', 'The code is incorrect or expired');
  const token = `mock_su_${rand()}`;
  const exp = Date.now() + 5 * 60e3;
  db().stepUpTokens.set(token, { userId: u.id, exp });
  return ok(requestId, { stepUpToken: token, expiresAt: new Date(exp).toISOString() });
});

// ---------- servers ----------
function findServer(id: string) {
  const s = db().servers.find((x) => x.id === id);
  if (!s) throw new HttpError(404, 'NOT_FOUND', 'Server not found');
  return s;
}
on('GET', '/servers', ({ req, url, requestId }) => {
  const u = currentUser(req);
  requirePerm(u, 'fleet.read');
  const env = url.searchParams.get('environment');
  const status = url.searchParams.get('status');
  const q = url.searchParams.get('q')?.toLowerCase();
  const items = db()
    .servers.filter((s) => hasPermFor(u, 'fleet.read', s))
    .filter((s) => !env || s.environment === env)
    .filter((s) => !status || s.status === status)
    .filter(
      (s) =>
        !q ||
        s.name.includes(q) ||
        s.tags.some((t) => t.includes(q)) ||
        s.addresses.some((a) => a.address.includes(q)),
    )
    .map((s) => withAllowedActions(u, s));
  const { slice, paginate: p } = paginate(items, url);
  return ok(requestId, slice, 200, p);
});
on('GET', '/servers/:id', ({ req, params, requestId }) => {
  const u = currentUser(req);
  const s = findServer(params[0]!);
  requirePerm(u, 'fleet.read', s);
  return ok(requestId, withAllowedActions(u, s));
});
on('PATCH', '/servers/:id', ({ req, params, body, requestId }) => {
  const u = currentUser(req);
  const s = findServer(params[0]!);
  // §8.1: buildNode needs policies.manage; every other field needs servers.operate.
  const onlyBuildNode =
    Object.keys(body).length > 0 && Object.keys(body).every((k) => k === 'buildNode');
  if (body.buildNode !== undefined) requirePerm(u, 'policies.manage', s);
  if (!onlyBuildNode) requirePerm(u, 'servers.operate', s);
  const ifMatch = req.headers.get('If-Match');
  if (ifMatch && Number(ifMatch) !== s.version) {
    throw new HttpError(
      409,
      'VERSION_CONFLICT',
      'This server was changed by someone else. Reload and try again.',
      { currentVersion: s.version },
    );
  }
  const details: Array<{ field: string; message: string }> = [];
  if (body.name !== undefined && !/^[a-z0-9][a-z0-9-]{0,62}$/.test(String(body.name)))
    details.push({ field: 'name', message: 'Lowercase letters, digits and dashes; max 63' });
  if (body.environment !== undefined && !ENVIRONMENTS.includes(body.environment as never))
    details.push({ field: 'environment', message: 'Unknown environment' });
  if (
    body.connectionPolicy !== undefined &&
    !CONNECTION_POLICIES.includes(body.connectionPolicy as never)
  )
    details.push({ field: 'connectionPolicy', message: 'Unknown policy' });
  if (body.tags !== undefined && (!Array.isArray(body.tags) || body.tags.length > 20))
    details.push({ field: 'tags', message: 'Up to 20 tags' });
  if (body.buildNode !== undefined && typeof body.buildNode !== 'boolean')
    details.push({ field: 'buildNode', message: 'Must be true or false' });
  if (body.buildNode === true && !s.capabilities.includes('build'))
    details.push({
      field: 'buildNode',
      message:
        'The agent does not report the build capability (enable builds in its local config).',
    });
  if (details.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', details);
  Object.assign(s, {
    ...(body.buildNode !== undefined ? { buildNode: body.buildNode } : {}),
    ...(body.name !== undefined ? { name: body.name, hostname: s.hostname } : {}),
    ...(body.environment !== undefined ? { environment: body.environment } : {}),
    ...(body.tags !== undefined ? { tags: body.tags } : {}),
    ...(body.connectionPolicy !== undefined ? { connectionPolicy: body.connectionPolicy } : {}),
    version: s.version + 1,
    updatedAt: new Date().toISOString(),
  });
  audit(
    u,
    body.buildNode !== undefined ? 'server.build_node' : 'server.update',
    s,
    'success',
    requestId,
  );
  return ok(requestId, withAllowedActions(u, s));
});
on('POST', '/servers/:id/revoke', ({ req, params, requestId }) => {
  const u = currentUser(req);
  const s = findServer(params[0]!);
  requirePerm(u, 'servers.revoke', s);
  if (s.environment === 'production') {
    const t = db().stepUpTokens.get(req.headers.get('X-Step-Up') ?? '');
    if (!t || t.userId !== u.id || t.exp < Date.now()) {
      audit(u, 'server.revoke', s, 'denied', requestId);
      throw new HttpError(
        403,
        'STEP_UP_REQUIRED',
        'Production revoke requires a fresh 2FA confirmation',
      );
    }
  }
  s.status = 'revoked';
  s.certificate = null;
  s.version += 1;
  audit(u, 'server.revoke', s, 'success', requestId);
  return ok(requestId, withAllowedActions(u, s));
});

// ---------- enrollments ----------
on('POST', '/enrollments', ({ req, body, requestId }) => {
  const u = currentUser(req);
  requirePerm(u, 'servers.enroll');
  const parsed = createEnrollmentSchema.safeParse(body);
  if (!parsed.success) {
    throw new HttpError(
      422,
      'VALIDATION_FAILED',
      'Validation failed',
      parsed.error.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    );
  }
  if (db().servers.some((s) => s.name === parsed.data.name)) {
    throw new HttpError(409, 'CONFLICT', 'A server with this name already exists', [
      { field: 'name', message: 'Name already in use' },
    ]);
  }
  const token = `ppe_${rand(40)}`;
  const expiresAt = new Date(Date.now() + parsed.data.ttlMinutes * 60e3).toISOString();
  audit(u, 'enrollment.create', null, 'success', requestId);
  return ok(
    requestId,
    {
      enrollmentId: rid(),
      token,
      expiresAt,
      installCommand: `curl -fsSL https://localhost:4443/install.sh | sudo bash -s -- --center https://localhost:4443 --token ${token}`,
    },
    201,
  );
});

// ---------- users / RBAC ----------
on('GET', '/users', ({ req, url, requestId }) => {
  const u = currentUser(req);
  requirePerm(u, 'users.manage');
  const items = db().users.map((x) => ({ ...publicUser(x), bindings: x.bindings }));
  const { slice, paginate: p } = paginate(items, url);
  return ok(requestId, slice, 200, p);
});
on('POST', '/users/:id/role-bindings', ({ req, params, body, requestId }) => {
  const u = currentUser(req);
  requirePerm(u, 'users.manage');
  const target = db().users.find((x) => x.id === params[0]);
  if (!target) throw new HttpError(404, 'NOT_FOUND', 'User not found');
  if (!ROLE_KEYS.includes(body.roleKey as never))
    throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
      { field: 'roleKey', message: 'Unknown role' },
    ]);
  if (!['global', 'environment', 'project', 'server'].includes(String(body.scopeType)))
    throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
      { field: 'scopeType', message: 'Unknown scope' },
    ]);
  if (body.scopeType !== 'global' && !body.scopeId)
    throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
      { field: 'scopeId', message: 'Required for scoped bindings' },
    ]);
  const b: RoleBinding = {
    id: rid(),
    userId: target.id,
    roleKey: body.roleKey as RoleBinding['roleKey'],
    scopeType: body.scopeType as RoleBinding['scopeType'],
    ...(body.scopeId ? { scopeId: String(body.scopeId) } : {}),
  };
  target.bindings.push(b);
  audit(u, 'role_binding.create', null, 'success', requestId);
  return ok(requestId, b, 201);
});
on('DELETE', '/role-bindings/:id', ({ req, params, requestId }) => {
  const u = currentUser(req);
  requirePerm(u, 'users.manage');
  const owner = db().users.find((x) => x.bindings.some((b) => b.id === params[0]));
  if (!owner) throw new HttpError(404, 'NOT_FOUND', 'Role binding not found');
  if (
    owner.id === u.id &&
    owner.bindings.find((b) => b.id === params[0])?.roleKey === 'platform_owner'
  ) {
    throw new HttpError(409, 'LAST_OWNER', 'You cannot remove your own platform_owner binding');
  }
  owner.bindings = owner.bindings.filter((b) => b.id !== params[0]);
  audit(u, 'role_binding.delete', null, 'success', requestId);
  return new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });
});

// ---------- audit ----------
on('GET', '/audit-events', ({ req, url, requestId }) => {
  const u = currentUser(req);
  requirePerm(u, 'audit.read');
  const action = url.searchParams.get('action[prefix]') ?? url.searchParams.get('action');
  const actor = url.searchParams.get('actor_id');
  const target = url.searchParams.get('target_id');
  const since = url.searchParams.get('created_at[gte]');
  const items = db()
    .audit.filter((e) => !action || e.action.startsWith(action))
    .filter((e) => !actor || e.actorId === actor)
    .filter((e) => !target || e.targetId === target)
    .filter((e) => !since || e.createdAt >= since)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const { slice, paginate: p } = paginate(items, url);
  return ok(requestId, slice, 200, p);
});

// ---------- P3: discovery / applications / nginx revisions ----------
const p3ctx: Parameters<typeof registerP3Routes>[0] = {
  on,
  ok,
  HttpError,
  currentUser,
  hasPermFor: hasPermFor as never,
  requirePerm: requirePerm as never,
  servers: () => db().servers,
  users: () => db().users,
  checkStepUp: (req, u) => {
    const t = db().stepUpTokens.get(req.headers.get('X-Step-Up') ?? '');
    return !!t && t.userId === u.id && t.exp >= Date.now();
  },
  audit: (u, action, s, result, requestId) =>
    audit(db().users.find((x) => x.id === u.id) ?? null, action, s, result, requestId),
  rid,
  paginate,
};
registerP3Routes(p3ctx);
// ---------- P4a: container apps / deployments / secrets / webhooks ----------
registerP4Routes(p3ctx);
registerP4bRoutes(p3ctx);
// ---------- P5: metrics / central logs / alerts / incidents / channels ----------
registerP5Routes(p3ctx);
// ---------- P6: backups / snapshots / restores ----------
registerP6Routes(p3ctx);

/** fetch-compatible entry point. */
export async function mockFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const req = new Request(input instanceof URL ? input.toString() : input, init);
  const url = new URL(req.url);
  const path = url.pathname.replace(/^.*\/api\/v1/, '');
  const requestId = req.headers.get('X-Request-ID') ?? rid();
  await new Promise((r) => setTimeout(r, 120 + Math.random() * 180));
  try {
    for (const [method, re, h] of routes) {
      if (method !== req.method) continue;
      const m = path.match(re);
      if (!m) continue;
      let body: Record<string, unknown> = {};
      if (req.method !== 'GET' && req.method !== 'DELETE') {
        const text = await req.text();
        if (text) {
          try {
            body = JSON.parse(text);
          } catch {
            throw new HttpError(400, 'BAD_JSON', 'Body is not valid JSON');
          }
        }
      }
      return await h({ req, url, params: m.slice(1).map(decodeURIComponent), body, requestId });
    }
    throw new HttpError(
      404,
      'NOT_IMPLEMENTED',
      `No mock route for ${req.method} ${path} (backend PROPOSED)`,
    );
  } catch (e) {
    if (e instanceof HttpError) return fail(requestId, e);
    return fail(requestId, new HttpError(500, 'MOCK_ERROR', (e as Error).message));
  }
}
