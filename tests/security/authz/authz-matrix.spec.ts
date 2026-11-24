/**
 * P7.01 authorization matrix + IDOR (threat TB1-E, tests P1-T03 / P5-T02 / E2E-16).
 *
 * For every HTTP route of the Center API (inventory from Nest metadata, cross-checked with the
 * Express router) the route is called:
 *   - unauthenticated            → 401 unless on the justified public allowlist
 *   - global viewer / deployer   → 403 for every route whose coarse permission the role lacks
 *   - principals scoped to server B (ops_admin, platform_owner, viewer) against server-A resources
 *                                → 403/404, never 2xx with A data, never a state change.
 */
import { bearer } from '../../../apps/api/test/integration/helpers';
import { BUILTIN_ROLES } from '../../../packages/shared-contracts/src/permissions';
import { diff, snapshot } from '../lib/db-snapshot';
import { expressRoutes, key, nestRoutes } from '../lib/routes';
import { buildWorld, type World } from '../lib/world';
import { PROBES, type Probe } from './probes';

let w: World;

beforeAll(async () => {
  w = await buildWorld();
});
afterAll(async () => w.t.close());

async function call(p: Probe, token: string | undefined, extra: Record<string, string> = {}) {
  const [method] = p.route.split(' ') as [string];
  let req = w.t.http[method.toLowerCase() as 'get'](p.path(w.ids));
  if (token) req = req.set(bearer(token));
  for (const [k, v] of Object.entries({ ...p.headers, ...extra })) req = req.set(k, v);
  if (p.body) req = req.send(p.body(w.ids) as object);
  const res = await req;
  return res;
}

const leaks = (body: unknown, needles: string[]) => {
  const s = JSON.stringify(body ?? null);
  return needles.filter((n) => s.includes(n));
};

describe('route inventory', () => {
  it('every mounted route has a probe and Nest metadata matches the Express router', () => {
    const nest = nestRoutes(w.t);
    const mounted = expressRoutes(w.t);
    expect(nest.map(key).sort()).toEqual(mounted);
    const probed = new Set(PROBES.map((p) => p.route));
    const missing = nest.map(key).filter((k) => !probed.has(k));
    expect(missing, 'routes without a security probe').toEqual([]);
    const stale = [...probed].filter((k) => !nest.some((r) => key(r) === k));
    expect(stale, 'probes for routes that no longer exist').toEqual([]);
  });

  it('@Public routes are exactly the justified allowlist', () => {
    const pub = nestRoutes(w.t)
      .filter((r) => r.isPublic)
      .map(key)
      .sort();
    const allow = PROBES.filter((p) => p.publicReason)
      .map((p) => p.route)
      .sort();
    expect(pub).toEqual(allow);
  });

  it('every non-public route without a coarse permission is explicitly classified', () => {
    const unclassified = nestRoutes(w.t)
      .filter((r) => !r.isPublic && !r.permission)
      .map(key)
      .filter((k) => {
        const p = PROBES.find((x) => x.route === k)!;
        return p.allowViewer === undefined || p.allowDeployer === undefined;
      });
    expect(unclassified).toEqual([]);
  });
});

describe('unauthenticated', () => {
  it('every non-public route answers 401 with the error envelope', async () => {
    const bad: string[] = [];
    for (const p of PROBES.filter((x) => !x.publicReason)) {
      for (const auth of [undefined, 'Bearer', 'Bearer not-a-jwt', 'Basic Zm9vOmJhcg==']) {
        const res = await call(p, undefined, auth ? { Authorization: auth } : {});
        if (res.status !== 401 || res.body?.error?.code !== 'UNAUTHENTICATED')
          bad.push(`${p.route} [${auth ?? 'none'}] → ${res.status}`);
      }
    }
    expect(bad).toEqual([]);
  });
});

describe('global roles without the coarse permission', () => {
  for (const role of ['viewer', 'deployer'] as const) {
    it(`${role}: 403 on every route needing a permission ${role} lacks, no state change`, async () => {
      const perms = BUILTIN_ROLES[role] as readonly string[];
      const token = w.p[role];
      const before = await snapshot(w.t.prisma);
      const bad: string[] = [];
      for (const r of nestRoutes(w.t)) {
        if (r.isPublic || !r.permission || perms.includes(r.permission)) continue;
        const p = PROBES.find((x) => x.route === key(r))!;
        const res = await call(p, token);
        if (res.status !== 403) bad.push(`${p.route} → ${res.status} ${res.body?.error?.code}`);
      }
      expect(bad).toEqual([]);
      expect(diff(before, await snapshot(w.t.prisma))).toEqual([]);
    });
  }
});

describe('IDOR: principals scoped to server B probing server-A resources', () => {
  for (const who of ['scopedB', 'scopedOwnerB', 'scopedViewerB'] as const) {
    it(`${who}: never 2xx with A data, mutations denied (403/404), no state change`, async () => {
      const token = w.p[who];
      const before = await snapshot(w.t.prisma, ['audit_events', 'mfa_factors']);
      const auditBefore = await w.t.prisma.auditEvent.count({ where: { result: 'success' } });
      const bad: string[] = [];
      for (const p of PROBES.filter((x) => !x.publicReason)) {
        const [method, path] = p.route.split(' ') as [string, string];
        const res = await call(p, token);
        const found = leaks(res.body, w.aSecrets);
        const isCollectionRead = method === 'GET' && !path.includes(':');
        const selfRoute = path.startsWith('/api/v1/auth/');
        if (res.status >= 500) bad.push(`${p.route} → ${res.status}`);
        else if (found.length) bad.push(`${p.route} → ${res.status} LEAK ${found.join(',')}`);
        else if (selfRoute || isCollectionRead || p.globalRead) continue;
        else if (p.scopedValidationOk && res.status < 500) continue;
        else if (res.status !== 403 && res.status !== 404)
          bad.push(
            `${p.route} → ${res.status} ${res.body?.error?.code ?? ''} ${JSON.stringify(res.body?.error?.details ?? '').slice(0, 160)}`,
          );
      }
      expect(bad).toEqual([]);
      expect(diff(before, await snapshot(w.t.prisma, ['audit_events', 'mfa_factors']))).toEqual([]);
      // no successful audited mutation by the scoped principal (MFA setup on self excluded)
      const succ = await w.t.prisma.auditEvent.findMany({
        where: { result: 'success', action: { notIn: ['auth.mfa.totp.setup'] } },
        orderBy: { createdAt: 'asc' },
        skip: auditBefore,
      });
      expect(succ.filter((a) => !a.action.startsWith('auth.mfa')).map((a) => a.action)).toEqual([]);
    });
  }
});

describe('service-level permissions beyond the coarse guard', () => {
  it('a global viewer cannot acknowledge or comment incidents (needs servers.operate in scope)', async () => {
    for (const path of ['acknowledge', 'comment']) {
      const r = await w.t.http
        .post(`/api/v1/incidents/${w.ids.incidentA}/${path}`)
        .set(bearer(w.p.viewer))
        .send({ comment: 'viewer' });
      expect(r.status, path).toBe(403);
    }
    const inc = await w.t.prisma.incident.findUniqueOrThrow({ where: { id: w.ids.incidentA } });
    expect(inc.status).toBe('firing');
  });

  it('a server-scoped platform_owner cannot mint users or global bindings (privilege escalation)', async () => {
    const r = await w.t.http
      .post(`/api/v1/users/${w.ids.targetUser}/role-bindings`)
      .set(bearer(w.p.scopedOwnerB))
      .send({ roleKey: 'platform_owner', scopeType: 'global' });
    expect(r.status).toBe(403);
    expect(
      await w.t.prisma.roleBinding.count({
        where: { userId: w.ids.targetUser, scopeType: 'global' },
      }),
    ).toBe(0);
  });
});
