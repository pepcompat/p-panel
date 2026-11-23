import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { bearer, bootApp, enrollAgent, login, resetDb, type TestApp } from './helpers';

let t: TestApp;
let owner: string;

beforeAll(async () => {
  t = await bootApp();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
});

async function createUser(email: string, bindings: Array<Record<string, string>>) {
  const r = await t.http
    .post('/api/v1/users')
    .set(bearer(owner))
    .send({ email, password: 'long-enough-password', displayName: email.split('@')[0], bindings });
  expect(r.status).toBe(201);
  return r.body.data.user as { id: string };
}

async function loginAs(email: string) {
  const r = await t.http
    .post('/api/v1/auth/login')
    .send({ email, password: 'long-enough-password' });
  expect(r.status).toBe(200);
  return r.body.data.accessToken as string;
}

describe('P1-T03 viewer cannot enroll, revoke or operate', () => {
  it('user1 (viewer) gets 403 on enrollment, revoke, job creation, patch; reads allowed', async () => {
    const a = await enrollAgent(t, owner);
    const viewer = await login(t, 'user1');

    const en = await t.http
      .post('/api/v1/enrollments')
      .set(bearer(viewer))
      .send({ name: 'x', environment: 'development' });
    expect(en.status).toBe(403);
    expect(en.body.error.code).toBe('FORBIDDEN');

    const rv = await t.http.post(`/api/v1/servers/${a.serverId}/revoke`).set(bearer(viewer));
    expect(rv.status).toBe(403);

    const job = await t.http
      .post(`/api/v1/servers/${a.serverId}/jobs`)
      .set(bearer(viewer))
      .send({ type: 'inventory.collect', params: {} });
    expect(job.status).toBe(403);

    const patch = await t.http
      .patch(`/api/v1/servers/${a.serverId}`)
      .set(bearer(viewer))
      .send({ tags: ['x'] });
    expect(patch.status).toBe(403);

    const users = await t.http.get('/api/v1/users').set(bearer(viewer));
    expect(users.status).toBe(403);

    // reads are fine and allowedActions reflects no write rights
    const list = await t.http.get('/api/v1/servers').set(bearer(viewer));
    expect(list.status).toBe(200);
    expect(list.body.data[0].allowedActions).toEqual([]);

    expect((await t.prisma.server.findUniqueOrThrow({ where: { id: a.serverId } })).status).toBe(
      'enrolling',
    );
    expect(await t.prisma.job.count()).toBe(0);
    expect(await t.prisma.agentEnrollment.count()).toBe(1);
    const denied = await t.prisma.auditEvent.count({
      where: { result: 'denied', actorId: { not: null } },
    });
    expect(denied).toBeGreaterThanOrEqual(4);
  });

  it('deployer (dev) cannot enroll or revoke either', async () => {
    const a = await enrollAgent(t, owner);
    const dev = await login(t, 'dev');
    expect(
      (
        await t.http
          .post('/api/v1/enrollments')
          .set(bearer(dev))
          .send({ name: 'x', environment: 'development' })
      ).status,
    ).toBe(403);
    expect(
      (await t.http.post(`/api/v1/servers/${a.serverId}/revoke`).set(bearer(dev))).status,
    ).toBe(403);
  });
});

describe('P1-T03 environment-scoped bindings', () => {
  it('ops_admin scoped to uat cannot touch a production server', async () => {
    const prod = await enrollAgent(t, owner, { name: 'app-prod-01', environment: 'production' });
    const uat = await enrollAgent(t, owner, { name: 'app-uat-01', environment: 'uat' });
    await createUser('uatops@ppanel.local', [
      { roleKey: 'ops_admin', scopeType: 'environment', scopeId: 'uat' },
    ]);
    const tok = await loginAs('uatops@ppanel.local');

    // visibility is scope-filtered; production server is invisible (404, no existence oracle)
    const list = await t.http.get('/api/v1/servers').set(bearer(tok));
    expect(list.body.data.map((s: { id: string }) => s.id)).toEqual([uat.serverId]);
    expect((await t.http.get(`/api/v1/servers/${prod.serverId}`).set(bearer(tok))).status).toBe(
      404,
    );
    expect(
      (
        await t.http
          .patch(`/api/v1/servers/${prod.serverId}`)
          .set(bearer(tok))
          .send({ tags: ['x'] })
      ).status,
    ).toBe(404);
    expect(
      (
        await t.http
          .post(`/api/v1/servers/${prod.serverId}/jobs`)
          .set(bearer(tok))
          .send({ type: 'inventory.collect' })
      ).status,
    ).toBe(404);
    expect(
      (await t.http.post(`/api/v1/servers/${prod.serverId}/revoke`).set(bearer(tok))).status,
    ).toBe(404);

    // enrollment into production refused, into uat allowed
    expect(
      (
        await t.http
          .post('/api/v1/enrollments')
          .set(bearer(tok))
          .send({ name: 'p', environment: 'production' })
      ).status,
    ).toBe(403);
    expect(
      (
        await t.http
          .post('/api/v1/enrollments')
          .set(bearer(tok))
          .send({ name: 'u', environment: 'uat' })
      ).status,
    ).toBe(201);

    // uat server can be operated
    expect(
      (
        await t.http
          .patch(`/api/v1/servers/${uat.serverId}`)
          .set(bearer(tok))
          .send({ tags: ['edge'] })
      ).status,
    ).toBe(200);
    expect(
      (
        await t.http
          .post(`/api/v1/servers/${uat.serverId}/jobs`)
          .set(bearer(tok))
          .send({ type: 'inventory.collect' })
      ).status,
    ).toBe(202);
    // ... but not moved into production
    const move = await t.http
      .patch(`/api/v1/servers/${uat.serverId}`)
      .set(bearer(tok))
      .send({ environment: 'production' });
    expect(move.status).toBe(403);
    expect(
      (await t.prisma.server.findUniqueOrThrow({ where: { id: uat.serverId } })).environment,
    ).toBe('uat');
  });

  it('global viewer + uat ops_admin: production visible but mutations are 403', async () => {
    const prod = await enrollAgent(t, owner, { environment: 'production' });
    await createUser('mixed@ppanel.local', [
      { roleKey: 'viewer', scopeType: 'global' },
      { roleKey: 'ops_admin', scopeType: 'environment', scopeId: 'uat' },
    ]);
    const tok = await loginAs('mixed@ppanel.local');
    const get = await t.http.get(`/api/v1/servers/${prod.serverId}`).set(bearer(tok));
    expect(get.status).toBe(200);
    expect(get.body.data.allowedActions).toEqual([]);
    expect(
      (
        await t.http
          .patch(`/api/v1/servers/${prod.serverId}`)
          .set(bearer(tok))
          .send({ tags: ['x'] })
      ).status,
    ).toBe(403);
    expect(
      (
        await t.http
          .post(`/api/v1/servers/${prod.serverId}/jobs`)
          .set(bearer(tok))
          .send({ type: 'inventory.collect' })
      ).status,
    ).toBe(403);
    expect(
      (await t.http.post(`/api/v1/servers/${prod.serverId}/revoke`).set(bearer(tok))).status,
    ).toBe(403);
    expect(
      await t.prisma.auditEvent.count({ where: { result: 'denied', targetId: prod.serverId } }),
    ).toBe(3);
  });
});

describe('servers admin (P1.06)', () => {
  it('PATCH with If-Match: success bumps version, stale version → 409 VERSION_CONFLICT, audited', async () => {
    const a = await enrollAgent(t, owner);
    const g = await t.http
      .post('/api/v1/server-groups')
      .set(bearer(owner))
      .send({ name: 'Production web', environment: 'production' });
    expect(g.status).toBe(201);
    const ok = await t.http
      .patch(`/api/v1/servers/${a.serverId}`)
      .set(bearer(owner))
      .set('If-Match', '"1"')
      .send({
        name: 'web-01',
        tags: ['web', 'php'],
        groupId: g.body.data.id,
        connectionPolicy: 'private_preferred',
      });
    expect(ok.status).toBe(200);
    expect(ok.body.data).toMatchObject({
      name: 'web-01',
      tags: ['web', 'php'],
      groupId: g.body.data.id,
      connectionPolicy: 'private_preferred',
      version: 2,
    });
    expect(ok.headers.etag).toBe('"2"');
    const stale = await t.http
      .patch(`/api/v1/servers/${a.serverId}`)
      .set(bearer(owner))
      .set('If-Match', '1')
      .send({ tags: [] });
    expect(stale.status).toBe(409);
    expect(stale.body.error).toMatchObject({
      code: 'VERSION_CONFLICT',
      details: { currentVersion: 2 },
    });
    const bad = await t.http
      .patch(`/api/v1/servers/${a.serverId}`)
      .set(bearer(owner))
      .send({ hostname: 'nope' });
    expect(bad.status).toBe(422);
    const ev = await t.prisma.auditEvent.findFirstOrThrow({ where: { action: 'servers.update' } });
    expect(ev.diffHash).toMatch(/^[0-9a-f]{64}$/);
    const groups = await t.http.get('/api/v1/server-groups').set(bearer(owner));
    expect(groups.body.data[0]).toMatchObject({ name: 'Production web', serverCount: 1 });
    expect(groups.body.paginate.total).toBe(1);
  });

  it('server list filters + pagination + q', async () => {
    await enrollAgent(t, owner, { name: 'alpha', environment: 'production' });
    await enrollAgent(t, owner, { name: 'beta', environment: 'uat' });
    await enrollAgent(t, owner, { name: 'gamma', environment: 'uat' });
    const uat = await t.http
      .get('/api/v1/servers?environment=uat&sort=name&order=asc')
      .set(bearer(owner));
    expect(uat.body.data.map((s: { name: string }) => s.name)).toEqual(['beta', 'gamma']);
    const page = await t.http
      .get('/api/v1/servers?limit=1&page=2&sort=name&order=asc')
      .set(bearer(owner));
    expect(page.body.data.map((s: { name: string }) => s.name)).toEqual(['beta']);
    expect(page.body.paginate).toEqual({ page: 2, limit: 1, total: 3 });
    const q = await t.http.get('/api/v1/servers?q=amm').set(bearer(owner));
    expect(q.body.data.map((s: { name: string }) => s.name)).toEqual(['gamma']);
    const inn = await t.http
      .get('/api/v1/servers?environment[in]=production,uat&status=enrolling')
      .set(bearer(owner));
    expect(inn.body.paginate.total).toBe(3);
    const badField = await t.http.get('/api/v1/servers?password=x').set(bearer(owner));
    expect(badField.status).toBe(400);
  });
});

describe('users & role bindings', () => {
  it('create user, add/remove bindings, last owner protected, all audited', async () => {
    const u = await createUser('ops2@ppanel.local', []);
    const add = await t.http
      .post(`/api/v1/users/${u.id}/role-bindings`)
      .set(bearer(owner))
      .send({ roleKey: 'deployer', scopeType: 'environment', scopeId: 'uat' });
    expect(add.status).toBe(201);
    expect(add.body.data).toMatchObject({
      userId: u.id,
      roleKey: 'deployer',
      scopeType: 'environment',
      scopeId: 'uat',
    });
    const dup = await t.http
      .post(`/api/v1/users/${u.id}/role-bindings`)
      .set(bearer(owner))
      .send({ roleKey: 'deployer', scopeType: 'environment', scopeId: 'uat' });
    expect(dup.status).toBe(409);
    const badScope = await t.http
      .post(`/api/v1/users/${u.id}/role-bindings`)
      .set(bearer(owner))
      .send({ roleKey: 'viewer', scopeType: 'environment', scopeId: 'mars' });
    expect(badScope.status).toBe(422);
    const globalWithId = await t.http
      .post(`/api/v1/users/${u.id}/role-bindings`)
      .set(bearer(owner))
      .send({ roleKey: 'viewer', scopeType: 'global', scopeId: 'x' });
    expect(globalWithId.status).toBe(422);
    const del = await t.http.delete(`/api/v1/role-bindings/${add.body.data.id}`).set(bearer(owner));
    expect(del.status).toBe(204);

    const ownerBinding = await t.prisma.roleBinding.findFirstOrThrow({
      where: { roleKey: 'platform_owner' },
    });
    const last = await t.http.delete(`/api/v1/role-bindings/${ownerBinding.id}`).set(bearer(owner));
    expect(last.status).toBe(409);
    expect(last.body.error.code).toBe('LAST_OWNER');

    const dupUser = await t.http
      .post('/api/v1/users')
      .set(bearer(owner))
      .send({ email: 'ops2@ppanel.local', password: 'long-enough-password', displayName: 'x' });
    expect(dupUser.status).toBe(409);
    const weak = await t.http
      .post('/api/v1/users')
      .set(bearer(owner))
      .send({ email: 'weak@ppanel.local', password: 'short', displayName: 'x' });
    expect(weak.status).toBe(422);

    // admin (ops_admin) lacks users.manage
    const admin = await login(t, 'admin');
    expect(
      (
        await t.http
          .post('/api/v1/users')
          .set(bearer(admin))
          .send({ email: 'z@ppanel.local', password: 'long-enough-password', displayName: 'z' })
      ).status,
    ).toBe(403);

    const actions = (
      await t.prisma.auditEvent.findMany({ where: { result: 'success' }, select: { action: true } })
    ).map((a) => a.action);
    expect(actions).toEqual(
      expect.arrayContaining(['users.create', 'role_bindings.create', 'role_bindings.delete']),
    );
  });
});

describe('audit-events query builder', () => {
  it('filters by action / actor_id / created_at[gte] with pagination; viewer can read; no secrets', async () => {
    await login(t, 'dev');
    await login(t, 'dev');
    await t.http.post('/api/v1/auth/login').send({ email: 'dev@ppanel.local', password: 'wrong' });
    const viewer = await login(t, 'user1');
    const devUser = await t.prisma.user.findUniqueOrThrow({ where: { email: 'dev@ppanel.local' } });
    const since = new Date(Date.now() - 60_000).toISOString();

    const r = await t.http
      .get(
        `/api/v1/audit-events?action=auth.login&actor_id=${devUser.id}&created_at[gte]=${encodeURIComponent(since)}&limit=1&page=1`,
      )
      .set(bearer(viewer));
    expect(r.status).toBe(200);
    expect(r.body.paginate).toEqual({ page: 1, limit: 1, total: 3 });
    expect(r.body.data).toHaveLength(1);
    expect(r.body.data[0]).toMatchObject({
      action: 'auth.login',
      actorId: devUser.id,
      requestId: expect.any(String),
    });

    const failures = await t.http
      .get('/api/v1/audit-events?result=failure&action[prefix]=auth.')
      .set(bearer(viewer));
    expect(failures.body.paginate.total).toBe(1);
    const inOp = await t.http
      .get('/api/v1/audit-events?result[in]=failure,denied')
      .set(bearer(viewer));
    expect(inOp.body.paginate.total).toBe(1);
    const orOp = await t.http
      .get('/api/v1/audit-events?or[0][result]=failure&or[0][actor_id]=nobody')
      .set(bearer(viewer));
    expect(orOp.body.paginate.total).toBe(1);
    const future = await t.http
      .get(
        `/api/v1/audit-events?created_at[gte]=${encodeURIComponent(new Date(Date.now() + 3_600_000).toISOString())}`,
      )
      .set(bearer(viewer));
    expect(future.body.paginate.total).toBe(0);
    const badOp = await t.http.get('/api/v1/audit-events?action[regex]=x').set(bearer(viewer));
    expect(badOp.status).toBe(400);

    const all = await t.http.get('/api/v1/audit-events?limit=100').set(bearer(viewer));
    expect(JSON.stringify(all.body)).not.toMatch(/password|argon2|eyJ/);
  });
});
