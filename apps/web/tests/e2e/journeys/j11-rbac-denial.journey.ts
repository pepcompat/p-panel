import { expect, test } from '@playwright/test';
import { SEED_PASSWORD, apiLogin, call, evidence, shot, signIn, signOut } from './lib';

// J11 — RBAC denial is enforced server-side and audited (E2E-16). The viewer (user1) sees read-only UI
// with explicit "no access" states; a direct API call that bypasses the UI is refused with 403 and an
// audit row (result=denied) that an owner then finds in the Audit log UI.

test('J11 viewer is denied in UI and API; the denial is audited', async ({
  page,
  request,
}, info) => {
  test.setTimeout(120_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));

  // 1 — viewer signs in; read pages work, privileged pages show the forbidden state
  await signIn(page, 'user1@ppanel.local', SEED_PASSWORD, { next: '/servers' });
  await expect(page.getByRole('heading', { name: 'Servers', level: 1 })).toBeVisible();
  await page.goto('/servers/new');
  await expect(page.getByText('You don’t have access to this')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create one-time token' })).toHaveCount(0);
  await shot(page, info, 'j11-1-viewer-enroll-forbidden');
  await page.goto('/approvals');
  await expect(
    page.getByText('You can see pending approvals but need approvals.decide to approve.'),
  ).toBeVisible();
  evidence(info, 'viewer UI: enroll page forbidden, approvals read-only');
  await signOut(page);

  // 2 — the same operation sent straight to the API is refused (the UI is not the boundary)
  const viewer = await apiLogin(request, 'user1@ppanel.local');
  const me = await call<{ user: { id: string } }>(request, 'GET', '/auth/me', { token: viewer });
  const viewerId = me.body.data!.user.id;
  const denied = await call(request, 'POST', '/enrollments', {
    token: viewer,
    body: { name: 'j11-should-not-exist', environment: 'production', ttlMinutes: 5 },
  });
  expect(denied.status).toBe(403);
  expect(denied.body.error?.code).toBeTruthy();
  evidence(info, 'viewer POST /enrollments refused', {
    status: denied.status,
    code: denied.body.error?.code,
  });

  // 3 — the denial is in the audit log (API) and visible to the owner in the UI
  const admin = await apiLogin(request, 'superadmin@ppanel.local');
  const audit = await call<Array<{ action: string; result: string; actorId: string }>>(
    request,
    'GET',
    `/audit-events?actor_id=${viewerId}&limit=50`,
    { token: admin },
  );
  const row = audit.body.data?.find((e) => e.result === 'denied' && e.action === 'http.post');
  expect(row, JSON.stringify(audit.body).slice(0, 400)).toBeTruthy();
  const servers = await call<unknown[]>(request, 'GET', '/servers?q=j11-should-not-exist', {
    token: admin,
  });
  expect(servers.body.data ?? []).toHaveLength(0);

  await signIn(page, 'superadmin@ppanel.local', SEED_PASSWORD, {
    next: `/settings/audit?actor_id=${viewerId}`,
  });
  await expect(page.getByText('denied').first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText('http.post').first()).toBeVisible();
  await shot(page, info, 'j11-2-owner-sees-denied-audit');
  evidence(info, 'owner sees audit row result=denied for the viewer', { action: row!.action });
  expect(errors).toEqual([]);
});
