import { expect, test, type Page } from '@playwright/test';

// Runs against the dev server in mock mode (NEXT_PUBLIC_API_MOCK=1). Seed accounts: see src/mocks/seed.ts.
async function signIn(page: Page, user = 'admin') {
  await page.goto('/login');
  await page.getByLabel('Email').fill(user);
  await page.getByLabel('Password').fill('password');
  await page.getByRole('button', { name: 'Continue' }).click();
}

test('login page renders and screenshot', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.screenshot({ path: 'test-results/login.png', fullPage: true });
});

test('MFA login → servers cards grouped by environment', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page, 'superadmin');
  await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
  await page.screenshot({ path: 'test-results/login-mfa.png' });
  await page.getByLabel('Digit 1 of 6').fill('123456');
  await page.getByRole('button', { name: 'Confirm' }).click();
  // Dev mode: the first client navigation to a not-yet-compiled /overview can be dropped by the
  // dev server (same fallback as the p4/p4b/p5 signIn helpers); the session survives a reload.
  try {
    await expect(page).toHaveURL(/\/overview/, { timeout: 10_000 });
  } catch {
    await page.goto('/overview');
    await expect(page).toHaveURL(/\/overview/, { timeout: 20_000 });
  }
  await page.goto('/servers');
  await expect(page.getByTestId('server-card')).toHaveCount(8);
  await expect(page.getByText('PRODUCTION').nth(1)).toBeVisible();
  await expect(page.getByText(/not a network or firewall trust boundary/)).toBeVisible();
  await page.screenshot({ path: 'test-results/servers.png', fullPage: true });
  await page.getByRole('radio', { name: /UAT/ }).click();
  await expect(page.getByTestId('server-card')).toHaveCount(2);
});

test('server detail network tab, TH locale, preview banner', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page);
  await expect(page).toHaveURL(/\/overview/);
  await page.goto('/servers');
  await page.getByRole('link', { name: 'db-prod-01' }).first().click();
  await expect(page.getByRole('heading', { name: 'db-prod-01' })).toBeVisible();
  const tabs = page.getByRole('navigation', { name: 'Server sections' });
  await tabs.getByRole('link', { name: 'Network' }).click();
  await expect(page.getByText('Preferred management connection').first()).toBeVisible();
  await page.screenshot({ path: 'test-results/server-network.png', fullPage: true });
  await tabs.getByRole('link', { name: 'Firewall', exact: true }).click();
  await expect(page.getByText('Backend not implemented yet (PROPOSED)')).toBeVisible();
  await page.getByRole('radio', { name: 'TH' }).click();
  await expect(page.getByRole('link', { name: 'ภาพรวม' }).first()).toBeVisible();
  // /logs is real since P5 (no preview banner); /backups is still a preview.
  await page.goto('/logs');
  await expect(page.getByTestId('log-explorer')).toBeVisible();
  await expect(page.getByTestId('preview-banner')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'ค้นหา' })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem('ppanel.lang'))).toBe('th');
  await page.screenshot({ path: 'test-results/logs-th.png', fullPage: true });
  await page.goto('/backups');
  await expect(page.getByTestId('preview-banner')).toBeVisible();
});

test('enroll shows one-time token once', async ({ page }) => {
  await signIn(page);
  await expect(page).toHaveURL(/\/overview/);
  await page.goto('/servers/new');
  await page.getByLabel('Server name').fill('app-prod-09');
  await page.getByRole('button', { name: 'Create one-time token' }).click();
  await expect(page.getByText(/will not be shown again/)).toBeVisible();
  await expect(page.locator('pre')).toContainText('--token ppe_');
  await page.screenshot({ path: 'test-results/enroll-token.png' });
});

const PREVIEW_ROUTES = [
  '/network',
  '/firewall',
  '/ssh',
  '/plugins',
  '/runtimes',
  '/databases',
  '/backups',
  '/ai-mcp',
];

test('every preview route renders with the preview banner and no page errors', async ({ page }) => {
  test.setTimeout(180_000); // dev server compiles each route on first visit
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page);
  await expect(page).toHaveURL(/\/overview/);
  for (const r of PREVIEW_ROUTES) {
    await page.goto(r);
    await expect(page.getByTestId('preview-banner'), r).toBeVisible();
    await expect(page.locator('h1').first(), r).toBeVisible();
  }
  for (const r of [
    '/overview',
    '/monitoring',
    '/logs',
    '/alerts',
    '/applications',
    '/imports',
    '/settings/users',
    '/settings/audit',
    '/settings/security',
    '/servers/new',
  ]) {
    await page.goto(r);
    await expect(page.locator('h1').first(), r).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('viewer sees permission-gated enroll button disabled and users page forbidden', async ({
  page,
}) => {
  await signIn(page, 'user1');
  await expect(page).toHaveURL(/\/overview/);
  await page.goto('/servers');
  await expect(page.getByRole('button', { name: '+ Enroll server' })).toBeDisabled();
  await page.goto('/settings/users');
  await expect(page.getByText('You don’t have access to this')).toBeVisible();
});
