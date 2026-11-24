import { expect, test, type Page } from '@playwright/test';

// P9 journeys in mock mode (NEXT_PUBLIC_API_MOCK=1): server cards + filters, connection policy
// (fail closed, step-up, 422 PRIVATE_PATH_UNVERIFIED), diagnostics, groups (409 GROUP_NOT_EMPTY),
// topology findings, provider token (never shown again), inventory import, pair test, and the
// gateway change plan (validate → shadow test → second-person approval → apply → rollback, cutover).
// Fixtures: src/mocks/p9-routes.ts (state in sessionStorage, so page reloads keep it).

async function signIn(page: Page, user: string, next = '/overview') {
  await page.goto(`/login?next=${encodeURIComponent(next)}`);
  await page.waitForLoadState('networkidle');
  await page.getByLabel('Email').fill(user);
  await page.getByLabel('Password').fill('password');
  await page.getByRole('button', { name: 'Continue' }).click();
  if (user === 'superadmin') {
    await page.getByLabel('Digit 1 of 6').fill('123456');
    await page.getByRole('button', { name: 'Confirm' }).click();
  }
  const path = next.split('?')[0];
  try {
    await expect(page).toHaveURL((u) => u.pathname === path, { timeout: 10_000 });
  } catch {
    await page.goto(next);
    await expect(page).toHaveURL((u) => u.pathname === path, { timeout: 20_000 });
  }
}
async function signOut(page: Page) {
  await page.evaluate(() => sessionStorage.removeItem('ppanel.mock.session'));
}
const card = (page: Page, name: string) =>
  page.getByTestId('server-card').filter({ hasText: name });

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1100 });
});

test('server cards: env, group, verified private, path dots, honest VPC; filters by group/tag/policy', async ({
  page,
}) => {
  test.setTimeout(90_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'admin', '/servers');
  await expect(page.getByTestId('server-card')).toHaveCount(8, { timeout: 20_000 });
  const app = card(page, 'app-prod-01');
  await expect(app.getByTestId('card-group')).toHaveText('storefront');
  await expect(app.getByTestId('private-verified')).toHaveAttribute('data-verified', 'true');
  await expect(app.getByTestId('active-path')).toHaveAttribute('data-path', 'private');
  await expect(app.getByTestId('vpc-label')).toHaveAttribute('data-source', 'provider');
  await expect(app.getByTestId('vpc-label')).toContainText('prod-sgp1');
  const db = card(page, 'db-prod-01');
  await expect(db.getByTestId('active-path')).toHaveText(/fail closed/);
  await expect(db.locator('[data-path="private"][data-health="down"]')).toHaveCount(1);
  await expect(card(page, 'dev-01').getByTestId('vpc-label')).toHaveAttribute(
    'data-source',
    'unknown',
  );
  await expect(card(page, 'web-legacy-02').getByTestId('private-verified')).toHaveAttribute(
    'data-verified',
    'false',
  );

  await page.getByTestId('filter-policy').selectOption('private_only');
  await expect(page.getByTestId('server-card')).toHaveCount(2);
  await expect(page).toHaveURL(/policy=private_only/);
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await page.getByTestId('filter-group').selectOption({ label: 'storefront' });
  await expect(page.getByTestId('server-card')).toHaveCount(3);
  await page.getByTestId('filter-tag').selectOption('legacy');
  await expect(page.getByTestId('server-card')).toHaveCount(1);
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await page.getByRole('radio', { name: 'Table' }).click();
  await expect(page.getByRole('columnheader', { name: 'Group' })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'VPC' })).toBeVisible();
  await page.getByRole('radio', { name: 'Cards' }).click();
  await page.screenshot({ path: 'test-results/p9-server-cards.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('network tab: fail closed explained, step-up + 422 PRIVATE_PATH_UNVERIFIED, diagnostics run', async ({
  page,
}) => {
  test.setTimeout(120_000);
  await signIn(page, 'superadmin', '/servers');
  await page.getByRole('link', { name: 'db-prod-01' }).first().click();
  await page
    .getByRole('navigation', { name: 'Server sections' })
    .getByRole('link', { name: 'Network' })
    .click();
  await expect(page.getByTestId('fail-closed')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId('probe-private')).toHaveAttribute('data-health', 'down');
  await expect(page.getByTestId('region-card')).toContainText('prod-sgp1');

  await page.goto('/servers');
  await page.getByRole('link', { name: 'web-legacy-02' }).first().click();
  await page
    .getByRole('navigation', { name: 'Server sections' })
    .getByRole('link', { name: 'Network' })
    .click();
  const editor = page.getByTestId('policy-editor');
  await editor.getByRole('radio', { name: 'Private-only' }).click();
  await expect(editor.getByTestId('fail-closed-explain')).toContainText(
    'never dials the public endpoint',
  );
  await expect(editor.getByText(/PRIVATE_PATH_UNVERIFIED/)).toBeVisible();
  await expect(editor.getByTestId('save-policy')).toBeDisabled();
  await editor.getByLabel('2FA code').fill('123456');
  await editor.getByTestId('save-policy').click();
  await expect(editor.getByTestId('private-unverified-error')).toBeVisible({ timeout: 15_000 });
  await expect(editor).toContainText('PRIVATE_PATH_UNVERIFIED');
  await page.screenshot({ path: 'test-results/p9-policy-422.png', fullPage: true });

  // diagnostics on a healthy production server
  await page.goto('/servers');
  await page.getByRole('link', { name: 'app-prod-01' }).first().click();
  await page
    .getByRole('navigation', { name: 'Server sections' })
    .getByRole('link', { name: 'Network' })
    .click();
  const diag = page.getByTestId('diagnostics');
  await diag.getByLabel('Resolve hostnames').fill('center.ppanel.internal');
  await diag.getByLabel('TCP checks (IP:port)').fill('8.8.8.8:443');
  await diag.getByTestId('run-diagnostics').click();
  await expect(diag.getByText(/is not a private address/)).toBeVisible();
  await diag.getByLabel('TCP checks (IP:port)').fill('10.104.0.12:5432\n10.130.0.20:80');
  await diag.getByTestId('run-diagnostics').click();
  await expect(diag.getByTestId('test-status').first()).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 20_000,
    },
  );
  await expect(diag.getByTestId('diag-tcp')).toContainText('10.104.0.12:5432');
  await expect(diag.getByTestId('diag-tcp')).toContainText('DIAL_TIMEOUT');
  await expect(diag.getByTestId('diag-center')).toContainText('https://10.104.0.5:4444');
  await expect(page.getByTestId('health-history')).toContainText('diagnostics run');
});

test('groups: create, assign, 409 GROUP_NOT_EMPTY, remove, delete', async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page, 'superadmin', '/servers/groups');
  await expect(page.getByTestId('group-row')).toHaveCount(3, { timeout: 20_000 });
  const form = page.getByTestId('group-create-form');
  await form.getByLabel('Group name').fill('e2e-edge');
  await form.getByLabel('Environment').selectOption('uat');
  await form.getByRole('button', { name: 'Create group' }).click();
  await expect(page.getByTestId('group-row')).toHaveCount(4);
  await page.getByTestId('group-row').filter({ hasText: 'e2e-edge' }).click();
  const detail = page.getByTestId('group-detail');
  await detail.getByTestId('assign-server').selectOption({ label: 'app-uat-01' });
  await detail.getByRole('button', { name: 'Assign' }).click();
  await expect(detail.getByTestId('group-members')).toContainText('app-uat-01', {
    timeout: 15_000,
  });
  await detail.getByTestId('delete-group').click();
  await page.getByTestId('confirm-delete-group').click();
  await expect(page.getByTestId('group-not-empty')).toBeVisible();
  await expect(page.getByRole('dialog')).toContainText('GROUP_NOT_EMPTY');
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
  await detail.getByRole('button', { name: 'Remove app-uat-01 from the group' }).click();
  await expect(detail.getByText('No servers in this group.')).toBeVisible({ timeout: 15_000 });
  await detail.getByTestId('delete-group').click();
  await page.getByTestId('confirm-delete-group').click();
  await expect(page.getByTestId('group-row')).toHaveCount(3, { timeout: 15_000 });
});

test('network topology: real page, regions → VPCs with sources, findings', async ({ page }) => {
  test.setTimeout(60_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'user1', '/network');
  await expect(page.getByTestId('preview-banner')).toHaveCount(0);
  const navLink = page
    .getByRole('navigation', { name: 'Main navigation' })
    .getByRole('link', { name: /Network/ });
  await expect(navLink).toBeVisible();
  await expect(navLink).not.toContainText('preview');
  await expect(page.getByTestId('finding')).not.toHaveCount(0, { timeout: 20_000 });
  for (const code of ['VPC_UNKNOWN', 'SAME_REGION_DIFFERENT_VPC', 'INVENTORY_MISMATCH'])
    await expect(page.locator(`[data-testid="finding"][data-code="${code}"]`)).toHaveCount(1);
  const region = page.locator('[data-testid="topology-region"][data-region="sgp1"]');
  await expect(region.getByTestId('topology-vpc')).toHaveCount(4);
  await expect(region.locator('[data-vpc="prod-sgp1"]')).toContainText('provider');
  await expect(region.locator('[data-vpc="uat-sgp1"]')).toContainText('inventory');
  await expect(region.locator('[data-vpc="unknown"]')).toContainText('dev-01');
  await page.screenshot({ path: 'test-results/p9-topology.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('provider token with step-up is never shown again; inventory import with validation preview', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await signIn(page, 'superadmin', '/network/providers');
  await expect(page.getByTestId('integration-row')).toHaveCount(1, { timeout: 20_000 });
  const add = page.getByTestId('add-integration');
  await add.getByLabel('Name').fill('do-e2e');
  const token = 'dop_v1_e2e_0123456789abcdef';
  await add.getByLabel('API token').fill(token);
  await add.getByLabel('2FA code').fill('123456');
  await add.getByRole('button', { name: 'Validate and save' }).click();
  await expect(add.getByTestId('token-never-again')).toBeVisible({ timeout: 15_000 });
  await expect(add.getByLabel('API token')).toHaveValue('');
  await expect(page.getByTestId('integration-row')).toHaveCount(2);
  expect(await page.content()).not.toContain(token);
  const row = page.getByTestId('integration-row').filter({ hasText: 'do-e2e' });
  await expect(row.getByTestId('last-sync')).toContainText('never');
  await row.getByTestId('sync-integration').click();
  await expect(row.getByTestId('last-sync')).not.toContainText('never', { timeout: 15_000 });

  await page.goto('/network/inventory');
  const json = page.getByTestId('inventory-json');
  await json.fill('[{ "hostname": "dev-01", "colour": "red" }, { "privateIpv4": "10.0.0.1" }]');
  await expect(page.getByTestId('inventory-issue-count')).toContainText('2 problem');
  await expect(page.getByTestId('inventory-issues')).toContainText('colour');
  await expect(page.getByTestId('inventory-import')).toBeDisabled();
  await json.fill(
    '[{ "hostname": "dev-01", "region": "sgp1", "vpcUuid": "9e7a6b54-1c2d-4e3f-8a9b-0c1d2e3f4a5b", "vpcName": "dev-sgp1" }, { "hostname": "dev-sandbox-02", "region": "sgp1", "vpcUuid": "9e7a6b54-1c2d-4e3f-8a9b-0c1d2e3f4a5b", "vpcName": "dev-sgp1" }]',
  );
  await expect(page.getByTestId('inventory-issue-count')).toContainText('0 problem');
  await page.getByTestId('inventory-import').click();
  await expect(page.getByTestId('inventory-done')).toContainText('Imported 2 row(s)');
  await page
    .getByRole('navigation', { name: 'Network sections' })
    .getByRole('link', { name: 'Topology' })
    .click();
  const region = page.locator('[data-testid="topology-region"][data-region="sgp1"]');
  await expect(region.locator('[data-vpc="dev-sgp1"]')).toContainText('dev-01', {
    timeout: 20_000,
  });
  await expect(page.locator('[data-testid="finding"][data-code="VPC_UNKNOWN"]')).toHaveCount(0);
});

test('pair connectivity test: same VPC reachable, different VPCs not', async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page, 'superadmin', '/network/connectivity');
  const form = page.getByTestId('pair-form');
  await form.getByLabel('From server').selectOption({ label: 'dev-01' });
  await form
    .getByLabel('To server (private IPv4)')
    .selectOption({ label: 'dev-sandbox-02 · 10.120.0.4' });
  await form.getByTestId('run-pair').click();
  await expect(page.getByTestId('pair-verdict').first()).toHaveAttribute('data-reachable', 'true', {
    timeout: 20_000,
  });
  await form.getByLabel('From server').selectOption({ label: 'app-prod-01' });
  await form
    .getByLabel('To server (private IPv4)')
    .selectOption({ label: 'web-legacy-02 · 10.130.0.20' });
  await form.getByLabel('Port').selectOption('80');
  await expect(form.getByTestId('pair-vpcs')).toContainText('Different VPCs');
  await form.getByTestId('run-pair').click();
  const verdict = page.getByTestId('pair-verdict').first();
  await expect(verdict).toHaveAttribute('data-reachable', 'false', { timeout: 20_000 });
  await expect(verdict).toContainText('different VPCs');
});

test('gateway change plan: validate → shadow test → second-person approval → apply → rollback', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await signIn(page, 'admin', '/network/gateways');
  await expect(page.getByTestId('never-dns')).toContainText('never edits DNS');
  await expect(page.getByTestId('mode-legend')).toContainText('DNS still points at the app server');
  await page.getByRole('link', { name: 'edge-prod-sgp1' }).click();
  await expect(page.getByTestId('route-row')).toHaveCount(3, { timeout: 20_000 });
  await expect(
    page.locator('[data-testid="route-row"][data-domain="api.w3.co"]').getByTestId('route-mode'),
  ).toHaveAttribute('data-mode', 'direct');
  await page.getByTestId('create-plan').click();
  await expect(page).toHaveURL(/\/network\/gateways\/[^/]+\/plans\/[^/]+$/, { timeout: 20_000 });
  const planUrl = new URL(page.url()).pathname;
  const detail = page.getByTestId('plan-detail');
  await expect(detail).toHaveAttribute('data-status', 'validated', { timeout: 20_000 });
  await expect(page.getByTestId('validation-result')).toHaveText('Configuration test passed');
  await expect(page.getByTestId('apply-plan')).toBeDisabled();
  await page.getByTestId('run-shadow').click();
  await expect(detail).toHaveAttribute('data-status', 'awaiting_approval', { timeout: 20_000 });
  await expect(page.locator('[data-testid="shadow-match"][data-match="false"]')).toHaveCount(1);
  await expect(page.getByTestId('shadow-mismatch')).toBeVisible();
  // requester cannot approve their own plan
  await expect(page.getByTestId('waiting-approver')).toContainText('you created this plan');
  await expect(page.getByRole('button', { name: /Approve plan/ })).toHaveCount(0);
  await expect(page.getByTestId('cutover-never-dns')).toBeVisible();
  await expect(page.getByTestId('cutover-no-dns')).toBeVisible(); // routes are hybrid
  await expect(page.getByTestId('cutover-rollback').locator('li')).not.toHaveCount(0);
  await page.screenshot({ path: 'test-results/p9-plan-awaiting.png', fullPage: true });

  await signOut(page);
  await signIn(page, 'superadmin', planUrl);
  await expect(detail).toHaveAttribute('data-status', 'awaiting_approval', { timeout: 20_000 });
  await page.getByTestId('plan-approval').getByLabel('2FA code').fill('123456');
  await page.getByRole('button', { name: /Approve plan/ }).click();
  await expect(page.getByTestId('plan-approval')).toContainText('Super Admin', { timeout: 15_000 });
  await page.getByTestId('apply-plan').click();
  const dlg = page.getByRole('dialog');
  await dlg.getByLabel('2FA code').fill('123456');
  await dlg.getByRole('button', { name: 'Apply plan' }).click();
  await expect(detail).toHaveAttribute('data-status', 'applied', { timeout: 20_000 });
  await expect(page.locator('[data-step="apply"]')).toHaveAttribute('data-state', 'done');
  await page.getByTestId('rollback-plan').click();
  await dlg.getByLabel('2FA code').fill('123456');
  await dlg.getByRole('button', { name: 'Roll back' }).click();
  await expect(detail).toHaveAttribute('data-status', 'rolled_back', { timeout: 20_000 });
});

test('gateway routes: add a Gateway-mode route; non-production plan needs no approval; DNS checklist', async ({
  page,
}) => {
  test.setTimeout(150_000);
  await signIn(page, 'superadmin', '/network/gateways');
  await page.getByRole('link', { name: 'edge-dev' }).click();
  await expect(page.getByTestId('route-row')).toHaveCount(1, { timeout: 20_000 });
  await page.getByTestId('add-route').click();
  const form = page.getByTestId('route-form');
  await form.getByLabel('Domain').fill('not a domain');
  await form.getByRole('button', { name: 'Add route' }).click();
  await expect(form.getByText('Enter a domain such as shop.example.com.')).toBeVisible();
  await form.getByLabel('Domain').fill('blog.dev.w3.co');
  await form.getByRole('radio', { name: 'Gateway' }).click();
  await expect(form.getByTestId('mode-explain')).toContainText(
    'DNS is expected to point at the gateway',
  );
  await form.getByLabel('Server').selectOption({ label: 'dev-01' });
  await expect(form.getByText(/Blank = preferred private IPv4 10\.120\.0\.3/)).toBeVisible();
  await form.getByLabel('Port').fill('3000');
  await form.getByRole('button', { name: 'Add route' }).click();
  await expect(page.getByTestId('route-row')).toHaveCount(2, { timeout: 15_000 });
  await page.getByTestId('create-plan').click();
  const detail = page.getByTestId('plan-detail');
  await expect(detail).toHaveAttribute('data-status', 'validated', { timeout: 20_000 });
  await page.getByTestId('run-shadow').click();
  await expect(detail).toHaveAttribute('data-status', 'shadow_tested', { timeout: 20_000 });
  await expect(page.getByText('No approval required (non-production gateway).')).toBeVisible();
  await expect(page.locator('[data-step="approval"]')).toHaveAttribute('data-state', 'skipped');
  await expect(page.getByTestId('cutover')).toContainText('blog.dev.w3.co. A 178.128.40.7');
  await page.getByTestId('apply-plan').click();
  await page.getByRole('dialog').getByRole('button', { name: 'Apply plan' }).click();
  await expect(detail).toHaveAttribute('data-status', 'applied', { timeout: 20_000 });
});

test('viewer: network pages readable, mutating actions disabled', async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page, 'user1', '/network/gateways');
  await page.getByRole('link', { name: 'edge-prod-sgp1' }).click();
  await expect(page.getByTestId('route-row')).toHaveCount(3, { timeout: 20_000 });
  await expect(page.getByTestId('create-plan')).toBeDisabled();
  await expect(page.getByTestId('add-route')).toBeDisabled();
  await page.goto('/network/providers');
  await expect(page.getByTestId('integration-row')).toHaveCount(1, { timeout: 20_000 });
  await expect(page.getByRole('button', { name: 'Validate and save' })).toBeDisabled();
  await expect(page.getByTestId('sync-integration')).toBeDisabled();
  await page.goto('/servers/groups');
  await expect(page.getByRole('button', { name: 'Create group' })).toBeDisabled();
  await page.getByRole('radio', { name: 'TH' }).click();
  await expect(page.getByRole('heading', { name: 'กลุ่มเซิร์ฟเวอร์', level: 1 })).toBeVisible();
});
