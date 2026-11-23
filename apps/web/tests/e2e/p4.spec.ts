import { expect, test, type Page } from '@playwright/test';

// P4a journeys in mock mode (NEXT_PUBLIC_API_MOCK=1). Mock state lives in sessionStorage and the mock
// picks the candidate outcome from the digest prefix (dead… = unhealthy).

const HEX = (c: string) => c.repeat(64).slice(0, 64);
const OK_DIGEST = `sha256:${HEX('a1b2')}`;
const UNHEALTHY_DIGEST = `sha256:dead${HEX('7c').slice(4)}`;

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
  try {
    await expect(page).toHaveURL((u) => u.pathname === next.split('?')[0], { timeout: 10_000 });
  } catch {
    await page.goto(next);
    await expect(page).toHaveURL((u) => u.pathname === next.split('?')[0], { timeout: 20_000 });
  }
}
async function signOut(page: Page) {
  await page.evaluate(() => sessionStorage.removeItem('ppanel.mock.session'));
}
const ORDER = ['source', 'detect', 'target', 'configure', 'domain', 'review'];
/** Click Next and wait until the wizard shows the following step (avoids lost clicks). */
async function next(page: Page) {
  const wiz = page.getByTestId('wizard');
  const cur = (await wiz.getAttribute('data-step')) ?? 'source';
  const want = ORDER[ORDER.indexOf(cur) + 1]!;
  const btn = page.getByRole('button', { name: 'Next →' });
  await expect(btn).toBeEnabled();
  // Dev server only: a click right after a step change can be swallowed by a re-render; retry.
  await expect(async () => {
    if ((await wiz.getAttribute('data-step')) !== want) await btn.click({ timeout: 2000 });
    await expect(wiz).toHaveAttribute('data-step', want, { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
}
const stepHeading = (page: Page, name: string) =>
  expect(page.getByTestId('wizard')).toHaveAttribute('data-step', name);

/** Opens the wizard for an existing container app (Deploy from application). */
async function openAppWizard(page: Page, appName: string) {
  await page.goto('/applications');
  await page.getByRole('link', { name: appName, exact: true }).click();
  await expect(page.getByRole('heading', { name: appName, level: 1 })).toBeVisible();
  await page.getByTestId('app-deploy').click();
  await expect(page).toHaveURL(/\/deployments\/new\?app=/);
  await stepHeading(page, 'source');
}

test('J04: registry image → configure with secret → domain → preflight green → deploy → succeeded', async ({
  page,
}) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 1100 });
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'admin', '/deployments/new');
  await stepHeading(page, 'source');
  await expect(page.locator('[aria-current="step"]')).toHaveText(/Source/);

  // Next stays disabled until the image is pinned; a tag needs a pasted digest.
  await expect(page.getByRole('button', { name: 'Next →' })).toBeDisabled();
  await page.getByLabel('Repository').fill('registry.example.lab/w3/shop-web');
  await page.getByLabel('Tag or digest').fill('v1.4.2');
  await expect(page.getByTestId('tag-resolution')).toContainText('must resolve to a digest');
  await expect(page.getByRole('button', { name: 'Next →' })).toBeDisabled();
  await page
    .getByLabel('Paste digest reference')
    .fill(`registry.example.lab/w3/shop-web@${OK_DIGEST}`);
  await next(page);

  await stepHeading(page, 'detect');
  await expect(page.getByRole('heading', { name: /Detect/, level: 2 })).toBeFocused();
  await page
    .getByLabel('Paste package.json')
    .fill('{"dependencies":{"next":"15.0.3"},"scripts":{"build":"next build"}}');
  await expect(page.getByTestId('detected-framework')).toHaveText('Next.js');
  await next(page);

  await stepHeading(page, 'target');
  await expect(page.getByRole('radio', { name: 'worker-uat-01' })).toBeDisabled();
  await page.getByRole('radio', { name: 'app-uat-01' }).check();
  await expect(page.getByTestId('managed-routing')).toHaveAttribute('data-status', 'enabled');
  await next(page);

  await stepHeading(page, 'configure');
  await page.getByLabel('Application name').fill('shop-web');
  await expect(page.getByLabel('Container port')).toHaveValue('8080');
  await page.getByRole('button', { name: '+ Add secret' }).click();
  await page.getByLabel('Secret name').fill('SESSION_SECRET');
  await expect(page.getByRole('button', { name: 'Next →' })).toBeDisabled();
  await page.getByLabel('SESSION_SECRET', { exact: true }).fill('super-secret-session-value');
  await page.getByTestId('secret-row').getByRole('button', { name: 'Use value' }).click();
  await expect(page.getByTestId('secret-row').getByTestId('secret-status')).toContainText(
    'entered',
  );
  expect(await page.content()).not.toContain('super-secret-session-value');
  await page.getByRole('button', { name: '+ Add volume' }).click();
  await page.getByLabel('Volume name').fill('/var/lib/data');
  await expect(page.getByText('Host paths are not allowed')).toBeVisible();
  await page.getByLabel('Volume name').fill('uploads');
  await page.getByLabel('Mount path in container').fill('/app/uploads');
  await next(page);

  await stepHeading(page, 'domain');
  await page.getByLabel('Hostname 1').fill('shop-web.uat.example.lab');
  await expect(page.getByText('no conflict in inventory')).toBeVisible();
  await next(page);

  await stepHeading(page, 'review');
  await expect(page.getByTestId('deploy-button')).toBeDisabled();
  await page.getByRole('button', { name: 'Create application & run preflight' }).click();
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('preflight-check')).toHaveCount(8);
  await expect(page.getByTestId('plan-image')).toHaveText(
    `registry.example.lab/w3/shop-web@${OK_DIGEST}`,
  );
  await expect(page.getByTestId('risk-flags')).toContainText('rollback never restores volume data');
  expect(await page.content()).not.toContain('super-secret-session-value');
  await expect(page.getByTestId('deploy-button')).toBeEnabled();
  await page.screenshot({ path: 'test-results/p4-wizard-review.png', fullPage: true });
  await page.getByTestId('deploy-button').click();

  await stepHeading(page, 'execution');
  await expect(page.getByTestId('deployment-step').first()).toBeVisible();
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 20_000,
    },
  );
  await expect(page.getByTestId('outcome')).toHaveAttribute('data-outcome', 'succeeded');
  await expect(
    page.locator('[data-testid="deployment-step"][data-status="succeeded"]'),
  ).toHaveCount(5);
  await page.screenshot({ path: 'test-results/p4-execution-timeline.png', fullPage: true });

  // Secret shows as set ✓ v1 on the application, never the value.
  const appHref = await page
    .getByTestId('deployment-execution')
    .locator('a[href^="/applications/"]')
    .first()
    .getAttribute('href');
  await page.goto(appHref!.replace(/\/deployments$/, '/env'));
  await expect(page.getByTestId('secrets-card').getByTestId('secret-status').first()).toContainText(
    'set ✓ v1',
  );
  expect(await page.content()).not.toContain('super-secret-session-value');
  expect(errors).toEqual([]);
});

test('unhealthy candidate: deployment fails and the live version is untouched', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page, 'admin', '/applications');
  await openAppWizard(page, 'shop-api');
  await page.getByLabel('Tag or digest').fill(UNHEALTHY_DIGEST);
  for (let i = 0; i < 5; i++) await next(page); // detect, target, configure, domain, review
  await stepHeading(page, 'review');
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('deploy-button').click();
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute('data-status', 'failed', {
    timeout: 20_000,
  });
  await expect(page.getByTestId('outcome')).toHaveAttribute('data-code', 'CANDIDATE_UNHEALTHY');
  await expect(page.getByTestId('live-untouched')).toContainText('Live version untouched');
  await expect(page.getByTestId('unhealthy-details')).toContainText('candidate removed');
  await expect(page.locator('[data-step="route_switch"]')).toHaveAttribute(
    'data-status',
    'skipped',
  );
  await page.screenshot({ path: 'test-results/p4-failed-candidate.png', fullPage: true });
});

test('preflight blocked: agent offline, no port, domain conflict → Deploy disabled', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page, 'admin', '/applications');

  for (const [app, check, code] of [['queue-worker', 'agent_online', 'AGENT_OFFLINE']] as const) {
    await openAppWizard(page, app);
    await page.getByLabel('Tag or digest').fill(OK_DIGEST);
    for (let i = 0; i < 5; i++) await next(page);
    await expect(page.getByTestId('preflight-blocked')).toBeVisible({ timeout: 15_000 });
    const row = page.locator(`[data-testid="preflight-check"][data-check="${check}"]`);
    await expect(row).toHaveAttribute('data-ok', 'false');
    await expect(row).toContainText(code);
    await expect(page.getByTestId('deploy-button')).toBeDisabled();
    await expect(page.getByTestId('deploy-blocked-reason')).toContainText(
      'while any preflight check fails',
    );
  }

  // dev-sandbox-02 has no free managed port (admin cannot deploy to development → use superadmin).
  await signOut(page);
  await signIn(page, 'superadmin', '/applications');
  await openAppWizard(page, 'sandbox-api');
  await page.getByLabel('Tag or digest').fill(OK_DIGEST);
  for (let i = 0; i < 5; i++) await next(page);
  const port = page.locator('[data-testid="preflight-check"][data-check="port_alloc"]');
  await expect(port).toHaveAttribute('data-ok', 'false', { timeout: 15_000 });
  await expect(port).toContainText('NO_PORT_AVAILABLE');
  await expect(page.getByTestId('deploy-button')).toBeDisabled();

  // New app with a domain already served by another application → DOMAIN_CONFLICT at creation.
  await page.goto('/deployments/new');
  await page.getByLabel('Repository').fill('registry.example.lab/w3/api2');
  await page.getByLabel('Tag or digest').fill(OK_DIGEST);
  await next(page);
  await next(page);
  await page.getByRole('radio', { name: 'app-uat-01' }).check();
  await next(page);
  await page.getByLabel('Application name').fill('api2');
  await next(page);
  await page.getByLabel('Hostname 1').fill('api.example.lab');
  await expect(page.getByTestId('domain-conflict')).toContainText('in use by');
  await next(page);
  await page.getByRole('button', { name: 'Create application & run preflight' }).click();
  const dom = page.locator('[data-testid="preflight-check"][data-check="domain_conflict"]');
  await expect(dom).toHaveAttribute('data-ok', 'false', { timeout: 15_000 });
  await expect(
    page.getByRole('alert').filter({ hasText: 'DOMAIN_CONFLICT' }).first(),
  ).toBeVisible();
  await expect(page.getByTestId('deploy-button')).toBeDisabled();
});

test('malicious compose shows violations with rule and path', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page, 'admin', '/deployments/new');
  await page.getByRole('radio', { name: /Compose/ }).check({ force: true });
  await expect(page.getByTestId('compose-risk')).toContainText('never restores volumes');
  await page
    .getByLabel('docker-compose.yml')
    .fill(
      [
        'services:',
        '  web:',
        '    image: nginx:latest',
        '    privileged: true',
        '    network_mode: host',
        '    cap_add:',
        '      - SYS_ADMIN',
        '    ports:',
        '      - "0.0.0.0:80:80"',
        '    volumes:',
        '      - /var/run/docker.sock:/var/run/docker.sock',
        '      - /etc:/host-etc',
      ].join('\n'),
    );
  await expect(page.getByTestId('compose-result')).toHaveAttribute('data-valid', 'false', {
    timeout: 10_000,
  });
  for (const rule of [
    'privileged',
    'host_network',
    'cap_add',
    'port_non_loopback',
    'docker_socket',
    'host_bind',
    'image_not_pinned',
  ])
    await expect(
      page.locator(`[data-testid="compose-violation"][data-rule="${rule}"]`).first(),
    ).toBeVisible();
  await expect(page.locator('[data-rule="privileged"]').first()).toContainText(
    'services.web.privileged',
  );
  await expect(page.getByRole('button', { name: 'Next →' })).toBeDisabled();
  await page.screenshot({ path: 'test-results/p4-compose-violations.png', fullPage: true });
});

test('rollback from history: distinct lifecycle actions, rollback never restores data', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1100 });
  await signIn(page, 'admin', '/applications');
  await page.getByRole('link', { name: 'shop-api', exact: true }).click();
  await page
    .getByRole('navigation', { name: 'Application sections' })
    .getByRole('link', { name: 'Deployments' })
    .click();
  await expect(page.getByTestId('marker-current')).toBeVisible();
  await expect(page.getByTestId('marker-previous')).toBeVisible();
  const effects = await page.getByTestId('lifecycle-effect').allTextContents();
  expect(effects).toHaveLength(5);
  expect(new Set(effects).size).toBe(5);
  const rb = page.locator('[data-testid="lifecycle-action"][data-action="rollback"]');
  await expect(rb).toContainText('Rollback never restores data');
  await rb.getByRole('button', { name: 'Rollback' }).click();
  const dlg = page.getByRole('dialog');
  await expect(dlg).toContainText('Rollback never restores data, volumes or databases.');
  await expect(dlg).toContainText('Target: deployment #2');
  await dlg.getByRole('button', { name: 'Rollback' }).click();
  await expect(page).toHaveURL(/\/deployments\/[0-9a-f-]+$/);
  await expect(page.getByTestId('trigger-badge').first()).toHaveText('rollback');
  await expect(page.locator('[data-step="start_target"]')).toBeVisible();
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 20_000,
    },
  );
});

test('production deploy waits for approval; the creator cannot approve', async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 1100 });
  await signIn(page, 'admin', '/applications');
  await openAppWizard(page, 'storefront');
  await page.getByLabel('Tag or digest').fill(OK_DIGEST);
  for (let i = 0; i < 5; i++) await next(page);
  await expect(page.getByTestId('approval-notice')).toContainText('another approver with 2FA');
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Request deployment' }).click();
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'awaiting_approval',
  );
  await expect(page.getByTestId('waiting-approver')).toContainText('creator cannot approve');
  await expect(page.getByRole('button', { name: /Approve plan/ })).toHaveCount(0);
  await page.getByRole('link', { name: 'Open deployment page →' }).click();
  await expect(page).toHaveURL(/\/deployments\/[0-9a-f-]{36}$/, { timeout: 20_000 });
  const depUrl = new URL(page.url()).pathname;

  // Approvals lists it (and the seeded billing-api request).
  await page.goto('/approvals');
  await expect(page.getByTestId('approval-item')).toHaveCount(2);

  await signOut(page);
  await signIn(page, 'superadmin', depUrl);
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'awaiting_approval',
  );
  await page.getByTestId('approval-panel').getByLabel('2FA code').fill('123456');
  await page.getByRole('button', { name: /Approve plan/ }).click();
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 25_000,
    },
  );
});

test('webhook integration: delivery history renders; created secret is never shown back', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page, 'superadmin', '/settings/integrations');
  await expect(page.getByText('GitHub App: BLOCKED')).toBeVisible();
  const rows = page.getByTestId('delivery-row');
  await expect(rows).toHaveCount(8);
  for (const r of ['deployed', 'ignored', 'duplicate', 'invalid', 'awaiting_approval'])
    await expect(
      page.locator(`[data-testid="delivery-result"][data-result="${r}"]`).first(),
    ).toBeVisible();
  await expect(page.getByText('(no_matching_policy)')).toBeVisible();
  await page.getByRole('button', { name: '+ Add webhook integration' }).click();
  await page.getByLabel('Name').fill('lab repos');
  await page.getByLabel('Webhook secret').fill('whsec-0123456789abcdef');
  await page.getByRole('button', { name: 'Create integration' }).click();
  await expect(page.getByTestId('webhook-url')).toContainText('/api/v1/webhooks/github/');
  expect(await page.content()).not.toContain('whsec-0123456789abcdef');
  await page.screenshot({ path: 'test-results/p4-integrations.png', fullPage: true });
});
