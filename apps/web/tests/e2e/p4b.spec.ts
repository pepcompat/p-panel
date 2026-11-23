import { expect, test, type Page } from '@playwright/test';

// P4b journeys in mock mode (NEXT_PUBLIC_API_MOCK=1). The mock picks the build outcome from the
// commit SHA prefix (dead… = failed image build) and progresses builds/deployments by wall clock.

const OK_SHA = '3f9c2a1b7e4d5c6f8a9b0c1d2e3f4a5b6c7d8e9f';
const BAD_SHA = `dead${'4'.repeat(36)}`;
const HEX = (c: string) => c.repeat(64).slice(0, 64);

async function signIn(page: Page, user: string, next = '/overview') {
  await page.goto(`/login?next=${encodeURIComponent(next)}`);
  await page.waitForLoadState('networkidle');
  await page.getByLabel('Email').fill(user);
  await page.getByLabel('Password').fill('password');
  await page.getByRole('button', { name: 'Continue' }).click();
  try {
    await expect(page).toHaveURL((u) => u.pathname === next.split('?')[0], { timeout: 10_000 });
  } catch {
    await page.goto(next);
    await expect(page).toHaveURL((u) => u.pathname === next.split('?')[0], { timeout: 20_000 });
  }
}
const ORDER = ['source', 'detect', 'target', 'configure', 'domain', 'review'];
async function next(page: Page) {
  const wiz = page.getByTestId('wizard');
  const cur = (await wiz.getAttribute('data-step')) ?? 'source';
  const want = ORDER[ORDER.indexOf(cur) + 1]!;
  const btn = page.getByRole('button', { name: 'Next →' });
  await expect(btn).toBeEnabled({ timeout: 15_000 });
  await expect(async () => {
    if ((await wiz.getAttribute('data-step')) !== want) await btn.click({ timeout: 2000 });
    await expect(wiz).toHaveAttribute('data-step', want, { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
}
const stepIs = (page: Page, name: string) =>
  expect(page.getByTestId('wizard')).toHaveAttribute('data-step', name);

async function openApp(page: Page, name: string) {
  await page.goto('/applications');
  await page.getByRole('link', { name, exact: true }).click();
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}
async function openAppWizard(page: Page, name: string) {
  await openApp(page, name);
  await page.getByTestId('app-deploy').click();
  await expect(page).toHaveURL(/\/deployments\/new\?app=/);
  await stepIs(page, 'source');
}

async function gitToReview(page: Page, sha: string) {
  await openAppWizard(page, 'shop-api');
  await page.getByRole('radio', { name: /Git source/ }).check({ force: true });
  const git = page.getByTestId('git-source');
  await expect(git).toBeVisible();
  // Prefilled from the stored build config.
  await expect(page.getByLabel('Repository URL')).toHaveValue(
    'https://github.com/w3co/shop-api.git',
  );
  await expect(page.getByTestId('git-allowlist')).toHaveAttribute('data-allow', 'allowed');
  await expect(page.getByTestId('secret-args-note')).toContainText(
    'Secret build args are not supported',
  );
  await expect(
    page.locator('[data-testid="build-node"][data-server="app-prod-01"]'),
  ).toHaveAttribute('data-eligible', 'false');
  await page.getByLabel('Commit SHA').fill(sha.slice(0, 7));
  await expect(git.getByRole('alert').filter({ hasText: 'Short SHA' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next →' })).toBeDisabled();
  await page.getByLabel('Commit SHA').fill(sha);
  return git;
}

test('Git source → inspect → live build log → deploy succeeded', async ({ page }) => {
  test.setTimeout(150_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'admin', '/applications');
  await gitToReview(page, OK_SHA);
  await page.screenshot({ path: 'test-results/p4b-git-source.png', fullPage: true });
  await next(page);

  await stepIs(page, 'detect');
  await page.getByTestId('inspect-button').click();
  await expect(page.getByTestId('inspected-framework')).toHaveText('NestJS', { timeout: 15_000 });
  await expect(page.getByTestId('inspected-files')).toContainText('nest-cli.json');
  await expect(page.getByTestId('detected-framework')).toHaveText('NestJS');
  for (let i = 0; i < 4; i++) await next(page); // target, configure, domain, review

  await stepIs(page, 'review');
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('build-flow')).toContainText(
    '→ push registry.example.lab/w3/shop-api → deploy digest',
  );
  await expect(page.getByTestId('plan-commit')).toContainText(OK_SHA);
  await page.getByTestId('build-deploy-button').click();

  await stepIs(page, 'execution');
  const exec = page.getByTestId('build-execution');
  await expect(exec).toHaveAttribute('data-status', 'building', { timeout: 10_000 });
  await expect(page.getByTestId('build-log-text')).toContainText('git fetch --depth 1', {
    timeout: 10_000,
  });
  await expect(page.getByTestId('build-cancel')).toBeVisible();
  await page.screenshot({ path: 'test-results/p4b-build-log.png', fullPage: true });
  await expect(exec).toHaveAttribute('data-status', 'succeeded', { timeout: 20_000 });
  await expect(page.getByTestId('build-image')).toContainText(
    'registry.example.lab/w3/shop-api@sha256:',
  );
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 25_000,
    },
  );

  // Builds tab lists it with the linked deployment.
  await openApp(page, 'shop-api');
  await page.getByRole('link', { name: 'Builds', exact: true }).click();
  await expect(page.getByTestId('build-row').first()).toHaveAttribute('data-status', 'succeeded');
  await expect(page.getByTestId('build-row').first()).toContainText('#5');
  expect(errors).toEqual([]);
});

test('failed image build: no deployment created, live version untouched', async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 1100 });
  await signIn(page, 'admin', '/applications');
  await gitToReview(page, BAD_SHA);
  for (let i = 0; i < 5; i++) await next(page);
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('build-deploy-button').click();
  const exec = page.getByTestId('build-execution');
  await expect(exec).toHaveAttribute('data-status', 'failed', { timeout: 20_000 });
  await expect(page.getByTestId('build-failed')).toContainText('No deployment was created');
  await expect(page.getByTestId('live-untouched')).toContainText('Live version untouched');
  await expect(page.getByTestId('build-log-text')).toContainText('exit code: 2');
  await expect(page.locator('[data-phase="building"]')).toHaveAttribute('data-state', 'failed');
  await expect(page.getByTestId('deployment-execution')).toHaveCount(0);
});

const COMPOSE = `services:
  app:
    image: registry.example.lab/w3/wiki@sha256:${HEX('ab12')}
    environment:
      DB_HOST: db
      DB_PASSWORD: \${DB_PASSWORD}
    depends_on: [db]
  db:
    image: postgres@sha256:${HEX('5a1d')}
    environment:
      POSTGRES_PASSWORD: \${DB_PASSWORD}
    volumes:
      - wikidata:/var/lib/postgresql/data
volumes:
  wikidata: {}
`;

test('compose create with secret placeholder → deploy → per-service actions', async ({ page }) => {
  test.setTimeout(150_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/deployments/new');
  await stepIs(page, 'source');
  await page.getByRole('radio', { name: /Compose/ }).check({ force: true });
  await page.getByTestId('compose-yaml').fill(COMPOSE);
  await expect(page.getByTestId('compose-result')).toHaveAttribute('data-valid', 'true', {
    timeout: 10_000,
  });
  await page.getByLabel('Route port (in container)').fill('3000');
  await expect(
    page.locator('[data-testid="compose-detected-row"][data-service="db"]'),
  ).toHaveAttribute('data-health', 'tcp');
  await expect(
    page.locator('[data-testid="compose-detected-row"][data-service="app"]'),
  ).toHaveAttribute('data-health', 'http');
  await expect(page.getByTestId('compose-risk')).toContainText(
    'never restores volumes or database data',
  );
  await expect(page.getByTestId('placeholders-missing')).toContainText('DB_PASSWORD');
  await expect(page.getByRole('button', { name: 'Next →' })).toBeDisabled();
  const ph = page.locator('[data-testid="compose-placeholder"][data-key="DB_PASSWORD"]').first();
  await ph.locator('input[type="password"]').fill('wiki-db-secret-value');
  await ph.getByRole('button', { name: 'Use value' }).click();
  await expect(
    page.locator('[data-testid="compose-placeholder"][data-status="missing"]'),
  ).toHaveCount(0);
  expect(await page.content()).not.toContain('wiki-db-secret-value');
  await next(page);
  await next(page); // target
  await page.getByRole('radio', { name: 'app-uat-01' }).check();
  await next(page);
  await page.getByLabel('Application name').fill('wiki');
  await next(page);
  await page.getByLabel('Hostname 1').fill('wiki.uat.example.lab');
  await next(page);

  await stepIs(page, 'review');
  await expect(page.locator('[data-testid="compose-plan-row"]')).toHaveCount(2);
  await expect(page.locator('[data-testid="compose-plan-row"][data-action="created"]')).toHaveCount(
    2,
  );
  await expect(page.getByTestId('risk-flags')).toContainText('dataRestored: false');
  await page.getByTestId('compose-prepare').click();
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await page.screenshot({ path: 'test-results/p4b-compose-plan.png', fullPage: true });
  await page.getByTestId('deploy-button').click();

  await stepIs(page, 'execution');
  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 25_000,
    },
  );
  await expect(
    page.locator('[data-testid="compose-service-row"][data-action="created"]'),
  ).toHaveCount(2);
  await expect(page.locator('[data-step="compose_apply"]')).toHaveAttribute(
    'data-status',
    'succeeded',
  );
  await page.screenshot({ path: 'test-results/p4b-compose-execution.png', fullPage: true });
  expect(await page.content()).not.toContain('wiki-db-secret-value');
});

test('compose redeploy with only the app changed keeps worker / db / redis unchanged', async ({
  page,
}) => {
  test.setTimeout(150_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/applications');
  await openApp(page, 'crm-suite');
  await page.getByRole('link', { name: 'Compose', exact: true }).click();
  await expect(page.getByTestId('compose-yaml-readonly')).toContainText('crm-worker');
  await expect(page.locator('[data-testid="compose-running-service"]')).toHaveCount(4);

  await page.getByTestId('app-deploy').click();
  await stepIs(page, 'source');
  const yaml = page.getByTestId('compose-yaml');
  await expect(yaml).toHaveValue(/crm-app@sha256/, { timeout: 10_000 });
  const cur = await yaml.inputValue();
  await yaml.fill(cur.replace(/crm-app@sha256:[a-f0-9]{64}/, `crm-app@sha256:${HEX('c0de')}`));
  await expect(page.getByTestId('compose-result')).toHaveAttribute('data-valid', 'true', {
    timeout: 10_000,
  });
  for (let i = 0; i < 5; i++) await next(page);

  await stepIs(page, 'review');
  const plan = (s: string) => page.locator(`[data-testid="compose-plan-row"][data-service="${s}"]`);
  await expect(plan('app')).toHaveAttribute('data-action', 'replaced');
  for (const s of ['worker', 'db', 'redis'])
    await expect(plan(s)).toHaveAttribute('data-action', 'unchanged');
  await expect(page.getByTestId('deploy-button')).toBeDisabled();
  await page.getByTestId('compose-prepare').click(); // save v2
  await expect(page.getByTestId('preflight-ok')).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('deploy-button').click();

  await expect(page.getByTestId('deployment-execution')).toHaveAttribute(
    'data-status',
    'succeeded',
    {
      timeout: 25_000,
    },
  );
  const row = (s: string) =>
    page.locator(`[data-testid="compose-service-row"][data-service="${s}"]`);
  await expect(row('app')).toHaveAttribute('data-action', 'replaced');
  for (const s of ['worker', 'db', 'redis'])
    await expect(row(s)).toHaveAttribute('data-action', 'unchanged');
  await expect(page.locator('[data-step="route_switch"]')).toHaveAttribute(
    'data-status',
    'succeeded',
  );
});

test('compose lifecycle states rollback never restores data', async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page, 'admin', '/applications');
  await openApp(page, 'crm-suite');
  const panel = page.getByTestId('lifecycle-panel');
  await expect(panel.locator('[data-testid="lifecycle-action"]')).toHaveCount(4);
  await expect(panel.locator('[data-action="restart"]')).toHaveCount(0);
  await expect(panel.getByTestId('rollback-warning')).toContainText(
    'Rollback never restores volumes or database data (dataRestored: false).',
  );
});

test('build node toggle shows the trust warning and needs confirmation', async ({ page }) => {
  test.setTimeout(90_000);
  await signIn(page, 'admin', '/servers');
  await page.getByRole('link', { name: 'app-uat-01' }).first().click();
  await expect(page).toHaveURL(/\/servers\/[^/]+/);
  const id = new URL(page.url()).pathname.split('/')[2];
  await page.goto(`/servers/${id}/settings`);
  const card = page.getByTestId('build-node-card');
  await expect(card).toHaveAttribute('data-enabled', 'false');
  await expect(page.getByTestId('build-node-warning')).toHaveText(
    'Dockerfile RUN steps execute on this host; use a dedicated trusted server.',
  );
  await page.getByTestId('build-node-toggle').click();
  await expect(page.getByTestId('build-node-confirm-button')).toBeDisabled();
  await page.getByLabel(/build steps from application repositories/).check();
  await page.getByTestId('build-node-confirm-button').click();
  await expect(card).toHaveAttribute('data-enabled', 'true', { timeout: 10_000 });
  await expect(page.getByTestId('build-node-state')).toHaveText('build node');
});
