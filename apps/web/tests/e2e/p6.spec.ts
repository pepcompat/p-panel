import { expect, test, type Page } from '@playwright/test';

// P6 journeys in mock mode (NEXT_PUBLIC_API_MOCK=1): policies with cron/timezone preview, run →
// honest verification badge → test restore, restore wizard (staging, in_place gating, production
// approval), requires_manual_recovery, viewer gating, recovery export one-time display.

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
const wizardStep = (page: Page, step: string) =>
  expect(page.getByTestId('restore-wizard')).toHaveAttribute('data-step', step, {
    timeout: 15_000,
  });

/** Opens the wizard from the Runs tab for the newest uploaded run of a policy. */
async function restoreFromRuns(page: Page, policy: string) {
  await page.goto('/backups?tab=runs');
  const row = page
    .locator('[data-testid="run-row"][data-status="uploaded"]')
    .filter({ hasText: policy })
    .first();
  await expect(row).toBeVisible({ timeout: 15_000 });
  await row.getByTestId('restore-action').click();
  await expect(page).toHaveURL(/\/restore\/new\?runId=/);
  await wizardStep(page, 'snapshot');
}

test('policy editor: cron + timezone preview with next 3 runs, retention by maintenance', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'admin', '/backups');
  await expect(page.getByRole('heading', { name: 'Backups', level: 1 })).toBeVisible();
  await expect(page.getByTestId('preview-banner')).toHaveCount(0);
  await expect(page.getByTestId('policy-row')).toHaveCount(3);
  await page.getByTestId('policy-new').click();
  const form = page.getByTestId('policy-form');
  await form.getByLabel('Policy name').fill('e2e uat files');
  await form.getByLabel('Server', { exact: true }).selectOption({ label: 'app-uat-01 · uat' });
  await form.getByLabel('Repository').selectOption({ label: 'lab-backup' });
  await form.getByRole('button', { name: '+ Host paths' }).click();
  await form.getByLabel('Paths (one per line)').fill('/proc/self');
  await form.getByLabel('Cron expression').fill('30 3 * * 0');
  await form.getByLabel('Timezone (IANA)').fill('Asia/Bangkok');
  await expect(page.getByTestId('cron-description')).toHaveText(
    'Every Sunday at 03:30 (Asia/Bangkok)',
  );
  await expect(page.getByTestId('next-runs').locator('li')).toHaveCount(3);
  await expect(page.getByTestId('next-runs').locator('li').first()).toContainText('Sun');
  await expect(page.getByTestId('next-runs').locator('li').first()).toContainText('03:30');
  await expect(page.getByTestId('next-runs').locator('li').first()).toContainText('T20:30:00Z');
  await expect(page.getByTestId('retention-note')).toContainText('maintenance script');
  // invalid timezone / cron → explained, no next runs
  await form.getByLabel('Timezone (IANA)').fill('Mars/Olympus');
  await expect(page.getByText('No upcoming run for this schedule.')).toBeVisible();
  await form.getByLabel('Timezone (IANA)').fill('Asia/Bangkok');
  // forbidden path is rejected client-side
  await page.getByTestId('policy-submit').click();
  await expect(
    form.getByText('Not allowed under /proc, /sys, /dev or the agent state dir'),
  ).toBeVisible();
  await form.getByLabel('Paths (one per line)').fill('/srv/uat/files');
  await page.screenshot({ path: 'test-results/p6-policy-form.png', fullPage: true });
  await page.getByTestId('policy-submit').click();
  const row = page.locator('[data-testid="policy-row"][data-name="e2e uat files"]');
  await expect(row).toBeVisible();
  await expect(row).toContainText('Every Sunday at 03:30 (Asia/Bangkok)');
  expect(errors).toEqual([]);
});

test('run now → "Snapshot uploaded — not verified" → test restore → "Restore verified on …"', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1100 });
  await signIn(page, 'admin', '/backups');
  // storefront policy verifies nothing after backup → the run stays "not verified".
  const row = page.locator('[data-testid="policy-row"][data-name="storefront uploads"]');
  await row.getByTestId('run-now').click();
  await page.getByTestId('run-queued').getByRole('link').click();
  await expect(page).toHaveURL(/\/backups\/runs\/[0-9a-f-]+$/);
  const detail = page.getByTestId('run-detail');
  await expect(detail).toHaveAttribute('data-status', 'uploaded', { timeout: 20_000 });
  const badge = page.getByTestId('verification-badge');
  await expect(badge).toHaveAttribute('data-level', 'none');
  await expect(badge).toHaveText('Snapshot uploaded — not verified');
  await expect(page.getByText('no restore has been tested')).toBeVisible();
  await expect(page.getByTestId('manifest-row').first()).toBeVisible();
  await expect(page.getByTestId('manifest-page')).toContainText('Page 1 of');
  await expect(page.getByTestId('run-logs')).toContainText('no prune (append-only)');
  await page.screenshot({ path: 'test-results/p6-run-not-verified.png', fullPage: true });
  await page.getByTestId('verify-restore').click();
  await expect(page.getByTestId('verifying')).toBeVisible();
  await expect(badge).toHaveAttribute('data-level', 'restore_verified', { timeout: 20_000 });
  await expect(badge).toContainText('Restore verified on');
  await page.screenshot({ path: 'test-results/p6-run-restore-verified.png', fullPage: true });
});

test('failed / partial / expired runs never show success; restore is disabled for them', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1100 });
  await signIn(page, 'admin', '/backups?tab=runs');
  const bad = page.locator(
    '[data-testid="run-row"][data-status="failed"], [data-testid="run-row"][data-status="expired"]',
  );
  await expect(bad.first()).toBeVisible();
  const n = await bad.count();
  expect(n).toBeGreaterThanOrEqual(2);
  for (let i = 0; i < n; i++) {
    const level = await bad.nth(i).getByTestId('verification-badge').getAttribute('data-level');
    expect(['failed', 'partial', 'expired', 'cancelled']).toContain(level);
    await expect(bad.nth(i).getByTestId('restore-action')).toBeDisabled();
    await expect(bad.nth(i)).not.toContainText('Restore verified');
  }
  await expect(page.locator('[data-testid="verification-badge"][data-level="partial"]')).toHaveText(
    'Partial — no usable snapshot',
  );
  await page.screenshot({ path: 'test-results/p6-runs.png', fullPage: true });
});

test('staging restore in UAT: no approval, dry-run → execute → verified with compare counts', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/backups?tab=runs');
  await restoreFromRuns(page, 'crm-suite nightly');
  await page.getByTestId('wizard-next').click();
  await wizardStep(page, 'target');
  await expect(page.getByTestId('mode-staging')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('approval-notice')).toContainText('No approval needed');
  await page.getByTestId('create-plan').click();
  await wizardStep(page, 'impact');
  await expect(
    page.locator('[data-testid="impact-item"][data-action="create"]').first(),
  ).toBeVisible();
  await expect(page.locator('[data-testid="impact-item"][data-action="overwrite"]')).toHaveCount(0);
  await expect(page.getByTestId('config-note')).toContainText('Config rollback ≠ data restore');
  await expect(page.getByTestId('impact-confirm')).toHaveCount(0);
  await page.getByTestId('dry-run').click();
  await wizardStep(page, 'dryrun');
  await expect(page.getByTestId('dry-entry').first()).toBeVisible();
  await expect(page.getByTestId('approval-not-required')).toBeVisible();
  await page.getByTestId('execute').click();
  await wizardStep(page, 'result');
  await expect(page.getByTestId('restore-result')).toHaveAttribute('data-outcome', 'verified');
  await expect(page.getByTestId('compare-files')).toContainText('0 mismatch(es)');
  await expect(page.getByTestId('staging-location')).toContainText(
    '/var/lib/ppanel-agent/restore/',
  );
  await page.screenshot({ path: 'test-results/p6-restore-staging-verified.png', fullPage: true });
});

test('in_place restore cannot proceed without the explicit impact confirmation', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/backups?tab=runs');
  await restoreFromRuns(page, 'crm-suite nightly');
  await page.getByTestId('wizard-next').click();
  await page.getByTestId('mode-in_place').click();
  await expect(page.getByTestId('approval-notice')).toContainText('Needs approval by another user');
  await page.getByTestId('create-plan').click();
  await wizardStep(page, 'impact');
  await expect(
    page.locator('[data-testid="impact-item"][data-action="overwrite"]').first(),
  ).toBeVisible();
  await expect(page.getByTestId('impact-safety')).toContainText('safety backup');
  await expect(page.getByTestId('dry-run')).toBeDisabled();
  await page.screenshot({ path: 'test-results/p6-inplace-impact-blocked.png', fullPage: true });
  await page.getByTestId('impact-confirm').check();
  await expect(page.getByTestId('dry-run')).toBeEnabled();
  await page.getByTestId('impact-confirm').uncheck();
  await expect(page.getByTestId('dry-run')).toBeDisabled();
});

test('production restore requires another approver with 2FA; the creator cannot approve', async ({
  page,
}) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/backups?tab=runs');
  await restoreFromRuns(page, 'storefront uploads');
  await page.getByTestId('wizard-next').click();
  await expect(page.getByTestId('mode-staging')).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByTestId('approval-notice')).toContainText('Needs approval');
  await page.getByTestId('create-plan').click();
  await wizardStep(page, 'impact');
  await page.getByTestId('dry-run').click();
  await wizardStep(page, 'approval');
  await expect(page.getByTestId('restore-wizard')).toHaveAttribute(
    'data-status',
    'awaiting_approval',
  );
  await expect(page.getByTestId('plan-hash')).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.getByTestId('waiting-approver')).toContainText('creator cannot approve');
  await expect(page.getByTestId('approve')).toHaveCount(0);
  await expect(page.getByTestId('execute')).toHaveCount(0);
  await page.screenshot({ path: 'test-results/p6-restore-awaiting-approval.png', fullPage: true });
  const url = new URL(page.url());
  const target = `${url.pathname}${url.search}`;

  await signOut(page);
  await signIn(page, 'superadmin', target);
  await wizardStep(page, 'approval');
  await expect(page.getByTestId('approve')).toBeDisabled();
  await page.getByTestId('approval-panel').getByLabel('2FA code').fill('123456');
  await page.getByTestId('approve').click();
  await expect(page.getByTestId('restore-wizard')).toHaveAttribute('data-status', 'approved', {
    timeout: 15_000,
  });
  await expect(page.getByTestId('approved-by')).toContainText('Super Admin');
  await page.getByTestId('execute').click();
  await wizardStep(page, 'result');
  await expect(page.getByTestId('restore-result')).toHaveAttribute('data-outcome', 'verified');
});

test('requires_manual_recovery shows the critical banner with safety snapshot and runbook', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/backups?tab=restores');
  const row = page.locator('[data-testid="restore-row"][data-status="requires_manual_recovery"]');
  await row.getByRole('link', { name: 'Open' }).click();
  await wizardStep(page, 'result');
  const banner = page.getByTestId('manual-recovery');
  await expect(banner).toBeVisible();
  await expect(banner).toContainText('Requires manual recovery');
  await expect(page.getByTestId('safety-snapshot').getByRole('link')).toBeVisible();
  await expect(page.locator('[data-testid="restore-step"][data-status="failed"]')).toHaveAttribute(
    'data-step',
    'start_app',
  );
  await page.screenshot({ path: 'test-results/p6-manual-recovery.png', fullPage: true });
  await banner.getByRole('link', { name: 'Open the recovery runbook →' }).click();
  await expect(page).toHaveURL(/\/settings\/security#recovery-runbook/);
  await expect(page.getByTestId('recovery-card')).toContainText('center-restore.sh');
});

test('viewer: restore actions disabled, wizard forbidden, verify disabled', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await signIn(page, 'user1', '/backups?tab=runs');
  const rows = page.locator('[data-testid="run-row"][data-status="uploaded"]');
  await expect(rows.first()).toBeVisible();
  const n = await rows.count();
  for (let i = 0; i < n; i++) {
    await expect(rows.nth(i).getByTestId('restore-action')).toBeDisabled();
    await expect(rows.nth(i).getByTestId('verify-restore')).toBeDisabled();
  }
  const runId = await rows.first().getAttribute('data-run-id');
  await page.goto('/backups?tab=policies');
  await expect(page.getByTestId('policy-new')).toBeDisabled();
  await page.goto(`/restore/new?runId=${runId}`);
  await expect(page.getByText('You don’t have access to this')).toBeVisible();
  await expect(page.getByTestId('restore-wizard')).toHaveCount(0);
});

test('recovery export: step-up, one-time display, offline checklist, then cleared', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'superadmin', '/backups?tab=repositories');
  await expect(page.getByTestId('append-only')).toContainText('maintenance script');
  await expect(page.getByTestId('repo-not-initialized')).toContainText(
    'scripts/backup/maintenance.sh init app-prod-02',
  );
  await expect(
    page.locator('[data-testid="maint"][data-kind="copy"][data-ok="false"]'),
  ).toBeVisible();
  const box = page.getByTestId('recovery-export');
  await expect(box).toContainText('Never exported');
  await box.getByTestId('export-open').click();
  await box.getByLabel('2FA code').fill('123456');
  await box.getByTestId('export-confirm').click();
  await expect(box.getByTestId('export-values')).toBeVisible();
  await expect(box.getByTestId('export-password').first()).not.toBeEmpty();
  await expect(box).toContainText('Shown once');
  await expect(box.getByTestId('export-done')).toBeDisabled();
  await page.screenshot({ path: 'test-results/p6-recovery-export.png', fullPage: true });
  const pw = (await box.getByTestId('export-password').first().textContent())!;
  for (const c of await box.getByRole('checkbox').all()) await c.check();
  await box.getByTestId('export-done').click();
  await expect(box.getByTestId('export-cleared')).toBeVisible();
  await expect(box.getByTestId('export-password')).toHaveCount(0);
  expect(await page.content()).not.toContain(pw);
  await expect(box).toContainText('Last export');
  // Settings → Security shows the export status and the runbook summary.
  await page.goto('/settings/security');
  await expect(page.getByTestId('recovery-export-status')).toContainText('last exported');
});

test('server and app Backups tabs are real: scoped policies, runs, live snapshots, Back up now (TH)', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/servers');
  await page.getByRole('link', { name: 'app-uat-01' }).first().click();
  await page
    .getByRole('navigation', { name: 'Server sections' })
    .getByRole('link', { name: 'Backups' })
    .click();
  const scoped = page.getByTestId('scoped-backups');
  await expect(scoped).toBeVisible();
  await expect(
    scoped.locator('[data-testid="policy-row"][data-name="crm-suite nightly"]'),
  ).toBeVisible();
  await expect(scoped.getByTestId('snapshot-row').first()).toBeVisible();
  await scoped
    .locator('[data-testid="policy-row"][data-name="crm-suite nightly"]')
    .getByTestId('run-now')
    .click();
  await expect(scoped.getByTestId('run-queued')).toBeVisible();

  await page.goto('/applications');
  await page.getByRole('link', { name: 'crm-suite', exact: true }).click();
  await page
    .getByRole('navigation', { name: 'Application sections' })
    .getByRole('link', { name: 'Backups' })
    .click();
  await expect(
    page.locator('[data-testid="policy-row"][data-name="crm-suite nightly"]'),
  ).toBeVisible();
  await page.getByRole('radio', { name: 'TH' }).click();
  await expect(page.getByText('การสำรองล่าสุด')).toBeVisible();
  await page.screenshot({ path: 'test-results/p6-app-backups-th.png', fullPage: true });

  // offline server: the live snapshot list is honestly unavailable
  await page.getByRole('radio', { name: 'EN' }).click();
  await page.goto('/backups?tab=snapshots');
  const workerId = await page
    .getByLabel('Server', { exact: true })
    .locator('option', { hasText: 'worker-uat-01' })
    .getAttribute('value');
  await page.getByLabel('Server', { exact: true }).selectOption(workerId!);
  await expect(page.getByTestId('snapshots-offline')).toBeVisible();
});
