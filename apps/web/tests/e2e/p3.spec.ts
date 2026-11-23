import { expect, test, type Page } from '@playwright/test';

// P3 journeys in mock mode (NEXT_PUBLIC_API_MOCK=1). Mock P3 state lives in sessionStorage, so it
// survives full page loads and user switches within one test.

async function signIn(page: Page, user: string, next = '/overview') {
  await page.goto(`/login?next=${encodeURIComponent(next)}`);
  await page.waitForLoadState('networkidle'); // dev server: let the page hydrate before typing
  await page.getByLabel('Email').fill(user);
  await page.getByLabel('Password').fill('password');
  await page.getByRole('button', { name: 'Continue' }).click();
  if (user === 'superadmin') {
    await page.getByLabel('Digit 1 of 6').fill('123456');
    await page.getByRole('button', { name: 'Confirm' }).click();
  }
  try {
    await expect(page).toHaveURL((u) => u.pathname === next, { timeout: 10_000 });
  } catch {
    // Dev server only: the first client navigation after an on-demand route compile can be dropped.
    // The session is already established (mock refresh session), so load the target directly.
    await page.goto(next);
    await expect(page).toHaveURL((u) => u.pathname === next, { timeout: 20_000 });
  }
}

/** Drop the mock refresh session (keeps P3 state) so another user can sign in. */
async function signOut(page: Page) {
  await page.evaluate(() => sessionStorage.removeItem('ppanel.mock.session'));
}

test('J02: read-only scan → findings → import as Observe, nothing else changes', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1100 });
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'admin');
  await page.goto('/imports');
  await expect(page.getByRole('heading', { name: 'Discovery & Import', level: 1 })).toBeVisible();
  await expect(page.getByTestId('scan-row').first()).toBeVisible();

  await page.getByRole('button', { name: 'Run read-only scan' }).first().click();
  const dlg = page.getByRole('dialog');
  await expect(dlg.getByText(/does not change anything on the host/)).toBeVisible();
  await dlg.getByLabel('Server').selectOption({ label: 'app-uat-01 · UAT · Online' });
  await dlg.getByRole('button', { name: 'Start read-only scan' }).click();

  await expect(page).toHaveURL(/\/imports\/[0-9a-f-]+$/);
  await expect(page.getByRole('heading', { name: 'app-uat-01 · scan results' })).toBeVisible();
  await expect(page.getByTestId('finding')).not.toHaveCount(0, { timeout: 15_000 });
  const nginx = page.locator('section', {
    has: page.getByRole('heading', { name: 'Nginx server blocks' }),
  });
  await expect(nginx.getByTestId('finding')).toHaveCount(9);
  await expect(page.getByText(/Duplicate server_name · also in/)).toHaveCount(2);
  await page.screenshot({ path: 'test-results/imports-detail.png', fullPage: true });
  // The only checksum change since the previous scan is pPanel's own applied revision — not external drift.
  await page.getByRole('tab', { name: 'Drift (1)' }).click();
  await expect(page.getByText('pPanel revision')).toBeVisible();
  await expect(page.getByText('External edit')).toHaveCount(0);
  await page.getByRole('tab', { name: /Findings/ }).click();

  // Already-imported findings link to inventory (re-import never changes ownership).
  await page.getByRole('checkbox', { name: 'Select php.example.lab for import' }).check();
  await expect(page.getByRole('radio', { name: /Observed/ })).toBeChecked();
  await expect(page.getByText(/Importing is not taking ownership/)).toBeVisible();
  await page.getByRole('button', { name: 'Import 1 as Observe' }).click();
  await expect(page.getByTestId('import-result')).toHaveText('1 application(s) in inventory.');
  await expect(
    page.getByText('No files on the server were changed and no service was reloaded.'),
  ).toBeVisible();

  // Config file checksums unchanged, no drift, app is Observed with no revisions.
  await page.getByRole('tab', { name: /Config files/ }).click();
  await expect(page.getByText('unchanged').first()).toBeVisible();
  await page
    .getByRole('navigation', { name: 'Main navigation' })
    .getByRole('link', { name: 'Applications' })
    .click();
  const row = page.getByTestId('app-row').filter({ hasText: 'php-example-lab' });
  await expect(row).toContainText('Observed');
  await expect(row).toContainText('Manual review');
  await row.getByRole('link', { name: 'php-example-lab' }).click();
  await expect(page.getByRole('heading', { name: 'php-example-lab' })).toBeVisible();
  await expect(page.getByTestId('ownership-panel').getByText('◉ Observed')).toBeVisible();
  await page
    .getByRole('navigation', { name: 'Application sections' })
    .getByRole('link', { name: 'Nginx' })
    .click();
  await expect(page.getByText('No revisions yet')).toBeVisible();
  await expect(
    page.getByText('Read-only: adopt this application before proposing Nginx changes.'),
  ).toBeVisible();
  expect(errors).toEqual([]);
});

test('J03: adopt with ack → invalid revision blocked → fix → approve as other user → apply → revert', async ({
  page,
}) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await signIn(page, 'admin', '/applications');
  await page.getByRole('link', { name: 'api-example-lab' }).click();
  await expect(page.getByRole('heading', { name: 'api-example-lab' })).toBeVisible();
  const appUrl = page.url().replace(/\/overview$/, '');

  // Adopt: reasons listed, ack checkbox required.
  await page.getByRole('button', { name: 'Move to Adopted ↑' }).click();
  const dlg = page.getByRole('dialog');
  await expect(dlg.getByTestId('ack-reasons')).toContainText('unsupported directives: limit_req');
  await dlg.getByLabel('Reason (audited)').fill('API team confirmed ownership');
  const confirm = dlg.getByRole('button', { name: 'Confirm Adopted' });
  await expect(confirm).toBeDisabled();
  await dlg.getByRole('checkbox', { name: 'I reviewed these reasons' }).check();
  await confirm.click();
  await expect(page.getByTestId('ownership-panel').getByText('◉ Adopted')).toBeVisible();
  // unsupported directives: no "Managed" step offered as enabled
  await expect(page.getByRole('button', { name: 'Move to Managed ↑' })).toBeDisabled();

  // Nginx tab: files read via job (202 → ready), then a broken draft.
  await page
    .getByRole('navigation', { name: 'Application sections' })
    .getByRole('link', { name: 'Nginx' })
    .click();
  const editor = page.getByTestId('nginx-editor');
  await expect(editor).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('symlink')).toContainText(
    'symlink → /etc/nginx/sites-available/03-proxy-api.conf',
  );
  const original = await editor.inputValue();
  await editor.fill(
    original.replace('proxy_pass http://legacy_api;', 'proxy_pass http://legacy_api'),
  );
  await expect(page.getByTestId('diff-viewer').first()).toBeVisible();
  await page.getByRole('button', { name: 'Create revision draft' }).click();
  const detail = page.getByTestId('revision-detail');
  await expect(detail).toHaveAttribute('data-status', 'draft');
  await page.getByRole('button', { name: 'Validate (nginx -t)' }).click();
  await expect(detail).toHaveAttribute('data-status', 'invalid', { timeout: 15_000 });
  await expect(page.getByTestId('apply-blocked')).toBeVisible();
  await expect(page.getByTestId('nginx-test-output')).toContainText('test failed');
  await expect(
    page.getByTestId('revision-actions').getByRole('button', { name: 'Apply + reload' }),
  ).toBeDisabled();
  await expect(page.getByTestId('apply-reason')).toHaveText('Apply disabled: nginx -t failed');
  await page.screenshot({ path: 'test-results/nginx-blocked.png', fullPage: true });

  // Fix in the editor (it kept the text) and add a header.
  await editor.fill(
    original.replace(
      'proxy_pass http://legacy_api;',
      'proxy_pass http://legacy_api;\n        proxy_read_timeout 30s;',
    ),
  );
  await page.getByRole('button', { name: 'Create revision draft' }).click();
  await expect(detail).toHaveAttribute('data-status', 'draft');
  await page.getByRole('button', { name: 'Validate (nginx -t)' }).click();
  await expect(detail).toHaveAttribute('data-status', 'awaiting_approval', { timeout: 15_000 });
  await expect(page.getByTestId('waiting-approver')).toBeVisible();
  await expect(detail.locator('tr[data-diff="add"]')).toContainText('proxy_read_timeout 30s;');
  await page.screenshot({ path: 'test-results/app-nginx-diff.png', fullPage: true });
  const planHash = (await page.getByTestId('plan-hash').textContent())?.trim();

  // Approve as another user (superadmin, step-up).
  await signOut(page);
  await signIn(page, 'superadmin', `${new URL(appUrl).pathname}/nginx`);
  await expect(page.getByTestId('plan-hash')).toHaveText(planHash!);
  await page.getByTestId('approval-panel').getByLabel('2FA code').fill('123456');
  await page.getByRole('button', { name: /Approve plan/ }).click();
  await expect(detail).toHaveAttribute('data-status', 'approved');

  // Creator applies.
  await signOut(page);
  await signIn(page, 'admin', `${new URL(appUrl).pathname}/nginx`);
  await expect(detail).toHaveAttribute('data-status', 'approved');
  await page
    .getByTestId('revision-actions')
    .getByRole('button', { name: 'Apply + reload' })
    .click();
  await page.getByRole('dialog').getByRole('button', { name: 'Apply + reload' }).click();
  await expect(detail).toHaveAttribute('data-status', 'applied', { timeout: 15_000 });
  await expect(page.getByTestId('applied')).toBeVisible();

  await page.getByTestId('revision-actions').getByRole('button', { name: 'Revert' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Revert' }).click();
  await expect(detail).toHaveAttribute('data-status', 'reverted', { timeout: 15_000 });

  await page
    .getByRole('navigation', { name: 'Application sections' })
    .getByRole('link', { name: 'Ownership history' })
    .click();
  await expect(page.getByText('API team confirmed ownership')).toBeVisible();
  await expect(page.getByText('acknowledged')).toBeVisible();
});
