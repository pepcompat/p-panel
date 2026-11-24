import { expect, test, type Page } from '@playwright/test';

// P10 journeys in mock mode (NEXT_PUBLIC_API_MOCK=1): SSH credentials (generate with step-up, import field
// cleared), access grants (request, production approval by another person, self-approval blocked),
// host-key mismatch (blocked terminal + prominent warning), terminal states (ready, exit status,
// reconnect, tabs, idle timeout) through the in-process gateway, and the real browser WebSocket path via
// page.routeWebSocket (ticket only in the first frame, close codes mapped).
// Fixtures: src/mocks/p10-routes.ts (state in sessionStorage, so page reloads keep it).

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
const card = (page: Page, name: string) =>
  page.getByTestId('server-card').filter({ hasText: name });
const termText = (page: Page) => page.getByTestId('terminal-pane').locator('.xterm-rows').first();

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1100 });
});

test('credentials: metadata only, generate with step-up, import field is cleared on submit', async ({
  page,
}) => {
  test.setTimeout(90_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'superadmin', '/ssh?tab=credentials');
  await expect(page.getByTestId('credential-card')).toHaveCount(3, { timeout: 20_000 });
  const ops = page.getByTestId('credential-card').filter({ hasText: 'ops-ed25519' }).first();
  await expect(ops.getByTestId('fingerprint').first()).toHaveText(/^SHA256:/);
  await expect(ops.getByTestId('deployment-row')).toHaveCount(6);
  await expect(page.getByText(/PRIVATE KEY/)).toHaveCount(0);

  await page.getByRole('button', { name: 'Generate key' }).click();
  const gen = page.getByRole('dialog');
  await gen.getByLabel('Name').fill('e2e-ed25519');
  await gen.getByLabel('2FA code').fill('123456');
  await gen.getByRole('button', { name: 'Generate' }).click();
  await expect(gen).toBeHidden();
  const created = page.getByTestId('credential-card').filter({ hasText: 'e2e-ed25519' });
  await expect(created).toBeVisible();
  await expect(created).toContainText('Not deployed to any server.');

  // deploy it, watch pending → installed
  await created.getByRole('button', { name: 'Deploy e2e-ed25519 to a server' }).click();
  const dep = page.getByRole('dialog');
  await dep.getByLabel('Server').selectOption({ label: 'dev-01 · development' });
  await dep.getByLabel('SSH user').fill('ops');
  await dep.getByRole('button', { name: 'Deploy', exact: true }).click();
  await expect(created.getByTestId('deployment-row')).toContainText('installed', {
    timeout: 10_000,
  });

  // import: the key is never kept in the field after submit
  await page.getByRole('button', { name: 'Import private key' }).click();
  const imp = page.getByRole('dialog');
  await imp.getByLabel('Name').fill('e2e-imported');
  const ta = imp.getByTestId('private-key-input');
  await ta.fill(
    '-----BEGIN OPENSSH PRIVATE KEY-----\nE2E-SECRET-BODY\nbcrypt aes256-ctr\n-----END OPENSSH PRIVATE KEY-----',
  );
  await imp.getByLabel('2FA code').fill('123456');
  await imp.getByTestId('import-submit').click();
  await expect(imp.getByTestId('key-cleared')).toBeVisible();
  await expect(imp.getByText('SSH_KEY_ENCRYPTED', { exact: false })).toBeVisible();
  await expect(ta).toHaveValue('');
  expect(await page.content()).not.toContain('E2E-SECRET-BODY');
  const stored = await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage }));
  expect(stored).not.toContain('E2E-SECRET-BODY');
  await ta.fill(
    '-----BEGIN OPENSSH PRIVATE KEY-----\nE2E-SECRET-BODY\n-----END OPENSSH PRIVATE KEY-----',
  );
  await imp.getByTestId('import-submit').click();
  await expect(imp).toBeHidden();
  await expect(
    page.getByTestId('credential-card').filter({ hasText: 'e2e-imported' }),
  ).toContainText('imported');
  expect(await page.content()).not.toContain('E2E-SECRET-BODY');
  await page.screenshot({ path: 'test-results/p10-credentials.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('grants: request in dev is active now; production waits; self-approval is blocked; approve with step-up', async ({
  page,
}) => {
  test.setTimeout(120_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  // admin (production + uat scope, no MFA) asks for production access
  await signIn(page, 'admin', '/ssh?tab=grants');
  const form = page.getByTestId('grant-form');
  await form.getByLabel('Server').selectOption({ label: 'app-prod-02 · production' });
  await expect(form.getByLabel('Network path')).toHaveValue('private');
  await expect(form.getByLabel('SSH user')).toHaveValue('ops');
  await expect(form.getByText('Production: the grant waits for approval')).toBeVisible();
  await form.getByLabel('Reason').fill('INC-501 look at disk');
  await form.getByRole('button', { name: 'Request grant' }).click();
  await expect(form.getByTestId('grant-created')).toContainText('waiting for approval');
  // admin cannot approve their own request either
  const mine = page.getByTestId('grant-row').filter({ hasText: 'INC-501' });
  await expect(mine.getByTestId('approve-self')).toBeDisabled();
  await expect(mine.getByTestId('self-approval-note')).toBeVisible();
  await page.evaluate(() => sessionStorage.removeItem('ppanel.mock.session'));

  // superadmin: approvals list; own request blocked, admin's approvable with 2FA
  await signIn(page, 'superadmin', '/ssh?tab=grants');
  const approvals = page.getByTestId('grant-approvals');
  await expect(approvals.getByTestId('grant-row')).toHaveCount(3, { timeout: 20_000 });
  const self = approvals.locator('[data-grant="grant-self-prod"]');
  await expect(self.getByTestId('approve-self')).toBeDisabled();
  await self.getByTestId('approve-self').locator('..').focus();
  await expect(page.getByRole('tooltip')).toContainText('self-approval is not allowed');
  const theirs = approvals.getByTestId('grant-row').filter({ hasText: 'INC-501' });
  await theirs.getByRole('button', { name: 'Approve' }).click();
  const dlg = page.getByRole('dialog');
  await expect(dlg).toContainText('INC-501 look at disk');
  await dlg.getByLabel('2FA code').fill('123456');
  await dlg.getByRole('button', { name: 'Approve' }).click();
  await expect(dlg).toBeHidden();
  await expect(
    page.getByTestId('grant-others').getByTestId('grant-row').filter({ hasText: 'INC-501' }),
  ).toContainText('active');

  // non-production request is active immediately and can open a terminal
  await form.getByLabel('Server').selectOption({ label: 'app-uat-01 · uat' });
  await expect(form.getByLabel('SSH user')).toHaveValue('ops');
  await expect(form.getByText('This grant becomes active immediately.')).toBeVisible();
  await form.getByLabel('Reason').fill('UAT smoke');
  await form.getByRole('button', { name: 'Request grant' }).click();
  await expect(form.getByTestId('grant-created')).toContainText('is active');
  await page.screenshot({ path: 'test-results/p10-grants.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('host key mismatch: terminal blocked with close 4409, prominent warning, trust needs step-up', async ({
  page,
}) => {
  test.setTimeout(90_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'superadmin', '/servers');
  await expect(card(page, 'dev-sandbox-02').getByTestId('open-terminal')).toHaveAttribute(
    'href',
    /grant=grant-sandbox/,
    {
      timeout: 20_000,
    },
  );
  await card(page, 'dev-sandbox-02').getByTestId('open-terminal').click();
  await expect(page).toHaveURL(/\/ssh\?/);
  const pane = page.getByTestId('terminal-pane');
  await expect(pane).toHaveAttribute('data-phase', 'closed', { timeout: 20_000 });
  await expect(pane.getByTestId('close-title')).toHaveAttribute('data-code', '4409');
  await expect(pane.getByTestId('close-title')).toHaveText(
    'Host key mismatch: connection blocked (4409)',
  );
  await expect(pane.getByRole('button', { name: 'Reconnect' }).last()).toBeVisible();
  await pane.getByRole('link', { name: 'Review host keys' }).click();
  await expect(page).toHaveURL(/tab=host-keys/);
  const banner = page.getByTestId('host-key-mismatch');
  await expect(banner).toBeVisible();
  await expect(banner).toHaveAttribute('role', 'alert');
  await expect(banner).toContainText('connections blocked');
  await expect(banner.getByTestId('agent-match')).toHaveAttribute('data-match', 'false');
  await expect(banner.getByTestId('fingerprint')).toHaveCount(2);
  await page.screenshot({ path: 'test-results/p10-host-key-mismatch.png', fullPage: true });

  // server detail shows the same block on Open Terminal
  await page.goto('/servers');
  await card(page, 'dev-sandbox-02').getByRole('link', { name: 'dev-sandbox-02' }).click();
  await page
    .getByRole('navigation', { name: /sections/i })
    .getByRole('link', { name: 'Terminal' })
    .click();
  await expect(page.getByTestId('server-ssh-tab')).toBeVisible();
  await expect(page.getByTestId('open-terminal').first()).toHaveAttribute(
    'data-block',
    'hostKeyMismatch',
  );
  await expect(page.getByTestId('host-key-mismatch')).toBeVisible();

  // trust the new key (agent disagrees → danger dialog with step-up), then the terminal opens
  await page.goto('/ssh?tab=host-keys');
  await page.getByTestId('hk-server').selectOption({ label: 'dev-sandbox-02 · development' });
  const pending = page.locator('[data-testid="host-key-row"][data-status="pending"]');
  await pending.getByRole('button', { name: /^Trust host key/ }).click();
  const dlg = page.getByRole('dialog');
  await expect(dlg).toContainText('The agent reports a different key');
  await dlg.getByLabel('2FA code').fill('123456');
  await dlg.getByRole('button', { name: 'Trust…' }).click();
  await expect(dlg).toBeHidden();
  await expect(page.getByTestId('host-key-mismatch')).toHaveCount(0);
  await expect(page.locator('[data-testid="host-key-row"][data-status="trusted"]')).toHaveCount(1);
  expect(errors).toEqual([]);
});

test('terminal: ready facts, command round-trip, exit status, reconnect, tabs, idle timeout', async ({
  page,
}) => {
  test.setTimeout(120_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'superadmin', '/servers');
  // no grant → disabled with explanation; grant → link
  await expect(card(page, 'web-legacy-02').getByTestId('open-terminal')).toBeDisabled({
    timeout: 20_000,
  });
  await expect(card(page, 'web-legacy-02').getByTestId('open-terminal')).toHaveAttribute(
    'data-block',
    'noGrant',
  );
  await expect(card(page, 'dev-01').getByTestId('ssh-line')).toContainText(
    'ops@Public path 178.128.40.2:22',
  );
  await expect(card(page, 'dev-01').getByTestId('ssh-line')).toContainText('public key');
  await card(page, 'dev-01').getByTestId('open-terminal').click();

  const pane = page.getByTestId('terminal-pane');
  await expect(pane).toHaveAttribute('data-phase', 'ready', { timeout: 20_000 });
  await expect(pane.getByTestId('term-user')).toHaveText('ops');
  await expect(pane.getByTestId('term-endpoint')).toHaveText(/178\.128\.40\.2:22/);
  await expect(pane.getByTestId('term-hostkey')).toHaveText(/^SHA256:/);
  await expect(pane.getByTestId('terminal-info')).toContainText('Idle timeout 15 min');
  await expect(termText(page)).toContainText('ops@dev-01:~$', { timeout: 10_000 });

  await pane.getByRole('region', { name: 'Terminal ops@dev-01' }).click();
  await page.keyboard.type('id -un');
  await page.keyboard.press('Enter');
  await expect(termText(page)).toContainText('$ id -un', { timeout: 10_000 });
  await expect(
    page
      .getByTestId('terminal-pane')
      .locator('.xterm-rows > div')
      .filter({ hasText: /^\s*ops\s*$/ }),
  ).toHaveCount(1);
  await page.keyboard.type('echo hello-from-e2e');
  await page.keyboard.press('Enter');
  await expect(
    page
      .getByTestId('terminal-pane')
      .locator('.xterm-rows > div')
      .filter({ hasText: /^\s*hello-from-e2e\s*$/ }),
  ).toHaveCount(1);
  // F6 leaves the terminal to its toolbar
  await page.keyboard.press('F6');
  await expect(pane.getByRole('button', { name: 'Focus terminal' })).toBeFocused();
  await pane.getByRole('button', { name: 'Focus terminal' }).click();
  await page.keyboard.type('exit 3');
  await page.keyboard.press('Enter');
  await expect(pane).toHaveAttribute('data-phase', 'closed', { timeout: 10_000 });
  await expect(pane.getByTestId('exit-status')).toHaveText('Process exited with status 3');
  await expect(pane.getByTestId('close-title')).toHaveText('Session closed');

  // reconnect creates a new session (new ticket)
  await pane.getByTestId('terminal-overlay').getByRole('button', { name: 'Reconnect' }).click();
  await expect(pane).toHaveAttribute('data-phase', 'ready', { timeout: 20_000 });

  // full screen toggle
  await pane.getByRole('button', { name: 'Full screen' }).click();
  await expect(pane.getByRole('button', { name: 'Exit full screen' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  await pane.getByRole('button', { name: 'Exit full screen' }).click();

  // second tab on the same grant
  await page.getByTestId('session-grant').selectOption('grant-dev01');
  await page.getByRole('button', { name: '>_ Connect' }).click();
  await expect(page.getByTestId('terminal-tab')).toHaveCount(2);
  const second = page.getByTestId('terminal-pane').nth(1);
  await expect(second).toHaveAttribute('data-phase', 'ready', { timeout: 20_000 });
  await second.getByRole('region').click();
  await page.keyboard.type('__idle');
  await page.keyboard.press('Enter');
  await expect(second).toHaveAttribute('data-phase', 'closed', { timeout: 10_000 });
  await expect(second.getByTestId('close-title')).toHaveText('Session timed out (4408)');
  await expect(second).toContainText('Closed after the idle timeout');
  await page.screenshot({ path: 'test-results/p10-terminal.png', fullPage: true });

  // tab switching keeps the first session alive
  await page.getByTestId('terminal-tab').first().click();
  await expect(page.getByTestId('terminal-pane').first()).toHaveAttribute('data-phase', 'ready');

  // sessions list shows the end reasons
  await page.getByRole('tab', { name: 'Sessions' }).click();
  await expect(page.getByTestId('sessions-active').getByTestId('session-row')).toHaveCount(1);
  await expect(page.getByTestId('sessions-recent')).toContainText('Closed after the idle timeout');
  await page.getByRole('tab', { name: 'Terminal' }).click();
  await page
    .getByRole('button', { name: /^Close session ops@dev-01/ })
    .first()
    .click();
  await expect(page.getByTestId('terminal-tab')).toHaveCount(1);
  expect(errors).toEqual([]);
});

test('real WebSocket path: ticket only in the first frame, never in the URL; 4403 mapped', async ({
  page,
}) => {
  test.setTimeout(90_000);
  const frames: string[] = [];
  const urls: string[] = [];
  await page.routeWebSocket(/\/api\/v1\/ssh\/stream/, (ws) => {
    urls.push(ws.url());
    ws.onMessage((m) => {
      const text = typeof m === 'string' ? m : null;
      if (text) frames.push(text);
      const msg = text ? (JSON.parse(text) as { type: string }) : null;
      if (msg?.type === 'auth') {
        ws.send(
          JSON.stringify({
            type: 'ready',
            sessionId: (msg as unknown as { sessionId: string }).sessionId,
            hostKeyFingerprint: 'SHA256:routedRoutedRoutedRoutedRoutedRoutedRout',
            endpoint: { path: 'public', host: '178.128.40.2', port: 22 },
            sshUser: 'ops',
          }),
        );
        ws.send(Buffer.from('routed-shell$ '));
      } else if (!text) {
        // binary stdin → echo, then the grant gets revoked
        ws.send(Buffer.from(m as Buffer));
        ws.send(JSON.stringify({ type: 'closing', reason: 'grant_revoked' }));
        ws.close({ code: 4403, reason: 'grant revoked' });
      }
    });
  });
  await signIn(page, 'superadmin', '/overview');
  await page.evaluate(() => sessionStorage.setItem('ppanel.mock.realWs', '1'));
  await page.goto('/ssh?tab=terminal&grant=grant-dev01');
  const pane = page.getByTestId('terminal-pane');
  await expect(pane).toHaveAttribute('data-phase', 'ready', { timeout: 20_000 });
  await expect(termText(page)).toContainText('routed-shell$');
  expect(urls).toHaveLength(1);
  expect(urls[0]).toMatch(/^ws:\/\/[^?#]+\/api\/v1\/ssh\/stream$/);
  const auth = JSON.parse(frames[0]!) as { type: string; ticket: string; sessionId: string };
  expect(auth.type).toBe('auth');
  expect(auth.ticket.length).toBeGreaterThan(20);
  expect(urls[0]).not.toContain(auth.ticket);
  const stored = await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage }));
  expect(stored).not.toContain(auth.ticket);
  await pane.getByRole('region').click();
  await page.keyboard.type('x');
  await expect(pane).toHaveAttribute('data-phase', 'closed', { timeout: 10_000 });
  await expect(pane.getByTestId('close-title')).toHaveText('Access no longer allowed (4403)');
  await expect(pane).toContainText('The access grant was revoked.');
  await expect(pane.getByRole('link', { name: 'Access grants' })).toBeVisible();
  // the ticket was sent exactly once
  expect(frames.filter((f) => f.includes(auth.ticket))).toHaveLength(1);
});
