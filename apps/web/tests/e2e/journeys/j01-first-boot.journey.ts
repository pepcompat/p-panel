import { expect, test } from '@playwright/test';
import { Totp, call, evidence, randomPassword, shot, signOut } from './lib';

// J01 — first boot + 2FA (E2E-01). Requires an EMPTY Center DB (no seeder yet) and the setup token the
// runner passed to the API (JOURNEYS_SETUP_TOKEN). Everything happens in the real UI; the TOTP code is
// computed from the secret the Center returns in the totp/setup response (what an authenticator app
// would read from the QR code).

const SETUP_TOKEN = process.env.JOURNEYS_SETUP_TOKEN ?? '';

test('J01 first boot: bootstrap owner, enrol TOTP, sign in with 2FA', async ({
  page,
  request,
}, info) => {
  test.setTimeout(180_000);
  expect(SETUP_TOKEN, 'JOURNEYS_SETUP_TOKEN must be set by scripts/lab/journeys.sh').not.toBe('');
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`${e.message} @ ${page.url()}`));

  const st = await call<{ bootstrapped: boolean }>(request, 'GET', '/setup/status');
  expect(st.body.data?.bootstrapped, 'journeys need a fresh, unseeded DB').toBe(false);

  const owner = { email: 'owner@journeys.test', name: 'Journey Owner', password: randomPassword() };

  // 1 — the login page detects first boot and shows the bootstrap form
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Create the first administrator' })).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByTestId('preview-banner')).toHaveCount(0); // not the mock adapter
  await shot(page, info, 'j01-1-bootstrap-form');
  const fill = async (token: string) => {
    await page.getByLabel('Email').fill(owner.email);
    await page.getByLabel('Display name').fill(owner.name);
    await page.getByLabel('Password').fill(owner.password);
    await page.getByLabel('Setup token').fill(token);
    await page.getByRole('button', { name: 'Create administrator' }).click();
  };

  // 2 — a wrong setup token is refused (and nothing is created)
  await fill('wrong-' + SETUP_TOKEN.slice(0, 6));
  await expect(page.getByRole('alert')).toBeVisible();
  expect(
    (await call<{ bootstrapped: boolean }>(request, 'GET', '/setup/status')).body.data,
  ).toMatchObject({ bootstrapped: false });
  evidence(info, 'wrong setup token refused, still not bootstrapped');

  // 3 — correct token creates the platform owner
  await fill(SETUP_TOKEN);
  await expect(page.getByText('Administrator created. Sign in to continue.')).toBeVisible();
  evidence(info, 'owner bootstrapped via UI', { email: owner.email });
  const again = await call(request, 'POST', '/setup/bootstrap', {
    body: {
      email: 'x@journeys.test',
      displayName: 'x',
      password: randomPassword(),
      setupToken: SETUP_TOKEN,
    },
  });
  expect([401, 409]).toContain(again.status);
  evidence(info, 'second bootstrap refused', {
    status: again.status,
    code: again.body.error?.code,
  });

  // 4 — sign in (password only, no factor yet) and enrol TOTP
  await page.getByLabel('Email').fill(owner.email);
  await page.getByLabel('Password').fill(owner.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL((u) => u.pathname !== '/login', { timeout: 30_000 });
  await page.goto('/setup/2fa');
  await expect(
    page.getByRole('heading', { name: 'Set up two-factor authentication' }),
  ).toBeVisible();
  const setupRes = page.waitForResponse(
    (r) => r.url().endsWith('/auth/mfa/totp/setup') && r.request().method() === 'POST',
  );
  await page.getByRole('button', { name: 'Generate QR code' }).click();
  const setupBody = (await (await setupRes).json()) as { data: { otpauthUrl: string } };
  const totp = Totp.fromOtpauth(setupBody.data.otpauthUrl);
  await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible();
  await shot(page, info, 'j01-2-totp-qr', page.getByRole('img'));
  await page.getByLabel('Digit 1 of 6').fill(await totp.next());
  await page.getByRole('button', { name: 'Confirm and enable' }).click();
  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  const codes = await page
    .getByRole('list', { name: 'Save your recovery codes' })
    .locator('li')
    .count();
  expect(codes).toBeGreaterThanOrEqual(8);
  evidence(info, 'TOTP confirmed, recovery codes shown once', { recoveryCodes: codes });
  await page.getByLabel('I have stored these codes somewhere safe').check();
  await page.getByRole('button', { name: 'Continue to pPanel' }).click();
  await expect(page).toHaveURL(/\/overview/);

  // 5 — sign out; the next sign-in requires the second factor
  await signOut(page);
  await page.getByLabel('Email').fill(owner.email);
  await page.getByLabel('Password').fill(owner.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
  await shot(page, info, 'j01-3-mfa-prompt');
  // password alone yields only an MFA challenge (no session) — checked against the API too
  const pw = await call<{ mfaRequired?: boolean; accessToken?: string }>(
    request,
    'POST',
    '/auth/login',
    {
      body: { email: owner.email, password: owner.password },
    },
  );
  expect(pw.body.data?.mfaRequired).toBe(true);
  expect(pw.body.data?.accessToken).toBeUndefined();
  await page.getByLabel('Digit 1 of 6').fill(await totp.next());
  await page.getByRole('button', { name: 'Confirm' }).click();
  await expect(page).toHaveURL(/\/overview/, { timeout: 30_000 });
  await page.goto('/settings/security');
  await shot(page, info, 'j01-4-signed-in-with-2fa');
  evidence(info, 'sign-in with password + TOTP reaches the app');

  // 6 — the bootstrap is audited. NB: the filter is labelled "Action starts with" but the UI sends
  // `action=<value>`, which the API matches exactly (prefix `setup.` finds nothing) — reported as a
  // UI bug in docs/ACCEPTANCE.md; the full action name is used here.
  await page.goto('/settings/audit?action=setup.bootstrap');
  await expect(page.getByText('setup.bootstrap').first()).toBeVisible({ timeout: 20_000 });
  await shot(page, info, 'j01-5-audit');
  expect(errors).toEqual([]);
});
