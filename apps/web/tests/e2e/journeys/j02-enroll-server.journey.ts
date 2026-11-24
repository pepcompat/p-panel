import { expect, test } from '@playwright/test';
import {
  J02_NODE,
  J02_PREFIX,
  LAB,
  SEED_PASSWORD,
  TAG,
  apiLogin,
  evidence,
  expectCall,
  enrollLabNode,
  killLabAgent,
  poll,
  shot,
  signIn,
  startLabAgent,
} from './lib';

// J02 — enroll a server from the UI and see it online (E2E-02). Lab only (JOURNEYS_LAB=1): the
// one-time token created in the Enroll wizard is used by the real Go agent inside ppanel-lab-node-b.

test('J02 enroll a lab server from the UI; it appears online and reconnects', async ({
  page,
  request,
}, info) => {
  test.skip(!LAB, 'needs lab agents (scripts/lab/journeys.sh --lab)');
  test.setTimeout(240_000);
  const name = `${J02_PREFIX}${TAG}`;
  await signIn(page, 'superadmin@ppanel.local', SEED_PASSWORD, { next: '/servers/new' });
  await expect(page.getByRole('heading', { name: 'Enroll server' })).toBeVisible();

  // 1 — create a one-time token in the wizard (production environment)
  await page.getByLabel('Server name').fill(name);
  await page.getByRole('radio', { name: 'Production' }).click();
  const created = page.waitForResponse(
    (r) => r.url().endsWith('/enrollments') && r.request().method() === 'POST',
  );
  await page.getByRole('button', { name: 'Create one-time token' }).click();
  const res = await created;
  expect(res.status()).toBe(201);
  const token = ((await res.json()) as { data: { token: string } }).data.token;
  await expect(page.getByLabel('Install command')).toBeVisible();
  await shot(page, info, 'j02-1-enroll-token'); // install command (contains the token) is masked
  evidence(info, 'one-time enrollment token created in UI', { name, environment: 'production' });

  // 2 — the agent on the lab node enrolls with it (what the operator's install command does)
  const serverId = enrollLabNode(J02_NODE, token);
  evidence(info, 'agent enrolled with the token', { serverId });
  await page.getByRole('button', { name: 'I copied it — close' }).click();
  await expect(page).toHaveURL(/\/servers$/);

  // 3 — the card shows up online
  const card = page.getByTestId('server-card').filter({ hasText: name });
  await expect(async () => {
    await page.reload();
    await expect(card.getByText('Online')).toBeVisible({ timeout: 3_000 });
  }).toPass({ timeout: 120_000, intervals: [2_000] });
  await shot(page, info, 'j02-2-server-online');

  const admin = await apiLogin(request, 'superadmin@ppanel.local');
  // 4 — reconnect: kill the agent, restart it, heartbeat resumes and the server stays online
  const before = await expectCall<{ lastHeartbeatAt: string }>(
    request,
    'GET',
    `/servers/${serverId}`,
    200,
    { token: admin },
  );
  killLabAgent(J02_NODE);
  await new Promise((r) => setTimeout(r, 5_000));
  startLabAgent(J02_NODE);
  const after = await poll(
    async () => {
      const s = await expectCall<{ status: string; lastHeartbeatAt: string }>(
        request,
        'GET',
        `/servers/${serverId}`,
        200,
        { token: admin },
      );
      return s.status === 'online' && s.lastHeartbeatAt > before.lastHeartbeatAt ? s : null;
    },
    90_000,
    'heartbeat after reconnect',
  );
  evidence(info, 'agent reconnects after restart', {
    heartbeatBefore: before.lastHeartbeatAt,
    heartbeatAfter: after.lastHeartbeatAt,
  });
  await page.goto(`/servers/${serverId}/overview`);
  await expect(page.getByText('Online').first()).toBeVisible({ timeout: 20_000 });
  await shot(page, info, 'j02-3-server-detail');
});
