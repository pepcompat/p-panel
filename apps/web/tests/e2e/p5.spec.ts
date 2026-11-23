import { expect, test, type Page } from '@playwright/test';

// P5 journeys in mock mode (NEXT_PUBLIC_API_MOCK=1): fleet metrics with gaps/stale/offline,
// central logs (redaction, retention, offline, 429), live tail over mock SSE, incidents, rules,
// channels. Fixtures: worker-uat-01 offline, db-prod-01 stale, dev-sandbox-02 never reported,
// app-prod-01 has a metrics gap ~25–31 minutes ago.

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

const card = (page: Page, name: string) =>
  page.locator(`[data-testid="fleet-card"][data-server="${name}"]`);

test.describe.configure({ timeout: 120_000 });

test('monitoring: offline, stale and no-metrics are distinct; charts render gaps; deep link keeps range', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await signIn(page, 'admin', '/monitoring');
  await expect(page.getByRole('heading', { name: 'Monitoring', level: 1 })).toBeVisible();
  await expect(page.getByTestId('preview-banner')).toHaveCount(0);

  await expect(card(page, 'worker-uat-01')).toHaveAttribute('data-state', 'offline');
  await expect(card(page, 'db-prod-01')).toHaveAttribute('data-state', 'stale');
  await expect(card(page, 'dev-sandbox-02')).toHaveAttribute('data-state', 'no_metrics');
  await expect(card(page, 'app-prod-01')).toHaveAttribute('data-state', 'ok');
  await expect(card(page, 'worker-uat-01').getByTestId('state-offline')).toBeVisible();
  await expect(card(page, 'db-prod-01').getByTestId('state-stale')).toContainText('stale since');
  await expect(card(page, 'dev-sandbox-02').getByTestId('state-no-metrics')).toBeVisible();
  // None of the three shows a 0% value.
  for (const n of ['worker-uat-01', 'dev-sandbox-02'])
    await expect(card(page, n)).not.toContainText('0%');

  // Drill down: app-prod-01 CPU has a gap (null points → broken path, never 0).
  await card(page, 'app-prod-01').getByRole('button', { name: 'Charts' }).click();
  const drill = page.getByTestId('drilldown');
  await expect(drill).toBeVisible();
  const cpu = drill.locator('[data-testid="metric-chart"][data-metric="cpu"]');
  await expect(cpu).toHaveAttribute('data-gaps', '1', { timeout: 15_000 });
  await expect(cpu).toHaveAttribute('data-segments', '2');
  expect(Number(await cpu.getAttribute('data-null-points'))).toBeGreaterThan(0);
  await expect(cpu.getByTestId('chart-gap')).toHaveCount(1);
  await expect(cpu.getByTestId('chart-summary')).toContainText('1 gap(s) with no data');

  // Keyboard: focus the plot and step through values.
  await cpu.getByRole('group', { name: /use arrow keys/ }).focus();
  await page.keyboard.press('End');
  await expect(cpu.getByTestId('chart-tooltip')).toBeVisible();

  await page.getByRole('radio', { name: '6h' }).click();
  await expect(page).toHaveURL(/range=6h/);
  await expect(drill.getByTestId('series-path')).toHaveCount(6, { timeout: 15_000 });
  await page.screenshot({ path: 'test-results/p5-monitoring.png', fullPage: true });

  // Stale server: charts carry the stale marker.
  await card(page, 'db-prod-01').getByRole('button', { name: 'Charts' }).click();
  const staleCpu = drill.locator('[data-testid="metric-chart"][data-metric="cpu"]');
  await expect(staleCpu).toHaveAttribute('data-stale', 'true', { timeout: 15_000 });
  await expect(staleCpu.getByTestId('stale-marker')).toBeAttached();

  // Deep link to the server Monitoring tab carries the range filter.
  await card(page, 'db-prod-01').getByTestId('server-monitoring-link').click();
  await expect(page).toHaveURL(/\/servers\/[^/]+\/monitoring\?range=6h/);
  await expect(page.getByTestId('server-monitoring-tab')).toHaveAttribute('data-range', '6h');
  await expect(page.getByTestId('server-metrics').getByTestId('metric-chart')).toHaveCount(6);
  expect(errors).toEqual([]);
});

test('logs: redacted lines as text, distinct empty states, 429, live tail with pause', async ({
  page,
}) => {
  await signIn(page, 'admin', '/logs');
  const form = page.getByTestId('log-query-form');
  await form.getByLabel('Server').selectOption({ label: 'web-legacy-02' });
  await form.getByLabel('Time range').selectOption('6h');
  await form.getByLabel('Text contains').fill('api_key');
  await form.getByRole('button', { name: 'Run query' }).click();
  const lines = page.getByTestId('log-line');
  await expect(lines.first()).toBeVisible({ timeout: 15_000 });
  await expect(lines.first()).toContainText('api_key=[REDACTED]');
  await expect(lines.first()).not.toContainText('sk_live');
  await expect(page.getByTestId('retention-notice')).toContainText('7-day retention');
  await expect(page).toHaveURL(/q=api_key/);

  // Markup in a log line is shown as text, never rendered.
  await form.getByLabel('Text contains').fill('<script>');
  await form.getByRole('button', { name: 'Run query' }).click();
  await expect(lines.first()).toContainText('<script>alert("pwned")</script>', { timeout: 15_000 });
  await expect(page.locator('[data-testid="log-table"] script')).toHaveCount(0);

  // Load more via cursor.
  await form.getByLabel('Text contains').fill('');
  await form.getByLabel('Time range').selectOption('24h');
  await form.getByRole('button', { name: 'Run query' }).click();
  await expect(page.getByTestId('logs-count')).toHaveText('200 lines', { timeout: 15_000 });
  await page.getByTestId('logs-load-more').click();
  await expect(page.getByTestId('logs-count')).toHaveText('400 lines', { timeout: 15_000 });

  // Outside retention vs server offline vs no logs — distinct empty states.
  const toLocal = (ms: number) =>
    new Date(ms - new Date(ms).getTimezoneOffset() * 60e3).toISOString().slice(0, 16);
  await form.getByLabel('Time range').selectOption('custom');
  await form.getByLabel('From').fill(toLocal(Date.now() - 10 * 864e5));
  await form.getByLabel('To', { exact: true }).fill(toLocal(Date.now() - 9 * 864e5));
  await form.getByRole('button', { name: 'Run query' }).click();
  await expect(page.getByTestId('logs-empty')).toHaveAttribute('data-kind', 'retention', {
    timeout: 15_000,
  });
  await expect(page.getByText('Outside log retention')).toBeVisible();

  await form.getByLabel('Server').selectOption({ label: 'worker-uat-01' });
  await form.getByLabel('Time range').selectOption('15m');
  await form.getByRole('button', { name: 'Run query' }).click();
  await expect(page.getByTestId('logs-empty')).toHaveAttribute('data-kind', 'offline', {
    timeout: 15_000,
  });
  await expect(page.getByText('worker-uat-01 is offline')).toBeVisible();

  await form.getByLabel('Server').selectOption({ label: 'app-prod-01' });
  await form.getByLabel('Text contains').fill('zz-no-such-text');
  await form.getByRole('button', { name: 'Run query' }).click();
  await expect(page.getByTestId('logs-empty')).toHaveAttribute('data-kind', 'none', {
    timeout: 15_000,
  });

  // 429 with Retry-After countdown.
  await form.getByLabel('Text contains').fill('simulate-429');
  await form.getByRole('button', { name: 'Run query' }).click();
  await expect(page.getByTestId('rate-limited')).toContainText(/Retrying in \d+s/, {
    timeout: 15_000,
  });

  // Live tail over (mock) SSE: lines stream in; pause holds them; resume continues.
  await form.getByLabel('Text contains').fill('');
  await form.getByLabel('Server').selectOption({ label: 'web-legacy-02' });
  await form.getByLabel('Time range').selectOption('1h');
  await form.getByRole('button', { name: 'Run query' }).click();
  await page.getByTestId('tail-toggle').click();
  const tail = page.getByTestId('live-tail');
  await expect(tail).toHaveAttribute('data-status', 'live', { timeout: 15_000 });
  const tailLines = page.getByTestId('tail-line');
  await expect.poll(() => tailLines.count(), { timeout: 15_000 }).toBeGreaterThan(3);
  await page.getByTestId('tail-pause').click();
  await expect(tail).toHaveAttribute('data-paused', 'true');
  await expect(page.getByTestId('tail-paused')).toBeVisible();
  const frozen = await tailLines.count();
  await page.waitForTimeout(2000);
  expect(await tailLines.count()).toBe(frozen);
  await expect(page.getByTestId('tail-paused')).toContainText(/\(\d+ waiting\)/);
  await page.screenshot({ path: 'test-results/p5-logs-tail.png', fullPage: true });
  await page.getByTestId('tail-pause').click();
  await expect.poll(() => tailLines.count(), { timeout: 10_000 }).toBeGreaterThan(frozen);
  await expect(page.getByTestId('tail-lines')).not.toContainText('sk_live');
});

test('live tail closes after the max duration with a notice', async ({ page }) => {
  await signIn(page, 'admin', '/logs');
  await page.evaluate(() => sessionStorage.setItem('ppanel.mock.tailMaxMs', '2500'));
  await page
    .getByTestId('log-query-form')
    .getByLabel('Server')
    .selectOption({ label: 'app-prod-01' });
  await page.getByTestId('tail-toggle').click();
  await expect(page.getByTestId('live-tail')).toHaveAttribute('data-status', 'live', {
    timeout: 15_000,
  });
  await expect(page.getByTestId('tail-timeout')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId('live-tail')).toHaveAttribute('data-status', 'closed');
  await expect(page.getByTestId('tail-restart')).toBeVisible();
  await page.evaluate(() => sessionStorage.removeItem('ppanel.mock.tailMaxMs'));
});

test('incidents: acknowledge with comment records the actor in the timeline', async ({ page }) => {
  await signIn(page, 'admin', '/alerts');
  const row = page.getByTestId('incident-row').filter({ hasText: 'worker-uat-01' });
  await expect(row).toHaveAttribute('data-status', 'firing', { timeout: 15_000 });
  await row.click();
  const detail = page.getByTestId('incident-detail');
  await expect(detail.getByTestId('timeline-entry').first()).toHaveAttribute('data-type', 'fired');
  await detail.getByTestId('incident-ack').click();
  await page.getByLabel('Comment (optional)').fill('Investigating the UAT worker');
  await page.getByTestId('incident-ack-confirm').click();
  const ackEntry = detail.locator('[data-testid="timeline-entry"][data-type="acknowledged"]');
  await expect(ackEntry).toBeVisible({ timeout: 15_000 });
  await expect(ackEntry.getByTestId('timeline-actor')).toContainText('Ops Admin');
  await expect(ackEntry).toContainText('Investigating the UAT worker');
  await expect(detail.getByTestId('incident-ack')).toBeDisabled();
  await expect(detail.getByTestId('incident-logs-link')).toHaveAttribute(
    'href',
    /\/logs\?serverId=/,
  );
  await page.screenshot({ path: 'test-results/p5-incidents-timeline.png', fullPage: true });

  // Overview shows the open-incident count with a link.
  await page.goto('/overview');
  await expect(page.getByTestId('active-incident-count')).toHaveText(/\d+/, { timeout: 15_000 });
  await expect(page.getByTestId('alert-firing-badge').first()).toBeVisible();
});

test('rules: create a metric threshold rule; channels: test success and failure', async ({
  page,
}) => {
  await signIn(page, 'admin', '/alerts?tab=rules');
  await expect(page.getByTestId('rule-row').first()).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('rule-new').click();
  const form = page.getByTestId('rule-form');
  await form.getByLabel('Name').fill('cpu-high');
  await expect(form.getByTestId('threshold-fields')).toBeVisible();
  await form.getByLabel('Metric').selectOption('cpu');
  await form.getByLabel('Threshold (%)').fill('150');
  await page.getByTestId('rule-save').click();
  await expect(form.getByText('Percent thresholds are between 0 and 100.')).toBeVisible();
  await form.getByLabel('Threshold (%)').fill('85');
  await form.getByLabel('For (seconds)').fill('120');
  await form.getByLabel('ops-webhook').check();
  await page.getByTestId('rule-save').click();
  const row = page.locator('[data-testid="rule-row"][data-name="cpu-high"]');
  await expect(row).toBeVisible({ timeout: 15_000 });
  await expect(row).toContainText('cpu > 85% · for 120s');
  await expect(row).toContainText('ops-webhook');

  await page.getByRole('tab', { name: 'Channels' }).click();
  const hook = page.locator('[data-testid="channel-card"][data-name="ops-webhook"]');
  await hook.getByTestId('channel-test').click();
  await expect(hook.getByTestId('channel-test-result')).toHaveAttribute('data-delivered', 'true', {
    timeout: 15_000,
  });
  await expect(hook.getByTestId('channel-test-result')).toContainText('delivered');

  await page.getByTestId('channel-new').click();
  const cf = page.getByTestId('channel-form');
  await cf.getByLabel('Name').fill('broken-hook');
  await cf.getByLabel('Webhook URL').fill('http://10.0.0.5/hook');
  await expect(cf.getByTestId('url-hints')).toContainText('SSRF guard');
  await cf.getByLabel('Webhook URL').fill('https://fail.example.com/hook');
  await cf.getByTestId('channel-secret').fill('s3cr3t-signing-value');
  await page.getByTestId('channel-save').click();
  const broken = page.locator('[data-testid="channel-card"][data-name="broken-hook"]');
  await expect(broken).toBeVisible({ timeout: 15_000 });
  await expect(broken.getByTestId('secret-status')).toContainText('set');
  await expect(page.getByText('s3cr3t-signing-value')).toHaveCount(0);
  await broken.getByTestId('channel-test').click();
  await expect(broken.getByTestId('channel-test-result')).toHaveAttribute(
    'data-delivered',
    'false',
    {
      timeout: 15_000,
    },
  );
  await expect(broken.getByTestId('channel-test-result')).toContainText('HTTP 500');
  await expect(
    page.getByText('Nothing can be approved or acknowledged from Telegram').first(),
  ).toBeVisible();
  await page.screenshot({ path: 'test-results/p5-channel-test.png', fullPage: true });
});

test('viewer cannot manage rules or channels, nor acknowledge incidents', async ({ page }) => {
  await signIn(page, 'user1', '/alerts?tab=rules');
  await expect(page.getByTestId('rules-forbidden')).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole('button', { name: '+ New rule' })).toBeDisabled();
  await page.getByRole('tab', { name: 'Channels' }).click();
  await expect(page.getByTestId('channels-forbidden')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('tab', { name: /Incidents/ }).click();
  await page.getByTestId('incident-row').first().click();
  await expect(page.getByTestId('incident-ack')).toBeDisabled();
});
