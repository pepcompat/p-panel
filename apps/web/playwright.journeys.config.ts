import { defineConfig, devices } from '@playwright/test';

/**
 * P8-T03 user journeys: the production web build against the real Center API and a fresh DB.
 * Never starts servers itself — run through scripts/lab/journeys.sh (starts API :4000 + web :3100,
 * creates the `ppanel_journeys` DB, tears everything down). Mock-mode specs stay in playwright.config.ts.
 *
 * Order matters: J01 needs an empty DB (first boot), then the dev seeder runs, then the rest.
 */
const artifacts = process.env.JOURNEYS_ARTIFACTS ?? 'test-results/journeys';

export default defineConfig({
  testDir: './tests/e2e/journeys',
  outputDir: `${artifacts}/test-results`,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: [
    ['list'],
    ['json', { outputFile: `${artifacts}/results.json` }],
    ['html', { outputFolder: `${artifacts}/html`, open: 'never' }],
  ],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:3100',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 1366, height: 900 },
    locale: 'en-US',
    timezoneId: 'UTC',
  },
  projects: [
    {
      name: 'first-boot',
      testMatch: /j01-.*\.journey\.ts$/,
      use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 } },
    },
    { name: 'seed', testMatch: /seed\.setup\.ts$/, dependencies: ['first-boot'] },
    {
      name: 'journeys',
      testMatch: /j(0[2-9]|1\d)-.*\.journey\.ts$/,
      dependencies: ['seed'],
      use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 } },
    },
  ],
});
