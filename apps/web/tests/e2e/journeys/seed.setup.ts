import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { apiLogin } from './lib';

// Runs after J01 (which needs an empty DB): adds the dev seeder users superadmin/admin/dev/user1
// (password `password`, apps/api/prisma/seed.ts) to the journeys DB for the remaining journeys.
test('seed dev users into the journeys DB', async ({ request }) => {
  const db = process.env.JOURNEYS_DATABASE_URL;
  expect(db, 'JOURNEYS_DATABASE_URL must be set by scripts/lab/journeys.sh').toBeTruthy();
  execFileSync('pnpm', ['--filter', '@ppanel/api', 'seed'], {
    cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../..'),
    env: { ...process.env, DATABASE_URL: db, NODE_ENV: 'development' },
    stdio: 'inherit',
    timeout: 120_000,
  });
  expect(await apiLogin(request, 'user1@ppanel.local')).toBeTruthy();
});
