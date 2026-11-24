import path from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';
import { SECURITY_DATABASE_URL } from '../../tests/security/lib/db-url';

/**
 * P7.01 security suite (`pnpm test:security`). Specs live in `tests/security/**` and reuse the API
 * integration harness. They run against an isolated database (`ppanel_security`) so they never race
 * the regular integration suite (`ppanel_test`).
 */
const repo = path.resolve(__dirname, '../..');

export default defineConfig({
  plugins: [
    swc.vite({ module: { type: 'es6' }, tsconfigFile: path.join(__dirname, 'tsconfig.json') }),
  ],
  root: repo,
  test: {
    include: ['tests/security/**/*.spec.ts'],
    globals: true,
    environment: 'node',
    env: {
      LOG_LEVEL: 'fatal',
      TEST_DATABASE_URL: SECURITY_DATABASE_URL,
    },
    globalSetup: [path.join(repo, 'tests/security/global-setup.ts')],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
