import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Integration tests run against a real PostgreSQL database `ppanel_test` (created + migrated in globalSetup).
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['test/integration/**/*.spec.ts'],
    environment: 'node',
    env: { LOG_LEVEL: 'fatal' },
    globalSetup: ['test/integration/global-setup.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
