import { defineConfig } from 'vitest/config';

// Property-based (fast-check) tests for the shared validators: `pnpm --filter
// @ppanel/shared-contracts test:fuzz`. FC_NUM_RUNS raises the run count.
export default defineConfig({
  test: {
    include: ['src/**/*.fuzz.test.ts'],
    testTimeout: 120_000,
  },
});
