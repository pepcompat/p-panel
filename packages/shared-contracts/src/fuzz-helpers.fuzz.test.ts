import { describe, expect, it } from 'vitest';

/** Shared run count for the property tests (FC_NUM_RUNS overrides). */
export const NUM_RUNS = Number(process.env.FC_NUM_RUNS ?? 2000);

describe('fuzz config', () => {
  it('has a positive run count', () => expect(NUM_RUNS).toBeGreaterThan(0));
});
