import { describe, expect, it } from 'vitest';
import { heartbeatSchema } from '@ppanel/shared-contracts';

// Regression: real Go agent payload from lab E2E (2026-11-17) was rejected with 422.
describe('heartbeatSchema (Go agent interop)', () => {
  const base = { seq: 1, sentAt: '2026-11-17T10:43:02.378691383Z', agentVersion: '0.1.0' };

  it('accepts null slices from Go and normalises them to []', () => {
    const r = heartbeatSchema.parse({ ...base, metrics: {}, addresses: null, capabilities: null, runningJobIds: null });
    expect(r.addresses).toEqual([]);
    expect(r.capabilities).toEqual([]);
    expect(r.runningJobIds).toEqual([]);
  });

  it('floors fractional uptime and keeps omitted metrics undefined (never 0)', () => {
    const r = heartbeatSchema.parse({ ...base, metrics: { uptimeSec: 1234.56, cpuPct: 3.2 } });
    expect(r.metrics.uptimeSec).toBe(1234);
    expect(r.metrics.memPct).toBeUndefined();
  });
});
