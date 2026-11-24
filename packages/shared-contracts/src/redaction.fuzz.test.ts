/**
 * P7.02 property tests for `redactLine` (shared with the Go agent, golden-tested). Properties:
 * never throws; known secret values never survive; idempotent. The counterexamples found by fuzzing
 * are regression guards (TS mirrors the Go agent's fixpoint Redactor).
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { REDACTED, redactLine } from './redaction';
import { NUM_RUNS } from './fuzz-helpers.fuzz.test';

const secretish = fc.stringMatching(/^[A-Za-z0-9_\-+/=]{6,40}$/);
const noisy = fc.string({
  unit: fc.constantFrom(...'ab =:"\',;&}{@/\nxyzTOKENpassword'.split('')),
  maxLength: 60,
});

describe('redactLine', () => {
  it('never throws and never leaves a random known secret in the output', () => {
    fc.assert(
      fc.property(noisy, secretish, noisy, fc.string({ maxLength: 200 }), (pre, s, post, junk) => {
        const out = redactLine(pre + s + post + junk + s, [s]);
        expect(out.includes(s)).toBe(false);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  it('is idempotent on pattern-only input (no known secrets)', () => {
    fc.assert(
      fc.property(fc.oneof(noisy, fc.string({ maxLength: 200 })), (l) => {
        const once = redactLine(l);
        expect(redactLine(once)).toBe(once);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  it('is idempotent with random (alphanumeric) known secrets', () => {
    fc.assert(
      fc.property(
        noisy,
        fc.array(fc.stringMatching(/^[A-Za-z0-9]{6,12}$/), { maxLength: 3 }),
        (l, ss) => {
          const once = redactLine(l + ss.join(' '), ss);
          expect(redactLine(once, ss)).toBe(once);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  // Counterexamples (fixed on both sides; Go: apps/agent/internal/redact):
  it('idempotent when a known secret replacement creates a word boundary for a pattern', () => {
    const a = redactLine('pa55wordghp_00000000000000000000', ['55word']);
    expect(redactLine(a, ['55word'])).toBe(a);
  });
  it('idempotent when a known secret overlaps the [REDACTED] marker', () => {
    const a = redactLine('aaaa[REDACTED]bbbb', ['[REDACTED]b']);
    expect(redactLine(a, ['[REDACTED]b'])).toBe(a);
  });
  it('a replacement never synthesises another known secret', () => {
    const out = redactLine('qqqqqqzzz', ['ED]zzz', 'qqqqqq']);
    expect(out.includes('ED]zzz')).toBe(false);
  });
  it('never leaves any known secret and is idempotent with marker-overlapping secrets', () => {
    const markerish = fc.stringMatching(/^[A-Za-z\[\]]{6,12}$/);
    fc.assert(
      fc.property(
        fc.string({ unit: fc.constantFrom(...'abRED[]AC TzQ'.split('')), maxLength: 40 }),
        fc.array(fc.oneof(markerish, secretish), { minLength: 1, maxLength: 3 }),
        (l, ss) => {
          const once = redactLine(l + ss.join(''), ss);
          for (const s of ss) if (!REDACTED.includes(s)) expect(once.includes(s)).toBe(false);
          expect(redactLine(once, ss)).toBe(once);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });
  it('sanity: marker constant', () => expect(REDACTED).toBe('[REDACTED]'));
});
