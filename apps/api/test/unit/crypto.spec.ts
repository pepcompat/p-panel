import { describe, expect, it } from 'vitest';
import {
  decryptSecret,
  encryptSecret,
  safeEqual,
  sha256Hex,
  stableHash,
} from '../../src/common/crypto';
import { uuidv7 } from '../../src/common/ids';

const key = Buffer.alloc(32, 1);

describe('AES-256-GCM secret envelope', () => {
  it('round-trips and binds AAD', () => {
    const env = encryptSecret(key, 'JBSWY3DPEHPK3PXP', 'mfa_totp:u1');
    expect(env.startsWith('v1.')).toBe(true);
    expect(env).not.toContain('JBSWY3DPEHPK3PXP');
    expect(decryptSecret(key, env, 'mfa_totp:u1').toString()).toBe('JBSWY3DPEHPK3PXP');
    expect(() => decryptSecret(key, env, 'mfa_totp:u2')).toThrow();
    expect(() => decryptSecret(Buffer.alloc(32, 2), env, 'mfa_totp:u1')).toThrow();
  });
  it('uses a random IV per encryption', () => {
    expect(encryptSecret(key, 'x', 'a')).not.toBe(encryptSecret(key, 'x', 'a'));
  });
  it('rejects wrong key sizes', () => {
    expect(() => encryptSecret(Buffer.alloc(16), 'x', 'a')).toThrow();
  });
});

describe('hash helpers', () => {
  it('sha256Hex / safeEqual / stableHash', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(safeEqual('a', 'a')).toBe(true);
    expect(safeEqual('a', 'ab')).toBe(false);
    expect(stableHash({ b: 1, a: [1, { d: 2, c: 3 }] })).toBe(
      stableHash({ a: [1, { c: 3, d: 2 }], b: 1 }),
    );
  });
});

describe('uuidv7', () => {
  it('is RFC 9562 v7 and time-ordered', () => {
    const a = uuidv7(1_700_000_000_000);
    const b = uuidv7(1_700_000_000_001);
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(a < b).toBe(true);
  });
});
