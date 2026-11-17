import argon2 from 'argon2';

// OWASP-recommended argon2id parameters (m=19 MiB, t=2, p=1).
const OPTS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

export function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, OPTS);
}

let dummyHash: Promise<string> | undefined;
/** Verify; when `hash` is missing a dummy verification runs so timing does not reveal account existence. */
export async function verifyPassword(hash: string | undefined, plain: string): Promise<boolean> {
  if (!hash) {
    dummyHash ??= argon2.hash('ppanel-dummy-password-for-timing', OPTS);
    await argon2.verify(await dummyHash, plain).catch(() => false);
    return false;
  }
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}
