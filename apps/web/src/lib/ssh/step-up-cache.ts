/**
 * Production terminals need a recent step-up (contract §5: within the last 10 minutes). The step-up token
 * is kept in memory only (never storage) until its own expiry so a reconnect does not ask again.
 */
let cached: { token: string; exp: number } | null = null;

export const stepUpCache = {
  get(now = Date.now()): string | null {
    if (cached && cached.exp - 5_000 > now) return cached.token;
    cached = null;
    return null;
  },
  set(token: string, expiresAt: string | undefined) {
    const exp = expiresAt ? Date.parse(expiresAt) : Date.now() + 5 * 60_000;
    cached = { token, exp: Number.isFinite(exp) ? exp : Date.now() + 5 * 60_000 };
  },
  clear() {
    cached = null;
  },
};
