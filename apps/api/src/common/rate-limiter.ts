import { Injectable } from '@nestjs/common';
import { AppError } from './app-error';

/**
 * Fixed-window in-memory limiter (single Center process). Keys are opaque strings
 * (e.g. `login:<ip>:<email>`). Multi-instance deployments should move this to Redis.
 */
@Injectable()
export class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();
  private lastGc = Date.now();

  /** Throws 429 when `key` exceeded `limit` hits in `windowMs`. */
  hit(key: string, limit: number, windowMs: number): void {
    const now = Date.now();
    this.gc(now);
    let w = this.windows.get(key);
    if (!w || w.resetAt <= now) {
      w = { count: 0, resetAt: now + windowMs };
      this.windows.set(key, w);
    }
    w.count += 1;
    if (w.count > limit) throw AppError.rateLimited(Math.max(1, Math.ceil((w.resetAt - now) / 1000)));
  }

  reset(prefix?: string): void {
    if (!prefix) return this.windows.clear();
    for (const k of this.windows.keys()) if (k.startsWith(prefix)) this.windows.delete(k);
  }

  private gc(now: number): void {
    if (now - this.lastGc < 60_000) return;
    this.lastGc = now;
    for (const [k, w] of this.windows) if (w.resetAt <= now) this.windows.delete(k);
  }
}
