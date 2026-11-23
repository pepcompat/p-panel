/**
 * Per-key token bucket for byte budgets (log ingest: 2 MiB/s sustained, 10 MiB burst per server).
 * In-memory, single Center process (like RateLimiter); move to Redis for multi-instance.
 */
export class ByteBucket {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();

  constructor(
    private readonly ratePerSec: number,
    private readonly burst: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Takes `cost` bytes or returns the seconds to wait (≥ 1) without taking anything. */
  take(key: string, cost: number): { ok: true } | { ok: false; retryAfterSec: number } {
    const t = this.now();
    const b = this.buckets.get(key) ?? { tokens: this.burst, at: t };
    b.tokens = Math.min(this.burst, b.tokens + ((t - b.at) / 1000) * this.ratePerSec);
    b.at = t;
    this.buckets.set(key, b);
    // a single request larger than the burst passes only on a full bucket (and leaves a debt)
    if (cost <= b.tokens || (cost > this.burst && b.tokens >= this.burst)) {
      b.tokens -= cost;
      return { ok: true };
    }
    const need = Math.min(cost, this.burst) - b.tokens;
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil(need / this.ratePerSec)) };
  }

  reset(): void {
    this.buckets.clear();
  }
}
