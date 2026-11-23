/**
 * Minimal Prometheus / Loki HTTP clients (127.0.0.1 only, fixed timeouts). Errors never carry the
 * query text or upstream bodies to API clients.
 */
import { Inject, Injectable } from '@nestjs/common';
import { ERROR_CODES } from '@ppanel/shared-contracts';
import { AppError } from '../common/app-error';
import { logger } from '../common/logger';
import { APP_CONFIG, type AppConfig } from '../config/config';

export class BackendUnavailableError extends Error {
  constructor(
    public readonly backend: 'prometheus' | 'loki',
    message: string,
  ) {
    super(message);
    this.name = 'BackendUnavailableError';
  }
}

export function metricsUnavailable(): AppError {
  return new AppError(
    503,
    ERROR_CODES.METRICS_BACKEND_UNAVAILABLE,
    'Metrics backend is unavailable, try again later',
    { backend: 'prometheus' },
    { 'Retry-After': '15' },
  );
}

export function logsUnavailable(retryAfterSec = 10): AppError {
  return new AppError(
    503,
    ERROR_CODES.LOGS_BACKEND_UNAVAILABLE,
    'Log backend is unavailable, try again later',
    { backend: 'loki' },
    { 'Retry-After': String(retryAfterSec) },
  );
}

export interface PromMatrixSeries {
  metric: Record<string, string>;
  values: Array<[number, string]>;
}

@Injectable()
export class PrometheusClient {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  async queryRange(
    query: string,
    start: number,
    end: number,
    step: number,
  ): Promise<PromMatrixSeries[]> {
    const u = new URL('/api/v1/query_range', this.config.PPANEL_PROMETHEUS_URL);
    const body = new URLSearchParams({
      query,
      start: String(start),
      end: String(end),
      step: `${step}s`,
      timeout: `${Math.max(1, Math.floor(this.config.PPANEL_OBS_TIMEOUT_MS / 1000))}s`,
    });
    let res: Response;
    try {
      res = await fetch(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        signal: AbortSignal.timeout(this.config.PPANEL_OBS_TIMEOUT_MS),
      });
    } catch (err) {
      throw new BackendUnavailableError('prometheus', (err as Error).message);
    }
    const json = (await res.json().catch(() => null)) as {
      status?: string;
      data?: { resultType?: string; result?: PromMatrixSeries[] };
      error?: string;
    } | null;
    if (!res.ok || json?.status !== 'success' || json.data?.resultType !== 'matrix') {
      logger.emit('warn', 'prometheus query failed', {
        component: 'observability',
        status: res.status,
        error: json?.error?.slice(0, 200),
      });
      throw new BackendUnavailableError('prometheus', `status ${res.status}`);
    }
    return json.data.result ?? [];
  }
}

export interface LokiStream {
  stream: Record<string, string>;
  values: Array<[string, string]>;
}

export type LokiPushResult = { ok: true } | { ok: false; rejected: true; status: number };

@Injectable()
export class LokiClient {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  /**
   * Push one batch. Network errors, 429 and 5xx → BackendUnavailableError (caller answers 503 so the
   * agent retries). Other 4xx (e.g. too-old / oversized entries) → `rejected` (not retryable).
   */
  async push(streams: LokiStream[]): Promise<LokiPushResult> {
    if (streams.length === 0) return { ok: true };
    const u = new URL('/loki/api/v1/push', this.config.PPANEL_LOKI_URL);
    let res: Response;
    try {
      res = await fetch(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ streams }),
        signal: AbortSignal.timeout(this.config.PPANEL_OBS_TIMEOUT_MS),
      });
    } catch (err) {
      throw new BackendUnavailableError('loki', (err as Error).message);
    }
    if (res.ok) {
      await res.body?.cancel().catch(() => undefined);
      return { ok: true };
    }
    const text = (await res.text().catch(() => '')).slice(0, 300);
    if (res.status === 429 || res.status >= 500)
      throw new BackendUnavailableError('loki', `status ${res.status}`);
    logger.emit('warn', 'loki rejected a push', {
      component: 'observability',
      status: res.status,
      reason: text.replace(/\{[^}]*\}/g, '{…}'), // no label values / lines in logs
    });
    return { ok: false, rejected: true, status: res.status };
  }

  /** Log query (range). Returns raw streams; caller merges, sorts and re-checks scope. */
  async queryRange(
    query: string,
    startNs: bigint,
    endNs: bigint,
    limit: number,
    direction: 'backward' | 'forward',
  ): Promise<LokiStream[]> {
    const u = new URL('/loki/api/v1/query_range', this.config.PPANEL_LOKI_URL);
    u.searchParams.set('query', query);
    u.searchParams.set('start', startNs.toString());
    u.searchParams.set('end', endNs.toString());
    u.searchParams.set('limit', String(limit));
    u.searchParams.set('direction', direction);
    let res: Response;
    try {
      res = await fetch(u, { signal: AbortSignal.timeout(this.config.PPANEL_OBS_TIMEOUT_MS) });
    } catch (err) {
      throw new BackendUnavailableError('loki', (err as Error).message);
    }
    const json = (await res.json().catch(() => null)) as {
      status?: string;
      data?: { resultType?: string; result?: LokiStream[] };
    } | null;
    if (!res.ok || json?.status !== 'success') {
      logger.emit('warn', 'loki query failed', { component: 'observability', status: res.status });
      throw new BackendUnavailableError('loki', `status ${res.status}`);
    }
    return json.data?.resultType === 'streams' ? (json.data.result ?? []) : [];
  }
}
