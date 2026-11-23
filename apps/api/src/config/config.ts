import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

const bool = z
  .enum(['0', '1', 'true', 'false'])
  .optional()
  .transform((v) => v === '1' || v === 'true');

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_URL: z.string().min(1),
  API_PORT: z.coerce.number().int().min(0).max(65535).default(4000),
  API_HOST: z.string().default('127.0.0.1'),
  AGENT_GATEWAY_PORT: z.coerce.number().int().min(0).max(65535).default(4443),
  AGENT_GATEWAY_HOST: z.string().default('0.0.0.0'),
  PPANEL_GATEWAY_HOSTNAMES: z.string().default('localhost,host.docker.internal'),
  PPANEL_PUBLIC_GATEWAY_URL: z
    .string()
    .url()
    .refine((u) => u.startsWith('https://'), 'PPANEL_PUBLIC_GATEWAY_URL must be https://')
    .default('https://localhost:4443'),
  PPANEL_PUBLIC_API_URL: z.string().url().default('http://localhost:4000'),
  PPANEL_MASTER_KEY: z
    .string()
    .min(1, 'PPANEL_MASTER_KEY is required (openssl rand -base64 32)')
    .refine(
      (v) => Buffer.from(v, 'base64').length === 32,
      'PPANEL_MASTER_KEY must be 32 bytes base64',
    ),
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  PPANEL_SETUP_TOKEN: z.string().optional(),
  WEB_ORIGIN: z.string().default('http://localhost:3100'),
  BODY_LIMIT: z.string().default('256kb'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error', 'fatal']).default('info'),
  COOKIE_SECURE: bool,
  PPANEL_AGENT_CERT_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  PPANEL_HEARTBEAT_KEEP: z.coerce.number().int().min(10).max(100_000).default(500),
  /** Max time a request waits for an `nginx.read_files` job (GET files / create revision). */
  PPANEL_NGINX_READ_WAIT_MS: z.coerce.number().int().min(0).max(60_000).default(20_000),
  PPANEL_TASK_LEASE_SEC: z.coerce.number().int().min(5).max(3600).default(60),
  PPANEL_TASK_RUNNING_LEASE_SEC: z.coerce.number().int().min(10).max(3600).default(120),
  PPANEL_SWEEP_INTERVAL_MS: z.coerce.number().int().min(100).max(600_000).default(5000),
  PPANEL_DEV_INSECURE_ENROLL: bool,
  /** Comma list of registry hosts (host[:port]) the Center may contact to resolve tags → digests. */
  PPANEL_REGISTRY_ALLOWLIST: z.string().default(''),
  /** Comma list of allowlisted registry hosts spoken to over plain HTTP (lab only). */
  PPANEL_REGISTRY_INSECURE: z.string().default(''),
  PPANEL_DISABLE_GATEWAY: bool,
  /**
   * P4b: comma list of git hosts (host or host:port) build configs may fetch from. An entry without a
   * port matches any port of that host. Outside production `lab-git` is always allowed.
   */
  PPANEL_GIT_HOST_ALLOWLIST: z.string().default('github.com'),

  // ---------------------------------------------------------------- P5 observability
  PPANEL_PROMETHEUS_URL: z.string().url().default('http://127.0.0.1:59090'),
  PPANEL_LOKI_URL: z.string().url().default('http://127.0.0.1:53100'),
  /** Timeout for every Prometheus / Loki HTTP call (ms). */
  PPANEL_OBS_TIMEOUT_MS: z.coerce.number().int().min(100).max(60_000).default(5000),
  /** Static bearer for GET /internal/metrics (or *_FILE, the same file Prometheus mounts). Unset = 404. */
  PPANEL_METRICS_SCRAPE_TOKEN: z.string().optional(),
  PPANEL_METRICS_SCRAPE_TOKEN_FILE: z.string().optional(),
  /** Loki retention (same variable as infra/observability); reported as meta.retention.days. */
  LOKI_RETENTION_PERIOD: z
    .string()
    .regex(/^\d+[hd]$/, 'LOKI_RETENTION_PERIOD must look like 168h or 7d')
    .default('168h'),
  /** Per-server log ingest budget (decompressed bytes): sustained rate + burst → 429 Retry-After. */
  PPANEL_LOG_INGEST_RATE_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .default(2 * 1024 * 1024),
  PPANEL_LOG_INGEST_BURST_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .default(10 * 1024 * 1024),
  PPANEL_LOG_TAIL_POLL_MS: z.coerce.number().int().min(100).max(60_000).default(2000),
  PPANEL_LOG_TAIL_MAX_SEC: z.coerce.number().int().min(1).max(3600).default(900),
  PPANEL_ALERT_EVAL_INTERVAL_MS: z.coerce.number().int().min(1000).max(600_000).default(15_000),
  /** Dashboard base used in notification links. */
  PPANEL_PUBLIC_WEB_URL: z.string().url().default('http://localhost:3100'),
  /** Hosts (host or host:port) webhook channels may reach over plain http (never in production). */
  PPANEL_WEBHOOK_HTTP_ALLOWLIST: z.string().default(''),
  /** Hosts (host or host:port) exempt from the private/loopback address block (metadata IPs stay blocked). */
  PPANEL_WEBHOOK_ALLOWLIST: z.string().default(''),
  /** SMTP for email channels, e.g. smtp://127.0.0.1:51025 (lab Mailpit). Unset = email channels fail. */
  PPANEL_SMTP_URL: z.string().optional(),
  PPANEL_SMTP_FROM: z.string().default('pPanel <alerts@ppanel.local>'),
  PPANEL_TELEGRAM_API_BASE: z.string().url().default('https://api.telegram.org'),
  PPANEL_NOTIFY_TIMEOUT_MS: z.coerce.number().int().min(100).max(60_000).default(5000),
  /** Backoff base between the 3 notification retries (base, 2×base, 4×base). */
  PPANEL_NOTIFY_RETRY_BASE_MS: z.coerce.number().int().min(0).max(60_000).default(1000),
});

export type AppConfig = z.infer<typeof envSchema> & {
  masterKey: Buffer;
  /** resolved scrape bearer (env or file), null = scrape endpoint disabled */
  metricsScrapeToken: string | null;
  lokiRetentionDays: number;
  webhookHttpAllowlist: string[];
  webhookAllowlist: string[];
  gatewayHostnames: string[];
  webOrigins: string[];
  isProduction: boolean;
};

let loaded = false;
function loadDotEnv(): void {
  if (loaded) return;
  loaded = true;
  // Real environment always wins; .env files only fill gaps (dev convenience).
  for (const file of [path.resolve(__dirname, '../.env'), path.resolve(process.cwd(), '.env')]) {
    if (existsSync(file)) {
      try {
        process.loadEnvFile(file);
      } catch {
        /* ignore malformed dev env */
      }
    }
  }
}

export function loadConfig(overrides: Record<string, string | undefined> = {}): AppConfig {
  loadDotEnv();
  const parsed = envSchema.safeParse({ ...process.env, ...overrides });
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  const c = parsed.data;
  let metricsScrapeToken: string | null = c.PPANEL_METRICS_SCRAPE_TOKEN?.trim() || null;
  if (!metricsScrapeToken && c.PPANEL_METRICS_SCRAPE_TOKEN_FILE) {
    try {
      metricsScrapeToken = readFileSync(c.PPANEL_METRICS_SCRAPE_TOKEN_FILE, 'utf8').trim() || null;
    } catch {
      throw new Error('Invalid configuration: PPANEL_METRICS_SCRAPE_TOKEN_FILE is not readable');
    }
  }
  if (metricsScrapeToken && metricsScrapeToken.length < 32)
    throw new Error('Invalid configuration: metrics scrape token must be at least 32 characters');
  const retention = /^(\d+)([hd])$/.exec(c.LOKI_RETENTION_PERIOD)!;
  const list = (v: string) =>
    v
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean);
  return {
    ...c,
    metricsScrapeToken,
    lokiRetentionDays:
      retention[2] === 'd'
        ? Number(retention[1])
        : Math.max(1, Math.ceil(Number(retention[1]) / 24)),
    webhookHttpAllowlist: list(c.PPANEL_WEBHOOK_HTTP_ALLOWLIST),
    webhookAllowlist: list(c.PPANEL_WEBHOOK_ALLOWLIST),
    masterKey: Buffer.from(c.PPANEL_MASTER_KEY, 'base64'),
    gatewayHostnames: c.PPANEL_GATEWAY_HOSTNAMES.split(',')
      .map((h) => h.trim())
      .filter(Boolean),
    webOrigins: c.WEB_ORIGIN.split(',')
      .map((h) => h.trim())
      .filter(Boolean),
    isProduction: c.NODE_ENV === 'production',
  };
}

export const APP_CONFIG = Symbol('APP_CONFIG');
