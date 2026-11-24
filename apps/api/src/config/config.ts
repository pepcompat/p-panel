import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import {
  type ConnectionPath,
  DEFAULT_DO_API_BASE,
  type GatewayEndpoint,
} from '@ppanel/shared-contracts';
import { z } from 'zod';
import { type BuildInfo, deriveMinAgentVersion, resolveBuildInfo } from '../version/build-info';

const bool = z
  .enum(['0', '1', 'true', 'false'])
  .optional()
  .transform((v) => v === '1' || v === 'true');

/** compose passes `VAR=` for unset optional values (infra/release/compose.yml) → treat '' as unset */
const emptyAsUnset = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess((v) => (typeof v === 'string' && v.trim() === '' ? undefined : v), schema);

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

  // ---------------------------------------------------------------- P6 backups
  /** Bearer for POST /backup-maintenance/reports (operator maintenance script). Unset = endpoint 404. */
  PPANEL_BACKUP_REPORT_TOKEN: z.string().optional(),
  /** Backup scheduler tick (cron slots are minute-granular). */
  PPANEL_BACKUP_SCHEDULER_INTERVAL_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(600_000)
    .default(30_000),
  /** TTL of backup.run / restore.run jobs (an agent that never finishes → run `expired`). */
  PPANEL_BACKUP_JOB_TTL_SEC: z.coerce
    .number()
    .int()
    .min(60)
    .max(86_400)
    .default(6 * 3600),

  // ---------------------------------------------------------------- P8 release
  /** Build identity, injected by the image build (Dockerfile build args); dev falls back to VERSION. */
  PPANEL_VERSION: z.string().max(64).optional(),
  PPANEL_COMMIT: z.string().max(64).optional(),
  PPANEL_BUILD_DATE: z.string().max(64).optional(),
  /**
   * Agents older than this get 409 AGENT_OUTDATED for mutating jobs (RELEASE_CONTRACT §2).
   * Default: production = N-1 minor of PPANEL_VERSION; development/test = 0.0.0 (ad-hoc lab builds).
   */
  /** Where enrollment install commands download install-agent.sh + binaries (default: GitHub release). */
  PPANEL_AGENT_DOWNLOAD_BASE: emptyAsUnset(
    z
      .string()
      .url()
      .refine((u) => u.startsWith('https://'), 'PPANEL_AGENT_DOWNLOAD_BASE must be https://')
      .optional(),
  ),
  // ---------------------------------------------------------------- P9 networking
  /**
   * One gateway listener per management path: `public=0.0.0.0:4443,private=0.0.0.0:4444`. Unset = one
   * `public` listener on AGENT_GATEWAY_HOST:AGENT_GATEWAY_PORT (pre-P9 behaviour).
   */
  PPANEL_GATEWAY_LISTENERS: emptyAsUnset(z.string().max(500).optional()),
  /** Advertised private-path gateway URL (optional; enables the `private` endpoint for agents). */
  PPANEL_PRIVATE_GATEWAY_URL: emptyAsUnset(
    z
      .string()
      .url()
      .refine((u) => u.startsWith('https://'), 'PPANEL_PRIVATE_GATEWAY_URL must be https://')
      .optional(),
  ),
  /**
   * Comma list of extra provider API bases a DigitalOcean integration may use (lab fake API). The
   * official https://api.digitalocean.com is always allowed. Listed bases are exempt from the
   * private-address block (cloud metadata addresses stay blocked); http only outside production.
   */
  PPANEL_DO_API_BASE: z.string().default(''),
  PPANEL_PROVIDER_TIMEOUT_MS: z.coerce.number().int().min(500).max(60_000).default(10_000),
  PPANEL_MIN_AGENT_VERSION: emptyAsUnset(
    z
      .string()
      .regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, 'PPANEL_MIN_AGENT_VERSION must be SemVer')
      .optional(),
  ),
});

export type AppConfig = z.infer<typeof envSchema> & {
  masterKey: Buffer;
  /** resolved scrape bearer (env or file), null = scrape endpoint disabled */
  metricsScrapeToken: string | null;
  /** P6 maintenance report bearer, null = endpoint disabled */
  backupReportToken: string | null;
  lokiRetentionDays: number;
  webhookHttpAllowlist: string[];
  webhookAllowlist: string[];
  gatewayHostnames: string[];
  webOrigins: string[];
  isProduction: boolean;
  build: BuildInfo;
  minAgentVersion: string;
  /** P9: gateway listeners (label = management path of every request arriving on it) */
  gatewayListeners: GatewayListener[];
  /** P9: advertised endpoints (public always, private when PPANEL_PRIVATE_GATEWAY_URL is set) */
  gatewayEndpoints: GatewayEndpoint[];
  /** P9: allowed provider API bases (normalised, no trailing slash) */
  doApiBases: string[];
};

export interface GatewayListener {
  label: ConnectionPath;
  host: string;
  port: number;
}

/** Parses `public=0.0.0.0:4443,private=[::]:4444` (labels unique, public/private only). */
export function parseGatewayListeners(raw: string): GatewayListener[] {
  const out: GatewayListener[] = [];
  for (const part of raw
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)) {
    const m = /^(public|private)=(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):(\d{1,5})$/.exec(part);
    if (!m) throw new Error(`Invalid configuration: PPANEL_GATEWAY_LISTENERS entry "${part}"`);
    const port = Number(m[3]);
    if (port > 65535)
      throw new Error(`Invalid configuration: PPANEL_GATEWAY_LISTENERS port ${port} out of range`);
    const label = m[1] as ConnectionPath;
    if (out.some((l) => l.label === label))
      throw new Error(`Invalid configuration: PPANEL_GATEWAY_LISTENERS label ${label} repeated`);
    out.push({ label, host: m[2]!.replace(/^\[|\]$/g, ''), port });
  }
  if (out.length === 0) throw new Error('Invalid configuration: PPANEL_GATEWAY_LISTENERS is empty');
  return out;
}

/** Canonical form of a provider API base: origin + path without trailing slash, no query/credentials. */
export function normalizeApiBase(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password) return null;
  if (u.search || u.hash) return null;
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

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
  const backupReportToken = c.PPANEL_BACKUP_REPORT_TOKEN?.trim() || null;
  if (backupReportToken && backupReportToken.length < 32)
    throw new Error(
      'Invalid configuration: PPANEL_BACKUP_REPORT_TOKEN must be at least 32 characters',
    );
  if (metricsScrapeToken && metricsScrapeToken.length < 32)
    throw new Error('Invalid configuration: metrics scrape token must be at least 32 characters');
  const retention = /^(\d+)([hd])$/.exec(c.LOKI_RETENTION_PERIOD)!;
  const build = resolveBuildInfo(c);
  const list = (v: string) =>
    v
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean);
  return {
    ...c,
    metricsScrapeToken,
    backupReportToken,
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
    build,
    minAgentVersion:
      c.PPANEL_MIN_AGENT_VERSION ??
      (c.NODE_ENV === 'production' ? deriveMinAgentVersion(build.version) : '0.0.0'),
    gatewayListeners: c.PPANEL_GATEWAY_LISTENERS
      ? parseGatewayListeners(c.PPANEL_GATEWAY_LISTENERS)
      : [{ label: 'public', host: c.AGENT_GATEWAY_HOST, port: c.AGENT_GATEWAY_PORT }],
    gatewayEndpoints: [
      { path: 'public', url: c.PPANEL_PUBLIC_GATEWAY_URL },
      ...(c.PPANEL_PRIVATE_GATEWAY_URL
        ? [{ path: 'private' as const, url: c.PPANEL_PRIVATE_GATEWAY_URL }]
        : []),
    ],
    doApiBases: doApiBases(c.PPANEL_DO_API_BASE, c.NODE_ENV === 'production'),
  };
}

function doApiBases(raw: string, production: boolean): string[] {
  const out = [DEFAULT_DO_API_BASE];
  for (const entry of raw
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean)) {
    const n = normalizeApiBase(entry);
    if (!n) throw new Error(`Invalid configuration: PPANEL_DO_API_BASE entry "${entry}"`);
    if (production && n.startsWith('http:'))
      throw new Error('Invalid configuration: PPANEL_DO_API_BASE must be https:// in production');
    if (!out.includes(n)) out.push(n);
  }
  return out;
}

export const APP_CONFIG = Symbol('APP_CONFIG');
