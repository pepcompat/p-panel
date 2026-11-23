import { existsSync } from 'node:fs';
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
  PPANEL_TASK_LEASE_SEC: z.coerce.number().int().min(5).max(3600).default(60),
  PPANEL_TASK_RUNNING_LEASE_SEC: z.coerce.number().int().min(10).max(3600).default(120),
  PPANEL_SWEEP_INTERVAL_MS: z.coerce.number().int().min(100).max(600_000).default(5000),
  PPANEL_DEV_INSECURE_ENROLL: bool,
  PPANEL_DISABLE_GATEWAY: bool,
});

export type AppConfig = z.infer<typeof envSchema> & {
  masterKey: Buffer;
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
  return {
    ...c,
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
