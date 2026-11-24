import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { expect, type APIRequestContext, type Page, type TestInfo } from '@playwright/test';

/**
 * Shared helpers for the P8-T03 user journeys. These drive the REAL web UI (production build) against
 * the REAL Center API (fresh `ppanel_journeys` DB) — never the mock adapter. Started by
 * scripts/lab/journeys.sh; see docs/ACCEPTANCE.md.
 */
export const API = (process.env.JOURNEYS_API_BASE ?? 'http://localhost:4000/api/v1').replace(
  /\/+$/,
  '',
);
export const LAB = process.env.JOURNEYS_LAB === '1';
export const ARTIFACTS = path.resolve(process.env.JOURNEYS_ARTIFACTS ?? 'test-results/journeys');
export const SEED_PASSWORD = 'password'; // dev seeder (apps/api/prisma/seed.ts), never production
export const TAG = String(Date.now() % 100_000);

export const randomPassword = () => `J-${randomBytes(12).toString('base64url')}`;

// ------------------------------------------------------------------ TOTP (RFC 6238, SHA-1, 30 s)
function base32Decode(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/=+$/, '').toUpperCase()) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32 secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totpAt(secret: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const d = createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const o = d[d.length - 1]! & 0x0f;
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

export const currentStep = () => Math.floor(Date.now() / 30_000);

/**
 * The Center accepts each TOTP time step once per user (replay-safe `last_used_step`), so every use
 * waits for a step newer than the previous one. Returns a code valid for at least ~3 s.
 */
export class Totp {
  private lastStep = 0;
  constructor(readonly secret: string) {}
  static fromOtpauth(url: string): Totp {
    const secret = new URL(url).searchParams.get('secret');
    if (!secret) throw new Error('otpauth URL has no secret');
    return new Totp(secret);
  }
  async next(): Promise<string> {
    for (;;) {
      const step = currentStep();
      const msLeft = 30_000 - (Date.now() % 30_000);
      if (step > this.lastStep && msLeft > 3_000) {
        this.lastStep = step;
        return totpAt(this.secret, step);
      }
      await new Promise((r) => setTimeout(r, Math.min(msLeft + 200, 30_000)));
    }
  }
}

// ------------------------------------------------------------------ API (test setup only)
export interface ApiResult<T = unknown> {
  status: number;
  body: { data?: T; error?: { code: string; message: string }; meta?: { requestId?: string } };
}

export async function call<T = Record<string, unknown>>(
  request: APIRequestContext,
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  p: string,
  opts: { token?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<ApiResult<T>> {
  const res = await request.fetch(API + p, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Request-ID': randomUUID(),
      ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.headers ?? {}),
    },
    data: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    failOnStatusCode: false,
  });
  const text = await res.text();
  return { status: res.status(), body: text ? JSON.parse(text) : {} };
}

export async function expectCall<T = Record<string, unknown>>(
  request: APIRequestContext,
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  p: string,
  expected: number | number[],
  opts: { token?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<T> {
  const r = await call<T>(request, method, p, opts);
  const ok = Array.isArray(expected) ? expected.includes(r.status) : r.status === expected;
  if (!ok)
    throw new Error(
      `${method} ${p} -> ${r.status} (expected ${expected}): ${JSON.stringify(r.body)}`,
    );
  return r.body.data as T;
}

const tokenCache = new Map<string, string>();
/** Password-only API login (seeded users have no MFA). Cached: the Center allows 5 logins/min/user. */
export async function apiLogin(
  request: APIRequestContext,
  email: string,
  password = SEED_PASSWORD,
) {
  const hit = tokenCache.get(email);
  if (hit) return hit;
  const d = await expectCall<{ accessToken: string }>(request, 'POST', '/auth/login', 200, {
    body: { email, password },
  });
  tokenCache.set(email, d.accessToken);
  return d.accessToken;
}

export async function poll<T>(
  fn: () => Promise<T | null | undefined | false>,
  timeoutMs: number,
  what: string,
  everyMs = 2_000,
): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, everyMs));
  }
}

/** Creates a global user with a confirmed TOTP factor (approver / second person). */
export async function createMfaUser(
  request: APIRequestContext,
  adminToken: string,
  name: string,
  roleKey: string,
) {
  const email = `${name}-${TAG}@journeys.test`;
  const password = randomPassword();
  await expectCall(request, 'POST', '/users', 201, {
    token: adminToken,
    body: { email, password, displayName: name, bindings: [{ roleKey, scopeType: 'global' }] },
  });
  const token = (
    await expectCall<{ accessToken: string }>(request, 'POST', '/auth/login', 200, {
      body: { email, password },
    })
  ).accessToken;
  const s = await expectCall<{ otpauthUrl: string }>(request, 'POST', '/auth/mfa/totp/setup', 200, {
    token,
  });
  const totp = Totp.fromOtpauth(s.otpauthUrl);
  await expectCall(request, 'POST', '/auth/mfa/totp/confirm', 200, {
    token,
    body: { code: await totp.next() },
  });
  return { email, password, token, totp };
}

// ------------------------------------------------------------------ UI helpers
export async function signIn(
  page: Page,
  email: string,
  password: string,
  opts: { totp?: Totp; next?: string } = {},
) {
  const next = opts.next ?? '/overview';
  await page.goto(`/login?next=${encodeURIComponent(next)}`);
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 30_000 });
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  if (opts.totp) {
    await expect(page.getByRole('heading', { name: 'Two-factor authentication' })).toBeVisible();
    await page.getByLabel('Digit 1 of 6').fill(await opts.totp.next());
    await page.getByRole('button', { name: 'Confirm' }).click();
  }
  await expect(page).toHaveURL((u) => u.pathname === next.split('?')[0], { timeout: 30_000 });
}

export async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page).toHaveURL(/\/login/, { timeout: 20_000 });
}

/** Viewport PNG per journey step (kept small for docs/evidence). */
export async function shot(page: Page, info: TestInfo, name: string, mask = page.locator('pre')) {
  const dir = path.join(ARTIFACTS, 'screens');
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${name}.png`);
  await page.screenshot({ path: file, mask: [mask], animations: 'disabled' });
  await info.attach(name, { path: file, contentType: 'image/png' });
}

/** Free-form evidence for the journey report (scripts/lab/journeys-report.mjs reads annotations). */
export function evidence(info: TestInfo, step: string, detail: Record<string, unknown> = {}) {
  info.annotations.push({ type: 'step', description: JSON.stringify({ step, ...detail }) });
}

// ------------------------------------------------------------------ lab nodes (JOURNEYS_LAB=1 only)
/** J02 enrolls this node as production; J05 deploys onto it (it has docker via lab dind + nginx). */
export const J02_NODE = 'ppanel-lab-node-b';
export const J02_PREFIX = 'j02-node-b-';
export const AGENT = '/opt/ppanel-agent/ppanel-agent-linux-arm64';
export const nodeExec = (container: string, cmd: string, timeout = 120_000) =>
  execFileSync('docker', ['exec', container, 'sh', '-c', cmd], {
    encoding: 'utf8',
    timeout,
  }).trim();

export function enrollLabNode(container: string, token: string): string {
  nodeExec(
    container,
    "pkill -f '[p]panel-agent-linux-arm64 run' || true; find /var/lib/ppanel-agent -mindepth 1 -delete",
  );
  const out = execFileSync(
    'docker',
    [
      'exec',
      container,
      'env',
      'PPANEL_DEV_INSECURE_ENROLL=1',
      AGENT,
      'enroll',
      '--center',
      'http://host.docker.internal:4000',
      '--token',
      token,
      '--state-dir',
      '/var/lib/ppanel-agent',
    ],
    { encoding: 'utf8', timeout: 120_000 },
  );
  startLabAgent(container);
  const m = /serverId=(\S+)/.exec(out);
  if (!m) throw new Error('agent enroll printed no serverId');
  return m[1]!;
}

export function startLabAgent(container: string) {
  execFileSync('docker', [
    'exec',
    '-d',
    container,
    'sh',
    '-c',
    `${AGENT} run --state-dir /var/lib/ppanel-agent > /var/log/ppanel-agent.log 2>&1`,
  ]);
}

export function killLabAgent(container: string) {
  nodeExec(container, "pkill -f '[p]panel-agent-linux-arm64 run' || true");
}
