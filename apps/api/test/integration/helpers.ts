import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import type { NestExpressApplication } from '@nestjs/platform-express';
import https from 'node:https';
import { webcrypto } from 'node:crypto';
import { authenticator } from 'otplib';
import request from 'supertest';
import { seed } from '../../prisma/seed';
import { AgentGatewayServer } from '../../src/agent/gateway.server';
import { PrismaService } from '../../src/common/prisma.service';
import { RateLimiter } from '../../src/common/rate-limiter';
import { loadConfig, type AppConfig } from '../../src/config/config';
import { createApp } from '../../src/create-app';
import { JobsService } from '../../src/jobs/jobs.service';
import { TEST_DATABASE_URL } from './env';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export const TEST_MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
export const TEST_SETUP_TOKEN = 'test-setup-token-0123456789';

export function testConfig(overrides: Record<string, string> = {}): AppConfig {
  return loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: TEST_DATABASE_URL,
    PPANEL_MASTER_KEY: TEST_MASTER_KEY,
    JWT_ACCESS_SECRET: 'test-jwt-secret-test-jwt-secret-test-jwt-secret',
    PPANEL_SETUP_TOKEN: TEST_SETUP_TOKEN,
    PPANEL_DISABLE_GATEWAY: '1',
    PPANEL_PUBLIC_GATEWAY_URL: 'https://localhost:4443',
    PPANEL_PUBLIC_API_URL: 'http://localhost:4000',
    WEB_ORIGIN: 'http://localhost:3100',
    LOG_LEVEL: 'fatal',
    BODY_LIMIT: '256kb',
    ...overrides,
  });
}

export interface TestApp {
  app: NestExpressApplication;
  http: ReturnType<typeof request>;
  prisma: PrismaService;
  jobs: JobsService;
  limiter: RateLimiter;
  gateway: AgentGatewayServer;
  config: AppConfig;
  close(): Promise<void>;
}

export async function bootApp(overrides: Record<string, string> = {}): Promise<TestApp> {
  const config = testConfig(overrides);
  const app = await createApp(config);
  await app.init();
  return {
    app,
    config,
    http: request(app.getHttpServer()),
    prisma: app.get(PrismaService),
    jobs: app.get(JobsService),
    limiter: app.get(RateLimiter),
    gateway: app.get(AgentGatewayServer),
    close: () => app.close(),
  };
}

const TABLES = [
  'notification_deliveries',
  'notification_channels',
  'incident_events',
  'incidents',
  'alert_states',
  'alert_rules',
  'log_tail_tokens',
  'log_batches',
  'server_telemetry',
  'container_samples',
  'source_inspections',
  'compose_app_versions',
  'builds',
  'build_configs',
  'auto_deploy_policies',
  'webhook_deliveries',
  'integrations',
  'operation_approvals',
  'deployment_steps',
  'deployments',
  'secrets',
  'container_apps',
  'host_port_allocations',
  'managed_routing',
  'nginx_revision_approvals',
  'nginx_config_revisions',
  'adoption_reviews',
  'discovery_findings',
  'applications',
  'discovery_scans',
  'audit_events',
  'jobs',
  'agent_heartbeats',
  'server_capabilities',
  'server_addresses',
  'agent_certificates',
  'agent_enrollments',
  'servers',
  'server_groups',
  'recovery_codes',
  'mfa_factors',
  'sessions',
  'role_bindings',
  'users',
];

/** Wipes all data except the CA (kept so a running app's in-memory CA stays consistent). */
export async function resetDb(
  prisma: PrismaService,
  opts: { seedUsers?: boolean } = { seedUsers: true },
): Promise<void> {
  await prisma.$executeRawUnsafe(`TRUNCATE ${TABLES.map((t) => `"${t}"`).join(', ')} CASCADE`);
  if (opts.seedUsers !== false) await seed(prisma);
}

export async function login(t: TestApp, name: string, password = 'password'): Promise<string> {
  const res = await t.http
    .post('/api/v1/auth/login')
    .send({ email: `${name}@ppanel.local`, password });
  if (res.status !== 200 || !res.body.data?.accessToken)
    throw new Error(`login ${name} failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body.data.accessToken as string;
}

export const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

export function totpNow(otpauthUrl: string): string {
  const secret = new URL(otpauthUrl).searchParams.get('secret')!;
  return authenticator.generate(secret);
}

/** Enrolls TOTP for the token's user and returns a fresh X-Step-Up token. */
export async function stepUpToken(t: TestApp, accessToken: string): Promise<string> {
  const setup = await t.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(accessToken));
  if (setup.status !== 200) throw new Error(`totp setup failed ${setup.status}`);
  const url = setup.body.data.otpauthUrl as string;
  const conf = await t.http
    .post('/api/v1/auth/mfa/totp/confirm')
    .set(bearer(accessToken))
    .send({ code: totpNow(url) });
  if (conf.status !== 200) throw new Error(`totp confirm failed ${conf.status}`);
  await t.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } }); // next TOTP window
  const su = await t.http
    .post('/api/v1/auth/step-up')
    .set(bearer(accessToken))
    .send({ code: totpNow(url) });
  if (su.status !== 200) throw new Error(`step-up failed ${su.status} ${JSON.stringify(su.body)}`);
  return su.body.data.stepUpToken as string;
}

// ---------------------------------------------------------------- agent PKI helpers

const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIG = { name: 'ECDSA', hash: 'SHA-256' } as const;

function pem(der: ArrayBuffer, label: string): string {
  return `-----BEGIN ${label}-----\n${Buffer.from(der)
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .trim()}\n-----END ${label}-----\n`;
}

export interface AgentKey {
  keyPem: string;
  csrPem: string;
  keys: CryptoKeyPair;
}

export async function newAgentKey(curve: 'P-256' | 'P-384' = 'P-256'): Promise<AgentKey> {
  const alg = { name: 'ECDSA', namedCurve: curve };
  const keys = (await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: 'CN=ignored-by-center',
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: curve === 'P-256' ? 'SHA-256' : 'SHA-384' },
  });
  return {
    keys,
    keyPem: pem(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY'),
    csrPem: csr.toString('pem'),
  };
}

/** A completely separate CA that issues a look-alike agent certificate (spoofing attempt). */
export async function spoofedAgentCert(
  serverId: string,
): Promise<{ keyPem: string; certPem: string }> {
  const caKeys = (await webcrypto.subtle.generateKey(EC, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    name: 'CN=pPanel Internal Agent CA evil',
    keys: caKeys,
    signingAlgorithm: SIG,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
    ],
  });
  const leaf = await newAgentKey();
  const cert = await x509.X509CertificateGenerator.create({
    subject: `CN=agent:${serverId}`,
    issuer: ca.subject,
    publicKey: leaf.keys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: SIG,
    extensions: [
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: 'url', value: `ppanel://agent/${serverId}` },
      ]),
    ],
  });
  return { keyPem: leaf.keyPem, certPem: cert.toString('pem') };
}

export interface AgentCreds {
  keyPem?: string;
  certPem?: string;
  caPem: string;
}

export interface AgentResponse {
  status: number;
  body: any;
}

/** Real mTLS request to the gateway (fresh TLS session each call). */
export function agentCall(
  port: number,
  creds: AgentCreds,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<AgentResponse> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        servername: 'localhost',
        method,
        path,
        key: creds.keyPem,
        cert: creds.certPem,
        ca: creds.caPem,
        agent: false,
        headers: {
          'X-Agent-Protocol': '1',
          ...(payload
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown = text;
          try {
            parsed = JSON.parse(text);
          } catch {
            /* keep text */
          }
          resolve({ status: res.statusCode ?? 0, body: parsed });
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export interface EnrolledAgent {
  serverId: string;
  creds: Required<AgentCreds>;
  key: AgentKey;
}

/** Creates an enrollment as `token` user and enrolls a fresh agent key. */
export async function enrollAgent(
  t: TestApp,
  accessToken: string,
  opts: { name?: string; environment?: 'production' | 'uat' | 'development' } = {},
): Promise<EnrolledAgent> {
  const en = await t.http
    .post('/api/v1/enrollments')
    .set(bearer(accessToken))
    .send({
      name: opts.name ?? `node-${Math.random().toString(36).slice(2, 8)}`,
      environment: opts.environment ?? 'development',
    });
  if (en.status !== 201)
    throw new Error(`enrollment create failed ${en.status} ${JSON.stringify(en.body)}`);
  const key = await newAgentKey();
  const res = await t.http.post('/api/v1/agent/enroll').send({
    token: en.body.data.token,
    csrPem: key.csrPem,
    hostname: 'lab-node',
    facts: { os: { id: 'ubuntu', version: '24.04', arch: 'arm64' }, agentVersion: '0.1.0' },
  });
  if (res.status !== 201)
    throw new Error(`agent enroll failed ${res.status} ${JSON.stringify(res.body)}`);
  return {
    serverId: res.body.data.serverId,
    key,
    creds: {
      keyPem: key.keyPem,
      certPem: res.body.data.certificatePem,
      caPem: res.body.data.caPem,
    },
  };
}

export function heartbeatBody(seq = 1, extra: Record<string, unknown> = {}) {
  return {
    seq,
    sentAt: new Date().toISOString(),
    agentVersion: '0.1.0',
    metrics: { cpuPct: 12.5, memPct: 40.1, diskPct: 63, load1: 0.4, uptimeSec: 3600 },
    addresses: [
      { family: 'ipv4', scope: 'private', address: '10.104.0.3', interface: 'eth1' },
      { family: 'ipv4', scope: 'public', address: '203.0.113.10', interface: 'eth0' },
    ],
    capabilities: ['docker', 'nginx', 'systemd'],
    runningJobIds: [],
    ...extra,
  };
}
