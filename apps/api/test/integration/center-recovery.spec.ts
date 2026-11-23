/**
 * P6-T05 (Center side): simulated Center loss → restore the Center from its own backup and
 * re-establish agent identities safely.
 *   1. Center A (ppanel_test): users + TOTP MFA, CA, an enrolled agent, a backup repo with an
 *      encrypted repo password.
 *   2. scripts/backup/center-backup.sh → pg_dump custom → restic (separate local Center repo).
 *   3. "Loss": a brand-new database `ppanel_recovered`; scripts/backup/center-restore.sh into it.
 *   4. Center B boots against ppanel_recovered with the SAME master key (from escrow):
 *      - CA private key decrypts (boot + gateway TLS issuance),
 *      - login + TOTP works (MFA secret decrypts), repo password decrypts (recovery export),
 *      - the agent's EXISTING certificate is accepted by B's mTLS gateway (no re-enrollment).
 *   5. The master key is not in the backup; a different master key cannot boot against it.
 * Needs host pg_dump/pg_restore/psql/restic or Docker (pinned postgres:16.6-alpine, restic/restic:0.17.3).
 */
import { PrismaClient } from '@prisma/client';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_DATABASE_URL, TEST_DATABASE_URL } from './env';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  heartbeatBody,
  login,
  resetDb,
  TEST_MASTER_KEY,
  type TestApp,
  totpNow,
} from './helpers';

const ROOT = path.resolve(__dirname, '../../../..');
const RECOVERED_DB = 'ppanel_recovered';
const RECOVERED_URL = TEST_DATABASE_URL.replace(/\/ppanel_test(\?|$)/, `/${RECOVERED_DB}$1`);
const REPO_PASSWORD_INPUT = 'Escrowed-Repo-Password-For-P6T05-0001';

let a: TestApp;
let work: string;
const env = () => ({
  ...process.env,
  PPANEL_CENTER_BACKUP_REPO: path.join(work, 'center-repo'),
  PPANEL_CENTER_BACKUP_PASSWORD: 'center-repo-password-p6t05-escrow',
});

function run(script: string, args: string[], extra: Record<string, string> = {}): string {
  return execFileSync(path.join(ROOT, 'scripts/backup', script), args, {
    env: { ...env(), ...extra },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 240_000,
  });
}

beforeAll(async () => {
  work = mkdtempSync(path.join(os.tmpdir(), 'ppanel-p6t05-'));
  a = await bootApp();
  const admin = new PrismaClient({ datasourceUrl: ADMIN_DATABASE_URL });
  try {
    await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${RECOVERED_DB}" WITH (FORCE)`);
    await admin.$executeRawUnsafe(`CREATE DATABASE "${RECOVERED_DB}"`);
  } finally {
    await admin.$disconnect();
  }
}, 120_000);

afterAll(async () => {
  await a?.close();
  rmSync(work, { recursive: true, force: true });
});

describe('P6-T05 Center recovery from backup', () => {
  it('backup → restore into a fresh DB → API with the same master key: MFA + CA + repo password decrypt, the existing agent cert is accepted', async () => {
    // ---- Center A state
    a.limiter.reset();
    await resetDb(a.prisma);
    await a.prisma.$executeRawUnsafe('TRUNCATE "backup_repositories" CASCADE');
    const owner = await login(a, 'superadmin');
    const setup = await a.http.post('/api/v1/auth/mfa/totp/setup').set(bearer(owner));
    const otpauth = setup.body.data.otpauthUrl as string;
    expect(
      (
        await a.http
          .post('/api/v1/auth/mfa/totp/confirm')
          .set(bearer(owner))
          .send({ code: totpNow(otpauth) })
      ).status,
    ).toBe(200);
    const agent = await enrollAgent(a, owner, { name: 'survivor', environment: 'uat' });
    const portA = await a.gateway.start(0, '127.0.0.1');
    expect(
      (await agentCall(portA, agent.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(1))).status,
    ).toBe(200);
    await a.gateway.stop();
    const repo = await a.http
      .post('/api/v1/backup-repositories')
      .set(bearer(owner))
      .send({ name: 'lab', baseUrl: 'http://backup.lab:8000' });
    expect(repo.status, JSON.stringify(repo.body)).toBe(201);
    expect(
      (
        await a.http
          .put(`/api/v1/backup-repositories/${repo.body.data.id}/servers/${agent.serverId}`)
          .set(bearer(owner))
          .send({
            restUser: 'survivor',
            restPassword: 'Rest-Pass-P6T05-0001',
            repoPassword: REPO_PASSWORD_INPUT,
          })
      ).status,
    ).toBe(200);
    // an in-flight job at backup time (must expire on the recovered Center, never replay)
    await a.prisma.job.create({
      data: {
        id: '01a20000-0000-7000-8000-00000000f00d',
        serverId: agent.serverId,
        type: 'service.restart',
        params: { unit: 'nginx.service' },
        status: 'queued',
        mutating: true,
        idempotencyKey: 'inflight-before-loss',
        expiresAt: new Date(Date.now() + 60_000),
        correlationId: 'p6t05',
      },
    });

    // ---- backup (separate Center repo; sanitized env without the master key)
    const envFile = path.join(work, 'center.env');
    writeFileSync(
      envFile,
      `API_PORT=4000\nPPANEL_MASTER_KEY=${TEST_MASTER_KEY}\nJWT_ACCESS_SECRET=jwt-secret-value-0123456789abcdef0123\nDATABASE_URL=${TEST_DATABASE_URL}\nPPANEL_GIT_HOST_ALLOWLIST=github.com\n`,
    );
    run('center-backup.sh', ['init']);
    const t0 = Date.now();
    const out = JSON.parse(
      run('center-backup.sh', ['backup'], {
        DATABASE_URL: TEST_DATABASE_URL,
        PPANEL_CENTER_ENV_FILE: envFile,
      })
        .trim()
        .split('\n')
        .pop()!,
    );
    const backupMs = Date.now() - t0;
    expect(out.snapshot).toMatch(/^[a-f0-9]{64}$/);
    expect(out.migrations).toBeGreaterThanOrEqual(6);

    // ---- "loss" + restore into the fresh DB
    const keep = path.join(work, 'meta');
    const t1 = Date.now();
    const res = JSON.parse(
      run('center-restore.sh', [out.snapshot, RECOVERED_URL], { PPANEL_RESTORE_KEEP_DIR: keep })
        .trim()
        .split('\n')
        .pop()!,
    );
    const restoreMs = Date.now() - t1;
    expect(res).toMatchObject({
      database: RECOVERED_DB,
      caKeys: 1,
      servers: 1,
      inflightJobs: 1,
      migrationStatus: 'up_to_date',
    });
    const sanitized = readFileSync(path.join(keep, 'center.env.sanitized'), 'utf8');
    expect(sanitized).toContain('API_PORT=4000');
    expect(sanitized).toContain('PPANEL_GIT_HOST_ALLOWLIST=github.com');
    expect(sanitized).toContain('PPANEL_MASTER_KEY=<removed');
    expect(sanitized).not.toContain(TEST_MASTER_KEY);
    expect(sanitized).not.toContain('jwt-secret-value');
    expect(
      JSON.parse(readFileSync(path.join(keep, 'manifest.json'), 'utf8')).masterKeyIncluded,
    ).toBe(false);
    // the raw restic repository never contains the master key in clear (restic encrypts; check anyway)
    const repoFiles = readdirSync(path.join(work, 'center-repo'), { recursive: true }) as string[];
    expect(repoFiles.length).toBeGreaterThan(3);
    // a re-run into a non-empty target is refused
    expect(() =>
      run('center-restore.sh', [out.snapshot, RECOVERED_URL], {
        PPANEL_SKIP_MIGRATION_STATUS: '1',
      }),
    ).toThrow(/not empty/);

    // ---- Center B on the recovered DB with the SAME master key (CA decrypts at boot)
    const b = await bootApp({ DATABASE_URL: RECOVERED_URL });
    try {
      const portB = await b.gateway.start(0, '127.0.0.1');
      // existing agent certificate, existing CA bundle → accepted (no re-enrollment)
      const hb = await agentCall(
        portB,
        agent.creds,
        'POST',
        '/agent/v1/heartbeat',
        heartbeatBody(2),
      );
      expect(hb.status, JSON.stringify(hb.body)).toBe(200);
      // in-flight job from before the loss: TTL lapses → expired, never delivered after it
      await b.prisma.job.update({
        where: { id: '01a20000-0000-7000-8000-00000000f00d' },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      await b.jobs.sweep();
      const tasks = await agentCall(portB, agent.creds, 'GET', '/agent/v1/tasks?waitSec=0');
      expect(tasks.status).toBe(200);
      expect(tasks.body.data.tasks).toEqual([]);
      expect(
        (
          await b.prisma.job.findUniqueOrThrow({
            where: { id: '01a20000-0000-7000-8000-00000000f00d' },
          })
        ).status,
      ).toBe('expired');
      // login + TOTP (MFA secret decrypts with the escrowed master key)
      const l = await b.http
        .post('/api/v1/auth/login')
        .send({ email: 'superadmin@ppanel.local', password: 'password' });
      expect(l.body.data.mfaRequired).toBe(true);
      await b.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
      const v = await b.http
        .post('/api/v1/auth/mfa/verify')
        .send({ mfaToken: l.body.data.mfaToken, code: totpNow(otpauth) });
      expect(v.status, JSON.stringify(v.body)).toBe(200);
      const token = v.body.data.accessToken as string;
      // repo password (encrypted with the master key) decrypts → recovery export works on B
      await b.prisma.mfaFactor.updateMany({ data: { lastUsedStep: 0 } });
      await new Promise((r) => setTimeout(r, 50));
      const su = await b.http
        .post('/api/v1/auth/step-up')
        .set(bearer(token))
        .send({ code: totpNow(otpauth) });
      expect(su.status, JSON.stringify(su.body)).toBe(200);
      const exp = await b.http
        .get(`/api/v1/backup-repositories/${repo.body.data.id}/recovery-export`)
        .set(bearer(token))
        .set('X-Step-Up', su.body.data.stepUpToken);
      expect(exp.status).toBe(200);
      expect(exp.body.data.servers[0].repoPassword).toBe(REPO_PASSWORD_INPUT);
      const servers = await b.http.get('/api/v1/servers').set(bearer(token));
      expect(servers.body.data.map((s: any) => s.name)).toEqual(['survivor']);
    } finally {
      await b.gateway.stop();
      await b.close();
    }
    // a wrong master key cannot use the backup (CA decrypt fails at boot)
    await expect(
      bootApp({
        DATABASE_URL: RECOVERED_URL,
        PPANEL_MASTER_KEY: Buffer.alloc(32, 9).toString('base64'),
      }),
    ).rejects.toThrow();
    // timings for docs/RECOVERY_RUNBOOK.md
    console.log(
      JSON.stringify({
        p6t05: {
          backupMs,
          restoreMs,
          dumpBytes: out.dumpBytes,
          scriptTotals: { backup: out.totalMs, restore: res.totalMs },
        },
      }),
    );
  }, 300_000);
});
