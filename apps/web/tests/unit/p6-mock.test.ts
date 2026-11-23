import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import { isApiError } from '@/lib/api/errors';
import { parseDryListing, parseRestoreResult } from '@/lib/p6-gates';
import type { LoginSuccess } from '@/lib/api/types';
import type { Server } from '@ppanel/shared-contracts';
import type {
  BackupPolicy,
  BackupRepository,
  BackupRun,
  BackupRunDetail,
  RecoveryExport,
  Restore,
} from '@/lib/api/p6-types';

let offset = 0;
const realNow = Date.now.bind(Date);
const advance = (ms: number) => (offset += ms);

function client() {
  let tok: string | null = null;
  const c = createApiClient({
    baseUrl: 'http://mock/api/v1',
    clientVersion: 't',
    fetch: mockFetch as typeof fetch,
    tokenStore: { get: () => tok, set: (t) => (tok = t) },
  });
  return {
    c,
    async login(email: string) {
      const r = await c.post<LoginSuccess | { mfaRequired: true; mfaToken: string }>(
        '/auth/login',
        { email, password: 'password' },
        { auth: false },
      );
      if ('mfaToken' in r) {
        const v = await c.post<LoginSuccess>(
          '/auth/mfa/verify',
          { mfaToken: r.mfaToken, code: '123456' },
          { auth: false },
        );
        tok = v.accessToken;
      } else tok = r.accessToken;
    },
    async stepUp() {
      return (await c.post<{ stepUpToken: string }>('/auth/step-up', { code: '123456' }))
        .stepUpToken;
    },
  };
}
const fail = (p: Promise<unknown>) =>
  p.then(
    () => null,
    (e: unknown) => (isApiError(e) ? e : null),
  );

beforeEach(() => {
  resetMockState();
  offset = 0;
  vi.spyOn(Date, 'now').mockImplementation(() => realNow() + offset);
});
afterEach(() => vi.restoreAllMocks());

async function serverBy(c: ReturnType<typeof client>['c'], name: string) {
  const { items } = await c.list<Server>('/servers', { query: { limit: 100 } });
  return items.find((s) => s.name === name)!;
}

describe('mock P6 (contract §10)', () => {
  it('repositories never return passwords; recovery export needs step-up and is audited once', async () => {
    const { c, login, stepUp } = client();
    await login('superadmin');
    const [repo] = (await c.list<BackupRepository>('/backup-repositories')).items;
    expect(JSON.stringify(repo)).not.toMatch(/"password"/);
    expect(repo!.servers.every((a) => a.repoPassword.set)).toBe(true);
    expect(repo!.servers.find((a) => a.serverName === 'app-prod-02')!.initialized).toBe(false);
    expect(repo!.servers.some((a) => a.maintenance.some((m) => m.kind === 'copy' && !m.ok))).toBe(
      true,
    );
    const denied = await fail(c.get(`/backup-repositories/${repo!.id}/recovery-export`));
    expect(denied?.code).toBe('STEP_UP_REQUIRED');
    const exp = await c.get<RecoveryExport>(`/backup-repositories/${repo!.id}/recovery-export`, {
      headers: { 'X-Step-Up': await stepUp() },
    });
    expect(exp.servers.length).toBeGreaterThan(3);
    expect(exp.servers[0]!.repoPassword).toMatch(/^[A-Za-z0-9+/=]{40,}$/);
  });

  it('create policy → run now → uploaded "none" → test restore → restore_verified', async () => {
    const { c, login } = client();
    await login('admin');
    const srv = await serverBy(c, 'app-uat-01');
    const [repo] = (await c.list<BackupRepository>('/backup-repositories')).items;
    const bad = await fail(
      c.post('/backup-policies', {
        name: 'x',
        serverId: srv.id,
        repositoryId: repo!.id,
        targets: [{ type: 'paths', paths: ['/proc/self'], excludes: [] }],
        schedule: { cron: '0 2 * * *', timezone: 'Asia/Bangkok' },
      }),
    );
    expect(bad?.status).toBe(422);
    const p = await c.post<BackupPolicy>('/backup-policies', {
      name: 'uat files',
      serverId: srv.id,
      repositoryId: repo!.id,
      targets: [{ type: 'paths', paths: ['/srv/uat/files'], excludes: ['*.tmp'] }],
      schedule: { cron: '0 3 * * *', timezone: 'Asia/Bangkok' },
      retention: { keepDaily: 7, keepWeekly: 4, keepMonthly: 6 },
      verify: { afterBackup: 'none', restoreTestEvery: 'never' },
      enabled: true,
    });
    expect(p.nextRunAt).toBeTruthy();
    const { run } = await c.post<{ run: BackupRun }>(`/backup-policies/${p.id}/run`);
    expect(run.status).toBe('queued');
    expect((await fail(c.post(`/backup-policies/${p.id}/run`)))?.code).toBe('BACKUP_IN_PROGRESS');
    advance(5000);
    const done = await c.get<BackupRunDetail>(`/backup-runs/${run.id}`);
    expect(done.status).toBe('uploaded');
    expect(done.verification).toBe('none');
    expect(done.manifestEntries.length).toBeGreaterThan(0);
    expect(done.manifestPaginate.total).toBe(done.manifest!.files);
    await c.post(`/backup-runs/${run.id}/verify`, { level: 'restore_test' });
    advance(4000);
    const v = await c.get<BackupRun>(`/backup-runs/${run.id}`);
    expect(v.verification).toBe('restore_verified');
    expect(v.verifiedAt).toBeTruthy();
  });

  it('partial / not-initialized / offline runs are never uploaded', async () => {
    const { c, login } = client();
    await login('superadmin');
    const runs = (await c.list<BackupRun>('/backup-runs')).items;
    const partial = runs.find((r) => r.error?.code === 'BACKUP_PARTIAL')!;
    expect(partial.status).toBe('failed');
    expect(partial.snapshots).toEqual([]);
    expect(runs.some((r) => r.status === 'expired' && r.snapshots.length === 0)).toBe(true);
    const [repo] = (await c.list<BackupRepository>('/backup-repositories')).items;
    const prod2 = await serverBy(c, 'app-prod-02');
    const p = await c.post<BackupPolicy>('/backup-policies', {
      name: 'prod2',
      serverId: prod2.id,
      repositoryId: repo!.id,
      targets: [{ type: 'paths', paths: ['/srv/x'], excludes: [] }],
      schedule: { cron: '0 2 * * *', timezone: 'UTC' },
      retention: { keepDaily: 1, keepWeekly: 0, keepMonthly: 0 },
      verify: { afterBackup: 'none', restoreTestEvery: 'never' },
    });
    const { run } = await c.post<{ run: BackupRun }>(`/backup-policies/${p.id}/run`);
    expect(run.status).toBe('failed');
    expect(run.error?.code).toBe('REPO_NOT_INITIALIZED');
    const worker = (await c.list<BackupPolicy>('/backup-policies')).items.find(
      (x) => x.serverName === 'worker-uat-01',
    )!;
    const w = (await c.post<{ run: BackupRun }>(`/backup-policies/${worker.id}/run`)).run;
    advance(6000);
    expect((await c.get<BackupRun>(`/backup-runs/${w.id}`)).status).toBe('expired');
  });

  it('staging restore in uat: no approval, dry-run → execute → verified with compare counts', async () => {
    const { c, login } = client();
    await login('admin');
    const runs = (await c.list<BackupRun>('/backup-runs')).items;
    const src = runs.find(
      (r) => r.status === 'uploaded' && r.environment === 'uat' && r.trigger !== 'safety',
    )!;
    const snap = src.snapshots.find((s) => s.targetType === 'paths')!;
    let r = await c.post<Restore>('/restores', {
      runId: src.id,
      snapshotId: snap.snapshotId,
      target: { type: 'paths', include: [], mode: 'staging' },
    });
    expect(r.status).toBe('planned');
    expect(r.approval.required).toBe(false);
    expect(
      r.plan.impact.filter((i) => i.effect !== 'note').every((i) => i.effect === 'create'),
    ).toBe(true);
    expect(r.plan.impact.at(-1)!.ref).toBe('config_vs_data');
    r = await c.post<Restore>(`/restores/${r.id}/dry-run`);
    advance(1500);
    r = await c.get<Restore>(`/restores/${r.id}`);
    expect(r.status).toBe('impact_reviewed');
    expect(parseDryListing(r.plan.dryRun?.listing, false).files).toBeGreaterThan(0);
    r = await c.post<Restore>(`/restores/${r.id}/execute`);
    expect(r.status).toBe('running');
    advance(10_000);
    r = await c.get<Restore>(`/restores/${r.id}`);
    expect(r.status).toBe('verified');
    expect(r.steps.map((s) => s.name)).toEqual(['dry_run', 'restore']);
    const res = parseRestoreResult(r.result);
    expect(res.ok).toBe(true);
    expect(res.compared).toBeGreaterThan(0);
    expect(res.mismatches).toBe(0);
  });

  it('in_place: impact confirmation required, approval by another user, safety backup first', async () => {
    const admin = client();
    await admin.login('admin');
    const runs = (await admin.c.list<BackupRun>('/backup-runs')).items;
    const src = runs.find((r) => r.status === 'uploaded' && r.policyName === 'crm-suite nightly')!;
    const dbSnap = src.snapshots.find((s) => s.targetType === 'postgres')!;
    const p = (await admin.c.list<BackupPolicy>('/backup-policies')).items.find(
      (x) => x.id === src.policyId,
    )!;
    const t = p.targets.find((x) => x.type === 'postgres')!;
    // Restore targets use the app slug (restoreTargetSchema), never applicationId.
    const { applicationId: _id, ...rt } = t as typeof t & { applicationId: string };
    const bad = await fail(
      admin.c.post('/restores', {
        runId: src.id,
        snapshotId: dbSnap.snapshotId,
        target: { ...rt, type: 'volume', volume: 'pgdata', mode: 'in_place' },
      }),
    );
    expect(bad?.code).toBe('RESTORE_TARGET_MISMATCH');
    let r = await admin.c.post<Restore>('/restores', {
      runId: src.id,
      snapshotId: dbSnap.snapshotId,
      target: { ...rt, mode: 'in_place' },
    });
    expect(r.approval.required).toBe(true);
    expect(r.approval.reasons).toEqual(['in_place']);
    expect(r.plan.impact[0]!.effect).toBe('overwrite');
    expect(r.plan.impact.some((i) => i.effect === 'downtime')).toBe(true);
    r = await admin.c.post<Restore>(`/restores/${r.id}/dry-run`);
    advance(1500);
    r = await admin.c.get<Restore>(`/restores/${r.id}`);
    expect(r.status).toBe('awaiting_approval');
    const early = await fail(admin.c.post(`/restores/${r.id}/execute`));
    expect(early?.code).toBe('APPROVAL_REQUIRED');
    const self = await fail(admin.c.post(`/restores/${r.id}/approve`, { planHash: r.planHash }));
    expect(self?.code).toBe('APPROVER_IS_CREATOR');
    expect(r.allowedActions).not.toContain('approve');
    const owner = client();
    await owner.login('superadmin');
    const noStepUp = await fail(
      owner.c.post(`/restores/${r.id}/approve`, { planHash: r.planHash }),
    );
    expect(noStepUp?.code).toBe('STEP_UP_REQUIRED');
    r = await owner.c.post<Restore>(
      `/restores/${r.id}/approve`,
      { planHash: r.planHash },
      { headers: { 'X-Step-Up': await owner.stepUp() } },
    );
    expect(r.status).toBe('approved');
    r = await admin.c.post<Restore>(`/restores/${r.id}/execute`);
    advance(20_000);
    r = await admin.c.get<Restore>(`/restores/${r.id}`);
    expect(r.status).toBe('verified');
    expect(r.approval.usedAt).toBeTruthy();
    expect(r.steps.map((s) => s.name)).toEqual([
      'dry_run',
      'safety_backup',
      'stop_app',
      'restore',
      'start_app',
    ]);
    expect(r.safetySnapshotRunId).toBeTruthy();
    expect(r.safetySnapshotIds.length).toBeGreaterThan(0);
    const safety = await admin.c.get<BackupRun>(`/backup-runs/${r.safetySnapshotRunId}`);
    expect(safety.trigger).toBe('safety');
    expect(safety.status).toBe('uploaded');
    expect(parseRestoreResult(r.result).tables.every((x) => x.actual === x.expected)).toBe(true);
  });

  it('seeded requires_manual_recovery restore carries the safety snapshot; viewer cannot restore', async () => {
    const viewer = client();
    await viewer.login('user1');
    const list = (await viewer.c.list<Restore>('/restores')).items;
    const manual = list.find((r) => r.status === 'requires_manual_recovery')!;
    expect(manual.safetySnapshotRunId).toBeTruthy();
    expect(manual.allowedActions).toEqual([]);
    const runs = (await viewer.c.list<BackupRun>('/backup-runs')).items;
    const up = runs.find((r) => r.status === 'uploaded')!;
    expect(up.allowedActions).toEqual([]);
    const denied = await fail(
      viewer.c.post('/restores', {
        runId: up.id,
        snapshotId: up.snapshots[0]!.snapshotId,
        target: { type: 'paths', include: [], mode: 'staging' },
      }),
    );
    expect(denied?.status).toBe(403);
  });
});
