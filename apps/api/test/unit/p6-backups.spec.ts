import {
  ACTIVE_ALERT_KINDS,
  BACKUP_MANIFEST_MAX_ENTRIES,
  type BackupPolicyTarget,
  JOB_TYPES,
} from '@ppanel/shared-contracts';
import { describe, expect, it } from 'vitest';
import {
  agentExcludes,
  approvalReasons,
  boundJson,
  boundManifest,
  computeImpact,
  manifestFor,
  manifestRows,
  mapSnapshots,
  nextRunAfter,
  pathViolation,
  restorePlanHash,
  restoreTargetMismatch,
  scheduleError,
} from '../../src/backup/backup-common';
import { repoUrl } from '../../src/backup/backup-credentials.service';
import { isolatedRestoreTarget } from '../../src/backup/backup-runs.service';
import { resourceKeyFor, RESTRICTED_JOB_TYPES } from '../../src/jobs/jobs.service';

const H = (c: string) => c.repeat(64);
const paths: BackupPolicyTarget = { type: 'paths', paths: ['/srv/data', '/etc/app'], excludes: [] };
const vol: BackupPolicyTarget = {
  type: 'volume',
  applicationId: 'x',
  app: 'web',
  volume: 'uploads',
};
const pg: BackupPolicyTarget = {
  type: 'postgres',
  applicationId: 'y',
  app: 'shop',
  service: 'db',
  database: 'app',
  user: 'postgres',
  passwordSecretKey: 'DB_PASSWORD',
};

describe('P6 schedules (croner, IANA tz)', () => {
  it('accepts 5-field cron + IANA tz only', () => {
    expect(scheduleError('0 2 * * *', 'Asia/Bangkok')).toBeNull();
    expect(scheduleError('*/15 * * * 1-5', 'UTC')).toBeNull();
    expect(scheduleError('0 0 2 * * *', 'UTC')).toMatch(/5 fields/);
    expect(scheduleError('0 2 * * *', 'Nowhere/City')).toMatch(/timezone/);
    expect(scheduleError('61 2 * * *', 'UTC')).toMatch(/invalid cron/);
  });
  it('next run honours the timezone and DST', () => {
    expect(
      nextRunAfter('0 2 * * *', 'Asia/Bangkok', new Date('2026-11-23T18:59:00Z'))!.toISOString(),
    ).toBe('2026-11-23T19:00:00.000Z');
    expect(
      nextRunAfter('0 2 * * *', 'Asia/Bangkok', new Date('2026-11-23T19:00:00Z'))!.toISOString(),
    ).toBe('2026-11-24T19:00:00.000Z');
    expect(
      nextRunAfter('0 12 * * *', 'Europe/Berlin', new Date('2026-07-01T00:00:00Z'))!.toISOString(),
    ).toBe('2026-07-01T10:00:00.000Z');
    expect(
      nextRunAfter('0 12 * * *', 'Europe/Berlin', new Date('2026-12-01T00:00:00Z'))!.toISOString(),
    ).toBe('2026-12-01T11:00:00.000Z');
  });
});

describe('P6 path policy', () => {
  it('forbids pseudo filesystems, the agent dirs and /; parents of the agent dirs get auto-excludes', () => {
    for (const p of [
      '/',
      '/proc',
      '/proc/1/environ',
      '/sys/kernel',
      '/dev/sda',
      '/run/secrets',
      '/var/lib/ppanel-agent',
      '/var/lib/ppanel-agent/key.pem',
      '/etc/ppanel-agent/agent.yaml',
    ])
      expect(pathViolation(p), p).not.toBeNull();
    for (const p of [
      '/srv/data',
      '/var/lib/postgresql',
      '/etc/nginx',
      '/home/app',
      '/procfs-backup',
      '/device',
      '/var/lib',
      '/etc',
    ])
      expect(pathViolation(p), p).toBeNull();
    expect(agentExcludes(['/var/lib', '/etc'])).toEqual([
      '/var/lib/ppanel-agent',
      '/etc/ppanel-agent',
    ]);
    expect(agentExcludes(['/srv'])).toEqual([]);
  });
});

describe('P6 run result mapping (P6-T04: never a false success)', () => {
  it('maps snapshots by index, by echoed target, or by order; missing any target → null', () => {
    const r = mapSnapshots([paths, pg], {
      snapshots: [
        { target: 1, snapshotId: H('b'), sizeBytes: 10 },
        { target: 0, snapshotId: H('a') },
      ],
      manifest: [],
      resticVersion: '0.17.3',
    });
    expect(r!.snapshots.map((s) => [s.target, s.targetType, s.shortId])).toEqual([
      [0, 'paths', 'aaaaaaaa'],
      [1, 'postgres', 'bbbbbbbb'],
    ]);
    expect(
      mapSnapshots([paths, pg], { snapshots: [{ snapshotId: H('a') }, { snapshotId: H('b') }] }),
    ).not.toBeNull();
    expect(
      mapSnapshots([vol], {
        snapshots: [
          { target: { type: 'volume', app: 'web', volume: 'uploads' }, snapshotId: H('c') },
        ],
      }),
    ).not.toBeNull();
    expect(
      mapSnapshots([paths, pg], { snapshots: [{ target: 0, snapshotId: H('a') }] }),
    ).toBeNull();
    expect(
      mapSnapshots([paths], {
        snapshots: [
          { target: 0, snapshotId: H('a') },
          { target: 0, snapshotId: H('b') },
        ],
      }),
    ).not.toBeNull();
    expect(mapSnapshots([paths], { snapshots: [{ target: 5, snapshotId: H('a') }] })).toBeNull();
    expect(mapSnapshots([paths], { snapshots: [{ target: 0, snapshotId: 'not-hex' }] })).toBeNull();
    expect(mapSnapshots([paths], null)).toBeNull();
    expect(mapSnapshots([paths], { snapshots: [] })).toBeNull();
  });
  it('bounds and validates per-target manifests (agent shape); filters per target; flattens rows', () => {
    const entries = [
      {
        target: 0,
        type: 'paths',
        snapshotId: H('a'),
        paths: ['/srv/data', '/etc/app'],
        files: [
          { path: '/srv/data/a', size: 1, sha256: H('1') },
          { path: '/etc/app/x', size: 2, sha256: H('2') },
        ],
        fileCount: 2,
        truncated: false,
      },
      {
        target: 1,
        type: 'volume',
        snapshotId: H('b'),
        app: 'web',
        volume: 'uploads',
        files: [{ path: '/backup/uploads/f', size: 3, sha256: H('3') }],
        fileCount: 1,
        truncated: false,
      },
      {
        target: 2,
        type: 'postgres',
        snapshotId: H('c'),
        database: 'app',
        bytes: 100,
        sha256: H('4'),
        tables: [{ name: 'public.t', rows: 1 }],
        constraints: ['t_pkey PRIMARY KEY (id)'],
        fileCount: 0,
        truncated: false,
      },
      { target: 3, type: 'paths', snapshotId: 'zz', files: [], fileCount: 0, truncated: false },
      { target: 0, type: 'paths', snapshotId: H('d'), unknownField: 1 },
    ];
    const m = boundManifest(entries, false);
    expect(m.invalid).toBe(2);
    expect(m.summary).toEqual({ files: 3, bytes: 106, databases: 1, truncated: false });
    expect(manifestFor(m.entries, [paths, vol, pg], 0)).toHaveLength(1);
    expect(manifestFor(m.entries, [paths, vol, pg], 2)[0]).toMatchObject({ database: 'app' });
    expect(manifestFor(m.entries, [paths, vol, pg], 5)).toEqual([]);
    const rows = manifestRows(m.entries);
    expect(rows.map((r) => r.kind)).toEqual(['file', 'file', 'file', 'database']);
    const many = Array.from({ length: BACKUP_MANIFEST_MAX_ENTRIES }, (_, i) => ({
      path: `/srv/data/${i}`,
      size: 1,
      sha256: H('a'),
    }));
    const big = boundManifest(
      [
        {
          target: 0,
          type: 'paths',
          snapshotId: H('a'),
          files: many,
          fileCount: many.length,
          truncated: false,
        },
        {
          target: 1,
          type: 'paths',
          snapshotId: H('b'),
          files: many.slice(0, 5),
          fileCount: 5,
          truncated: false,
        },
      ],
      false,
    );
    expect(big.entries[1]!.files).toHaveLength(0); // run budget of 10 000 files exhausted
    expect(big.summary.truncated).toBe(true);
    expect(boundManifest([], true).summary.truncated).toBe(true);
  });
  it('boundJson caps stored agent output', () => {
    const v = boundJson(
      Array.from({ length: 5000 }, (_, i) => ({ i, s: 'x'.repeat(50) })),
      4096,
    ) as any;
    expect(v.truncated).toBe(true);
    expect(JSON.stringify(v).length).toBeLessThan(4200);
  });
});

describe('P6 restore planning', () => {
  it('target must address the snapshot; approval for in_place or production', () => {
    expect(
      restoreTargetMismatch(paths, { type: 'paths', include: ['/srv/data/a'], mode: 'staging' }),
    ).toBeNull();
    expect(
      restoreTargetMismatch(paths, { type: 'paths', include: ['/etc/passwd'], mode: 'staging' }),
    ).toMatch(/not inside/);
    expect(
      restoreTargetMismatch(vol, { type: 'volume', app: 'web', volume: 'other', mode: 'staging' }),
    ).not.toBeNull();
    expect(restoreTargetMismatch(pg, { ...pg, mode: 'scratch' } as never)).toBeNull();
    expect(
      restoreTargetMismatch(pg, { type: 'volume', app: 'shop', volume: 'pgdata', mode: 'staging' }),
    ).toMatch(/postgres/);
    expect(approvalReasons({ type: 'paths', include: [], mode: 'staging' }, 'uat')).toEqual([]);
    expect(approvalReasons({ type: 'paths', include: [], mode: 'in_place' }, 'uat')).toEqual([
      'in_place',
    ]);
    expect(approvalReasons({ type: 'paths', include: [], mode: 'staging' }, 'production')).toEqual([
      'production',
    ]);
    expect(
      approvalReasons(
        { type: 'volume', app: 'web', volume: 'uploads', mode: 'in_place' },
        'production',
      ),
    ).toEqual(['in_place', 'production']);
  });
  it('impact lists overwrites / creations / downtime and the config-vs-data note; planHash binds snapshot + target + impact', () => {
    const ctx = {
      snapshotId: H('a'),
      restoreId: '01a20000-0000-7000-8000-0000deadbeef',
      appKind: 'container',
      manifestFiles: 0,
    };
    const inPlace = computeImpact(
      vol,
      { type: 'volume', app: 'web', volume: 'uploads', mode: 'in_place' },
      ctx,
    );
    expect(inPlace.map((i) => i.effect)).toEqual(['overwrite', 'note', 'downtime', 'note']);
    const staging = computeImpact(
      vol,
      { type: 'volume', app: 'web', volume: 'uploads', mode: 'staging' },
      ctx,
    );
    expect(staging[0]).toMatchObject({ effect: 'create', ref: 'ppanel-web-restore-deadbeef' });
    const scratch = computeImpact(pg, { ...pg, mode: 'scratch' } as never, ctx);
    expect(scratch[0]!.effect).toBe('create');
    const base = {
      runId: 'r',
      snapshotId: H('a'),
      serverId: 's',
      target: { type: 'paths' as const, include: [] as string[], mode: 'staging' as const },
      impact: staging,
    };
    expect(restorePlanHash(base)).toMatch(/^[a-f0-9]{64}$/);
    expect(restorePlanHash(base)).not.toBe(restorePlanHash({ ...base, snapshotId: H('b') }));
    expect(restorePlanHash(base)).not.toBe(restorePlanHash({ ...base, impact: inPlace }));
  });
  it('restore tests are always isolated (staging / scratch)', () => {
    expect(isolatedRestoreTarget(paths)).toEqual({ type: 'paths', include: [], mode: 'staging' });
    expect(isolatedRestoreTarget(vol)).toMatchObject({ mode: 'staging' });
    expect(isolatedRestoreTarget(pg)).toMatchObject({ mode: 'scratch', database: 'app' });
  });
});

describe('P6 job wiring', () => {
  it('backup jobs are Center-only, locked per repo / app, verify accepts a manifest', () => {
    for (const t of ['backup.run', 'backup.snapshots', 'backup.verify', 'restore.run'] as const)
      expect(RESTRICTED_JOB_TYPES).toContain(t);
    const repo = {
      url: 'http://b:8000/node-a/',
      repositoryId: '01a20000-0000-7000-8000-000000000001',
    };
    expect(resourceKeyFor('backup.run', { repo })).toBe(`backup:${repo.repositoryId}`);
    expect(resourceKeyFor('restore.run', { repo, target: { type: 'volume', app: 'web' } })).toBe(
      'app:web',
    );
    expect(resourceKeyFor('restore.run', { repo, target: { type: 'paths' } })).toBe(
      `restore:${repo.repositoryId}`,
    );
    expect(resourceKeyFor('backup.verify', { repo })).toBeNull();
    const v = JOB_TYPES['backup.verify'].params.safeParse({
      repo,
      snapshotId: H('a'),
      manifest: [
        {
          target: 0,
          type: 'paths',
          snapshotId: H('a'),
          files: [{ path: '/srv/a', size: 1, sha256: H('1') }],
          fileCount: 1,
          truncated: false,
        },
      ],
    });
    expect(v.success).toBe(true);
    expect(repoUrl('https://backup.lab:8000/', 'node-a')).toBe('https://backup.lab:8000/node-a/');
    expect(ACTIVE_ALERT_KINDS).toContain('backup_failed');
  });
});

// Regression (P6 lab E2E 2026-11-23): compose_app_versions.plan is stored as an ARRAY of services;
// DB/volume backup targets were rejected with "compose service db not found (known: )".
import { planServices } from '../../src/backup/backup-policies.service';

describe('planServices (compose plan shapes)', () => {
  const svc = [{ service: 'db', volumes: [{ name: 'pgdata' }] }, { service: 'web' }];
  it('accepts the stored array form', () => {
    expect(planServices(svc).map((s) => s.service)).toEqual(['db', 'web']);
  });
  it('accepts the wrapped { services } form', () => {
    expect(planServices({ services: svc }).map((s) => s.service)).toEqual(['db', 'web']);
  });
  it('returns [] for null / unknown shapes', () => {
    expect(planServices(null)).toEqual([]);
    expect(planServices({ foo: 1 })).toEqual([]);
  });
});
