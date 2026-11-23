import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import {
  describeCron,
  isValidTimeZone,
  nextRuns,
  parseCron,
  zonedToUtc,
  type ParsedCron,
} from '@/lib/cron';
import {
  hostPathError,
  impactGate,
  parseDryListing,
  parseRestoreResult,
  restoreGate,
  restoreNeedsApproval,
  runGate,
  stepForStatus,
  validatePolicy,
  verificationBadge,
} from '@/lib/p6-gates';
import type { BackupRun, Restore } from '@/lib/api/p6-types';
import { en } from '@/i18n/en';
import { th } from '@/i18n/th';
import { translate } from '@/i18n/core';
import { VerificationBadge, describeSchedule } from '@/components/p6/bits';
import { emptyPolicy } from '@/components/p6/policy-form';
import { meWithRole, renderWith } from './test-utils';

const parsed = (e: string): ParsedCron => {
  const p = parseCron(e);
  if (!p.ok) throw new Error(`bad cron ${e}`);
  return p.cron;
};
const isoZ = (ms: number) => new Date(ms).toISOString();
const tEn = (k: keyof typeof en, v?: Record<string, string | number>) => translate(en, k, v);
const tTh = (k: keyof typeof en, v?: Record<string, string | number>) => translate(th, k, v);

describe('cron: parse', () => {
  it('parses lists, ranges, steps, names and dow 7 = Sunday', () => {
    const c = parsed('*/15 1-3,22 * jan-mar mon,7');
    expect(c.minute.values).toEqual([0, 15, 30, 45]);
    expect(c.hour.values).toEqual([1, 2, 3, 22]);
    expect(c.dom.any).toBe(true);
    expect(c.month.values).toEqual([1, 2, 3]);
    expect(c.dow.values).toEqual([0, 1]);
  });
  it('rejects bad input with the offending field', () => {
    expect(parseCron('0 2 * *')).toEqual({
      ok: false,
      error: { field: 'fields', value: '0 2 * *' },
    });
    expect(parseCron('60 2 * * *')).toMatchObject({ ok: false, error: { field: 'minute' } });
    expect(parseCron('0 24 * * *')).toMatchObject({ ok: false, error: { field: 'hour' } });
    expect(parseCron('0 2 0 * *')).toMatchObject({ ok: false, error: { field: 'dom' } });
    expect(parseCron('0 2 * 13 *')).toMatchObject({ ok: false, error: { field: 'month' } });
    expect(parseCron('0 2 * * 8')).toMatchObject({ ok: false, error: { field: 'dow' } });
    expect(parseCron('0 5-2 * * *').ok).toBe(false);
    expect(parseCron('*/0 * * * *').ok).toBe(false);
  });
});

describe('cron: human-readable preview (EN + TH)', () => {
  it('describes common shapes', () => {
    expect(describeCron(parsed('0 2 * * *'))).toEqual({ kind: 'daily', times: ['02:00'] });
    expect(describeCron(parsed('*/15 * * * *'))).toEqual({ kind: 'everyNMinutes', n: 15 });
    expect(describeCron(parsed('5 * * * *'))).toEqual({ kind: 'hourly', minute: 5 });
    expect(describeCron(parsed('0 */6 * * *'))).toEqual({ kind: 'everyNHours', n: 6, minute: 0 });
    expect(describeCron(parsed('30 3 * * 0'))).toEqual({
      kind: 'weekly',
      days: [0],
      times: ['03:30'],
    });
    expect(describeCron(parsed('0 4 1,15 * *'))).toEqual({
      kind: 'monthly',
      days: [1, 15],
      times: ['04:00'],
    });
    expect(describeCron(parsed('0 4 * 6 *'))).toEqual({ kind: 'custom' });
  });
  it('renders text with the timezone, in both locales', () => {
    expect(describeSchedule('0 2 * * *', 'Asia/Bangkok', tEn)).toBe(
      'Every day at 02:00 (Asia/Bangkok)',
    );
    expect(describeSchedule('30 3 * * 0', 'UTC', tEn)).toBe('Every Sunday at 03:30 (UTC)');
    expect(describeSchedule('0 2 * * *', 'Asia/Bangkok', tTh)).toBe(
      'ทุกวัน เวลา 02:00 (Asia/Bangkok)',
    );
    expect(describeSchedule('0 25 * * *', 'UTC', tEn)).toBe('Invalid cron: hour “25”');
  });
});

describe('cron: next runs in an IANA timezone', () => {
  it('validates zones', () => {
    expect(isValidTimeZone('Asia/Bangkok')).toBe(true);
    expect(isValidTimeZone('Mars/Olympus')).toBe(false);
    expect(isValidTimeZone('')).toBe(false);
  });

  it('02:00 Asia/Bangkok (UTC+7) = 19:00Z the day before; next 3 are consecutive days', () => {
    const from = Date.parse('2026-11-23T12:00:00Z'); // 19:00 ICT
    const runs = nextRuns('0 2 * * *', 'Asia/Bangkok', from, 3).map(isoZ);
    expect(runs).toEqual([
      '2026-11-23T19:00:00.000Z',
      '2026-11-24T19:00:00.000Z',
      '2026-11-25T19:00:00.000Z',
    ]);
  });

  it('is strictly after `from` and matches the same wall time in UTC', () => {
    const from = Date.parse('2026-11-23T02:00:00Z');
    expect(nextRuns('0 2 * * *', 'UTC', from, 1).map(isoZ)).toEqual(['2026-11-24T02:00:00.000Z']);
    expect(nextRuns('*/20 * * * *', 'UTC', from, 3).map(isoZ)).toEqual([
      '2026-11-23T02:20:00.000Z',
      '2026-11-23T02:40:00.000Z',
      '2026-11-23T03:00:00.000Z',
    ]);
  });

  it('weekly Sunday 03:30 in New York uses the local day', () => {
    const from = Date.parse('2026-11-23T00:00:00Z'); // Sun 22 Nov 19:00 EST
    const runs = nextRuns('30 3 * * 0', 'America/New_York', from, 2).map(isoZ);
    expect(runs).toEqual(['2026-11-29T08:30:00.000Z', '2026-12-06T08:30:00.000Z']); // EST = UTC-5
  });

  it('DST spring-forward: a non-existent wall time is skipped', () => {
    // Europe/Berlin jumps 02:00 → 03:00 on 2026-03-29.
    expect(zonedToUtc(2026, 3, 29, 2, 30, 'Europe/Berlin')).toBeNull();
    const runs = nextRuns('30 2 * * *', 'Europe/Berlin', Date.parse('2026-03-28T12:00:00Z'), 2);
    expect(runs.map(isoZ)).toEqual(['2026-03-30T00:30:00.000Z', '2026-03-31T00:30:00.000Z']);
  });

  it('DST fall-back: an ambiguous wall time runs once, at its first occurrence', () => {
    // 2026-10-25 02:30 happens twice in Berlin (CEST then CET); first = 00:30Z.
    const runs = nextRuns('30 2 * * *', 'Europe/Berlin', Date.parse('2026-10-24T12:00:00Z'), 2);
    expect(runs.map(isoZ)).toEqual(['2026-10-25T00:30:00.000Z', '2026-10-26T01:30:00.000Z']);
  });

  it('dom + dow restricted → either matches (Vixie semantics); Feb 29 is found', () => {
    const runs = nextRuns('0 0 13 * 5', 'UTC', Date.parse('2026-11-01T00:00:00Z'), 3).map(isoZ);
    expect(runs).toEqual([
      '2026-11-06T00:00:00.000Z', // Friday
      '2026-11-13T00:00:00.000Z', // 13th (also a Friday)
      '2026-11-20T00:00:00.000Z',
    ]);
    expect(nextRuns('0 0 29 2 *', 'UTC', Date.parse('2026-03-01T00:00:00Z'), 1).map(isoZ)).toEqual([
      '2028-02-29T00:00:00.000Z',
    ]);
  });

  it('returns nothing for an invalid zone or cron', () => {
    expect(nextRuns('0 2 * * *', 'Nope/Zone', Date.now(), 3)).toEqual([]);
    expect(nextRuns('bad', 'UTC', Date.now(), 3)).toEqual([]);
  });
});

const run = (over: Partial<BackupRun>): BackupRun => ({
  id: 'r1',
  policyId: 'p1',
  policyName: 'p',
  serverId: 's1',
  repositoryId: 'repo1',
  trigger: 'manual',
  status: 'uploaded',
  verification: 'none',
  verifiedAt: null,
  verifying: null,
  targets: [{ type: 'paths', paths: ['/srv'], excludes: [] }],
  snapshots: [
    {
      target: 0,
      targetType: 'paths',
      snapshotId: 'abcdef12',
      shortId: 'abcdef12',
      sizeBytes: 1,
      filesNew: 1,
      filesChanged: 0,
      durationMs: 1,
    },
  ],
  manifest: { files: 1, bytes: 1, databases: 0, truncated: false },
  error: null,
  scheduledFor: null,
  startedAt: null,
  finishedAt: null,
  jobId: null,
  resticVersion: null,
  restoreId: null,
  createdBy: null,
  createdAt: '2026-11-23T00:00:00Z',
  allowedActions: ['verify_check', 'verify_restore_test', 'restore'],
  ...over,
});

describe('verification badge mapping (D4-C: honest wording)', () => {
  it('maps each uploaded verification level', () => {
    expect(verificationBadge(run({ verification: 'none' }))).toMatchObject({
      key: 'bk.ver.notVerified',
      tone: 'stale',
    });
    expect(verificationBadge(run({ verification: 'repository_checked' }))).toMatchObject({
      key: 'bk.ver.repoChecked',
    });
    expect(
      verificationBadge(
        run({ verification: 'restore_verified', verifiedAt: '2026-11-20T10:00:00Z' }),
        () => '20 Nov',
      ),
    ).toMatchObject({ key: 'bk.ver.restoreVerifiedOn', vars: { date: '20 Nov' }, tone: 'ok' });
    expect(verificationBadge(run({ verification: 'verify_failed' }))).toMatchObject({
      key: 'bk.ver.verifyFailed',
      tone: 'crit',
    });
    expect(en['bk.ver.notVerified']).toBe('Snapshot uploaded — not verified');
  });

  it('a failed / partial / expired run never shows success, whatever verification says', () => {
    for (const status of ['failed', 'expired', 'cancelled', 'queued', 'running'] as const) {
      const b = verificationBadge(run({ status, verification: 'restore_verified', snapshots: [] }));
      expect(b.success).toBe(false);
      expect(b.tone).not.toBe('ok');
      expect(b.key).not.toMatch(/restoreVerified|repoChecked|notVerified/);
    }
    expect(
      verificationBadge(
        run({ status: 'failed', error: { code: 'BACKUP_PARTIAL', message: '' }, snapshots: [] }),
      ),
    ).toMatchObject({ key: 'bk.ver.partial', level: 'partial', tone: 'crit' });
  });

  it('renders EN and TH badges', () => {
    renderWith(<VerificationBadge run={run({})} showHint />);
    expect(screen.getByTestId('verification-badge')).toHaveTextContent(
      'Snapshot uploaded — not verified',
    );
    expect(screen.getByText(/no restore has been tested/)).toBeInTheDocument();
    renderWith(<VerificationBadge run={run({ status: 'failed', snapshots: [] })} />, {
      locale: 'th',
    });
    expect(screen.getAllByTestId('verification-badge')[1]).toHaveTextContent(
      'สำรองล้มเหลว — ไม่มีสแนปช็อต',
    );
  });

  it('verify / restore actions only for an uploaded run with the right permission', () => {
    const owner = meWithRole('platform_owner').permissions;
    const viewer = meWithRole('viewer').permissions;
    expect(runGate('restore', run({}), owner).allowed).toBe(true);
    expect(runGate('restore', run({}), viewer)).toMatchObject({
      allowed: false,
      reason: { key: 'perm.missing', vars: { perm: 'backups.restore' } },
    });
    expect(runGate('verify_check', run({ status: 'failed', snapshots: [] }), owner)).toMatchObject({
      allowed: false,
      reason: { key: 'bk.reason.notUploaded' },
    });
    expect(
      runGate('verify_restore_test', run({ verifying: { level: 'check', startedAt: '' } }), owner)
        .allowed,
    ).toBe(false);
  });
});

const A: Restore['approval'] = {
  required: false,
  reasons: [],
  approvedBy: null,
  approvedAt: null,
  expiresAt: null,
  usedAt: null,
};
const restore = (over: Partial<Restore>): Restore => ({
  id: 'x1',
  runId: 'r1',
  snapshotId: 'abcdef12',
  serverId: 's1',
  target: { type: 'paths', include: [], mode: 'staging' },
  status: 'impact_reviewed',
  applicationId: null,
  plan: { impact: [], dryRun: null },
  planHash: 'aa'.repeat(32),
  approval: A,
  safetySnapshotRunId: null,
  safetySnapshotIds: [],
  steps: [],
  result: null,
  error: null,
  createdBy: 'u1',
  createdAt: '2026-11-23T00:00:00Z',
  updatedAt: '2026-11-23T00:00:00Z',
  finishedAt: null,
  version: 1,
  allowedActions: ['dry_run', 'approve', 'execute', 'cancel'],
  ...over,
});

describe('restore gating (P6-T03, D4-B)', () => {
  const owner = meWithRole('platform_owner').permissions;
  it('approval needed for in_place anywhere or any production target', () => {
    expect(restoreNeedsApproval('staging', 'uat')).toBe(false);
    expect(restoreNeedsApproval('scratch', 'development')).toBe(false);
    expect(restoreNeedsApproval('staging', 'production')).toBe(true);
    expect(restoreNeedsApproval('in_place', 'uat')).toBe(true);
  });
  it('in_place cannot continue without the explicit impact confirmation', () => {
    expect(impactGate('in_place', false)).toMatchObject({
      allowed: false,
      reason: { key: 'rs.reason.confirmImpact' },
    });
    expect(impactGate('in_place', true).allowed).toBe(true);
    expect(impactGate('staging', false).allowed).toBe(true);
    const r = restore({
      target: { type: 'paths', include: [], mode: 'in_place' },
      status: 'approved',
      approval: { ...A, required: true, reasons: ['in_place'], approvedBy: 'u2', approvedAt: '' },
    });
    expect(restoreGate('execute', r, owner, 'u1', false, 'in_place').allowed).toBe(false);
    expect(restoreGate('execute', r, owner, 'u1', true, 'in_place').allowed).toBe(true);
  });
  it('the creator cannot approve; execute waits for approval', () => {
    const r = restore({
      status: 'awaiting_approval',
      approval: { ...A, required: true, reasons: ['production'] },
    });
    expect(restoreGate('approve', r, owner, 'u1')).toMatchObject({
      reason: { key: 'rs.reason.selfApproval' },
    });
    expect(restoreGate('approve', r, owner, 'u2').allowed).toBe(true);
    expect(restoreGate('approve', r, meWithRole('deployer').permissions, 'u2').allowed).toBe(false);
    expect(restoreGate('execute', r, owner, 'u1')).toMatchObject({
      reason: { key: 'rs.reason.needsApproval' },
    });
    expect(restoreGate('execute', restore({}), owner, 'u1').allowed).toBe(true);
    expect(restoreGate('execute', restore({ status: 'planned' }), owner, 'u1').allowed).toBe(false);
  });
  it('maps statuses onto wizard steps', () => {
    expect(stepForStatus('planned')).toBe('impact');
    expect(stepForStatus('impact_reviewed')).toBe('dryrun');
    expect(stepForStatus('awaiting_approval')).toBe('approval');
    expect(stepForStatus('running')).toBe('execute');
    expect(stepForStatus('requires_manual_recovery')).toBe('result');
  });
});

describe('tolerant parsing of agent-defined blobs', () => {
  it('dry-run listing: object or array; unknown shapes degrade to empty', () => {
    expect(
      parseDryListing(
        { files: 3, bytes: 10, entries: [{ path: '/a', action: 'overwrite' }] },
        true,
      ),
    ).toMatchObject({ files: 3, bytes: 10, entries: [{ path: '/a', action: 'overwrite' }] });
    expect(parseDryListing(['/a', '/b'], false).entries).toEqual([
      { path: '/a', action: 'create' },
      { path: '/b', action: 'create' },
    ]);
    expect(parseDryListing(null, false)).toMatchObject({ files: null, entries: [], tables: [] });
  });
  it('restore result: verify.compared / mismatches / stagingPath', () => {
    expect(
      parseRestoreResult({ verify: { ok: true, compared: 12, mismatches: [] }, stagingPath: '/x' }),
    ).toMatchObject({ ok: true, compared: 12, mismatches: 0, location: '/x' });
    expect(parseRestoreResult(undefined)).toMatchObject({ ok: null, compared: null });
  });
});

describe('policy validation', () => {
  it('rejects forbidden / non-canonical paths and bad schedule', () => {
    expect(hostPathError('/srv/app/uploads')).toBeNull();
    expect(hostPathError('srv')).toBe('bk.err.pathFormat');
    expect(hostPathError('/srv/../etc')).toBe('bk.err.pathCanonical');
    expect(hostPathError('/proc/1')).toBe('bk.err.pathForbidden');
    expect(hostPathError('/var/lib/ppanel-agent/state')).toBe('bk.err.pathForbidden');
    expect(hostPathError('/')).toBe('bk.err.pathRoot');
    const p = {
      ...emptyPolicy('s1', 'repo1'),
      name: 'x',
      targets: [{ type: 'paths' as const, paths: ['/dev/sda'], excludes: [] }],
      schedule: { cron: '0 2 * *', timezone: 'Nope/Zone' },
    };
    const e = validatePolicy(p);
    expect(e['targets.0.paths.0']).toBe('bk.err.pathForbidden');
    expect(e.cron).toBe('bk.err.cron');
    expect(e.timezone).toBe('bk.err.timezone');
    expect(validatePolicy({ ...emptyPolicy('s1', 'repo1'), name: 'x' }).targets).toBe(
      'bk.err.noTargets',
    );
  });
});
