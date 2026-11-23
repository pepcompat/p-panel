import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BUILTIN_ROLES } from '@ppanel/shared-contracts';
import { DiffViewer } from '@/components/p3/diff-viewer';
import { OwnershipDialog, OwnershipPanel } from '@/components/p3/ownership';
import { diffStats, parseUnifiedDiff, unifiedDiff } from '@/lib/diff';
import { ownershipConfirmReady, ownershipSteps, revisionGate } from '@/lib/p3-gates';
import type { Application, NginxRevision } from '@/lib/api/p3-types';
import { meWithRole, renderWith } from './test-utils';

const ALL = [...BUILTIN_ROLES.platform_owner];

function app(over: Partial<Application> = {}): Application {
  return {
    id: 'a1',
    serverId: 's1',
    serverName: 'app-uat-01',
    name: 'api-example-lab',
    environment: 'uat',
    kind: 'nginx_proxy',
    domains: ['api.example.lab'],
    ownershipMode: 'observed',
    flags: { unsupported: true, conflict: false, manualReview: true, driftDetected: false },
    sourceFindingFingerprint: 'f'.repeat(64),
    nginxFiles: [
      { path: '/etc/nginx/sites-enabled/03-proxy-api.conf', lastKnownSha256: 'a'.repeat(64) },
    ],
    lastScanId: 'scan1',
    allowedActions: ['discover', 'adopt'],
    version: 2,
    createdAt: '2026-11-20T00:00:00Z',
    updatedAt: '2026-11-20T00:00:00Z',
    reasons: ['unsupported directives: limit_req'],
    unsupportedDirectives: ['limit_req'],
    driftFiles: [],
    ...over,
  };
}

function rev(over: Partial<NginxRevision> = {}): NginxRevision {
  return {
    id: 'r1',
    serverId: 's1',
    applicationId: 'a1',
    status: 'draft',
    files: [],
    planHash: 'p'.repeat(64),
    postchecks: [],
    validation: null,
    validateJobId: null,
    approval: { required: true, approvedBy: null, approvedAt: null, expiresAt: null },
    applyJobId: null,
    revertJobId: null,
    result: null,
    createdBy: 'creator',
    createdAt: '2026-11-20T00:00:00Z',
    updatedAt: '2026-11-20T00:00:00Z',
    version: 1,
    ...over,
  };
}

describe('unified diff', () => {
  it('produces hunks with + / - lines and parses line numbers back', () => {
    const before = 'a\nb\nc\nd\n';
    const after = 'a\nb\nC\nd\ne\n';
    const d = unifiedDiff('/etc/nginx/x.conf', before, after);
    expect(d).toContain('--- a/etc/nginx/x.conf');
    expect(d).toContain('-c');
    expect(d).toContain('+C');
    expect(diffStats(d)).toEqual({ added: 2, removed: 1 });
    const rows = parseUnifiedDiff(d);
    expect(rows.find((r) => r.type === 'del')).toMatchObject({ oldNo: 3, text: 'c' });
    expect(rows.find((r) => r.type === 'add')).toMatchObject({ newNo: 3, text: 'C' });
    expect(unifiedDiff('/x', 'same\n', 'same\n')).toBe('');
  });
});

describe('DiffViewer', () => {
  it('renders added/removed lines with colour AND text markers for screen readers', () => {
    const diff = unifiedDiff(
      '/etc/nginx/x.conf',
      'listen 80;\nroot /a;\n',
      'listen 80;\nroot /b;\n',
    );
    renderWith(
      <DiffViewer
        files={[
          {
            path: '/etc/nginx/x.conf',
            diff,
            beforeSha256: 'a'.repeat(64),
            afterSha256: 'b'.repeat(64),
          },
        ]}
      />,
    );
    const table = screen.getByRole('table', { name: 'Changes to /etc/nginx/x.conf' });
    const added = table.querySelector('tr[data-diff="add"]')!;
    const removed = table.querySelector('tr[data-diff="del"]')!;
    expect(added.className).toContain('bg-ok-bg');
    expect(removed.className).toContain('bg-crit-bg');
    expect(within(added as HTMLElement).getByText('added')).toHaveClass('sr-only');
    expect(within(removed as HTMLElement).getByText('removed')).toHaveClass('sr-only');
    expect(added.textContent).toContain('+');
    expect(removed.textContent).toContain('−');
    expect(screen.getByLabelText('1 lines added')).toHaveTextContent('+1');
  });
  it('shows an empty state when nothing changed', () => {
    renderWith(<DiffViewer files={[{ path: '/x', diff: '' }]} />);
    expect(screen.getByTestId('diff-empty')).toHaveTextContent('No changes');
  });
});

describe('ownership step gating', () => {
  it('only offers adjacent tiers (never skips)', () => {
    const steps = ownershipSteps(app(), ALL);
    expect(steps.map((s) => s.to).sort()).toEqual(['adopted', 'discovered']);
    expect(
      ownershipSteps(app({ ownershipMode: 'discovered', allowedActions: ['observe'] }), ALL).map(
        (s) => s.to,
      ),
    ).toEqual(['observed']);
  });
  it('requires ack for flagged adopt, step-up for production, and blocks managed when unsupported', () => {
    const up = ownershipSteps(app(), ALL).find((s) => s.to === 'adopted')!;
    expect(up.needsAck).toBe(true);
    expect(up.needsStepUp).toBe(false);
    expect(
      ownershipSteps(app({ environment: 'production' }), ALL).find((s) => s.to === 'adopted')!
        .needsStepUp,
    ).toBe(true);
    const managed = ownershipSteps(
      app({ ownershipMode: 'adopted', allowedActions: ['observe', 'manage'] }),
      ALL,
    ).find((s) => s.to === 'managed')!;
    expect(managed.gate).toEqual({ allowed: false, reason: { key: 'own.blocked.unsupported' } });
  });
  it('mirrors permissions and allowedActions', () => {
    const viewer = ownershipSteps(app(), BUILTIN_ROLES.viewer);
    expect(viewer.every((s) => !s.gate.allowed)).toBe(true);
    const noAction = ownershipSteps(app({ allowedActions: [] }), ALL);
    expect(noAction.find((s) => s.to === 'adopted')!.gate.reason?.key).toBe(
      'perm.actionNotAllowed',
    );
  });
  it('confirm needs reason + ack checkbox (+ 6-digit code in production)', () => {
    const step = ownershipSteps(app(), ALL).find((s) => s.to === 'adopted')!;
    const base = {
      step,
      reason: 'owner confirmed',
      acknowledged: false,
      otp: '',
      mfaEnabled: true,
    };
    expect(ownershipConfirmReady(base)).toBe(false);
    expect(ownershipConfirmReady({ ...base, acknowledged: true })).toBe(true);
    expect(ownershipConfirmReady({ ...base, acknowledged: true, reason: ' ' })).toBe(false);
    const prod = ownershipSteps(app({ environment: 'production' }), ALL).find(
      (s) => s.to === 'adopted',
    )!;
    expect(ownershipConfirmReady({ ...base, step: prod, acknowledged: true })).toBe(false);
    expect(ownershipConfirmReady({ ...base, step: prod, acknowledged: true, otp: '123456' })).toBe(
      true,
    );
    expect(
      ownershipConfirmReady({
        ...base,
        step: prod,
        acknowledged: true,
        otp: '123456',
        mfaEnabled: false,
      }),
    ).toBe(false);
  });
  it('adopt dialog lists reasons and keeps Confirm disabled until "I reviewed these" is ticked', async () => {
    const a = app();
    const step = ownershipSteps(a, ALL).find((s) => s.to === 'adopted')!;
    renderWith(<OwnershipDialog app={a} step={step} open onOpenChange={() => {}} />, {
      me: meWithRole('ops_admin'),
    });
    expect(screen.getByTestId('ack-reasons')).toHaveTextContent(
      'unsupported directives: limit_req',
    );
    expect(screen.getByText('Ownership changes never touch the host.')).toBeInTheDocument();
    const confirm = screen.getByRole('button', { name: 'Confirm Adopted' });
    await userEvent.type(screen.getByLabelText('Reason (audited)'), 'owner confirmed');
    expect(confirm).toBeDisabled();
    await userEvent.click(screen.getByRole('checkbox', { name: 'I reviewed these reasons' }));
    expect(confirm).toBeEnabled();
  });
  it('panel shows one-step buttons gated for a viewer', () => {
    renderWith(<OwnershipPanel app={app()} />, { me: meWithRole('viewer') });
    expect(screen.getByRole('button', { name: 'Move to Adopted ↑' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Back to Discovered ↓' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: /Managed/ })).toBeNull();
  });
});

describe('revision apply gating', () => {
  const base = { app: { flags: app().flags }, permissions: ALL, userId: 'approver' };
  it('blocks apply when nginx -t failed', () => {
    const g = revisionGate('apply', {
      ...base,
      rev: rev({
        status: 'invalid',
        validation: { jobId: 'j', valid: false, nginxTestOutput: 'x', error: null },
      }),
    });
    expect(g.reason?.key).toBe('rev.reason.invalid');
  });
  it('blocks apply before validation and while unapproved', () => {
    expect(revisionGate('apply', { ...base, rev: rev() }).reason?.key).toBe(
      'rev.reason.notValidated',
    );
    const awaiting = rev({
      status: 'awaiting_approval',
      validation: { jobId: 'j', valid: true, nginxTestOutput: 'ok', error: null },
    });
    expect(revisionGate('apply', { ...base, rev: awaiting }).reason?.key).toBe(
      'rev.reason.needsApproval',
    );
    const approved = rev({
      status: 'approved',
      validation: { jobId: 'j', valid: true, nginxTestOutput: 'ok', error: null },
      approval: {
        required: true,
        approvedBy: 'x',
        approvedAt: '2026-11-20T00:00:00Z',
        expiresAt: new Date(Date.now() + 60e3).toISOString(),
      },
    });
    expect(revisionGate('apply', { ...base, rev: approved })).toEqual({ allowed: true });
    const expired = {
      ...approved,
      approval: { ...approved.approval, expiresAt: new Date(Date.now() - 1000).toISOString() },
    };
    expect(revisionGate('apply', { ...base, rev: expired }).reason?.key).toBe(
      'rev.reason.approvalExpired',
    );
  });
  it('blocks apply on drift', () => {
    const valid = rev({
      status: 'valid',
      validation: { jobId: 'j', valid: true, nginxTestOutput: 'ok', error: null },
      approval: { required: false, approvedBy: null, approvedAt: null, expiresAt: null },
    });
    expect(revisionGate('apply', { ...base, rev: valid })).toEqual({ allowed: true });
    expect(
      revisionGate('apply', {
        ...base,
        app: { flags: { ...app().flags, driftDetected: true } },
        rev: valid,
      }).reason?.key,
    ).toBe('rev.reason.drift');
    expect(
      revisionGate('apply', { ...base, rev: { ...valid, status: 'drift_blocked' } }).reason?.key,
    ).toBe('rev.reason.drift');
  });
  it('approver must differ from creator and hold approvals.decide', () => {
    const awaiting = rev({
      status: 'awaiting_approval',
      validation: { jobId: 'j', valid: true, nginxTestOutput: 'ok', error: null },
    });
    expect(revisionGate('approve', { ...base, rev: awaiting })).toEqual({ allowed: true });
    expect(revisionGate('approve', { ...base, userId: 'creator', rev: awaiting }).reason?.key).toBe(
      'rev.reason.selfApproval',
    );
    expect(
      revisionGate('approve', { ...base, permissions: BUILTIN_ROLES.deployer, rev: awaiting })
        .reason?.key,
    ).toBe('perm.missing');
  });
});
