/**
 * Pure UI gating for P3 (ownership steps and Nginx revision actions). The Center enforces all of
 * this server-side; these functions only decide button state and the explanation shown.
 */
import type { MessageKey } from '@/i18n/en';
import { evaluateGate, type GateResult } from './permissions';
import {
  OWNERSHIP_ORDER,
  type Application,
  type NginxRevision,
  type OwnershipMode,
} from './api/p3-types';

export const MODE_ACTION: Record<OwnershipMode, string> = {
  discovered: 'discover',
  observed: 'observe',
  adopted: 'adopt',
  managed: 'manage',
};

export interface OwnershipStep {
  to: OwnershipMode;
  direction: 'up' | 'down';
  gate: GateResult;
  /** Adopt on a flagged app requires the explicit "I reviewed these" acknowledgement. */
  needsAck: boolean;
  /** Production up-steps to adopted/managed need X-Step-Up. */
  needsStepUp: boolean;
}

/** Only the adjacent modes are ever offered — skipping a tier is impossible from the UI. */
export function ownershipSteps(
  app: Pick<Application, 'ownershipMode' | 'flags' | 'allowedActions' | 'environment'>,
  permissions: readonly string[] | undefined,
): OwnershipStep[] {
  const i = OWNERSHIP_ORDER.indexOf(app.ownershipMode);
  const out: OwnershipStep[] = [];
  const up = OWNERSHIP_ORDER[i + 1];
  const down = OWNERSHIP_ORDER[i - 1];
  if (up) {
    const blockedReason =
      up === 'managed' && app.flags.unsupported
        ? ({ key: 'own.blocked.unsupported' } as { key: MessageKey })
        : undefined;
    out.push({
      to: up,
      direction: 'up',
      gate: evaluateGate({
        permissions,
        perm: up === 'observed' ? 'servers.operate' : 'nginx.write',
        action: MODE_ACTION[up],
        allowedActions: app.allowedActions,
        blockedReason,
      }),
      needsAck: up === 'adopted' && (app.flags.manualReview || app.flags.conflict),
      needsStepUp: (up === 'adopted' || up === 'managed') && app.environment === 'production',
    });
  }
  if (down) {
    out.push({
      to: down,
      direction: 'down',
      gate: evaluateGate({
        permissions,
        perm: 'servers.operate',
        action: MODE_ACTION[down],
        allowedActions: app.allowedActions,
      }),
      needsAck: false,
      needsStepUp: false,
    });
  }
  return out;
}

/** Confirm button of the ownership dialog. */
export function ownershipConfirmReady(o: {
  step: Pick<OwnershipStep, 'needsAck' | 'needsStepUp' | 'gate'>;
  reason: string;
  acknowledged: boolean;
  otp: string;
  mfaEnabled: boolean;
}): boolean {
  if (!o.step.gate.allowed) return false;
  if (!o.reason.trim()) return false;
  if (o.step.needsAck && !o.acknowledged) return false;
  if (o.step.needsStepUp && (!o.mfaEnabled || !/^\d{6}$/.test(o.otp))) return false;
  return true;
}

export type RevisionAction = 'validate' | 'approve' | 'apply' | 'revert' | 'cancel';

export interface RevisionGateInput {
  rev: NginxRevision;
  app: Pick<Application, 'flags'>;
  permissions: readonly string[] | undefined;
  userId: string | undefined;
  now?: number;
}

const block = (key: MessageKey): GateResult => ({ allowed: false, reason: { key } });

export function approvalExpired(rev: NginxRevision, now = Date.now()): boolean {
  return !!rev.approval.expiresAt && Date.parse(rev.approval.expiresAt) < now;
}

/** Button state for each revision action, in the order the UI explains blockers. */
export function revisionGate(action: RevisionAction, i: RevisionGateInput): GateResult {
  const { rev, app, permissions, userId } = i;
  const now = i.now ?? Date.now();
  const perm = action === 'approve' ? 'approvals.decide' : 'nginx.write';
  const p = evaluateGate({ permissions, perm });
  if (!p.allowed) return p;
  switch (action) {
    case 'validate':
      if (app.flags.driftDetected) return block('rev.reason.drift');
      return rev.status === 'draft' ? { allowed: true } : block('rev.reason.state');
    case 'approve':
      if (!rev.approval.required) return block('rev.reason.noApprovalNeeded');
      if (rev.createdBy === userId) return block('rev.reason.selfApproval');
      return rev.status === 'awaiting_approval' ? { allowed: true } : block('rev.reason.state');
    case 'apply':
      if (rev.status === 'drift_blocked' || app.flags.driftDetected)
        return block('rev.reason.drift');
      if (rev.status === 'invalid' || rev.validation?.valid === false)
        return block('rev.reason.invalid');
      if (rev.status === 'draft' || rev.status === 'validating' || !rev.validation?.valid)
        return block('rev.reason.notValidated');
      if (rev.approval.required) {
        if (rev.status === 'awaiting_approval' || !rev.approval.approvedBy)
          return block('rev.reason.needsApproval');
        if (approvalExpired(rev, now)) return block('rev.reason.approvalExpired');
        return rev.status === 'approved' ? { allowed: true } : block('rev.reason.state');
      }
      return rev.status === 'valid' ? { allowed: true } : block('rev.reason.state');
    case 'revert':
      return rev.status === 'applied' ? { allowed: true } : block('rev.reason.state');
    case 'cancel':
      return ['draft', 'valid', 'awaiting_approval', 'approved'].includes(rev.status)
        ? { allowed: true }
        : block('rev.reason.state');
  }
}
