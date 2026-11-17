import type { Permission } from '@ppanel/shared-contracts';
import type { MessageKey } from '@/i18n/en';

export interface GateInput {
  /** Permissions from GET /auth/me (undefined while loading). */
  permissions: readonly string[] | undefined;
  /** Global permission required for the action. */
  perm?: Permission;
  /** Per-resource action name that must be present in the resource's `allowedActions`. */
  action?: string;
  allowedActions?: readonly string[];
  /** Extra hard block, e.g. backend not implemented. */
  blockedReason?: { key: MessageKey; vars?: Record<string, string> };
}

export interface GateResult {
  allowed: boolean;
  reason?: { key: MessageKey; vars?: Record<string, string> };
}

/**
 * UI-side gate. Authorization is enforced by the Center; this only decides button state:
 * enabled iff the user holds `perm` (from /auth/me) AND the resource's `allowedActions` contains `action`.
 */
export function evaluateGate(i: GateInput): GateResult {
  // Order: missing permission → hard block (offline / backend PROPOSED) → per-resource grant.
  if (i.perm && !(i.permissions ?? []).includes(i.perm)) {
    return { allowed: false, reason: { key: 'perm.missing', vars: { perm: i.perm } } };
  }
  if (i.blockedReason) return { allowed: false, reason: i.blockedReason };
  if (i.action && !(i.allowedActions ?? []).includes(i.action)) {
    return { allowed: false, reason: { key: 'perm.actionNotAllowed', vars: { action: i.action } } };
  }
  return { allowed: true };
}
