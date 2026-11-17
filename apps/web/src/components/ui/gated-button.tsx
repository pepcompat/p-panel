'use client';

import { useId } from 'react';
import type { Permission } from '@ppanel/shared-contracts';
import { useAuth } from '@/lib/auth/auth-provider';
import { useT } from '@/i18n/provider';
import { evaluateGate, type GateInput } from '@/lib/permissions';
import { Button, type ButtonProps } from './button';
import { Tip } from './tooltip';

/**
 * Button enabled only when /auth/me grants `perm` AND the resource's `allowedActions` include `action`.
 * When disabled it stays focusable (wrapper) and explains why via tooltip + aria-describedby.
 */
export function GatedButton({
  perm,
  action,
  allowedActions,
  blockedReason,
  children,
  disabled,
  ...rest
}: ButtonProps & {
  perm?: Permission;
  action?: string;
  allowedActions?: readonly string[];
  blockedReason?: GateInput['blockedReason'];
}) {
  const { me } = useAuth();
  const t = useT();
  const reasonId = useId();
  const gate = evaluateGate({ permissions: me?.permissions, perm, action, allowedActions, blockedReason });
  if (gate.allowed) {
    return (
      <Button disabled={disabled} {...rest}>
        {children}
      </Button>
    );
  }
  const reason = gate.reason ? t(gate.reason.key, gate.reason.vars) : '';
  return (
    <Tip content={reason}>
      <span tabIndex={0} className="inline-flex rounded-md" aria-describedby={reasonId}>
        <Button {...rest} disabled aria-describedby={reasonId}>
          {children}
        </Button>
        <span id={reasonId} className="sr-only">
          {reason}
        </span>
      </span>
    </Tip>
  );
}
