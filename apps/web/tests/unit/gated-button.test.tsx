import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { GatedButton } from '@/components/ui/gated-button';
import { evaluateGate } from '@/lib/permissions';
import { meWithRole, renderWith } from './test-utils';

describe('evaluateGate', () => {
  it('requires the permission AND the per-resource allowed action', () => {
    expect(
      evaluateGate({
        permissions: ['servers.revoke'],
        perm: 'servers.revoke',
        action: 'revoke',
        allowedActions: ['revoke'],
      }),
    ).toEqual({ allowed: true });
    expect(
      evaluateGate({
        permissions: ['fleet.read'],
        perm: 'servers.revoke',
        action: 'revoke',
        allowedActions: ['revoke'],
      }).reason?.key,
    ).toBe('perm.missing');
    expect(
      evaluateGate({
        permissions: ['servers.revoke'],
        perm: 'servers.revoke',
        action: 'revoke',
        allowedActions: [],
      }).reason?.key,
    ).toBe('perm.actionNotAllowed');
    expect(evaluateGate({ permissions: undefined, perm: 'servers.revoke' }).allowed).toBe(false);
  });
  it('reports a missing permission before a hard block', () => {
    expect(
      evaluateGate({
        permissions: [],
        perm: 'ssh.connect',
        blockedReason: { key: 'perm.proposed' },
      }).reason?.key,
    ).toBe('perm.missing');
    expect(
      evaluateGate({
        permissions: ['ssh.connect'],
        perm: 'ssh.connect',
        blockedReason: { key: 'perm.proposed' },
      }).reason?.key,
    ).toBe('perm.proposed');
  });
});

describe('GatedButton', () => {
  it('is disabled with a reason when /auth/me lacks the permission (viewer)', () => {
    const onClick = vi.fn();
    renderWith(
      <GatedButton
        perm="servers.revoke"
        action="revoke"
        allowedActions={['revoke']}
        onClick={onClick}
      >
        Revoke agent…
      </GatedButton>,
      { me: meWithRole('viewer') },
    );
    const btn = screen.getByRole('button', { name: 'Revoke agent…' });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAccessibleDescription('Requires permission: servers.revoke');
  });

  it('is disabled when the resource does not grant the action even if the role has the permission', () => {
    renderWith(
      <GatedButton perm="servers.revoke" action="revoke" allowedActions={['edit']}>
        Revoke agent…
      </GatedButton>,
      { me: meWithRole('platform_owner') },
    );
    const btn = screen.getByRole('button', { name: 'Revoke agent…' });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAccessibleDescription(/Not allowed for this server \(revoke\)/);
  });

  it('is enabled and clickable when both permission and allowedActions grant it', async () => {
    const onClick = vi.fn();
    renderWith(
      <GatedButton
        perm="servers.revoke"
        action="revoke"
        allowedActions={['revoke']}
        onClick={onClick}
      >
        Revoke agent…
      </GatedButton>,
      { me: meWithRole('ops_admin') },
    );
    const btn = screen.getByRole('button', { name: 'Revoke agent…' });
    expect(btn).toBeEnabled();
    await userEvent.click(btn);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('translates the reason in Thai', () => {
    renderWith(<GatedButton perm="users.manage">+</GatedButton>, {
      me: meWithRole('viewer'),
      locale: 'th',
    });
    expect(screen.getByRole('button', { name: '+' })).toHaveAccessibleDescription(
      'ต้องมีสิทธิ์: users.manage',
    );
  });
});
