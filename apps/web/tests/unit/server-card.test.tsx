import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import { ServerCard } from '@/components/servers/server-card';
import { connectionPath } from '@/lib/servers';
import { makeServer, renderWith } from './test-utils';

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

describe('ServerCard stale/offline rendering', () => {
  it('shows last-known metrics with a stale marker for a stale server — never zeros', () => {
    const server = makeServer({
      name: 'db-prod-01',
      status: 'stale',
      lastHeartbeatAt: ago(360),
      metrics: { cpuPct: 17, memPct: 52, diskPct: 58, sampledAt: ago(360), stale: true },
      allowedActions: ['edit', 'revoke'],
    });
    renderWith(<ServerCard server={server} now={Date.now()} />);
    const card = screen.getByTestId('server-card');
    expect(within(card).getByText('◐ 17%')).toBeInTheDocument();
    expect(within(card).getByText('◐ 52%')).toBeInTheDocument();
    expect(within(card).getByText('◐ 58%')).toBeInTheDocument();
    expect(within(card).getByTestId('stale-marker')).toHaveTextContent(
      /last known · sampled 6 min ago/,
    );
    expect(card.textContent).not.toMatch(/(^|[^0-9])0%/);
    expect(within(card).getByText('Stale')).toBeInTheDocument();
    expect(within(card).getByText(/Heartbeat stale/)).toBeInTheDocument();
  });

  it('shows "No data" (not 0%) when an offline server never reported metrics', () => {
    const server = makeServer({
      name: 'worker-uat-01',
      environment: 'uat',
      status: 'offline',
      lastHeartbeatAt: ago(1080),
      metrics: null,
      connectionPolicy: 'private_only',
      allowedActions: [],
    });
    renderWith(<ServerCard server={server} now={Date.now()} />);
    const card = screen.getByTestId('server-card');
    expect(within(card).getAllByText('No data')).toHaveLength(3);
    expect(within(card).queryAllByRole('meter')).toHaveLength(0);
    expect(card.textContent).not.toMatch(/(^|[^0-9])0%/);
    expect(within(card).getByText('Private-only · unreachable')).toBeInTheDocument();
  });

  it('keeps offline-but-known metrics as last-known values', () => {
    const server = makeServer({
      status: 'offline',
      lastHeartbeatAt: ago(900),
      metrics: { cpuPct: 0.4, memPct: 33, diskPct: 91, sampledAt: ago(900), stale: true },
    });
    renderWith(<ServerCard server={server} now={Date.now()} />);
    // 0.4 % rounds to "0%" — a real reading, so it is shown with the stale marker, not hidden
    expect(screen.getByText('◐ 0%')).toBeInTheDocument();
    expect(screen.getByText('◐ 91%')).toBeInTheDocument();
    expect(screen.getByTestId('stale-marker')).toBeInTheDocument();
  });

  it('renders live metrics as meters without a stale marker', () => {
    renderWith(<ServerCard server={makeServer()} now={Date.now()} />);
    expect(screen.getAllByRole('meter')).toHaveLength(3);
    expect(screen.queryByTestId('stale-marker')).not.toBeInTheDocument();
    expect(screen.getByText('Private path')).toBeInTheDocument();
  });

  it('disables terminal/restart on an offline card and explains why', () => {
    const server = makeServer({ status: 'offline', metrics: null, allowedActions: [] });
    renderWith(<ServerCard server={server} now={Date.now()} />);
    const terminal = screen.getByRole('button', { name: '>_ Terminal' });
    expect(terminal).toBeDisabled();
    expect(
      screen.getAllByText('Disabled while the agent is offline or stale').length,
    ).toBeGreaterThan(0);
  });
});

describe('connectionPath', () => {
  it('never reports a private path that is not verified', () => {
    const s = makeServer();
    s.addresses[1]!.verifiedAt = null;
    expect(connectionPath(s).key).toBe('path.publicUnverified');
    expect(connectionPath({ ...s, connectionPolicy: 'private_only' }).key).toBe('path.blocked');
  });
});
