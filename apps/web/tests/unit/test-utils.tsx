import type { ReactNode } from 'react';
import { render } from '@testing-library/react';
import * as Tooltip from '@radix-ui/react-tooltip';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BUILTIN_ROLES, type RoleKey, type Server } from '@ppanel/shared-contracts';
import { I18nProvider } from '@/i18n/provider';
import { StaticAuthProvider } from '@/lib/auth/auth-provider';
import type { MeResponse } from '@/lib/api/types';
import type { Locale } from '@/i18n/core';

export function meWithRole(role: RoleKey, mfaEnabled = false): MeResponse {
  return {
    user: {
      id: 'u1',
      email: 'x@ppanel.local',
      displayName: 'Test User',
      status: 'active',
      mfaEnabled,
      lastLoginAt: null,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    },
    permissions: [...BUILTIN_ROLES[role]],
    bindings: [{ id: 'b1', userId: 'u1', roleKey: role, scopeType: 'global' }],
    mfaEnabled,
  };
}

export function renderWith(ui: ReactNode, opts: { me?: MeResponse | null; locale?: Locale } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <I18nProvider initialLocale={opts.locale ?? 'en'}>
        <Tooltip.Provider>
          <StaticAuthProvider me={opts.me === undefined ? meWithRole('platform_owner') : opts.me}>
            {ui}
          </StaticAuthProvider>
        </Tooltip.Provider>
      </I18nProvider>
    </QueryClientProvider>,
  );
}

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

export function makeServer(over: Partial<Server> = {}): Server {
  return {
    id: 's1',
    name: 'app-prod-01',
    hostname: 'app-prod-01',
    environment: 'production',
    groupId: null,
    tags: ['web'],
    status: 'online',
    lastHeartbeatAt: ago(3),
    agentVersion: '0.4.2',
    os: { id: 'ubuntu', version: '24.04', arch: 'amd64' },
    provider: { name: 'digitalocean', region: 'sgp1', dropletId: '1', vpcUuid: '5f1c2a9e-0000' },
    addresses: [
      {
        family: 'ipv4',
        scope: 'public',
        address: '159.89.201.14',
        interface: 'eth0',
        source: 'detected',
        verifiedAt: ago(60),
      },
      {
        family: 'ipv4',
        scope: 'private',
        address: '10.104.0.11',
        interface: 'eth1',
        source: 'detected',
        verifiedAt: ago(60),
      },
    ],
    connectionPolicy: 'private_preferred',
    metrics: { cpuPct: 38, memPct: 61, diskPct: 72, sampledAt: ago(10), stale: false },
    capabilities: ['docker', 'nginx'],
    certificate: { serial: 'abc', notAfter: new Date(Date.now() + 864e5).toISOString() },
    allowedActions: ['edit', 'restart_service', 'rotate_cert', 'revoke', 'open_terminal'],
    createdAt: ago(1000),
    updatedAt: ago(100),
    version: 3,
    ...over,
  };
}
