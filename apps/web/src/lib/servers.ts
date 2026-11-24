import {
  ENVIRONMENTS,
  type Environment,
  type Server,
  type ServerAddress,
} from '@ppanel/shared-contracts';
import type { Tone } from '@/components/ui/badge';
import type { MessageKey } from '@/i18n/en';

export const SERVER_TABS = [
  'overview',
  'applications',
  'network',
  'terminal',
  'firewall',
  'software',
  'runtimes',
  'databases',
  'monitoring',
  'logs',
  'backups',
  'events',
  'settings',
] as const;
export type ServerTab = (typeof SERVER_TABS)[number];
export const REAL_TABS: readonly ServerTab[] = [
  'overview',
  'applications',
  'network',
  'terminal',
  'monitoring',
  'logs',
  'backups',
  'settings',
];
export const isServerTab = (v: string): v is ServerTab =>
  (SERVER_TABS as readonly string[]).includes(v);

/** Display order: Production first, like the design's environment groups. */
export const ENV_DISPLAY_ORDER: Environment[] = ['production', 'uat', 'development'];
export { ENVIRONMENTS };

export const isLive = (s: Pick<Server, 'status'>) =>
  s.status === 'online' || s.status === 'degraded';

export function address(
  s: Pick<Server, 'addresses'>,
  scope: 'public' | 'private',
  family: 'ipv4' | 'ipv6' = 'ipv4',
): ServerAddress | undefined {
  return s.addresses.find((a) => a.scope === scope && a.family === family);
}

/**
 * Connection path label, mirroring the design's netOf(): never claims a private path that is not
 * verified, and never shows a silent public downgrade for Private-only.
 */
export function connectionPath(s: Pick<Server, 'status' | 'connectionPolicy' | 'addresses'>): {
  tone: Tone;
  key: MessageKey;
} {
  const priv = address(s, 'private');
  const privVerified = !!priv?.verifiedAt;
  const pol = s.connectionPolicy;
  if (s.status === 'revoked') return { tone: 'crit', key: 'path.revoked' };
  if (s.status === 'enrolling') return { tone: 'info', key: 'path.pending' };
  if (s.status === 'offline')
    return pol === 'private_only'
      ? { tone: 'off', key: 'path.privateOnlyUnreachable' }
      : { tone: 'off', key: 'path.unreachable' };
  if (s.status === 'stale') return { tone: 'stale', key: 'path.privateStale' };
  if (pol === 'public_preferred' || pol === 'public_only')
    return { tone: 'warn', key: 'path.public' };
  if (!privVerified) {
    return pol === 'private_only'
      ? { tone: 'crit', key: 'path.blocked' }
      : { tone: 'warn', key: 'path.publicUnverified' };
  }
  return { tone: 'ok', key: 'path.private' };
}

export interface FleetCounts {
  total: number;
  online: number;
  degraded: number;
  stale: number;
  offline: number;
  other: number;
}

export function fleetCounts(servers: Pick<Server, 'status'>[]): FleetCounts {
  const c: FleetCounts = {
    total: servers.length,
    online: 0,
    degraded: 0,
    stale: 0,
    offline: 0,
    other: 0,
  };
  for (const s of servers) {
    if (s.status === 'online') c.online++;
    else if (s.status === 'degraded') c.degraded++;
    else if (s.status === 'stale') c.stale++;
    else if (s.status === 'offline') c.offline++;
    else c.other++;
  }
  return c;
}

export function groupByEnv<T extends Pick<Server, 'environment'>>(
  servers: T[],
): Array<{ env: Environment; servers: T[] }> {
  return ENV_DISPLAY_ORDER.map((env) => ({
    env,
    servers: servers.filter((s) => s.environment === env),
  }));
}

export function matchesQuery(s: Server, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return (
    s.name.toLowerCase().includes(needle) ||
    s.hostname.toLowerCase().includes(needle) ||
    s.tags.some((t) => t.toLowerCase().includes(needle)) ||
    s.addresses.some((a) => a.address.includes(needle)) ||
    (s.provider?.region ?? '').toLowerCase().includes(needle)
  );
}

export function osLabel(s: Pick<Server, 'os'>): string | null {
  if (!s.os) return null;
  const name = s.os.id.charAt(0).toUpperCase() + s.os.id.slice(1);
  return `${name} ${s.os.version}`;
}

export function providerLabel(s: Pick<Server, 'provider'>): string | null {
  const n = s.provider?.name;
  if (!n) return null;
  return n === 'digitalocean' ? 'DigitalOcean' : n;
}

export const envLabelKey = (env: Environment): MessageKey => `env.${env}` as MessageKey;
export const envBadgeKey = (env: Environment): MessageKey => `env.badge.${env}` as MessageKey;
export const statusKey = (st: Server['status']): MessageKey => `status.${st}` as MessageKey;
