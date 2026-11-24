/**
 * Pure P10 UI rules: when "Open Terminal" is possible for a server, host-key mismatch detection and
 * grant timing. The Center enforces all of this; the UI only explains it.
 */
import type { Server } from '@ppanel/shared-contracts';
import type { MessageKey } from '@/i18n/en';
import { isLive } from './servers';
import type { SshCredential, SshEndpoint, SshGrant, SshHostKey, SshPath } from './api/p10-types';

export type TerminalBlock =
  | 'perm'
  | 'offline'
  | 'noCredential'
  | 'pendingApproval'
  | 'noGrant'
  | 'noHostKey'
  | 'hostKeyMismatch';

export const BLOCK_KEY: Record<TerminalBlock, MessageKey> = {
  perm: 'p10.block.perm',
  offline: 'p10.block.offline',
  noCredential: 'p10.block.noCredential',
  pendingApproval: 'p10.block.pendingApproval',
  noGrant: 'p10.block.noGrant',
  noHostKey: 'p10.block.noHostKey',
  hostKeyMismatch: 'p10.block.hostKeyMismatch',
};

/** Installed deployments of an active credential on this server (any SSH user). */
export function installedUsers(serverId: string, creds: readonly SshCredential[]): string[] {
  const out = new Set<string>();
  for (const c of creds)
    if (c.status === 'active')
      for (const d of c.deployments)
        if (d.serverId === serverId && d.status === 'installed') out.add(d.sshUser);
  return [...out].sort();
}

export const grantLive = (g: SshGrant, now = Date.now()) =>
  g.status === 'active' && (!g.expiresAt || Date.parse(g.expiresAt) > now);

const keysFor = (keys: readonly SshHostKey[], path: SshPath | null) =>
  path ? keys.filter((k) => !k.endpointPath || k.endpointPath === path) : [...keys];

export interface HostKeyState {
  trusted: SshHostKey | null;
  /** a different key was presented on connect while another key is trusted */
  mismatch: SshHostKey | null;
  /** keys waiting for a decision */
  pending: SshHostKey[];
}

export function hostKeyState(keys: readonly SshHostKey[], path: SshPath | null): HostKeyState {
  const list = keysFor(keys, path);
  const trusted = list.find((k) => k.status === 'trusted') ?? null;
  const pending = list.filter((k) => k.status === 'pending');
  const mismatch =
    pending.find(
      (k) =>
        k.seenVia === 'connect' &&
        (!trusted ||
          (k.algorithm === trusted.algorithm && k.fingerprintSha256 !== trusted.fingerprintSha256)),
    ) ?? null;
  return { trusted, mismatch: trusted ? mismatch : null, pending };
}

export interface TerminalGateInput {
  server: Pick<Server, 'id' | 'status'>;
  permissions: readonly string[] | undefined;
  userId: string | undefined;
  grants: readonly SshGrant[] | undefined;
  credentials: readonly SshCredential[] | undefined;
  /** only on the server detail (per-server fetch) */
  hostKeys?: readonly SshHostKey[];
  now?: number;
}

export interface TerminalGate {
  block: TerminalBlock | null;
  grant: SshGrant | null;
  pendingGrant: SshGrant | null;
}

export function terminalGate(i: TerminalGateInput): TerminalGate {
  const now = i.now ?? Date.now();
  const mine = (i.grants ?? []).filter((g) => g.userId === i.userId && g.serverId === i.server.id);
  const grant = mine.find((g) => grantLive(g, now)) ?? null;
  const pendingGrant = mine.find((g) => g.status === 'awaiting_approval') ?? null;
  const out = (block: TerminalBlock | null): TerminalGate => ({ block, grant, pendingGrant });
  if (!(i.permissions ?? []).includes('ssh.connect')) return out('perm');
  if (!isLive(i.server)) return out('offline');
  if (i.credentials && installedUsers(i.server.id, i.credentials).length === 0)
    return out('noCredential');
  if (!grant) return out(pendingGrant ? 'pendingApproval' : 'noGrant');
  if (i.hostKeys) {
    const hk = hostKeyState(i.hostKeys, grant.endpointPath);
    if (hk.mismatch) return out('hostKeyMismatch');
    if (!hk.trusted) return out('noHostKey');
  }
  return out(null);
}

/** Paths a grant may use under the server's P9 connection policy (no automatic fallback). */
export function allowedPaths(
  policy: Server['connectionPolicy'],
  endpoints: readonly SshEndpoint[],
): SshPath[] {
  const have = endpoints.map((e) => e.path);
  const ok: SshPath[] =
    policy === 'private_only'
      ? ['private']
      : policy === 'public_only'
        ? ['public']
        : ['private', 'public'];
  return ok.filter((p) => have.includes(p));
}

export function minutesLeft(iso: string | null, now = Date.now()): number | null {
  if (!iso) return null;
  return Math.max(0, Math.ceil((Date.parse(iso) - now) / 60_000));
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export function formatSeconds(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h
    ? `${h}h ${String(m).padStart(2, '0')}m`
    : m
      ? `${m}m ${String(r).padStart(2, '0')}s`
      : `${r}s`;
}

/** Link into the grant request form, prefilled. */
export function grantRequestHref(serverId: string, path?: SshPath, sshUser?: string): string {
  const p = new URLSearchParams({ tab: 'grants', server: serverId });
  if (path) p.set('path', path);
  if (sshUser) p.set('user', sshUser);
  return `/ssh?${p.toString()}`;
}
export const terminalHref = (grantId: string) =>
  `/ssh?${new URLSearchParams({ tab: 'terminal', grant: grantId }).toString()}`;
export const hostKeysHref = (serverId: string) =>
  `/ssh?${new URLSearchParams({ tab: 'host-keys', server: serverId }).toString()}`;
