/**
 * P10 shapes (docs/P10_SSH_CONTRACT.md §1–§5). @ppanel/shared-contracts has no SSH types yet, so the
 * web defines them locally from the contract (camelCase JSON of the snake_case models). Private key
 * material never appears in any of these read shapes.
 */
import type { Environment } from '@ppanel/shared-contracts';

export type SshPath = 'private' | 'public';
export type SshAlgorithm = 'ssh-ed25519' | 'rsa-sha2-512' | 'ecdsa-sha2-nistp256';
export type CredentialKind = 'generated' | 'imported';
export type CredentialStatus = 'active' | 'rotated' | 'revoked';
export type DeploymentStatus = 'pending' | 'installed' | 'removing' | 'removed' | 'failed';
export type HostKeyStatus = 'pending' | 'trusted' | 'rejected' | 'superseded';
export type GrantStatus = 'awaiting_approval' | 'active' | 'expired' | 'revoked' | 'rejected';
export type SessionStatus = 'pending' | 'open' | 'closed' | 'failed';

export const END_REASONS = [
  'client_closed',
  'server_closed',
  'idle_timeout',
  'max_duration',
  'grant_expired',
  'grant_revoked',
  'credential_revoked',
  'host_key_mismatch',
  'auth_failed',
  'connect_failed',
  'center_shutdown',
  'center_restart',
  'limit',
  'terminated',
] as const;
export type EndReason = (typeof END_REASONS)[number];

export interface CredentialDeployment {
  /** web-assumed: the contract lists { serverId, serverName, sshUser, status }; `id` is needed for DELETE. */
  id?: string;
  serverId: string;
  serverName: string;
  sshUser: string;
  status: DeploymentStatus;
  lastError?: string | null;
}

export interface SshCredential {
  id: string;
  name: string;
  kind: CredentialKind;
  algorithm: SshAlgorithm;
  publicKey: string;
  fingerprintSha256: string;
  status: CredentialStatus;
  rotatedFromId: string | null;
  createdAt: string;
  createdByLabel: string | null;
  revokedAt: string | null;
  deployments: CredentialDeployment[];
}

export type CreateCredentialInput =
  | { name: string; mode: 'generate' }
  | { name: string; mode: 'import'; privateKey: string; passphrase?: string };

export interface SshEndpoint {
  path: SshPath;
  host: string;
  port: number;
  allowedUsers: string[];
}

export interface SshHostKey {
  id: string;
  serverId: string;
  endpointId: string;
  /** web-assumed convenience (the API may add it); falls back to matching endpointId. */
  endpointPath?: SshPath;
  algorithm: string;
  fingerprintSha256: string;
  publicKey: string;
  status: HostKeyStatus;
  seenVia: 'scan' | 'connect';
  agentMatch: boolean | null;
  firstSeenAt: string;
  lastSeenAt: string;
  trustedBy: string | null;
  trustedByLabel?: string | null;
  trustedAt: string | null;
}

export interface SshGrant {
  id: string;
  userId: string;
  userLabel: string | null;
  serverId: string;
  serverName: string;
  environment: Environment;
  sshUser: string;
  endpointPath: SshPath;
  reason: string;
  durationMin: number;
  status: GrantStatus;
  grantHash: string;
  requestedAt: string;
  approvedBy: string | null;
  approvedByLabel: string | null;
  approvedAt: string | null;
  startsAt: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
}

export interface CreateGrantInput {
  serverId: string;
  sshUser: string;
  endpointPath: SshPath;
  durationMinutes: number;
  reason: string;
}

export interface SshSession {
  id: string;
  grantId: string;
  userId: string;
  userLabel?: string | null;
  serverId: string;
  serverName?: string | null;
  sshUser: string;
  endpointPath: SshPath;
  endpointHost: string;
  endpointPort: number;
  credentialFingerprint: string;
  hostKeyFingerprint: string | null;
  status: SessionStatus;
  endReason: EndReason | null;
  exitCode: number | null;
  clientIp: string | null;
  userAgent: string | null;
  bytesIn: number;
  bytesOut: number;
  createdAt: string;
  openedAt: string | null;
  closedAt: string | null;
}

/** 201 from POST /ssh/sessions. The ticket is single-use (30 s) and is only ever sent in the WS `auth` frame. */
export interface SessionTicket {
  sessionId: string;
  ticket: string;
  wsUrl: string;
  expiresAt: string;
  idleTimeoutSec: number;
  maxDurationSec: number;
}

export const GRANT_DURATIONS = [15, 30, 60, 120, 240, 480] as const;
export const GRANT_DEFAULT_DURATION = 60;
export const REASON_MIN = 3;
export const REASON_MAX = 500;
export const SSH_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
/** Contract: POST /ssh/credentials rejects bodies > 16 KiB (413). */
export const PRIVATE_KEY_MAX_BYTES = 16 * 1024;
