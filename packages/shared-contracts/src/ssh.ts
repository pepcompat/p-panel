/**
 * P10 central SSH gateway (docs/P10_SSH_CONTRACT.md). A terminal exists only through the Center:
 * browser ↔ Center (ws + ssh2) ↔ server sshd. Private keys never leave the Center database.
 * Keep this module free of imports from other contract modules (jobs.ts imports it).
 */
import { z } from 'zod';

export const SSH_ENDPOINT_PATHS = ['private', 'public'] as const;
export type SshEndpointPath = (typeof SSH_ENDPOINT_PATHS)[number];

export const SSH_CREDENTIAL_KINDS = ['generated', 'imported'] as const;
export type SshCredentialKind = (typeof SSH_CREDENTIAL_KINDS)[number];
export const SSH_CREDENTIAL_ALGORITHMS = [
  'ssh-ed25519',
  'rsa-sha2-512',
  'ecdsa-sha2-nistp256',
] as const;
export type SshCredentialAlgorithm = (typeof SSH_CREDENTIAL_ALGORITHMS)[number];
export const SSH_CREDENTIAL_STATUSES = ['active', 'rotated', 'revoked'] as const;
export type SshCredentialStatus = (typeof SSH_CREDENTIAL_STATUSES)[number];
export const SSH_DEPLOYMENT_STATUSES = [
  'pending',
  'installed',
  'removing',
  'removed',
  'failed',
] as const;
export type SshDeploymentStatus = (typeof SSH_DEPLOYMENT_STATUSES)[number];
export const SSH_HOST_KEY_STATUSES = ['pending', 'trusted', 'rejected', 'superseded'] as const;
export type SshHostKeyStatus = (typeof SSH_HOST_KEY_STATUSES)[number];
export const SSH_GRANT_STATUSES = [
  'awaiting_approval',
  'active',
  'expired',
  'revoked',
  'rejected',
] as const;
export type SshGrantStatus = (typeof SSH_GRANT_STATUSES)[number];
export const SSH_SESSION_STATUSES = ['pending', 'open', 'closed', 'failed'] as const;
export type SshSessionStatus = (typeof SSH_SESSION_STATUSES)[number];
export const SSH_END_REASONS = [
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
  /** P10 API addition: POST /ssh/sessions/:id/terminate (owner or credentials.manage) */
  'terminated',
] as const;
export type SshEndReason = (typeof SSH_END_REASONS)[number];

/** WebSocket close codes of `GET /api/v1/ssh/stream` (§5). */
export const SSH_WS_CLOSE = {
  NORMAL: 1000,
  PROTOCOL: 4400,
  AUTH: 4401,
  FORBIDDEN: 4403,
  TIMEOUT: 4408,
  HOST_KEY: 4409,
  LIMIT: 4429,
  INTERNAL: 4500,
} as const;

export const SSH_STREAM_PATH = '/api/v1/ssh/stream';
export const SSH_TICKET_TTL_SEC = 30;
export const SSH_AUTH_TIMEOUT_SEC = 5;
export const SSH_WS_MAX_PAYLOAD = 64 * 1024;
export const SSH_WS_PING_SEC = 20;
export const SSH_BACKPRESSURE_BYTES = 1024 * 1024;
/** Unused production approvals expire this long after approval (no session opened). */
export const SSH_APPROVAL_UNUSED_TTL_MIN = 30;
export const SSH_MAX_KEYS_PER_SYNC = 20;
/** Import body cap (the private key text); larger bodies → 413. */
export const SSH_IMPORT_MAX_BYTES = 16 * 1024;
export const SSH_MANAGED_BLOCK_ID = 'ppanel';

/** Linux login name accepted for ssh users (agent re-validates against /etc/passwd). */
export const SSH_USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
export const sshUserSchema = z.string().regex(SSH_USER_RE, 'invalid ssh user name');
/** `SHA256:<base64 without padding>` (OpenSSH fingerprint format). */
export const SSH_FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
export const sshFingerprintSchema = z.string().regex(SSH_FINGERPRINT_RE);
/** One-line OpenSSH public key `<type> <base64>[ comment]`, no options, no newlines. */
export const SSH_PUBLIC_KEY_RE =
  /^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [\x21-\x7e]{1,64})?$/;
export const sshPublicKeySchema = z.string().max(2048).regex(SSH_PUBLIC_KEY_RE);

// ---------------------------------------------------------------- §2 credentials

const credentialName = z.string().trim().min(1).max(64);
export const createSshCredentialSchema = z.discriminatedUnion('mode', [
  z.object({ name: credentialName, mode: z.literal('generate') }).strict(),
  z
    .object({
      name: credentialName,
      mode: z.literal('import'),
      privateKey: z.string().min(1).max(SSH_IMPORT_MAX_BYTES),
      passphrase: z.string().max(1024).optional(),
    })
    .strict(),
]);
export type CreateSshCredentialInput = z.infer<typeof createSshCredentialSchema>;

export const deploySshCredentialSchema = z
  .object({ serverId: z.string().uuid(), sshUser: sshUserSchema })
  .strict();
export type DeploySshCredentialInput = z.infer<typeof deploySshCredentialSchema>;

export interface SshKeyDeploymentView {
  id: string;
  serverId: string;
  serverName: string | null;
  sshUser: string;
  status: SshDeploymentStatus;
  jobId: string | null;
  lastError: string | null;
  updatedAt: string;
}

/** Metadata only. There is no field that could carry private key material. */
export interface SshCredential {
  id: string;
  name: string;
  kind: SshCredentialKind;
  algorithm: SshCredentialAlgorithm;
  publicKey: string;
  fingerprintSha256: string;
  status: SshCredentialStatus;
  rotatedFromId: string | null;
  createdAt: string;
  createdBy: string;
  createdByLabel: string | null;
  revokedAt: string | null;
  revokedByLabel: string | null;
  deployments: SshKeyDeploymentView[];
}

export interface SshJobsQueued {
  jobIds: string[];
}
export interface SshDeployQueued {
  jobId: string;
  deployment: SshKeyDeploymentView;
}

// ---------------------------------------------------------------- agent job ssh.keys.sync

export const sshKeysSyncParams = z
  .object({
    user: sshUserSchema,
    keys: z
      .array(
        z.object({ fingerprint: sshFingerprintSchema, publicKey: sshPublicKeySchema }).strict(),
      )
      .max(SSH_MAX_KEYS_PER_SYNC),
    managedBlockId: z.literal(SSH_MANAGED_BLOCK_ID),
  })
  .strict();
export type SshKeysSyncParams = z.infer<typeof sshKeysSyncParams>;

export const sshKeysSyncResultSchema = z
  .object({
    user: z.string().max(64),
    managedFingerprints: z.preprocess(
      (v) => (v === null ? [] : v),
      z.array(z.string().max(128)).max(SSH_MAX_KEYS_PER_SYNC),
    ),
    preservedLines: z.number().int().nonnegative(),
    fileSha256: z.string().max(128),
  })
  .strip();
export type SshKeysSyncResult = z.infer<typeof sshKeysSyncResultSchema>;
/** Agent result error codes of ssh.keys.sync. */
export const SSH_AGENT_ERROR_CODES = ['SSH_USER_INVALID', 'SSH_KEY_INVALID'] as const;

/** Agent facts `ssh` (heartbeat / enroll facts); null = no sshd host keys readable. */
export const agentSshFactsSchema = z
  .object({
    hostKeys: z.preprocess(
      (v) => (v === null ? [] : v),
      z
        .array(
          z
            .object({
              algorithm: z.string().min(1).max(64),
              fingerprintSha256: sshFingerprintSchema,
            })
            .strip(),
        )
        .max(16),
    ),
    port: z.number().int().min(1).max(65535).default(22),
  })
  .strip();
export type AgentSshFacts = z.infer<typeof agentSshFactsSchema>;

// ---------------------------------------------------------------- §3 endpoints + host keys

export const sshEndpointInputSchema = z
  .object({
    path: z.enum(SSH_ENDPOINT_PATHS),
    host: z.string().trim().ip(),
    port: z.number().int().min(1).max(65535).default(22),
    allowedUsers: z.array(sshUserSchema).min(1).max(16),
  })
  .strict();
export const putSshEndpointsSchema = z
  .array(sshEndpointInputSchema)
  .max(2)
  .refine((a) => new Set(a.map((e) => e.path)).size === a.length, 'one endpoint per path');
export type PutSshEndpointsInput = z.infer<typeof putSshEndpointsSchema>;

export interface SshEndpoint {
  path: SshEndpointPath;
  host: string;
  port: number;
  allowedUsers: string[];
  updatedAt: string;
}

export const scanSshHostKeysSchema = z.object({ path: z.enum(SSH_ENDPOINT_PATHS) }).strict();
export type ScanSshHostKeysInput = z.infer<typeof scanSshHostKeysSchema>;

export interface SshHostKey {
  id: string;
  serverId: string;
  endpointPath: SshEndpointPath;
  endpointHost: string;
  endpointPort: number;
  algorithm: string;
  fingerprintSha256: string;
  publicKey: string;
  status: SshHostKeyStatus;
  seenVia: 'scan' | 'connect';
  /** true/false = compared with the agent's host key facts (mTLS channel); null = no agent facts */
  agentMatch: boolean | null;
  firstSeenAt: string;
  lastSeenAt: string;
  trustedAt: string | null;
  trustedByLabel: string | null;
}

/** Additive `Server.ssh` summary. */
export interface ServerSshSummary {
  endpoints: Array<{ path: SshEndpointPath; host: string; port: number }>;
  trustedHostKey: boolean;
  hasCredential: boolean;
}

// ---------------------------------------------------------------- §4 grants

export const createSshGrantSchema = z
  .object({
    serverId: z.string().uuid(),
    sshUser: sshUserSchema,
    endpointPath: z.enum(SSH_ENDPOINT_PATHS),
    durationMinutes: z.number().int().min(15).max(480).default(60),
    reason: z.string().trim().min(3).max(500),
  })
  .strict();
export type CreateSshGrantInput = z.infer<typeof createSshGrantSchema>;

/** Optional: the approver may pin the exact request they reviewed (compare-and-set). */
export const approveSshGrantSchema = z
  .object({
    grantHash: z
      .string()
      .regex(/^[0-9a-f]{64}$/)
      .optional(),
  })
  .strict();
export type ApproveSshGrantInput = z.infer<typeof approveSshGrantSchema>;

export interface SshAccessGrant {
  id: string;
  userId: string;
  userLabel: string | null;
  serverId: string;
  serverName: string | null;
  environment: string | null;
  sshUser: string;
  endpointPath: SshEndpointPath;
  reason: string;
  durationMinutes: number;
  status: SshGrantStatus;
  grantHash: string;
  requestedAt: string;
  approvedBy: string | null;
  approvedByLabel: string | null;
  approvedAt: string | null;
  startsAt: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  revokedByLabel: string | null;
}

// ---------------------------------------------------------------- §5 sessions

export const createSshSessionSchema = z
  .object({
    grantId: z.string().uuid(),
    cols: z.number().int().min(1).max(500).default(80),
    rows: z.number().int().min(1).max(200).default(24),
  })
  .strict();
export type CreateSshSessionInput = z.infer<typeof createSshSessionSchema>;

export interface SshSessionCreated {
  sessionId: string;
  /** single-use, 30 s; send it as the first WebSocket message, never in the URL */
  ticket: string;
  wsUrl: string;
  expiresAt: string;
  idleTimeoutSec: number;
  maxDurationSec: number;
}

export interface SshSession {
  id: string;
  grantId: string;
  userId: string;
  userLabel: string | null;
  serverId: string;
  serverName: string | null;
  sshUser: string;
  endpointPath: SshEndpointPath;
  endpointHost: string;
  endpointPort: number;
  credentialFingerprint: string;
  hostKeyFingerprint: string | null;
  status: SshSessionStatus;
  endReason: SshEndReason | null;
  exitCode: number | null;
  clientIp: string | null;
  bytesIn: number;
  bytesOut: number;
  createdAt: string;
  openedAt: string | null;
  closedAt: string | null;
}

/** Client → Center text frames. Binary frames are stdin bytes. */
export const sshWsClientMessageSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('auth'),
      ticket: z.string().min(16).max(128),
      sessionId: z.string().uuid(),
    })
    .strict(),
  z
    .object({
      type: z.literal('resize'),
      cols: z.number().int().min(1).max(500),
      rows: z.number().int().min(1).max(200),
    })
    .strict(),
  z.object({ type: z.literal('ping') }).strict(),
  z.object({ type: z.literal('close') }).strict(),
]);
export type SshWsClientMessage = z.infer<typeof sshWsClientMessageSchema>;

/** Center → client text frames. Binary frames are stdout/stderr bytes. */
export type SshWsServerMessage =
  | {
      type: 'ready';
      sessionId: string;
      hostKeyFingerprint: string;
      endpoint: { path: SshEndpointPath; host: string; port: number };
      sshUser: string;
    }
  | { type: 'pong' }
  | { type: 'exit'; code: number | null; signal?: string }
  | { type: 'closing'; reason: SshEndReason }
  | { type: 'error'; code: string; message: string };

/** Settings surface (§6): terminal recording is not implemented. */
export interface SshSettings {
  recording: 'disabled';
  idleTimeoutSec: number;
  maxSessionSec: number;
  maxSessionsPerUser: number;
  maxSessionsPerServer: number;
  maxSessionsGlobal: number;
}
