/** P10 shared view mappers + lookups (display labels, server scope). Metadata only. */
import type {
  SshAccessGrant,
  SshCredential,
  SshCredentialAlgorithm,
  SshCredentialKind,
  SshCredentialStatus,
  SshDeploymentStatus,
  SshEndReason,
  SshEndpointPath,
  SshGrantStatus,
  SshHostKey,
  SshHostKeyStatus,
  SshKeyDeploymentView,
  SshSession,
  SshSessionStatus,
} from '@ppanel/shared-contracts';
import type {
  SshAccessGrant as GrantRow,
  SshCredential as CredentialRow,
  SshEndpoint as EndpointRow,
  SshHostKey as HostKeyRow,
  SshKeyDeployment as DeploymentRow,
  SshSession as SessionRow,
} from '@prisma/client';
import type { PrismaService, Tx } from '../common/prisma.service';

/** Never select `privateKeyEnc` for views. */
export const credentialPublicSelect = {
  id: true,
  name: true,
  kind: true,
  algorithm: true,
  publicKey: true,
  fingerprintSha256: true,
  status: true,
  rotatedFromId: true,
  createdBy: true,
  createdAt: true,
  revokedAt: true,
  revokedBy: true,
} as const;
export type CredentialPublicRow = Omit<CredentialRow, 'privateKeyEnc'>;

export async function userLabels(
  db: PrismaService | Tx,
  ids: Array<string | null | undefined>,
): Promise<Map<string, string>> {
  const uniq = [...new Set(ids.filter((x): x is string => !!x))];
  if (uniq.length === 0) return new Map();
  const rows = await db.user.findMany({
    where: { id: { in: uniq } },
    select: { id: true, displayName: true },
  });
  return new Map(rows.map((u) => [u.id, u.displayName]));
}

export async function serverNames(
  db: PrismaService | Tx,
  ids: string[],
): Promise<Map<string, { name: string; environment: string }>> {
  const uniq = [...new Set(ids)];
  if (uniq.length === 0) return new Map();
  const rows = await db.server.findMany({
    where: { id: { in: uniq } },
    select: { id: true, name: true, environment: true },
  });
  return new Map(rows.map((s) => [s.id, { name: s.name, environment: s.environment }]));
}

export function toDeploymentView(
  d: DeploymentRow,
  names: Map<string, { name: string }>,
): SshKeyDeploymentView {
  return {
    id: d.id,
    serverId: d.serverId,
    serverName: names.get(d.serverId)?.name ?? null,
    sshUser: d.sshUser,
    status: d.status as SshDeploymentStatus,
    jobId: d.jobId,
    lastError: d.lastError,
    updatedAt: d.updatedAt.toISOString(),
  };
}

export function toCredentialView(
  c: CredentialPublicRow,
  deployments: SshKeyDeploymentView[],
  labels: Map<string, string>,
): SshCredential {
  return {
    id: c.id,
    name: c.name,
    kind: c.kind as SshCredentialKind,
    algorithm: c.algorithm as SshCredentialAlgorithm,
    publicKey: c.publicKey,
    fingerprintSha256: c.fingerprintSha256,
    status: c.status as SshCredentialStatus,
    rotatedFromId: c.rotatedFromId,
    createdAt: c.createdAt.toISOString(),
    createdBy: c.createdBy,
    createdByLabel: labels.get(c.createdBy) ?? null,
    revokedAt: c.revokedAt?.toISOString() ?? null,
    revokedByLabel: c.revokedBy ? (labels.get(c.revokedBy) ?? null) : null,
    deployments,
  };
}

export function toHostKeyView(
  k: HostKeyRow & { endpoint: Pick<EndpointRow, 'path' | 'host' | 'port'> },
  labels: Map<string, string>,
): SshHostKey {
  return {
    id: k.id,
    serverId: k.serverId,
    endpointPath: k.endpoint.path as SshEndpointPath,
    endpointHost: k.endpoint.host,
    endpointPort: k.endpoint.port,
    algorithm: k.algorithm,
    fingerprintSha256: k.fingerprintSha256,
    publicKey: k.publicKey,
    status: k.status as SshHostKeyStatus,
    seenVia: k.seenVia as 'scan' | 'connect',
    agentMatch: k.agentMatch,
    firstSeenAt: k.firstSeenAt.toISOString(),
    lastSeenAt: k.lastSeenAt.toISOString(),
    trustedAt: k.trustedAt?.toISOString() ?? null,
    trustedByLabel: k.trustedBy ? (labels.get(k.trustedBy) ?? null) : null,
  };
}

export function toGrantView(
  g: GrantRow,
  labels: Map<string, string>,
  servers: Map<string, { name: string; environment: string }>,
): SshAccessGrant {
  const s = servers.get(g.serverId);
  return {
    id: g.id,
    userId: g.userId,
    userLabel: labels.get(g.userId) ?? null,
    serverId: g.serverId,
    serverName: s?.name ?? null,
    environment: s?.environment ?? null,
    sshUser: g.sshUser,
    endpointPath: g.endpointPath as SshEndpointPath,
    reason: g.reason,
    durationMinutes: g.durationMin,
    status: g.status as SshGrantStatus,
    grantHash: g.grantHash,
    requestedAt: g.requestedAt.toISOString(),
    approvedBy: g.approvedBy,
    approvedByLabel: g.approvedBy ? (labels.get(g.approvedBy) ?? null) : null,
    approvedAt: g.approvedAt?.toISOString() ?? null,
    startsAt: g.startsAt?.toISOString() ?? null,
    expiresAt: g.expiresAt?.toISOString() ?? null,
    revokedAt: g.revokedAt?.toISOString() ?? null,
    revokedByLabel: g.revokedBy ? (labels.get(g.revokedBy) ?? null) : null,
  };
}

export function toSessionView(
  s: SessionRow,
  labels: Map<string, string>,
  servers: Map<string, { name: string }>,
): SshSession {
  return {
    id: s.id,
    grantId: s.grantId,
    userId: s.userId,
    userLabel: labels.get(s.userId) ?? null,
    serverId: s.serverId,
    serverName: servers.get(s.serverId)?.name ?? null,
    sshUser: s.sshUser,
    endpointPath: s.endpointPath as SshEndpointPath,
    endpointHost: s.endpointHost,
    endpointPort: s.endpointPort,
    credentialFingerprint: s.credentialFingerprint,
    hostKeyFingerprint: s.hostKeyFingerprint,
    status: s.status as SshSessionStatus,
    endReason: (s.endReason as SshEndReason | null) ?? null,
    exitCode: s.exitCode,
    clientIp: s.clientIp,
    bytesIn: Number(s.bytesIn),
    bytesOut: Number(s.bytesOut),
    createdAt: s.createdAt.toISOString(),
    openedAt: s.openedAt?.toISOString() ?? null,
    closedAt: s.closedAt?.toISOString() ?? null,
  };
}
