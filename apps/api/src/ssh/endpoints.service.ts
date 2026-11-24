import { Inject, Injectable } from '@nestjs/common';
import {
  ERROR_CODES,
  type PutSshEndpointsInput,
  type SshEndpoint,
  type SshEndpointPath,
  type SshHostKey,
} from '@ppanel/shared-contracts';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { scopeOf } from '../servers/servers.service';
import { type PresentedHostKey, scanHostKey } from './ssh-client';
import { toHostKeyView, userLabels } from './ssh-common';
import { agentMatchOf, knownAddressesForScope, verifyEndpointHost } from './ssh-keys';

/** §3 endpoints (verified against P9 inventory / agent facts) and host keys (scan, trust, reject). */
@Injectable()
export class SshEndpointsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** Out-of-scope servers look like unknown ones (404, no existence oracle). */
  private async loadServer(
    user: AuthUser,
    id: string,
    perm: 'fleet.read' | 'credentials.manage',
    action: string,
  ) {
    const s = await this.prisma.server.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        environment: true,
        status: true,
        sshFacts: true,
        addresses: { select: { family: true, scope: true, address: true } },
        networkInventory: { select: { privateIpv4: true, publicIpv4: true } },
      },
    });
    if (!s || !this.authz.can(user, 'fleet.read', scopeOf(s))) throw AppError.notFound('Server');
    if (perm !== 'fleet.read')
      await this.authz.enforce(user, perm, scopeOf(s), {
        action,
        targetType: 'server',
        targetId: id,
      });
    return s;
  }

  async getEndpoints(user: AuthUser, serverId: string): Promise<SshEndpoint[]> {
    await this.loadServer(user, serverId, 'fleet.read', 'ssh.endpoint.read');
    const rows = await this.prisma.sshEndpoint.findMany({
      where: { serverId },
      orderBy: { path: 'asc' },
    });
    return rows.map((r) => ({
      path: r.path as SshEndpointPath,
      host: r.host,
      port: r.port,
      allowedUsers: r.allowedUsers,
      updatedAt: r.updatedAt.toISOString(),
    }));
  }

  async putEndpoints(
    user: AuthUser,
    serverId: string,
    input: PutSshEndpointsInput,
  ): Promise<SshEndpoint[]> {
    const s = await this.loadServer(user, serverId, 'credentials.manage', 'ssh.endpoint.update');
    if (input.some((e) => e.allowedUsers.includes('root'))) {
      await this.audit.record({
        actorId: user.id,
        action: 'ssh.endpoint.update',
        targetType: 'server',
        targetId: serverId,
        result: 'denied',
        metadata: { reason: 'root_forbidden' },
      });
      throw new AppError(422, ERROR_CODES.SSH_ROOT_FORBIDDEN, 'root is never an allowed SSH user');
    }
    const verdicts: Record<string, string> = {};
    for (const e of input) {
      const known = knownAddressesForScope(s.addresses, s.networkInventory, e.path);
      const v = verifyEndpointHost(e, known, this.config.sshLabEndpoints);
      if (v === 'unverified') {
        await this.audit.record({
          actorId: user.id,
          action: 'ssh.endpoint.update',
          targetType: 'server',
          targetId: serverId,
          result: 'denied',
          metadata: { reason: 'unverified', path: e.path, host: e.host, port: e.port },
        });
        throw new AppError(
          422,
          ERROR_CODES.SSH_ENDPOINT_UNVERIFIED,
          `${e.host} is not a known ${e.path} address of this server`,
          { path: e.path, host: e.host },
        );
      }
      verdicts[e.path] = v;
    }
    await this.prisma.$transaction(async (tx) => {
      const keep = input.map((e) => e.path);
      // removing an endpoint drops its host keys (cascade)
      await tx.sshEndpoint.deleteMany({ where: { serverId, path: { notIn: keep } } });
      for (const e of input) {
        const existing = await tx.sshEndpoint.findUnique({
          where: { serverId_path: { serverId, path: e.path } },
        });
        if (existing && (existing.host !== e.host || existing.port !== e.port)) {
          // a different address is a different host: previously trusted keys no longer apply
          await tx.sshHostKey.updateMany({
            where: { endpointId: existing.id, status: 'trusted' },
            data: { status: 'superseded' },
          });
        }
        await tx.sshEndpoint.upsert({
          where: { serverId_path: { serverId, path: e.path } },
          create: {
            id: uuidv7(),
            serverId,
            path: e.path,
            host: e.host,
            port: e.port,
            allowedUsers: [...new Set(e.allowedUsers)],
          },
          update: { host: e.host, port: e.port, allowedUsers: [...new Set(e.allowedUsers)] },
        });
      }
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.endpoint.update',
          targetType: 'server',
          targetId: serverId,
          result: 'success',
          diff: input,
          metadata: {
            endpoints: input.map((e) => ({
              path: e.path,
              host: e.host,
              port: e.port,
              allowedUsers: e.allowedUsers,
              verification: verdicts[e.path],
            })),
          },
        },
        tx,
      );
    });
    return this.getEndpoints(user, serverId);
  }

  // ---------------------------------------------------------------- host keys

  async listHostKeys(user: AuthUser, serverId: string): Promise<SshHostKey[]> {
    await this.loadServer(user, serverId, 'fleet.read', 'ssh.host_key.read');
    return this.hostKeyViews(serverId);
  }

  private async hostKeyViews(serverId: string): Promise<SshHostKey[]> {
    const rows = await this.prisma.sshHostKey.findMany({
      where: { serverId },
      include: { endpoint: { select: { path: true, host: true, port: true } } },
      orderBy: [{ lastSeenAt: 'desc' }, { id: 'asc' }],
    });
    const labels = await userLabels(
      this.prisma,
      rows.map((r) => r.trustedBy),
    );
    return rows.map((r) => toHostKeyView(r, labels));
  }

  async scan(user: AuthUser, serverId: string, path: SshEndpointPath): Promise<SshHostKey[]> {
    const s = await this.loadServer(user, serverId, 'credentials.manage', 'ssh.host_key.scan');
    const ep = await this.prisma.sshEndpoint.findUnique({
      where: { serverId_path: { serverId, path } },
    });
    if (!ep)
      throw AppError.validation({ path: [`no ${path} SSH endpoint configured for this server`] });
    let presented: PresentedHostKey;
    try {
      presented = await scanHostKey(ep.host, ep.port);
    } catch {
      await this.audit.record({
        actorId: user.id,
        action: 'ssh.host_key.scan',
        targetType: 'server',
        targetId: serverId,
        result: 'failure',
        metadata: { path, host: ep.host, port: ep.port, reason: 'connect_failed' },
      });
      throw new AppError(
        502,
        ERROR_CODES.SSH_CONNECT_FAILED,
        `SSH handshake with ${ep.host}:${ep.port} failed`,
      );
    }
    const agentMatch = agentMatchOf(presented.fingerprintSha256, s.sshFacts);
    const row = await this.recordObserved(serverId, ep.id, presented, 'scan', agentMatch);
    await this.audit.record({
      actorId: user.id,
      action: 'ssh.host_key.scan',
      targetType: 'ssh_host_key',
      targetId: row.id,
      result: 'success',
      metadata: {
        serverId,
        path,
        host: ep.host,
        port: ep.port,
        algorithm: presented.algorithm,
        fingerprint: presented.fingerprintSha256,
        status: row.status,
        agentMatch,
      },
    });
    return this.hostKeyViews(serverId);
  }

  /** Upserts an observed key: new keys are `pending`; known keys only refresh last_seen_at. */
  async recordObserved(
    serverId: string,
    endpointId: string,
    k: PresentedHostKey,
    seenVia: 'scan' | 'connect',
    agentMatch: boolean | null,
  ) {
    const now = new Date();
    return this.prisma.sshHostKey.upsert({
      where: {
        endpointId_fingerprintSha256: { endpointId, fingerprintSha256: k.fingerprintSha256 },
      },
      create: {
        id: uuidv7(),
        serverId,
        endpointId,
        algorithm: k.algorithm,
        fingerprintSha256: k.fingerprintSha256,
        publicKey: k.publicKey,
        status: 'pending',
        seenVia,
        agentMatch,
        firstSeenAt: now,
        lastSeenAt: now,
      },
      update: { lastSeenAt: now, agentMatch },
    });
  }

  private async loadKey(user: AuthUser, id: string, action: string) {
    const k = await this.prisma.sshHostKey.findUnique({
      where: { id },
      include: { server: { select: { id: true, environment: true } } },
    });
    if (!k || !this.authz.can(user, 'fleet.read', scopeOf(k.server)))
      throw AppError.notFound('SSH host key');
    await this.authz.enforce(user, 'credentials.manage', scopeOf(k.server), {
      action,
      targetType: 'ssh_host_key',
      targetId: id,
    });
    return k;
  }

  /** Step-up always. The previously trusted key of the same endpoint + algorithm → superseded. */
  async trust(user: AuthUser, id: string, stepUp: string | undefined): Promise<SshHostKey[]> {
    const k = await this.loadKey(user, id, 'ssh.host_key.trust');
    this.auth.assertStepUp(user, stepUp);
    if (k.status === 'trusted') return this.hostKeyViews(k.serverId);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const superseded = await tx.sshHostKey.updateMany({
        where: {
          endpointId: k.endpointId,
          algorithm: k.algorithm,
          status: 'trusted',
          id: { not: id },
        },
        data: { status: 'superseded' },
      });
      const r = await tx.sshHostKey.updateMany({
        where: { id, status: k.status },
        data: { status: 'trusted', trustedBy: user.id, trustedAt: now },
      });
      if (r.count !== 1)
        throw AppError.conflict('Host key changed concurrently', ERROR_CODES.SSH_STATE_INVALID);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.host_key.trust',
          targetType: 'ssh_host_key',
          targetId: id,
          result: 'success',
          metadata: {
            serverId: k.serverId,
            algorithm: k.algorithm,
            fingerprint: k.fingerprintSha256,
            agentMatch: k.agentMatch,
            superseded: superseded.count,
          },
        },
        tx,
      );
    });
    return this.hostKeyViews(k.serverId);
  }

  async reject(user: AuthUser, id: string): Promise<SshHostKey[]> {
    const k = await this.loadKey(user, id, 'ssh.host_key.reject');
    if (k.status !== 'rejected') {
      await this.prisma.$transaction(async (tx) => {
        await tx.sshHostKey.update({ where: { id }, data: { status: 'rejected' } });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'ssh.host_key.reject',
            targetType: 'ssh_host_key',
            targetId: id,
            result: 'success',
            metadata: {
              serverId: k.serverId,
              fingerprint: k.fingerprintSha256,
              previous: k.status,
            },
          },
          tx,
        );
      });
    }
    return this.hostKeyViews(k.serverId);
  }
}
