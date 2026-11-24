import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import {
  type CreateSshGrantInput,
  ERROR_CODES,
  SSH_APPROVAL_UNUSED_TTL_MIN,
  SSH_WS_CLOSE,
  type SshAccessGrant,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, type FieldMap, paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { scopeOf } from '../servers/servers.service';
import { SshCredentialsService } from './credentials.service';
import { serverNames, toGrantView, userLabels } from './ssh-common';
import { grantHash } from './ssh-keys';
import { SshSessionRegistry } from './ssh-registry';

export const GRANT_FIELDS: FieldMap = {
  status: { prop: 'status', type: 'string' },
  server_id: { prop: 'serverId', type: 'uuid' },
  user_id: { prop: 'userId', type: 'uuid' },
  ssh_user: { prop: 'sshUser', type: 'string' },
  requested_at: { prop: 'requestedAt', type: 'date' },
  expires_at: { prop: 'expiresAt', type: 'date' },
};

const minutes = (n: number) => n * 60_000;

/** §4 grants: request → (production) approval by another user with step-up → active window. */
@Injectable()
export class SshGrantsService implements OnApplicationBootstrap, OnApplicationShutdown {
  private timer: NodeJS.Timeout | undefined;
  private sweeping = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly credentials: SshCredentialsService,
    private readonly registry: SshSessionRegistry,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.NODE_ENV === 'test') return; // tests drive sweeps explicitly
    this.timer = setInterval(() => void this.sweep(), this.config.PPANEL_SSH_SWEEP_INTERVAL_MS);
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async views(rows: Prisma.SshAccessGrantGetPayload<object>[]): Promise<SshAccessGrant[]> {
    const labels = await userLabels(
      this.prisma,
      rows.flatMap((g) => [g.userId, g.approvedBy, g.revokedBy]),
    );
    const servers = await serverNames(
      this.prisma,
      rows.map((g) => g.serverId),
    );
    return rows.map((g) => toGrantView(g, labels, servers));
  }

  async view(id: string): Promise<SshAccessGrant> {
    const g = await this.prisma.sshAccessGrant.findUniqueOrThrow({ where: { id } });
    return (await this.views([g]))[0]!;
  }

  // ---------------------------------------------------------------- request

  async create(user: AuthUser, input: CreateSshGrantInput): Promise<SshAccessGrant> {
    const s = await this.prisma.server.findUnique({
      where: { id: input.serverId },
      select: { id: true, environment: true, status: true, connectionPolicy: true },
    });
    if (!s || !this.authz.can(user, 'fleet.read', scopeOf(s))) throw AppError.notFound('Server');
    const audit = { action: 'ssh.grant.request', targetType: 'server', targetId: s.id };
    await this.authz.enforce(user, 'ssh.connect', scopeOf(s), audit);
    const deny = async (reason: string, err: AppError) => {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'denied',
        metadata: { reason, sshUser: input.sshUser, endpointPath: input.endpointPath },
      });
      return err;
    };
    if (s.status === 'revoked' || s.status === 'enrolling')
      throw await deny(
        'server_inactive',
        AppError.conflict('Server is not active', ERROR_CODES.SSH_STATE_INVALID),
      );
    if (input.sshUser === 'root')
      throw await deny(
        'root',
        new AppError(422, ERROR_CODES.SSH_ROOT_FORBIDDEN, 'root is never an allowed SSH user'),
      );
    // P9 connection policy: no fallback between paths; the user asks for the other path explicitly
    const policy = s.connectionPolicy;
    if (
      (policy === 'private_only' && input.endpointPath !== 'private') ||
      (policy === 'public_only' && input.endpointPath !== 'public')
    )
      throw await deny(
        'path_policy',
        new AppError(
          422,
          ERROR_CODES.CONNECTION_PATH_NOT_ALLOWED,
          `The server's connection policy (${policy}) does not allow the ${input.endpointPath} path`,
        ),
      );
    const ep = await this.prisma.sshEndpoint.findUnique({
      where: { serverId_path: { serverId: s.id, path: input.endpointPath } },
    });
    if (!ep)
      throw await deny(
        'no_endpoint',
        AppError.validation({ endpointPath: [`no ${input.endpointPath} SSH endpoint configured`] }),
      );
    if (!ep.allowedUsers.includes(input.sshUser))
      throw await deny(
        'user_not_allowed',
        AppError.validation({ sshUser: ['not an allowed user of this endpoint'] }),
      );
    if (!(await this.credentials.usableCredential(this.prisma, s.id, input.sshUser)))
      throw await deny(
        'no_credential',
        new AppError(
          422,
          ERROR_CODES.SSH_NO_CREDENTIAL,
          `No installed key of an active credential for ${input.sshUser} on this server`,
        ),
      );
    const production = s.environment === 'production';
    const now = new Date();
    const id = uuidv7();
    const hash = grantHash({
      userId: user.id,
      serverId: s.id,
      sshUser: input.sshUser,
      endpointPath: input.endpointPath,
      durationMin: input.durationMinutes,
    });
    await this.prisma.$transaction(async (tx) => {
      await tx.sshAccessGrant.create({
        data: {
          id,
          userId: user.id,
          serverId: s.id,
          sshUser: input.sshUser,
          endpointPath: input.endpointPath,
          reason: input.reason,
          durationMin: input.durationMinutes,
          status: production ? 'awaiting_approval' : 'active',
          grantHash: hash,
          requestedAt: now,
          ...(production
            ? {}
            : {
                startsAt: now,
                expiresAt: new Date(now.getTime() + minutes(input.durationMinutes)),
              }),
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.grant.request',
          targetType: 'ssh_grant',
          targetId: id,
          result: 'success',
          metadata: {
            serverId: s.id,
            environment: s.environment,
            sshUser: input.sshUser,
            endpointPath: input.endpointPath,
            durationMinutes: input.durationMinutes,
            reason: input.reason,
            status: production ? 'awaiting_approval' : 'active',
          },
        },
        tx,
      );
    });
    return this.view(id);
  }

  // ---------------------------------------------------------------- list

  async list(user: AuthUser, pq: ParsedQuery): Promise<Paginated<SshAccessGrant>> {
    const visibility: Prisma.SshAccessGrantWhereInput[] = [{ userId: user.id }];
    let global = false;
    for (const perm of ['credentials.manage', 'approvals.decide'] as const) {
      const sw = this.authz.serverWhere(user, perm);
      // An empty relation filter (global scope) matches nothing inside OR in Prisma: drop the clause instead.
      if (sw && Object.keys(sw).length === 0) global = true;
      else if (sw) visibility.push({ server: sw });
    }
    const filters = buildWhere(pq, GRANT_FIELDS) as Prisma.SshAccessGrantWhereInput;
    const where: Prisma.SshAccessGrantWhereInput = global
      ? filters
      : { AND: [{ OR: visibility }, filters] };
    const [total, rows] = await Promise.all([
      this.prisma.sshAccessGrant.count({ where }),
      this.prisma.sshAccessGrant.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(await this.views(rows), paginate(pq, total));
  }

  /** Grants of out-of-scope servers look like unknown ones. */
  private async loadVisible(user: AuthUser, id: string) {
    const g = await this.prisma.sshAccessGrant.findUnique({
      where: { id },
      include: { server: { select: { id: true, environment: true } } },
    });
    if (!g) throw AppError.notFound('SSH grant');
    const scope = scopeOf(g.server);
    if (g.userId !== user.id && !this.authz.can(user, 'fleet.read', scope))
      throw AppError.notFound('SSH grant');
    return { g, scope };
  }

  // ---------------------------------------------------------------- approve / reject

  async approve(
    user: AuthUser,
    id: string,
    pinnedHash: string | undefined,
    stepUp: string | undefined,
  ): Promise<SshAccessGrant> {
    const { g, scope } = await this.loadVisible(user, id);
    await this.authz.enforce(user, 'approvals.decide', scope, {
      action: 'ssh.grant.approve',
      targetType: 'ssh_grant',
      targetId: id,
    });
    if (g.userId === user.id) {
      await this.audit.record({
        actorId: user.id,
        action: 'ssh.grant.approve',
        targetType: 'ssh_grant',
        targetId: id,
        result: 'denied',
        metadata: { reason: 'self_approval' },
      });
      throw AppError.forbidden(
        'The requester of a grant cannot approve it',
        ERROR_CODES.SELF_APPROVAL_FORBIDDEN,
      );
    }
    this.auth.assertStepUp(user, stepUp);
    if (g.status !== 'awaiting_approval')
      throw AppError.conflict(`Grant is ${g.status}`, ERROR_CODES.SSH_STATE_INVALID);
    const expected = grantHash(g);
    if (expected !== g.grantHash || (pinnedHash !== undefined && pinnedHash !== g.grantHash))
      throw AppError.conflict(
        'grantHash does not match the request',
        ERROR_CODES.PLAN_HASH_MISMATCH,
        { grantHash: g.grantHash },
      );
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      // compare-and-set: single use — a concurrent approve/reject/revoke wins exactly once
      const r = await tx.sshAccessGrant.updateMany({
        where: { id, status: 'awaiting_approval', grantHash: expected, approvedBy: null },
        data: {
          status: 'active',
          approvedBy: user.id,
          approvedAt: now,
          startsAt: now,
          expiresAt: new Date(now.getTime() + minutes(g.durationMin)),
        },
      });
      if (r.count !== 1)
        throw AppError.conflict('Grant changed concurrently', ERROR_CODES.APPROVAL_ALREADY_EXISTS);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.grant.approve',
          targetType: 'ssh_grant',
          targetId: id,
          result: 'success',
          diff: { grantHash: expected },
          metadata: {
            requesterId: g.userId,
            serverId: g.serverId,
            sshUser: g.sshUser,
            grantHash: expected,
          },
        },
        tx,
      );
    });
    return this.view(id);
  }

  async reject(user: AuthUser, id: string): Promise<SshAccessGrant> {
    const { g, scope } = await this.loadVisible(user, id);
    await this.authz.enforce(user, 'approvals.decide', scope, {
      action: 'ssh.grant.reject',
      targetType: 'ssh_grant',
      targetId: id,
    });
    if (g.status !== 'awaiting_approval')
      throw AppError.conflict(`Grant is ${g.status}`, ERROR_CODES.SSH_STATE_INVALID);
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.sshAccessGrant.updateMany({
        where: { id, status: 'awaiting_approval' },
        data: { status: 'rejected', revokedAt: new Date(), revokedBy: user.id },
      });
      if (r.count !== 1)
        throw AppError.conflict('Grant changed concurrently', ERROR_CODES.SSH_STATE_INVALID);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.grant.reject',
          targetType: 'ssh_grant',
          targetId: id,
          result: 'success',
          metadata: { requesterId: g.userId, serverId: g.serverId },
        },
        tx,
      );
    });
    return this.view(id);
  }

  // ---------------------------------------------------------------- revoke / expire

  async revoke(user: AuthUser, id: string): Promise<SshAccessGrant> {
    const { g, scope } = await this.loadVisible(user, id);
    if (g.userId !== user.id)
      await this.authz.enforce(user, 'credentials.manage', scope, {
        action: 'ssh.grant.revoke',
        targetType: 'ssh_grant',
        targetId: id,
      });
    if (g.status !== 'active' && g.status !== 'awaiting_approval')
      throw AppError.conflict(`Grant is ${g.status}`, ERROR_CODES.SSH_STATE_INVALID);
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.sshAccessGrant.updateMany({
        where: { id, status: { in: ['active', 'awaiting_approval'] } },
        data: { status: 'revoked', revokedAt: new Date(), revokedBy: user.id },
      });
      if (r.count !== 1)
        throw AppError.conflict('Grant changed concurrently', ERROR_CODES.SSH_STATE_INVALID);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.grant.revoke',
          targetType: 'ssh_grant',
          targetId: id,
          result: 'success',
          metadata: { requesterId: g.userId, serverId: g.serverId },
        },
        tx,
      );
    });
    await this.registry.closeWhere(
      (s) => s.grantId === id,
      'grant_revoked',
      SSH_WS_CLOSE.FORBIDDEN,
      'grant revoked',
    );
    await this.prisma.sshSession.updateMany({
      where: { grantId: id, status: 'pending' },
      data: {
        status: 'closed',
        endReason: 'grant_revoked',
        closedAt: new Date(),
        ticketHash: null,
        ticketExpiresAt: null,
      },
    });
    return this.view(id);
  }

  /**
   * Every 30 s: active grants past `expiresAt` → expired (sessions closed `grant_expired`); approved
   * production grants unused 30 min after approval → expired.
   */
  async sweep(now = new Date()): Promise<number> {
    if (this.sweeping) return 0;
    this.sweeping = true;
    try {
      const unusedCut = new Date(now.getTime() - minutes(SSH_APPROVAL_UNUSED_TTL_MIN));
      const due = await this.prisma.sshAccessGrant.findMany({
        where: {
          status: 'active',
          OR: [
            { expiresAt: { lte: now } },
            { approvedBy: { not: null }, approvedAt: { lte: unusedCut }, sessions: { none: {} } },
          ],
        },
        select: { id: true, userId: true, serverId: true, expiresAt: true },
      });
      for (const g of due) {
        const r = await this.prisma.sshAccessGrant.updateMany({
          where: { id: g.id, status: 'active' },
          data: { status: 'expired' },
        });
        if (r.count !== 1) continue;
        await this.audit.record({
          actorType: 'system',
          action: 'ssh.grant.expire',
          targetType: 'ssh_grant',
          targetId: g.id,
          result: 'success',
          metadata: {
            userId: g.userId,
            serverId: g.serverId,
            reason: g.expiresAt && g.expiresAt <= now ? 'window_elapsed' : 'approval_unused',
          },
        });
        await this.registry.closeWhere(
          (s) => s.grantId === g.id,
          'grant_expired',
          SSH_WS_CLOSE.TIMEOUT,
          'grant expired',
        );
        await this.prisma.sshSession.updateMany({
          where: { grantId: g.id, status: 'pending' },
          data: {
            status: 'closed',
            endReason: 'grant_expired',
            closedAt: now,
            ticketHash: null,
            ticketExpiresAt: null,
          },
        });
      }
      // never-connected tickets: their pending rows must not count toward the limits forever
      await this.prisma.sshSession.updateMany({
        where: { status: 'pending', ticketExpiresAt: { lt: now } },
        data: {
          status: 'failed',
          endReason: 'client_closed',
          closedAt: now,
          ticketHash: null,
          ticketExpiresAt: null,
        },
      });
      return due.length;
    } catch (err) {
      logger.emit('error', 'ssh grant sweep failed', { err });
      return 0;
    } finally {
      this.sweeping = false;
    }
  }
}
