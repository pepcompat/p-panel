import { Inject, Injectable } from '@nestjs/common';
import {
  type CreateJobInput,
  ERROR_CODES,
  isJobType,
  type Job,
  JOB_TYPES,
  type JobStatus,
  type JobType,
  type TaskGrant,
  type TaskResultInput,
} from '@ppanel/shared-contracts';
import type { Job as JobRow, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AppError } from '../common/app-error';
import { randomToken, safeEqual, sha256Hex, stableStringify } from '../common/crypto';
import { zodDetails } from '../common/exception.filter';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { currentRequestId } from '../common/request-context';
import { Paginated } from '../common/envelope';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ServersService } from '../servers/servers.service';
import { type FinishedJob, JobHooks } from './job-hooks';
import { JobNotifier } from './job-notifier';

const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_.:-]{8,128}$/;
const TERMINAL: JobStatus[] = ['succeeded', 'failed', 'expired', 'cancelled'];
export const MAX_TASKS_PER_POLL = 5;

/** Job types that can only be created by the Center itself (revision workflow, §6.3) — never via POST /jobs. */
export const RESTRICTED_JOB_TYPES: readonly JobType[] = [
  'nginx.validate',
  'nginx.apply',
  'nginx.revert',
];

/** Mutating jobs lock a per-server resource so two never run concurrently on the same target. */
export function resourceKeyFor(
  type: JobType,
  params: Record<string, unknown>,
  serverId?: string,
): string | null {
  if (!JOB_TYPES[type].mutating) return null;
  if (type === 'service.restart') return `unit:${String(params.unit)}`;
  // all mutating nginx jobs (validate writes candidate files too) share one lock per server
  if (type.startsWith('nginx.')) return `nginx:${serverId ?? ''}`;
  return `type:${type}`;
}

export interface InternalJobInput {
  serverId: string;
  type: JobType;
  params: Record<string, unknown>;
  actorId: string;
  ttlSec: number;
  /** audit metadata (e.g. revisionId / scanId) */
  metadata?: Record<string, unknown>;
}

export function toJob(r: JobRow): Job {
  return {
    id: r.id,
    serverId: r.serverId,
    type: r.type as JobType,
    params: r.params as Record<string, unknown>,
    status: r.status as JobStatus,
    idempotencyKey: r.idempotencyKey,
    expiresAt: r.expiresAt.toISOString(),
    leaseUntil: r.leaseUntil?.toISOString() ?? null,
    attempt: r.attempt,
    desiredVersion: r.desiredVersion,
    actorId: r.actorId,
    correlationId: r.correlationId,
    result: r.result ?? (r.error ? { error: r.error } : null),
    createdAt: r.createdAt.toISOString(),
    updatedAt: r.updatedAt.toISOString(),
  };
}

@Injectable()
export class JobsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly servers: ServersService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly notifier: JobNotifier,
    private readonly hooks: JobHooks,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /**
   * Creates a typed job on behalf of a Center workflow (discovery, nginx revisions). The caller has
   * already enforced permission/step-up/ownership. Runs inside the caller's transaction; the caller
   * must call `notify(serverId)` after commit.
   */
  async createInternal(tx: Prisma.TransactionClient, input: InternalJobInput): Promise<JobRow> {
    const def = JOB_TYPES[input.type];
    const parsed = def.params.safeParse(input.params);
    if (!parsed.success) throw AppError.validation(zodDetails(parsed.error), 'Invalid job params');
    const params = parsed.data as Record<string, unknown>;
    const id = uuidv7();
    const row = await tx.job.create({
      data: {
        id,
        serverId: input.serverId,
        type: input.type,
        params: params as Prisma.InputJsonValue,
        status: 'queued',
        mutating: def.mutating,
        resourceKey: resourceKeyFor(input.type, params, input.serverId),
        idempotencyKey: `internal:${id}`,
        expiresAt: new Date(Date.now() + input.ttlSec * 1000),
        actorId: input.actorId,
        correlationId: currentRequestId() ?? id,
      },
    });
    await this.audit.record(
      {
        actorId: input.actorId,
        action: 'jobs.create',
        targetType: 'job',
        targetId: id,
        result: 'success',
        diff: { serverId: input.serverId, type: input.type, params },
        metadata: { serverId: input.serverId, type: input.type, ...input.metadata },
      },
      tx,
    );
    return row;
  }

  notify(serverId: string): void {
    this.notifier.notify(serverId);
  }

  /** Runs the completion hook for a terminal job (idempotent; used by result handling and reconcile). */
  async dispatchFinished(job: FinishedJob): Promise<void> {
    if (!this.isTerminal(job.status)) return;
    await this.hooks.dispatch(job);
  }

  // ------------------------------------------------------------------ user side

  async create(
    user: AuthUser,
    serverId: string,
    input: CreateJobInput,
    idempotencyKeyHeader: string | undefined,
    stepUpHeader: string | undefined,
  ): Promise<{ created: boolean; job: Job }> {
    const server = await this.servers.load(user, serverId, 'servers.operate', 'jobs.create');
    if (!isJobType(input.type)) {
      throw new AppError(422, ERROR_CODES.JOB_TYPE_UNKNOWN, `Unknown job type: ${input.type}`, {
        allowed: Object.keys(JOB_TYPES),
      });
    }
    const type = input.type;
    if (RESTRICTED_JOB_TYPES.includes(type)) {
      throw new AppError(
        422,
        ERROR_CODES.JOB_TYPE_RESTRICTED,
        `${type} jobs are created only through the Nginx revision workflow`,
      );
    }
    const def = JOB_TYPES[type];
    const parsed = def.params.safeParse(input.params);
    if (!parsed.success) throw AppError.validation(zodDetails(parsed.error), 'Invalid job params');
    const params = parsed.data as Record<string, unknown>;

    if (idempotencyKeyHeader !== undefined && !IDEMPOTENCY_KEY_RE.test(idempotencyKeyHeader)) {
      throw AppError.badRequest('Idempotency-Key must be 8-128 chars of [A-Za-z0-9_.:-]');
    }
    const idempotencyKey = idempotencyKeyHeader ?? uuidv7();

    // Idempotent replay first: same key → same job (even if the server was revoked since).
    const existing = await this.prisma.job.findUnique({
      where: { serverId_idempotencyKey: { serverId, idempotencyKey } },
    });
    if (existing) return { created: false, job: this.assertSameRequest(existing, type, params) };

    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (def.mutating && server.environment === 'production')
      this.auth.assertStepUp(user, stepUpHeader);
    if (type === 'service.restart' && !server.ownedUnits.includes(String(params.unit))) {
      throw new AppError(
        422,
        ERROR_CODES.RESOURCE_NOT_OWNED,
        'Unit is not in this server’s owned-resource allowlist',
        {
          unit: params.unit,
        },
      );
    }

    const id = uuidv7();
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const r = await tx.job.create({
          data: {
            id,
            serverId,
            type,
            params: params as Prisma.InputJsonValue,
            status: 'queued',
            mutating: def.mutating,
            resourceKey: resourceKeyFor(type, params, serverId),
            idempotencyKey,
            expiresAt: new Date(Date.now() + input.ttlSec * 1000),
            desiredVersion: input.desiredVersion ?? null,
            actorId: user.id,
            correlationId: currentRequestId() ?? id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            action: 'jobs.create',
            targetType: 'job',
            targetId: id,
            result: 'success',
            diff: { serverId, type, params },
            metadata: { serverId, type },
          },
          tx,
        );
        return r;
      });
      this.notifier.notify(serverId);
      return { created: true, job: toJob(row) };
    } catch (e) {
      if (!isUniqueViolation(e)) throw e;
      const raced = await this.prisma.job.findUniqueOrThrow({
        where: { serverId_idempotencyKey: { serverId, idempotencyKey } },
      });
      return { created: false, job: this.assertSameRequest(raced, type, params) };
    }
  }

  private assertSameRequest(existing: JobRow, type: string, params: Record<string, unknown>): Job {
    if (existing.type !== type || stableStringify(existing.params) !== stableStringify(params)) {
      throw AppError.conflict(
        'Idempotency-Key was already used for a different request',
        ERROR_CODES.CONFLICT,
      );
    }
    return toJob(existing);
  }

  async list(user: AuthUser, serverId: string, pq: ParsedQuery) {
    await this.servers.load(user, serverId, 'fleet.read', 'jobs.list');
    const where: Prisma.JobWhereInput = {
      AND: [
        { serverId },
        buildWhere(pq, {
          status: { prop: 'status', type: 'string' },
          type: { prop: 'type', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }),
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.job.count({ where }),
      this.prisma.job.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(rows.map(toJob), paginate(pq, total));
  }

  async get(user: AuthUser, serverId: string, jobId: string): Promise<Job> {
    await this.servers.load(user, serverId, 'fleet.read', 'jobs.read');
    const row = await this.prisma.job.findFirst({ where: { id: jobId, serverId } });
    if (!row) throw AppError.notFound('Job');
    return toJob(row);
  }

  async cancel(user: AuthUser, serverId: string, jobId: string): Promise<Job> {
    await this.servers.load(user, serverId, 'servers.operate', 'jobs.cancel');
    const r = await this.prisma.job.updateMany({
      where: { id: jobId, serverId, status: { in: ['queued', 'leased'] } },
      data: {
        status: 'cancelled',
        finishedAt: new Date(),
        leaseTokenHash: null,
        error: { code: 'CANCELLED' },
      },
    });
    const row = await this.prisma.job.findFirst({ where: { id: jobId, serverId } });
    if (!row) throw AppError.notFound('Job');
    if (r.count !== 1)
      throw AppError.conflict(
        `Job is ${row.status} and cannot be cancelled`,
        ERROR_CODES.JOB_NOT_CANCELLABLE,
      );
    await this.audit.record({
      actorId: user.id,
      action: 'jobs.cancel',
      targetType: 'job',
      targetId: jobId,
      result: 'success',
    });
    await this.dispatchFinished(row);
    return toJob(row);
  }

  // ------------------------------------------------------------------ agent side

  /**
   * Leases up to MAX_TASKS_PER_POLL queued, unexpired jobs for a server using
   * `SELECT … FOR UPDATE SKIP LOCKED`. Leases live in Postgres (durable across restarts).
   * Mutating jobs are skipped while another job holds the same resource lock.
   */
  async lease(serverId: string): Promise<TaskGrant[]> {
    const now = new Date();
    const leaseUntil = new Date(now.getTime() + this.config.PPANEL_TASK_LEASE_SEC * 1000);
    try {
      return await this.prisma.$transaction(async (tx) => {
        const candidates = await tx.$queryRaw<Array<{ id: string; resource_key: string | null }>>`
          SELECT j.id, j.resource_key
            FROM jobs j
           WHERE j.server_id = ${serverId}::uuid
             AND j.status = 'queued'
             AND j.expires_at > ${now}
             AND (j.resource_key IS NULL OR NOT EXISTS (
                   SELECT 1 FROM jobs k
                    WHERE k.server_id = j.server_id
                      AND k.resource_key = j.resource_key
                      AND k.status IN ('leased', 'running')))
           ORDER BY j.created_at, j.id
           LIMIT ${MAX_TASKS_PER_POLL}
           FOR UPDATE SKIP LOCKED`;
        const grants: TaskGrant[] = [];
        const lockedResources = new Set<string>();
        for (const c of candidates) {
          if (c.resource_key) {
            if (lockedResources.has(c.resource_key)) continue;
            lockedResources.add(c.resource_key);
          }
          const leaseToken = randomToken(32);
          const job = await tx.job.update({
            where: { id: c.id },
            data: {
              status: 'leased',
              leaseTokenHash: sha256Hex(leaseToken),
              leaseUntil,
              leasedAt: now,
              attempt: { increment: 1 },
            },
          });
          grants.push({
            jobId: job.id,
            type: job.type as JobType,
            params: job.params as Record<string, unknown>,
            idempotencyKey: job.idempotencyKey,
            issuedAt: now.toISOString(),
            expiresAt: job.expiresAt.toISOString(),
            leaseToken,
            desiredVersion: job.desiredVersion,
            serverId: job.serverId,
          });
        }
        return grants;
      });
    } catch (e) {
      // Concurrent poll grabbed the same resource lock (partial unique index) → nothing this round.
      if (isUniqueViolation(e)) return [];
      throw e;
    }
  }

  private async lockForAgent(
    tx: Prisma.TransactionClient,
    serverId: string,
    jobId: string,
  ): Promise<JobRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: string }>>`
      SELECT id FROM jobs WHERE id = ${jobId}::uuid AND server_id = ${serverId}::uuid FOR UPDATE`;
    if (rows.length === 0) return null;
    return tx.job.findUnique({ where: { id: jobId } });
  }

  private tokenMatches(job: JobRow, leaseToken: string): boolean {
    return !!job.leaseTokenHash && safeEqual(job.leaseTokenHash, sha256Hex(leaseToken));
  }

  async ack(serverId: string, jobId: string, leaseToken: string): Promise<{ status: 'running' }> {
    const now = new Date();
    const outcome = await this.prisma.$transaction(async (tx) => {
      const job = await this.lockForAgent(tx, serverId, jobId);
      if (!job || !this.tokenMatches(job, leaseToken)) return 'not_leased' as const;
      if (job.status === 'running') return 'ok' as const;
      if (job.status === 'expired') return 'expired' as const;
      if (job.status !== 'leased') return 'not_leased' as const;
      if ((job.leaseUntil && job.leaseUntil <= now) || job.expiresAt <= now) {
        await tx.job.update({ where: { id: jobId }, data: this.lapsedTransition(job, now) });
        return 'expired' as const;
      }
      await tx.job.update({
        where: { id: jobId },
        data: {
          status: 'running',
          startedAt: now,
          leaseUntil: new Date(now.getTime() + this.config.PPANEL_TASK_RUNNING_LEASE_SEC * 1000),
        },
      });
      return 'ok' as const;
    });
    if (outcome === 'expired')
      throw AppError.conflict('Task lease or TTL expired', ERROR_CODES.TASK_EXPIRED);
    if (outcome === 'not_leased')
      throw AppError.conflict('Task is not leased to this agent', ERROR_CODES.TASK_NOT_LEASED);
    return { status: 'running' };
  }

  async result(
    serverId: string,
    jobId: string,
    input: TaskResultInput,
  ): Promise<{ accepted: true }> {
    const now = new Date();
    const outcome = await this.prisma.$transaction(async (tx) => {
      const job = await this.lockForAgent(tx, serverId, jobId);
      if (!job || !this.tokenMatches(job, input.leaseToken)) return 'not_leased' as const;
      if (job.status === 'succeeded' || job.status === 'failed') return 'ok' as const; // idempotent replay
      if (job.status === 'expired' || job.status === 'cancelled') return job.status;
      if (job.status !== 'leased' && job.status !== 'running') return 'not_leased' as const;
      const error =
        input.error == null
          ? null
          : typeof input.error === 'string'
            ? { message: input.error }
            : input.error;
      // `rejected` (agent refused the grant) is persisted as `failed` carrying the REJECTED_* code.
      const status = input.status === 'succeeded' ? 'succeeded' : 'failed';
      await tx.job.update({
        where: { id: jobId },
        data: {
          status,
          result: (input.output ?? null) as Prisma.InputJsonValue,
          error: (error ?? undefined) as Prisma.InputJsonValue | undefined,
          finishedAt: now,
          leaseUntil: null,
        },
      });
      await this.audit.record(
        {
          actorId: serverId,
          actorType: 'agent',
          action: 'jobs.result',
          targetType: 'job',
          targetId: jobId,
          result: status === 'succeeded' ? 'success' : 'failure',
          metadata: {
            type: job.type,
            status,
            reported: input.status,
            acked: job.status === 'running',
            attempt: job.attempt,
            ...(error && 'code' in error ? { errorCode: error.code } : {}),
          },
        },
        tx,
      );
      return 'ok' as const;
    });
    if (outcome === 'ok') {
      const row = await this.prisma.job.findUnique({ where: { id: jobId } });
      if (row) await this.dispatchFinished(row);
      return { accepted: true };
    }
    if (outcome === 'expired') {
      logger.emit('warn', 'late result for expired job ignored', { jobId, serverId });
      throw AppError.conflict('Task lease or TTL expired', ERROR_CODES.TASK_EXPIRED);
    }
    if (outcome === 'cancelled')
      throw AppError.conflict('Task was cancelled', ERROR_CODES.TASK_NOT_LEASED);
    throw AppError.conflict('Task is not leased to this agent', ERROR_CODES.TASK_NOT_LEASED);
  }

  /** Heartbeat lease renewal for jobs the agent reports as running. */
  async renewRunning(serverId: string, jobIds: string[]): Promise<number> {
    if (jobIds.length === 0) return 0;
    const now = new Date();
    const r = await this.prisma.job.updateMany({
      where: { serverId, id: { in: jobIds }, status: 'running', leaseUntil: { gt: now } },
      data: {
        leaseUntil: new Date(now.getTime() + this.config.PPANEL_TASK_RUNNING_LEASE_SEC * 1000),
      },
    });
    return r.count;
  }

  /** State for a job whose lease lapsed: mutating → expired forever; read-only → re-queued if TTL allows. */
  private lapsedTransition(
    job: Pick<JobRow, 'mutating' | 'expiresAt'>,
    now: Date,
  ): Prisma.JobUpdateInput {
    if (job.mutating || job.expiresAt <= now) {
      return {
        status: 'expired',
        finishedAt: now,
        leaseUntil: null,
        error: { code: job.mutating ? 'LEASE_EXPIRED' : 'TTL_EXPIRED' },
      };
    }
    return { status: 'queued', leaseUntil: null, leaseTokenHash: null, leasedAt: null };
  }

  /**
   * Expiry sweeper (idempotent, safe to run concurrently on several instances).
   * Invariant: a mutating job never returns to `queued` once leased.
   */
  async sweep(now = new Date()): Promise<{
    expiredQueued: number;
    expiredMutating: number;
    requeued: number;
    expiredReadOnly: number;
  }> {
    const expiredQueued = await this.prisma.job.updateMany({
      where: { status: 'queued', expiresAt: { lte: now } },
      data: { status: 'expired', finishedAt: now, error: { code: 'TTL_EXPIRED' } },
    });
    const lapsed = {
      status: { in: ['leased', 'running'] },
      leaseUntil: { lte: now },
    } satisfies Prisma.JobWhereInput;
    const expiredMutating = await this.prisma.job.updateMany({
      where: { ...lapsed, mutating: true },
      data: {
        status: 'expired',
        finishedAt: now,
        leaseUntil: null,
        error: { code: 'LEASE_EXPIRED' },
      },
    });
    const expiredReadOnly = await this.prisma.job.updateMany({
      where: { ...lapsed, mutating: false, expiresAt: { lte: now } },
      data: {
        status: 'expired',
        finishedAt: now,
        leaseUntil: null,
        error: { code: 'TTL_EXPIRED' },
      },
    });
    const requeued = await this.prisma.job.updateMany({
      where: { ...lapsed, mutating: false, expiresAt: { gt: now } },
      data: { status: 'queued', leaseUntil: null, leaseTokenHash: null, leasedAt: null },
    });
    const out = {
      expiredQueued: expiredQueued.count,
      expiredMutating: expiredMutating.count,
      requeued: requeued.count,
      expiredReadOnly: expiredReadOnly.count,
    };
    if (out.expiredQueued + out.expiredMutating + out.requeued + out.expiredReadOnly > 0)
      logger.emit('info', 'job sweep', out);
    return out;
  }

  isTerminal(status: string): boolean {
    return TERMINAL.includes(status as JobStatus);
  }
}
