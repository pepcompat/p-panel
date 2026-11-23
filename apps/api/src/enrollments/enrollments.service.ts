import { Inject, Injectable } from '@nestjs/common';
import type {
  CreateEnrollmentInput,
  Enrollment,
  EnrollmentCreated,
  Environment,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { randomToken, sha256Hex } from '../common/crypto';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import { APP_CONFIG, type AppConfig } from '../config/config';

export const ENROLLMENT_TOKEN_PREFIX = 'ppe_';

@Injectable()
export class EnrollmentsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async create(user: AuthUser, input: CreateEnrollmentInput): Promise<EnrollmentCreated> {
    await this.authz.enforce(
      user,
      'servers.enroll',
      { environment: input.environment },
      {
        action: 'enrollments.create',
        targetType: 'enrollment',
      },
    );
    const token = `${ENROLLMENT_TOKEN_PREFIX}${randomToken(32)}`;
    const id = uuidv7();
    const expiresAt = new Date(Date.now() + input.ttlMinutes * 60_000);
    await this.prisma.$transaction(async (tx) => {
      await tx.agentEnrollment.create({
        data: {
          id,
          name: input.name,
          environment: input.environment,
          tags: input.tags ?? [],
          tokenHash: sha256Hex(token),
          ttlMinutes: input.ttlMinutes,
          expiresAt,
          createdById: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'enrollments.create',
          targetType: 'enrollment',
          targetId: id,
          result: 'success',
          diff: {
            name: input.name,
            environment: input.environment,
            tags: input.tags ?? [],
            ttlMinutes: input.ttlMinutes,
          },
        },
        tx,
      );
    });
    const center = this.config.PPANEL_PUBLIC_API_URL.replace(/\/$/, '');
    return {
      enrollmentId: id,
      token, // shown exactly once; only sha256(token) is stored
      expiresAt: expiresAt.toISOString(),
      installCommand: `sudo ppanel-agent enroll --center ${center} --token ${token}`,
    };
  }

  async list(user: AuthUser, pq: ParsedQuery) {
    const envs = this.authz.environmentsFor(user, 'servers.enroll');
    if (envs !== 'all' && envs.length === 0) throw AppError.forbidden();
    const where: Prisma.AgentEnrollmentWhereInput = {
      AND: [
        envs === 'all' ? {} : { environment: { in: envs } },
        buildWhere(pq, {
          environment: { prop: 'environment', type: 'string' },
          created_at: { prop: 'createdAt', type: 'date' },
        }),
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.agentEnrollment.count({ where }),
      this.prisma.agentEnrollment.findMany({
        where,
        orderBy: { [pq.sort]: pq.order },
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    const now = Date.now();
    const items: Enrollment[] = rows.map((r) => ({
      id: r.id,
      name: r.name,
      environment: r.environment as Environment,
      tags: r.tags,
      status: r.usedAt ? 'used' : r.expiresAt.getTime() <= now ? 'expired' : 'pending',
      expiresAt: r.expiresAt.toISOString(),
      usedAt: r.usedAt?.toISOString() ?? null,
      serverId: r.serverId,
      createdById: r.createdById,
      createdAt: r.createdAt.toISOString(),
    }));
    return new Paginated(items, paginate(pq, total));
  }
}
