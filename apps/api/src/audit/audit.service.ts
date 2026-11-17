import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { stableHash } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger, redact } from '../common/logger';
import { PrismaService, type Tx } from '../common/prisma.service';
import { requestContext } from '../common/request-context';

export interface AuditInput {
  actorId?: string | null;
  actorType?: 'user' | 'agent' | 'system' | 'anonymous';
  action: string;
  targetType?: string;
  targetId?: string | null;
  result: 'success' | 'failure' | 'denied';
  /** before/after or input; only its hash is stored, never the raw value. */
  diff?: unknown;
  /** non-secret metadata (redacted defensively). */
  metadata?: Record<string, unknown>;
}

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async record(input: AuditInput, tx?: Tx): Promise<void> {
    const ctx = requestContext.getStore();
    const data: Prisma.AuditEventUncheckedCreateInput = {
      id: uuidv7(),
      actorId: input.actorId ?? null,
      actorType: input.actorType ?? (input.actorId ? 'user' : 'anonymous'),
      action: input.action,
      targetType: input.targetType ?? null,
      targetId: input.targetId ?? null,
      result: input.result,
      requestId: ctx?.requestId ?? null,
      diffHash: input.diff === undefined ? null : stableHash(input.diff),
      metadata: input.metadata ? (redact(input.metadata) as Prisma.InputJsonValue) : undefined,
      ip: ctx?.ip ?? null,
    };
    try {
      await (tx ?? this.prisma).auditEvent.create({ data });
    } catch (err) {
      if (tx) throw err; // inside a transaction the caller must roll back
      logger.emit('error', 'audit write failed', { action: input.action, err });
    }
  }
}
