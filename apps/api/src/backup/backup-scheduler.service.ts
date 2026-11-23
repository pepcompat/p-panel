import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import type { BackupPolicy as PolicyRow } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { nextRunAfter } from './backup-common';
import { BackupRunsService } from './backup-runs.service';

const LOCK_KEY = 0x70_50_36_01; // "pP6" scheduler advisory lock
const RESTORE_TEST_PERIOD_MS = { weekly: 7 * 86_400_000, monthly: 30 * 86_400_000 } as const;

export interface SchedulerTickResult {
  started: Array<{ policyId: string; runId: string; slot: string }>;
  skipped: Array<{ policyId: string; slot: string; reason: string }>;
  restoreTests: string[];
}

/**
 * Durable backup scheduler (state = `backup_policies.next_run_at`). Each due policy claims its slot
 * with a compare-and-set on `next_run_at`, which is advanced to the first slot AFTER `now` — so a
 * Center that was down over several slots runs the policy exactly once on startup, not once per
 * missed slot. One active run per policy (partial unique index) → a due slot while a run is still
 * active is skipped (recorded in the audit log), never queued twice.
 */
@Injectable()
export class BackupSchedulerService implements OnApplicationBootstrap, OnApplicationShutdown {
  private timer: NodeJS.Timeout | undefined;
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly runs: BackupRunsService,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.NODE_ENV === 'test') return; // tests drive ticks explicitly
    // first tick right away: a missed slot is executed once on startup
    setTimeout(() => void this.tick(), 2000).unref();
    this.timer = setInterval(
      () => void this.tick(),
      this.config.PPANEL_BACKUP_SCHEDULER_INTERVAL_MS,
    );
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async tick(now = new Date()): Promise<SchedulerTickResult> {
    const out: SchedulerTickResult = { started: [], skipped: [], restoreTests: [] };
    if (this.running) return out;
    this.running = true;
    try {
      const got = await this.prisma.$queryRaw<Array<{ ok: boolean }>>`
        SELECT pg_try_advisory_lock(${LOCK_KEY}) AS ok`;
      if (!got[0]?.ok) return out;
      try {
        const due = await this.prisma.backupPolicy.findMany({
          where: { enabled: true, deletedAt: null, nextRunAt: { lte: now } },
          orderBy: { nextRunAt: 'asc' },
          take: 100,
        });
        for (const p of due) await this.fire(p, now, out);
        await this.restoreTests(now, out);
      } finally {
        await this.prisma.$queryRaw`SELECT pg_advisory_unlock(${LOCK_KEY})`;
      }
    } catch (err) {
      logger.emit('error', 'backup scheduler tick failed', { component: 'backup', err });
    } finally {
      this.running = false;
    }
    return out;
  }

  private async fire(p: PolicyRow, now: Date, out: SchedulerTickResult): Promise<void> {
    const slot = p.nextRunAt!;
    let next: Date | null;
    try {
      next = nextRunAfter(p.scheduleCron, p.timezone, now);
    } catch {
      next = null;
    }
    // claim the slot (CAS) — concurrent instances / repeated ticks never double-fire it
    const claim = await this.prisma.backupPolicy.updateMany({
      where: { id: p.id, nextRunAt: slot, enabled: true, deletedAt: null },
      data: { nextRunAt: next, lastScheduledAt: slot },
    });
    if (claim.count !== 1) return;
    const missed = next ? this.countMissed(p, slot, now) : 0;
    try {
      const { run } = await this.runs.startRun({
        policy: p,
        trigger: 'schedule',
        actorId: null,
        scheduledFor: slot,
        idempotencyKey: `schedule:${slot.toISOString()}`,
      });
      out.started.push({ policyId: p.id, runId: run.id, slot: slot.toISOString() });
      if (missed > 0)
        logger.emit('info', 'backup scheduler collapsed missed slots into one run', {
          policyId: p.id,
          missedSlots: missed,
        });
    } catch (err) {
      const reason = err instanceof AppError ? err.code : 'ERROR';
      out.skipped.push({ policyId: p.id, slot: slot.toISOString(), reason });
      await this.audit.record({
        actorType: 'system',
        action: 'backup_runs.schedule_skipped',
        targetType: 'backup_policy',
        targetId: p.id,
        result: 'failure',
        metadata: { slot: slot.toISOString(), reason },
      });
    }
  }

  /** Slots between the claimed one and `now` that were collapsed (for logging only). */
  private countMissed(p: PolicyRow, slot: Date, now: Date): number {
    let n = 0;
    let cur = slot;
    while (n < 1000) {
      const nx = nextRunAfter(p.scheduleCron, p.timezone, cur);
      if (!nx || nx > now) break;
      n++;
      cur = nx;
    }
    return n;
  }

  /** restoreTestEvery: weekly / monthly isolated restore test of the latest uploaded run. */
  private async restoreTests(now: Date, out: SchedulerTickResult): Promise<void> {
    const policies = await this.prisma.backupPolicy.findMany({
      where: { enabled: true, deletedAt: null },
      take: 500,
    });
    for (const p of policies) {
      const every = (p.verify as { restoreTestEvery?: string } | null)?.restoreTestEvery;
      if (every !== 'weekly' && every !== 'monthly') continue;
      const period = RESTORE_TEST_PERIOD_MS[every];
      if (p.lastRestoreTestAt && now.getTime() - p.lastRestoreTestAt.getTime() < period) continue;
      const run = await this.prisma.backupRun.findFirst({
        where: { policyId: p.id, status: 'uploaded', trigger: { not: 'safety' } },
        orderBy: { createdAt: 'desc' },
      });
      if (!run) continue;
      const running = await this.prisma.backupVerification.findFirst({
        where: { run: { policyId: p.id }, level: 'restore_test', status: 'running' },
        select: { id: true },
      });
      if (running) continue;
      const recentFail = await this.prisma.backupVerification.findFirst({
        where: {
          runId: run.id,
          level: 'restore_test',
          createdAt: { gt: new Date(now.getTime() - 86_400_000) },
        },
        select: { id: true },
      });
      if (recentFail) continue; // at most one attempt per day per run
      try {
        await this.runs.startVerification(run, 'restore_test', null);
        out.restoreTests.push(run.id);
      } catch (err) {
        logger.emit('warn', 'scheduled restore test not started', { policyId: p.id, err });
      }
    }
  }
}
