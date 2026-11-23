import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { JobsService } from './jobs.service';

/** Periodic job-expiry sweep + bounded heartbeat retention. */
@Injectable()
export class SweeperService implements OnApplicationBootstrap, OnApplicationShutdown {
  private timer: NodeJS.Timeout | undefined;
  private running = false;
  private ticks = 0;

  constructor(
    private readonly jobs: JobsService,
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.NODE_ENV === 'test') return; // tests drive sweeps explicitly
    this.timer = setInterval(() => void this.tick(), this.config.PPANEL_SWEEP_INTERVAL_MS);
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.jobs.sweep();
      if (this.ticks++ % 12 === 0) await this.pruneHeartbeats();
    } catch (err) {
      logger.emit('error', 'sweeper tick failed', { err });
    } finally {
      this.running = false;
    }
  }

  /** Keep only the newest PPANEL_HEARTBEAT_KEEP heartbeats per server. */
  async pruneHeartbeats(): Promise<number> {
    const keep = this.config.PPANEL_HEARTBEAT_KEEP;
    return this.prisma.$executeRaw`
      DELETE FROM agent_heartbeats h
       USING (SELECT id FROM (
                SELECT id, row_number() OVER (PARTITION BY server_id ORDER BY received_at DESC, id DESC) AS rn
                  FROM agent_heartbeats) ranked
               WHERE ranked.rn > ${keep}) old
       WHERE h.id = old.id`;
  }
}
