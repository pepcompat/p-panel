import { Controller, Get, Inject } from '@nestjs/common';
import {
  AGENT_PROTOCOL_VERSION,
  type CenterVersionInfo,
  ERROR_CODES,
} from '@ppanel/shared-contracts';
import { AppError } from '../common/app-error';
import { Public } from '../common/decorators';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';

const SCHEMA_CACHE_MS = 15_000;

/**
 * P8 (RELEASE_CONTRACT §1/§4): public, unauthenticated, no secrets.
 * `GET /version` — build identity + compatibility policy (installer / upgrade pre-flight).
 * `GET /health`  — liveness + DB reachability (compose healthcheck, install.sh, upgrade.sh).
 */
@Public()
@Controller()
export class VersionController {
  private schemaCache: { at: number; value: string | null } | null = null;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  @Get('version')
  async version(): Promise<CenterVersionInfo> {
    return {
      version: this.config.build.version,
      commit: this.config.build.commit,
      buildDate: this.config.build.buildDate,
      agentProtocol: AGENT_PROTOCOL_VERSION,
      minAgentVersion: this.config.minAgentVersion,
      schemaVersion: await this.schemaVersion(),
    };
  }

  @Get('health')
  async health(): Promise<{ status: 'ok'; db: 'ok'; version: string }> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
    } catch (err) {
      logger.emit('warn', 'health: database unreachable', { err });
      throw new AppError(
        503,
        ERROR_CODES.SERVICE_UNAVAILABLE,
        'Database unreachable',
        { retryAfterSec: 5 },
        { 'Retry-After': '5' },
      );
    }
    return { status: 'ok', db: 'ok', version: this.config.build.version };
  }

  /** Latest applied Prisma migration (cached briefly: the endpoint is public). */
  private async schemaVersion(): Promise<string | null> {
    const now = Date.now();
    if (this.schemaCache && now - this.schemaCache.at < SCHEMA_CACHE_MS)
      return this.schemaCache.value;
    let value: string | null = null;
    try {
      const rows = await this.prisma.$queryRaw<Array<{ migration_name: string }>>`
        SELECT migration_name FROM _prisma_migrations
        WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL
        ORDER BY migration_name DESC LIMIT 1`;
      value = rows[0]?.migration_name ?? null;
    } catch {
      return null; // DB unreachable: report null, do not cache
    }
    this.schemaCache = { at: now, value };
    return value;
  }
}
