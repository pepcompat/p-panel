import { Inject, Injectable, type OnApplicationBootstrap } from '@nestjs/common';
import { type BootstrapInput, ERROR_CODES, type UserPublic } from '@ppanel/shared-contracts';
import { AuditService } from '../audit/audit.service';
import { hashPassword } from '../auth/password';
import { AppError } from '../common/app-error';
import { randomToken, safeEqual } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { toUserPublic } from '../users/user-view';

@Injectable()
export class SetupService implements OnApplicationBootstrap {
  private setupToken: string | undefined;

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {
    this.setupToken = config.PPANEL_SETUP_TOKEN || undefined;
  }

  async onApplicationBootstrap(): Promise<void> {
    if (this.setupToken) return;
    if (await this.isBootstrapped()) return;
    // Contract: when no PPANEL_SETUP_TOKEN is configured, a one-time token is printed once at first start.
    // It is written directly to stderr (not the structured log pipeline, which redacts secrets).
    this.setupToken = randomToken(24);
    process.stderr.write(
      `\n[pPanel] No users exist yet. One-time setup token (valid until this process exits):\n  ${this.setupToken}\n\n`,
    );
    logger.emit('warn', 'setup token generated and printed to stderr once; set PPANEL_SETUP_TOKEN to control it');
  }

  async isBootstrapped(): Promise<boolean> {
    return (await this.prisma.user.count()) > 0;
  }

  async bootstrap(input: BootstrapInput): Promise<{ user: UserPublic }> {
    if (!this.setupToken || !safeEqual(input.setupToken, this.setupToken)) {
      await this.audit.record({ action: 'setup.bootstrap', result: 'denied' });
      throw AppError.unauthenticated('Invalid setup token', ERROR_CODES.SETUP_TOKEN_INVALID);
    }
    const passwordHash = await hashPassword(input.password);
    const user = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('ppanel_bootstrap'))`;
      if ((await tx.user.count()) > 0) throw AppError.conflict('Setup already completed', ERROR_CODES.ALREADY_BOOTSTRAPPED);
      const id = uuidv7();
      const u = await tx.user.create({ data: { id, email: input.email, displayName: input.displayName, passwordHash } });
      await tx.roleBinding.create({ data: { id: uuidv7(), userId: id, roleKey: 'platform_owner', scopeType: 'global' } });
      await this.audit.record({ actorId: id, action: 'setup.bootstrap', targetType: 'user', targetId: id, result: 'success' }, tx);
      return u;
    });
    return { user: toUserPublic(user, false) };
  }
}
