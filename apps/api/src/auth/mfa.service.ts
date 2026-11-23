import { Inject, Injectable } from '@nestjs/common';
import { ERROR_CODES } from '@ppanel/shared-contracts';
import { authenticator } from 'otplib';
import { randomBytes } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret, sha256Hex } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';

authenticator.options = { window: 1, step: 30, digits: 6 };

const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const aadFor = (userId: string) => `mfa_totp:${userId}`;

export function normalizeRecoveryCode(code: string): string {
  return code.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function newRecoveryCode(): string {
  const bytes = randomBytes(10);
  const chars = [...bytes].map((b) => RECOVERY_ALPHABET[b % RECOVERY_ALPHABET.length]).join('');
  return `${chars.slice(0, 5)}-${chars.slice(5)}`;
}

@Injectable()
export class MfaService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async isEnabled(userId: string): Promise<boolean> {
    const f = await this.prisma.mfaFactor.findUnique({
      where: { userId_type: { userId, type: 'totp' } },
    });
    return !!f?.confirmedAt;
  }

  async setup(
    userId: string,
    email: string,
  ): Promise<{ otpauthUrl: string; secretMasked: string }> {
    const existing = await this.prisma.mfaFactor.findUnique({
      where: { userId_type: { userId, type: 'totp' } },
    });
    if (existing?.confirmedAt)
      throw AppError.conflict('MFA is already enabled', ERROR_CODES.MFA_ALREADY_ENABLED);
    const secret = authenticator.generateSecret(20);
    const secretEnc = encryptSecret(this.config.masterKey, secret, aadFor(userId));
    await this.prisma.mfaFactor.upsert({
      where: { userId_type: { userId, type: 'totp' } },
      create: { id: uuidv7(), userId, type: 'totp', secretEnc },
      update: { secretEnc, confirmedAt: null, lastUsedStep: null },
    });
    await this.audit.record({
      actorId: userId,
      action: 'auth.mfa.totp.setup',
      targetType: 'user',
      targetId: userId,
      result: 'success',
    });
    return {
      otpauthUrl: authenticator.keyuri(email, 'pPanel', secret),
      secretMasked: `${secret.slice(0, 4)}${'•'.repeat(8)}${secret.slice(-4)}`,
    };
  }

  async confirm(userId: string, code: string): Promise<{ recoveryCodes: string[] }> {
    const factor = await this.prisma.mfaFactor.findUnique({
      where: { userId_type: { userId, type: 'totp' } },
    });
    if (!factor || factor.confirmedAt)
      throw AppError.conflict('No pending TOTP setup', ERROR_CODES.MFA_NOT_PENDING);
    if (!(await this.checkTotp(userId, code, true))) {
      await this.audit.record({
        actorId: userId,
        action: 'auth.mfa.totp.confirm',
        targetType: 'user',
        targetId: userId,
        result: 'failure',
      });
      throw AppError.unauthenticated('Invalid code', ERROR_CODES.MFA_INVALID);
    }
    const codes = Array.from({ length: 10 }, newRecoveryCode);
    await this.prisma.$transaction(async (tx) => {
      await tx.mfaFactor.update({ where: { id: factor.id }, data: { confirmedAt: new Date() } });
      await tx.recoveryCode.deleteMany({ where: { userId } });
      await tx.recoveryCode.createMany({
        data: codes.map((c) => ({
          id: uuidv7(),
          userId,
          codeHash: sha256Hex(normalizeRecoveryCode(c)),
        })),
      });
      await this.audit.record(
        {
          actorId: userId,
          action: 'auth.mfa.totp.confirm',
          targetType: 'user',
          targetId: userId,
          result: 'success',
        },
        tx,
      );
    });
    return { recoveryCodes: codes };
  }

  /**
   * Verifies a TOTP code against the (confirmed, unless allowPending) factor.
   * Replay-safe: a time step can be used at most once (conditional update on last_used_step).
   */
  async checkTotp(userId: string, code: string, allowPending = false): Promise<boolean> {
    const factor = await this.prisma.mfaFactor.findUnique({
      where: { userId_type: { userId, type: 'totp' } },
    });
    if (!factor || (!factor.confirmedAt && !allowPending)) return false;
    let secret: string;
    try {
      secret = decryptSecret(this.config.masterKey, factor.secretEnc, aadFor(userId)).toString(
        'utf8',
      );
    } catch {
      return false;
    }
    const delta = authenticator.checkDelta(code, secret);
    if (delta === null) return false;
    const step = Math.floor(Date.now() / 30_000) + delta;
    const updated = await this.prisma.mfaFactor.updateMany({
      where: { id: factor.id, OR: [{ lastUsedStep: null }, { lastUsedStep: { lt: step } }] },
      data: { lastUsedStep: step },
    });
    return updated.count === 1;
  }

  async useRecoveryCode(userId: string, code: string): Promise<boolean> {
    const r = await this.prisma.recoveryCode.updateMany({
      where: { userId, codeHash: sha256Hex(normalizeRecoveryCode(code)), usedAt: null },
      data: { usedAt: new Date() },
    });
    return r.count === 1;
  }
}
