import { Injectable } from '@nestjs/common';
import { ERROR_CODES, type LoginResponse, type MeResponse, type StepUpResponse } from '@ppanel/shared-contracts';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { randomToken, sha256Hex } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import { type AuthUser, toRoleBinding } from '../common/principal';
import { RateLimiter } from '../common/rate-limiter';
import { toUserPublic } from '../users/user-view';
import { AuthzService } from './authz.service';
import { MfaService } from './mfa.service';
import { verifyPassword } from './password';
import { type MfaClaims, type StepUpClaims, TokenService } from './token.service';

export const REFRESH_TTL_MS = 7 * 24 * 3600 * 1000;

export interface ClientInfo {
  ip?: string;
  userAgent?: string;
}

export interface IssuedSession {
  body: LoginResponse;
  refreshToken?: string;
}

const invalidCredentials = () => AppError.unauthenticated('Invalid email or password', ERROR_CODES.INVALID_CREDENTIALS);

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    private readonly mfa: MfaService,
    private readonly audit: AuditService,
    private readonly limiter: RateLimiter,
    private readonly authz: AuthzService,
  ) {}

  async login(email: string, password: string, client: ClientInfo): Promise<IssuedSession> {
    this.limiter.hit(`login:${client.ip ?? '-'}:${email}`, 5, 60_000);
    const user = await this.prisma.user.findUnique({ where: { email } });
    const ok = await verifyPassword(user?.passwordHash, password);
    if (!user || !ok || user.status !== 'active') {
      await this.audit.record({
        actorId: user?.id ?? null,
        action: 'auth.login',
        targetType: 'user',
        targetId: user?.id ?? null,
        result: 'failure',
      });
      throw invalidCredentials();
    }
    if (await this.mfa.isEnabled(user.id)) {
      const { token } = this.tokens.sign('mfa', { sub: user.id });
      await this.audit.record({ actorId: user.id, action: 'auth.login.mfa_challenge', targetType: 'user', targetId: user.id, result: 'success' });
      return { body: { mfaRequired: true, mfaToken: token } };
    }
    return this.issueSession(user.id, ['pwd'], client, 'auth.login');
  }

  async verifyMfa(
    input: { mfaToken: string; code?: string; recoveryCode?: string },
    client: ClientInfo,
  ): Promise<IssuedSession> {
    const invalid = () => AppError.unauthenticated('Invalid or expired MFA challenge', ERROR_CODES.MFA_INVALID);
    const claims = this.tokens.verify<MfaClaims>('mfa', input.mfaToken, invalid);
    this.limiter.hit(`mfa:${claims.sub}`, 5, 60_000);
    const ok = input.code
      ? await this.mfa.checkTotp(claims.sub, input.code)
      : await this.mfa.useRecoveryCode(claims.sub, input.recoveryCode ?? '');
    if (!ok) {
      await this.audit.record({ actorId: claims.sub, action: 'auth.mfa.verify', targetType: 'user', targetId: claims.sub, result: 'failure' });
      throw invalid();
    }
    const user = await this.prisma.user.findUnique({ where: { id: claims.sub } });
    if (!user || user.status !== 'active') throw invalid();
    return this.issueSession(user.id, ['pwd', 'mfa', ...(input.recoveryCode ? ['recovery'] : [])], client, 'auth.mfa.verify');
  }

  private async issueSession(userId: string, amr: string[], client: ClientInfo, action: string): Promise<IssuedSession> {
    const refreshToken = randomToken(32);
    const sessionId = uuidv7();
    const user = await this.prisma.$transaction(async (tx) => {
      await tx.session.create({
        data: {
          id: sessionId,
          userId,
          familyId: sessionId,
          refreshTokenHash: sha256Hex(refreshToken),
          amr,
          ip: client.ip,
          userAgent: client.userAgent?.slice(0, 255),
          expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
        },
      });
      const u = await tx.user.update({ where: { id: userId }, data: { lastLoginAt: new Date() } });
      await this.audit.record({ actorId: userId, action, targetType: 'session', targetId: sessionId, result: 'success' }, tx);
      return u;
    });
    const access = this.tokens.sign('access', { sub: userId, sid: sessionId, amr });
    return {
      refreshToken,
      body: { accessToken: access.token, expiresIn: access.expiresIn, user: toUserPublic(user, await this.mfa.isEnabled(userId)) },
    };
  }

  /** Rotating refresh. Presenting an already-rotated token revokes the whole family (reuse detection). */
  async refresh(rawToken: string | undefined, client: ClientInfo): Promise<{ accessToken: string; expiresIn: number; refreshToken: string }> {
    this.limiter.hit(`refresh:${client.ip ?? '-'}`, 60, 60_000);
    const invalid = () => AppError.unauthenticated('Session expired, please sign in again', ERROR_CODES.REFRESH_INVALID);
    if (!rawToken) throw invalid();
    const current = await this.prisma.session.findUnique({ where: { refreshTokenHash: sha256Hex(rawToken) } });
    if (!current || current.revokedAt || current.expiresAt <= new Date()) throw invalid();
    if (current.rotatedAt) {
      await this.revokeFamily(current.familyId, 'refresh_reuse');
      await this.audit.record({
        actorId: current.userId,
        action: 'auth.refresh.reuse_detected',
        targetType: 'session_family',
        targetId: current.familyId,
        result: 'denied',
      });
      throw AppError.unauthenticated('Session revoked', ERROR_CODES.REFRESH_REUSED);
    }
    const user = await this.prisma.user.findUnique({ where: { id: current.userId } });
    if (!user || user.status !== 'active') throw invalid();

    const next = randomToken(32);
    const nextId = uuidv7();
    const rotated = await this.prisma.$transaction(async (tx) => {
      const r = await tx.session.updateMany({
        where: { id: current.id, rotatedAt: null, revokedAt: null },
        data: { rotatedAt: new Date(), replacedById: nextId, lastUsedAt: new Date() },
      });
      if (r.count !== 1) return false; // lost a race with a concurrent refresh → treated as reuse
      await tx.session.create({
        data: {
          id: nextId,
          userId: current.userId,
          familyId: current.familyId,
          refreshTokenHash: sha256Hex(next),
          amr: current.amr,
          ip: client.ip,
          userAgent: client.userAgent?.slice(0, 255),
          expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
        },
      });
      return true;
    });
    if (!rotated) {
      await this.revokeFamily(current.familyId, 'refresh_race');
      throw AppError.unauthenticated('Session revoked', ERROR_CODES.REFRESH_REUSED);
    }
    const access = this.tokens.sign('access', { sub: current.userId, sid: nextId, amr: current.amr });
    return { accessToken: access.token, expiresIn: access.expiresIn, refreshToken: next };
  }

  async logout(rawRefresh: string | undefined, sessionId: string | undefined, actorId: string | undefined): Promise<void> {
    let familyId: string | undefined;
    let userId = actorId;
    if (rawRefresh) {
      const s = await this.prisma.session.findUnique({ where: { refreshTokenHash: sha256Hex(rawRefresh) } });
      if (s) {
        familyId = s.familyId;
        userId ??= s.userId;
      }
    }
    if (!familyId && sessionId) familyId = (await this.prisma.session.findUnique({ where: { id: sessionId } }))?.familyId;
    if (familyId) {
      await this.revokeFamily(familyId, 'logout');
      await this.audit.record({ actorId: userId ?? null, action: 'auth.logout', targetType: 'session_family', targetId: familyId, result: 'success' });
    }
  }

  async revokeFamily(familyId: string, reason: string): Promise<void> {
    await this.prisma.session.updateMany({ where: { familyId, revokedAt: null }, data: { revokedAt: new Date(), revokedReason: reason } });
  }

  async me(principal: AuthUser): Promise<MeResponse> {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: principal.id } });
    const mfaEnabled = await this.mfa.isEnabled(user.id);
    return {
      user: toUserPublic(user, mfaEnabled),
      permissions: this.authz.permissionsOf(principal.bindings),
      bindings: principal.bindings.map(toRoleBinding),
      mfaEnabled,
    };
  }

  async stepUp(principal: AuthUser, code: string): Promise<StepUpResponse> {
    this.limiter.hit(`stepup:${principal.id}`, 5, 60_000);
    if (!(await this.mfa.isEnabled(principal.id))) {
      throw AppError.forbidden('Enable MFA before performing privileged actions', ERROR_CODES.MFA_REQUIRED);
    }
    if (!(await this.mfa.checkTotp(principal.id, code))) {
      await this.audit.record({ actorId: principal.id, action: 'auth.step_up', targetType: 'user', targetId: principal.id, result: 'failure' });
      throw AppError.unauthenticated('Invalid code', ERROR_CODES.MFA_INVALID);
    }
    const t = this.tokens.sign('step_up', { sub: principal.id, sid: principal.sessionId });
    await this.audit.record({ actorId: principal.id, action: 'auth.step_up', targetType: 'user', targetId: principal.id, result: 'success' });
    return { stepUpToken: t.token, expiresAt: t.expiresAt.toISOString() };
  }

  /** Throws 403 STEP_UP_REQUIRED unless `header` holds a valid step-up token for this session. */
  assertStepUp(principal: AuthUser, header: string | undefined): void {
    const fail = () => AppError.forbidden('Step-up authentication required for this action', ERROR_CODES.STEP_UP_REQUIRED);
    if (!header) throw fail();
    const c = this.tokens.verify<StepUpClaims>('step_up', header, fail);
    if (c.sub !== principal.id || c.sid !== principal.sessionId) throw fail();
  }
}
