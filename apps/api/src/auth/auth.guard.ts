import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Permission } from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { IS_PUBLIC, PERMISSION } from '../common/decorators';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { AuthzService } from './authz.service';
import { type AccessClaims, TokenService } from './token.service';

/**
 * Global guard: validates the bearer access token on every non-public route
 * (signature, audience, expiry, live session, active user), then the coarse permission.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, targets)) return true;
    const req = ctx.switchToHttp().getRequest<Request & { user?: AuthUser }>();
    req.user = await this.authenticate(req);
    const perm = this.reflector.getAllAndOverride<Permission | undefined>(PERMISSION, targets);
    if (perm && !this.authz.hasAnywhere(req.user, perm)) {
      if (req.method !== 'GET') {
        await this.audit.record({
          actorId: req.user.id,
          action: `http.${req.method.toLowerCase()}`,
          targetType: 'route',
          targetId: req.route?.path ?? req.path,
          result: 'denied',
          metadata: { permission: perm },
        });
      }
      throw AppError.forbidden();
    }
    return true;
  }

  async authenticate(req: Request): Promise<AuthUser> {
    const header = req.header('authorization') ?? '';
    const m = /^Bearer\s+(\S+)$/i.exec(header);
    if (!m) throw AppError.unauthenticated();
    const claims = this.tokens.verify<AccessClaims>('access', m[1]!, () =>
      AppError.unauthenticated(),
    );
    const session = await this.prisma.session.findUnique({
      where: { id: claims.sid },
      select: { revokedAt: true, expiresAt: true, userId: true },
    });
    if (!session || session.revokedAt || session.userId !== claims.sub)
      throw AppError.unauthenticated();
    const user = await this.prisma.user.findUnique({
      where: { id: claims.sub },
      select: { id: true, email: true, status: true, roleBindings: true },
    });
    if (!user || user.status !== 'active') throw AppError.unauthenticated();
    return {
      id: user.id,
      email: user.email,
      sessionId: claims.sid,
      amr: claims.amr ?? [],
      bindings: user.roleBindings,
    };
  }
}
