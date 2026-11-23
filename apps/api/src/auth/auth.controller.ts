import { Body, Controller, Get, HttpCode, Inject, Post, Req, Res } from '@nestjs/common';
import {
  ERROR_CODES,
  REFRESH_COOKIE_NAME,
  REFRESH_COOKIE_PATH,
  loginSchema,
  mfaVerifySchema,
  totpCodeSchema,
} from '@ppanel/shared-contracts';
import type { CookieOptions, Request, Response } from 'express';
import { AppError } from '../common/app-error';
import { CurrentUser, Public } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { ZodPipe } from '../common/zod.pipe';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { type ClientInfo, type IssuedSession, AuthService, REFRESH_TTL_MS } from './auth.service';
import { MfaService } from './mfa.service';
import { type AccessClaims, TokenService } from './token.service';

function client(req: Request): ClientInfo {
  return { ip: req.ip, userAgent: req.header('user-agent') };
}

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly mfa: MfaService,
    private readonly tokens: TokenService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  private cookieOpts(): CookieOptions {
    return {
      httpOnly: true,
      sameSite: 'strict',
      secure: this.config.COOKIE_SECURE || this.config.isProduction,
      path: REFRESH_COOKIE_PATH,
    };
  }

  private respond(res: Response, issued: IssuedSession) {
    if (issued.refreshToken)
      res.cookie(REFRESH_COOKIE_NAME, issued.refreshToken, {
        ...this.cookieOpts(),
        maxAge: REFRESH_TTL_MS,
      });
    return issued.body;
  }

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(
    @Body(new ZodPipe(loginSchema)) body: { email: string; password: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.respond(res, await this.auth.login(body.email, body.password, client(req)));
  }

  @Public()
  @Post('mfa/verify')
  @HttpCode(200)
  async verifyMfa(
    @Body(new ZodPipe(mfaVerifySchema))
    body: { mfaToken: string; code?: string; recoveryCode?: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.respond(res, await this.auth.verifyMfa(body, client(req)));
  }

  @Public()
  @Post('refresh')
  @HttpCode(200)
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    if (req.header('x-csrf') !== '1')
      throw AppError.forbidden('Missing X-CSRF header', ERROR_CODES.CSRF_REQUIRED);
    const raw = (req.cookies as Record<string, string> | undefined)?.[REFRESH_COOKIE_NAME];
    try {
      const r = await this.auth.refresh(raw, client(req));
      res.cookie(REFRESH_COOKIE_NAME, r.refreshToken, {
        ...this.cookieOpts(),
        maxAge: REFRESH_TTL_MS,
      });
      return { accessToken: r.accessToken, expiresIn: r.expiresIn };
    } catch (e) {
      res.clearCookie(REFRESH_COOKIE_NAME, this.cookieOpts());
      throw e;
    }
  }

  @Public()
  @Post('logout')
  @HttpCode(204)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<void> {
    const raw = (req.cookies as Record<string, string> | undefined)?.[REFRESH_COOKIE_NAME];
    let sid: string | undefined;
    let sub: string | undefined;
    const m = /^Bearer\s+(\S+)$/i.exec(req.header('authorization') ?? '');
    if (m) {
      try {
        const c = this.tokens.verify<AccessClaims>('access', m[1]!, () =>
          AppError.unauthenticated(),
        );
        sid = c.sid;
        sub = c.sub;
      } catch {
        /* logout is best-effort for expired access tokens */
      }
    }
    await this.auth.logout(raw, sid, sub);
    res.clearCookie(REFRESH_COOKIE_NAME, this.cookieOpts());
  }

  @Get('me')
  me(@CurrentUser() user: AuthUser) {
    return this.auth.me(user);
  }

  @Post('mfa/totp/setup')
  @HttpCode(200)
  setupTotp(@CurrentUser() user: AuthUser) {
    return this.mfa.setup(user.id, user.email);
  }

  @Post('mfa/totp/confirm')
  @HttpCode(200)
  confirmTotp(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(totpCodeSchema)) body: { code: string },
  ) {
    return this.mfa.confirm(user.id, body.code);
  }

  @Post('step-up')
  @HttpCode(200)
  stepUp(@CurrentUser() user: AuthUser, @Body(new ZodPipe(totpCodeSchema)) body: { code: string }) {
    return this.auth.stepUp(user, body.code);
  }
}
