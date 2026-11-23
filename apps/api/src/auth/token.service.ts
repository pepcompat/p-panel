import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ACCESS_TOKEN_TTL_SEC } from '@ppanel/shared-contracts';
import { AppError } from '../common/app-error';
import { APP_CONFIG, type AppConfig } from '../config/config';

type TokenKind = 'access' | 'mfa' | 'step_up';
const TTL: Record<TokenKind, number> = { access: ACCESS_TOKEN_TTL_SEC, mfa: 300, step_up: 300 };

export interface AccessClaims {
  sub: string;
  sid: string;
  amr: string[];
}
export interface MfaClaims {
  sub: string;
}
export interface StepUpClaims {
  sub: string;
  sid: string;
}

/** HS256 JWTs. Each kind has its own audience so tokens are never interchangeable. */
@Injectable()
export class TokenService {
  private readonly jwt: JwtService;
  constructor(@Inject(APP_CONFIG) config: AppConfig) {
    this.jwt = new JwtService({ secret: config.JWT_ACCESS_SECRET });
  }

  sign(kind: TokenKind, claims: object): { token: string; expiresIn: number; expiresAt: Date } {
    const expiresIn = TTL[kind];
    const token = this.jwt.sign(
      { ...claims },
      { algorithm: 'HS256', expiresIn, issuer: 'ppanel', audience: `ppanel:${kind}` },
    );
    return { token, expiresIn, expiresAt: new Date(Date.now() + expiresIn * 1000) };
  }

  verify<T extends object>(kind: TokenKind, token: string, onError: () => AppError): T {
    try {
      return this.jwt.verify<T>(token, {
        algorithms: ['HS256'],
        issuer: 'ppanel',
        audience: `ppanel:${kind}`,
      });
    } catch {
      throw onError();
    }
  }
}
