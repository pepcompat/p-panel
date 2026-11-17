import { createParamDecorator, type ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Permission } from '@ppanel/shared-contracts';
import type { Request } from 'express';
import type { AuthUser } from './principal';

export const IS_PUBLIC = 'ppanel:public';
export const PERMISSION = 'ppanel:permission';

/** Route needs no access token. */
export const Public = () => SetMetadata(IS_PUBLIC, true);

/**
 * Coarse guard: caller must hold `perm` in at least one binding (any scope).
 * Services then enforce the resource-scoped check (global ⊇ environment ⊇ server).
 */
export const RequirePermission = (perm: Permission) => SetMetadata(PERMISSION, perm);

export const CurrentUser = createParamDecorator((_: unknown, ctx: ExecutionContext): AuthUser => {
  const req = ctx.switchToHttp().getRequest<Request & { user?: AuthUser }>();
  return req.user!;
});
