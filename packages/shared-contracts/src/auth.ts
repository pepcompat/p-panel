import { z } from 'zod';
import type { Permission, RoleBinding } from './permissions';

export const REFRESH_COOKIE_NAME = 'ppanel_rt';
export const REFRESH_COOKIE_PATH = '/api/v1/auth';
/** Required on cookie-authenticated refresh (CSRF defence). */
export const CSRF_HEADER = 'X-CSRF';
export const STEP_UP_HEADER = 'X-Step-Up';
export const ACCESS_TOKEN_TTL_SEC = 900;

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(1).max(1024),
});
export type LoginInput = z.infer<typeof loginSchema>;

const totpCode = z
  .string()
  .trim()
  .regex(/^\d{6}$/);
export const mfaVerifySchema = z.union([
  z.object({ mfaToken: z.string().min(10), code: totpCode }).strict(),
  z
    .object({ mfaToken: z.string().min(10), recoveryCode: z.string().trim().min(8).max(32) })
    .strict(),
]);
export type MfaVerifyInput = z.infer<typeof mfaVerifySchema>;

export const totpCodeSchema = z.object({ code: totpCode }).strict();

export const passwordSchema = z.string().min(12).max(256);

export const bootstrapSchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    password: passwordSchema,
    displayName: z.string().trim().min(1).max(100),
    setupToken: z.string().min(1).max(512),
  })
  .strict();
export type BootstrapInput = z.infer<typeof bootstrapSchema>;

export interface UserPublic {
  id: string;
  email: string;
  displayName: string;
  status: 'active' | 'disabled';
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface LoginSuccess {
  accessToken: string;
  expiresIn: number;
  user: UserPublic;
}
export interface LoginMfaRequired {
  mfaRequired: true;
  mfaToken: string;
}
export type LoginResponse = LoginSuccess | LoginMfaRequired;

export interface RefreshResponse {
  accessToken: string;
  expiresIn: number;
}

export interface MeResponse {
  user: UserPublic;
  /** Union of permissions across all bindings (any scope). Server enforces scope per resource. */
  permissions: Permission[];
  bindings: RoleBinding[];
  mfaEnabled: boolean;
}

export interface TotpSetupResponse {
  otpauthUrl: string;
  secretMasked: string;
}
export interface TotpConfirmResponse {
  recoveryCodes: string[];
}
export interface StepUpResponse {
  stepUpToken: string;
  expiresAt: string;
}
