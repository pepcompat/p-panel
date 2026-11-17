/**
 * API shapes. Prefer @ppanel/shared-contracts; the few web-only extensions are marked and listed in
 * the web report as contract requests.
 */
import type {
  AuditEvent as SharedAuditEvent,
  Environment,
  LoginMfaRequired,
  LoginResponse,
  RoleBinding,
  UserPublic,
} from '@ppanel/shared-contracts';

export type {
  CreateRoleBindingInput,
  LoginMfaRequired,
  LoginResponse,
  LoginSuccess,
  MeResponse,
  StepUpResponse,
  TotpSetupResponse as TotpSetup,
  UserPublic as AuthUser,
} from '@ppanel/shared-contracts';

export function isMfaRequired(r: LoginResponse): r is LoginMfaRequired {
  return (r as LoginMfaRequired).mfaRequired === true;
}

export interface SetupStatus {
  bootstrapped: boolean;
}

/** GET /users row: UserPublic + embedded bindings (as the API returns today). */
export type UserRecord = UserPublic & { bindings?: RoleBinding[] };

/** Audit row. `actorLabel` / `targetLabel` are web-requested display fields (PROPOSED); optional. */
export type AuditEvent = Omit<SharedAuditEvent, 'metadata' | 'actorType'> & {
  actorType: SharedAuditEvent['actorType'] | string;
  metadata?: Record<string, unknown> | null;
  actorLabel?: string | null;
  targetLabel?: string | null;
};

export interface ServerPatch {
  name?: string;
  environment?: Environment;
  tags?: string[];
  groupId?: string | null;
  connectionPolicy?: string;
}
