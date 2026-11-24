/**
 * WebSocket close codes and session end reasons (docs/P10_SSH_CONTRACT.md §5) mapped to UI copy.
 * Pure — unit tested in tests/unit/p10.test.tsx.
 */
import type { Tone } from '@/components/ui/badge';
import type { MessageKey } from '@/i18n/en';
import { END_REASONS, type EndReason } from '@/lib/api/p10-types';

export const CLOSE = {
  normal: 1000,
  abnormal: 1006,
  protocol: 4400,
  auth: 4401,
  forbidden: 4403,
  expired: 4408,
  hostKey: 4409,
  limit: 4429,
  internal: 4500,
} as const;

/** Where the user can fix the cause. */
export type CloseAction = 'reconnect' | 'grants' | 'hostKeys' | 'sessions' | null;

export interface CloseInfo {
  code: number;
  /** end reason from the server's `closing` frame, if any */
  reason: EndReason | null;
  tone: Tone;
  titleKey: MessageKey;
  bodyKey: MessageKey;
  action: CloseAction;
  /** a new session (new ticket) may succeed */
  canReconnect: boolean;
}

export const isEndReason = (v: unknown): v is EndReason =>
  typeof v === 'string' && (END_REASONS as readonly string[]).includes(v);

export const endReasonKey = (r: EndReason): MessageKey => `p10.end.${r}` as MessageKey;

/** Map a close code (+ optional `closing` reason) to a state the terminal can explain. */
export function describeClose(code: number, rawReason?: unknown): CloseInfo {
  const reason = isEndReason(rawReason) ? rawReason : null;
  const base = { code, reason };
  switch (code) {
    case CLOSE.normal:
      return {
        ...base,
        tone: 'off',
        titleKey: 'p10.close.normal.title',
        bodyKey: reason ? endReasonKey(reason) : 'p10.close.normal.body',
        action: 'reconnect',
        canReconnect: true,
      };
    case CLOSE.auth:
      return {
        ...base,
        tone: 'crit',
        titleKey: 'p10.close.auth.title',
        bodyKey: 'p10.close.auth.body',
        action: 'reconnect',
        canReconnect: true,
      };
    case CLOSE.forbidden:
      return {
        ...base,
        tone: 'crit',
        titleKey: 'p10.close.forbidden.title',
        bodyKey:
          reason === 'credential_revoked'
            ? 'p10.end.credential_revoked'
            : reason === 'grant_revoked'
              ? 'p10.end.grant_revoked'
              : 'p10.close.forbidden.body',
        action: 'grants',
        canReconnect: false,
      };
    case CLOSE.expired: {
      const bodyKey: MessageKey =
        reason === 'max_duration' || reason === 'grant_expired' || reason === 'idle_timeout'
          ? endReasonKey(reason)
          : 'p10.close.expired.body';
      return {
        ...base,
        tone: 'warn',
        titleKey: 'p10.close.expired.title',
        bodyKey,
        // an idle timeout can be resumed with a new session; an expired grant needs a new grant
        action: reason === 'grant_expired' ? 'grants' : 'reconnect',
        canReconnect: reason !== 'grant_expired',
      };
    }
    case CLOSE.hostKey:
      return {
        ...base,
        tone: 'crit',
        titleKey: 'p10.close.hostKey.title',
        bodyKey: 'p10.close.hostKey.body',
        action: 'hostKeys',
        canReconnect: false,
      };
    case CLOSE.limit:
      return {
        ...base,
        tone: 'warn',
        titleKey: 'p10.close.limit.title',
        bodyKey: 'p10.close.limit.body',
        action: 'sessions',
        canReconnect: true,
      };
    case CLOSE.protocol:
      return {
        ...base,
        tone: 'crit',
        titleKey: 'p10.close.protocol.title',
        bodyKey: 'p10.close.protocol.body',
        action: 'reconnect',
        canReconnect: true,
      };
    case CLOSE.internal:
      return {
        ...base,
        tone: 'crit',
        titleKey: 'p10.close.internal.title',
        bodyKey:
          reason === 'auth_failed' || reason === 'connect_failed' || reason === 'center_shutdown'
            ? endReasonKey(reason)
            : 'p10.close.internal.body',
        action: 'reconnect',
        canReconnect: true,
      };
    default:
      return {
        ...base,
        tone: 'warn',
        titleKey: 'p10.close.lost.title',
        bodyKey: reason ? endReasonKey(reason) : 'p10.close.lost.body',
        action: 'reconnect',
        canReconnect: true,
      };
  }
}

/** Map an HTTP error from POST /ssh/sessions to the same vocabulary (before any socket exists). */
export function describeCreateError(status: number, code: string): CloseInfo {
  if (code === 'SSH_HOST_KEY_MISMATCH') return describeClose(CLOSE.hostKey, 'host_key_mismatch');
  if (code === 'SSH_HOST_KEY_UNTRUSTED')
    return { ...describeClose(CLOSE.hostKey), bodyKey: 'p10.close.hostKeyUntrusted.body' };
  if (status === 429 || code === 'SSH_SESSION_LIMIT') return describeClose(CLOSE.limit, 'limit');
  if (code === 'SSH_GRANT_INVALID' || code === 'SSH_NO_CREDENTIAL')
    return describeClose(CLOSE.forbidden);
  return describeClose(CLOSE.internal);
}
