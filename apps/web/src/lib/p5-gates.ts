/**
 * P5 UI gates and validation hints. The Center enforces everything; these only decide button state
 * and show early hints.
 */
import {
  BUILTIN_ROLES,
  SERVER_OFFLINE_MIN_FOR_SEC,
  type Permission,
  type RoleBinding,
} from '@ppanel/shared-contracts';
import type { MeResponse } from './api/types';
import type { AlertRuleInput, Incident, RuleKind, ThresholdParams } from './api/p5-types';
import { ALERT_KIND_SCOPES, LOG_MAX_SPAN_MS, LOG_Q_MAX, THRESHOLD_METRICS } from './api/p5-types';
import type { MessageKey } from '@/i18n/en';

function bindingCovers(
  b: RoleBinding,
  perm: Permission,
  target: { environment?: string; serverId?: string },
): boolean {
  if (!BUILTIN_ROLES[b.roleKey]?.includes(perm)) return false;
  if (b.scopeType === 'global') return true;
  if (b.scopeType === 'environment')
    return !!target.environment && b.scopeId === target.environment;
  if (b.scopeType === 'server') return !!target.serverId && b.scopeId === target.serverId;
  return false;
}

/**
 * Acknowledge needs `fleet.read` + `servers.operate` in the target's scope (§9.4). Uses the
 * incident's `allowedActions` when the Center provides it, else the caller's role bindings.
 */
export function canAckIncident(me: MeResponse | null | undefined, inc: Incident): boolean {
  if (!me) return false;
  if (inc.status === 'resolved') return false;
  if (inc.allowedActions) return inc.allowedActions.includes('acknowledge');
  if (!me.permissions.includes('fleet.read')) return false;
  const target = { environment: inc.environment, serverId: inc.serverId };
  return me.bindings.some((b) => bindingCovers(b, 'servers.operate', target));
}

/** Comments follow the same scope rule as acknowledge but stay possible after resolve. */
export function canCommentIncident(me: MeResponse | null | undefined, inc: Incident): boolean {
  if (!me) return false;
  if (inc.allowedActions) return inc.allowedActions.includes('comment');
  return canAckIncident(me, { ...inc, status: 'firing' });
}

// ---------------------------------------------------------------- webhook URL hints

const PRIVATE_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
];

export type UrlHint =
  | { level: 'error'; key: MessageKey }
  | { level: 'warn'; key: MessageKey }
  | { level: 'ok'; key: MessageKey };

/** Early, client-side hints for a webhook URL (the Center resolves DNS and decides). */
export function webhookUrlHints(raw: string): UrlHint[] {
  const v = raw.trim();
  if (!v) return [];
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return [{ level: 'error', key: 'ch.hint.invalidUrl' }];
  }
  const out: UrlHint[] = [];
  if (u.protocol !== 'https:' && u.protocol !== 'http:')
    return [{ level: 'error', key: 'ch.hint.invalidUrl' }];
  if (u.username || u.password) out.push({ level: 'error', key: 'ch.hint.userinfo' });
  if (u.protocol === 'http:') out.push({ level: 'warn', key: 'ch.hint.http' });
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const internal =
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.internal') ||
    host === 'metadata.google.internal' ||
    host === '::1' ||
    host.startsWith('fc') ||
    host.startsWith('fd') ||
    host.startsWith('fe80') ||
    PRIVATE_V4.some((re) => re.test(host));
  if (internal) out.push({ level: 'warn', key: 'ch.hint.private' });
  if (out.length === 0) out.push({ level: 'ok', key: 'ch.hint.ok' });
  return out;
}

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const TELEGRAM_CHAT_RE = /^(?:-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/;
export const TELEGRAM_TOKEN_RE = /^\d{3,20}:[A-Za-z0-9_-]{20,100}$/;

// ---------------------------------------------------------------- rule form

export interface RuleFormErrors {
  name?: MessageKey;
  scopeId?: MessageKey;
  forSec?: MessageKey;
  value?: MessageKey;
  metric?: MessageKey;
}

export function validateRule(r: AlertRuleInput): RuleFormErrors {
  const e: RuleFormErrors = {};
  if (!r.name.trim() || r.name.trim().length > 120) e.name = 'rule.err.name';
  if (r.scopeType !== 'global' && !r.scopeId) e.scopeId = 'rule.err.scope';
  if (!Number.isInteger(r.forSec) || r.forSec < 0 || r.forSec > 86400) e.forSec = 'rule.err.forSec';
  else if (r.kind === 'server_offline' && r.forSec < SERVER_OFFLINE_MIN_FOR_SEC)
    e.forSec = 'rule.err.forSecOffline';
  if (r.kind === 'metric_threshold') {
    const p = r.params as Partial<ThresholdParams>;
    if (!p.metric || !(THRESHOLD_METRICS as readonly string[]).includes(p.metric))
      e.metric = 'rule.err.metric';
    if (typeof p.value !== 'number' || !Number.isFinite(p.value)) e.value = 'rule.err.value';
    else if (p.metric !== 'load1' && (p.value < 0 || p.value > 100)) e.value = 'rule.err.pct';
  }
  return e;
}

/** Scope types that make sense per kind (app_down targets apps; thresholds target servers). */
export function scopeTypesFor(kind: RuleKind): ReadonlyArray<AlertRuleInput['scopeType']> {
  return ALERT_KIND_SCOPES[kind];
}

// ---------------------------------------------------------------- log time range

export type LogRangeError = 'logs.err.order' | 'logs.err.span' | 'logs.err.q' | null;
export function validateLogRange(fromMs: number, toMs: number, q = ''): LogRangeError {
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || fromMs >= toMs) return 'logs.err.order';
  if (toMs - fromMs > LOG_MAX_SPAN_MS) return 'logs.err.span';
  if (q.length > LOG_Q_MAX) return 'logs.err.q';
  return null;
}

/** True when a global binding grants `perm` (log queries may then omit serverId/appId). */
export function hasGlobalPerm(me: MeResponse | null | undefined, perm: Permission): boolean {
  return !!me?.bindings.some(
    (b) => b.scopeType === 'global' && BUILTIN_ROLES[b.roleKey]?.includes(perm),
  );
}
