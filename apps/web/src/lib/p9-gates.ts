/**
 * P9 UI rules: management path state, connection policy changes, VPC source honesty, diagnostics
 * and inventory validation, gateway route validation and change-plan gating. Pure functions (unit tested).
 * The Center enforces every rule again; these only decide what the UI offers and explains.
 */
import type { ConnectionPolicy, Permission } from '@ppanel/shared-contracts';
import type { Tone } from '@/components/ui/badge';
import type { MessageKey } from '@/i18n/en';
import type { GateResult } from './permissions';
import {
  DIAG_MAX_RESOLVE,
  DIAG_MAX_TCP,
  DIAG_PORTS,
  HEALTH_PATH_RE,
  NETWORK_INVENTORY_MAX_ROWS,
  PLAN_RUNNING,
  dialOrder,
  isDiagnosePrivateAddress,
  networkInventoryRowSchema,
  type CreateGatewayRouteInput,
  type DiagnoseParams,
  type EndpointProbe,
  type GatewayChangePlan,
  type InventoryRowInput,
  type MgmtPath,
  type ServerView,
} from './api/p9-types';

export { dialOrder };

/**
 * Permission mapping. The contract names `servers.manage` and `settings.manage`, which are not in
 * shared-contracts PERMISSIONS yet; the closest existing permissions are used until they are added.
 */
export const P9_PERM = {
  read: 'fleet.read',
  /** contract: servers.manage (policy change, diagnostics, inventory import) */
  serversManage: 'servers.operate',
  /** contract: settings.manage (provider integrations) */
  settingsManage: 'policies.manage',
  /** POST /server-groups already requires policies.manage in the API */
  groups: 'policies.manage',
  gateways: 'policies.manage',
  approve: 'approvals.decide',
} as const satisfies Record<string, Permission>;

/** A private probe must have succeeded this recently before `private_only` is accepted (§1). */
export const PRIVATE_PROBE_FRESH_MS = 5 * 60_000;
export const PROVIDER_STALE_MS = 24 * 3600_000;

// ---------------------------------------------------------------- IP helpers

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const isIpv4 = (s: string) => IPV4.test(s.trim());
export function isIpv6(s: string): boolean {
  const v = s.trim();
  if (!v.includes(':') || !/^[0-9a-fA-F:.]+$/.test(v)) return false;
  const dbl = v.split('::').length - 1;
  if (dbl > 1) return false;
  const parts = v.split(':').filter((p) => p !== '');
  return parts.length <= 8 && parts.every((p) => p.length <= 4 || isIpv4(p));
}
export const isIpLiteral = (s: string) => isIpv4(s) || isIpv6(s);

/** RFC 1918, 100.64/10 (CGNAT) or fd00::/8 — the ranges the agent accepts for diagnostics. */
export const isPrivateIp = (v: string) => isDiagnosePrivateAddress(v.trim());

const HOSTNAME =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
export const isHostname = (s: string) => HOSTNAME.test(s.trim());
/** Domain served by a gateway route: at least one dot, no wildcard, no scheme/port. */
export const isDomain = (s: string) => isHostname(s) && s.includes('.') && !isIpv4(s);

// ---------------------------------------------------------------- management paths

export type PathHealth = 'ok' | 'down' | 'unknown';

export function probeFor(s: ServerView, path: MgmtPath): EndpointProbe | undefined {
  return s.connection?.endpoints.find((e) => e.path === path);
}

export function pathHealth(p: EndpointProbe | undefined): PathHealth {
  if (!p || !p.checkedAt) return 'unknown';
  return p.ok ? 'ok' : 'down';
}

export interface PathState {
  tone: Tone;
  key: MessageKey;
  activePath: MgmtPath | null;
  /** private_only and the private path is down: the agent will not fall back (fail closed). */
  failClosed: boolean;
}

/**
 * Card/table path label from the P9 `connection` block. Returns null when the API does not send it yet
 * (callers fall back to the P1 address-based label).
 */
export function pathState(s: ServerView): PathState | null {
  const c = s.connection;
  if (!c) return null;
  const policy = s.connectionPolicy;
  const priv = pathHealth(probeFor(s, 'private'));
  const st = (tone: Tone, key: MessageKey, activePath: MgmtPath | null, failClosed = false) => ({
    tone,
    key,
    activePath,
    failClosed,
  });
  if (s.status === 'revoked') return st('crit', 'path.revoked', null);
  if (s.status === 'enrolling') return st('info', 'path.pending', null);
  if (s.status === 'offline')
    return policy === 'private_only'
      ? st('off', 'path.privateOnlyUnreachable', null, priv !== 'ok')
      : st('off', 'path.unreachable', null);
  if (policy === 'private_only' && priv !== 'ok' && c.activePath !== 'private')
    return st('crit', 'p9.path.failClosed', null, true);
  if (c.activePath === 'private')
    return s.status === 'stale'
      ? st('stale', 'path.privateStale', 'private')
      : st('ok', 'p9.path.activePrivate', 'private');
  if (c.activePath === 'public') {
    const fellBack = policy !== 'public_only' && policy !== 'public_preferred' && priv === 'down';
    return st('warn', fellBack ? 'p9.path.activePublicFallback' : 'p9.path.activePublic', 'public');
  }
  return st('off', 'p9.path.none', null);
}

/** Healthy private probe reported within the last 5 min (precondition for private_only). */
export function privateProbeFresh(s: ServerView, now = Date.now()): boolean {
  const p = probeFor(s, 'private');
  if (!p?.ok || !p.checkedAt) return false;
  return now - new Date(p.checkedAt).getTime() <= PRIVATE_PROBE_FRESH_MS;
}

export interface PolicyChangeCheck {
  needsStepUp: boolean;
  /** The Center will answer 422 PRIVATE_PATH_UNVERIFIED (predicted; it decides). */
  privateUnverified: boolean;
  /** Explain fail-closed before saving private_only. */
  failClosedWarning: boolean;
  /** Policy dials public only although a private path is healthy. */
  publicWarning: boolean;
}

export function policyChangeCheck(
  s: ServerView,
  next: ConnectionPolicy,
  now = Date.now(),
): PolicyChangeCheck {
  const changed = next !== s.connectionPolicy;
  const fresh = privateProbeFresh(s, now);
  return {
    needsStepUp: changed && s.environment === 'production',
    privateUnverified: changed && next === 'private_only' && !fresh,
    failClosedWarning: next === 'private_only',
    publicWarning: next === 'public_only' && pathHealth(probeFor(s, 'private')) === 'ok',
  };
}

// ---------------------------------------------------------------- VPC source honesty

export type VpcDisplay =
  | {
      known: true;
      uuid: string;
      name: string | null;
      source: 'provider' | 'inventory';
      key: MessageKey;
    }
  | { known: false; key: MessageKey };

/** A VPC is shown only when provider or inventory data says so; agent facts never imply one. */
export function vpcDisplay(s: Pick<ServerView, 'network'>): VpcDisplay {
  const n = s.network;
  if (n?.vpcUuid && (n.vpcSource === 'provider' || n.vpcSource === 'inventory'))
    return {
      known: true,
      uuid: n.vpcUuid,
      name: n.vpcName,
      source: n.vpcSource,
      key: n.vpcSource === 'provider' ? 'p9.source.provider' : 'p9.source.inventory',
    };
  return { known: false, key: 'p9.source.unknown' };
}

/** Region from P9 network view, then (agent-reported) provider facts. */
export const regionOf = (s: ServerView): string | null =>
  s.network?.region ?? s.provider?.region ?? null;

export const FINDING_TONE: Record<string, Tone> = {
  VPC_UNKNOWN: 'warn',
  SAME_REGION_DIFFERENT_VPC: 'warn',
  PRIVATE_IP_CONFLICT: 'crit',
  PROVIDER_STALE: 'stale',
  INVENTORY_MISMATCH: 'crit',
};
export const findingTone = (code: string): Tone => FINDING_TONE[code] ?? 'info';
export const findingKey = (code: string): MessageKey =>
  (code in FINDING_TONE ? `p9.finding.${code}` : 'p9.finding.other') as MessageKey;
/** What the operator should do about a finding. */
export const findingWhatKey = (code: string): MessageKey =>
  `${findingKey(code)}.what` as MessageKey;

// ---------------------------------------------------------------- server list filters

export interface ServerFilters {
  groupId: string;
  tag: string;
  policy: ConnectionPolicy | '';
}
export function matchesFilters(s: ServerView, f: ServerFilters): boolean {
  if (f.groupId === '__none' && s.groupId) return false;
  if (f.groupId && f.groupId !== '__none' && s.groupId !== f.groupId) return false;
  if (f.tag && !s.tags.includes(f.tag)) return false;
  if (f.policy && s.connectionPolicy !== f.policy) return false;
  return true;
}

// ---------------------------------------------------------------- diagnostics

export interface DiagErrors {
  resolve?: MessageKey;
  tcp?: MessageKey;
  tcpVars?: Record<string, string>;
  /** non-blocking: ports outside the agent's fixed list (allowed only if the Center lists them) */
  portWarning?: string[];
}

/** Parses "host:port" lines; returns null entries for unparsable lines. */
export function parseTcpLines(text: string): Array<{ host: string; port: number } | null> {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const m = l.match(/^\[?([0-9a-fA-F:.]+?)\]?:(\d{1,5})$/);
      if (!m) return null;
      const port = Number(m[2]);
      return port >= 1 && port <= 65535 ? { host: m[1]!, port } : null;
    });
}

export const splitLines = (text: string) =>
  text
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);

/** Hosts of advertised Center endpoints (from a diagnostics result) — also valid TCP targets. */
export function centerHosts(endpoints: ReadonlyArray<{ url?: string }>): string[] {
  return endpoints
    .map((e) => {
      try {
        return e.url ? new URL(e.url).hostname.replace(/^\[|\]$/g, '') : null;
      } catch {
        return null;
      }
    })
    .filter((h): h is string => !!h);
}

export function validateDiagnose(
  resolveText: string,
  tcpText: string,
  includeRoutes = true,
  allowedHosts: string[] = [],
): { params: DiagnoseParams | null; errors: DiagErrors } {
  const errors: DiagErrors = {};
  const resolve = splitLines(resolveText);
  if (resolve.length > DIAG_MAX_RESOLVE) errors.resolve = 'p9.diag.err.resolveMax';
  else if (resolve.some((h) => !isHostname(h) || isIpLiteral(h)))
    errors.resolve = 'p9.diag.err.hostname';
  const parsed = parseTcpLines(tcpText);
  const tcp = parsed.filter((x): x is { host: string; port: number } => !!x);
  if (parsed.length > DIAG_MAX_TCP) errors.tcp = 'p9.diag.err.tcpMax';
  else if (parsed.some((x) => !x)) errors.tcp = 'p9.diag.err.tcpFormat';
  else {
    const bad = tcp.find((x) => !isIpLiteral(x.host));
    const outside = tcp.find(
      (x) => isIpLiteral(x.host) && !isPrivateIp(x.host) && !allowedHosts.includes(x.host),
    );
    if (bad) {
      errors.tcp = 'p9.diag.err.ipLiteral';
      errors.tcpVars = { host: bad.host };
    } else if (outside) {
      errors.tcp = 'p9.diag.err.privateOnly';
      errors.tcpVars = { host: outside.host };
    }
  }
  const odd = [
    ...new Set(
      tcp
        .filter((x) => !(DIAG_PORTS as readonly number[]).includes(x.port))
        .map((x) => String(x.port)),
    ),
  ];
  if (odd.length) errors.portWarning = odd;
  const blocking = !!errors.resolve || !!errors.tcp;
  return { params: blocking ? null : { resolve, tcp, includeRoutes }, errors };
}

// ---------------------------------------------------------------- inventory import

/** Strict row schema from shared-contracts (exactly one of serverId / hostname). */
export const inventoryRowSchema = networkInventoryRowSchema;
export const INVENTORY_MAX_ROWS = NETWORK_INVENTORY_MAX_ROWS;

export interface InventoryIssue {
  row: number;
  field: string;
  message: string;
}
export interface InventoryParse {
  rows: InventoryRowInput[];
  issues: InventoryIssue[];
  /** whole-document error (bad JSON, not an array, too many rows) */
  fatal: MessageKey | null;
}

/** Accepts `[...]` or `{ "rows": [...] }`. Every row is validated against the strict server schema. */
export function parseInventory(text: string): InventoryParse {
  const out: InventoryParse = { rows: [], issues: [], fatal: null };
  if (!text.trim()) return { ...out, fatal: 'p9.inv.err.empty' };
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return { ...out, fatal: 'p9.inv.err.json' };
  }
  const arr = Array.isArray(doc)
    ? doc
    : doc && typeof doc === 'object' && Array.isArray((doc as { rows?: unknown }).rows)
      ? (doc as { rows: unknown[] }).rows
      : null;
  if (!arr) return { ...out, fatal: 'p9.inv.err.shape' };
  if (arr.length === 0) return { ...out, fatal: 'p9.inv.err.empty' };
  if (arr.length > INVENTORY_MAX_ROWS) return { ...out, fatal: 'p9.inv.err.tooMany' };
  arr.forEach((raw, i) => {
    const r = inventoryRowSchema.safeParse(raw);
    if (r.success) out.rows.push(r.data);
    else
      for (const iss of r.error.issues)
        out.issues.push({
          row: i + 1,
          field:
            iss.path.join('.') || (iss.code === 'unrecognized_keys' ? iss.keys.join(', ') : '—'),
          message:
            iss.code === 'unrecognized_keys'
              ? `Unknown field: ${iss.keys.join(', ')}`
              : iss.message,
        });
  });
  return out;
}

// ---------------------------------------------------------------- gateway routes

/** Route form state: address may be blank = "server's preferred private IPv4" (decided by the API). */
export interface RouteDraft {
  domain: string;
  mode: CreateGatewayRouteInput['mode'];
  healthPath: string;
  backends: Array<{ serverId: string; address: string; port: string }>;
}

export type RouteErrors = Partial<Record<'domain' | 'backends' | 'healthPath', MessageKey>> & {
  backendRows?: Record<number, MessageKey>;
};

export function validateRoute(
  r: RouteDraft,
  existingDomains: string[] = [],
  editing = false,
): RouteErrors {
  const e: RouteErrors = {};
  const d = r.domain.trim().toLowerCase();
  if (!editing) {
    if (!isDomain(d)) e.domain = 'p9.route.err.domain';
    else if (existingDomains.includes(d)) e.domain = 'p9.route.err.duplicate';
  }
  if (!HEALTH_PATH_RE.test(r.healthPath)) e.healthPath = 'p9.route.err.healthPath';
  if (r.backends.length === 0) e.backends = 'p9.route.err.noBackends';
  else if (r.backends.length > 10) e.backends = 'p9.route.err.tooManyBackends';
  const rows: Record<number, MessageKey> = {};
  const seen = new Set<string>();
  r.backends.forEach((b, i) => {
    const port = Number(b.port);
    if (!b.serverId) rows[i] = 'p9.route.err.server';
    else if (b.address.trim() && !isIpv4(b.address)) rows[i] = 'p9.route.err.address';
    else if (!/^\d+$/.test(b.port) || port < 1 || port > 65535) rows[i] = 'p9.route.err.port';
    else if (seen.has(`${b.serverId}:${port}`)) rows[i] = 'p9.route.err.dupBackend';
    seen.add(`${b.serverId}:${port}`);
  });
  if (Object.keys(rows).length) e.backendRows = rows;
  return e;
}
export const routeValid = (e: RouteErrors) => Object.keys(e).length === 0;

export function routeBody(r: RouteDraft): CreateGatewayRouteInput {
  return {
    domain: r.domain.trim().toLowerCase(),
    mode: r.mode,
    healthPath: r.healthPath,
    backends: r.backends.map((b) => ({
      serverId: b.serverId,
      ...(b.address.trim() ? { address: b.address.trim() } : {}),
      port: Number(b.port),
    })),
  };
}

/** Backend address: verified private IPv4 preferred, else public (flagged by the caller). */
export function backendAddressFor(
  s: ServerView,
): { address: string; scope: 'private' | 'public' } | null {
  const priv =
    s.privateIpv4 ??
    s.addresses.find((a) => a.scope === 'private' && a.family === 'ipv4' && a.verifiedAt)?.address;
  if (priv) return { address: priv, scope: 'private' };
  const pub =
    s.publicIpv4 ?? s.addresses.find((a) => a.scope === 'public' && a.family === 'ipv4')?.address;
  return pub ? { address: pub, scope: 'public' } : null;
}

// ---------------------------------------------------------------- change plans

export type PlanAction = 'shadow_test' | 'approve' | 'apply' | 'rollback';

export const planApproved = (p: Pick<GatewayChangePlan, 'approval'>) => !!p.approval?.approvedBy;

/** A job runs (validation of a draft, shadow test, apply, rollback): poll and disable actions. */
export const planBusy = (p: Pick<GatewayChangePlan, 'status' | 'validation'>) =>
  PLAN_RUNNING.includes(p.status) || (p.status === 'draft' && p.validation?.valid !== false);

export const shadowAllMatch = (p: Pick<GatewayChangePlan, 'shadowResults'>) =>
  !!p.shadowResults?.length && p.shadowResults.every((r) => r.match);

export const PLAN_STEPS = ['validate', 'shadow', 'approval', 'apply'] as const;
export type PlanStep = (typeof PLAN_STEPS)[number];
export type StepState = 'done' | 'current' | 'running' | 'todo' | 'skipped' | 'failed';

/** Stepper state for create → validate → shadow test → approval → apply. */
export function planStepState(p: GatewayChangePlan): Record<PlanStep, StepState> {
  const st = p.status;
  const approval = !!p.approval?.required;
  const approved = planApproved(p);
  const invalid = p.validation?.valid === false;
  const validated = !invalid && st !== 'draft';
  const shadowDone = !!p.shadowResults && st !== 'shadow_testing' && validated;
  const final = st === 'applied' || st === 'rolled_back' || st === 'rolling_back';
  const failed = st === 'failed' || st === 'cancelled';
  return {
    validate: invalid ? 'failed' : validated ? 'done' : 'running',
    shadow:
      st === 'shadow_testing'
        ? 'running'
        : shadowDone
          ? 'done'
          : validated && !failed
            ? 'current'
            : 'todo',
    approval: !approval
      ? 'skipped'
      : approved
        ? 'done'
        : shadowDone && !failed && !final
          ? 'current'
          : 'todo',
    apply:
      st === 'applying'
        ? 'running'
        : final
          ? 'done'
          : failed && shadowDone
            ? 'failed'
            : shadowDone && (!approval || approved) && !failed
              ? 'current'
              : 'todo',
  };
}

const ok: GateResult = { allowed: true };
const no = (key: MessageKey, vars?: Record<string, string>): GateResult => ({
  allowed: false,
  reason: { key, vars },
});

/**
 * UI gate for plan actions. Mirrors the Center: permission, plan state, second-person approval,
 * and the plan's own `allowedActions` (when the API sends a list that omits the action, it is blocked).
 */
export function planGate(
  action: PlanAction,
  p: GatewayChangePlan,
  permissions: readonly string[] | undefined,
  userId: string | undefined,
): GateResult {
  const has = (perm: Permission) => (permissions ?? []).includes(perm);
  const busy = planBusy(p);
  const approval = !!p.approval?.required;
  const shadowed = p.status === 'shadow_tested' || p.status === 'awaiting_approval';
  const allowedByApi = !p.allowedActions || p.allowedActions.includes(action);
  let r: GateResult;
  switch (action) {
    case 'shadow_test':
      if (!has(P9_PERM.gateways)) return no('perm.missing', { perm: P9_PERM.gateways });
      if (busy) return no('p9.plan.gate.busy');
      if (!['validated', 'shadow_tested', 'awaiting_approval'].includes(p.status))
        return no('p9.plan.gate.notValidated');
      r = ok;
      break;
    case 'approve':
      if (!approval) return no('p9.plan.gate.noApproval');
      if (!has(P9_PERM.approve)) return no('perm.missing', { perm: P9_PERM.approve });
      if (p.createdBy && p.createdBy === userId) return no('p9.plan.gate.ownPlan');
      if (planApproved(p)) return no('p9.plan.gate.alreadyApproved');
      if (!shadowed) return no('p9.plan.gate.needShadow');
      r = ok;
      break;
    case 'apply':
      if (!has(P9_PERM.gateways)) return no('perm.missing', { perm: P9_PERM.gateways });
      if (busy) return no('p9.plan.gate.busy');
      if (!shadowed) return no('p9.plan.gate.needShadow');
      if (approval && !planApproved(p)) return no('p9.plan.gate.needApproval');
      r = ok;
      break;
    case 'rollback':
      if (!has(P9_PERM.gateways)) return no('perm.missing', { perm: P9_PERM.gateways });
      if (busy) return no('p9.plan.gate.busy');
      if (p.status !== 'applied' && p.status !== 'failed') return no('p9.plan.gate.notApplied');
      r = ok;
      break;
  }
  return allowedByApi ? r : no('perm.actionNotAllowed', { action });
}

/** Plain-text cutover checklist for a change ticket. pPanel never edits DNS. */
export function cutoverText(p: Pick<GatewayChangePlan, 'cutover'>): string {
  const c = p.cutover;
  if (!c) return '';
  const lines = ['# DNS changes - make them by hand at your DNS provider (pPanel never edits DNS)'];
  for (const r of c.dnsChanges.filter((x) => x.action !== 'none'))
    lines.push(
      `${r.recordType} ${r.domain} -> ${(r.action === 'point_to_gateway' ? r.target : r.directTarget) ?? '?'}` +
        `  # ${r.action === 'point_to_gateway' ? `was ${r.directTarget ?? '?'}` : 'back to the direct origin'}`,
    );
  if (!c.dnsChanges.some((x) => x.action !== 'none'))
    lines.push('# no DNS change needed for this plan');
  lines.push('', `# TTL: ${c.ttlAdvice}`, '', '# Verify');
  lines.push(...c.verification);
  lines.push('', '# Rollback');
  lines.push(...c.rollback.map((s, i) => `${i + 1}. ${s}`));
  if (c.note) lines.push('', `# ${c.note}`);
  return lines.join('\n');
}
