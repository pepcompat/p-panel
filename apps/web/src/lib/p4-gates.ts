/**
 * Pure P4 UI logic: deploy wizard state + step gating, input validation (image digest, hostnames, env
 * keys, named volumes, TLS paths), preflight → deploy readiness, deployment action gates and the
 * container lifecycle actions. The Center enforces all of it; this only decides UI state.
 */
import type { Server } from '@ppanel/shared-contracts';
import type { MessageKey } from '@/i18n/en';
import { evaluateGate, type GateResult } from './permissions';
import { GIT_HOST_ALLOWLIST } from './config';
import {
  composeIssues,
  gitSourceIssues,
  initialCompose,
  initialGitSource,
  type ComposeState,
  type GitSourceState,
} from './p4b-gates';
import type { Application } from './api/p3-types';
import {
  DEPLOYMENT_CANCELLABLE,
  ENV_KEY_RE,
  IMAGE_DIGEST_REF_RE,
  TLS_PATH_RE,
  isValidHostname,
  type Deployment,
  type Framework,
  type PreflightCheck,
} from './api/p4-types';

// ---------------------------------------------------------------- validation

export const isPinnedImage = (ref: string) => IMAGE_DIGEST_REF_RE.test(ref.trim());
export const isEnvKey = (k: string) => ENV_KEY_RE.test(k);
export const APP_NAME_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;

const REPO_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
const TAG_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

export type ImageResolution =
  | { kind: 'empty' }
  | { kind: 'invalid'; reason: MessageKey }
  | { kind: 'pinned'; ref: string }
  /** A tag was given: the API refuses tags, a digest ref must be pasted. */
  | { kind: 'tag'; tagRef: string; pasted: string; pastedValid: boolean; ref: string | null };

/**
 * Registry source → digest-pinned image ref. `repo` may already contain `@sha256:` or `:tag`.
 * `pastedDigestRef` is the operator-supplied `repo@sha256:…` used when only a tag is known.
 */
export function resolveImage(
  repo: string,
  tagOrDigest: string,
  pastedDigestRef = '',
): ImageResolution {
  let r = repo.trim();
  let ref = tagOrDigest.trim();
  if (!r && !ref) return { kind: 'empty' };
  const at = r.indexOf('@');
  if (at > 0) {
    ref = r.slice(at + 1);
    r = r.slice(0, at);
  } else {
    const lastSlash = r.lastIndexOf('/');
    const colon = r.lastIndexOf(':');
    if (colon > lastSlash && !ref) {
      ref = r.slice(colon + 1);
      r = r.slice(0, colon);
    }
  }
  if (!REPO_RE.test(r)) return { kind: 'invalid', reason: 'wiz.src.err.repo' };
  if (!ref) return { kind: 'invalid', reason: 'wiz.src.err.ref' };
  if (ref.startsWith('sha256:')) {
    if (!DIGEST_RE.test(ref)) return { kind: 'invalid', reason: 'wiz.src.err.digest' };
    const full = `${r}@${ref}`;
    return isPinnedImage(full)
      ? { kind: 'pinned', ref: full }
      : { kind: 'invalid', reason: 'wiz.src.err.digest' };
  }
  if (!TAG_RE.test(ref)) return { kind: 'invalid', reason: 'wiz.src.err.ref' };
  const pasted = pastedDigestRef.trim();
  const pastedValid = isPinnedImage(pasted) && pasted.split('@')[0] === r;
  return {
    kind: 'tag',
    tagRef: `${r}:${ref}`,
    pasted,
    pastedValid,
    ref: pastedValid ? pasted : null,
  };
}

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
/** RFC 1123 hostname, lowercase, at least one dot, no wildcard / regex / port / scheme. */
export function hostnameError(h: string): MessageKey | null {
  const v = h.trim();
  if (!v) return 'wiz.dom.err.empty';
  if (v !== v.toLowerCase()) return 'wiz.dom.err.lowercase';
  if (v.length > 253) return 'wiz.dom.err.long';
  if (v.includes('*')) return 'wiz.dom.err.wildcard';
  if (/[:/\s]/.test(v)) return 'wiz.dom.err.chars';
  const labels = v.split('.');
  if (labels.length < 2) return 'wiz.dom.err.dot';
  if (!labels.every((l) => LABEL_RE.test(l))) return 'wiz.dom.err.label';
  if (/^\d+$/.test(labels[labels.length - 1]!)) return 'wiz.dom.err.ip';
  // Shared HOSTNAME_RE is the injection boundary the Center enforces.
  if (!isValidHostname(v)) return 'wiz.dom.err.label';
  return null;
}

/** Named volumes only: name is a slug, mount path absolute inside the container. */
export function volumeError(v: { name: string; mountPath: string }): MessageKey | null {
  const n = v.name.trim();
  if (n.startsWith('/') || n.startsWith('.') || n.startsWith('~') || n.includes('/'))
    return 'wiz.cfg.vol.err.hostPath';
  if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(n)) return 'wiz.cfg.vol.err.name';
  if (!/^\/[A-Za-z0-9._/-]{1,200}$/.test(v.mountPath.trim()) || v.mountPath.includes('..'))
    return 'wiz.cfg.vol.err.mount';
  if (['/', '/etc', '/proc', '/sys', '/dev', '/var/run'].includes(v.mountPath.trim()))
    return 'wiz.cfg.vol.err.mount';
  return null;
}

/** Existing certificate paths must live under /etc/ssl or /etc/letsencrypt/live (§7.3). */
export function tlsPathError(p: string): MessageKey | null {
  const v = p.trim();
  if (!v) return 'wiz.dom.tls.err.empty';
  if (v.includes('..') || !/^\/[A-Za-z0-9._/-]+$/.test(v)) return 'wiz.dom.tls.err.path';
  if (!v.startsWith('/etc/ssl/') && !v.startsWith('/etc/letsencrypt/live/'))
    return 'wiz.dom.tls.err.root';
  if (!TLS_PATH_RE.test(v) || v.includes('//')) return 'wiz.dom.tls.err.path';
  return null;
}

// ---------------------------------------------------------------- wizard state

export const WIZARD_STEPS = [
  'source',
  'detect',
  'target',
  'configure',
  'domain',
  'review',
  'execution',
] as const;
export type WizardStep = (typeof WIZARD_STEPS)[number];
/** `git` = build from a Git commit on a build node (§8); `github` = GitHub App flow (BLOCKED). */
export type SourceKind = 'registry' | 'git' | 'compose' | 'github';

export interface EnvRow {
  id: string;
  key: string;
  value: string;
}
export interface SecretRow {
  id: string;
  key: string;
  /** A value was typed and is held (outside React state) until the app is created. */
  staged: boolean;
}

export interface WizardState {
  /** `existing` = deploy a new version of an existing container app (target/config fixed). */
  mode: 'new' | 'existing';
  appId: string | null;
  source: {
    kind: SourceKind;
    repo: string;
    ref: string;
    digestRef: string;
  };
  /** §8 Git source (build on a build node → push → deploy the digest). */
  git: GitSourceState;
  /** §8.3 Compose application. */
  compose: ComposeState;
  detect: { override: Framework | ''; skipped: boolean };
  target: { serverId: string };
  config: {
    name: string;
    containerPort: string;
    hcPath: string;
    hcStatus: string;
    hcTimeoutSec: string;
    hcStartPeriodSec: string;
    memoryMb: string;
    cpus: string;
    env: EnvRow[];
    secrets: SecretRow[];
    volumes: Array<{ id: string; name: string; mountPath: string }>;
    registry: { serveraddress: string; username: string; passwordStaged: boolean };
  };
  domain: {
    domains: string[];
    tls: 'http' | 'existing';
    certPath: string;
    keyPath: string;
  };
}

export function initialWizard(mode: 'new' | 'existing' = 'new'): WizardState {
  return {
    mode,
    appId: null,
    source: { kind: 'registry', repo: '', ref: '', digestRef: '' },
    git: initialGitSource(),
    compose: initialCompose(),
    detect: { override: '', skipped: false },
    target: { serverId: '' },
    config: {
      name: '',
      containerPort: '8080',
      hcPath: '/healthz',
      hcStatus: '200',
      hcTimeoutSec: '3',
      hcStartPeriodSec: '60',
      memoryMb: '512',
      cpus: '1',
      env: [],
      secrets: [],
      volumes: [],
      registry: { serveraddress: '', username: '', passwordStaged: false },
    },
    domain: { domains: [''], tls: 'http', certPath: '', keyPath: '' },
  };
}

export interface WizardCtx {
  servers: Array<Pick<Server, 'id' | 'status'> & { capabilities?: string[]; buildNode?: boolean }>;
  /** Secret keys already set on the application (compose placeholders). */
  setSecrets?: readonly string[];
  /** Git host allowlist hint (defaults to the client config). */
  gitAllowlist?: readonly string[];
}

/** Why a server cannot be a deploy target (null = eligible). */
export function targetBlockReason(
  s: Pick<Server, 'status'> & { capabilities?: string[] },
): MessageKey | null {
  if (s.status !== 'online') return `wiz.tgt.reason.${s.status}` as MessageKey;
  if (s.capabilities && !s.capabilities.includes('docker')) return 'wiz.tgt.reason.noDocker';
  return null;
}

const intIn = (s: string, min: number, max: number) => {
  const n = Number(s);
  return /^\d+$/.test(s.trim()) && n >= min && n <= max;
};

/** Blocking issues of a step (empty = can continue). Execution is reached only by deploying. */
export function stepIssues(step: WizardStep, w: WizardState, ctx: WizardCtx): MessageKey[] {
  const out: MessageKey[] = [];
  switch (step) {
    case 'source': {
      if (w.source.kind === 'github') out.push('wiz.src.issue.github');
      else if (w.source.kind === 'compose')
        out.push(...composeIssues(w.compose, ctx.setSecrets ?? []));
      else if (w.source.kind === 'git')
        out.push(
          ...gitSourceIssues(
            w.git,
            ctx.servers.map((s) => ({ capabilities: [], ...s })),
            ctx.gitAllowlist ?? GIT_HOST_ALLOWLIST,
            { allowUnknownNode: w.mode === 'existing' },
          ),
        );
      else {
        const r = resolveImage(w.source.repo, w.source.ref, w.source.digestRef);
        if (r.kind === 'empty') out.push('wiz.src.issue.image');
        else if (r.kind === 'invalid') out.push(r.reason);
        else if (r.kind === 'tag' && !r.pastedValid) out.push('wiz.src.issue.digest');
      }
      break;
    }
    case 'detect':
      break;
    case 'target': {
      if (w.mode === 'existing') break;
      const s = ctx.servers.find((x) => x.id === w.target.serverId);
      if (!s) out.push('wiz.tgt.issue.server');
      else if (targetBlockReason(s)) out.push('wiz.tgt.issue.offline');
      break;
    }
    case 'configure': {
      if (w.mode === 'existing') break;
      const c = w.config;
      if (!APP_NAME_RE.test(c.name)) out.push('wiz.cfg.issue.name');
      if (w.source.kind === 'compose') break;
      if (!intIn(c.containerPort, 1, 65535)) out.push('wiz.cfg.issue.port');
      if (!/^\/[A-Za-z0-9._~/?=&%-]{0,200}$/.test(c.hcPath)) out.push('wiz.cfg.issue.hcPath');
      if (!intIn(c.hcStatus, 100, 599)) out.push('wiz.cfg.issue.hcStatus');
      if (!intIn(c.hcTimeoutSec, 1, 30) || !intIn(c.hcStartPeriodSec, 1, 600))
        out.push('wiz.cfg.issue.hcTimes');
      if (!intIn(c.memoryMb, 32, 65536) || !(Number(c.cpus) >= 0.1 && Number(c.cpus) <= 64))
        out.push('wiz.cfg.issue.resources');
      const keys = [...c.env.map((e) => e.key), ...c.secrets.map((s) => s.key)].filter(Boolean);
      if (
        c.env.some((e) => !isEnvKey(e.key)) ||
        c.secrets.some((s) => !isEnvKey(s.key)) ||
        new Set(keys).size !== keys.length
      )
        out.push('wiz.cfg.issue.envKeys');
      if (c.secrets.some((s) => !s.staged)) out.push('wiz.cfg.issue.secretValue');
      if (c.volumes.some((v) => volumeError(v))) out.push('wiz.cfg.issue.volumes');
      const r = c.registry;
      if (
        (r.serveraddress || r.username || r.passwordStaged) &&
        !(r.serveraddress && r.username && r.passwordStaged)
      )
        out.push('wiz.cfg.issue.registry');
      break;
    }
    case 'domain': {
      if (w.mode === 'existing') break;
      const ds = w.domain.domains.map((d) => d.trim()).filter(Boolean);
      if (ds.length === 0) out.push('wiz.dom.issue.none');
      if (w.domain.domains.some((d) => d.trim() && hostnameError(d)))
        out.push('wiz.dom.issue.invalid');
      if (new Set(ds).size !== ds.length) out.push('wiz.dom.issue.duplicate');
      if (
        w.domain.tls === 'existing' &&
        (tlsPathError(w.domain.certPath) || tlsPathError(w.domain.keyPath))
      )
        out.push('wiz.dom.issue.tls');
      break;
    }
    case 'review':
    case 'execution':
      break;
  }
  return out;
}

/** Index of the furthest step the user may open (all earlier steps valid). Execution excluded. */
export function maxReachableStep(w: WizardState, ctx: WizardCtx): number {
  const review = WIZARD_STEPS.indexOf('review');
  for (let i = 0; i < review; i++) {
    if (stepIssues(WIZARD_STEPS[i]!, w, ctx).length) return i;
  }
  return review;
}

export function canEnterStep(step: WizardStep, w: WizardState, ctx: WizardCtx): boolean {
  if (step === 'execution') return false;
  return WIZARD_STEPS.indexOf(step) <= maxReachableStep(w, ctx);
}

// ---------------------------------------------------------------- preflight / deploy readiness

export function failingChecks(checks: readonly PreflightCheck[] | null | undefined) {
  return (checks ?? []).filter((c) => !c.ok);
}

/**
 * Deploy button: enabled iff a preflight ran for exactly the current plan, all checks are ok, the user
 * may deploy, and nothing is in flight.
 */
export function deployReady(o: {
  checks: readonly PreflightCheck[] | null | undefined;
  stale: boolean;
  canDeploy: boolean;
  busy: boolean;
}): { ready: boolean; reason: MessageKey | null } {
  if (!o.canDeploy) return { ready: false, reason: 'wiz.rev.block.perm' };
  if (!o.checks || o.checks.length === 0) return { ready: false, reason: 'wiz.rev.block.notRun' };
  if (o.stale) return { ready: false, reason: 'wiz.rev.block.stale' };
  if (failingChecks(o.checks).length) return { ready: false, reason: 'wiz.rev.block.failing' };
  if (o.busy) return { ready: false, reason: 'wiz.rev.block.busy' };
  return { ready: true, reason: null };
}

// ---------------------------------------------------------------- deployment gates

const block = (key: MessageKey): GateResult => ({ allowed: false, reason: { key } });

export function approvalExpiredAt(expiresAt: string | null | undefined, now = Date.now()) {
  return !!expiresAt && Date.parse(expiresAt) < now;
}

/**
 * Approve / cancel button state. Explains the blocker in order (permission → creator → state); when
 * the Center sends `allowedActions` it has the final word.
 */
export function deploymentGate(
  action: 'approve' | 'cancel',
  d: Pick<Deployment, 'status' | 'createdBy' | 'approval' | 'allowedActions'>,
  permissions: readonly string[] | undefined,
  userId: string | undefined,
): GateResult {
  let g: GateResult;
  if (action === 'approve') {
    const p = evaluateGate({ permissions, perm: 'approvals.decide' });
    if (!p.allowed) return p;
    if (!d.approval.required) return block('dep.reason.noApproval');
    if (d.createdBy && d.createdBy === userId) return block('dep.reason.selfApproval');
    g = d.status === 'awaiting_approval' ? { allowed: true } : block('dep.reason.state');
  } else {
    const p = evaluateGate({ permissions, perm: 'apps.deploy' });
    if (!p.allowed) return p;
    g = DEPLOYMENT_CANCELLABLE.includes(d.status)
      ? { allowed: true }
      : block('dep.reason.pastRoute');
  }
  if (g.allowed && d.allowedActions && !d.allowedActions.includes(action))
    return { allowed: false, reason: { key: 'perm.actionNotAllowed', vars: { action } } };
  return g;
}

// ---------------------------------------------------------------- container lifecycle

export const LIFECYCLE_ACTIONS = ['restart', 'redeploy', 'rollback', 'stop', 'start'] as const;
export type LifecycleAction = (typeof LIFECYCLE_ACTIONS)[number];

export interface LifecycleItem {
  action: LifecycleAction;
  /** Exact effect summary shown next to the button (distinct per action). */
  effect: MessageKey;
  /** Extra warning, e.g. rollback never restores data. */
  warning: MessageKey | null;
  gate: GateResult;
  danger: boolean;
  /** Creates a deployment record (and approval in production). */
  createsDeployment: boolean;
}

export function lifecycleActions(
  app: Pick<Application, 'allowedActions' | 'environment' | 'container'>,
  permissions: readonly string[] | undefined,
  activeDeployment: boolean,
): LifecycleItem[] {
  const c = app.container;
  const running = c?.runtimeState !== 'stopped';
  const hasCurrent = !!c?.currentDeploymentId;
  const hasPrevious = c?.rollbackAvailable ?? !!c?.previousDeploymentId;
  const reason = (a: LifecycleAction): { key: MessageKey } | undefined => {
    if (activeDeployment && a !== 'stop') return { key: 'life.block.active' };
    if ((a === 'restart' || a === 'redeploy' || a === 'stop') && !hasCurrent)
      return { key: 'life.block.noCurrent' };
    if (a === 'rollback' && !hasPrevious) return { key: 'life.block.noPrevious' };
    if (a === 'start' && running) return { key: 'life.block.running' };
    if ((a === 'stop' || a === 'restart') && !running) return { key: 'life.block.stopped' };
    return undefined;
  };
  const gate = (a: LifecycleAction) =>
    evaluateGate({
      permissions,
      perm: 'apps.deploy',
      action: a,
      allowedActions: app.allowedActions,
      blockedReason: reason(a),
    });
  return [
    {
      action: 'restart',
      effect: 'life.restart.effect',
      warning: null,
      gate: gate('restart'),
      danger: false,
      createsDeployment: false,
    },
    {
      action: 'redeploy',
      effect: 'life.redeploy.effect',
      warning: null,
      gate: gate('redeploy'),
      danger: false,
      createsDeployment: true,
    },
    {
      action: 'rollback',
      effect: 'life.rollback.effect',
      warning: 'life.rollback.noData',
      gate: gate('rollback'),
      danger: false,
      createsDeployment: true,
    },
    {
      action: 'stop',
      effect: 'life.stop.effect',
      warning: 'life.stop.warning',
      gate: gate('stop'),
      danger: true,
      createsDeployment: false,
    },
    {
      action: 'start',
      effect: 'life.start.effect',
      warning: null,
      gate: gate('start'),
      danger: false,
      createsDeployment: false,
    },
  ];
}
