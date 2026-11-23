/**
 * Pure P4b UI logic (docs/API_CONTRACTS.md §8): Git source validation (40-hex commit, git host allowlist
 * hint, Dockerfile vs template exclusivity, non-secret build args, build node eligibility), compose
 * service table derivation (inferred health, `${SECRET}` placeholders, per-service plan), build log
 * bounds and compose lifecycle actions. The Center enforces all of it; this only decides UI state.
 */
import type { Server } from '@ppanel/shared-contracts';
import type { MessageKey } from '@/i18n/en';
import { evaluateGate, type GateResult } from './permissions';
import type { Application } from './api/p3-types';
import { ENV_KEY_RE, type ComposeValidation } from './api/p4-types';
import {
  BUILD_PHASES,
  COMMIT_SHA_RE,
  GIT_URL_RE,
  IMAGE_REPO_RE,
  type Build,
  type BuildConfigInput,
  type BuildPhase,
  type ComposeHealthView,
  type ComposeServiceAction,
  type ComposeServiceView,
  type DockerfileTemplate,
} from './api/p4b-types';

type BuildNodeServer = Pick<Server, 'id' | 'status' | 'capabilities'> & { buildNode?: boolean };
type ComposeHealth = ComposeHealthView;
/** Plan rows may also show services that the new file drops. */
export type PlanAction = ComposeServiceAction | 'removed';

/** Strip timing fields: `http :port path` · `tcp :port` · `running`. */
export function healthView(
  h: { type: string; port?: number; path?: string } | null | undefined,
): ComposeHealthView {
  if (h?.type === 'http') return { type: 'http', port: h.port ?? 0, path: h.path ?? '/' };
  if (h?.type === 'tcp') return { type: 'tcp', port: h.port ?? 0 };
  return { type: 'running' };
}
import type { LifecycleItem } from './p4-gates';

// ---------------------------------------------------------------- Git source

export interface KeyValueRow {
  id: string;
  key: string;
  value: string;
}

export interface GitSourceState {
  repoUrl: string;
  branch: string;
  commitSha: string;
  subdir: string;
  method: 'dockerfile' | 'template';
  dockerfile: string;
  template: DockerfileTemplate | '';
  buildArgs: KeyValueRow[];
  target: string;
  buildServerId: string;
  pushRepo: string;
  network: 'default' | 'none';
  memoryMb: string;
  cpus: string;
  timeoutSec: string;
  /** A token was typed and is held outside React state until the app exists. */
  tokenStaged: boolean;
}

export function initialGitSource(): GitSourceState {
  return {
    repoUrl: '',
    branch: 'main',
    commitSha: '',
    subdir: '',
    method: 'template',
    dockerfile: 'Dockerfile',
    template: '',
    buildArgs: [],
    target: '',
    buildServerId: '',
    pushRepo: '',
    network: 'default',
    memoryMb: '2048',
    cpus: '2',
    timeoutSec: '900',
    tokenStaged: false,
  };
}

export type HostAllow = 'allowed' | 'not_listed' | 'unknown';

/** Repo URL → error (blocking) + host + allowlist hint (non-blocking; the Center has the real list). */
export function gitUrlCheck(
  url: string,
  allowlist: readonly string[],
): { error: MessageKey | null; host: string | null; allow: HostAllow } {
  const v = url.trim();
  if (!v) return { error: 'wiz.git.err.urlEmpty', host: null, allow: 'unknown' };
  const m = /^([a-z]+):\/\/([^/]*)(\/.*)?$/i.exec(v);
  if (!m) return { error: 'wiz.git.err.url', host: null, allow: 'unknown' };
  const [, scheme, authority] = m;
  if (authority!.includes('@'))
    return { error: 'wiz.git.err.credentials', host: null, allow: 'unknown' };
  if (scheme!.toLowerCase() !== 'https' && scheme!.toLowerCase() !== 'git')
    return { error: 'wiz.git.err.scheme', host: null, allow: 'unknown' };
  if (!GIT_URL_RE.test(v)) return { error: 'wiz.git.err.url', host: null, allow: 'unknown' };
  const host = authority!.split(':')[0]!.toLowerCase();
  const allow: HostAllow = !allowlist.length
    ? 'unknown'
    : allowlist.includes(host)
      ? 'allowed'
      : 'not_listed';
  return { error: null, host, allow };
}

/** A build needs the full 40-hex commit (the branch is only context). */
export function commitShaError(sha: string): MessageKey | null {
  const v = sha.trim();
  if (!v) return 'wiz.git.err.shaEmpty';
  if (COMMIT_SHA_RE.test(v)) return null;
  if (/^[a-f0-9]{7,39}$/i.test(v)) return 'wiz.git.err.shaShort';
  if (/^[A-F0-9]{40}$/i.test(v)) return 'wiz.git.err.shaCase';
  return 'wiz.git.err.sha';
}

export function branchError(b: string): MessageKey | null {
  const v = b.trim();
  if (!v) return null;
  if (!/^[A-Za-z0-9._/-]{1,255}$/.test(v) || v.includes('..') || v.startsWith('/'))
    return 'wiz.git.err.branch';
  return null;
}

const relPath = (p: string) =>
  /^[A-Za-z0-9._/-]{0,200}$/.test(p) && !p.split('/').includes('..') && !p.startsWith('/');

export function subdirError(p: string): MessageKey | null {
  return relPath(p.trim()) ? null : 'wiz.git.err.subdir';
}

export function dockerfileError(p: string): MessageKey | null {
  const v = p.trim();
  if (!v) return 'wiz.git.err.dockerfileEmpty';
  return relPath(v) ? null : 'wiz.git.err.dockerfile';
}

export function pushRepoError(r: string): MessageKey | null {
  const v = r.trim();
  if (!v) return 'wiz.git.err.pushEmpty';
  if (v.includes('@') || /:[^/]*$/.test(v.slice(v.lastIndexOf('/')))) return 'wiz.git.err.pushTag';
  return IMAGE_REPO_RE.test(v) ? null : 'wiz.git.err.push';
}

/** Names that look like credentials: secret build args are not supported (they leak into layers). */
export const SECRET_LIKE_RE =
  /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|CREDENTIAL)/i;

export function buildArgIssues(rows: readonly KeyValueRow[]): MessageKey[] {
  const out = new Set<MessageKey>();
  const keys = rows.map((r) => r.key.trim()).filter(Boolean);
  if (rows.some((r) => !ENV_KEY_RE.test(r.key.trim()))) out.add('wiz.git.issue.argKey');
  if (new Set(keys).size !== keys.length) out.add('wiz.git.issue.argDup');
  if (rows.some((r) => r.value.length > 1024)) out.add('wiz.git.issue.argLong');
  if (keys.some((k) => SECRET_LIKE_RE.test(k))) out.add('wiz.git.issue.secretArg');
  return [...out];
}

/** Exactly one of Dockerfile path / built-in template (mirrors the shared `imageBuildParams` refine). */
export function buildSpecError(spec: {
  dockerfile?: string | null;
  template?: string | null;
}): MessageKey | null {
  const hasD = !!spec.dockerfile?.trim();
  const hasT = !!spec.template;
  if (hasD && hasT) return 'wiz.git.issue.exclusive';
  if (!hasD && !hasT) return 'wiz.git.issue.method';
  return null;
}

/** Why a server cannot run builds (null = eligible build node). */
export function buildNodeBlockReason(
  s: Pick<BuildNodeServer, 'status' | 'capabilities' | 'buildNode'>,
): MessageKey | null {
  if (!(s.capabilities ?? []).includes('build')) return 'wiz.git.node.noCapability';
  if (!s.buildNode) return 'wiz.git.node.notDesignated';
  if (s.status !== 'online' && s.status !== 'degraded') return 'wiz.git.node.offline';
  return null;
}

const intIn = (s: string, min: number, max: number) =>
  /^\d+$/.test(s.trim()) && Number(s) >= min && Number(s) <= max;

export function limitsError(g: Pick<GitSourceState, 'memoryMb' | 'cpus' | 'timeoutSec'>) {
  const cpus = Number(g.cpus);
  if (
    !intIn(g.memoryMb, 256, 32768) ||
    !(cpus >= 0.5 && cpus <= 32) ||
    !intIn(g.timeoutSec, 60, 3600)
  )
    return 'wiz.git.issue.limits' as const;
  return null;
}

/** Git source → exactly-one-of build config (template wins only when chosen). */
export function toBuildConfig(g: GitSourceState): BuildConfigInput {
  const args = Object.fromEntries(
    g.buildArgs.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value]),
  );
  return {
    repoUrl: g.repoUrl.trim(),
    subdir: g.subdir.trim() || undefined,
    ...(g.method === 'dockerfile'
      ? { dockerfile: g.dockerfile.trim() }
      : { template: (g.template || undefined) as DockerfileTemplate | undefined }),
    buildArgs: Object.keys(args).length ? args : undefined,
    target: g.target.trim() || undefined,
    buildServerId: g.buildServerId,
    pushRepo: g.pushRepo.trim(),
    network: g.network,
    limits: {
      memoryMb: Number(g.memoryMb),
      cpus: Number(g.cpus),
      timeoutSec: Number(g.timeoutSec),
    },
  };
}

/** Blocking issues of the Git source step. `existing` = deploy a new commit of a configured app. */
export function gitSourceIssues(
  g: GitSourceState,
  servers: ReadonlyArray<Pick<BuildNodeServer, 'id' | 'status' | 'capabilities' | 'buildNode'>>,
  allowlist: readonly string[],
  /** Existing config: the stored build node may be outside the user's server scope (Center checks). */
  opts: { allowUnknownNode?: boolean } = {},
): MessageKey[] {
  const out: MessageKey[] = [];
  const url = gitUrlCheck(g.repoUrl, allowlist);
  if (url.error) out.push(url.error);
  const sha = commitShaError(g.commitSha);
  if (sha) out.push(sha === 'wiz.git.err.shaEmpty' ? 'wiz.git.issue.sha' : sha);
  const br = branchError(g.branch);
  if (br) out.push(br);
  const sd = subdirError(g.subdir);
  if (sd) out.push(sd);
  const spec = buildSpecError(
    g.method === 'dockerfile' ? { dockerfile: g.dockerfile } : { template: g.template },
  );
  if (spec) out.push(spec);
  if (g.method === 'dockerfile') {
    const d = dockerfileError(g.dockerfile);
    if (d && !spec) out.push(d);
  }
  out.push(...buildArgIssues(g.buildArgs));
  if (g.target.trim() && !/^[A-Za-z0-9._-]{1,64}$/.test(g.target.trim()))
    out.push('wiz.git.issue.target');
  const node = servers.find((s) => s.id === g.buildServerId);
  if (!node) {
    if (!(opts.allowUnknownNode && g.buildServerId)) out.push('wiz.git.issue.node');
  } else if (buildNodeBlockReason(node)) out.push('wiz.git.issue.nodeBlocked');
  const pr = pushRepoError(g.pushRepo);
  if (pr) out.push(pr);
  const lim = limitsError(g);
  if (lim) out.push(lim);
  return out;
}

// ---------------------------------------------------------------- Compose: scan + derive

export interface ScannedService {
  name: string;
  image: string | null;
  /** `${NAME}` placeholders anywhere in the service block (secret references). */
  placeholders: string[];
  envKeys: string[];
  volumes: Array<{ name: string; mountPath: string }>;
  dependsOn: string[];
  ports: string[];
  build: boolean;
}

const PLACEHOLDER_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?:[:?-][^}]*)?\}/g;
const indentOf = (l: string) => l.length - l.trimStart().length;
const unq = (v: string) => v.trim().replace(/^["']|["']$/g, '');

/**
 * Small indentation-aware scan of a compose file (the Center parses YAML for real). Extracts what
 * the service table needs: image, placeholders, env keys, named volumes, depends_on and ports.
 */
export function scanComposeServices(yaml: string): ScannedService[] {
  const out: ScannedService[] = [];
  let inServices = false;
  let svcIndent = -1;
  let keyIndent = -1;
  let key = '';
  let cur: ScannedService | null = null;
  for (const raw of yaml.split('\n')) {
    const line = raw.replace(/\s+#.*$/, '').replace(/^\s*#.*$/, '');
    if (!line.trim()) continue;
    const ind = indentOf(line);
    const t = line.trim();
    if (ind === 0) {
      inServices = /^services\s*:/.test(t);
      cur = null;
      svcIndent = -1;
      continue;
    }
    if (!inServices) continue;
    if (svcIndent < 0 || ind <= svcIndent) {
      svcIndent = ind;
      cur = {
        name: t.replace(/:.*$/, '').trim(),
        image: null,
        placeholders: [],
        envKeys: [],
        volumes: [],
        dependsOn: [],
        ports: [],
        build: false,
      };
      out.push(cur);
      key = '';
      keyIndent = -1;
      continue;
    }
    if (!cur) continue;
    for (const m of t.matchAll(PLACEHOLDER_RE))
      if (!cur.placeholders.includes(m[1]!)) cur.placeholders.push(m[1]!);
    const km = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/.exec(t);
    if (km && (keyIndent < 0 || ind <= keyIndent)) {
      key = km[1]!;
      keyIndent = ind;
      const v = unq(km[2] ?? '');
      if (key === 'image') cur.image = v || null;
      if (key === 'build') cur.build = true;
      if (key === 'depends_on' && v.startsWith('['))
        cur.dependsOn.push(...v.replace(/[[\]]/g, '').split(',').map(unq).filter(Boolean));
      continue;
    }
    // nested under `key`
    const item = t.replace(/^-\s*/, '');
    if (key === 'environment') {
      const k = /^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]/.exec(item)?.[1];
      if (k && !cur.envKeys.includes(k)) cur.envKeys.push(k);
    } else if (key === 'volumes') {
      const [src, dst] = unq(item).split(':');
      if (src && dst && /^[a-z0-9][a-z0-9_-]*$/.test(src))
        cur.volumes.push({ name: src, mountPath: dst });
    } else if (key === 'depends_on') {
      const d = unq(item.replace(/:.*$/, ''));
      if (d && t.startsWith('-')) cur.dependsOn.push(d);
      else if (d && ind > keyIndent && !/^condition$/.test(d) && /:\s*$/.test(item))
        cur.dependsOn.push(d);
    } else if (key === 'ports') {
      cur.ports.push(unq(item));
    }
  }
  return out;
}

const DB_PORTS: Array<[string, number]> = [
  ['postgres', 5432],
  ['mysql', 3306],
  ['mariadb', 3306],
  ['redis', 6379],
];

function imageBase(image: string | null): string {
  if (!image) return '';
  const noDigest = image.split('@')[0]!;
  const last = noDigest.slice(noDigest.lastIndexOf('/') + 1);
  return last.split(':')[0]!.toLowerCase();
}

/** Center inference (§8.3): route → http on routePort + healthPath; known DB → tcp; else running. */
export function inferHealth(
  svc: Pick<ScannedService, 'name' | 'image'>,
  route: { service: string; port: number; healthPath: string },
): ComposeHealth {
  if (svc.name === route.service)
    return { type: 'http', port: route.port, path: route.healthPath || '/' };
  const base = imageBase(svc.image);
  const db = DB_PORTS.find(([n]) => base === n || base.startsWith(n));
  if (db) return { type: 'tcp', port: db[1] };
  return { type: 'running' };
}

export type PlaceholderStatus = 'set' | 'staged' | 'missing';

export interface ComposeServiceRow {
  service: string;
  image: string | null;
  pinned: boolean;
  isRoute: boolean;
  health: ComposeHealth;
  placeholders: Array<{ key: string; status: PlaceholderStatus }>;
  volumes: Array<{ name: string; mountPath: string }>;
  dependsOn: string[];
  /** Ports declared on a non-route service (the Center rejects them). */
  portsNotAllowed: boolean;
  build: boolean;
}

export function deriveComposeServices(o: {
  yaml: string;
  routeService: string;
  routePort: number;
  healthPath: string;
  secretStatus: (key: string) => PlaceholderStatus;
}): ComposeServiceRow[] {
  return scanComposeServices(o.yaml).map((s) => ({
    service: s.name,
    image: s.image,
    pinned: !!s.image && /@sha256:[a-f0-9]{64}$/.test(s.image),
    isRoute: s.name === o.routeService,
    health: inferHealth(s, {
      service: o.routeService,
      port: o.routePort,
      healthPath: o.healthPath,
    }),
    placeholders: s.placeholders.map((key) => ({ key, status: o.secretStatus(key) })),
    volumes: s.volumes,
    dependsOn: s.dependsOn,
    portsNotAllowed: s.name !== o.routeService && s.ports.length > 0,
    build: s.build,
  }));
}

/** All `${NAME}` placeholders of a file (distinct, in order). */
export function composeSecretKeys(rows: readonly Pick<ComposeServiceRow, 'placeholders'>[]) {
  return [...new Set(rows.flatMap((r) => r.placeholders.map((p) => p.key)))];
}

/** depends_on cycle (the Center rejects cycles). */
export function hasDependencyCycle(
  rows: readonly Pick<ComposeServiceRow, 'service' | 'dependsOn'>[],
) {
  const deps = new Map(rows.map((r) => [r.service, r.dependsOn]));
  const state = new Map<string, 1 | 2>();
  const visit = (n: string): boolean => {
    if (state.get(n) === 1) return true;
    if (state.get(n) === 2) return false;
    state.set(n, 1);
    for (const d of deps.get(n) ?? []) if (deps.has(d) && visit(d)) return true;
    state.set(n, 2);
    return false;
  };
  return rows.some((r) => visit(r.service));
}

export interface ComposeState {
  yaml: string;
  routeService: string;
  routePort: string;
  healthPath: string;
  /** Validation result for exactly `validatedYaml` (null = not validated yet). */
  validation: ComposeValidation | null;
  validatedYaml: string;
  /** Placeholder secrets whose value was typed and is staged outside React state. */
  staged: string[];
}

export function initialCompose(): ComposeState {
  return {
    yaml: '',
    routeService: '',
    routePort: '8000',
    healthPath: '/',
    validation: null,
    validatedYaml: '',
    staged: [],
  };
}

export const HEALTH_PATH_RE = /^\/[A-Za-z0-9._~/?=&%-]{0,200}$/;

export function composeIssues(c: ComposeState, setSecrets: readonly string[]): MessageKey[] {
  const out: MessageKey[] = [];
  if (!c.yaml.trim()) return ['wiz.cmp.issue.yaml'];
  if (!c.validation || c.validatedYaml !== c.yaml) out.push('wiz.cmp.issue.validating');
  else if (!c.validation.valid) out.push('wiz.cmp.issue.invalid');
  const port = Number(c.routePort);
  const rows = deriveComposeServices({
    yaml: c.yaml,
    routeService: c.routeService,
    routePort: port,
    healthPath: c.healthPath,
    secretStatus: (k) =>
      setSecrets.includes(k) ? 'set' : c.staged.includes(k) ? 'staged' : 'missing',
  });
  if (!rows.length) out.push('wiz.cmp.issue.noServices');
  if (!rows.some((r) => r.service === c.routeService)) out.push('wiz.cmp.issue.route');
  if (!intIn(c.routePort, 1, 65535)) out.push('wiz.cmp.issue.port');
  if (!HEALTH_PATH_RE.test(c.healthPath)) out.push('wiz.cmp.issue.health');
  if (rows.some((r) => r.portsNotAllowed)) out.push('wiz.cmp.issue.ports');
  if (hasDependencyCycle(rows)) out.push('wiz.cmp.issue.cycle');
  if (rows.some((r) => r.placeholders.some((p) => p.status === 'missing')))
    out.push('wiz.cmp.issue.secrets');
  return out;
}

export interface ComposePlanRow {
  service: string;
  action: PlanAction;
  image: string | null;
  previousImage: string | null;
  isRoute: boolean;
}

const specKey = (s: {
  image: string | null;
  health: ComposeHealth;
  secrets: string[];
  volumes: Array<{ name: string; mountPath: string }>;
  dependsOn: string[];
}) =>
  JSON.stringify([
    s.image,
    s.health,
    [...s.secrets].sort(),
    s.volumes.map((v) => `${v.name}:${v.mountPath}`).sort(),
    [...s.dependsOn].sort(),
  ]);

/**
 * Expected per-service actions (Review). The Center decides from spec hashes after resolving tags;
 * this compares image + health + secret refs + volumes + depends_on with the current version.
 */
export function composePlan(
  current: readonly ComposeServiceView[] | null | undefined,
  rows: readonly ComposeServiceRow[],
): ComposePlanRow[] {
  const prev = new Map((current ?? []).map((s) => [s.service, s]));
  const out: ComposePlanRow[] = rows.map((r) => {
    const p = prev.get(r.service);
    if (!p)
      return {
        service: r.service,
        action: 'created',
        image: r.image,
        previousImage: null,
        isRoute: r.isRoute,
      };
    const same =
      specKey({
        image: p.image,
        health: healthView(p.health),
        secrets: Object.values(p.secretEnv ?? {}),
        volumes: p.volumes ?? [],
        dependsOn: p.dependsOn ?? [],
      }) ===
      specKey({
        image: r.image,
        health: healthView(r.health),
        secrets: r.placeholders.map((x) => x.key),
        volumes: r.volumes,
        dependsOn: r.dependsOn,
      });
    return {
      service: r.service,
      action: same ? 'unchanged' : 'replaced',
      image: r.image,
      previousImage: p.image,
      isRoute: r.isRoute,
    };
  });
  for (const p of current ?? [])
    if (!rows.some((r) => r.service === p.service))
      out.push({
        service: p.service,
        action: 'removed',
        image: null,
        previousImage: p.image,
        isRoute: false,
      });
  return out;
}

// ---------------------------------------------------------------- build log + phases

export const BUILD_LOG_MAX_LINES = 2000;
export const BUILD_LOG_MAX_LINE_CHARS = 4000;

/**
 * Keep the last `max` lines (bounded viewer) and clip very long lines. Returns how many lines were
 * dropped from the top so the viewer can say so.
 */
export function boundLog(
  lines: readonly string[] | null | undefined,
  max = BUILD_LOG_MAX_LINES,
  maxChars = BUILD_LOG_MAX_LINE_CHARS,
): { lines: string[]; dropped: number; clipped: number } {
  const all = lines ?? [];
  const keep = Math.max(0, Math.floor(max));
  const start = Math.max(0, all.length - keep);
  let clipped = 0;
  const out = all.slice(start).map((l) => {
    if (l.length <= maxChars) return l;
    clipped += 1;
    return `${l.slice(0, maxChars)} …`;
  });
  return { lines: out, dropped: start, clipped };
}

export type PhaseState = 'done' | 'current' | 'pending' | 'failed' | 'skipped';

/** Failures before the node picked the job up stay on `queued`; everything else is `building`. */
const FAIL_PHASE: Record<string, BuildPhase> = {
  NO_BUILD_NODE: 'queued',
  AGENT_OFFLINE: 'queued',
};

/** State of each phase pill for a build (failed phase from the error code, else the last reached). */
export function buildPhaseStates(
  b: Pick<Build, 'status' | 'error'> & { failedPhase?: BuildPhase | null },
): Record<BuildPhase, PhaseState> {
  const res = {} as Record<BuildPhase, PhaseState>;
  const live = b.status === 'fetching' || b.status === 'pushing' ? 'building' : b.status;
  const idx = BUILD_PHASES.indexOf(live as BuildPhase);
  if (idx >= 0) {
    BUILD_PHASES.forEach((p, i) => (res[p] = i < idx ? 'done' : i === idx ? 'current' : 'pending'));
    return res;
  }
  if (b.status === 'succeeded') {
    BUILD_PHASES.forEach((p) => (res[p] = 'done'));
    return res;
  }
  const failed: BuildPhase =
    b.failedPhase ?? (b.error?.code ? FAIL_PHASE[b.error.code] : undefined) ?? 'building';
  const fi = BUILD_PHASES.indexOf(failed);
  BUILD_PHASES.forEach(
    (p, i) =>
      (res[p] =
        i < fi ? 'done' : i === fi ? (b.status === 'failed' ? 'failed' : 'skipped') : 'skipped'),
  );
  return res;
}

// ---------------------------------------------------------------- app helpers + gates

/** Runtime fields of a deployable app (container or compose). */
export function runtimeOf(app: Pick<Application, 'container' | 'compose'>) {
  const r = app.compose ?? app.container ?? null;
  return {
    currentDeploymentId: r?.currentDeploymentId ?? null,
    previousDeploymentId: r?.previousDeploymentId ?? null,
    rollbackAvailable: r?.rollbackAvailable ?? !!r?.previousDeploymentId,
    runtimeState: (r?.runtimeState ?? 'unknown') as 'running' | 'stopped' | 'unknown',
    secretKeys: r?.secretKeys ?? [],
  };
}

export const isDeployable = (app: Pick<Application, 'kind'>) =>
  app.kind === 'container' || app.kind === 'compose';

/** Build button: perm apps.deploy + allowedActions `build` + a stored build config. */
export function buildGate(
  app: Pick<Application, 'allowedActions'> & { build?: Application['build'] | { config: unknown } },
  permissions: readonly string[] | undefined,
): GateResult {
  return evaluateGate({
    permissions,
    perm: 'apps.deploy',
    action: 'build',
    allowedActions: app.allowedActions,
    blockedReason: app.build?.config ? undefined : { key: 'builds.block.noConfig' },
  });
}

/** Compose lifecycle: redeploy / rollback (never restores data) / stop / start. */
export function composeLifecycleActions(
  app: Pick<Application, 'allowedActions' | 'compose'>,
  permissions: readonly string[] | undefined,
  activeDeployment: boolean,
): LifecycleItem[] {
  const c = app.compose;
  const running = c?.runtimeState !== 'stopped';
  const hasCurrent = !!c?.currentDeploymentId;
  const hasPrevious = c?.rollbackAvailable ?? !!c?.previousDeploymentId;
  const reason = (a: string): { key: MessageKey } | undefined => {
    if (activeDeployment && a !== 'stop') return { key: 'life.block.active' };
    if ((a === 'redeploy' || a === 'stop') && !hasCurrent) return { key: 'life.block.noCurrent' };
    if (a === 'rollback' && !hasPrevious) return { key: 'life.cmp.block.noPrevious' };
    if (a === 'start' && (running || !hasCurrent))
      return { key: hasCurrent ? 'life.cmp.block.running' : 'life.block.noCurrent' };
    if (a === 'stop' && !running) return { key: 'life.cmp.block.stopped' };
    return undefined;
  };
  const gate = (a: string) =>
    evaluateGate({
      permissions,
      perm: 'apps.deploy',
      action: a,
      allowedActions: app.allowedActions,
      blockedReason: reason(a),
    });
  return [
    {
      action: 'redeploy',
      effect: 'life.cmp.redeploy.effect',
      warning: 'life.cmp.restartRisk',
      gate: gate('redeploy'),
      danger: false,
      createsDeployment: true,
    },
    {
      action: 'rollback',
      effect: 'life.cmp.rollback.effect',
      warning: 'life.cmp.rollback.noData',
      gate: gate('rollback'),
      danger: false,
      createsDeployment: true,
    },
    {
      action: 'stop',
      effect: 'life.cmp.stop.effect',
      warning: 'life.stop.warning',
      gate: gate('stop'),
      danger: true,
      createsDeployment: false,
    },
    {
      action: 'start',
      effect: 'life.cmp.start.effect',
      warning: null,
      gate: gate('start'),
      danger: false,
      createsDeployment: false,
    },
  ];
}

/** Build node toggle (server Settings): perm policies.manage; enabling needs the `build` capability. */
export function buildNodeToggleGate(
  s: Pick<Server, 'capabilities'> & { buildNode?: boolean },
  permissions: readonly string[] | undefined,
): GateResult {
  return evaluateGate({
    permissions,
    perm: 'policies.manage',
    blockedReason:
      !s.buildNode && !(s.capabilities ?? []).includes('build')
        ? { key: 'bn.block.noCapability' }
        : undefined,
  });
}
