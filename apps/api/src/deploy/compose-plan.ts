/**
 * P4b Compose normalisation (§8.3). Pure: validated YAML document → ordered, normalised services the
 * agent can execute without parsing YAML. The static deny policy (§7.6) runs first; execution rules
 * (named volumes only, ports only on the route service, no host env pass-through, `${SECRET}` → secretEnv,
 * dependency cycles, inferred health) are added here.
 */
import {
  APP_SLUG_RE,
  COMPOSE_SERVICE_NAME_RE,
  type ComposeHealth,
  type ComposePlanService,
  type ComposeValidation,
  type ComposeViolation,
  containerHealthcheckSchema,
  containerResourcesSchema,
  ENV_KEY_RE,
  isDigestPinned,
  RESERVED_SECRET_KEYS,
  validateComposeDocument,
} from '@ppanel/shared-contracts';
import { sha256Hex, stableStringify } from '../common/crypto';
import { parseTaggedRef } from './registry.client';

export const MAX_COMPOSE_SERVICES = 20;
const VOLUME_NAME_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const MOUNT_PATH_RE = /^\/[A-Za-z0-9._/-]{1,200}$/;
const SECRET_PLACEHOLDER_RE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;

/** Keys the executor understands. */
const SUPPORTED_KEYS = new Set([
  'image',
  'environment',
  'command',
  'volumes',
  'ports',
  'depends_on',
]);
/** Accepted but ignored (pPanel manages these itself) → warning. */
const IGNORED_KEYS = new Set([
  'restart',
  'container_name',
  'networks',
  'labels',
  'expose',
  'healthcheck',
  'stop_grace_period',
  'logging',
  'hostname',
  'init',
  'tty',
  'stdin_open',
]);

/** Known database images → TCP health on their default port. */
const DB_PORTS: Array<[RegExp, number]> = [
  [/^(?:.*\/)?postgres(?:ql)?$/, 5432],
  [/^(?:.*\/)?mysql$/, 3306],
  [/^(?:.*\/)?mariadb$/, 3306],
  [/^(?:.*\/)?redis$/, 6379],
];

function isMap(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Repository path of an image ref without registry host, tag or digest (`postgres`, `bitnami/redis`). */
export function imageRepoName(image: string): string {
  let s = image.split('@')[0]!;
  const lastSlash = s.lastIndexOf('/');
  const colon = s.lastIndexOf(':');
  if (colon > lastSlash) s = s.slice(0, colon);
  const parts = s.split('/');
  if (parts.length > 1 && /[.:]/.test(parts[0]!)) parts.shift(); // registry host
  if (parts[0] === 'library') parts.shift();
  return parts.join('/');
}

export function inferHealth(
  service: string,
  image: string,
  route: { service: string; port: number; path: string },
): ComposeHealth {
  if (service === route.service) {
    const d = containerHealthcheckSchema.parse({ path: route.path });
    return { type: 'http', port: route.port, ...d };
  }
  const repo = imageRepoName(image);
  for (const [re, port] of DB_PORTS)
    if (re.test(repo)) return { type: 'tcp', port, startPeriodSec: 60 };
  return { type: 'running', startPeriodSec: 10 };
}

export interface NormalizeOptions {
  app: string;
  routeService: string;
  routePort: number;
  healthPath?: string;
  /** existing app secret keys; when given, missing placeholders are violations (`secret_missing`) */
  existingSecrets?: Set<string>;
}

export interface NormalizedCompose {
  validation: ComposeValidation;
  /** services in dependency order (empty when invalid) */
  services: ComposePlanService[];
  /** secret keys referenced by `${VAR}` placeholders (sorted) */
  secretKeys: string[];
}

/** `$$` escapes `$`; any other `$` interpolation is unsupported (no host env pass-through). */
function literal(v: string): string | null {
  const unescaped = v.replace(/\$\$/g, '');
  if (unescaped.includes('$')) return null;
  return v.replace(/\$\$/g, '$');
}

export function normalizeComposeDocument(doc: unknown, opts: NormalizeOptions): NormalizedCompose {
  const base = validateComposeDocument(doc);
  const violations: ComposeViolation[] = [...base.violations];
  const warnings: ComposeViolation[] = [];
  const add = (
    service: string | null,
    rule: ComposeViolation['rule'],
    path: string,
    message: string,
    warn = false,
  ) => (warn ? warnings : violations).push({ service, rule, path, message });
  // execution: builds are not possible inside a compose app → violation; tag refs are resolved at deploy
  for (const w of base.warnings) {
    if (w.rule === 'build_unsupported')
      violations.push({ ...w, message: 'Compose `build:` is not supported; use a registry image' });
    else if (w.rule === 'image_not_pinned')
      warnings.push({ ...w, message: `${w.message}; it is resolved to a digest at deploy time` });
    else warnings.push(w);
  }
  const fail = (): NormalizedCompose => ({
    validation: { ...base, valid: false, violations, warnings },
    services: [],
    secretKeys: [],
  });
  if (!isMap(doc) || !isMap(doc.services) || Object.keys(doc.services).length === 0) {
    if (isMap(doc) && !isMap(doc.services))
      add(null, 'not_a_mapping', 'services', 'At least one service is required');
    return fail();
  }
  const raw = doc.services;
  const names = Object.keys(raw);
  if (names.length > MAX_COMPOSE_SERVICES)
    add(null, 'too_many_services', 'services', `At most ${MAX_COMPOSE_SERVICES} services`);
  if (!names.includes(opts.routeService))
    add(
      null,
      'route_service_missing',
      'routeService',
      `routeService \`${opts.routeService}\` is not a service of this file`,
    );
  if (doc.networks !== undefined)
    add(null, 'key_ignored', 'networks', 'Custom networks are ignored (one app network)', true);

  const healthPath = opts.healthPath ?? '/';
  const services: ComposePlanService[] = [];
  const secretKeys = new Set<string>();
  for (const name of names) {
    const p = `services.${name}`;
    const svc = raw[name];
    if (!isMap(svc)) continue; // reported by the static policy
    if (!COMPOSE_SERVICE_NAME_RE.test(name))
      add(name, 'service_name_invalid', p, 'Service names must match ^[a-z0-9][a-z0-9-]{0,30}$');
    else if (!APP_SLUG_RE.test(`${opts.app}-${name}`))
      add(name, 'name_too_long', p, 'Application name + service name must be ≤ 41 characters');
    for (const key of Object.keys(svc)) {
      if (SUPPORTED_KEYS.has(key) || key === 'build') continue;
      if (IGNORED_KEYS.has(key))
        add(
          name,
          'key_ignored',
          `${p}.${key}`,
          `\`${key}\` is managed by pPanel and ignored`,
          true,
        );
      else add(name, 'service_key_unsupported', `${p}.${key}`, `\`${key}\` is not supported`);
    }

    // image
    const image = typeof svc.image === 'string' ? svc.image.trim() : '';
    if (!image) {
      if (svc.build === undefined)
        add(name, 'image_required', `${p}.image`, 'Every service needs an image');
    } else if (image.includes('$'))
      add(
        name,
        'env_interpolation',
        `${p}.image`,
        'Variable interpolation in images is not supported',
      );
    else if (!isDigestPinned(image) && !parseTaggedRef(image))
      add(
        name,
        'image_unresolvable',
        `${p}.image`,
        'Image must be pinned by digest or be registry-host/repo:tag (resolvable to a digest)',
      );

    // environment → env / secretEnv
    const env: Record<string, string> = {};
    const secretEnv: Record<string, string> = {};
    const entries: Array<[string, unknown]> = [];
    if (Array.isArray(svc.environment))
      for (const item of svc.environment) {
        const s = String(item);
        const i = s.indexOf('=');
        entries.push(i < 0 ? [s, null] : [s.slice(0, i), s.slice(i + 1)]);
      }
    else if (isMap(svc.environment)) entries.push(...Object.entries(svc.environment));
    else if (svc.environment !== undefined)
      add(name, 'not_a_mapping', `${p}.environment`, '`environment` must be a mapping or a list');
    for (const [k, v] of entries) {
      const ep = `${p}.environment.${k}`;
      if (!ENV_KEY_RE.test(k)) {
        add(name, 'env_key_invalid', ep, 'Environment keys must match ^[A-Z_][A-Z0-9_]{0,63}$');
        continue;
      }
      if (v === null || v === undefined) {
        add(name, 'env_interpolation', ep, 'Host environment pass-through is not supported');
        continue;
      }
      if (isMap(v) || Array.isArray(v)) {
        add(name, 'not_a_mapping', ep, 'Environment values must be scalars');
        continue;
      }
      const sv = String(v);
      const ph = SECRET_PLACEHOLDER_RE.exec(sv);
      if (ph) {
        const key = ph[1]!;
        if (!ENV_KEY_RE.test(key) || (RESERVED_SECRET_KEYS as readonly string[]).includes(key))
          add(name, 'env_key_invalid', ep, `\`${key}\` is not a valid application secret key`);
        else {
          secretEnv[k] = key;
          secretKeys.add(key);
          if (opts.existingSecrets && !opts.existingSecrets.has(key))
            add(name, 'secret_missing', ep, `Application secret \`${key}\` is not set`);
        }
        continue;
      }
      const lit = literal(sv);
      if (lit === null)
        add(
          name,
          'env_interpolation',
          ep,
          'Only whole-value `${SECRET}` placeholders are supported (use $$ for a literal $)',
        );
      else if (lit.length > 4096) add(name, 'not_a_mapping', ep, 'Value longer than 4096 chars');
      else env[k] = lit;
    }

    // command (array, or a simple whitespace-separated string without quotes)
    let command: string[] | undefined;
    if (Array.isArray(svc.command)) command = svc.command.map((c) => String(c));
    else if (typeof svc.command === 'string') {
      if (/["'\\]/.test(svc.command))
        add(name, 'command_unsupported', `${p}.command`, 'Use the list form for quoted commands');
      else command = svc.command.trim().split(/\s+/).filter(Boolean);
    } else if (svc.command !== undefined)
      add(name, 'command_unsupported', `${p}.command`, '`command` must be a list or a string');
    if (command) {
      if (command.length > 64 || command.some((c) => c.length > 1024))
        add(name, 'command_unsupported', `${p}.command`, 'Command too long');
      else if (command.some((c) => literal(c) === null))
        add(name, 'env_interpolation', `${p}.command`, 'Variable interpolation is not supported');
      else command = command.map((c) => literal(c)!);
    }

    // volumes: named only
    const volumes: Array<{ name: string; mountPath: string }> = [];
    if (Array.isArray(svc.volumes))
      svc.volumes.forEach((v, i) => {
        const vp = `${p}.volumes[${i}]`;
        let src: string | undefined;
        let target: string | undefined;
        if (typeof v === 'string') {
          const parts = v.split(':');
          if (parts.length >= 2 && parts.length <= 3) [src, target] = parts;
          if (parts.length === 3 && parts[2] !== 'rw')
            add(name, 'key_ignored', vp, `Volume mode \`${parts[2]}\` is ignored`, true);
        } else if (isMap(v) && (v.type === undefined || v.type === 'volume')) {
          src = typeof v.source === 'string' ? v.source : undefined;
          target = typeof v.target === 'string' ? v.target : undefined;
        }
        if (!src || !target) {
          if (!violations.some((x) => x.path === vp))
            add(name, 'volume_unsupported', vp, 'Only named volumes (`name:/path`) are supported');
          return;
        }
        if (!VOLUME_NAME_RE.test(src) || !MOUNT_PATH_RE.test(target) || target.includes('..')) {
          if (!violations.some((x) => x.path === vp))
            add(
              name,
              'volume_unsupported',
              vp,
              'Volume names must match ^[a-z0-9][a-z0-9-]{0,40}$ with an absolute mount path',
            );
          return;
        }
        volumes.push({ name: src, mountPath: target });
      });
    else if (svc.volumes !== undefined)
      add(name, 'volume_unsupported', `${p}.volumes`, '`volumes` must be a list');
    if (volumes.length > 10) add(name, 'volume_unsupported', `${p}.volumes`, 'At most 10 volumes');

    // ports: only on the route service (pPanel allocates the 127.0.0.1 host port)
    if (svc.ports !== undefined && name !== opts.routeService)
      add(
        name,
        'ports_not_route_service',
        `${p}.ports`,
        'Only the route service may publish ports (pPanel allocates the host port)',
      );
    else if (svc.ports !== undefined)
      add(name, 'key_ignored', `${p}.ports`, 'Host port is allocated by pPanel (127.0.0.1)', true);

    // depends_on
    let dependsOn: string[] = [];
    if (Array.isArray(svc.depends_on)) dependsOn = svc.depends_on.map((d) => String(d));
    else if (isMap(svc.depends_on)) dependsOn = Object.keys(svc.depends_on);
    else if (svc.depends_on !== undefined)
      add(name, 'depends_on_unknown', `${p}.depends_on`, '`depends_on` must be a list or mapping');
    for (const d of dependsOn)
      if (!names.includes(d) || d === name)
        add(name, 'depends_on_unknown', `${p}.depends_on`, `Unknown dependency \`${d}\``);

    services.push({
      service: name,
      image,
      env,
      secretEnv,
      ...(command ? { command } : {}),
      volumes,
      dependsOn: [...new Set(dependsOn)],
      health: inferHealth(name, image, {
        service: opts.routeService,
        port: opts.routePort,
        path: healthPath,
      }),
      ...(name === opts.routeService ? { containerPort: opts.routePort } : {}),
    });
  }

  const order = topoSort(services);
  if (!order.ok)
    add(null, 'depends_on_cycle', 'services', `depends_on cycle: ${order.cycle.join(' → ')}`);
  if (violations.length) return fail();
  return {
    validation: { ...base, valid: true, violations, warnings },
    services: order.ok ? order.services : [],
    secretKeys: [...secretKeys].sort(),
  };
}

/** Kahn's algorithm, stable by file order; returns one cycle when there is one. */
export function topoSort(
  services: ComposePlanService[],
): { ok: true; services: ComposePlanService[] } | { ok: false; cycle: string[] } {
  const byName = new Map(services.map((s) => [s.service, s]));
  const indeg = new Map(services.map((s) => [s.service, 0]));
  for (const s of services)
    for (const d of s.dependsOn) if (byName.has(d)) indeg.set(s.service, indeg.get(s.service)! + 1);
  const out: ComposePlanService[] = [];
  const done = new Set<string>();
  for (;;) {
    const next = services.find((s) => !done.has(s.service) && indeg.get(s.service) === 0);
    if (!next) break;
    done.add(next.service);
    out.push(next);
    for (const s of services)
      if (s.dependsOn.includes(next.service)) indeg.set(s.service, indeg.get(s.service)! - 1);
  }
  if (out.length === services.length) return { ok: true, services: out };
  // walk dependencies among the remaining nodes until a node repeats
  const left = services.filter((s) => !done.has(s.service));
  const path: string[] = [];
  let cur: string | undefined = left[0]!.service;
  while (cur && !path.includes(cur)) {
    path.push(cur);
    cur = byName.get(cur)!.dependsOn.find((d) => byName.has(d) && !done.has(d));
  }
  return { ok: false, cycle: cur ? [...path.slice(path.indexOf(cur)), cur] : path };
}

// ---------------------------------------------------------------- execution plan helpers

/** Container name `ppanel-<app>-<service>-<8 hex>` (unique per deployment + service). */
export function composeContainerName(app: string, service: string, deploymentId: string): string {
  return `ppanel-${app}-${service}-${sha256Hex(`${deploymentId}:${service}`).slice(0, 8)}`;
}

export interface ResolvedService extends ComposePlanService {
  /** digest-pinned image */
  resolvedImage: string;
}

/**
 * Spec hash of a resolved service: digest image + every runtime-relevant field + the versions of the
 * secrets it references (a rotated secret recreates the service). Never includes secret values.
 */
export function composeSpecHash(
  s: ResolvedService,
  secretVersions: Record<string, number>,
): string {
  return sha256Hex(
    stableStringify({
      service: s.service,
      image: s.resolvedImage,
      env: s.env,
      secretEnv: s.secretEnv,
      secretVersions: Object.fromEntries(
        Object.values(s.secretEnv)
          .sort()
          .map((k) => [k, secretVersions[k] ?? 0]),
      ),
      command: s.command ?? null,
      volumes: s.volumes,
      dependsOn: [...s.dependsOn].sort(),
      health: s.health,
      containerPort: s.containerPort ?? null,
      resources: containerResourcesSchema.parse({}),
    }),
  );
}

/** Plan stored on a compose deployment (`deployments.plan`): digests, spec hashes, names; no secrets. */
export interface StoredComposePlan {
  versionId: string;
  version: number;
  routeService: string;
  services: Array<
    ResolvedService & {
      specHash: string;
      name: string;
      plannedAction: 'unchanged' | 'replace';
      previousName: string | null;
    }
  >;
}

export interface ComposeServiceResult {
  service: string;
  name: string;
  action: 'unchanged' | 'created' | 'replaced';
  previousName?: string | null;
  hostPort?: number | null;
  /** agent reports `{ status, … }`; a plain string is accepted too */
  health?: string | { status?: string } | null;
}

/** Health status string of an agent service result (`healthy`, `running`, …) or null. */
export function healthStatusOf(h: ComposeServiceResult['health']): string | null {
  if (typeof h === 'string') return h.slice(0, 64);
  return h && typeof h === 'object' && typeof h.status === 'string' ? h.status.slice(0, 64) : null;
}

export function planOf(v: unknown): StoredComposePlan | null {
  return v && typeof v === 'object' && Array.isArray((v as StoredComposePlan).services)
    ? (v as StoredComposePlan)
    : null;
}

/** Hash of what a compose deployment will run (names excluded: they depend on the deployment id). */
export function composePlanDigest(plan: StoredComposePlan): string {
  return sha256Hex(
    stableStringify({
      routeService: plan.routeService,
      services: plan.services.map((s) => ({ service: s.service, specHash: s.specHash })),
    }),
  );
}

/** compose.apply job params for a stored plan (route service gets the allocated 127.0.0.1 port). */
export function composeApplyParamsOf(
  deploymentId: string,
  app: string,
  plan: StoredComposePlan,
  hostPort: number,
  registryAuth: boolean,
) {
  return {
    deploymentId,
    app,
    routeService: plan.routeService,
    registryAuth,
    services: plan.services.map((s) => ({
      service: s.service,
      name: s.name,
      image: s.resolvedImage,
      specHash: s.specHash,
      env: s.env,
      secretEnv: s.secretEnv,
      ...(s.command ? { command: s.command } : {}),
      volumes: s.volumes,
      dependsOn: s.dependsOn,
      health: s.health,
      resources: containerResourcesSchema.parse({}),
      ...(s.service === plan.routeService ? { hostPort, containerPort: s.containerPort } : {}),
    })),
  };
}
