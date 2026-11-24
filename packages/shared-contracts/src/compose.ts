// P4.02 — static Compose policy (deny rules). Pure: operates on an already-parsed document so the
// Center (yaml parser with alias limits) and the UI can share it. Execution of Compose is P4b.
import { IMAGE_DIGEST_REF_RE } from './jobs';

export const COMPOSE_RULES = [
  'yaml_invalid',
  'yaml_alias_bomb',
  'not_a_mapping',
  'unknown_top_level_key',
  'external_include',
  'external_extends',
  'privileged',
  'host_network',
  'shared_namespace',
  'host_pid',
  'host_ipc',
  'host_userns',
  'host_uts',
  'host_cgroup',
  'cap_add',
  'devices',
  'host_bind',
  'docker_socket',
  'security_opt',
  'port_non_loopback',
  'image_not_pinned',
  'build_unsupported',
  // P4b execution rules (compose applications; see docs/API_CONTRACTS.md §8.3)
  'image_required',
  'image_unresolvable',
  'route_service_missing',
  'ports_not_route_service',
  'depends_on_unknown',
  'depends_on_cycle',
  'secret_missing',
  'env_interpolation',
  'env_key_invalid',
  'service_name_invalid',
  'service_key_unsupported',
  'volume_unsupported',
  'command_unsupported',
  'name_too_long',
  'too_many_services',
  /** warning: key accepted but ignored (restart, networks, healthcheck test, …) */
  'key_ignored',
  // P7.02 hardening (fuzzing follow-up)
  'gpus',
  'sysctls',
  'runtime',
  'volumes_from',
  'merge_key',
  'extra_hosts',
  'volume_driver',
  'volume_external',
] as const;
export type ComposeRule = (typeof COMPOSE_RULES)[number];

export interface ComposeViolation {
  service: string | null;
  rule: ComposeRule;
  path: string;
  message: string;
}

export interface ComposeValidation {
  valid: boolean;
  violations: ComposeViolation[];
  warnings: ComposeViolation[];
  services: Array<{ name: string; image: string | null; build: boolean; ports: string[] }>;
}

/** Linux capabilities a managed container may add (mirrors the agent's hardened run). */
export const COMPOSE_CAP_ALLOWLIST = [
  'CHOWN',
  'SETUID',
  'SETGID',
  'NET_BIND_SERVICE',
  'DAC_OVERRIDE',
] as const;

/**
 * Service keys the Center's Compose executor understands (compose-plan.ts). The static policy and the
 * normaliser share these lists so a file the validator accepts uses only keys the plan can handle.
 */
export const COMPOSE_SUPPORTED_SERVICE_KEYS = [
  'image',
  'environment',
  'command',
  'volumes',
  'ports',
  'depends_on',
] as const;
/** Accepted but ignored by the executor (pPanel manages these itself) → `key_ignored` warning. */
export const COMPOSE_IGNORED_SERVICE_KEYS = [
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
] as const;
/**
 * Keys with a dedicated deny rule that are accepted when their value passes it (allowlisted
 * capabilities, `no-new-privileges`, `privileged: false`, private ipc/cgroup). The executor ignores
 * them (the agent's hardened HostConfig already applies these settings) → `key_ignored` in the plan.
 */
export const COMPOSE_POLICY_CHECKED_SERVICE_KEYS = [
  'cap_add',
  'security_opt',
  'privileged',
  'ipc',
  'cgroup',
] as const;
/** Allowlist of service keys (plus `build`, reported as `build_unsupported`, and inert `x-*`). */
export const COMPOSE_ALLOWED_SERVICE_KEYS: ReadonlySet<string> = new Set<string>([
  ...COMPOSE_SUPPORTED_SERVICE_KEYS,
  ...COMPOSE_IGNORED_SERVICE_KEYS,
  ...COMPOSE_POLICY_CHECKED_SERVICE_KEYS,
  'build',
]);

const TOP_LEVEL_KEYS = new Set([
  'version',
  'name',
  'services',
  'networks',
  'volumes',
  'secrets',
  'configs',
]);
const LOOPBACK = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);
/** The only security_opt values allowed (everything else may weaken confinement: label:type:spc_t, …). */
const SAFE_SECOPTS = new Set([
  'no-new-privileges',
  'no-new-privileges:true',
  'no-new-privileges=true',
]);
const FALSY = new Set(['false', 'no', 'n', 'off', '0', '']);

/** Scalar → trimmed lower-case string (null for maps, lists, null/undefined). */
function norm(v: unknown): string | null {
  if (typeof v === 'string') return v.trim().toLowerCase();
  if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint')
    return String(v).toLowerCase();
  return null;
}
/** Compose list fields given as a scalar are normalised to a one-element list. */
function asList(v: unknown): unknown[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}
function present(v: unknown): boolean {
  return v !== undefined && v !== null;
}

function isMap(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Named volume source: no slash, not relative/home-relative (those are host paths). */
function isHostPathSource(src: string): boolean {
  return (
    src.startsWith('/') ||
    src.startsWith('\\') ||
    src.startsWith('.') ||
    src.startsWith('~') ||
    src.includes('/') ||
    /^[A-Za-z]:\\/.test(src) ||
    src.startsWith('$')
  );
}

function containsDockerSocket(v: unknown, depth = 0): boolean {
  if (depth > 20) return false;
  if (typeof v === 'string')
    return /docker\.sock|\/run\/docker|containerd\.sock|podman\.sock/i.test(v);
  if (Array.isArray(v)) return v.some((x) => containsDockerSocket(x, depth + 1));
  if (isMap(v))
    return Object.entries(v).some(
      ([k, x]) => containsDockerSocket(k, depth + 1) || containsDockerSocket(x, depth + 1),
    );
  return false;
}

/** Parse a short port spec → host IP ('' = all interfaces) or null when no host binding. */
export function portHostIp(spec: string): string | null {
  const s = spec.trim().replace(/\/(tcp|udp|sctp)$/i, '');
  // [ip:]host:container  |  container  (container-only publishes on all interfaces with a random port)
  const ipv6 = /^\[([^\]]+)\]:(.+)$/.exec(s);
  if (ipv6) return `[${ipv6[1]}]`;
  const parts = s.split(':');
  if (parts.length >= 3) return parts.slice(0, parts.length - 2).join(':');
  return '';
}

export function validateComposeDocument(
  doc: unknown,
  opts: { environment?: 'production' | 'uat' | 'development' } = {},
): ComposeValidation {
  const violations: ComposeViolation[] = [];
  const warnings: ComposeViolation[] = [];
  const services: ComposeValidation['services'] = [];
  const add = (
    service: string | null,
    rule: ComposeRule,
    path: string,
    message: string,
    warn = false,
  ) => (warn ? warnings : violations).push({ service, rule, path, message });

  if (!isMap(doc)) {
    add(null, 'not_a_mapping', '$', 'Compose file must be a YAML mapping');
    return { valid: false, violations, warnings, services };
  }

  const production = opts.environment === 'production';
  for (const key of Object.keys(doc)) {
    if (key === 'include')
      add(
        null,
        'external_include',
        'include',
        '`include` of external Compose files is not allowed',
      );
    else if (key === '<<')
      add(null, 'merge_key', key, 'Unresolved YAML merge key `<<` is not allowed');
    else if (!TOP_LEVEL_KEYS.has(key) && !key.startsWith('x-'))
      add(null, 'unknown_top_level_key', key, `Unknown top-level key \`${key}\``);
  }

  // top-level volumes: local driver only; driver_opts only for tmpfs (no bind/device/o=bind, any case)
  if (isMap(doc.volumes)) {
    for (const [name, v] of Object.entries(doc.volumes)) {
      if (!isMap(v)) continue;
      const vp = `volumes.${name}`;
      if ('<<' in v) add(null, 'merge_key', `${vp}.<<`, 'Unresolved YAML merge key `<<`');
      if (present(v.driver) && norm(v.driver) !== 'local')
        add(null, 'volume_driver', `${vp}.driver`, 'Only the `local` volume driver is allowed');
      // external / name overrides could attach another app's (or a host) volume: pPanel always names
      // volumes ppanel-<app>-<name> itself, so neither is ever allowed (P7.02 follow-up)
      if (present(v.external) && norm(v.external) !== 'false')
        add(null, 'volume_external', `${vp}.external`, 'External volumes are not allowed');
      if (present(v.name))
        add(
          null,
          'volume_external',
          `${vp}.name`,
          'Overriding the volume name is not allowed (pPanel names volumes per app)',
        );
      if (present(v.driver_opts) && !isMap(v.driver_opts))
        add(null, 'host_bind', `${vp}.driver_opts`, '`driver_opts` must be a mapping');
      else if (isMap(v.driver_opts)) {
        for (const [k, raw] of Object.entries(v.driver_opts)) {
          const key = k.trim().toLowerCase();
          const val = norm(raw) ?? '';
          const bad =
            key === 'type'
              ? val !== 'tmpfs'
              : key === 'device'
                ? val !== 'tmpfs'
                : key === 'o'
                  ? /bind/.test(val)
                  : true;
          if (bad)
            add(
              null,
              'host_bind',
              `${vp}.driver_opts.${k}`,
              'Volume driver options may only create a tmpfs (no bind/device mounts)',
            );
        }
      }
    }
  }
  // top-level networks: never the host network (or L2 drivers that attach to the host interface)
  if (isMap(doc.networks)) {
    for (const [name, n] of Object.entries(doc.networks)) {
      const np = `networks.${name}`;
      const hostLike =
        name.trim().toLowerCase() === 'host' ||
        (isMap(n) &&
          (norm(n.name) === 'host' ||
            ['host', 'macvlan', 'ipvlan'].includes(norm(n.driver) ?? '')));
      if (hostLike) add(null, 'host_network', np, 'The host network is not allowed');
      if (isMap(n) && '<<' in n)
        add(null, 'merge_key', `${np}.<<`, 'Unresolved YAML merge key `<<`');
    }
  }
  for (const section of ['secrets', 'configs'] as const) {
    const s = doc[section];
    if (!isMap(s)) continue;
    for (const [name, v] of Object.entries(s))
      if (isMap(v) && typeof v.file === 'string')
        add(null, 'host_bind', `${section}.${name}.file`, `${section} entry reads a host file`);
  }

  const svcs = doc.services;
  if (svcs !== undefined && !isMap(svcs)) {
    add(null, 'not_a_mapping', 'services', '`services` must be a mapping');
    return { valid: false, violations, warnings, services };
  }
  for (const [name, raw] of Object.entries(svcs ?? {})) {
    const p = `services.${name}`;
    if (!isMap(raw)) {
      add(name, 'not_a_mapping', p, 'Service must be a mapping');
      continue;
    }
    const svc = raw;
    const image = typeof svc.image === 'string' ? svc.image : null;
    const ports: string[] = [];

    if ('<<' in svc)
      add(name, 'merge_key', `${p}.<<`, 'Unresolved YAML merge key `<<` is not allowed');

    if (present(svc.privileged) && !FALSY.has(norm(svc.privileged) ?? 'x'))
      add(name, 'privileged', `${p}.privileged`, 'Privileged containers are not allowed');

    // namespaces: anything but the private default is refused (host, container:, service:, …)
    const ns: Array<[string, ComposeRule, readonly string[]]> = [
      ['pid', 'host_pid', []],
      ['ipc', 'host_ipc', ['private', 'shareable', 'none']],
      ['userns_mode', 'host_userns', []],
      ['uts', 'host_uts', []],
      ['cgroup', 'host_cgroup', ['private']],
    ];
    for (const [key, rule, allowed] of ns) {
      if (!present(svc[key])) continue;
      const v = norm(svc[key]);
      if (v === '' || (v !== null && allowed.includes(v))) continue;
      if (v !== null && /^(container|service):/.test(v))
        add(
          name,
          'shared_namespace',
          `${p}.${key}`,
          `Sharing another container's ${key} namespace is not allowed`,
        );
      else add(name, rule, `${p}.${key}`, `\`${key}: ${String(svc[key])}\` is not allowed`);
    }
    for (const key of ['network_mode', 'net'] as const) {
      if (!present(svc[key])) continue;
      const v = norm(svc[key]);
      if (v !== null && ['bridge', 'none', 'default', ''].includes(v)) continue;
      if (v !== null && /^(container|service):/.test(v))
        add(
          name,
          'shared_namespace',
          `${p}.${key}`,
          'Sharing another container network namespace is not allowed',
        );
      else
        add(
          name,
          'host_network',
          `${p}.${key}`,
          `\`${key}: ${String(svc[key])}\` is not allowed (bridge or none only)`,
        );
    }
    if (present(svc.networks)) {
      const refs = isMap(svc.networks) ? Object.keys(svc.networks) : asList(svc.networks);
      if (refs.some((r) => norm(r) === 'host'))
        add(name, 'host_network', `${p}.networks`, 'The host network is not allowed');
    }

    if (present(svc.cap_add)) {
      if (isMap(svc.cap_add))
        add(name, 'cap_add', `${p}.cap_add`, '`cap_add` must be a list of capabilities');
      for (const c of isMap(svc.cap_add) ? [] : asList(svc.cap_add)) {
        const cap = (norm(c) ?? String(c)).toUpperCase().replace(/^CAP_/, '');
        if (!(COMPOSE_CAP_ALLOWLIST as readonly string[]).includes(cap))
          add(name, 'cap_add', `${p}.cap_add`, `Capability ${cap} is not in the allowlist`);
      }
    }
    for (const key of ['devices', 'device_cgroup_rules'] as const) {
      const v = svc[key];
      if (
        present(v) &&
        !(Array.isArray(v) && v.length === 0) &&
        !(isMap(v) && !Object.keys(v).length)
      )
        add(name, 'devices', `${p}.${key}`, 'Host device access is not allowed');
    }
    if (present(svc.security_opt)) {
      const opts2 = isMap(svc.security_opt) ? [svc.security_opt] : asList(svc.security_opt);
      for (const o of opts2)
        if (!SAFE_SECOPTS.has(norm(o) ?? ''))
          add(
            name,
            'security_opt',
            `${p}.security_opt`,
            `security_opt \`${typeof o === 'string' ? o : JSON.stringify(o)}\` is not allowed (only no-new-privileges)`,
          );
    }
    const always: Array<[string, ComposeRule, string]> = [
      ['gpus', 'gpus', 'GPU access is not allowed'],
      ['cgroup_parent', 'host_cgroup', '`cgroup_parent` is not allowed'],
      ['sysctls', 'sysctls', '`sysctls` are not allowed'],
      ['runtime', 'runtime', 'Custom container runtimes are not allowed'],
      ['volumes_from', 'volumes_from', "Mounting another container's volumes is not allowed"],
    ];
    for (const [key, rule, message] of always)
      if (present(svc[key])) add(name, rule, `${p}.${key}`, message);
    if (present(svc.extra_hosts))
      add(
        name,
        'extra_hosts',
        `${p}.extra_hosts`,
        '`extra_hosts` is not allowed (it can redirect names to host-local addresses)',
        !production,
      );

    if (present(svc.volumes) && isMap(svc.volumes))
      add(name, 'volume_unsupported', `${p}.volumes`, '`volumes` must be a list');
    else
      asList(svc.volumes).forEach((v, i) => {
        const vp = `${p}.volumes[${i}]`;
        if (typeof v === 'string') {
          const t = v.trim();
          const src = /^[A-Za-z]:[\\/]/.test(t) ? t : (t.split(':')[0] ?? '');
          if ((t.includes(':') || t.startsWith('\\')) && isHostPathSource(src))
            add(name, 'host_bind', vp, `Host path bind \`${src}\` is not allowed`);
        } else if (isMap(v)) {
          const type = present(v.type) ? norm(v.type) : 'volume';
          const source = typeof v.source === 'string' ? v.source.trim() : v.source;
          if (type === 'bind' || type === 'npipe')
            add(name, 'host_bind', vp, 'Bind mounts are not allowed');
          else if (type === 'tmpfs') {
            if (present(source) && source !== '')
              add(name, 'host_bind', vp, 'tmpfs mounts must not have a source');
          } else if (type !== 'volume')
            add(name, 'volume_unsupported', vp, `Volume type \`${String(v.type)}\` is not allowed`);
          else if (typeof source === 'string' && isHostPathSource(source))
            add(name, 'host_bind', vp, `Host path \`${source}\` is not allowed`);
          else if (present(source) && typeof source !== 'string')
            add(name, 'volume_unsupported', vp, 'Volume source must be a volume name');
        } else add(name, 'volume_unsupported', vp, 'Volume entries must be strings or mappings');
      });
    if (containsDockerSocket(svc))
      add(name, 'docker_socket', p, 'Docker/containerd socket access is not allowed');

    if (present(svc.ports) && isMap(svc.ports))
      add(name, 'port_non_loopback', `${p}.ports`, '`ports` must be a list');
    else
      asList(svc.ports).forEach((spec, i) => {
        const pp = `${p}.ports[${i}]`;
        if (typeof spec === 'string' || typeof spec === 'number') {
          const s = String(spec);
          ports.push(s);
          const ip = portHostIp(s);
          if (ip !== null && !LOOPBACK.has(ip.toLowerCase()))
            add(
              name,
              'port_non_loopback',
              pp,
              `Port \`${s}\` is published on a non-loopback interface`,
            );
        } else if (isMap(spec)) {
          ports.push(JSON.stringify(spec));
          // long syntax publishes (a random port when `published` is absent) on host_ip, default 0.0.0.0
          const ip = typeof spec.host_ip === 'string' ? spec.host_ip.trim().toLowerCase() : '';
          if (!LOOPBACK.has(ip))
            add(name, 'port_non_loopback', pp, 'Published port must bind host_ip 127.0.0.1');
        } else
          add(name, 'port_non_loopback', pp, 'Port entries must be strings, numbers or mappings');
      });

    if (isMap(svc.extends) && typeof svc.extends.file === 'string')
      add(name, 'external_extends', `${p}.extends`, '`extends` from external files is not allowed');
    else if (typeof svc.extends === 'string' && svc.extends.includes('/'))
      add(name, 'external_extends', `${p}.extends`, '`extends` from external files is not allowed');

    const build = svc.build !== undefined;
    if (build)
      add(
        name,
        'build_unsupported',
        `${p}.build`,
        'Builds are not supported yet (P4b); use a registry image',
        true,
      );
    if (image !== null && !IMAGE_DIGEST_REF_RE.test(image))
      add(
        name,
        'image_not_pinned',
        `${p}.image`,
        `Image \`${image}\` is not pinned by digest`,
        opts.environment !== 'production',
      );
    // allowlist: any other key is unsupported (violation in production, warning elsewhere) unless a
    // dedicated rule already reported it
    const reported = [...violations, ...warnings].map((v) => v.path);
    for (const key of Object.keys(svc)) {
      if (COMPOSE_ALLOWED_SERVICE_KEYS.has(key) || key.startsWith('x-') || key === '<<') continue;
      const kp = `${p}.${key}`;
      if (reported.some((r) => r === kp || r.startsWith(`${kp}.`) || r.startsWith(`${kp}[`)))
        continue;
      add(name, 'service_key_unsupported', kp, `\`${key}\` is not supported`, !production);
    }
    services.push({ name, image, build, ports });
  }
  return { valid: violations.length === 0, violations, warnings, services };
}
