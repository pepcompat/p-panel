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
const UNCONFINED_SECOPT_RE =
  /^(?:apparmor|seccomp)[:=]unconfined$|^label[:=]disable$|^systempaths[:=]unconfined$|^no-new-privileges[:=]false$/i;

function isMap(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Named volume source: no slash, not relative/home-relative (those are host paths). */
function isHostPathSource(src: string): boolean {
  return (
    src.startsWith('/') ||
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

  for (const key of Object.keys(doc)) {
    if (key === 'include')
      add(
        null,
        'external_include',
        'include',
        '`include` of external Compose files is not allowed',
      );
    else if (!TOP_LEVEL_KEYS.has(key) && !key.startsWith('x-'))
      add(null, 'unknown_top_level_key', key, `Unknown top-level key \`${key}\``);
  }

  // top-level volumes that are really host binds (local driver with o=bind / device=/path)
  if (isMap(doc.volumes)) {
    for (const [name, v] of Object.entries(doc.volumes)) {
      if (!isMap(v)) continue;
      const o = isMap(v.driver_opts) ? v.driver_opts : {};
      const device = typeof o.device === 'string' ? o.device : '';
      if (
        /bind/.test(String(o.o ?? '')) ||
        String(o.type ?? '') === 'none' ||
        device.startsWith('/')
      )
        add(null, 'host_bind', `volumes.${name}.driver_opts`, 'Volume binds a host path');
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

    if (svc.privileged === true || svc.privileged === 'true')
      add(name, 'privileged', `${p}.privileged`, 'Privileged containers are not allowed');

    const ns: Array<[string, ComposeRule]> = [
      ['pid', 'host_pid'],
      ['ipc', 'host_ipc'],
      ['userns_mode', 'host_userns'],
      ['uts', 'host_uts'],
      ['cgroup', 'host_cgroup'],
    ];
    for (const [key, rule] of ns)
      if (svc[key] === 'host') add(name, rule, `${p}.${key}`, `\`${key}: host\` is not allowed`);
    for (const key of ['pid', 'ipc'] as const)
      if (typeof svc[key] === 'string' && /^(container|service):/.test(svc[key] as string))
        add(
          name,
          'shared_namespace',
          `${p}.${key}`,
          `Sharing another container's ${key} namespace is not allowed`,
        );
    if (typeof svc.network_mode === 'string') {
      if (svc.network_mode === 'host')
        add(name, 'host_network', `${p}.network_mode`, '`network_mode: host` is not allowed');
      else if (/^container:/.test(svc.network_mode))
        add(
          name,
          'shared_namespace',
          `${p}.network_mode`,
          'Sharing another container network namespace is not allowed',
        );
    }
    if (Array.isArray(svc.cap_add)) {
      for (const c of svc.cap_add) {
        const cap = String(c).toUpperCase().replace(/^CAP_/, '');
        if (!(COMPOSE_CAP_ALLOWLIST as readonly string[]).includes(cap))
          add(name, 'cap_add', `${p}.cap_add`, `Capability ${cap} is not in the allowlist`);
      }
    }
    if (
      (Array.isArray(svc.devices) && svc.devices.length > 0) ||
      (Array.isArray(svc.device_cgroup_rules) && svc.device_cgroup_rules.length > 0) ||
      isMap(svc.devices)
    )
      add(name, 'devices', `${p}.devices`, 'Host device access is not allowed');
    if (Array.isArray(svc.security_opt))
      for (const o of svc.security_opt)
        if (UNCONFINED_SECOPT_RE.test(String(o).trim()))
          add(
            name,
            'security_opt',
            `${p}.security_opt`,
            `security_opt \`${String(o)}\` disables confinement`,
          );

    if (Array.isArray(svc.volumes)) {
      svc.volumes.forEach((v, i) => {
        const vp = `${p}.volumes[${i}]`;
        if (typeof v === 'string') {
          const src = v.split(':')[0] ?? '';
          if (v.includes(':') && isHostPathSource(src))
            add(name, 'host_bind', vp, `Host path bind \`${src}\` is not allowed`);
        } else if (isMap(v)) {
          if (v.type === 'bind' || v.type === 'npipe')
            add(name, 'host_bind', vp, 'Bind mounts are not allowed');
          else if (typeof v.source === 'string' && v.type !== 'tmpfs' && isHostPathSource(v.source))
            add(name, 'host_bind', vp, `Host path \`${v.source}\` is not allowed`);
        }
      });
    }
    if (containsDockerSocket(svc))
      add(name, 'docker_socket', p, 'Docker/containerd socket access is not allowed');

    if (Array.isArray(svc.ports)) {
      svc.ports.forEach((spec, i) => {
        const pp = `${p}.ports[${i}]`;
        if (typeof spec === 'string' || typeof spec === 'number') {
          const s = String(spec);
          ports.push(s);
          const ip = portHostIp(s);
          if (ip !== null && !LOOPBACK.has(ip))
            add(
              name,
              'port_non_loopback',
              pp,
              `Port \`${s}\` is published on a non-loopback interface`,
            );
        } else if (isMap(spec)) {
          ports.push(JSON.stringify(spec));
          const ip = typeof spec.host_ip === 'string' ? spec.host_ip : '';
          if (spec.published !== undefined && !LOOPBACK.has(ip))
            add(name, 'port_non_loopback', pp, 'Published port must bind host_ip 127.0.0.1');
        }
      });
    }

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
    services.push({ name, image, build, ports });
  }
  return { valid: violations.length === 0, violations, warnings, services };
}
