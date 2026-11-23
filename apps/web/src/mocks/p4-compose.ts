/**
 * Mock of the Center's static Compose validator (API_CONTRACTS §7.6). A small indentation-aware line
 * scanner — enough to exercise the UI with realistic violations; the real validator parses YAML.
 */
import { COMPOSE_CAP_ALLOWLIST, type ComposeRule } from '@ppanel/shared-contracts';
import type { ComposeValidation, ComposeViolation } from '@/lib/api/p4-types';

const TOP_LEVEL = ['version', 'name', 'services', 'volumes', 'networks', 'configs', 'secrets'];
const CAP_ALLOW: readonly string[] = COMPOSE_CAP_ALLOWLIST;
const MAX_ALIASES = 20;

const indentOf = (l: string) => l.length - l.trimStart().length;
const unquote = (v: string) => v.trim().replace(/^["']|["']$/g, '');

export function validateComposeMock(yaml: string, environment = 'production'): ComposeValidation {
  const violations: ComposeViolation[] = [];
  const warnings: ComposeViolation[] = [];
  const services: ComposeValidation['services'] = [];
  const add = (
    service: string | null,
    rule: ComposeRule,
    path: string,
    message: string,
    severity: 'error' | 'warning' = 'error',
  ) => (severity === 'warning' ? warnings : violations).push({ service, rule, path, message });

  const aliases = (yaml.match(/(^|[\s[,])\*[A-Za-z0-9_-]+/g) ?? []).length;
  if (aliases > MAX_ALIASES)
    add(null, 'yaml_alias_bomb', '$', `${aliases} YAML aliases (limit ${MAX_ALIASES}).`);
  if (/<<\s*:/.test(yaml) && aliases > 5)
    add(null, 'yaml_alias_bomb', '$', 'Merge keys combined with many aliases are refused.');

  let top = '';
  let service: string | null = null;
  let serviceIndent = -1;
  let key = '';
  let keyIndent = -1;
  const lines = yaml.split('\n');
  for (const raw of lines) {
    const line = raw.replace(/\s+#.*$/, '').replace(/^\s*#.*$/, '');
    if (!line.trim()) continue;
    const ind = indentOf(line);
    const t = line.trim();
    if (ind === 0) {
      top = t.replace(/:.*$/, '');
      service = null;
      key = '';
      if (!TOP_LEVEL.includes(top) && !top.startsWith('x-'))
        add(null, 'unknown_top_level_key', top, `Top-level key "${top}" is not allowed.`);
      if (top === 'include')
        add(null, 'external_include', 'include', 'include of external files is refused.');
      continue;
    }
    if (top !== 'services') continue;
    if (service === null || ind <= serviceIndent) {
      service = t.replace(/:.*$/, '');
      serviceIndent = ind;
      services.push({ name: service, image: null, build: false, ports: [] });
      key = '';
      keyIndent = -1;
      continue;
    }
    const base = `services.${service}`;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/.exec(t);
    if (m && (keyIndent < 0 || ind <= keyIndent || key === '')) {
      key = m[1]!;
      keyIndent = ind;
      const v = unquote(m[2] ?? '');
      if (key === 'privileged' && v === 'true')
        add(service, 'privileged', `${base}.privileged`, 'Privileged containers are not allowed.');
      if (key === 'network_mode' && v === 'host')
        add(service, 'host_network', `${base}.network_mode`, 'network_mode: host is not allowed.');
      if (key === 'pid' && v === 'host')
        add(service, 'host_pid', `${base}.pid`, 'pid: host is not allowed.');
      if (key === 'ipc' && v === 'host')
        add(service, 'host_ipc', `${base}.ipc`, 'ipc: host is not allowed.');
      if (key === 'userns_mode' && v === 'host')
        add(service, 'host_userns', `${base}.userns_mode`, 'userns_mode: host is not allowed.');
      if (key === 'devices')
        add(service, 'devices', `${base}.devices`, 'Host devices cannot be mapped.');
      if (key === 'extends')
        add(service, 'external_extends', `${base}.extends`, 'extends of other files is refused.');
      const svc = services[services.length - 1]!;
      if (key === 'image') svc.image = v || null;
      if (key === 'build') {
        svc.build = true;
        add(service, 'build_unsupported', `${base}.build`, 'Builds are not supported yet (P4b).');
      }
      if (key === 'image' && v && !/@sha256:[a-f0-9]{64}$/.test(v))
        add(
          service,
          'image_not_pinned',
          `${base}.image`,
          `Image "${v}" is not pinned by digest.`,
          environment === 'production' ? 'error' : 'warning',
        );
      if (v.includes('docker.sock'))
        add(service, 'docker_socket', `${base}.${key}`, 'The Docker socket must never be mounted.');
      continue;
    }
    // list items / nested values under `key`
    const item = unquote(t.replace(/^-\s*/, ''));
    const path = `${base}.${key}`;
    if (item.includes('docker.sock')) {
      add(service, 'docker_socket', path, 'The Docker socket must never be mounted.');
      continue;
    }
    if (key === 'volumes') {
      if (/^type\s*:\s*bind$/.test(item))
        add(service, 'host_bind', path, 'Bind mounts (type: bind) are not allowed.');
      else if (/^(\/|\.{1,2}\/|~)/.test(item.split(':')[0] ?? ''))
        add(service, 'host_bind', path, `Host path "${item.split(':')[0]}" — use a named volume.`);
      else if (/^source\s*:\s*(\/|\.|~)/.test(item))
        add(service, 'host_bind', path, 'Host path source — use a named volume.');
    }
    if (key === 'cap_add') {
      const cap = item.replace(/^CAP_/, '');
      if (!CAP_ALLOW.includes(cap))
        add(service, 'cap_add', path, `Capability ${cap} is outside the allowlist.`);
    }
    if (key === 'security_opt' && /(apparmor|seccomp)[:=]unconfined/.test(item))
      add(service, 'security_opt', path, `"${item}" disables a security profile.`);
    if (key === 'ports') {
      services[services.length - 1]!.ports.push(item);
      const parts = item.split(':');
      if (parts.length >= 3 && parts[0] !== '127.0.0.1')
        add(service, 'port_non_loopback', path, `Port ${item} binds a non-loopback host IP.`);
      else if (parts.length === 2)
        add(service, 'port_non_loopback', path, `Port ${item} binds all interfaces (0.0.0.0).`);
    }
  }
  return { valid: violations.length === 0, violations, warnings, services };
}
