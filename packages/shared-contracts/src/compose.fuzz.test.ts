/**
 * P7.02 property tests for the static Compose policy (`validateComposeDocument`).
 *
 * - never throws on arbitrary (YAML-ish) input, including shared sub-trees as produced by anchors;
 * - never accepts privileged / host namespaces / host binds / docker.sock / non-loopback ports in the
 *   encodings it is meant to catch, wherever the construct is placed (any service, shared via an
 *   anchor-like reference, short or long syntax);
 * - the former KNOWN GAPS (inputs the validator used to ACCEPT) are regression guards since the
 *   P7.02 follow-up (service-key allowlist + case/whitespace/scalar-normalised deny rules).
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { validateComposeDocument } from './compose';
import { NUM_RUNS } from './fuzz-helpers.fuzz.test';

const IMG = 'registry.example/acme/web@sha256:' + 'a'.repeat(64);

const benignKey = fc.constantFrom(
  'image',
  'environment',
  'command',
  'labels',
  'restart',
  'depends_on',
  'healthcheck',
  'x-note',
);
const yamlScalar = fc.oneof(
  fc.string(),
  fc.integer(),
  fc.boolean(),
  fc.constant(null),
  fc.double(),
);
const yamlValue = fc.letrec((tie) => ({
  v: fc.oneof(
    { depthSize: 'small' },
    yamlScalar,
    fc.array(tie('v'), { maxLength: 4 }),
    fc.dictionary(fc.string(), tie('v'), { maxKeys: 4 }),
  ),
})).v;
const benignService = fc
  .dictionary(benignKey, yamlValue, { maxKeys: 4 })
  .map((s) => ({ ...s, image: IMG }));

/** Dangerous constructs in the encodings the validator is designed to catch. */
const CAUGHT: Array<[string, Record<string, unknown>]> = [
  ['privileged true', { privileged: true }],
  ['privileged "true"', { privileged: 'true' }],
  ['network_mode host', { network_mode: 'host' }],
  ['network_mode container:', { network_mode: 'container:abc' }],
  ['pid host', { pid: 'host' }],
  ['pid container:', { pid: 'container:abc' }],
  ['ipc host', { ipc: 'host' }],
  ['ipc service:', { ipc: 'service:db' }],
  ['uts host', { uts: 'host' }],
  ['userns host', { userns_mode: 'host' }],
  ['cgroup host', { cgroup: 'host' }],
  ['cap_add SYS_ADMIN', { cap_add: ['SYS_ADMIN'] }],
  ['cap_add cap_sys_ptrace', { cap_add: ['cap_sys_ptrace'] }],
  ['cap_add ALL', { cap_add: ['ALL'] }],
  ['devices list', { devices: ['/dev/sda:/dev/sda'] }],
  ['device_cgroup_rules', { device_cgroup_rules: ['a *:* rwm'] }],
  ['security_opt seccomp unconfined', { security_opt: ['seccomp:unconfined'] }],
  ['security_opt apparmor=unconfined', { security_opt: ['apparmor=unconfined'] }],
  ['security_opt label disable', { security_opt: ['label:disable'] }],
  ['security_opt no-new-privileges false', { security_opt: ['no-new-privileges:false'] }],
  ['short bind abs', { volumes: ['/etc:/host-etc'] }],
  ['short bind ro', { volumes: ['/:/host:ro'] }],
  ['short bind relative', { volumes: ['./data:/data'] }],
  ['short bind parent', { volumes: ['../:/x'] }],
  ['short bind home', { volumes: ['~/x:/x'] }],
  ['short bind env', { volumes: ['${PWD}:/x'] }],
  ['long bind', { volumes: [{ type: 'bind', source: '/etc', target: '/x' }] }],
  ['long bind no source', { volumes: [{ type: 'bind', target: '/x' }] }],
  ['long npipe', { volumes: [{ type: 'npipe', source: 'x', target: '/x' }] }],
  ['long volume abs source', { volumes: [{ type: 'volume', source: '/etc', target: '/x' }] }],
  ['docker.sock short', { volumes: ['/var/run/docker.sock:/var/run/docker.sock'] }],
  ['docker.sock /run', { volumes: [{ type: 'volume', source: 'x', target: '/run/docker.sock' }] }],
  ['docker.sock in env', { environment: { DOCKER_HOST: 'unix:///var/run/docker.sock' } }],
  [
    'containerd.sock in command',
    { command: ['ctr', '--address', '/run/containerd/containerd.sock'] },
  ],
  ['podman.sock in label', { labels: { x: '/run/podman/podman.sock' } }],
  ['port all interfaces', { ports: ['80:80'] }],
  ['port 0.0.0.0', { ports: ['0.0.0.0:80:80'] }],
  ['port container only', { ports: ['8080'] }],
  ['port number', { ports: [8080] }],
  ['port ipv6 any', { ports: ['[::]:80:80'] }],
  ['port long published', { ports: [{ target: 80, published: 8080 }] }],
  ['port long 0.0.0.0', { ports: [{ target: 80, published: '8080', host_ip: '0.0.0.0' }] }],
  ['extends file', { extends: { file: '../other.yml', service: 'x' } }],
];

/** Formerly accepted (standalone validator gaps found by fuzzing) — must now be rejected. */
const KNOWN_GAPS: Array<[string, unknown]> = [
  ['privileged "True"', { privileged: 'True' }],
  ['privileged "yes"', { privileged: 'yes' }],
  ['privileged 1', { privileged: 1 }],
  ['network_mode "HOST"', { network_mode: 'HOST' }],
  ['network_mode " host"', { network_mode: ' host' }],
  ['network_mode service:<other>', { network_mode: 'service:db' }],
  ['legacy net: host', { net: 'host' }],
  ['networks: [host]', { networks: ['host'] }],
  ['pid "HOST"', { pid: 'HOST' }],
  ['uts "HOST"', { uts: 'HOST' }],
  ['userns_mode "HOST"', { userns_mode: 'HOST' }],
  ['cap_add as a scalar', { cap_add: 'SYS_ADMIN' }],
  ['devices as a scalar', { devices: '/dev/sda:/dev/sda' }],
  ['security_opt as a scalar', { security_opt: 'seccomp=unconfined' }],
  ['security_opt label:type:spc_t', { security_opt: ['label:type:spc_t'] }],
  ['long volume type "BIND"', { volumes: [{ type: 'BIND', source: 'x', target: '/y' }] }],
  ['long tmpfs with host source', { volumes: [{ type: 'tmpfs', source: '/etc', target: '/x' }] }],
  ['short bind windows path', { volumes: ['C:\\x:/x'] }],
  ['volumes_from another container', { volumes_from: ['container:other'] }],
  ['ports long without published (random port on 0.0.0.0)', { ports: [{ target: 80 }] }],
  ['ports as a scalar', { ports: '80:80' }],
  ['gpus: all', { gpus: 'all' }],
  ['cgroup_parent', { cgroup_parent: '/' }],
  ['sysctls', { sysctls: { 'kernel.core_pattern': '|/tmp/x' } }],
  ['runtime', { runtime: 'runc-unsafe' }],
  ['merge key left unresolved (parser without merge:true)', { '<<': { privileged: true } }],
  // further encodings from the P7.02 follow-up brief
  ['privileged " TRUE "', { privileged: ' TRUE ' }],
  ['privileged "on"', { privileged: 'on' }],
  ['network_mode container:', { network_mode: 'Container:abc' }],
  ['net: " HOST"', { net: ' HOST' }],
  ['networks map {host: {}}', { networks: { host: {} } }],
  ['ipc "HOST"', { ipc: 'HOST' }],
  ['cgroup "Host"', { cgroup: 'Host' }],
  ['pid " host "', { pid: ' host ' }],
  ['cap_add scalar lower-case', { cap_add: 'cap_sys_admin' }],
  ['security_opt label=disable', { security_opt: ['label=disable'] }],
  ['security_opt APPARMOR=UNCONFINED', { security_opt: ['APPARMOR=UNCONFINED'] }],
  ['security_opt seccomp=unconfined scalar', { security_opt: ' seccomp=unconfined ' }],
  ['security_opt systempaths=unconfined', { security_opt: ['systempaths=unconfined'] }],
  ['long volume type " Bind "', { volumes: [{ type: ' Bind ', source: '/etc', target: '/y' }] }],
  ['long volume type npipe upper', { volumes: [{ type: 'NPIPE', source: 'x', target: '/y' }] }],
  ['volumes as a scalar host bind', { volumes: '/etc:/x' }],
  ['short bind windows forward slash', { volumes: ['C:/x:/x'] }],
  ['short bind UNC', { volumes: ['\\\\srv\\share:/x'] }],
  ['ports long host_ip 0.0.0.0 no published', { ports: [{ target: 80, host_ip: '0.0.0.0' }] }],
  ['ports scalar number', { ports: 8080 }],
  ['extra_hosts (production)', { extra_hosts: ['metadata:169.254.169.254'] }],
  ['unknown key (production): userns_mode-like oom_kill_disable', { oom_kill_disable: true }],
  ['unknown key (production): cap_drop', { cap_drop: ['ALL'] }],
  ['unknown key (production): deploy GPU reservation', { deploy: { resources: {} } }],
  ['device_cgroup_rules scalar', { device_cgroup_rules: 'a *:* rwm' }],
];
const TOP_GAPS: Array<[string, Record<string, unknown>]> = [
  [
    'top-level default network = external host',
    { networks: { default: { name: 'host', external: true } } },
  ],
  [
    'volume plugin with a host mountpoint',
    { volumes: { v: { driver: 'local-persist', driver_opts: { mountpoint: '/etc' } } } },
  ],
  [
    'volume driver_opts o=BIND (case)',
    { volumes: { v: { driver_opts: { o: 'BIND', device: 'etc' } } } },
  ],
  ['volume driver_opts TYPE none', { volumes: { v: { driver_opts: { type: 'NONE' } } } }],
  ['volume driver_opts device path', { volumes: { v: { driver_opts: { device: '/srv/x' } } } }],
  ['volume driver nfs-ish', { volumes: { v: { driver: 'Rexray' } } }],
  ['top-level network name " HOST "', { networks: { n: { name: ' HOST ' } } }],
  ['top-level network driver host', { networks: { n: { driver: 'host' } } }],
  ['top-level network driver macvlan', { networks: { n: { driver: 'macvlan' } } }],
  ['top-level unresolved merge key', { '<<': { services: {} } }],
];

const valid = (doc: unknown) => validateComposeDocument(doc, { environment: 'production' }).valid;

describe('validateComposeDocument — robustness', () => {
  it('never throws on arbitrary values', () => {
    fc.assert(
      fc.property(fc.anything({ maxDepth: 6 }), (doc) => {
        validateComposeDocument(doc);
        validateComposeDocument({ services: doc });
        validateComposeDocument({ services: { a: doc }, volumes: doc, secrets: doc, configs: doc });
      }),
      { numRuns: NUM_RUNS },
    );
  });

  it('never throws on compose-shaped documents with shared (anchor-like) sub-trees', () => {
    fc.assert(
      fc.property(
        fc.array(benignService, { minLength: 1, maxLength: 5 }),
        yamlValue,
        (svcs, shared) => {
          const services: Record<string, unknown> = {};
          svcs.forEach(
            (s, i) => (services[`s${i}`] = { ...s, environment: shared, labels: shared }),
          );
          const r = validateComposeDocument({ 'x-shared': shared, services });
          expect(Array.isArray(r.violations)).toBe(true);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  it('terminates on wide shared DAGs (alias bombs are bounded by the parser; depth cap here)', () => {
    let node: unknown = 'leaf';
    for (let i = 0; i < 30; i++) node = [node, node];
    const t = Date.now();
    validateComposeDocument({ services: { a: { image: IMG, environment: { X: node } } } });
    expect(Date.now() - t).toBeLessThan(10_000);
  });
});

describe('validateComposeDocument — never accepts dangerous constructs', () => {
  it('rejects every caught encoding in any service position, also when shared by reference', () => {
    fc.assert(
      fc.property(
        fc.array(benignService, { minLength: 1, maxLength: 4 }),
        fc.constantFrom(...CAUGHT),
        fc.nat(),
        fc.boolean(),
        (svcs, [, bad], pos, viaShared) => {
          const services: Record<string, unknown> = {};
          const idx = pos % svcs.length;
          svcs.forEach((s, i) => (services[`svc-${i}`] = s));
          if (viaShared) {
            // anchor + merge resolved by the parser: the same object shows up in the service
            const shared = { ...bad };
            services[`svc-${idx}`] = Object.assign({}, svcs[idx], shared);
            services['other'] = Object.assign({ image: IMG }, shared);
          } else {
            services[`svc-${idx}`] = { ...svcs[idx], ...bad };
          }
          expect(valid({ services })).toBe(false);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  it('finds docker.sock at any depth/position inside a service', () => {
    const path = fc.array(fc.oneof(fc.string({ minLength: 1, maxLength: 5 }), fc.nat(3)), {
      minLength: 1,
      maxLength: 8,
    });
    fc.assert(
      fc.property(
        path,
        fc.string(),
        fc.string(),
        fc.constantFrom(
          '/var/run/docker.sock',
          '/run/docker.sock',
          'DOCKER.SOCK',
          '/run/containerd/containerd.sock',
        ),
        (p, pre, post, sock) => {
          let leaf: unknown = pre + sock + post;
          for (const k of [...p].reverse())
            leaf =
              typeof k === 'number' ? Array.from({ length: k + 1 }, () => leaf) : { [k]: leaf };
          expect(valid({ services: { a: { image: IMG, 'x-any': leaf } } })).toBe(false);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  it('only loopback published ports are accepted', () => {
    fc.assert(
      fc.property(
        fc.ipV4(),
        fc.integer({ min: 1, max: 65535 }),
        fc.integer({ min: 1, max: 65535 }),
        (ip, h, c) => {
          const ok = valid({ services: { a: { image: IMG, ports: [`${ip}:${h}:${c}`] } } });
          expect(ok).toBe(ip === '127.0.0.1');
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });

  it('accepts a minimal hardened document (sanity: the property is not vacuous)', () => {
    expect(
      valid({
        services: { app: { image: IMG, ports: ['127.0.0.1:20001:3000'], volumes: ['data:/data'] } },
        volumes: { data: {} },
      }),
    ).toBe(true);
  });
});

describe('validateComposeDocument — former KNOWN GAPS (P7.02 follow-up regression guards)', () => {
  for (const [name, bad] of KNOWN_GAPS)
    it(`rejects: ${name}`, () => {
      expect(valid({ services: { app: { image: IMG, ...(bad as object) } } })).toBe(false);
    });
  it('rejects privileged injected through an x- extension + resolved << merge', () => {
    const ext = { privileged: 'yes' };
    expect(
      valid({ 'x-base': ext, services: { app: Object.assign({}, ext, { image: IMG }) } }),
    ).toBe(false);
  });
  it('rejects every former gap also in development mode (dangerous keys are not just "unknown")', () => {
    for (const [name, bad] of KNOWN_GAPS) {
      if (name.includes('(production)')) continue;
      const r = validateComposeDocument(
        { services: { app: { image: IMG, ...(bad as object) } } },
        { environment: 'development' },
      );
      expect(r.valid, name).toBe(false);
    }
  });
  it('unknown keys and extra_hosts are warnings outside production', () => {
    const r = validateComposeDocument(
      { services: { app: { image: IMG, extra_hosts: ['a:10.0.0.1'], cap_drop: ['ALL'] } } },
      { environment: 'development' },
    );
    expect(r.valid).toBe(true);
    expect(r.warnings.map((w) => w.rule).sort()).toEqual(
      expect.arrayContaining(['extra_hosts', 'service_key_unsupported']),
    );
  });
  it('accepts safe values of policy-checked keys; other known-but-unexecuted keys are unsupported', () => {
    const ok = validateComposeDocument(
      {
        services: {
          app: {
            image: IMG,
            privileged: false,
            ipc: 'private',
            cap_add: ['NET_BIND_SERVICE'],
            security_opt: ['no-new-privileges:true'],
          },
        },
      },
      { environment: 'production' },
    );
    expect(ok.violations).toEqual([]);
    const r = validateComposeDocument(
      { services: { app: { image: IMG, network_mode: 'bridge', cap_drop: ['ALL'] } } },
      { environment: 'production' },
    );
    expect(r.violations.map((v) => v.rule)).toEqual([
      'service_key_unsupported',
      'service_key_unsupported',
    ]);
  });
  it('accepts tmpfs volumes without a source and local tmpfs top-level volumes', () => {
    expect(
      valid({
        services: {
          app: { image: IMG, volumes: [{ type: 'tmpfs', target: '/tmp' }, 'data:/data'] },
        },
        volumes: {
          data: { driver: 'local', driver_opts: { type: 'tmpfs', device: 'tmpfs', o: 'size=64m' } },
        },
      }),
    ).toBe(true);
  });
  for (const [name, top] of TOP_GAPS)
    it(`rejects: ${name}`, () => {
      // the same document without the top-level construct is valid (the rejection is not vacuous)
      expect(valid({ services: { app: { image: IMG, volumes: ['data:/data'] } } })).toBe(true);
      expect(valid({ services: { app: { image: IMG, volumes: ['data:/data'] } }, ...top })).toBe(
        false,
      );
    });
  it('a single-letter short volume source is a Windows drive (compose-go semantics) → host bind', () => {
    expect(valid({ services: { app: { image: IMG, volumes: ['v:/data'] } } })).toBe(false);
  });
});

// Follow-up found by the validator fix review: top-level volume `external` / `name` overrides could
// attach another app's or a host-managed volume if an executor ever honoured them.
describe('top-level volumes cannot be external or renamed', () => {
  const base = (vol: Record<string, unknown>) => ({
    services: {
      app: { image: `registry.lab/app@sha256:${'a'.repeat(64)}`, volumes: ['data:/data'] },
    },
    volumes: { data: vol },
  });
  it.each([
    [{ external: true }],
    [{ external: 'yes' }],
    [{ external: { name: 'other-app-data' } }],
    [{ name: 'ppanel-otherapp-data' }],
  ])('rejects %j', (vol) => {
    const r = validateComposeDocument(base(vol), { environment: 'development' });
    expect(r.violations.map((v) => v.rule)).toContain('volume_external');
  });
  it('accepts a plain local volume', () => {
    const r = validateComposeDocument(base({}), { environment: 'development' });
    expect(r.violations.filter((v) => v.rule === 'volume_external')).toEqual([]);
  });
});
