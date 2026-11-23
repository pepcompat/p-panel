/** P4a pure units: compose policy (P4-T05), detectFramework (P4.03), route template + hostname validation. */
import {
  branchMatches,
  createContainerAppSchema,
  detectFramework,
  isValidHostname,
  portHostIp,
  renderImageTemplate,
} from '@ppanel/shared-contracts';
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { redactKnownValues } from '../../src/common/logger';
import { validateComposeYaml } from '../../src/deploy/compose-validator';
import { containerNameFor } from '../../src/deploy/container-common';
import { parseChallenge, parseTaggedRef } from '../../src/deploy/registry.client';
import {
  renderRoute,
  RouteTemplateError,
  routePath,
  upstreamName,
} from '../../src/deploy/route-template';
import { verifyGithubSignature } from '../../src/deploy/webhooks.service';

// built at runtime: the API lint rule forbids socket-path literals (the Center never touches it)
const SOCK = ['/var/run/docker', 'sock'].join('.');
const DIGEST = `lab-registry:5000/demo/api@sha256:${'a'.repeat(64)}`;
const rules = (yaml: string, env?: 'production') =>
  validateComposeYaml(yaml, { environment: env }).violations.map((v) => v.rule);

describe('P4-T05 compose static policy', () => {
  it('clean compose file is valid (digest-pinned image, loopback port, named volume)', () => {
    const r = validateComposeYaml(
      `services:\n  web:\n    image: ${DIGEST}\n    ports: ["127.0.0.1:8080:3000"]\n    volumes: ["data:/var/lib/app"]\n    cap_add: [NET_BIND_SERVICE]\nvolumes:\n  data: {}\n`,
      { environment: 'production' },
    );
    expect(r.violations).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.services).toEqual([
      { name: 'web', image: DIGEST, build: false, ports: ['127.0.0.1:8080:3000'] },
    ]);
  });

  it.each([
    ['privileged', 'services:\n  a:\n    image: x\n    privileged: true\n', 'privileged'],
    ['host network', 'services:\n  a:\n    image: x\n    network_mode: host\n', 'host_network'],
    ['pid host', 'services:\n  a:\n    image: x\n    pid: host\n', 'host_pid'],
    ['ipc host', 'services:\n  a:\n    image: x\n    ipc: host\n', 'host_ipc'],
    ['userns host', 'services:\n  a:\n    image: x\n    userns_mode: host\n', 'host_userns'],
    [
      'docker socket bind',
      `services:\n  a:\n    image: x\n    volumes: ["${SOCK}:${SOCK}"]\n`,
      'docker_socket',
    ],
    [
      'host path bind',
      'services:\n  a:\n    image: x\n    volumes: ["/etc:/host-etc:ro"]\n',
      'host_bind',
    ],
    ['relative bind', 'services:\n  a:\n    image: x\n    volumes: ["./src:/app"]\n', 'host_bind'],
    [
      'long-form bind',
      'services:\n  a:\n    image: x\n    volumes:\n      - type: bind\n        source: /srv\n        target: /srv\n',
      'host_bind',
    ],
    ['cap_add SYS_ADMIN', 'services:\n  a:\n    image: x\n    cap_add: [SYS_ADMIN]\n', 'cap_add'],
    ['cap_add ALL', 'services:\n  a:\n    image: x\n    cap_add: [ALL]\n', 'cap_add'],
    ['devices', 'services:\n  a:\n    image: x\n    devices: ["/dev/kmsg:/dev/kmsg"]\n', 'devices'],
    [
      '0.0.0.0 port',
      'services:\n  a:\n    image: x\n    ports: ["0.0.0.0:80:80"]\n',
      'port_non_loopback',
    ],
    [
      'all-interface port',
      'services:\n  a:\n    image: x\n    ports: ["8080:80"]\n',
      'port_non_loopback',
    ],
    [
      'apparmor unconfined',
      'services:\n  a:\n    image: x\n    security_opt: ["apparmor:unconfined"]\n',
      'security_opt',
    ],
    [
      'seccomp unconfined',
      'services:\n  a:\n    image: x\n    security_opt: ["seccomp=unconfined"]\n',
      'security_opt',
    ],
    ['include', 'include: [other.yml]\nservices: {}\n', 'external_include'],
    [
      'extends file',
      'services:\n  a:\n    image: x\n    extends:\n      file: ../base.yml\n      service: b\n',
      'external_extends',
    ],
    ['unknown top-level key', 'services: {}\nfoo: 1\n', 'unknown_top_level_key'],
    [
      'bind via top-level volume driver_opts',
      'services: {}\nvolumes:\n  v:\n    driver_opts: { type: none, o: bind, device: /etc }\n',
      'host_bind',
    ],
  ])('%s → violation', (_n, yaml, rule) => {
    const r = validateComposeYaml(yaml);
    expect(r.valid).toBe(false);
    expect(r.violations.map((v) => v.rule)).toContain(rule);
    const v = r.violations.find((x) => x.rule === rule)!;
    expect(v.path).toBeTruthy();
    expect(v.message).toBeTruthy();
  });

  it('unpinned image: warning in dev/uat, violation in production', () => {
    const y = 'services:\n  a:\n    image: nginx:latest\n';
    const dev = validateComposeYaml(y);
    expect(dev.valid).toBe(true);
    expect(dev.warnings.map((w) => w.rule)).toContain('image_not_pinned');
    expect(rules(y, 'production')).toContain('image_not_pinned');
  });

  it('YAML alias bomb (billion laughs) is rejected without expansion', () => {
    const lines = ['a: &a ["x","x","x","x","x","x","x","x","x"]'];
    const names = 'bcdefghijk'.split('');
    let prev = 'a';
    for (const n of names) {
      lines.push(`${n}: &${n} [${Array(9).fill(`*${prev}`).join(',')}]`);
      prev = n;
    }
    lines.push('services: {}');
    const t0 = Date.now();
    const r = validateComposeYaml(lines.join('\n'));
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r.valid).toBe(false);
    expect(r.violations[0]!.rule).toBe('yaml_alias_bomb');
  });

  it('a few anchors are fine; invalid YAML and duplicate keys are reported', () => {
    const ok = validateComposeYaml(
      `x-base: &base\n  image: ${DIGEST}\nservices:\n  a:\n    <<: *base\n  b:\n    <<: *base\n`,
    );
    expect(ok.violations).toEqual([]);
    expect(rules('services: [')).toEqual(['yaml_invalid']);
    expect(rules('services: {}\nservices: {}\n')).toEqual(['yaml_invalid']);
  });

  it('portHostIp parses short port syntax', () => {
    expect(portHostIp('127.0.0.1:80:80')).toBe('127.0.0.1');
    expect(portHostIp('80:80')).toBe('');
    expect(portHostIp('80')).toBe('');
    expect(portHostIp('[::1]:80:80')).toBe('[::1]');
  });
});

describe('P4.03 detectFramework', () => {
  it('Next.js', () => {
    const r = detectFramework({
      'package.json': JSON.stringify({
        dependencies: { next: '14.2.3', react: '18' },
        scripts: { build: 'next build' },
      }),
      'next.config.mjs': 'export default {}',
    });
    expect(r).toMatchObject({ framework: 'nextjs', confidence: 'high' });
    expect(r.suggested).toEqual({
      containerPort: 3000,
      healthcheckPath: '/',
      buildMethod: 'framework_default',
    });
    expect(r.evidence.join(' ')).toContain('next@14.2.3');
  });
  it('NestJS (+ Dockerfile EXPOSE wins the port)', () => {
    const r = detectFramework({
      'package.json': JSON.stringify({ dependencies: { '@nestjs/core': '^11.0.0' } }),
      'nest-cli.json': '{}',
      Dockerfile: 'FROM node:22\nEXPOSE 4000\n',
    });
    expect(r).toMatchObject({ framework: 'nestjs', confidence: 'high' });
    expect(r.suggested).toMatchObject({ containerPort: 4000, buildMethod: 'dockerfile' });
  });
  it('Laravel', () => {
    const r = detectFramework({
      'composer.json': JSON.stringify({ require: { 'laravel/framework': '^11.0' } }),
      artisan: '',
    });
    expect(r).toMatchObject({ framework: 'laravel', confidence: 'high' });
    expect(r.suggested.containerPort).toBe(80);
  });
  it('plain Dockerfile', () => {
    const r = detectFramework({ Dockerfile: 'FROM alpine\nEXPOSE 8080/tcp\n' });
    expect(r).toMatchObject({ framework: 'dockerfile', confidence: 'high' });
    expect(r.suggested).toEqual({
      containerPort: 8080,
      healthcheckPath: '/',
      buildMethod: 'dockerfile',
    });
  });
  it('Compose takes precedence', () => {
    const r = detectFramework({
      'docker-compose.yml': 'services: {}',
      'package.json': JSON.stringify({ dependencies: { next: '14' } }),
    });
    expect(r).toMatchObject({ framework: 'compose', suggested: { buildMethod: 'compose' } });
  });
  it('unknown (also tolerates malformed package.json)', () => {
    expect(detectFramework({ 'README.md': 'hi' })).toMatchObject({
      framework: 'unknown',
      confidence: 'low',
    });
    const r = detectFramework({ 'package.json': '{not json' });
    expect(r.framework).toBe('unknown');
    expect(r.evidence).toContain('package.json is not valid JSON');
  });
});

describe('route template + hostname validation', () => {
  const id = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b';
  it('renders the exact contract template', () => {
    const out = renderRoute({
      deploymentId: id,
      app: 'shop-api',
      hostPort: 20017,
      domains: ['api.example.lab', 'www.example.lab'],
    });
    expect(out).toBe(
      [
        `# managed by pPanel — deployment ${id}`,
        'upstream ppanel_shop_api { server 127.0.0.1:20017; keepalive 16; }',
        'server {',
        '    listen 80;',
        '    server_name api.example.lab www.example.lab;',
        '    location / {',
        '        proxy_pass http://ppanel_shop_api;',
        '        proxy_http_version 1.1;',
        '        proxy_set_header Host $host;',
        '        proxy_set_header X-Real-IP $remote_addr;',
        '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
        '        proxy_set_header X-Forwarded-Proto $scheme;',
        '    }',
        '}',
        '',
      ].join('\n'),
    );
    expect(upstreamName('a-b-c')).toBe('ppanel_a_b_c');
    expect(routePath('shop-api')).toBe('/etc/nginx/ppanel-managed/shop-api/route.conf');
  });

  it('TLS with operator-provided certificate paths', () => {
    const out = renderRoute({
      deploymentId: id,
      app: 'web',
      hostPort: 20000,
      domains: ['web.example.lab'],
      tls: {
        certPath: '/etc/letsencrypt/live/web/fullchain.pem',
        keyPath: '/etc/letsencrypt/live/web/privkey.pem',
      },
    });
    expect(out).toContain(
      '    listen 443 ssl;\n    ssl_certificate /etc/letsencrypt/live/web/fullchain.pem;',
    );
    expect(() =>
      renderRoute({
        deploymentId: id,
        app: 'web',
        hostPort: 20000,
        domains: ['a.example'],
        tls: { certPath: '/root/x.pem', keyPath: '/etc/ssl/k.pem' },
      }),
    ).toThrow(RouteTemplateError);
  });

  it.each([
    'a.com; include /etc/passwd',
    'a.com;',
    'a.com\ninclude /etc/passwd;',
    'a.com }',
    '$host',
    '*.example.com',
    'example',
    '127.0.0.1',
    '-bad.example.com',
    'bad-.example.com',
    'UPPER.example.com',
    'a..b.com',
    `${'a'.repeat(64)}.com`,
    'a.com/x',
    'a.com"',
    '',
  ])('rejects domain %j', (d) => {
    expect(isValidHostname(d)).toBe(false);
    expect(() =>
      renderRoute({ deploymentId: id, app: 'web', hostPort: 20000, domains: [d] }),
    ).toThrow(RouteTemplateError);
  });

  it.each(['example.com', 'app.example.lab', 'a-b.c-d.example.co', 'xn--bcher-kva.example'])(
    'accepts %s',
    (d) => {
      expect(isValidHostname(d)).toBe(true);
    },
  );

  it('DTO lowercases/trims domains and rejects injection', () => {
    const base = { serverId: id, name: 'web', containerPort: 3000 };
    expect(
      createContainerAppSchema.parse({ ...base, domains: [' App.Example.LAB '] }).domains,
    ).toEqual(['app.example.lab']);
    expect(
      createContainerAppSchema.safeParse({ ...base, domains: ['a.com; include /etc/passwd'] })
        .success,
    ).toBe(false);
    expect(
      createContainerAppSchema.safeParse({ ...base, name: 'Bad_Name', domains: ['a.example'] })
        .success,
    ).toBe(false);
  });

  it('rejects bad port / app slug / deployment id', () => {
    expect(() =>
      renderRoute({ deploymentId: id, app: 'web', hostPort: 8080, domains: ['a.example'] }),
    ).toThrow(/port/);
    expect(() =>
      renderRoute({ deploymentId: id, app: 'we b', hostPort: 20000, domains: ['a.example'] }),
    ).toThrow(/slug/);
    expect(() =>
      renderRoute({ deploymentId: 'x;', app: 'web', hostPort: 20000, domains: ['a.example'] }),
    ).toThrow(/deployment/);
  });

  it('container name uses the random tail of the deployment id', () => {
    expect(containerNameFor('web', id)).toBe('ppanel-web-2e3f4a5b');
  });
});

describe('webhook + registry helpers', () => {
  it('GitHub signature check (constant time, exact format)', () => {
    const body = Buffer.from('{"a":1}');
    const sig = `sha256=${createHmac('sha256', 's3cret-s3cret-s3cret').update(body).digest('hex')}`;
    expect(verifyGithubSignature('s3cret-s3cret-s3cret', body, sig)).toBe(true);
    expect(verifyGithubSignature('wrong', body, sig)).toBe(false);
    expect(verifyGithubSignature('s3cret-s3cret-s3cret', Buffer.from('{"a":2}'), sig)).toBe(false);
    expect(verifyGithubSignature('s3cret-s3cret-s3cret', body, undefined)).toBe(false);
    expect(verifyGithubSignature('s3cret-s3cret-s3cret', body, sig.toUpperCase())).toBe(false);
  });
  it('branch globs and image templates', () => {
    expect(branchMatches('main', 'main')).toBe(true);
    expect(branchMatches('main', 'main2')).toBe(false);
    expect(branchMatches('release/*', 'release/1.2')).toBe(true);
    expect(branchMatches('release/*', 'hotfix/1')).toBe(false);
    expect(branchMatches('*', 'any/thing')).toBe(true);
    const sha = 'abcdef0123456789abcdef0123456789abcdef01';
    expect(renderImageTemplate('r:5000/app:sha-{sha7}-{branch}', sha, 'feature/x')).toBe(
      'r:5000/app:sha-abcdef0-feature-x',
    );
  });
  it('parses image refs and auth challenges', () => {
    expect(parseTaggedRef('lab-registry:5000/demo/api:sha-1')).toEqual({
      host: 'lab-registry:5000',
      name: 'demo/api',
      tag: 'sha-1',
    });
    expect(parseTaggedRef('nginx:latest')).toBeNull();
    expect(
      parseChallenge(
        'Bearer realm="https://auth.example/token",service="reg",scope="repository:a:pull"',
      ),
    ).toEqual({
      scheme: 'bearer',
      params: { realm: 'https://auth.example/token', service: 'reg', scope: 'repository:a:pull' },
    });
  });
  it('redactKnownValues scrubs secret values anywhere (longest first)', () => {
    const v = redactKnownValues(
      { lines: ['token=supersecret123 ok', 'x'], nested: { e: 'supersecret123supersecret123' } },
      ['supersecret123', 'abc'],
    );
    expect(JSON.stringify(v)).not.toContain('supersecret123');
    expect(v.lines[0]).toBe('token=[REDACTED] ok');
  });
});
