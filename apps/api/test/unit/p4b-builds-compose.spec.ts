import {
  buildConfigSchema,
  createBuildSchema,
  createComposeAppSchema,
  createDeploymentSchema,
  autoDeployPolicySchema,
  gitAuthHeader,
  JOB_TYPES,
} from '@ppanel/shared-contracts';
import { describe, expect, it } from 'vitest';
import { boundLog, gitHostAllowed, gitHostOf } from '../../src/deploy/builds.service';
import { repoOf } from '../../src/deploy/build-common';
import {
  composeApplyParamsOf,
  composeContainerName,
  composeSpecHash,
  imageRepoName,
  inferHealth,
  normalizeComposeDocument,
  topoSort,
} from '../../src/deploy/compose-plan';
import { parseComposeYaml } from '../../src/deploy/compose-validator';
import { resourceKeyFor, RESTRICTED_JOB_TYPES } from '../../src/jobs/jobs.service';

const D = (c: string) => `busybox@sha256:${c.repeat(64)}`;
const route = { app: 'shop', routeService: 'web', routePort: 3000 };

function norm(yaml: string, opts: Partial<Parameters<typeof normalizeComposeDocument>[1]> = {}) {
  const p = parseComposeYaml(yaml);
  if ('failure' in p) throw new Error(JSON.stringify(p.failure));
  return normalizeComposeDocument(p.doc, { ...route, ...opts });
}
const rules = (n: ReturnType<typeof norm>) => n.validation.violations.map((v) => v.rule);

describe('P4b compose normalisation', () => {
  it('maps env/secretEnv, infers health, sorts by depends_on', () => {
    const n = norm(`
services:
  web:
    image: reg.example.com/acme/web:1.0
    environment: ["A=1", "TOKEN=\${API_TOKEN}", "DOLLAR=$$HOME"]
    depends_on: { cache: { condition: service_healthy } }
    ports: ["127.0.0.1:8080:3000"]
  cache:
    image: redis@sha256:${'1'.repeat(64)}
  db:
    image: docker.io/library/postgres:16
`);
    expect(n.validation.valid).toBe(true);
    // stable Kahn order: file order among ready services, dependencies first
    expect(n.services.map((s) => s.service)).toEqual(['cache', 'web', 'db']);
    const web = n.services.find((s) => s.service === 'web')!;
    expect(web.env).toEqual({ A: '1', DOLLAR: '$HOME' });
    expect(web.secretEnv).toEqual({ TOKEN: 'API_TOKEN' });
    expect(web.health).toMatchObject({ type: 'http', port: 3000, path: '/' });
    expect(web.containerPort).toBe(3000);
    expect(n.services[0]!.health).toEqual({ type: 'tcp', port: 6379, startPeriodSec: 60 });
    expect(n.services.find((s) => s.service === 'db')!.health).toMatchObject({
      type: 'tcp',
      port: 5432,
    });
    expect(n.secretKeys).toEqual(['API_TOKEN']);
    expect(n.validation.warnings.map((w) => w.rule)).toEqual(
      expect.arrayContaining(['key_ignored', 'image_not_pinned']),
    );
  });

  it('rejects ports on non-route services, cycles, unknown deps, host env pass-through, embedded placeholders, anonymous/host volumes, unsupported keys, long names', () => {
    expect(
      rules(
        norm(
          `services:\n  web:\n    image: ${D('a')}\n  db:\n    image: ${D('b')}\n    ports: ["127.0.0.1:5432:5432"]\n`,
        ),
      ),
    ).toContain('ports_not_route_service');
    expect(
      rules(
        norm(
          `services:\n  web:\n    image: ${D('a')}\n    depends_on: [a]\n  a:\n    image: ${D('a')}\n    depends_on: [web]\n`,
        ),
      ),
    ).toContain('depends_on_cycle');
    expect(
      rules(norm(`services:\n  web:\n    image: ${D('a')}\n    depends_on: [nope]\n`)),
    ).toContain('depends_on_unknown');
    expect(
      rules(norm(`services:\n  web:\n    image: ${D('a')}\n    environment: [HOME]\n`)),
    ).toContain('env_interpolation');
    expect(
      rules(
        norm(`services:\n  web:\n    image: ${D('a')}\n    environment:\n      URL: "x\${P}y"\n`),
      ),
    ).toContain('env_interpolation');
    expect(
      rules(norm(`services:\n  web:\n    image: ${D('a')}\n    volumes: ["/data"]\n`)),
    ).toContain('volume_unsupported');
    expect(
      rules(norm(`services:\n  web:\n    image: ${D('a')}\n    volumes: ["./x:/data"]\n`)),
    ).toContain('host_bind');
    expect(
      rules(norm(`services:\n  web:\n    image: ${D('a')}\n    entrypoint: ["sh"]\n`)),
    ).toContain('service_key_unsupported');
    expect(rules(norm(`services:\n  web:\n    image: ${D('a')}\n    env_file: .env\n`))).toContain(
      'service_key_unsupported',
    );
    expect(rules(norm(`services:\n  web:\n    image: nginx:latest\n`))).toContain(
      'image_unresolvable',
    );
    expect(
      rules(
        norm(
          `services:\n  web:\n    image: ${D('a')}\n    environment:\n      K: "\${__GIT_TOKEN__}"\n`,
        ),
      ),
    ).toContain('env_key_invalid');
    expect(
      rules(norm(`services:\n  web:\n    image: ${D('a')}\n`, { app: 'a'.repeat(38) })),
    ).toContain('name_too_long');
    expect(rules(norm(`services:\n  api:\n    image: ${D('a')}\n`))).toContain(
      'route_service_missing',
    );
    expect(
      rules(
        norm(
          `services:\n  web:\n    image: ${D('a')}\n    environment:\n      K: "\${MISSING}"\n`,
          { existingSecrets: new Set(['OTHER']) },
        ),
      ),
    ).toContain('secret_missing');
  });

  it('topoSort reports a cycle path; spec hash covers digest and secret versions, not values', () => {
    const s = (service: string, dependsOn: string[]) => ({
      service,
      image: D('a'),
      env: {},
      secretEnv: {},
      volumes: [],
      dependsOn,
      health: { type: 'running' as const, startPeriodSec: 10 },
    });
    const r = topoSort([s('a', ['b']), s('b', ['c']), s('c', ['b'])]);
    expect(r).toEqual({ ok: false, cycle: ['b', 'c', 'b'] });
    const svc = { ...s('web', []), secretEnv: { T: 'TOKEN' }, resolvedImage: D('a') };
    const h1 = composeSpecHash(svc, { TOKEN: 1 });
    expect(composeSpecHash(svc, { TOKEN: 1 })).toBe(h1);
    expect(composeSpecHash(svc, { TOKEN: 2 })).not.toBe(h1);
    expect(composeSpecHash({ ...svc, resolvedImage: D('b') }, { TOKEN: 1 })).not.toBe(h1);
    expect(composeSpecHash(svc, { TOKEN: 1, UNRELATED: 5 })).toBe(h1);
    expect(composeContainerName('shop', 'web', '01900000-0000-7000-8000-000000000001')).toMatch(
      /^ppanel-shop-web-[a-f0-9]{8}$/,
    );
  });

  it('compose.apply params validate against the shared job schema (route service only gets a host port)', () => {
    const n = norm(
      `services:\n  web:\n    image: ${D('a')}\n    depends_on: [db]\n  db:\n    image: postgres@sha256:${'2'.repeat(64)}\n`,
    );
    const id = '01900000-0000-7000-8000-000000000001';
    const plan = {
      versionId: id,
      version: 1,
      routeService: 'web',
      services: n.services.map((s) => ({
        ...s,
        resolvedImage: s.image,
        specHash: 'a'.repeat(64),
        name: composeContainerName('shop', s.service, id),
        plannedAction: 'replace' as const,
        previousName: null,
      })),
    };
    const params = composeApplyParamsOf(id, 'shop', plan, 20001, false);
    const parsed = JOB_TYPES['compose.apply'].params.safeParse(params);
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
    expect(params.services.map((s) => [s.service, 'hostPort' in s ? s.hostPort : null])).toEqual([
      ['db', null],
      ['web', 20001],
    ]);
  });

  it('image repo name + inferred health', () => {
    expect(imageRepoName('docker.io/library/postgres:16')).toBe('postgres');
    expect(imageRepoName('reg:5000/bitnami/redis@sha256:' + 'a'.repeat(64))).toBe('bitnami/redis');
    expect(inferHealth('db', 'mariadb:11', { service: 'web', port: 80, path: '/' })).toMatchObject({
      type: 'tcp',
      port: 3306,
    });
    expect(inferHealth('x', 'busybox', { service: 'web', port: 80, path: '/' })).toEqual({
      type: 'running',
      startPeriodSec: 10,
    });
  });
});

describe('P4b builds helpers + contracts', () => {
  it('git host allowlist (host matches any port, host:port exact), repo derivation, no credentials in URLs', () => {
    expect(gitHostOf('https://github.com/acme/web.git')).toBe('github.com');
    expect(gitHostOf('https://user:pw@github.com/acme/web.git')).toBeNull();
    expect(gitHostAllowed('lab-git:3000', ['lab-git'])).toBe(true);
    expect(gitHostAllowed('lab-git:3000', ['lab-git:8080'])).toBe(false);
    expect(gitHostAllowed('github.com.evil.io', ['github.com'])).toBe(false);
    expect(repoOf('https://github.com/acme/web.git')).toBe('acme/web');
    expect(repoOf('https://lab-git/group/sub/web.git')).toBeNull();
  });

  it('boundLog strips ANSI, redacts known values, bounds lines/bytes', () => {
    const r = boundLog(['\u001b[31mtoken=abcdefgh123\u001b[0m', 'ok', 5], ['abcdefgh123']);
    expect(r).toEqual({ lines: ['token=[REDACTED]', 'ok'], truncated: false });
    const many = boundLog(
      Array.from({ length: 2500 }, (_, i) => `l${i}`),
      [],
    );
    expect(many.lines).toHaveLength(2000);
    expect(many.truncated).toBe(true);
    expect(many.lines.at(-1)).toBe('l2499');
    const big = boundLog(
      Array.from({ length: 1000 }, () => 'x'.repeat(1000)),
      [],
    );
    expect(big.truncated).toBe(true);
    expect(big.lines.length).toBeLessThan(530);
  });

  it('schemas: build config exactly one of dockerfile/template, commit sha, compose create, optional image, build-mode policy', () => {
    const base = {
      repoUrl: 'https://github.com/a/b.git',
      buildServerId: '01900000-0000-7000-8000-000000000001',
      pushRepo: 'reg.example.com/a/b',
    };
    expect(buildConfigSchema.safeParse({ ...base, template: 'nextjs' }).success).toBe(true);
    expect(buildConfigSchema.safeParse({ ...base }).success).toBe(false);
    expect(
      buildConfigSchema.safeParse({ ...base, template: 'nextjs', dockerfile: 'Dockerfile' })
        .success,
    ).toBe(false);
    expect(
      buildConfigSchema.safeParse({ ...base, template: 'nextjs', subdir: '../x' }).success,
    ).toBe(false);
    expect(
      buildConfigSchema.safeParse({
        ...base,
        template: 'nextjs',
        repoUrl: 'https://u:p@github.com/a/b',
      }).success,
    ).toBe(false);
    expect(createBuildSchema.parse({ commitSha: 'a'.repeat(40) })).toMatchObject({
      deployAfter: true,
      force: false,
    });
    expect(createBuildSchema.safeParse({ commitSha: 'A'.repeat(40) }).success).toBe(false);
    expect(
      createComposeAppSchema.safeParse({
        kind: 'compose',
        serverId: base.buildServerId,
        name: 'x',
        domains: ['x.example.com'],
        yaml: 'services: {}',
        routeService: 'web',
        routePort: 80,
      }).success,
    ).toBe(true);
    expect(createDeploymentSchema.safeParse({}).success).toBe(true);
    expect(
      autoDeployPolicySchema.parse({
        integrationId: base.buildServerId,
        repo: 'a/b',
        branches: ['main'],
        mode: 'build',
      }),
    ).toMatchObject({ mode: 'build' });
    expect(gitAuthHeader('t0k', (s) => Buffer.from(s).toString('base64'))).toBe(
      `Authorization: Basic ${Buffer.from('x-access-token:t0k').toString('base64')}`,
    );
  });

  it('P4b job types are Center-only and locked per app', () => {
    for (const t of ['image.build', 'source.inspect', 'compose.apply', 'compose.stop'] as const)
      expect(RESTRICTED_JOB_TYPES).toContain(t);
    expect(resourceKeyFor('compose.apply', { app: 'shop' })).toBe('app:shop');
    expect(resourceKeyFor('compose.stop', { app: 'shop' })).toBe('app:shop');
    expect(resourceKeyFor('image.build', { app: 'shop' })).toBe('build:shop');
    expect(resourceKeyFor('source.inspect', {})).toBeNull();
  });
});
