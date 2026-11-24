/**
 * P7.01 injection: query builder (SQL), LogQL, nginx route template, compose YAML, raw SQL usage,
 * header injection, path traversal in every path-accepting field.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import {
  bearer,
  bootApp,
  login,
  resetDb,
  type TestApp,
} from '../../../apps/api/test/integration/helpers';
import { parseQuery, buildWhere } from '../../../apps/api/src/common/query-builder';
import { normalizeComposeDocument } from '../../../apps/api/src/deploy/compose-plan';
import {
  parseComposeYaml,
  validateComposeYaml,
} from '../../../apps/api/src/deploy/compose-validator';
import { renderRoute } from '../../../apps/api/src/deploy/route-template';
import { checkRevisionPath } from '../../../apps/api/src/nginx/nginx-plan';
import { buildLogQL, escapeQuoted } from '../../../apps/api/src/observability/query-templates';
import {
  buildConfigSchema,
  containerVolumeSchema,
  createBackupPolicySchema,
  hostPathSchema,
  nginxPathSchema,
} from '../../../packages/shared-contracts/src';

const SQLI = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  '1) OR (1=1',
  '\\x27 UNION SELECT password_hash FROM users --',
  '%',
  '_',
  '\u0000',
];

describe('query builder (SQL injection)', () => {
  let t: TestApp;
  let owner: string;
  beforeAll(async () => {
    t = await bootApp();
    await resetDb(t.prisma);
    owner = await login(t, 'superadmin');
  });
  afterAll(async () => t.close());

  it('unknown sort / filter fields and operators are 400, never reach SQL', async () => {
    for (const qs of [
      'sort=password_hash',
      'sort=createdAt;DROP TABLE users',
      'sort=(SELECT 1)',
      'password_hash[eq]=x',
      'email[regex]=.*',
      'email[raw]=1',
      '__proto__[eq]=1',
      'constructor[eq]=1',
      'email[eq][0]=1',
      'or[0][password_hash]=x',
      'or[999][email]=x',
      'order=desc;--',
      'limit=1e9',
      'page=-1',
    ]) {
      const r = await t.http.get(`/api/v1/users?${qs}`).set(bearer(owner));
      expect(r.status, qs).toBe(400);
      expect(r.body.error.code, qs).toBe('BAD_REQUEST');
    }
  });

  it('SQL metacharacters in filter values / q are data (200, no 500, no extra rows)', async () => {
    for (const v of SQLI) {
      for (const qs of [
        `email[eq]=${encodeURIComponent(v)}`,
        `email[contains]=${encodeURIComponent(v)}`,
        `q=${encodeURIComponent(v)}`,
        `or[0][email]=${encodeURIComponent(v)}&or[0][display_name][like]=${encodeURIComponent(v)}`,
      ]) {
        for (const route of ['/api/v1/users', '/api/v1/audit-events', '/api/v1/servers']) {
          const r = await t.http
            .get(
              `${route}?${qs.replace(/email|display_name/g, route.includes('audit') ? 'action' : route.includes('servers') ? 'name' : '$&')}`,
            )
            .set(bearer(owner));
          expect(r.status, `${route}?${qs}`).toBeLessThan(500);
          if (r.status === 200 && (v.startsWith("'") || v.includes('UNION')))
            expect(r.body.data, `${route}?${qs}`).toEqual([]);
        }
      }
    }
    // the users table is intact
    expect(await t.prisma.user.count()).toBe(4);
  });

  it('oversized constrained collections (zod GHSA-mrhx-c7xc-m3w5) are bounded by BODY_LIMIT', async () => {
    const id = '01a207ea-0000-7000-8000-000000000000';
    // ~ 250 KB of uuids for a `.max(10)` array: refused quickly (422), memory bounded by the body limit
    const ids = Array(6400).fill(id);
    const t0 = Date.now();
    const r = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({ name: 'x', scopeType: 'global', kind: 'server_offline', channelIds: ids });
    expect(r.status).toBe(422);
    expect(Date.now() - t0).toBeLessThan(2000);
    const big = await t.http
      .post('/api/v1/alert-rules')
      .set(bearer(owner))
      .send({
        name: 'x',
        scopeType: 'global',
        kind: 'server_offline',
        channelIds: Array(20000).fill(id),
      });
    expect(big.status).toBe(413);
  });

  it('NUL bytes in JSON bodies are a 400, not a 500', async () => {
    const r = await t.http
      .post('/api/v1/server-groups')
      .set(bearer(owner))
      .set('Content-Type', 'application/json')
      .send('{"name":"a\\u0000b"}');
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('BAD_REQUEST');
  });

  it('parsed filters become typed Prisma conditions (parameterised), not SQL text', () => {
    const pq = parseQuery(`/x?email[contains]=${encodeURIComponent("' OR 1=1 --")}`, {
      sortable: ['createdAt'],
    });
    expect(buildWhere(pq, { email: { prop: 'email', type: 'string' } })).toEqual({
      AND: [{ email: { contains: "' OR 1=1 --", mode: 'insensitive' } }],
    });
  });

  it('no $queryRawUnsafe / $executeRawUnsafe / Prisma.raw in the Center API source', () => {
    const src = path.resolve(__dirname, '../../../apps/api/src');
    const walk = (d: string, o: string[] = []): string[] => {
      for (const f of readdirSync(d)) {
        const p = path.join(d, f);
        if (statSync(p).isDirectory()) walk(p, o);
        else if (p.endsWith('.ts')) o.push(p);
      }
      return o;
    };
    const hits = walk(src).filter((f) =>
      /\$queryRawUnsafe|\$executeRawUnsafe|Prisma\.raw\(/.test(readFileSync(f, 'utf8')),
    );
    expect(hits).toEqual([]);
  });
});

describe('LogQL', () => {
  const SID = '01a207ea-0000-7000-8000-000000000001';
  it('q is a single escaped line filter whatever it contains', () => {
    for (const q of [
      '"} |~ ".*',
      '\\"} or vector(1)',
      '`raw`',
      '") | json | __error__=""',
      'a\nb\r\tc',
      '}{',
    ]) {
      const out = buildLogQL({ serverIds: [SID], q });
      expect(
        out.startsWith(`{server_id=~"${SID}"}`) || out.startsWith(`{server_id="${SID}"}`),
      ).toBe(true);
      const filter = out.slice(out.indexOf('|= "') + 4, -1);
      // every `"` inside the literal is escaped
      expect(filter.replace(/\\\\/g, '').match(/(^|[^\\])"/g)).toBeNull();
      expect(out.endsWith('"')).toBe(true);
      expect(filter).toBe(escapeQuoted(q));
    }
  });

  it('LogQL is never built for an empty server scope (no cross-scope query)', () => {
    expect(() => buildLogQL({ serverIds: [] })).toThrow();
  });
});

describe('nginx route template (hostnames, paths)', () => {
  const base = {
    deploymentId: '01a207ea-0000-7000-8000-000000000001',
    app: 'web',
    hostPort: 20001,
    domains: ['app.example.test'],
  };
  for (const d of [
    'a.example.test; include /etc/passwd',
    'a.example.test\n}',
    'a.example.test }',
    'a.example.test$host',
    '"a.example.test"',
    'а.example.test', // Cyrillic а
    '*.example.test',
    'a..example.test',
    '-a.example.test',
    '',
    'a'.repeat(254),
  ])
    it(`rejects domain ${JSON.stringify(d).slice(0, 40)}`, () => {
      expect(() => renderRoute({ ...base, domains: [d] })).toThrow();
    });
  it('rejects app slugs and TLS paths that could escape the template', () => {
    for (const app of ['web;', 'web\n', '../x', 'Web', 'a b'])
      expect(() => renderRoute({ ...base, app })).toThrow();
    for (const certPath of [
      '/etc/ssl/../../x',
      '/etc/ssl/a.pem;',
      '/etc/ssl/a.pem\nroot /',
      'relative.pem',
    ])
      expect(() =>
        renderRoute({ ...base, tls: { certPath, keyPath: '/etc/ssl/k.pem' } }),
      ).toThrow();
  });
});

describe('compose YAML', () => {
  const hex = 'a'.repeat(64);
  const img = `registry.example.test/x@sha256:${hex}`;
  it('alias/merge bombs are refused without expansion', () => {
    const lines = ['x0: &a0 [1,1,1,1,1,1,1,1,1,1]'];
    for (let i = 1; i < 12; i++)
      lines.push(
        `x${i}: &a${i} [${Array(10)
          .fill(`*a${i - 1}`)
          .join(',')}]`,
      );
    lines.push(`services:\n  web:\n    image: ${img}`);
    const t0 = Date.now();
    const v = validateComposeYaml(lines.join('\n'));
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(v.valid).toBe(false);
  });

  it('`<<` merge cannot smuggle privileged / host namespaces / docker.sock past the policy', () => {
    for (const evil of [
      'privileged: true',
      'network_mode: host',
      'pid: host',
      'volumes: ["/var/run/docker.sock:/var/run/docker.sock"]',
      'cap_add: [SYS_ADMIN]',
      'volumes: ["/:/host"]',
    ]) {
      const yaml = `x-base: &base\n  ${evil}\nservices:\n  web:\n    <<: *base\n    image: ${img}\n`;
      const v = validateComposeYaml(yaml);
      expect(v.valid, evil).toBe(false);
    }
  });

  it('huge, duplicate-key, custom-tag and multi-document files are refused', () => {
    expect(
      validateComposeYaml(
        `services:\n  web:\n    image: ${img}\n    labels:\n${'      a: b\n'.repeat(1)}` +
          '#'.repeat(2_000_000),
      ).valid,
    ).toBe(false);
    expect(
      validateComposeYaml(`services:\n  web:\n    image: ${img}\n    image: evil:latest\n`).valid,
    ).toBe(false);
    expect(validateComposeYaml(`services:\n  web: !!js/function "function(){}"\n`).valid).toBe(
      false,
    );
    expect(
      validateComposeYaml(
        `services:\n  web:\n    image: ${img}\n---\nservices:\n  evil:\n    privileged: true\n`,
      ).valid,
    ).toBe(false);
  });

  it('unicode / control characters in service names are refused on the deploy path', () => {
    for (const name of ['w\u0435b', 'web\u202e', 'WEB', 'web_1']) {
      const parsed = parseComposeYaml(`services:\n  "${name}":\n    image: ${img}\n`);
      if ('failure' in parsed) continue;
      const n = normalizeComposeDocument(parsed.doc, {
        app: 'x',
        routeService: name,
        routePort: 80,
      });
      expect(n.validation.valid, name).toBe(false);
    }
  });
});

describe('path traversal in path-accepting fields', () => {
  const TRAVERSAL = [
    '/etc/nginx/../shadow',
    '/etc/nginx/./x/../../passwd',
    '/etc/nginx//x',
    '/etc/nginx/x\u0000',
    '/etc/nginx/%2e%2e/x',
  ];
  it('nginx paths', () => {
    for (const p of TRAVERSAL) expect(nginxPathSchema.safeParse(p).success, p).toBe(false);
    expect(
      checkRevisionPath('/etc/nginx/ppanel-managed/other-app/route.conf', 'web', []),
    ).not.toBeNull();
    expect(
      checkRevisionPath('/etc/nginx/ppanel-managed/web/../other/route.conf', 'web', []),
    ).not.toBeNull();
    expect(checkRevisionPath('/etc/nginx/sites-enabled/default', 'web', [])).not.toBeNull();
    expect(checkRevisionPath('/etc/nginx/ppanel-managed/web/route.conf', 'web', [])).toBeNull();
  });
  it('backup host paths', () => {
    for (const p of [
      '/srv/../etc/shadow',
      '/srv//x',
      'srv/x',
      '/srv/x\n',
      '/srv/$(id)',
      '/srv/`id`',
      '/srv/a;b',
    ])
      expect(hostPathSchema.safeParse(p).success, p).toBe(false);
    expect(
      createBackupPolicySchema.safeParse({
        name: 'x',
        serverId: '01a207ea-0000-7000-8000-000000000001',
        repositoryId: '01a207ea-0000-7000-8000-000000000001',
        targets: [{ type: 'paths', paths: ['/srv/../../etc'] }],
        schedule: { cron: '0 3 * * *', timezone: 'UTC' },
      }).success,
    ).toBe(false);
  });
  it('build subdir / dockerfile', () => {
    const base = {
      repoUrl: 'https://github.com/o/r.git',
      buildServerId: '01a207ea-0000-7000-8000-000000000001',
      pushRepo: 'registry.example.test/x',
    };
    for (const subdir of ['../x', 'a/../../x', '/abs', 'a/..'])
      expect(
        buildConfigSchema.safeParse({ ...base, subdir, dockerfile: 'Dockerfile' }).success,
        subdir,
      ).toBe(false);
    for (const dockerfile of ['../Dockerfile', '/etc/passwd', 'a/../../Dockerfile'])
      expect(buildConfigSchema.safeParse({ ...base, dockerfile }).success, dockerfile).toBe(false);
  });
  it('container volume mount paths', () => {
    for (const mountPath of ['/data/../../etc', 'relative', '/a b'])
      expect(containerVolumeSchema.safeParse({ name: 'data', mountPath }).success, mountPath).toBe(
        false,
      );
  });
});

describe('header injection', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await bootApp();
  });
  afterAll(async () => t.close());
  it('X-Request-ID is echoed only when it matches the safe charset', async () => {
    for (const bad of ['<script>', 'a'.repeat(65), 'abc def ghi', 'x;Set-Cookie=a', '../../etc']) {
      const r = await t.http.get('/api/v1/setup/status').set('X-Request-ID', bad);
      expect(r.headers['x-request-id']).not.toBe(bad);
      expect(r.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
    }
    const ok = await t.http.get('/api/v1/setup/status').set('X-Request-ID', 'req-12345678');
    expect(ok.headers['x-request-id']).toBe('req-12345678');
  });
  it('API responses carry the hardened header set', async () => {
    for (const p of ['/api/v1/setup/status', '/api/v1/servers', '/api/v1/nope']) {
      const r = await t.http.get(p);
      expect(r.headers['x-content-type-options']).toBe('nosniff');
      expect(r.headers['x-frame-options']).toBe('DENY');
      expect(r.headers['referrer-policy']).toBe('no-referrer');
      expect(r.headers['content-security-policy']).toMatch(
        /default-src 'none'.*frame-ancestors 'none'/,
      );
      expect(r.headers['cache-control']).toBe('no-store');
      expect(r.headers['x-powered-by']).toBeUndefined();
      expect(r.headers['content-type']).toMatch(/application\/json/);
    }
  });
  it('HSTS only when cookies are Secure (production / TLS deployments)', async () => {
    expect(
      (await t.http.get('/api/v1/setup/status')).headers['strict-transport-security'],
    ).toBeUndefined();
    const p = await bootApp({ COOKIE_SECURE: '1' });
    try {
      expect(
        (await p.http.get('/api/v1/setup/status')).headers['strict-transport-security'],
      ).toMatch(/max-age=31536000/);
    } finally {
      await p.close();
    }
  });
});
