import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import {
  boundLog,
  buildArgIssues,
  buildNodeBlockReason,
  buildPhaseStates,
  buildSpecError,
  commitShaError,
  composeIssues,
  composePlan,
  deriveComposeServices,
  gitSourceIssues,
  gitUrlCheck,
  initialCompose,
  initialGitSource,
  inferHealth,
  scanComposeServices,
  toBuildConfig,
  BUILD_LOG_MAX_LINES,
} from '@/lib/p4b-gates';
import { BuildLogViewer } from '@/components/p4/build-execution';
import type { Application } from '@/lib/api/p3-types';
import type { Deployment } from '@/lib/api/p4-types';
import type { Build } from '@/lib/api/p4b-types';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import type { LoginSuccess } from '@/lib/api/types';
import { renderWith } from './test-utils';

const SHA = 'a'.repeat(40);
const ALLOW = ['github.com', 'git.example.lab'];
const node = {
  id: 'n1',
  status: 'online' as const,
  capabilities: ['docker', 'build'],
  buildNode: true,
};

function validGit() {
  return {
    ...initialGitSource(),
    repoUrl: 'https://github.com/w3co/shop-api.git',
    commitSha: SHA,
    template: 'nestjs' as const,
    buildServerId: 'n1',
    pushRepo: 'registry.example.lab/w3/shop-api',
  };
}

describe('Git source validation', () => {
  it('requires the full 40-hex lowercase commit SHA (branch is context only)', () => {
    expect(commitShaError(SHA)).toBeNull();
    expect(commitShaError('')).toBe('wiz.git.err.shaEmpty');
    expect(commitShaError('abc1234')).toBe('wiz.git.err.shaShort');
    expect(commitShaError('A'.repeat(40))).toBe('wiz.git.err.shaCase');
    expect(commitShaError('z'.repeat(40))).toBe('wiz.git.err.sha');
    const g = { ...validGit(), commitSha: 'abc1234', branch: 'main' };
    expect(gitSourceIssues(g, [node], ALLOW)).toContain('wiz.git.err.shaShort');
    expect(gitSourceIssues({ ...g, commitSha: SHA }, [node], ALLOW)).toEqual([]);
  });

  it('allowlist is a hint; credentials / http are refused', () => {
    expect(gitUrlCheck('https://github.com/w3co/x.git', ALLOW)).toMatchObject({
      error: null,
      allow: 'allowed',
    });
    expect(gitUrlCheck('https://bitbucket.org/w3co/x', ALLOW)).toMatchObject({
      error: null,
      allow: 'not_listed',
    });
    expect(gitUrlCheck('https://bitbucket.org/w3co/x', []).allow).toBe('unknown');
    expect(gitUrlCheck('https://user:tok@github.com/w3co/x', ALLOW).error).toBe(
      'wiz.git.err.credentials',
    );
    expect(gitUrlCheck('http://github.com/w3co/x', ALLOW).error).toBe('wiz.git.err.scheme');
    // not listed is not blocking (the Center has the real list)
    expect(
      gitSourceIssues({ ...validGit(), repoUrl: 'https://bitbucket.org/w3co/x' }, [node], ALLOW),
    ).toEqual([]);
  });

  it('Dockerfile path and template are mutually exclusive', () => {
    expect(buildSpecError({ dockerfile: 'Dockerfile', template: 'nestjs' })).toBe(
      'wiz.git.issue.exclusive',
    );
    expect(buildSpecError({})).toBe('wiz.git.issue.method');
    expect(buildSpecError({ template: 'nextjs' })).toBeNull();
    const t = toBuildConfig({ ...validGit(), dockerfile: 'Dockerfile', method: 'template' });
    expect(t.template).toBe('nestjs');
    expect(t.dockerfile).toBeUndefined();
    const d = toBuildConfig({
      ...validGit(),
      method: 'dockerfile',
      dockerfile: 'docker/api.Dockerfile',
    });
    expect(d.dockerfile).toBe('docker/api.Dockerfile');
    expect(d.template).toBeUndefined();
    expect(
      gitSourceIssues({ ...validGit(), method: 'dockerfile', dockerfile: '../x' }, [node], ALLOW),
    ).toContain('wiz.git.err.dockerfile');
  });

  it('secret-looking build args are refused; build node must be designated + capable + online', () => {
    expect(buildArgIssues([{ id: '1', key: 'NPM_TOKEN', value: 'x' }])).toContain(
      'wiz.git.issue.secretArg',
    );
    expect(buildArgIssues([{ id: '1', key: 'NODE_ENV', value: 'production' }])).toEqual([]);
    expect(buildNodeBlockReason({ ...node, buildNode: false })).toBe('wiz.git.node.notDesignated');
    expect(buildNodeBlockReason({ ...node, capabilities: ['docker'] })).toBe(
      'wiz.git.node.noCapability',
    );
    expect(buildNodeBlockReason({ ...node, status: 'offline' })).toBe('wiz.git.node.offline');
    expect(gitSourceIssues(validGit(), [{ ...node, buildNode: false }], ALLOW)).toContain(
      'wiz.git.issue.nodeBlocked',
    );
  });
});

const YAML = `services:
  app:
    image: registry.example.lab/w3/crm-app@sha256:${'b'.repeat(64)}
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
      APP_KEY: \${APP_KEY}
    depends_on: [db, redis]
  worker:
    image: registry.example.lab/w3/crm-worker:1.2
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
    depends_on:
      - db
  db:
    image: postgres:16.4
    volumes:
      - pgdata:/var/lib/postgresql/data
  redis:
    image: redis:7.4
volumes:
  pgdata: {}
`;

describe('compose service table derivation', () => {
  it('scans images, placeholders, volumes and depends_on', () => {
    const s = scanComposeServices(YAML);
    expect(s.map((x) => x.name)).toEqual(['app', 'worker', 'db', 'redis']);
    expect(s[0]!.placeholders).toEqual(['DB_PASSWORD', 'APP_KEY']);
    expect(s[0]!.dependsOn).toEqual(['db', 'redis']);
    expect(s[1]!.dependsOn).toEqual(['db']);
    expect(s[2]!.volumes).toEqual([{ name: 'pgdata', mountPath: '/var/lib/postgresql/data' }]);
  });

  it('infers health: route http, known DB tcp, else running; placeholders carry status', () => {
    const route = { service: 'app', port: 8000, healthPath: '/healthz' };
    expect(inferHealth({ name: 'app', image: 'x' }, route)).toEqual({
      type: 'http',
      port: 8000,
      path: '/healthz',
    });
    expect(inferHealth({ name: 'db', image: 'postgres:16' }, route)).toEqual({
      type: 'tcp',
      port: 5432,
    });
    expect(inferHealth({ name: 'c', image: 'bitnami/redis:7' }, route)).toEqual({
      type: 'tcp',
      port: 6379,
    });
    expect(inferHealth({ name: 'worker', image: 'x/worker:1' }, route)).toEqual({
      type: 'running',
    });
    const rows = deriveComposeServices({
      yaml: YAML,
      routeService: 'app',
      routePort: 8000,
      healthPath: '/',
      secretStatus: (k) => (k === 'APP_KEY' ? 'set' : 'missing'),
    });
    expect(rows[0]).toMatchObject({ isRoute: true, pinned: true });
    expect(rows[1]).toMatchObject({ pinned: false });
    expect(rows[0]!.placeholders).toEqual([
      { key: 'DB_PASSWORD', status: 'missing' },
      { key: 'APP_KEY', status: 'set' },
    ]);
  });

  it('issues: missing secrets, ports on non-route services, cycles; plan marks unchanged / replaced', () => {
    const c = {
      ...initialCompose(),
      yaml: YAML,
      routeService: 'app',
      routePort: '8000',
      validation: { valid: true, violations: [], warnings: [], services: [] },
      validatedYaml: YAML,
    };
    expect(composeIssues(c, ['APP_KEY'])).toEqual(['wiz.cmp.issue.secrets']);
    expect(composeIssues({ ...c, staged: ['DB_PASSWORD'] }, ['APP_KEY'])).toEqual([]);
    const withPorts = YAML.replace(
      '  redis:\n    image: redis:7.4',
      '  redis:\n    image: redis:7.4\n    ports:\n      - "6379:6379"',
    );
    expect(
      composeIssues({ ...c, yaml: withPorts, validatedYaml: withPorts }, [
        'APP_KEY',
        'DB_PASSWORD',
      ]),
    ).toContain('wiz.cmp.issue.ports');
    const cyc = YAML.replace(
      '  db:\n    image: postgres:16.4',
      '  db:\n    image: postgres:16.4\n    depends_on: [app]',
    );
    expect(
      composeIssues({ ...c, yaml: cyc, validatedYaml: cyc }, ['APP_KEY', 'DB_PASSWORD']),
    ).toContain('wiz.cmp.issue.cycle');

    const rows = deriveComposeServices({
      yaml: YAML,
      routeService: 'app',
      routePort: 8000,
      healthPath: '/',
      secretStatus: () => 'set',
    });
    const current = rows.map((r) => ({
      service: r.service,
      image: r.image!,
      env: {},
      secretEnv: Object.fromEntries(r.placeholders.map((p) => [p.key, p.key])),
      volumes: r.volumes,
      dependsOn: r.dependsOn,
      health:
        r.health.type === 'http'
          ? { ...r.health, expectStatus: [200], intervalSec: 2, timeoutSec: 3, startPeriodSec: 60 }
          : r.health.type === 'tcp'
            ? { ...r.health, startPeriodSec: 60 }
            : { type: 'running' as const, startPeriodSec: 10 },
    }));
    expect(composePlan(null, rows).every((p) => p.action === 'created')).toBe(true);
    const next = deriveComposeServices({
      yaml: YAML.replace('b'.repeat(64), 'c'.repeat(64)),
      routeService: 'app',
      routePort: 8000,
      healthPath: '/',
      secretStatus: () => 'set',
    });
    const plan = composePlan(current, next);
    expect(Object.fromEntries(plan.map((p) => [p.service, p.action]))).toEqual({
      app: 'replaced',
      worker: 'unchanged',
      db: 'unchanged',
      redis: 'unchanged',
    });
  });
});

describe('build log viewer bounds', () => {
  it('keeps the last N lines, reports dropped and clips long lines', () => {
    const lines = Array.from({ length: BUILD_LOG_MAX_LINES + 250 }, (_, i) => `line ${i}`);
    const b = boundLog(lines);
    expect(b.lines).toHaveLength(BUILD_LOG_MAX_LINES);
    expect(b.dropped).toBe(250);
    expect(b.lines[0]).toBe('line 250');
    const c = boundLog(['x'.repeat(10), 'y'.repeat(50)], 10, 20);
    expect(c.clipped).toBe(1);
    expect(c.lines[1]).toBe(`${'y'.repeat(20)} …`);
    expect(boundLog(null).lines).toEqual([]);
  });

  it('renders only the bounded tail and says how many lines were hidden', () => {
    const lines = Array.from({ length: 30 }, (_, i) => `step ${i}`);
    renderWith(<BuildLogViewer lines={lines} live={false} max={10} />);
    const pre = screen.getByTestId('build-log-text');
    expect(pre.textContent).not.toContain('step 19\n');
    expect(pre.textContent?.startsWith('step 20')).toBe(true);
    expect(pre).toHaveAttribute('data-dropped', '20');
    expect(screen.getByText(/20 older lines not shown/)).toBeInTheDocument();
  });

  it('phases: queued → building only; failure marks building', () => {
    expect(buildPhaseStates({ status: 'queued', error: null })).toEqual({
      queued: 'current',
      building: 'pending',
    });
    expect(buildPhaseStates({ status: 'fetching', error: null })).toEqual({
      queued: 'done',
      building: 'current',
    });
    expect(
      buildPhaseStates({ status: 'failed', error: { code: 'BUILD_FAILED', message: '' } }),
    ).toEqual({
      queued: 'done',
      building: 'failed',
    });
  });
});

function client() {
  let tok: string | null = null;
  const c = createApiClient({
    baseUrl: 'http://mock/api/v1',
    clientVersion: 't',
    fetch: mockFetch as typeof fetch,
    tokenStore: { get: () => tok, set: (t) => (tok = t) },
  });
  return {
    c,
    async login(email: string) {
      const r = await c.post<LoginSuccess>(
        '/auth/login',
        { email, password: 'password' },
        { auth: false },
      );
      tok = r.accessToken;
    },
  };
}

describe('mock P4b (contract §8)', () => {
  beforeEach(() => resetMockState());
  afterEach(() => vi.useRealTimers());

  it('build → digest → deployment; failed build creates no deployment; reuse does not deploy', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const shop = (await c.list<Application>('/applications')).items.find(
      (a) => a.name === 'shop-api',
    )!;
    expect(shop.build?.config.template).toBe('nestjs');
    expect(shop.allowedActions).toContain('build');
    vi.useFakeTimers({ toFake: ['Date'] });
    const t0 = Date.now();
    const ok = await c.post<{ build: Build }>(`/applications/${shop.id}/builds`, {
      commitSha: SHA,
      branch: 'main',
    });
    expect(ok.build.status).toBe('queued');
    vi.setSystemTime(t0 + 2000);
    expect((await c.get<Build>(`/builds/${ok.build.id}`)).status).toBe('building');
    vi.setSystemTime(t0 + 6000);
    const done = await c.get<Build>(`/builds/${ok.build.id}`);
    expect(done.status).toBe('succeeded');
    expect(done.image).toMatch(/^registry\.example\.lab\/w3\/shop-api@sha256:[a-f0-9]{64}$/);
    const dep = await c.get<Deployment>(`/deployments/${done.deploymentId}`);
    expect(dep.image).toBe(done.image);
    expect(dep.buildId).toBe(done.id);
    expect(dep.sourceRef?.commitSha).toBe(SHA);
    const log = await c.get<{ lines: string[] }>(`/builds/${done.id}/log`);
    expect(log.lines.length).toBeGreaterThan(10);

    const again = await c.post<{ build: Build; reused?: boolean }>(
      `/applications/${shop.id}/builds`,
      { commitSha: SHA },
    );
    expect(again.reused).toBe(true);
    expect(again.build.id).toBe(done.id);

    vi.setSystemTime(t0 + 60_000);
    const bad = await c.post<{ build: Build }>(`/applications/${shop.id}/builds`, {
      commitSha: `dead${'1'.repeat(36)}`,
    });
    vi.setSystemTime(t0 + 70_000);
    const failed = await c.get<Build>(`/builds/${bad.build.id}`);
    expect(failed.status).toBe('failed');
    expect(failed.deploymentId).toBeNull();
    expect(failed.error?.code).toBe('IMAGE_BUILD_FAILED');
  });

  it('build node toggle needs policies.manage and the build capability', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const servers = (
      await c.list<{ id: string; name: string; version: number; buildNode: boolean }>('/servers')
    ).items;
    const uat = servers.find((s) => s.name === 'app-uat-01')!;
    const prod = servers.find((s) => s.name === 'app-prod-01')!;
    expect(uat.buildNode).toBe(false);
    const r = await c.patch<{ buildNode: boolean }>(`/servers/${uat.id}`, { buildNode: true });
    expect(r.buildNode).toBe(true);
    await expect(c.patch(`/servers/${prod.id}`, { buildNode: true })).rejects.toMatchObject({
      code: 'VALIDATION_FAILED',
    });
  });

  it('compose: create with placeholder → secrets missing → deploy → only the changed service is replaced', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const servers = (await c.list<{ id: string; name: string }>('/servers')).items;
    const uat = servers.find((s) => s.name === 'app-uat-01')!;
    const app = await c.post<Application>('/applications', {
      kind: 'compose',
      serverId: uat.id,
      name: 'wiki',
      domains: ['wiki.uat.example.lab'],
      yaml: YAML,
      routeService: 'app',
      routePort: 8000,
    });
    expect(app.kind).toBe('compose');
    expect(app.container).toBeUndefined();
    expect(app.compose?.secretKeys.sort()).toEqual(['APP_KEY', 'DB_PASSWORD']);
    const pf = await c.post<{ checks: Array<{ check: string; ok: boolean; code?: string }> }>(
      `/applications/${app.id}/deployments/preflight`,
      {},
    );
    expect(pf.checks.find((x) => !x.ok)?.code).toBe('SECRETS_MISSING');
    for (const k of ['APP_KEY', 'DB_PASSWORD'])
      await c.request('PUT', `/applications/${app.id}/secrets/${k}`, { body: { value: 'v' } });
    vi.useFakeTimers({ toFake: ['Date'] });
    const t0 = Date.now();
    const d1 = await c.post<{ deployment: Deployment }>(`/applications/${app.id}/deployments`, {});
    vi.setSystemTime(t0 + 10_000);
    const done1 = await c.get<Deployment>(`/deployments/${d1.deployment.id}`);
    expect(done1.status).toBe('succeeded');
    expect(done1.compose?.services.every((x) => x.action === 'created')).toBe(true);
    expect(done1.compose?.dataRestored).toBe(false);

    const cur = await c.get<Application>(`/applications/${app.id}`);
    await c.request('PUT', `/applications/${app.id}/compose`, {
      body: {
        yaml: YAML.replace('b'.repeat(64), 'c'.repeat(64)),
        routeService: 'app',
        routePort: 8000,
      },
      headers: { 'If-Match': String(cur.version) },
    });
    const d2 = await c.post<{ deployment: Deployment }>(`/applications/${app.id}/deployments`, {});
    vi.setSystemTime(t0 + 20_000);
    const done2 = await c.get<Deployment>(`/deployments/${d2.deployment.id}`);
    expect(done2.status).toBe('succeeded');
    expect(Object.fromEntries(done2.compose!.services.map((x) => [x.service, x.action]))).toEqual({
      app: 'replaced',
      worker: 'unchanged',
      db: 'unchanged',
      redis: 'unchanged',
    });
    // route service replaced → route switch ran
    expect(done2.steps.find((x) => x.name === 'route_switch')?.status).toBe('succeeded');
  });
});
