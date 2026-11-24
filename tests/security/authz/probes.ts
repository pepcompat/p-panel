/**
 * Probe table: one entry per HTTP route. `path` substitutes server-A resource ids; `body` is a
 * schema-valid request so a scoped principal gets past validation and reaches the authorization
 * check (a 422 from a probe would mean "authz not exercised" and is reported by the matrix test).
 */
import type { WorldIds } from '../lib/world';

const H = (c: string, n = 64) => c.repeat(n).slice(0, n);
const DIGEST_IMAGE = `registry.example.test/a@sha256:${H('a')}`;

export interface Probe {
  /** `METHOD /api/v1/...` with Nest params */
  route: string;
  path: (ids: WorldIds) => string;
  body?: (ids: WorldIds) => unknown;
  headers?: Record<string, string>;
  /** public route: justification (allowlist) */
  publicReason?: string;
  /**
   * Coarse-permission-less route whose access is enforced in the service: which global roles
   * are allowed (others must get 403/404).
   */
  allowViewer?: boolean;
  allowDeployer?: boolean;
  /** a 422 for the scoped-B probe is acceptable (route validates a server-A-agnostic body first) */
  scopedValidationOk?: string;
  /** read of a global object: 200 allowed for scoped principals as long as no server-A data leaks */
  globalRead?: string;
}

const r = (route: string, path: Probe['path'], extra: Partial<Probe> = {}): Probe => ({
  route,
  path,
  ...extra,
});

export const PROBES: Probe[] = [
  // ------------------------------------------------------------------ public
  r('POST /api/v1/agent/enroll', () => '/api/v1/agent/enroll', {
    publicReason: 'agent bootstrap: authorised by the one-time enrollment token in the body',
    body: () => ({ token: 'ppe_' + 'x'.repeat(40), csrPem: 'x', hostname: 'h', facts: {} }),
  }),
  r('POST /api/v1/auth/login', () => '/api/v1/auth/login', {
    publicReason: 'credential login',
    body: () => ({ email: 'nobody@ppanel.local', password: 'wrong-password' }),
  }),
  r('POST /api/v1/auth/logout', () => '/api/v1/auth/logout', {
    publicReason: 'best-effort logout (revokes the presented cookie family only)',
  }),
  r('POST /api/v1/auth/mfa/verify', () => '/api/v1/auth/mfa/verify', {
    publicReason: 'second factor: authorised by the short-lived mfa token',
    body: () => ({ mfaToken: 'x'.repeat(20), code: '123456' }),
  }),
  r('POST /api/v1/auth/refresh', () => '/api/v1/auth/refresh', {
    publicReason: 'authorised by the HttpOnly SameSite=Strict refresh cookie + X-CSRF',
  }),
  r('POST /api/v1/backup-maintenance/reports', () => '/api/v1/backup-maintenance/reports', {
    publicReason: 'maintenance identity: static bearer (PPANEL_BACKUP_REPORT_TOKEN), 404 if unset',
    body: () => ({}),
  }),
  r('GET /api/v1/logs/tail', () => '/api/v1/logs/tail?token=' + 'x'.repeat(32), {
    publicReason: 'SSE: EventSource cannot send headers; single-use 60 s tail token in query',
  }),
  r('POST /api/v1/setup/bootstrap', () => '/api/v1/setup/bootstrap', {
    publicReason: 'first-run only: setup token + no existing owner (409 afterwards)',
    body: () => ({
      setupToken: 'x',
      email: 'a@b.test',
      password: 'x'.repeat(16),
      displayName: 'x',
    }),
  }),
  r('GET /api/v1/setup/status', () => '/api/v1/setup/status', {
    publicReason: 'returns only {initialized} for the first-run UI',
  }),
  r('GET /api/v1/version', () => '/api/v1/version', {
    publicReason:
      'P8: build identity + compatibility policy for installer/upgrade pre-flight; no secrets',
  }),
  r('GET /api/v1/health', () => '/api/v1/health', {
    publicReason: 'P8: liveness + DB reachability for container healthchecks; no data',
  }),
  r(
    'POST /api/v1/webhooks/github/:integrationId',
    (i) => `/api/v1/webhooks/github/${i.integration}`,
    {
      publicReason: 'GitHub webhook: HMAC-SHA256 signature over the raw body',
    },
  ),

  // ------------------------------------------------------------------ auth (any authenticated user)
  r('GET /api/v1/auth/me', () => '/api/v1/auth/me', { allowViewer: true, allowDeployer: true }),
  r('POST /api/v1/auth/mfa/totp/confirm', () => '/api/v1/auth/mfa/totp/confirm', {
    allowViewer: true,
    allowDeployer: true,
    body: () => ({ code: '000000' }),
  }),
  r('POST /api/v1/auth/mfa/totp/setup', () => '/api/v1/auth/mfa/totp/setup', {
    allowViewer: true,
    allowDeployer: true,
  }),
  r('POST /api/v1/auth/step-up', () => '/api/v1/auth/step-up', {
    allowViewer: true,
    allowDeployer: true,
    body: () => ({ code: '000000' }),
  }),

  // ------------------------------------------------------------------ alert rules
  r('GET /api/v1/alert-rules', () => '/api/v1/alert-rules'),
  r('POST /api/v1/alert-rules', () => '/api/v1/alert-rules', {
    body: (i) => ({
      name: 'probe',
      scopeType: 'server',
      scopeId: i.serverA,
      kind: 'server_offline',
    }),
  }),
  r('GET /api/v1/alert-rules/:id', (i) => `/api/v1/alert-rules/${i.ruleA}`),
  r('PATCH /api/v1/alert-rules/:id', (i) => `/api/v1/alert-rules/${i.ruleA}`, {
    body: () => ({ name: 'pwn' }),
  }),
  r('DELETE /api/v1/alert-rules/:id', (i) => `/api/v1/alert-rules/${i.ruleA}`),

  // ------------------------------------------------------------------ applications
  r('GET /api/v1/applications', () => '/api/v1/applications'),
  r('POST /api/v1/applications', () => '/api/v1/applications', {
    body: (i) => ({
      serverId: i.serverA,
      name: 'probe-app',
      domains: ['probe.example.test'],
      containerPort: 8080,
    }),
  }),
  r('GET /api/v1/applications/:id', (i) => `/api/v1/applications/${i.appA}`),
  r(
    'GET /api/v1/applications/:id/auto-deploy',
    (i) => `/api/v1/applications/${i.appA}/auto-deploy`,
  ),
  r(
    'POST /api/v1/applications/:id/auto-deploy',
    (i) => `/api/v1/applications/${i.appA}/auto-deploy`,
    {
      body: (i) => ({
        integrationId: i.integration,
        repo: 'org/probe',
        branches: ['main'],
        imageTemplate: 'registry.example.test/a:{sha}',
      }),
    },
  ),
  r(
    'PATCH /api/v1/applications/:id/auto-deploy/:policyId',
    (i) => `/api/v1/applications/${i.appA}/auto-deploy/${i.autoDeployA}`,
    { body: () => ({ enabled: false }) },
  ),
  r(
    'DELETE /api/v1/applications/:id/auto-deploy/:policyId',
    (i) => `/api/v1/applications/${i.appA}/auto-deploy/${i.autoDeployA}`,
  ),
  r(
    'GET /api/v1/applications/:id/build-config',
    (i) => `/api/v1/applications/${i.appA}/build-config`,
  ),
  r(
    'PUT /api/v1/applications/:id/build-config',
    (i) => `/api/v1/applications/${i.appA}/build-config`,
    {
      body: (i) => ({
        repoUrl: 'https://github.com/org/probe.git',
        buildServerId: i.serverA,
        pushRepo: 'registry.example.test/probe',
        dockerfile: 'Dockerfile',
      }),
    },
  ),
  r('GET /api/v1/applications/:id/builds', (i) => `/api/v1/applications/${i.appA}/builds`),
  r('POST /api/v1/applications/:id/builds', (i) => `/api/v1/applications/${i.appA}/builds`, {
    body: () => ({ commitSha: H('7', 40) }),
  }),
  r('GET /api/v1/applications/:id/compose', (i) => `/api/v1/applications/${i.composeAppA}/compose`),
  r(
    'PUT /api/v1/applications/:id/compose',
    (i) => `/api/v1/applications/${i.composeAppA}/compose`,
    {
      body: () => ({
        yaml: `services:\n  web:\n    image: ${DIGEST_IMAGE}\n`,
        routeService: 'web',
        routePort: 80,
      }),
    },
  ),
  r('PATCH /api/v1/applications/:id/container', (i) => `/api/v1/applications/${i.appA}/container`, {
    body: () => ({ containerPort: 9090 }),
  }),
  r(
    'POST /api/v1/applications/:id/deployments/preflight',
    (i) => `/api/v1/applications/${i.appA}/deployments/preflight`,
    { body: () => ({ image: DIGEST_IMAGE }) },
  ),
  r(
    'GET /api/v1/applications/:id/deployments',
    (i) => `/api/v1/applications/${i.appA}/deployments`,
  ),
  r(
    'POST /api/v1/applications/:id/deployments',
    (i) => `/api/v1/applications/${i.appA}/deployments`,
    {
      body: () => ({ image: DIGEST_IMAGE }),
    },
  ),
  r(
    'POST /api/v1/applications/:id/drift/acknowledge',
    (i) => `/api/v1/applications/${i.nginxAppA}/drift/acknowledge`,
    { body: () => ({ reason: 'probe' }) },
  ),
  r('GET /api/v1/applications/:id/git-auth', (i) => `/api/v1/applications/${i.appA}/git-auth`),
  r('PUT /api/v1/applications/:id/git-auth', (i) => `/api/v1/applications/${i.appA}/git-auth`, {
    body: () => ({ token: 'ghp_probe' }),
  }),
  r('DELETE /api/v1/applications/:id/git-auth', (i) => `/api/v1/applications/${i.appA}/git-auth`),
  r('GET /api/v1/applications/:id/logs', (i) => `/api/v1/applications/${i.appA}/logs`),
  r(
    'GET /api/v1/applications/:id/nginx/files',
    (i) => `/api/v1/applications/${i.nginxAppA}/nginx/files`,
  ),
  r(
    'GET /api/v1/applications/:id/nginx/revisions',
    (i) => `/api/v1/applications/${i.nginxAppA}/nginx/revisions`,
  ),
  r(
    'POST /api/v1/applications/:id/nginx/revisions',
    (i) => `/api/v1/applications/${i.nginxAppA}/nginx/revisions`,
    {
      body: () => ({
        files: [{ path: '/etc/nginx/sites-enabled/a.conf', content: 'server { listen 80; }\n' }],
      }),
    },
  ),
  r(
    'GET /api/v1/applications/:id/ownership-history',
    (i) => `/api/v1/applications/${i.nginxAppA}/ownership-history`,
  ),
  r(
    'POST /api/v1/applications/:id/ownership',
    (i) => `/api/v1/applications/${i.nginxAppA}/ownership`,
    {
      body: () => ({ toMode: 'observed', reason: 'probe' }),
    },
  ),
  r('POST /api/v1/applications/:id/redeploy', (i) => `/api/v1/applications/${i.appA}/redeploy`, {
    body: () => ({}),
  }),
  r(
    'GET /api/v1/applications/:id/registry-auth',
    (i) => `/api/v1/applications/${i.appA}/registry-auth`,
  ),
  r(
    'PUT /api/v1/applications/:id/registry-auth',
    (i) => `/api/v1/applications/${i.appA}/registry-auth`,
    {
      body: () => ({ serveraddress: 'registry.example.test', username: 'u', password: 'p' }),
    },
  ),
  r(
    'DELETE /api/v1/applications/:id/registry-auth',
    (i) => `/api/v1/applications/${i.appA}/registry-auth`,
  ),
  r('POST /api/v1/applications/:id/restart', (i) => `/api/v1/applications/${i.appA}/restart`, {
    body: () => ({}),
  }),
  r('POST /api/v1/applications/:id/rollback', (i) => `/api/v1/applications/${i.appA}/rollback`, {
    body: () => ({}),
  }),
  r('GET /api/v1/applications/:id/secrets', (i) => `/api/v1/applications/${i.appA}/secrets`),
  r(
    'PUT /api/v1/applications/:id/secrets/:key',
    (i) => `/api/v1/applications/${i.appA}/secrets/API_KEY`,
    {
      body: () => ({ value: 'pwned' }),
    },
  ),
  r(
    'DELETE /api/v1/applications/:id/secrets/:key',
    (i) => `/api/v1/applications/${i.appA}/secrets/API_KEY`,
  ),
  r(
    'GET /api/v1/applications/:id/source/inspect/:inspectionId',
    (i) => `/api/v1/applications/${i.appA}/source/inspect/${i.inspectionA}`,
  ),
  r(
    'POST /api/v1/applications/:id/source/inspect',
    (i) => `/api/v1/applications/${i.appA}/source/inspect`,
    {
      body: () => ({ commitSha: H('7', 40) }),
    },
  ),
  r('POST /api/v1/applications/:id/start', (i) => `/api/v1/applications/${i.appA}/start`, {
    body: () => ({}),
  }),
  r('POST /api/v1/applications/:id/stop', (i) => `/api/v1/applications/${i.appA}/stop`, {
    body: () => ({}),
  }),

  // ------------------------------------------------------------------ audit
  r('GET /api/v1/audit-events', () => '/api/v1/audit-events'),

  // ------------------------------------------------------------------ backups
  r('GET /api/v1/backup-policies', () => '/api/v1/backup-policies'),
  r('POST /api/v1/backup-policies', () => '/api/v1/backup-policies', {
    body: (i) => ({
      name: 'probe',
      serverId: i.serverA,
      repositoryId: i.repo,
      targets: [{ type: 'paths', paths: ['/srv/probe'] }],
      schedule: { cron: '0 4 * * *', timezone: 'UTC' },
    }),
  }),
  r('GET /api/v1/backup-policies/:id', (i) => `/api/v1/backup-policies/${i.policyA}`),
  r('PATCH /api/v1/backup-policies/:id', (i) => `/api/v1/backup-policies/${i.policyA}`, {
    body: () => ({ enabled: false }),
  }),
  r('DELETE /api/v1/backup-policies/:id', (i) => `/api/v1/backup-policies/${i.policyA}`),
  r('POST /api/v1/backup-policies/:id/run', (i) => `/api/v1/backup-policies/${i.policyA}/run`, {
    body: () => ({}),
  }),
  r('GET /api/v1/backup-repositories', () => '/api/v1/backup-repositories'),
  r('POST /api/v1/backup-repositories', () => '/api/v1/backup-repositories', {
    body: () => ({ name: 'probe-repo', baseUrl: 'https://backup2.example.test' }),
  }),
  r('GET /api/v1/backup-repositories/:id', (i) => `/api/v1/backup-repositories/${i.repo}`, {
    globalRead: 'shared repository; per-server access entries are scope-filtered',
  }),
  r('PATCH /api/v1/backup-repositories/:id', (i) => `/api/v1/backup-repositories/${i.repo}`, {
    body: () => ({ name: 'pwn-repo' }),
  }),
  r(
    'GET /api/v1/backup-repositories/:id/recovery-export',
    (i) => `/api/v1/backup-repositories/${i.repo}/recovery-export`,
  ),
  r(
    'PUT /api/v1/backup-repositories/:id/servers/:serverId',
    (i) => `/api/v1/backup-repositories/${i.repo}/servers/${i.serverA}`,
    { body: () => ({ restUser: 'probe-user', restPassword: 'probe-password-123' }) },
  ),
  r(
    'POST /api/v1/backup-repositories/:id/servers/:serverId/initialized',
    (i) => `/api/v1/backup-repositories/${i.repo}/servers/${i.serverA}/initialized`,
    { body: () => ({}) },
  ),
  r('GET /api/v1/backup-runs', () => '/api/v1/backup-runs'),
  r('GET /api/v1/backup-runs/:id', (i) => `/api/v1/backup-runs/${i.runA}`),
  r('POST /api/v1/backup-runs/:id/verify', (i) => `/api/v1/backup-runs/${i.runA}/verify`, {
    body: () => ({ level: 'check' }),
  }),
  r('GET /api/v1/restores', () => '/api/v1/restores'),
  r('POST /api/v1/restores', () => '/api/v1/restores', {
    body: (i) => ({
      runId: i.runA,
      snapshotId: H('5'),
      target: { type: 'paths', include: ['/srv/a'], mode: 'in_place' },
    }),
  }),
  r('GET /api/v1/restores/:id', (i) => `/api/v1/restores/${i.restoreA}`),
  r('POST /api/v1/restores/:id/approve', (i) => `/api/v1/restores/${i.restoreA}/approve`, {
    body: () => ({ planHash: H('6') }),
  }),
  r('POST /api/v1/restores/:id/cancel', (i) => `/api/v1/restores/${i.restoreA}/cancel`, {
    body: () => ({}),
  }),
  r('POST /api/v1/restores/:id/dry-run', (i) => `/api/v1/restores/${i.restoreA}/dry-run`, {
    body: () => ({}),
  }),
  r('POST /api/v1/restores/:id/execute', (i) => `/api/v1/restores/${i.restoreA}/execute`, {
    body: () => ({ confirmImpact: true }),
  }),
  r('GET /api/v1/servers/:id/snapshots', (i) => `/api/v1/servers/${i.serverA}/snapshots`),

  // ------------------------------------------------------------------ builds / deployments
  r('GET /api/v1/builds/:id', (i) => `/api/v1/builds/${i.buildA}`),
  r('GET /api/v1/builds/:id/log', (i) => `/api/v1/builds/${i.buildA}/log`),
  r('POST /api/v1/builds/:id/cancel', (i) => `/api/v1/builds/${i.buildA}/cancel`, {
    body: () => ({}),
  }),
  r('POST /api/v1/deploy/compose/validate', () => '/api/v1/deploy/compose/validate', {
    body: () => ({ yaml: `services:\n  web:\n    image: ${DIGEST_IMAGE}\n` }),
    scopedValidationOk: 'stateless validator; no server-A data involved',
  }),
  r('POST /api/v1/deploy/detect', () => '/api/v1/deploy/detect', {
    body: () => ({ files: { 'package.json': '{}' } }),
    scopedValidationOk: 'stateless detector; no server-A data involved',
  }),
  r('GET /api/v1/deployments', () => '/api/v1/deployments'),
  r('GET /api/v1/deployments/:id', (i) => `/api/v1/deployments/${i.deploymentA}`),
  r(
    'POST /api/v1/deployments/:id/approve',
    (i) => `/api/v1/deployments/${i.deploymentPendingA}/approve`,
    {
      body: () => ({ planHash: H('f') }),
    },
  ),
  r(
    'POST /api/v1/deployments/:id/cancel',
    (i) => `/api/v1/deployments/${i.deploymentPendingA}/cancel`,
    {
      body: () => ({}),
    },
  ),

  // ------------------------------------------------------------------ discovery / nginx
  r('GET /api/v1/discovery-scans', () => '/api/v1/discovery-scans'),
  r('GET /api/v1/discovery-scans/:id', (i) => `/api/v1/discovery-scans/${i.scanA}`),
  r(
    'GET /api/v1/discovery-scans/:id/findings',
    (i) => `/api/v1/discovery-scans/${i.scanA}/findings`,
  ),
  r('POST /api/v1/discovery-scans/:id/import', (i) => `/api/v1/discovery-scans/${i.scanA}/import`, {
    body: () => ({ findingIds: ['01a207ea-0000-7000-8000-000000000000'], mode: 'observed' }),
  }),
  r(
    'POST /api/v1/servers/:serverId/discovery-scans',
    (i) => `/api/v1/servers/${i.serverA}/discovery-scans`,
    {
      body: () => ({}),
    },
  ),
  r('GET /api/v1/nginx-revisions/:id', (i) => `/api/v1/nginx-revisions/${i.revisionA}`),
  r(
    'POST /api/v1/nginx-revisions/:id/apply',
    (i) => `/api/v1/nginx-revisions/${i.revisionA}/apply`,
    {
      body: () => ({ planHash: H('1') }),
    },
  ),
  r(
    'POST /api/v1/nginx-revisions/:id/approve',
    (i) => `/api/v1/nginx-revisions/${i.revisionA}/approve`,
    {
      body: () => ({ planHash: H('1') }),
    },
  ),
  r(
    'POST /api/v1/nginx-revisions/:id/cancel',
    (i) => `/api/v1/nginx-revisions/${i.revisionA}/cancel`,
    {
      body: () => ({}),
    },
  ),
  r(
    'POST /api/v1/nginx-revisions/:id/revert',
    (i) => `/api/v1/nginx-revisions/${i.revisionA}/revert`,
    {
      body: () => ({}),
    },
  ),
  r(
    'POST /api/v1/nginx-revisions/:id/validate',
    (i) => `/api/v1/nginx-revisions/${i.revisionA}/validate`,
    {
      body: () => ({}),
    },
  ),

  // ------------------------------------------------------------------ enrollments / incidents
  r('GET /api/v1/enrollments', () => '/api/v1/enrollments'),
  r('POST /api/v1/enrollments', () => '/api/v1/enrollments', {
    body: () => ({ name: 'probe', environment: 'production' }),
  }),
  r('GET /api/v1/incidents', () => '/api/v1/incidents'),
  r('GET /api/v1/incidents/:id', (i) => `/api/v1/incidents/${i.incidentA}`),
  r(
    'POST /api/v1/incidents/:id/acknowledge',
    (i) => `/api/v1/incidents/${i.incidentA}/acknowledge`,
    {
      body: () => ({ comment: 'probe' }),
    },
  ),
  r('POST /api/v1/incidents/:id/comment', (i) => `/api/v1/incidents/${i.incidentA}/comment`, {
    body: () => ({ comment: 'probe' }),
  }),

  // ------------------------------------------------------------------ integrations
  r('GET /api/v1/integrations', () => '/api/v1/integrations'),
  r('POST /api/v1/integrations/github', () => '/api/v1/integrations/github', {
    body: () => ({ name: 'probe', webhookSecret: 'probe-secret-0123456789' }),
  }),
  r('GET /api/v1/integrations/github/app', () => '/api/v1/integrations/github/app'),
  r(
    'GET /api/v1/integrations/github/:id/deliveries',
    (i) => `/api/v1/integrations/github/${i.integration}/deliveries`,
    { globalRead: 'global integration; deliveries filtered to visible apps (SEC-P7-03)' },
  ),

  // ------------------------------------------------------------------ logs / metrics (service-scoped)
  r('GET /api/v1/logs/query', (i) => `/api/v1/logs/query?serverId=${i.serverA}`, {
    allowViewer: true,
    allowDeployer: true,
  }),
  r('POST /api/v1/logs/tail-token', () => '/api/v1/logs/tail-token', {
    allowViewer: true,
    allowDeployer: true,
    body: (i) => ({ serverId: i.serverA }),
  }),
  r('GET /api/v1/metrics/fleet', () => '/api/v1/metrics/fleet'),
  r(
    'GET /api/v1/metrics/series',
    (i) => `/api/v1/metrics/series?scope=server&id=${i.serverA}&metric=cpu`,
    {
      allowViewer: true,
      allowDeployer: true,
    },
  ),

  // ------------------------------------------------------------------ notification channels
  r('GET /api/v1/notification-channels', () => '/api/v1/notification-channels'),
  r('POST /api/v1/notification-channels', () => '/api/v1/notification-channels', {
    body: () => ({
      type: 'webhook',
      name: 'probe',
      config: { url: 'https://hooks.example.test/p', signingSecret: 'probe-signing-0123456789' },
    }),
  }),
  r('GET /api/v1/notification-channels/:id', (i) => `/api/v1/notification-channels/${i.channel}`),
  r(
    'PATCH /api/v1/notification-channels/:id',
    (i) => `/api/v1/notification-channels/${i.channel}`,
    {
      body: () => ({ name: 'pwn' }),
    },
  ),
  r(
    'DELETE /api/v1/notification-channels/:id',
    (i) => `/api/v1/notification-channels/${i.channel}`,
  ),
  r(
    'POST /api/v1/notification-channels/:id/test',
    (i) => `/api/v1/notification-channels/${i.channel}/test`,
    {
      body: () => ({}),
    },
  ),

  // ------------------------------------------------------------------ users / groups / servers
  r('GET /api/v1/users', () => '/api/v1/users'),
  r('POST /api/v1/users', () => '/api/v1/users', {
    body: () => ({
      email: 'escalate@ppanel.local',
      password: 'long-enough-password',
      displayName: 'x',
      bindings: [{ roleKey: 'platform_owner', scopeType: 'global' }],
    }),
  }),
  r('POST /api/v1/users/:id/role-bindings', (i) => `/api/v1/users/${i.targetUser}/role-bindings`, {
    body: () => ({ roleKey: 'platform_owner', scopeType: 'global' }),
  }),
  r('DELETE /api/v1/role-bindings/:id', (i) => `/api/v1/role-bindings/${i.targetBinding}`),
  r('GET /api/v1/server-groups', () => '/api/v1/server-groups'),
  r('POST /api/v1/server-groups', () => '/api/v1/server-groups', {
    body: () => ({ name: 'probe-group' }),
  }),
  r('GET /api/v1/server-groups/:id', (i) => `/api/v1/server-groups/${i.groupA}`, {
    globalRead: 'server groups are global, non-secret metadata (SEC-P7-A1)',
  }),
  r('PATCH /api/v1/server-groups/:id', (i) => `/api/v1/server-groups/${i.groupA}`, {
    body: () => ({ name: 'pwned-group' }),
  }),
  r('DELETE /api/v1/server-groups/:id', (i) => `/api/v1/server-groups/${i.groupA}`),

  // ------------------------------------------------------------------ P9 provider / network
  r('GET /api/v1/provider-integrations', () => '/api/v1/provider-integrations'),
  r('POST /api/v1/provider-integrations', () => '/api/v1/provider-integrations', {
    body: () => ({ provider: 'digitalocean', name: 'probe', token: 'TEST_FAKE_PROBE_TOKEN' }),
  }),
  r(
    'DELETE /api/v1/provider-integrations/:id',
    (i) => `/api/v1/provider-integrations/${i.provider}`,
  ),
  r(
    'POST /api/v1/provider-integrations/:id/sync',
    (i) => `/api/v1/provider-integrations/${i.provider}/sync`,
    { body: () => ({}) },
  ),
  r('POST /api/v1/network/inventory', () => '/api/v1/network/inventory', {
    body: (i) => ({ rows: [{ serverId: i.serverA, vpcUuid: 'pwned' }] }),
    scopedValidationOk:
      'a server of another scope resolves like an unknown one (422 INVENTORY_SERVER_UNRESOLVED, no oracle, nothing written)',
  }),
  r('GET /api/v1/network/topology', () => '/api/v1/network/topology'),
  r('POST /api/v1/network/connectivity-tests', () => '/api/v1/network/connectivity-tests', {
    body: (i) => ({ fromServerId: i.serverA, toServerId: i.serverB, port: 22 }),
  }),
  r(
    'POST /api/v1/servers/:id/network-diagnostics',
    (i) => `/api/v1/servers/${i.serverA}/network-diagnostics`,
    { body: () => ({ tcp: [{ host: '10.77.0.2', port: 22 }] }) },
  ),
  r(
    'GET /api/v1/servers/:id/network-diagnostics',
    (i) => `/api/v1/servers/${i.serverA}/network-diagnostics`,
  ),
  r('GET /api/v1/network-diagnostics/:testId', (i) => `/api/v1/network-diagnostics/${i.diagTestA}`),

  // ------------------------------------------------------------------ P9 gateways
  r('GET /api/v1/gateways', () => '/api/v1/gateways'),
  r('POST /api/v1/gateways', () => '/api/v1/gateways', {
    body: (i) => ({ serverId: i.serverA, name: 'probe-gw' }),
    scopedValidationOk:
      'a server of another scope looks like an unknown server (422 VALIDATION_FAILED, no oracle)',
  }),
  r('GET /api/v1/gateways/:id', (i) => `/api/v1/gateways/${i.gatewayA}`),
  r('DELETE /api/v1/gateways/:id', (i) => `/api/v1/gateways/${i.gatewayA}`),
  r('GET /api/v1/gateways/:id/routes', (i) => `/api/v1/gateways/${i.gatewayA}/routes`),
  r('POST /api/v1/gateways/:id/routes', (i) => `/api/v1/gateways/${i.gatewayA}/routes`, {
    body: (i) => ({ domain: 'probe.example.test', backends: [{ serverId: i.serverB, port: 80 }] }),
  }),
  r(
    'PATCH /api/v1/gateways/:id/routes/:routeId',
    (i) => `/api/v1/gateways/${i.gatewayA}/routes/${i.routeA}`,
    { body: () => ({ mode: 'gateway' }) },
  ),
  r(
    'DELETE /api/v1/gateways/:id/routes/:routeId',
    (i) => `/api/v1/gateways/${i.gatewayA}/routes/${i.routeA}`,
  ),
  r('GET /api/v1/gateways/:id/plans', (i) => `/api/v1/gateways/${i.gatewayA}/plans`),
  r('POST /api/v1/gateways/:id/plans', (i) => `/api/v1/gateways/${i.gatewayA}/plans`, {
    body: () => ({}),
  }),
  r('GET /api/v1/gateway-plans/:id', (i) => `/api/v1/gateway-plans/${i.planA}`),
  r(
    'POST /api/v1/gateway-plans/:id/shadow-test',
    (i) => `/api/v1/gateway-plans/${i.planA}/shadow-test`,
    { body: () => ({}) },
  ),
  r('POST /api/v1/gateway-plans/:id/approve', (i) => `/api/v1/gateway-plans/${i.planA}/approve`, {
    body: () => ({ planHash: H('7') }),
  }),
  r('POST /api/v1/gateway-plans/:id/apply', (i) => `/api/v1/gateway-plans/${i.planA}/apply`, {
    body: () => ({}),
  }),
  r('POST /api/v1/gateway-plans/:id/rollback', (i) => `/api/v1/gateway-plans/${i.planA}/rollback`, {
    body: () => ({}),
  }),
  r('POST /api/v1/gateway-plans/:id/cancel', (i) => `/api/v1/gateway-plans/${i.planA}/cancel`, {
    body: () => ({}),
  }),
  r('GET /api/v1/servers', () => '/api/v1/servers'),
  r('GET /api/v1/servers/:id', (i) => `/api/v1/servers/${i.serverA}`),
  r('PATCH /api/v1/servers/:id', (i) => `/api/v1/servers/${i.serverA}`, {
    body: () => ({ tags: ['pwned'] }),
  }),
  r('GET /api/v1/servers/:id/heartbeats', (i) => `/api/v1/servers/${i.serverA}/heartbeats`),
  r('POST /api/v1/servers/:id/revoke', (i) => `/api/v1/servers/${i.serverA}/revoke`, {
    body: () => ({ reason: 'probe' }),
  }),
  r(
    'GET /api/v1/servers/:id/managed-routing',
    (i) => `/api/v1/servers/${i.serverA}/managed-routing`,
  ),
  r(
    'POST /api/v1/servers/:id/managed-routing',
    (i) => `/api/v1/servers/${i.serverA}/managed-routing`,
    {
      body: () => ({}),
    },
  ),
  r(
    'POST /api/v1/servers/:id/managed-routing/approve',
    (i) => `/api/v1/servers/${i.serverA}/managed-routing/approve`,
    { body: () => ({ planHash: H('4') }) },
  ),
  r('GET /api/v1/servers/:serverId/jobs', (i) => `/api/v1/servers/${i.serverA}/jobs`),
  r('POST /api/v1/servers/:serverId/jobs', (i) => `/api/v1/servers/${i.serverA}/jobs`, {
    body: () => ({ type: 'inventory.collect', params: {} }),
  }),
  r(
    'GET /api/v1/servers/:serverId/jobs/:jobId',
    (i) => `/api/v1/servers/${i.serverA}/jobs/${i.jobA}`,
  ),
  r(
    'POST /api/v1/servers/:serverId/jobs/:jobId/cancel',
    (i) => `/api/v1/servers/${i.serverA}/jobs/${i.jobA}/cancel`,
    { body: () => ({}) },
  ),
];
