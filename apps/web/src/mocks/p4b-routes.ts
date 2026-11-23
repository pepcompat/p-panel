/**
 * Mock routes for API_CONTRACTS §8 (P4b): build config + git token (values never stored), builds with
 * live logs / cancel / deployAfter, source inspection (pending → succeeded), compose applications
 * (create, versions, normalised plan, per-service actions) wired into the P4a orchestration.
 *
 * Build outcome is chosen by the commit SHA prefix so tests can drive failures:
 *   dead… → IMAGE_BUILD_FAILED (failed image build) · bad0… → GIT_FETCH_FAILED · anything else → ok
 */
import type { Server } from '@ppanel/shared-contracts';
import type { Application } from '@/lib/api/p3-types';
import type { ContainerSpec, Deployment } from '@/lib/api/p4-types';
import {
  COMMIT_SHA_RE,
  GIT_URL_RE,
  IMAGE_REPO_RE,
  type Build,
  type BuildConfig,
  type ComposeAppConfig,
  type ComposePlanService,
  type DeploymentCompose,
} from '@/lib/api/p4b-types';
import { ENV_KEY_RE, IMAGE_DIGEST_REF_RE, detectFramework } from '@/lib/api/p4-types';
import { hasDependencyCycle, inferHealth, scanComposeServices } from '@/lib/p4b-gates';
import { mockDigest } from './p3-data';
import { p3Internals, type P3Ctx } from './p3-routes';
import { composeHooks, p4Internals } from './p4-routes';
import { validateComposeMock } from './p4-compose';

const KEY = 'ppanel.mock.p4b';
const GIT_ALLOW = ['github.com', 'gitlab.com', 'git.example.lab'];
const REGISTRY_ALLOW = ['registry.example.lab', 'ghcr.io'];
/** Build phase schedule (ms from start). */
const B = { queued: 600, fetching: 1600, building: 4200, pushing: 5200 };

type Outcome = 'ok' | 'build_fail' | 'fetch_fail';
interface MockBuild extends Build {
  plan: { t0: number; outcome: Outcome; settled: boolean; cancelledAt?: number };
}
interface VersionRec {
  version: number;
  versionId: string;
  yaml: string;
  routeService: string;
  routePort: number;
  healthPath: string;
  createdAt: string;
  createdBy: string | null;
}
interface P4bState {
  builds: MockBuild[];
  gitAuth: Record<string, { updatedAt: string }>;
  versions: Record<string, VersionRec[]>;
  inspections: Record<string, { t0: number; appId: string; commitSha: string; jobId: string }>;
}
interface U {
  id: string;
  displayName: string;
}
type MockApp = Application & { container: ContainerSpec };

let st: P4bState | null = null;
let ctx: P3Ctx;

function storage(): Storage | null {
  try {
    return typeof window !== 'undefined' ? window.sessionStorage : null;
  } catch {
    return null;
  }
}
function save() {
  try {
    storage()?.setItem(KEY, JSON.stringify(st));
  } catch {
    /* memory only */
  }
}
export function resetP4bState() {
  st = null;
  storage()?.removeItem(KEY);
}
function s(): P4bState {
  // Ensure the P4 store exists first (its seed calls ours).
  p4Internals.state();
  if (!st) {
    const raw = storage()?.getItem(KEY);
    if (raw)
      try {
        st = JSON.parse(raw) as P4bState;
      } catch {
        st = null;
      }
    if (!st) {
      st = { builds: [], gitAuth: {}, versions: {}, inspections: {} };
      save();
    }
  }
  return st;
}

const iso = (ms: number) => new Date(ms).toISOString();
const apps = () => p3Internals.state().apps;
const hex8 = (id: string) => id.replace(/-/g, '').slice(-8);
const userOf = (id: string | null): U =>
  (ctx.users().find((x) => x.id === id) ?? ctx.users()[0]!) as U;
const need = (u: U, perm: Parameters<P3Ctx['requirePerm']>[1], srv?: Server) =>
  ctx.requirePerm(u as never, perm, srv);
const can = (u: U, perm: Parameters<P3Ctx['hasPermFor']>[1], srv?: Server) =>
  ctx.hasPermFor(u as never, perm, srv);

function hostOf(url: string) {
  return /^[a-z]+:\/\/([^/:]+)/i.exec(url)?.[1]?.toLowerCase() ?? '';
}
function repoSlug(url: string): string | null {
  const m = /^[a-z]+:\/\/[^/]+\/([^/]+)\/([^/]+?)(?:\.git)?$/i.exec(url);
  return m ? `${m[1]}/${m[2]}` : null;
}

// ---------------------------------------------------------------- build log + orchestration

function buildLines(b: MockBuild, phase: 'fetching' | 'building' | 'pushing'): string[] {
  const short = b.commitSha.slice(0, 12);
  if (phase === 'fetching')
    return [
      `git init /var/lib/ppanel/builds/${hex8(b.id)}`,
      `git fetch --depth 1 origin ${b.commitSha}`,
      `HEAD is now at ${short}`,
      'source.size 4.1 MiB · 312 files',
    ];
  if (phase === 'pushing')
    return [
      `docker push ${b.pushRepo}:build-${b.id.replace(/-/g, '').slice(0, 12)}`,
      'layer 1/7 pushed',
      'layer 5/7 pushed',
      'layer 7/7 pushed',
      `digest: sha256:${mockDigest(b.id)} size: 2412`,
    ];
  const tpl = b.template ?? 'Dockerfile';
  const steps = [
    `docker build --network ${'default'} --memory 2048m --cpus 2 -f ${b.dockerfile ?? `<template:${tpl}>`} .`,
    '#1 [internal] load build definition',
    '#2 [internal] load metadata for docker.io/library/node:22-alpine',
    '#3 [base 1/3] FROM docker.io/library/node:22-alpine@sha256:4b9a…',
    '#4 [deps 1/2] COPY package.json pnpm-lock.yaml ./',
    '#5 [deps 2/2] RUN corepack enable && pnpm install --frozen-lockfile',
  ];
  for (let i = 1; i <= 24; i++)
    steps.push(
      `#5 ${(i * 0.41).toFixed(2)} Progress: resolved ${i * 61}, reused ${i * 58}, downloaded ${i * 3}`,
    );
  steps.push(
    '#5 DONE 11.2s',
    '#6 [build 1/2] COPY . .',
    '#7 [build 2/2] RUN pnpm build',
    '#7 3.10 > build',
    '#7 9.84 compiled successfully',
    '#8 [runtime 1/2] COPY --from=build /app/dist ./dist',
    '#9 exporting to image',
    '#9 naming to build-local:latest done',
  );
  return steps;
}

function settleBuild(b: MockBuild, now: number): boolean {
  if (b.plan.settled) return false;
  const el = (b.plan.cancelledAt ?? now) - b.plan.t0;
  const failAt: 'fetching' | 'building' | null =
    b.plan.outcome === 'fetch_fail'
      ? 'fetching'
      : b.plan.outcome === 'build_fail'
        ? 'building'
        : null;
  const lines: string[] = [`queued on build node · job ${b.jobId?.slice(0, 8)}`];
  const phases: Array<['fetching' | 'building' | 'pushing', number, number]> = [
    ['fetching', B.queued, B.fetching],
    ['building', B.fetching, B.building],
    ['pushing', B.building, B.pushing],
  ];
  let status: Build['status'] = 'queued';
  for (const [ph, start, end] of phases) {
    if (el < start) break;
    // The Center reports queued → building → terminal only (no fetch/push progress channel).
    status = 'building';
    const all = buildLines(b, ph);
    const p = Math.min(1, (el - start) / (end - start));
    if (failAt === ph && p >= 0.6) {
      lines.push(...all.slice(0, Math.ceil(all.length * 0.6)));
      if (ph === 'building')
        lines.push(
          '#7 [build 2/2] RUN pnpm build',
          '#7 4.21 src/main.ts(12,7): error TS2304: Cannot find name "bootstrapApp".',
          '#7 ERROR: process "/bin/sh -c pnpm build" did not complete successfully: exit code: 2',
          'failed to solve: exit code 2',
        );
      else
        lines.push('fatal: remote error: upload-pack: not our ref', 'git fetch failed (exit 128)');
      b.status = 'failed';
      b.error =
        ph === 'building'
          ? {
              code: 'IMAGE_BUILD_FAILED',
              message:
                'RUN pnpm build exited with code 2 (see log). Nothing was pushed or deployed.',
            }
          : {
              code: 'GIT_FETCH_FAILED',
              message: 'Commit not reachable from the remote (not our ref).',
            };
      return finish(b, lines, b.plan.t0 + start + (end - start) * 0.6);
    }
    lines.push(...all.slice(0, Math.max(1, Math.ceil(all.length * p))));
  }
  b.logTail = lines.slice(-20);
  (b as MockBuild & { log?: string[] }).log = lines;
  if (b.plan.cancelledAt !== undefined) {
    b.status = 'cancelled';
    lines.push('build cancelled by operator; builder container removed');
    return finish(b, lines, b.plan.cancelledAt);
  }
  if (el < B.pushing) {
    const changed = b.status !== status;
    b.status = status;
    b.updatedAt = iso(now);
    return changed || true;
  }
  b.status = 'succeeded';
  b.image = `${b.pushRepo}@sha256:${mockDigest(b.id)}`;
  lines.push(`pushed ${b.image}`);
  finish(b, lines, b.plan.t0 + B.pushing);
  if (b.deployAfter) {
    const app = apps().find((a) => a.id === b.applicationId) as MockApp | undefined;
    if (app?.container) {
      try {
        const d = p4Internals.createDeployment(
          userOf(b.createdBy),
          app,
          b.image,
          'manual',
          ctx.rid(),
          {
            sourceRef: {
              ...(app.build?.config.repo ? { repo: app.build.config.repo } : {}),
              commitSha: b.commitSha,
              ...(b.branch ? { branch: b.branch } : {}),
            },
            reason: `Build ${b.commitSha.slice(0, 7)}`,
            buildId: b.id,
          },
        );
        b.deploymentId = d.id;
      } catch (e) {
        const err = e as { code?: string; message?: string };
        b.deployError = {
          code: err.code ?? 'DEPLOY_FAILED',
          message: err.message ?? 'Deployment not created',
        };
      }
    }
  }
  return true;
}

function finish(b: MockBuild, lines: string[], at: number) {
  (b as MockBuild & { log?: string[] }).log = lines;
  b.logTail = lines.slice(-20);
  b.finishedAt = iso(at);
  b.updatedAt = b.finishedAt;
  b.durationMs = Math.max(0, at - b.plan.t0);
  b.plan.settled = true;
  const app = apps().find((a) => a.id === b.applicationId);
  if (app?.build)
    app.build.lastBuild = {
      id: b.id,
      status: b.status,
      commitSha: b.commitSha,
      image: b.image,
      finishedAt: b.finishedAt,
    };
  p3Internals.save();
  return true;
}

function tickBuilds() {
  const now = Date.now();
  let dirty = false;
  for (const b of s().builds) if (settleBuild(b, now)) dirty = true;
  if (dirty) save();
}

function publicBuild(b: MockBuild, u?: U): Build {
  const { plan: _p, ...rest } = b as MockBuild & { log?: string[] };
  void _p;
  delete (rest as { log?: string[] }).log;
  const srv = ctx.servers().find((x) => x.id === b.buildServerId);
  const app = apps().find((a) => a.id === b.applicationId);
  const dep = b.deploymentId
    ? p4Internals.state().deployments.find((d) => d.id === b.deploymentId)
    : null;
  const live = ['queued', 'fetching', 'building', 'pushing'].includes(b.status);
  const appSrv = app ? ctx.servers().find((x) => x.id === app.serverId) : undefined;
  return {
    ...rest,
    allowedActions: [
      'view_log',
      ...(live && u && can(u, 'apps.deploy', appSrv) ? (['cancel'] as const) : []),
    ],
    buildServerName: srv?.name,
    createdByLabel:
      ctx.users().find((x) => x.id === b.createdBy)?.displayName ??
      (b.trigger === 'webhook' ? 'GitHub webhook' : null),
    deploymentNumber: dep?.number ?? null,
  };
}

function buildOf(id: string) {
  const b = s().builds.find((x) => x.id === id);
  if (!b) throw new ctx.HttpError(404, 'NOT_FOUND', 'Build not found');
  return b;
}

function newBuild(
  app: MockApp,
  cfg: BuildConfig,
  commitSha: string,
  o: {
    branch?: string | null;
    deployAfter: boolean;
    createdBy: string | null;
    t0: number;
    trigger?: 'manual' | 'webhook';
  },
): MockBuild {
  const id = ctx.rid();
  return {
    id,
    applicationId: app.id,
    buildServerId: cfg.buildServerId,
    status: 'queued',
    commitSha,
    branch: o.branch ?? null,
    trigger: o.trigger ?? 'manual',
    image: null,
    template: cfg.template,
    dockerfile: cfg.dockerfile,
    pushRepo: cfg.pushRepo,
    deployAfter: o.deployAfter,
    logTail: [],
    error: null,
    durationMs: null,
    jobId: ctx.rid(),
    deploymentId: null,
    deployError: null,
    createdBy: o.createdBy,
    createdAt: iso(o.t0),
    updatedAt: iso(o.t0),
    finishedAt: null,
    allowedActions: [],
    plan: {
      t0: o.t0,
      outcome: commitSha.startsWith('dead')
        ? 'build_fail'
        : commitSha.startsWith('bad0')
          ? 'fetch_fail'
          : 'ok',
      settled: false,
    },
  };
}

// ---------------------------------------------------------------- compose: normalise + plan

function normalise(
  yaml: string,
  route: { service: string; port: number; healthPath: string },
): ComposePlanService[] {
  return scanComposeServices(yaml).map((x) => {
    const h = inferHealth(x, route);
    return {
      service: x.name,
      image: x.image ?? '',
      env: Object.fromEntries(
        x.envKeys.filter((k) => !x.placeholders.includes(k)).map((k) => [k, '…']),
      ),
      secretEnv: Object.fromEntries(x.placeholders.map((k) => [k, k])),
      volumes: x.volumes,
      dependsOn: x.dependsOn,
      health:
        h.type === 'http'
          ? { ...h, expectStatus: [200], intervalSec: 2, timeoutSec: 3, startPeriodSec: 60 }
          : h.type === 'tcp'
            ? { ...h, startPeriodSec: 60 }
            : { type: 'running', startPeriodSec: 10 },
      ...(x.name === route.service ? { containerPort: route.port } : {}),
    } satisfies ComposePlanService;
  });
}

function validateCompose(
  yaml: string,
  environment: string,
  routeService: string,
  routePort: number,
) {
  const v = validateComposeMock(yaml, environment);
  const scanned = scanComposeServices(yaml);
  const add = (service: string | null, rule: string, path: string, message: string) =>
    v.violations.push({ service, rule: rule as never, path, message });
  if (!scanned.some((x) => x.name === routeService))
    add(
      null,
      'route_service_missing',
      'routeService',
      `Route service "${routeService}" is not defined.`,
    );
  for (const x of scanned) {
    if (!x.image)
      add(x.name, 'image_required', `services.${x.name}.image`, 'Every service needs an image.');
    if (x.ports.length && x.name !== routeService)
      add(
        x.name,
        'ports_not_route_service',
        `services.${x.name}.ports`,
        'Only the route service may publish a port (allocated by pPanel).',
      );
  }
  if (hasDependencyCycle(scanned.map((x) => ({ service: x.name, dependsOn: x.dependsOn }))))
    add(null, 'depends_on_cycle', 'services', 'depends_on has a cycle.');
  if (!(routePort >= 1 && routePort <= 65535))
    add(null, 'route_service_missing', 'routePort', '1–65535');
  // Route service ports are allocated by pPanel: drop the P4a loopback rule for it.
  v.violations = v.violations.filter(
    (x) => !(x.rule === 'port_non_loopback' && x.service === routeService),
  );
  v.valid = v.violations.length === 0;
  return v;
}

const resolve = (image: string) =>
  IMAGE_DIGEST_REF_RE.test(image)
    ? image
    : `${image.replace(/:[^/:]+$/, '')}@sha256:${mockDigest(`tag|${image}`)}`;

function specHash(x: ComposePlanService, resolved: string) {
  return mockDigest(
    JSON.stringify([
      resolved,
      x.env,
      x.secretEnv,
      x.volumes,
      x.dependsOn,
      x.health,
      x.containerPort ?? null,
    ]),
  );
}

function currentVersion(appId: string): VersionRec | undefined {
  const vs = s().versions[appId] ?? [];
  return vs[vs.length - 1];
}

function planFor(app: MockApp, trigger: Deployment['trigger']) {
  const deps = p4Internals.state().deployments;
  const cur = deps.find((d) => d.id === app.container.currentDeploymentId);
  const curSvcs = new Map((cur?.compose?.services ?? []).map((x) => [x.service, x]));
  let services: DeploymentCompose['services'];
  let version: number;
  let versionId: string;
  let routeService: string;
  if (trigger === 'rollback') {
    const prev = deps.find((d) => d.id === app.container.previousDeploymentId);
    if (!prev?.compose)
      throw new ctx.HttpError(409, 'ROLLBACK_UNAVAILABLE', 'No previous successful compose plan.');
    version = prev.compose.version;
    versionId = prev.compose.versionId;
    routeService = prev.compose.routeService;
    services = prev.compose.services.map((x) => {
      const c = curSvcs.get(x.service);
      const same = c?.specHash === x.specHash;
      return {
        ...x,
        name: same ? c!.name : `ppanel-${app.name}-${x.service}-${hex8(ctx.rid())}`,
        plannedAction: same ? 'unchanged' : 'replace',
        action: null,
        previousName: same ? null : (c?.name ?? null),
        health: null,
      };
    });
  } else {
    const v = currentVersion(app.id);
    if (!v) throw new ctx.HttpError(409, 'COMPOSE_VERSION_NOT_FOUND', 'No compose version stored.');
    version = v.version;
    versionId = v.versionId;
    routeService = v.routeService;
    const norm = normalise(v.yaml, {
      service: v.routeService,
      port: v.routePort,
      healthPath: v.healthPath,
    });
    services = norm.map((x) => {
      const image = resolve(x.image);
      const hash = specHash(x, image);
      const c = curSvcs.get(x.service);
      const same = trigger !== 'redeploy' && c?.specHash === hash;
      return {
        service: x.service,
        image,
        sourceImage: x.image,
        specHash: hash,
        name: same ? c!.name : `ppanel-${app.name}-${x.service}-${hex8(ctx.rid())}`,
        plannedAction: same ? 'unchanged' : 'replace',
        action: null,
        previousName: same ? null : (c?.name ?? null),
        hostPort:
          x.service === v.routeService ? 20000 + (parseInt(hash.slice(0, 4), 16) % 900) : null,
        health: null,
      };
    });
  }
  const route = services.find((x) => x.service === routeService)!;
  return {
    compose: { versionId, version, routeService, services, dataRestored: false as const },
    routeImage: route.image,
    routeChanged: route.plannedAction === 'replace',
  };
}

function composeConfig(
  app: Application,
  v: VersionRec,
  warnings: ComposeAppConfig['warnings'],
): ComposeAppConfig {
  const services = normalise(v.yaml, {
    service: v.routeService,
    port: v.routePort,
    healthPath: v.healthPath,
  });
  return {
    version: v.version,
    versionId: v.versionId,
    routeService: v.routeService,
    routePort: v.routePort,
    healthPath: v.healthPath,
    services,
    secretKeys: [...new Set(services.flatMap((x) => Object.values(x.secretEnv)))],
    warnings,
    currentDeploymentId: app.container?.currentDeploymentId ?? null,
    previousDeploymentId: app.container?.previousDeploymentId ?? null,
    containerName: app.container?.containerName ?? null,
    hostPort: app.container?.hostPort ?? null,
    routePath: `/etc/nginx/ppanel-managed/${app.name}/route.conf`,
    tls: null,
    rollbackAvailable: !!app.container?.rollbackAvailable,
    rollback: { dataRestored: false },
    createdAt: v.createdAt,
    yaml: v.yaml,
  };
}

function applyVersion(app: MockApp, v: VersionRec, warnings: ComposeAppConfig['warnings']) {
  app.compose = composeConfig(app, v, warnings);
  app.container.containerPort = v.routePort;
  app.container.healthcheck = { ...app.container.healthcheck, path: v.healthPath };
}

// ---------------------------------------------------------------- seed

const CRM_YAML = (appImage: string) => `services:
  app:
    image: ${appImage}
    environment:
      APP_ENV: production
      DB_HOST: db
      REDIS_HOST: redis
      DB_PASSWORD: \${DB_PASSWORD}
      APP_KEY: \${APP_KEY}
    depends_on: [db, redis]
  worker:
    image: registry.example.lab/w3/crm-worker@sha256:${mockDigest('crm-worker-1')}
    command: ["php", "artisan", "queue:work"]
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
    depends_on: [db, redis]
  db:
    image: postgres:16.4
    environment:
      POSTGRES_PASSWORD: \${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
  redis:
    image: redis:7.4
volumes:
  pgdata: {}
`;

function seed(p4: {
  deployments: Deployment[];
  secrets: Record<string, Record<string, { version: number; updatedAt: string }>>;
}) {
  st = { builds: [], gitAuth: {}, versions: {}, inspections: {} };
  const servers = ctx.servers();
  const by = (n: string) => servers.find((x) => x.name === n)!;
  const [owner, admin, dev] = [ctx.users()[0]!, ctx.users()[1]!, ctx.users()[2]!];
  const now = Date.now();
  const node = by('dev-01');

  // shop-api: build config (NestJS template on dev-01) + two builds.
  const shop = apps().find((a) => a.name === 'shop-api' && a.kind === 'container') as
    MockApp | undefined;
  if (shop) {
    const cfg: BuildConfig = {
      repoUrl: 'https://github.com/w3co/shop-api.git',
      repo: 'w3co/shop-api',
      subdir: '',
      dockerfile: null,
      template: 'nestjs',
      buildArgs: { NODE_ENV: 'production' },
      target: null,
      buildServerId: node.id,
      pushRepo: 'registry.example.lab/w3/shop-api',
      network: 'default',
      limits: { memoryMb: 2048, cpus: 2, timeoutSec: 900 },
      gitAuth: { set: true },
      updatedAt: iso(now - 6 * 864e5),
      version: 1,
    };
    shop.build = { config: cfg, lastBuild: null };
    st.gitAuth[shop.id] = { updatedAt: iso(now - 6 * 864e5) };
    const s4 = p4.deployments.find((d) => d.applicationId === shop.id && d.number === 4);
    const okSha = mockDigest('shop-commit-4').slice(0, 40);
    const b1 = newBuild(shop, cfg, okSha, {
      branch: 'main',
      deployAfter: false,
      createdBy: dev.id,
      t0: now - 200 * 60e3,
    });
    settleBuild(b1, now);
    b1.deployAfter = true;
    if (s4) {
      b1.image = s4.image;
      b1.deploymentId = s4.id;
      s4.buildId = b1.id;
      s4.sourceRef = { repo: 'w3co/shop-api', commitSha: okSha, branch: 'main' };
    }
    const b0 = newBuild(shop, cfg, `dead${mockDigest('shop-bad').slice(4, 40)}`, {
      branch: 'feature/bootstrap',
      deployAfter: false,
      createdBy: admin.id,
      t0: now - 26 * 3600e3,
    });
    settleBuild(b0, now);
    st.builds.push(b0, b1);
    shop.build.lastBuild = {
      id: b1.id,
      status: b1.status,
      commitSha: b1.commitSha,
      image: b1.image,
      finishedAt: b1.finishedAt,
    };
  }

  // crm-suite: compose app (app + worker + postgres + redis) on app-uat-01 with one deployment.
  const srv = by('app-uat-01');
  const id = '01934f2a-c001-7000-8000-000000000010';
  if (!apps().some((a) => a.id === id)) {
    const app = p4Internals.containerApp(
      id,
      srv,
      'crm-suite',
      ['crm.uat.example.lab'],
      {
        containerPort: 8000,
        healthcheck: {
          path: '/',
          expectStatus: [200],
          intervalSec: 2,
          timeoutSec: 3,
          startPeriodSec: 60,
        },
        secretKeys: ['DB_PASSWORD', 'APP_KEY'],
        env: {},
      },
      24 * 6,
    ) as MockApp;
    app.kind = 'compose';
    const v: VersionRec = {
      version: 1,
      versionId: ctx.rid(),
      yaml: CRM_YAML(`registry.example.lab/w3/crm-app@sha256:${mockDigest('crm-app-1')}`),
      routeService: 'app',
      routePort: 8000,
      healthPath: '/',
      createdAt: iso(now - 3 * 864e5),
      createdBy: owner.id,
    };
    st.versions[app.id] = [v];
    applyVersion(app, v, [
      {
        service: 'db',
        rule: 'image_not_pinned',
        path: 'services.db.image',
        message: 'postgres:16.4 is resolved to a digest at deploy time.',
      },
    ]);
    apps().push(app);
    const d = p4Internals.seedDeployment(
      app,
      1,
      'manual',
      60 * 24 * 2,
      admin as U,
      'crm-app-1',
    ) as Deployment & {
      plan: { kind?: string; routeChanged?: boolean };
    };
    const plan = planFor(app, 'manual');
    plan.compose.services.forEach((x) => {
      x.action = 'created';
      x.health = x.service === 'app' ? 'healthy (http 200)' : 'healthy';
    });
    d.compose = plan.compose;
    d.image = plan.routeImage;
    const names = [
      'preflight',
      'resolve_images',
      'compose_apply',
      'route_switch',
      'stop_previous',
    ] as const;
    const msgs = [
      'All checks passed',
      'Image tags resolved to digests',
      'compose.apply done — 4 services created',
      `route → 127.0.0.1:${d.container?.hostPort}`,
      'Nothing to stop (first deployment)',
    ];
    d.steps = d.steps.map((x, i) => ({ ...x, name: names[i]!, message: msgs[i]! }));
    d.plan.kind = 'compose';
    d.plan.routeChanged = true;
    p4.deployments.push(d);
    p4Internals.point(app, d, null);
    app.container.runtimeState = 'running';
    p4.secrets[app.id] = {
      DB_PASSWORD: { version: 1, updatedAt: iso(now - 3 * 864e5) },
      APP_KEY: { version: 1, updatedAt: iso(now - 3 * 864e5) },
    };
  }
  save();
}

// ---------------------------------------------------------------- routes

export function registerP4bRoutes(c: P3Ctx) {
  ctx = c;
  const { on, ok, HttpError } = c;

  composeHooks.seed = (p4) => seed(p4 as never);
  composeHooks.tick = () => tickBuilds();
  composeHooks.plan = (app, trigger) => planFor(app as MockApp, trigger);
  composeHooks.create = (u, srv, body, requestId) => {
    const errs: Array<{ field: string; message: string }> = [];
    const name = String(body.name ?? '');
    if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(name))
      errs.push({ field: 'name', message: 'lowercase slug' });
    if (apps().some((a) => a.serverId === srv.id && a.name === name))
      throw new HttpError(
        409,
        'APP_NAME_TAKEN',
        `An application named ${name} already exists on ${srv.name}.`,
      );
    const domains = Array.isArray(body.domains) ? (body.domains as string[]) : [];
    if (!domains.length) errs.push({ field: 'domains', message: 'At least one domain' });
    const yaml = String(body.yaml ?? '');
    const routeService = String(body.routeService ?? '');
    const routePort = Number(body.routePort);
    const healthPath = String(body.healthPath ?? '/') || '/';
    if (errs.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
    const v = validateCompose(yaml, srv.environment, routeService, routePort);
    if (!v.valid)
      throw new HttpError(422, 'COMPOSE_INVALID', 'The compose file was refused.', {
        violations: v.violations,
      });
    const conflicts = domains.filter((d) => apps().some((a) => a.domains.includes(d)));
    if (conflicts.length)
      throw new HttpError(
        409,
        'DOMAIN_CONFLICT',
        `Domain already in use: ${conflicts.join(', ')}.`,
        {
          checks: [
            {
              check: 'domain_conflict',
              ok: false,
              code: 'DOMAIN_CONFLICT',
              message: `Domain already in use: ${conflicts.join(', ')}.`,
            },
          ],
        },
      );
    const app = p4Internals.containerApp(
      c.rid(),
      srv,
      name,
      domains,
      {
        containerPort: routePort,
        healthcheck: {
          path: healthPath,
          expectStatus: [200],
          intervalSec: 2,
          timeoutSec: 3,
          startPeriodSec: 60,
        },
        env: {},
        runtimeState: 'unknown',
      },
      0,
    ) as MockApp;
    app.kind = 'compose';
    app.createdAt = iso(Date.now());
    app.updatedAt = app.createdAt;
    const rec: VersionRec = {
      version: 1,
      versionId: c.rid(),
      yaml,
      routeService,
      routePort,
      healthPath,
      createdAt: app.createdAt,
      createdBy: u.id,
    };
    s().versions[app.id] = [rec];
    applyVersion(app, rec, v.warnings);
    app.container.secretKeys = app.compose!.secretKeys;
    apps().push(app);
    p3Internals.save();
    save();
    c.audit(u, 'application.create', srv, 'success', requestId);
    return ok(requestId, p3Internals.decorate(u, app), 201);
  };

  const containerOnly = (id: string) => {
    const a = p4Internals.containerAppOf(id) as MockApp;
    if (a.kind !== 'container')
      throw new HttpError(409, 'NOT_CONTAINER_APP', 'Builds apply to container applications only.');
    return a;
  };
  const composeOnly = (id: string) => {
    const a = p4Internals.containerAppOf(id) as MockApp;
    if (a.kind !== 'compose' || !a.compose)
      throw new HttpError(409, 'NOT_COMPOSE_APP', 'This application is not a compose application.');
    return a;
  };

  // ---- build config + git auth
  on('GET', '/applications/:id/build-config', ({ req, params, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    return ok(requestId, a.build?.config ?? null);
  });

  on('PUT', '/applications/:id/build-config', ({ req, params, body, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    const ifMatch = req.headers.get('If-Match');
    if (ifMatch && a.build && Number(ifMatch) !== a.build.config.version)
      throw new HttpError(
        409,
        'VERSION_CONFLICT',
        'The build config changed. Reload and try again.',
        {
          currentVersion: a.build.config.version,
        },
      );
    const errs: Array<{ field: string; message: string }> = [];
    const repoUrl = String(body.repoUrl ?? '').trim();
    if (!GIT_URL_RE.test(repoUrl))
      errs.push({ field: 'repoUrl', message: 'https://host/path without credentials' });
    const hasD = !!body.dockerfile;
    const hasT = !!body.template;
    if (hasD === hasT)
      errs.push({
        field: 'dockerfile',
        message: 'exactly one of dockerfile or template is required',
      });
    if (hasT && !['nextjs', 'nestjs', 'laravel'].includes(String(body.template)))
      errs.push({ field: 'template', message: 'nextjs | nestjs | laravel' });
    const pushRepo = String(body.pushRepo ?? '');
    if (!IMAGE_REPO_RE.test(pushRepo))
      errs.push({ field: 'pushRepo', message: 'registry/repository' });
    const args = (body.buildArgs ?? {}) as Record<string, string>;
    for (const k of Object.keys(args))
      if (!ENV_KEY_RE.test(k)) errs.push({ field: `buildArgs.${k}`, message: 'Invalid key' });
    const buildServer = ctx.servers().find((x) => x.id === body.buildServerId);
    if (!buildServer) errs.push({ field: 'buildServerId', message: 'Unknown server' });
    if (errs.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
    if (!GIT_ALLOW.includes(hostOf(repoUrl)))
      throw new HttpError(
        422,
        'GIT_HOST_NOT_ALLOWED',
        `Git host ${hostOf(repoUrl)} is not in PPANEL_GIT_HOST_ALLOWLIST.`,
      );
    if (!REGISTRY_ALLOW.includes(pushRepo.split('/')[0]!.split(':')[0]!))
      throw new HttpError(
        422,
        'REGISTRY_NOT_ALLOWED',
        `Registry ${pushRepo.split('/')[0]} is not allowlisted.`,
      );
    const limits = (body.limits ?? {}) as Partial<BuildConfig['limits']>;
    const prev = a.build?.config;
    const cfg: BuildConfig = {
      repoUrl,
      repo: repoSlug(repoUrl),
      subdir: String(body.subdir ?? ''),
      dockerfile: hasD ? String(body.dockerfile) : null,
      template: hasT ? (body.template as BuildConfig['template']) : null,
      buildArgs: args,
      target: body.target ? String(body.target) : null,
      buildServerId: buildServer!.id,
      pushRepo,
      network: body.network === 'none' ? 'none' : 'default',
      limits: {
        memoryMb: limits.memoryMb ?? 2048,
        cpus: limits.cpus ?? 2,
        timeoutSec: limits.timeoutSec ?? 900,
      },
      gitAuth: { set: !!s().gitAuth[a.id] },
      updatedAt: iso(Date.now()),
      version: (prev?.version ?? 0) + 1,
    };
    a.build = { config: cfg, lastBuild: a.build?.lastBuild ?? null };
    a.updatedAt = cfg.updatedAt;
    p3Internals.save();
    c.audit(u, 'build_config.put', srv, 'success', requestId);
    return ok(requestId, cfg);
  });

  on('GET', '/applications/:id/git-auth', ({ req, params, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const g = s().gitAuth[a.id];
    return ok(requestId, { set: !!g, updatedAt: g?.updatedAt ?? null });
  });

  on('PUT', '/applications/:id/git-auth', ({ req, params, body, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    if (typeof body.token !== 'string' || !body.token)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Token required', [
        { field: 'token', message: 'Required' },
      ]);
    if (srv.environment === 'production' && !c.checkStepUp(req, u)) {
      c.audit(u, 'git_auth.put', srv, 'denied', requestId);
      throw new HttpError(
        403,
        'STEP_UP_REQUIRED',
        'This action requires a fresh 2FA confirmation (X-Step-Up).',
      );
    }
    // The token itself is dropped: the mock never stores secret values.
    s().gitAuth[a.id] = { updatedAt: iso(Date.now()) };
    if (a.build) a.build.config.gitAuth = { set: true };
    p3Internals.save();
    save();
    c.audit(u, 'git_auth.put', srv, 'success', requestId);
    return ok(requestId, { set: true, updatedAt: s().gitAuth[a.id]!.updatedAt });
  });

  // ---- source inspection (pending → succeeded after ~0.8 s)
  const inspectionView = (iid: string) => {
    const rec = s().inspections[iid];
    if (!rec) throw new HttpError(404, 'NOT_FOUND', 'Inspection not found');
    const a = apps().find((x) => x.id === rec.appId)!;
    const done = Date.now() - rec.t0 >= 800;
    if (!done)
      return {
        inspectionId: iid,
        jobId: rec.jobId,
        status: 'pending' as const,
        commitSha: rec.commitSha,
        files: {},
        truncated: [],
        detection: null,
        error: null,
      };
    if (rec.commitSha.startsWith('bad0'))
      return {
        inspectionId: iid,
        jobId: rec.jobId,
        status: 'failed' as const,
        commitSha: rec.commitSha,
        files: {},
        truncated: [],
        detection: null,
        error: { code: 'GIT_FETCH_FAILED', message: 'Commit not reachable from the remote.' },
      };
    const tpl = a.build?.config.template ?? 'nestjs';
    const files: Record<string, string> =
      tpl === 'nextjs'
        ? {
            'package.json':
              '{"dependencies":{"next":"15.0.3","react":"19.0.0"},"scripts":{"build":"next build","start":"next start"}}',
            'next.config.mjs': 'export default {}',
          }
        : tpl === 'laravel'
          ? { 'composer.json': '{"require":{"laravel/framework":"^11.0"}}', artisan: '' }
          : {
              'package.json':
                '{"dependencies":{"@nestjs/core":"^10.4.0","@nestjs/common":"^10.4.0"},"scripts":{"build":"nest build","start:prod":"node dist/main"}}',
              'nest-cli.json': '{"collection":"@nestjs/schematics"}',
              Dockerfile: 'FROM node:22-alpine\nEXPOSE 3000\nCMD ["node","dist/main"]',
            };
    return {
      inspectionId: iid,
      jobId: rec.jobId,
      status: 'succeeded' as const,
      commitSha: rec.commitSha,
      files,
      truncated: [],
      detection: detectFramework(files),
      error: null,
    };
  };

  on('POST', '/applications/:id/source/inspect', ({ req, params, body, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    need(u, 'apps.deploy', p3Internals.serverOf(a.serverId));
    const sha = String(body.commitSha ?? '');
    if (!COMMIT_SHA_RE.test(sha))
      throw new HttpError(422, 'VALIDATION_FAILED', 'commitSha must be 40 lowercase hex', [
        { field: 'commitSha', message: '40 hex' },
      ]);
    if (!a.build) throw new HttpError(409, 'BUILD_CONFIG_MISSING', 'Save a build config first.');
    const node = ctx.servers().find((x) => x.id === a.build!.config.buildServerId);
    if (!node?.buildNode || !node.capabilities.includes('build'))
      throw new HttpError(
        409,
        'NO_BUILD_NODE',
        'The configured server is not an eligible build node.',
      );
    const iid = c.rid();
    s().inspections[iid] = { t0: Date.now(), appId: a.id, commitSha: sha, jobId: c.rid() };
    save();
    return ok(requestId, inspectionView(iid), 202);
  });

  on('GET', '/applications/:id/source/inspect/:iid', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    return ok(requestId, inspectionView(params[1]!));
  });

  // ---- builds
  on('POST', '/applications/:id/builds', ({ req, params, body, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    const sha = String(body.commitSha ?? '');
    if (!COMMIT_SHA_RE.test(sha))
      throw new HttpError(422, 'VALIDATION_FAILED', 'commitSha must be 40 lowercase hex', [
        { field: 'commitSha', message: '40 hex' },
      ]);
    if (!a.build) throw new HttpError(409, 'BUILD_CONFIG_MISSING', 'Save a build config first.');
    const key = req.headers.get('Idempotency-Key');
    const dup = key
      ? s().builds.find((b) => (b as MockBuild & { idem?: string }).idem === key)
      : null;
    if (dup) return ok(requestId, { build: publicBuild(dup, u) }, 200);
    const node = ctx.servers().find((x) => x.id === a.build!.config.buildServerId);
    if (
      !node?.buildNode ||
      !node.capabilities.includes('build') ||
      (node.status !== 'online' && node.status !== 'degraded')
    )
      throw new HttpError(
        409,
        'NO_BUILD_NODE',
        `${node?.name ?? 'The build server'} is not an eligible build node (needs buildNode + build capability + online).`,
      );
    const existing = s().builds.find(
      (b) => b.applicationId === a.id && b.commitSha === sha && b.status === 'succeeded',
    );
    if (existing && body.force !== true)
      return ok(requestId, { build: publicBuild(existing, u), reused: true }, 200);
    if (
      s().builds.some(
        (b) =>
          b.applicationId === a.id &&
          b.commitSha === sha &&
          ['queued', 'fetching', 'building', 'pushing'].includes(b.status),
      )
    )
      throw new HttpError(409, 'BUILD_STATE_INVALID', 'A build of this commit is already running.');
    const b = newBuild(a, a.build.config, sha, {
      branch: typeof body.branch === 'string' ? body.branch : null,
      deployAfter: body.deployAfter !== false,
      createdBy: u.id,
      t0: Date.now(),
    });
    (b as MockBuild & { idem?: string }).idem = key ?? undefined;
    s().builds.push(b);
    save();
    c.audit(u, 'build.create', srv, 'success', requestId);
    return ok(requestId, { build: publicBuild(b, u) }, 202);
  });

  on('GET', '/applications/:id/builds', ({ req, params, url, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = containerOnly(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const items = s()
      .builds.filter((b) => b.applicationId === a.id)
      .sort((x, y) => y.createdAt.localeCompare(x.createdAt))
      .map((b) => publicBuild(b, u));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('GET', '/builds/:id', ({ req, params, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const b = buildOf(params[0]!);
    const a = apps().find((x) => x.id === b.applicationId)!;
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    return ok(requestId, publicBuild(b, u));
  });

  on('GET', '/builds/:id/log', ({ req, params, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const b = buildOf(params[0]!);
    const a = apps().find((x) => x.id === b.applicationId)!;
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const all = (b as MockBuild & { log?: string[] }).log ?? b.logTail;
    return ok(requestId, {
      buildId: b.id,
      status: b.status,
      lines: all.slice(-2000),
      truncated: all.length > 2000,
    });
  });

  on('POST', '/builds/:id/cancel', ({ req, params, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const b = buildOf(params[0]!);
    const a = apps().find((x) => x.id === b.applicationId)!;
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    if (!['queued', 'fetching', 'building', 'pushing'].includes(b.status))
      throw new HttpError(409, 'BUILD_STATE_INVALID', `Cannot cancel a ${b.status} build.`);
    b.plan.cancelledAt = Date.now();
    settleBuild(b, Date.now());
    save();
    c.audit(u, 'build.cancel', srv, 'success', requestId);
    return ok(requestId, { build: publicBuild(b, u) });
  });

  // ---- compose versions
  on('GET', '/applications/:id/compose', ({ req, params, url, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = composeOnly(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const pub = p3Internals.decorate(u, a);
    const want = Number(url.searchParams.get('version') ?? 0);
    const v = want
      ? (s().versions[a.id] ?? []).find((x) => x.version === want)
      : currentVersion(a.id);
    if (!v) throw new HttpError(404, 'COMPOSE_VERSION_NOT_FOUND', `Version ${want} not found.`);
    return ok(requestId, {
      ...pub.compose,
      ...(want ? composeConfig(a, v, []) : {}),
      yaml: v.yaml,
    });
  });

  on('PUT', '/applications/:id/compose', ({ req, params, body, requestId }) => {
    p4Internals.tick();
    const u = c.currentUser(req);
    const a = composeOnly(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    const ifMatch = req.headers.get('If-Match');
    if (ifMatch && Number(ifMatch) !== a.version)
      throw new HttpError(
        409,
        'VERSION_CONFLICT',
        'This application changed since you loaded it. Reload and try again.',
        { currentVersion: a.version },
      );
    const yaml = String(body.yaml ?? '');
    const routeService = String(body.routeService ?? '');
    const routePort = Number(body.routePort);
    const healthPath = String(body.healthPath ?? '/') || '/';
    const v = validateCompose(yaml, srv.environment, routeService, routePort);
    if (!v.valid)
      throw new HttpError(422, 'COMPOSE_INVALID', 'The compose file was refused.', {
        violations: v.violations,
      });
    const vs = s().versions[a.id] ?? [];
    const rec: VersionRec = {
      version: (vs[vs.length - 1]?.version ?? 0) + 1,
      versionId: c.rid(),
      yaml,
      routeService,
      routePort,
      healthPath,
      createdAt: iso(Date.now()),
      createdBy: u.id,
    };
    s().versions[a.id] = [...vs, rec];
    applyVersion(a, rec, v.warnings);
    a.version += 1;
    a.updatedAt = rec.createdAt;
    p3Internals.save();
    save();
    c.audit(u, 'compose.update', srv, 'success', requestId);
    return ok(requestId, p3Internals.decorate(u, a));
  });
}
