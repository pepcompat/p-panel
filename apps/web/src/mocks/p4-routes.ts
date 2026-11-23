/**
 * Mock routes for API_CONTRACTS §7 (P4a): managed container applications, secrets (values are never
 * stored — the mock keeps only key + version), deployments with preflight / approval / cancel /
 * rollback / redeploy / restart / start / stop, container logs (redacted), managed routing, GitHub
 * webhook integrations + delivery history, auto-deploy policies, compose validation and detection.
 *
 * Deployment progress is time based and settled lazily on every request (no timers survive reloads).
 * Outcome of a candidate is chosen by the image digest prefix so tests can drive each failure:
 *   sha256:dead… → CANDIDATE_UNHEALTHY · sha256:0bad… → route switch failed (reverted)
 *   sha256:feed… → requires_manual_recovery · sha256:baad… → IMAGE_PULL_FAILED · anything else → ok
 */
import type { Permission, Server } from '@ppanel/shared-contracts';
import type { Application } from '@/lib/api/p3-types';
import type {
  AutoDeployPolicy,
  ContainerSpec,
  Deployment,
  DeploymentStep,
  Integration,
  ManagedRouting,
  PreflightCheck,
  PreflightCheckName,
  StepName,
  WebhookDelivery,
} from '@/lib/api/p4-types';
import { ENV_KEY_RE, IMAGE_DIGEST_REF_RE, detectFramework } from '@/lib/api/p4-types';
import { mockDigest } from './p3-data';
import { p3Internals, p3LoadHooks, type P3Ctx } from './p3-routes';
import { validateComposeMock } from './p4-compose';

const P4_KEY = 'ppanel.mock.p4';
const APPROVAL_TTL_MS = 60 * 60e3;
/** Step schedule (ms from start). */
const T = { preflight: 600, pull: 2200, health: 3800, route: 4800, stop: 5400 };

type Outcome = 'ok' | 'unhealthy' | 'route_fail' | 'manual' | 'pull_fail';
interface MockDeployment extends Deployment {
  plan: {
    t0: number | null;
    outcome: Outcome;
    settled: boolean;
    cancelledAt?: number;
    /** P4b compose deployment (steps resolve_images → compose_apply). */
    kind?: 'container' | 'compose';
    /** compose: route service replaced → route_switch + stop_previous run. */
    routeChanged?: boolean;
  };
}
interface MockRouting {
  enabled: boolean;
  status: NonNullable<ManagedRouting['status']>;
  planHash: string | null;
  approval: NonNullable<ManagedRouting['approval']>;
  createdBy: string | null;
  applyUntil: number | null;
  updatedAt: string | null;
}
/** Contract steps; rollback starts the kept container (`start_target`) instead of pulling. */
const stepNames = (rollback: boolean, compose = false): StepName[] =>
  compose
    ? ['preflight', 'resolve_images', 'compose_apply', 'route_switch', 'stop_previous']
    : [
        'preflight',
        rollback ? 'start_target' : 'pull_start',
        'health_check',
        'route_switch',
        'stop_previous',
      ];

interface P4State {
  deployments: MockDeployment[];
  secrets: Record<string, Record<string, { version: number; updatedAt: string }>>;
  registryAuth: Record<string, { serveraddress: string; username: string }>;
  routing: Record<string, MockRouting>;
  integrations: Integration[];
  deliveries: Record<string, WebhookDelivery[]>;
  policies: AutoDeployPolicy[];
  logs: Record<string, string[]>;
  noPortServers: string[];
}

interface U {
  id: string;
  displayName: string;
}

let st: P4State | null = null;
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
    storage()?.setItem(P4_KEY, JSON.stringify(st));
  } catch {
    /* keep in memory */
  }
}
export function resetP4State() {
  st = null;
  storage()?.removeItem(P4_KEY);
}

const iso = (ms: number) => new Date(ms).toISOString();
const digest = (seed: string) => `sha256:${mockDigest(seed)}`;
const hex8 = (id: string) => id.replace(/-/g, '').slice(-8);
const apps = () => p3Internals.state().apps;

function outcomeOf(image: string): Outcome {
  const h = image.split('@sha256:')[1] ?? '';
  if (h.startsWith('dead')) return 'unhealthy';
  if (h.startsWith('0bad')) return 'route_fail';
  if (h.startsWith('feed')) return 'manual';
  if (h.startsWith('baad')) return 'pull_fail';
  return 'ok';
}

// ---------------------------------------------------------------- seed

function containerApp(
  id: string,
  srv: Server,
  name: string,
  domains: string[],
  spec: Partial<ContainerSpec>,
  ageH: number,
): Application {
  const now = Date.now();
  return {
    id,
    serverId: srv.id,
    name,
    environment: srv.environment,
    kind: 'container',
    domains,
    ownershipMode: 'managed',
    flags: { unsupported: false, conflict: false, manualReview: false, driftDetected: false },
    reasons: [],
    unsupportedDirectives: [],
    sourceFindingFingerprint: mockDigest(`container|${name}`),
    nginxFiles: [
      {
        path: `/etc/nginx/ppanel-managed/${name}/route.conf`,
        lastKnownSha256: mockDigest(`route|${name}`),
      },
    ],
    driftFiles: [],
    lastScanId: null,
    allowedActions: [],
    version: 1,
    createdAt: iso(now - ageH * 3600e3),
    updatedAt: iso(now - 3 * 3600e3),
    container: {
      containerPort: 8080,
      healthcheck: {
        path: '/healthz',
        expectStatus: [200],
        intervalSec: 2,
        timeoutSec: 3,
        startPeriodSec: 60,
      },
      resources: { memoryMb: 512, cpus: 1, pids: 512 },
      env: { NODE_ENV: 'production', LOG_LEVEL: 'info' },
      volumes: [],
      currentDeploymentId: null,
      previousDeploymentId: null,
      hostPort: null,
      containerName: null,
      routePath: `/etc/nginx/ppanel-managed/${name}/route.conf`,
      rollbackAvailable: false,
      secretKeys: [],
      tls: null,
      image: null,
      runtimeState: 'running',
      ...spec,
    },
  };
}

function steps(
  status: 'succeeded' | 'unhealthy' | 'awaiting' | 'cancelled',
  t0: number,
  image: string,
  hostPort: number,
): DeploymentStep[] {
  const at = (ms: number) => iso(t0 + ms);
  return stepNames(false).map((name, i): DeploymentStep => {
    const start = [0, T.preflight, T.pull, T.health, T.route][i]!;
    const end = [T.preflight, T.pull, T.health, T.route, T.stop][i]!;
    const base = { name, jobId: name === 'preflight' ? null : ctx.rid(), logTail: [] as string[] };
    if (status === 'awaiting') {
      if (name === 'preflight')
        return {
          ...base,
          status: 'succeeded',
          startedAt: at(0),
          finishedAt: at(end),
          message: 'All checks passed',
        };
      return {
        ...base,
        jobId: null,
        status: 'pending',
        startedAt: null,
        finishedAt: null,
        message: null,
      };
    }
    if (status === 'unhealthy' && i >= 3)
      return {
        ...base,
        jobId: null,
        status: 'skipped',
        startedAt: null,
        finishedAt: null,
        message: 'Skipped — candidate unhealthy',
      };
    const failed = status === 'unhealthy' && name === 'health_check';
    return {
      ...base,
      status: failed ? 'failed' : 'succeeded',
      startedAt: at(start),
      finishedAt: at(end),
      message: failed ? 'GET /healthz → 503 (5/5 attempts)' : stepMessage(name, image, hostPort),
      logTail: failed
        ? ['health: GET /healthz → 503', 'health: GET /healthz → 503', 'candidate removed']
        : [],
    };
  });
}

function stepMessage(name: StepName, image: string, hostPort: number | null): string {
  switch (name) {
    case 'preflight':
      return 'All checks passed';
    case 'pull_start':
      return `Pulled ${image.split('@')[1]?.slice(0, 19) ?? ''}… · started on 127.0.0.1:${hostPort}`;
    case 'start_target':
      return `Started the kept container on 127.0.0.1:${hostPort}`;
    case 'health_check':
      return 'Healthy (GET /healthz → 200)';
    case 'route_switch':
      return `nginx -t ok · reloaded · route → 127.0.0.1:${hostPort}`;
    case 'stop_previous':
      return 'Previous container stopped (kept for rollback)';
    case 'resolve_images':
      return 'Image tags resolved to digests';
    case 'compose_apply':
      return 'compose.apply done — changed services healthy';
    default:
      return 'Done';
  }
}

function seedDeployment(
  app: Application,
  n: number,
  trigger: Deployment['trigger'],
  kind: 'succeeded' | 'unhealthy' | 'awaiting',
  ageMin: number,
  createdBy: U | null,
  imageSeed: string,
  sourceRef?: Deployment['sourceRef'],
): MockDeployment {
  const t0 = Date.now() - ageMin * 60e3;
  const id = `01934f2a-d${String(n).padStart(3, '0')}-7000-8000-${mockDigest(app.id + n).slice(0, 12)}`;
  const repo = `registry.example.lab/w3/${app.name}`;
  const image = `${repo}@${digest(imageSeed)}`;
  const hostPort = 20000 + Math.floor(Math.random() * 900) + n;
  const done = kind !== 'awaiting';
  return {
    id,
    applicationId: app.id,
    serverId: app.serverId,
    number: n,
    trigger,
    image,
    sourceRef: sourceRef ?? null,
    status:
      kind === 'succeeded' ? 'succeeded' : kind === 'unhealthy' ? 'failed' : 'awaiting_approval',
    steps: steps(kind, t0, image, hostPort),
    preflight: preflightOkList(),
    container: { name: `ppanel-${app.name}-${hex8(id)}`, hostPort },
    previousDeploymentId: null,
    rollbackOfDeploymentId: null,
    allowedActions: [],
    version: 1,
    updatedAt: iso(t0),
    planHash: mockDigest(`${app.id}|${app.serverId}|${image}|plan`),
    approval: {
      required: app.environment === 'production',
      approvedBy: app.environment === 'production' && done ? ctx.users()[0]!.id : null,
      approvedByLabel:
        app.environment === 'production' && done ? ctx.users()[0]!.displayName : null,
      approvedAt: app.environment === 'production' && done ? iso(t0 - 60e3) : null,
      expiresAt: app.environment === 'production' && done ? iso(t0 + APPROVAL_TTL_MS) : null,
    },
    reason: null,
    createdBy: createdBy?.id ?? null,
    createdByLabel: createdBy?.displayName ?? (trigger === 'webhook' ? 'GitHub webhook' : null),
    createdAt: iso(t0),
    finishedAt: done ? iso(t0 + (kind === 'unhealthy' ? T.health : T.stop)) : null,
    error:
      kind === 'unhealthy'
        ? {
            code: 'CANDIDATE_UNHEALTHY',
            message:
              'Candidate failed its health check; it was removed and the live version was not touched.',
            details: {
              logTail: [
                'health: GET /healthz → 503',
                'health: GET /healthz → 503',
                'candidate removed',
              ],
              attempts: 5,
              elapsedMs: 60000,
              reason: 'unexpected status',
              removed: true,
              lastStatus: 503,
            },
          }
        : null,
    plan: { t0, outcome: kind === 'unhealthy' ? 'unhealthy' : 'ok', settled: true },
  };
}

function preflightOkList(): PreflightCheck[] {
  return (
    [
      ['agent_online', 'Agent online'],
      ['managed_routing', 'Managed routing enabled'],
      ['image_pinned', 'Image pinned by digest'],
      ['secrets_present', 'All declared secrets are set'],
      ['domain_conflict', 'No domain conflicts'],
      ['port_alloc', 'Host port available'],
      ['disk', 'Disk usage OK'],
      ['lock', 'No other deployment in progress'],
    ] as Array<[PreflightCheckName, string]>
  ).map(([check, message]) => ({ check, ok: true, message }));
}

function point(app: Application, cur: Deployment, prev: Deployment | null) {
  app.container = {
    ...app.container!,
    currentDeploymentId: cur.id,
    previousDeploymentId: prev?.id ?? null,
    rollbackAvailable: !!prev,
    hostPort: cur.container?.hostPort ?? null,
    containerName: cur.container?.name ?? null,
    image: cur.image,
  };
}

function seed(): P4State {
  const servers = ctx.servers();
  const by = (n: string) => servers.find((x) => x.name === n)!;
  const [owner, admin, dev] = [ctx.users()[0]!, ctx.users()[1]!, ctx.users()[2]!];
  const now = Date.now();
  st = {
    deployments: [],
    secrets: {},
    registryAuth: {},
    routing: {},
    integrations: [],
    deliveries: {},
    policies: [],
    logs: {},
    noPortServers: [by('dev-sandbox-02').id],
  };
  for (const s of servers) {
    const on = [
      'app-prod-01',
      'app-prod-02',
      'app-uat-01',
      'worker-uat-01',
      'dev-sandbox-02',
    ].includes(s.name);
    st.routing[s.id] = {
      enabled: on,
      status: on ? 'enabled' : 'disabled',
      planHash: on ? mockDigest(`${s.id}|managed-routing`) : null,
      approval: {
        required: s.environment === 'production',
        approvedBy: on && s.environment === 'production' ? owner.id : null,
        approvedAt: null,
        expiresAt: null,
      },
      createdBy: on ? owner.id : null,
      applyUntil: null,
      updatedAt: on ? iso(now - 30 * 864e5) : null,
    };
  }

  const inv = apps();
  const put = (a: Application) => {
    if (!inv.some((x) => x.id === a.id)) inv.push(a);
    return inv.find((x) => x.id === a.id)!;
  };

  // shop-api (UAT): history with a failed webhook candidate between two good versions.
  const shop = put(
    containerApp(
      '01934f2a-c001-7000-8000-000000000001',
      by('app-uat-01'),
      'shop-api',
      ['shop-api.uat.example.lab'],
      {
        secretKeys: ['DATABASE_URL', 'STRIPE_SECRET_KEY'],
        volumes: [{ name: 'uploads', mountPath: '/app/uploads' }],
      },
      24 * 9,
    ),
  );
  const ref = (sha: string, branch = 'main') => ({ repo: 'w3co/shop-api', commitSha: sha, branch });
  const s1 = seedDeployment(shop, 1, 'manual', 'succeeded', 60 * 24 * 5, admin, 'shop-api-1');
  const s2 = seedDeployment(
    shop,
    2,
    'webhook',
    'succeeded',
    60 * 24 * 2,
    null,
    'shop-api-2',
    ref(mockDigest('c2').slice(0, 40)),
  );
  const s3 = seedDeployment(
    shop,
    3,
    'webhook',
    'unhealthy',
    60 * 26,
    null,
    'dead-shop-3',
    ref(mockDigest('c3').slice(0, 40)),
  );
  const s4 = seedDeployment(shop, 4, 'manual', 'succeeded', 180, dev, 'shop-api-4');
  s2.previousDeploymentId = s1.id;
  s3.previousDeploymentId = s2.id;
  s4.previousDeploymentId = s2.id;
  s3.image = `registry.example.lab/w3/shop-api@sha256:dead${mockDigest('s3').slice(4)}`;
  point(shop, s4, s2);
  st.deployments.push(s1, s2, s3, s4);
  st.secrets[shop.id] = {
    DATABASE_URL: { version: 2, updatedAt: iso(now - 4 * 864e5) },
    STRIPE_SECRET_KEY: { version: 1, updatedAt: iso(now - 9 * 864e5) },
  };
  st.registryAuth[shop.id] = { serveraddress: 'registry.example.lab', username: 'ci-pull' };
  st.logs[shop.id] = [
    '2026-11-23T03:10:01Z info  server listening on :8080',
    '2026-11-23T03:10:01Z info  connected to postgres://shop:[REDACTED]@10.104.0.21:5432/shop',
    '2026-11-23T03:12:44Z info  GET /healthz 200 2ms',
    '2026-11-23T03:13:02Z info  POST /api/checkout 201 184ms',
    '2026-11-23T03:13:02Z warn  stripe: retrying request (key=[REDACTED])',
    '2026-11-23T03:15:30Z info  GET /api/products 200 23ms',
  ];

  // storefront (production): clean, two versions → rollback + approval flows.
  const store = put(
    containerApp(
      '01934f2a-c001-7000-8000-000000000002',
      by('app-prod-01'),
      'storefront',
      ['store.example.com', 'www.store.example.com'],
      {
        secretKeys: ['SESSION_SECRET'],
        tls: {
          certPath: '/etc/letsencrypt/live/store.example.com/fullchain.pem',
          keyPath: '/etc/letsencrypt/live/store.example.com/privkey.pem',
        },
      },
      24 * 30,
    ),
  );
  const f1 = seedDeployment(store, 1, 'manual', 'succeeded', 60 * 24 * 8, admin, 'store-1');
  const f2 = seedDeployment(store, 2, 'manual', 'succeeded', 60 * 24, admin, 'store-2');
  f2.previousDeploymentId = f1.id;
  point(store, f2, f1);
  st.deployments.push(f1, f2);
  st.secrets[store.id] = { SESSION_SECRET: { version: 3, updatedAt: iso(now - 20 * 864e5) } };
  st.logs[store.id] = [
    '2026-11-23T02:00:00Z info  next start -p 8080',
    '2026-11-23T02:00:01Z info  ready in 812ms',
  ];

  // billing-api (production): a deployment waiting for a second approver.
  const billing = put(
    containerApp(
      '01934f2a-c001-7000-8000-000000000003',
      by('app-prod-02'),
      'billing-api',
      ['billing.example.com'],
      {
        secretKeys: ['BILLING_TOKEN'],
      },
      24 * 40,
    ),
  );
  const b1 = seedDeployment(billing, 1, 'manual', 'succeeded', 60 * 24 * 6, owner, 'billing-1');
  const b2 = seedDeployment(billing, 2, 'manual', 'awaiting', 25, dev, 'billing-2');
  b2.previousDeploymentId = b1.id;
  b2.reason = 'Invoice PDF fix';
  point(billing, b1, null);
  st.deployments.push(b1, b2);
  st.secrets[billing.id] = { BILLING_TOKEN: { version: 1, updatedAt: iso(now - 40 * 864e5) } };
  st.logs[billing.id] = ['2026-11-23T01:00:00Z info  billing-api up'];

  // queue-worker on an offline server → preflight AGENT_OFFLINE.
  const worker = put(
    containerApp(
      '01934f2a-c001-7000-8000-000000000004',
      by('worker-uat-01'),
      'queue-worker',
      ['queue.uat.example.lab'],
      {},
      24 * 12,
    ),
  );
  const w1 = seedDeployment(worker, 1, 'manual', 'succeeded', 60 * 24 * 3, admin, 'worker-1');
  point(worker, w1, null);
  worker.container!.runtimeState = 'unknown';
  st.deployments.push(w1);

  // sandbox-api on dev-sandbox-02: managed port range exhausted → NO_PORT_AVAILABLE.
  const sandbox = put(
    containerApp(
      '01934f2a-c001-7000-8000-000000000005',
      by('dev-sandbox-02'),
      'sandbox-api',
      ['sandbox-api.dev.example.lab'],
      {},
      24 * 2,
    ),
  );
  const x1 = seedDeployment(sandbox, 1, 'manual', 'succeeded', 60 * 30, dev, 'sandbox-1');
  point(sandbox, x1, null);
  st.deployments.push(x1);

  // GitHub repo-webhook integration + delivery history.
  const integ: Integration = {
    id: '01934f2a-1a00-7000-8000-000000000001',
    kind: 'github',
    name: 'w3co GitHub',
    webhookUrl: '/api/v1/webhooks/github/01934f2a-1a00-7000-8000-000000000001',
    webhookSecret: { set: true },
    enabled: true,
    createdBy: owner.id,
    createdAt: iso(now - 20 * 864e5),
  };
  st.integrations.push(integ);
  const dl = (
    i: number,
    ageMin: number,
    o: Partial<WebhookDelivery> & Pick<WebhookDelivery, 'result'>,
  ): WebhookDelivery => ({
    id: `01934f2a-de1${i}-7000-8000-000000000000`,
    integrationId: integ.id,
    deliveryId: `72d3162e-cc78-11e3-81ab-4c9367dc095${i}`,
    event: 'push',
    repo: 'w3co/shop-api',
    ref: 'refs/heads/main',
    after: mockDigest(`c${i}`).slice(0, 40),
    signatureOk: true,
    reasons: [],
    deploymentIds: [],
    buildIds: [],
    receivedAt: iso(now - ageMin * 60e3),
    ...o,
  });
  st.deliveries[integ.id] = [
    dl(8, 60 * 2, {
      result: 'awaiting_approval',
      repo: 'w3co/billing-api',
      after: mockDigest('b8').slice(0, 40),
      deploymentIds: [],
    }),
    dl(7, 60 * 26 - 3, {
      result: 'ignored',
      reasons: ['already_deployed'],
      after: s3.sourceRef!.commitSha!,
    }),
    dl(6, 60 * 26, { result: 'deployed', deploymentIds: [s3.id], after: s3.sourceRef!.commitSha! }),
    dl(5, 60 * 30, {
      result: 'ignored',
      reasons: ['not_push'],
      event: 'ping',
      ref: null,
      after: null,
    }),
    dl(4, 60 * 40, {
      result: 'failed',
      reasons: ['WEBHOOK_SIGNATURE_INVALID'],
      signatureOk: false,
      repo: null,
      ref: null,
      after: null,
    }),
    dl(3, 60 * 24 * 2 - 1, {
      result: 'ignored',
      reasons: ['duplicate_delivery'],
      deliveryId: '72d3162e-cc78-11e3-81ab-4c9367dc0951',
      after: s2.sourceRef!.commitSha!,
    }),
    dl(2, 60 * 24 * 2 + 30, {
      result: 'ignored',
      reasons: ['no_matching_policy'],
      ref: 'refs/heads/feature/cart-v3',
    }),
    dl(1, 60 * 24 * 2, {
      result: 'deployed',
      deploymentIds: [s2.id],
      after: s2.sourceRef!.commitSha!,
    }),
  ].sort((a, b) => b.receivedAt.localeCompare(a.receivedAt));
  st.policies.push({
    id: '01934f2a-ad00-7000-8000-000000000001',
    applicationId: shop.id,
    integrationId: integ.id,
    repo: 'w3co/shop-api',
    mode: 'image',
    branches: ['main', 'release/*'],
    imageTemplate: 'registry.example.lab/w3/shop-api:sha-{sha7}',
    enabled: true,
    createdBy: owner.id,
    createdAt: iso(now - 15 * 864e5),
    updatedAt: iso(now - 15 * 864e5),
  });
  composeHooks.seed(st);
  p3Internals.save();
  return st;
}

function s(): P4State {
  if (!st) {
    const raw = storage()?.getItem(P4_KEY);
    if (raw) {
      try {
        st = JSON.parse(raw) as P4State;
      } catch {
        st = null;
      }
    }
    if (!st) {
      seed();
      save();
    }
  }
  // Container apps live in the P3 inventory; re-seed if that store was reset on its own.
  if (!apps().some((a) => a.kind === 'container')) {
    st = null;
    seed();
    save();
  }
  return st!;
}

// ---------------------------------------------------------------- P4b hooks (compose apps, builds)

type MockApp = Application & { container: ContainerSpec };

/** Filled by ./p4b-routes (compose + builds live there; orchestration stays here). */
export const composeHooks: {
  create: (u: U, srv: Server, body: Record<string, unknown>, rid: string) => Response;
  plan: (
    app: MockApp,
    trigger: Deployment['trigger'],
  ) => { compose: NonNullable<Deployment['compose']>; routeImage: string; routeChanged: boolean };
  onLive: (app: Application, d: Deployment) => void;
  setState: (app: Application, state: 'running' | 'stopped') => void;
  seed: (st: { deployments: Deployment[]; secrets: P4State['secrets'] }) => void;
  tick: () => void;
} = {
  create: () => {
    throw new Error('compose hooks not registered');
  },
  plan: () => {
    throw new Error('compose hooks not registered');
  },
  onLive: () => {},
  setState: () => {},
  seed: () => {},
  tick: () => {},
};

/** Per-service progress during compose_apply: unchanged → kept; others created/replaced in order. */
function progressCompose(d: MockDeployment, p: number, failing: boolean) {
  const svcs = d.compose?.services ?? [];
  const changing = svcs.filter((x) => x.plannedAction !== 'unchanged');
  for (const x of svcs) {
    if (x.plannedAction === 'unchanged') {
      x.action = 'unchanged';
      x.health = 'kept running';
      continue;
    }
    const i = changing.indexOf(x);
    const due = (i + 1) / changing.length;
    if (p >= due || p >= 1) {
      const isRoute = x.service === d.compose?.routeService;
      x.action = x.previousName ? 'replaced' : 'created';
      x.health =
        failing && p >= 1 && isRoute ? 'unhealthy' : isRoute ? 'healthy (http 200)' : 'healthy';
    } else if (p >= i / changing.length) {
      x.health = 'starting';
    }
  }
}

/** Internals shared with ./p4b-routes. */
export const p4Internals = {
  state: () => s(),
  save: () => save(),
  tick: () => tick(),
  containerAppOf: (id: string) => containerAppOf(id),
  createDeployment: (
    u: U,
    app: MockApp,
    image: string,
    trigger: Deployment['trigger'],
    rid: string,
    extra: { sourceRef?: Deployment['sourceRef']; reason?: string; buildId?: string } = {},
  ) => createDeployment(u, app, image, trigger, rid, extra),
  publicDep: (d: Deployment, u?: U) => publicDep(d as MockDeployment, u),
  seedDeployment: (
    app: Application,
    n: number,
    trigger: Deployment['trigger'],
    ageMin: number,
    createdBy: U | null,
    imageSeed: string,
  ) => seedDeployment(app, n, trigger, 'succeeded', ageMin, createdBy, imageSeed),
  point: (app: Application, cur: Deployment, prev: Deployment | null) => point(app, cur, prev),
  containerApp: (
    id: string,
    srv: Server,
    name: string,
    domains: string[],
    spec: Partial<ContainerSpec>,
    ageH: number,
  ) => containerApp(id, srv, name, domains, spec, ageH),
  digest: (seed: string) => digest(seed),
};

// ---------------------------------------------------------------- orchestration

function timeline(d: MockDeployment, now: number) {
  const t0 = d.plan.t0!;
  const el = (d.plan.cancelledAt ?? now) - t0;
  const fail: Partial<Record<StepName, { code: string; message: string; log: string[] }>> = {
    pull_start:
      d.plan.outcome === 'pull_fail'
        ? {
            code: 'IMAGE_PULL_FAILED',
            message: 'manifest unknown: digest not found in registry',
            log: ['pull: manifest unknown'],
          }
        : undefined,
    health_check:
      d.plan.outcome === 'unhealthy'
        ? {
            code: 'CANDIDATE_UNHEALTHY',
            message: 'GET /healthz → 503 (5/5 attempts)',
            log: [
              'health: GET /healthz → 503',
              'health: GET /healthz → 503',
              'health: GET /healthz → 503',
              'candidate removed',
            ],
          }
        : undefined,
    route_switch:
      d.plan.outcome === 'route_fail'
        ? {
            code: 'POSTCHECK_FAILED_REVERTED',
            message: 'Postcheck Host: domain → 502; route reverted, previous still serving',
            log: ['nginx -t ok', 'reload ok', 'postcheck → 502', 'reverted to previous route'],
          }
        : d.plan.outcome === 'manual'
          ? {
              code: 'REVERT_FAILED_MANUAL_RECOVERY',
              message: 'Route switch failed and restoring the previous route also failed',
              log: [
                'postcheck → 502',
                'restore route.conf: permission denied',
                'nginx -t failed after restore',
              ],
            }
          : undefined,
  };
  const compose = d.plan.kind === 'compose';
  if (compose) {
    fail.compose_apply =
      d.plan.outcome === 'unhealthy'
        ? {
            code: 'COMPOSE_SERVICE_UNHEALTHY',
            message: 'Service "app" failed its health check; previous containers kept serving',
            log: ['app: GET / → 503', 'app: GET / → 503', 'candidate removed, previous kept'],
          }
        : undefined;
    fail.health_check = undefined;
    fail.pull_start = undefined;
  }
  const names = stepNames(d.trigger === 'rollback', compose);
  const bounds: Array<[StepName, number, number]> = [
    [names[0]!, 0, T.preflight],
    [names[1]!, T.preflight, T.pull],
    [names[2]!, T.pull, T.health],
    [names[3]!, T.health, T.route],
    [names[4]!, T.route, T.stop],
  ];
  let failedAt: StepName | null = null;
  for (const [name, start, end] of bounds) {
    const step = d.steps.find((x) => x.name === name)!;
    if (failedAt || (d.plan.cancelledAt !== undefined && el < start)) {
      step.status = 'skipped';
      step.message = failedAt ? 'Skipped' : 'Skipped — cancelled';
      continue;
    }
    if (el < start) {
      step.status = 'pending';
      continue;
    }
    if (compose && !d.plan.routeChanged && (name === 'route_switch' || name === 'stop_previous')) {
      step.status = 'skipped';
      step.message =
        name === 'route_switch'
          ? 'Route service unchanged — no route switch needed'
          : 'Route container unchanged — nothing to stop';
      continue;
    }
    step.startedAt = iso(t0 + start);
    if (name !== 'preflight' && !step.jobId) step.jobId = ctx.rid();
    const f = fail[name];
    const progress = Math.min(1, (el - start) / (end - start));
    step.logTail = logLines(d, name, progress, f?.log);
    if (compose && name === 'compose_apply') progressCompose(d, progress, !!f);
    if (el < end) {
      if (d.plan.cancelledAt !== undefined) {
        step.status = 'failed';
        step.message = 'Cancelled by operator';
        step.finishedAt = iso(t0 + el);
        failedAt = name;
        continue;
      }
      step.status = 'running';
      step.message = null;
      continue;
    }
    step.finishedAt = iso(t0 + end);
    if (f) {
      step.status = 'failed';
      step.message = f.message;
      failedAt = name;
      step.errorCode = f.code;
      d.error =
        f.code === 'CANDIDATE_UNHEALTHY'
          ? {
              code: f.code,
              message:
                'Candidate failed its health check; it was removed and the live version was not touched.',
              details: {
                logTail: f.log,
                attempts: 5,
                elapsedMs: T.health - T.pull,
                reason: 'unexpected status',
                removed: true,
                lastStatus: 503,
              },
            }
          : { code: f.code, message: f.message };
    } else {
      step.status = 'succeeded';
      step.message = stepMessage(name, d.image, d.container?.hostPort ?? null);
    }
  }
  if (d.plan.cancelledAt !== undefined) return { phase: 'cancelled' as const, failedAt };
  if (failedAt) return { phase: 'failed' as const, failedAt };
  if (el >= T.stop) return { phase: 'done' as const, failedAt };
  if (el < T.preflight) return { phase: 'preflight' as const, failedAt };
  if (el < (T.preflight + T.pull) / 2) return { phase: 'pulling' as const, failedAt };
  if (el < T.pull) return { phase: 'starting' as const, failedAt };
  if (el < T.health) return { phase: 'health_check' as const, failedAt };
  return { phase: 'routing' as const, failedAt };
}

function logLines(d: MockDeployment, name: StepName, p: number, failLog?: string[]): string[] {
  const c = d.container?.name ?? 'candidate';
  const all: Partial<Record<StepName, string[]>> = {
    preflight: [
      'agent_online ok',
      'managed_routing ok',
      'image_pinned ok',
      'secrets_present ok',
      'domain_conflict ok',
      'port_alloc ok',
    ],
    pull_start: [
      `docker pull ${d.image.split('@')[0]}@${d.image.split('@')[1]?.slice(0, 19)}…`,
      'Digest verified',
      `docker create ${c} --read-only=false --cap-drop=ALL -p 127.0.0.1:${d.container?.hostPort}:8080`,
      `docker start ${c}`,
    ],
    health_check: [
      'health: GET /healthz → 200',
      'health: GET /healthz → 200',
      'healthy after 2 checks',
    ],
    route_switch: [
      'write /etc/nginx/ppanel-managed/route.conf',
      'nginx -t: syntax ok',
      'systemctl reload nginx',
      'postcheck Host → 200',
    ],
    stop_previous: ['docker stop previous container (kept for rollback)'],
    resolve_images: (d.compose?.services ?? []).map((x) =>
      x.sourceImage === x.image
        ? `${x.service}: pinned ${x.image.split('@')[1]?.slice(0, 19)}…`
        : `${x.service}: ${x.sourceImage} → ${x.image.split('@')[1]?.slice(0, 19)}…`,
    ),
    compose_apply: (d.compose?.services ?? []).map((x) =>
      x.plannedAction === 'unchanged'
        ? `${x.service}: unchanged (spec ${x.specHash.slice(0, 8)}) — kept running`
        : `${x.service}: ${x.previousName ? 'replace' : 'create'} ${x.name} · health ${x.health ?? 'running'}`,
    ),
    start_target: [
      `docker start ${c}`,
      'container started (existing, kept from the previous deployment)',
    ],
  };
  const src = failLog && p >= 1 ? failLog : (all[name] ?? []);
  return src.slice(0, Math.max(1, Math.ceil(src.length * p)));
}

function settle(d: MockDeployment, now: number) {
  if (d.plan.settled || d.plan.t0 === null) return false;
  const r = timeline(d, now);
  const app = apps().find((a) => a.id === d.applicationId);
  switch (r.phase) {
    case 'preflight':
    case 'pulling':
    case 'starting':
    case 'health_check':
    case 'routing':
      d.status = r.phase;
      return true;
    case 'cancelled':
      d.status = 'cancelled';
      break;
    case 'failed':
      d.status = d.plan.outcome === 'manual' ? 'requires_manual_recovery' : 'failed';
      if (d.plan.outcome === 'manual')
        d.error = {
          code: 'REVERT_FAILED_MANUAL_RECOVERY',
          message:
            'Route switch failed and the previous route could not be restored automatically.',
        };
      break;
    case 'done':
      d.status = 'succeeded';
      if (d.plan.kind === 'compose' && d.compose) progressCompose(d, 1, false);
      if (app?.container) {
        // The replaced container is stopped and kept, so it becomes the rollback target.
        app.container.previousDeploymentId = app.container.currentDeploymentId;
        app.container.rollbackAvailable = !!app.container.previousDeploymentId;
        app.container.currentDeploymentId = d.id;
        app.container.containerName = d.container?.name ?? null;
        app.container.hostPort = d.container?.hostPort ?? null;
        app.container.image = d.image;
        app.container.runtimeState = 'running';
        app.updatedAt = iso(now);
        app.version += 1;
        if (app.compose && d.compose) composeHooks.onLive(app, d);
      }
      s().logs[d.applicationId] = [
        ...(s().logs[d.applicationId] ?? []),
        `${iso(now)} info  deployment #${d.number} live on 127.0.0.1:${d.container?.hostPort}`,
      ];
      break;
  }
  d.finishedAt = iso(Math.min(now, (d.plan.t0 ?? now) + T.stop));
  d.updatedAt = d.finishedAt;
  d.version = (d.version ?? 1) + 1;
  d.plan.settled = true;
  p3Internals.save();
  return true;
}

function tick() {
  p3Internals.tick();
  const now = Date.now();
  let dirty = false;
  for (const d of s().deployments) if (settle(d, now)) dirty = true;
  composeHooks.tick();
  for (const r of Object.values(s().routing)) {
    if (r.status === 'applying' && r.applyUntil && now >= r.applyUntil) {
      r.status = 'enabled';
      r.enabled = true;
      r.applyUntil = null;
      r.updatedAt = iso(now);
      dirty = true;
    }
  }
  if (dirty) save();
}

// ---------------------------------------------------------------- helpers

const can = (u: U, perm: Permission, srv?: Server) => ctx.hasPermFor(u as never, perm, srv);
const need = (u: U, perm: Permission, srv?: Server) => ctx.requirePerm(u as never, perm, srv);

function containerAppOf(id: string) {
  const a = p3Internals.appOf(id);
  if ((a.kind !== 'container' && a.kind !== 'compose') || !a.container)
    throw new ctx.HttpError(
      409,
      'NOT_CONTAINER_APP',
      'This application is not a managed container application.',
    );
  return a as Application & { container: ContainerSpec };
}

function stepUpOrThrow(req: Request, u: U, srv: Server, action: string, rid: string) {
  if (!ctx.checkStepUp(req, u)) {
    ctx.audit(u, action, srv, 'denied', rid);
    throw new ctx.HttpError(
      403,
      'STEP_UP_REQUIRED',
      'This action requires a fresh 2FA confirmation (X-Step-Up).',
    );
  }
}

const ACTIVE = [
  'awaiting_approval',
  'queued',
  'preflight',
  'pulling',
  'starting',
  'health_check',
  'routing',
  'rollback_pending',
];

function domainOwners(domain: string, exceptAppId: string | null) {
  return apps().filter((a) => a.id !== exceptAppId && a.domains.includes(domain));
}

function preflight(
  app: Application & { container: ContainerSpec },
  image: string,
): PreflightCheck[] {
  const srv = p3Internals.serverOf(app.serverId);
  const checks: PreflightCheck[] = [];
  const add = (
    check: PreflightCheckName,
    ok: boolean,
    okMsg: string,
    code?: string,
    failMsg?: string,
  ) =>
    checks.push(
      ok ? { check, ok, message: okMsg } : { check, ok, code, message: failMsg ?? okMsg },
    );
  add(
    'agent_online',
    srv.status === 'online',
    `Agent on ${srv.name} is online`,
    'AGENT_OFFLINE',
    `Agent on ${srv.name} is ${srv.status}. Deploy when it reconnects; no job was sent.`,
  );
  add(
    'managed_routing',
    !!s().routing[srv.id]?.enabled,
    'Managed routing enabled',
    'MANAGED_ROUTING_DISABLED',
    `Managed routing is not enabled on ${srv.name}. Enable it from the Target step.`,
  );
  add(
    'image_pinned',
    IMAGE_DIGEST_REF_RE.test(image) || (!image && (!!app.compose || !!app.build)),
    !image && app.compose
      ? 'Compose images are resolved to digests at deploy time'
      : !image && app.build
        ? 'The image digest comes from the build'
        : 'Image pinned by digest',
    'IMAGE_NOT_PINNED',
    'Image must be pinned as repo@sha256:<digest>; tags are refused.',
  );
  const declared = app.compose ? app.compose.secretKeys : (app.container.secretKeys ?? []);
  const missing = declared.filter((k) => !s().secrets[app.id]?.[k]);
  add(
    'secrets_present',
    missing.length === 0,
    'All declared secrets are set',
    'SECRETS_MISSING',
    `Missing secret(s): ${missing.join(', ')}. Set them in Env & Secrets.`,
  );
  const conflicts = app.domains.flatMap((d) =>
    domainOwners(d, app.id).map((o) => `${d} (${o.name})`),
  );
  add(
    'domain_conflict',
    conflicts.length === 0,
    'No domain conflicts',
    'DOMAIN_CONFLICT',
    `Domain already in use: ${conflicts.join(', ')}.`,
  );
  const noPort = s().noPortServers.includes(srv.id);
  add(
    'port_alloc',
    !noPort,
    'Free host port in 20000–29999',
    'NO_PORT_AVAILABLE',
    `No free managed port (20000–29999) on ${srv.name}. Remove unused managed containers.`,
  );
  const disk = srv.metrics?.diskPct ?? null;
  const stale = !srv.metrics || srv.metrics.stale;
  const prod = srv.environment === 'production';
  if (stale)
    checks.push(
      prod
        ? {
            check: 'disk',
            ok: false,
            code: 'DISK_UNKNOWN',
            message: 'Disk metrics are stale; production deploys need a fresh heartbeat.',
          }
        : {
            check: 'disk',
            ok: true,
            warning: true,
            code: 'DISK_UNKNOWN',
            message: 'Disk metrics are stale (warning only outside production).',
          },
    );
  else if (disk !== null && disk >= 90)
    checks.push(
      prod
        ? {
            check: 'disk',
            ok: false,
            code: 'DISK_LOW',
            message: `Disk ${disk}% used on ${srv.name}.`,
          }
        : {
            check: 'disk',
            ok: true,
            warning: true,
            code: 'DISK_LOW',
            message: `Disk ${disk}% used (warning only outside production).`,
          },
    );
  else add('disk', true, `Disk ${disk ?? '?'}% used`);
  const busy = s().deployments.find((d) => d.applicationId === app.id && ACTIVE.includes(d.status));
  add(
    'lock',
    !busy,
    'No other deployment in progress',
    'DEPLOYMENT_IN_PROGRESS',
    `Deployment #${busy?.number} is still ${busy?.status}.`,
  );
  return checks;
}

function publicDep(d: MockDeployment, u?: U): Deployment {
  const { plan: _p, ...rest } = d;
  void _p;
  const srv0 = ctx.servers().find((x) => x.id === d.serverId);
  const allowedActions: Deployment['allowedActions'] = [];
  if (u && srv0) {
    if (
      d.status === 'awaiting_approval' &&
      d.createdBy !== u.id &&
      can(u, 'approvals.decide', srv0)
    )
      allowedActions.push('approve');
    if (
      ['awaiting_approval', 'queued', 'preflight', 'pulling', 'starting'].includes(d.status) &&
      can(u, 'apps.deploy', srv0)
    )
      allowedActions.push('cancel');
  }
  const app = apps().find((a) => a.id === d.applicationId);
  const srv = ctx.servers().find((x) => x.id === d.serverId);
  const creator = ctx.users().find((x) => x.id === d.createdBy);
  return {
    ...rest,
    allowedActions,
    applicationName: app?.name,
    serverName: srv?.name,
    environment: srv?.environment,
    domains: app?.domains,
    createdByLabel: creator?.displayName ?? rest.createdByLabel ?? null,
  };
}

function depOf(id: string) {
  const d = s().deployments.find((x) => x.id === id);
  if (!d) throw new ctx.HttpError(404, 'NOT_FOUND', 'Deployment not found');
  return d;
}

function createDeployment(
  u: U,
  app: Application & { container: ContainerSpec },
  image: string,
  trigger: Deployment['trigger'],
  requestId: string,
  extra: { sourceRef?: Deployment['sourceRef']; reason?: string; buildId?: string } = {},
): MockDeployment {
  const srv = p3Internals.serverOf(app.serverId);
  const checks = preflight(app, image);
  const lockFail = checks.find((c) => c.check === 'lock' && !c.ok);
  if (lockFail) throw new ctx.HttpError(409, 'DEPLOYMENT_IN_PROGRESS', lockFail.message);
  const composePlan = app.compose ? composeHooks.plan(app, trigger) : null;
  if (composePlan) image = composePlan.routeImage;
  if (!IMAGE_DIGEST_REF_RE.test(image))
    throw new ctx.HttpError(
      422,
      'IMAGE_NOT_PINNED',
      'Image must be pinned by digest (repo@sha256:…).',
      [{ field: 'image', message: 'Tags are refused; pin a digest.' }],
    );
  const now = Date.now();
  const n =
    Math.max(
      0,
      ...s()
        .deployments.filter((d) => d.applicationId === app.id)
        .map((d) => d.number),
    ) + 1;
  const id = ctx.rid();
  const used = s().deployments.map((d) => d.container?.hostPort ?? 0);
  let hostPort = 20000 + ((n * 37) % 900);
  while (used.includes(hostPort)) hostPort += 1;
  const failing = checks.filter((c) => !c.ok);
  const prod = srv.environment === 'production';
  const prev =
    trigger === 'rollback' ? app.container.previousDeploymentId : app.container.currentDeploymentId;
  const prevDep = s().deployments.find((d) => d.id === app.container.previousDeploymentId);
  const d: MockDeployment = {
    id,
    applicationId: app.id,
    serverId: srv.id,
    number: n,
    trigger,
    image,
    sourceRef: extra.sourceRef ?? null,
    status: 'queued',
    steps: stepNames(trigger === 'rollback', !!composePlan).map((name) => ({
      name,
      status: 'pending',
      jobId: null,
      startedAt: null,
      finishedAt: null,
      message: null,
      logTail: [],
    })),
    preflight: checks,
    container:
      trigger === 'rollback' && prevDep?.container
        ? { name: prevDep.container.name, hostPort: prevDep.container.hostPort }
        : { name: `ppanel-${app.name}-${hex8(id)}`, hostPort },
    previousDeploymentId: prev,
    rollbackOfDeploymentId: trigger === 'rollback' ? app.container.previousDeploymentId : null,
    allowedActions: [],
    version: 1,
    updatedAt: iso(now),
    planHash: mockDigest(
      `${app.id}|${srv.id}|${image}|${JSON.stringify(app.container)}|${app.domains.join(',')}`,
    ),
    approval: { required: prod, approvedBy: null, approvedAt: null, expiresAt: null },
    reason: extra.reason ?? null,
    createdBy: u.id,
    createdAt: iso(now),
    finishedAt: null,
    error: null,
    plan: {
      t0: null,
      outcome: outcomeOf(image),
      settled: false,
      kind: composePlan ? 'compose' : 'container',
      routeChanged: composePlan?.routeChanged,
    },
    compose: composePlan?.compose ?? null,
    buildId: extra.buildId ?? null,
  };
  if (trigger === 'rollback') d.plan.outcome = 'ok';
  if (composePlan && !composePlan.routeChanged && prevDep?.container && trigger !== 'rollback')
    d.container = app.container.containerName
      ? { name: app.container.containerName, hostPort: app.container.hostPort ?? hostPort }
      : d.container;
  const pf = d.steps[0]!;
  pf.startedAt = iso(now);
  pf.finishedAt = iso(now + 200);
  pf.logTail = checks.map((c) => `${c.check} ${c.ok ? 'ok' : `FAILED ${c.code}`}`);
  if (failing.length) {
    pf.status = 'failed';
    pf.message = failing.map((c) => c.code).join(', ');
    d.steps.slice(1).forEach((x) => {
      x.status = 'skipped';
      x.message = 'Skipped — preflight failed';
    });
    d.status = 'failed';
    d.error = { code: failing[0]!.code ?? 'PREFLIGHT_FAILED', message: failing[0]!.message };
    d.finishedAt = iso(now + 200);
    d.plan.settled = true;
  } else if (prod) {
    pf.status = 'succeeded';
    pf.message = 'All checks passed · waiting for approval';
    d.status = 'awaiting_approval';
  } else {
    d.plan.t0 = now;
  }
  s().deployments.push(d);
  save();
  ctx.audit(
    u,
    `deployment.${trigger === 'manual' ? 'create' : trigger}`,
    srv,
    'success',
    requestId,
  );
  return d;
}

// ---------------------------------------------------------------- routes

export function registerP4Routes(c: P3Ctx) {
  ctx = c;
  p3LoadHooks.push(() => void s());
  const { on, ok, HttpError } = c;

  on('POST', '/applications', ({ req, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const srv = p3Internals.serverOf(String(body.serverId ?? ''));
    need(u, 'apps.deploy', srv);
    if (body.kind === 'compose') return composeHooks.create(u, srv, body, requestId);
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
    const port = Number(body.containerPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      errs.push({ field: 'containerPort', message: '1–65535' });
    const env = (body.env ?? {}) as Record<string, string>;
    for (const k of Object.keys(env))
      if (!ENV_KEY_RE.test(k)) errs.push({ field: `env.${k}`, message: 'Invalid key' });
    const volumes = (Array.isArray(body.volumes) ? body.volumes : []) as Array<{
      name: string;
      mountPath: string;
    }>;
    for (const v of volumes)
      if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(v.name) || !v.mountPath?.startsWith('/'))
        errs.push({ field: 'volumes', message: `Named volumes only: ${v.name}` });
    if (errs.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
    const conflicts = domains.flatMap((d) => domainOwners(d, null).map((o) => `${d} (${o.name})`));
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
    const hc = (body.healthcheck ?? {}) as Partial<ContainerSpec['healthcheck']>;
    const rs = (body.resources ?? {}) as Partial<ContainerSpec['resources']>;
    const a = containerApp(
      c.rid(),
      srv,
      name,
      domains,
      {
        containerPort: port,
        healthcheck: {
          path: hc.path ?? '/',
          expectStatus: hc.expectStatus ?? [200],
          intervalSec: hc.intervalSec ?? 2,
          timeoutSec: hc.timeoutSec ?? 3,
          startPeriodSec: hc.startPeriodSec ?? 60,
        },
        resources: { memoryMb: rs.memoryMb ?? 512, cpus: rs.cpus ?? 1, pids: rs.pids ?? 512 },
        env,
        volumes,
        secretKeys: Array.isArray(body.secretKeys) ? (body.secretKeys as string[]) : [],
        tls: (body.tls as ContainerSpec['tls']) ?? null,
        runtimeState: 'unknown',
      },
      0,
    );
    a.createdAt = iso(Date.now());
    a.updatedAt = a.createdAt;
    apps().push(a);
    p3Internals.save();
    s().logs[a.id] = [];
    save();
    c.audit(u, 'application.create', srv, 'success', requestId);
    return ok(requestId, p3Internals.decorate(u, a), 201);
  });

  // ---- secrets
  on('GET', '/applications/:id/secrets', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const items = Object.entries(s().secrets[a.id] ?? {}).map(([key, m]) => ({
      key,
      set: true,
      version: m.version,
      updatedAt: m.updatedAt,
    }));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('PUT', '/applications/:id/secrets/:key', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    const key = params[1]!;
    if (!ENV_KEY_RE.test(key))
      throw new HttpError(422, 'VALIDATION_FAILED', 'Invalid secret key', [
        { field: 'key', message: 'A-Z, 0-9, _' },
      ]);
    if (typeof body.value !== 'string' || !body.value.length)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Value required', [
        { field: 'value', message: 'Required' },
      ]);
    if (srv.environment === 'production') stepUpOrThrow(req, u, srv, 'secret.put', requestId);
    // The value itself is dropped here: the mock never stores secret values.
    const cur = s().secrets[a.id]?.[key];
    s().secrets[a.id] = {
      ...(s().secrets[a.id] ?? {}),
      [key]: { version: (cur?.version ?? 0) + 1, updatedAt: iso(Date.now()) },
    };
    // planHash includes secret versions: a pending approval no longer matches.
    for (const d of s().deployments)
      if (d.applicationId === a.id && d.status === 'awaiting_approval')
        d.planHash = mockDigest(`${d.planHash}|${key}|${s().secrets[a.id]![key]!.version}`);
    if (!(a.container.secretKeys ?? []).includes(key)) {
      a.container.secretKeys = [...(a.container.secretKeys ?? []), key];
      p3Internals.save();
    }
    save();
    c.audit(u, 'secret.put', srv, 'success', requestId);
    return ok(requestId, { key, set: true, version: s().secrets[a.id]![key]!.version });
  });

  on('DELETE', '/applications/:id/secrets/:key', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    if (srv.environment === 'production') stepUpOrThrow(req, u, srv, 'secret.delete', requestId);
    const m = { ...(s().secrets[a.id] ?? {}) };
    delete m[params[1]!];
    s().secrets[a.id] = m;
    a.container.secretKeys = (a.container.secretKeys ?? []).filter((k) => k !== params[1]);
    p3Internals.save();
    save();
    c.audit(u, 'secret.delete', srv, 'success', requestId);
    return new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });
  });

  on('GET', '/applications/:id/registry-auth', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const r = s().registryAuth[a.id];
    return ok(requestId, r ? { ...r, set: true } : null);
  });

  on('PUT', '/applications/:id/registry-auth', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    if (!body.serveraddress || !body.username || !body.password)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'password', message: 'All fields required' },
      ]);
    if (srv.environment === 'production')
      stepUpOrThrow(req, u, srv, 'registry_auth.put', requestId);
    s().registryAuth[a.id] = {
      serveraddress: String(body.serveraddress),
      username: String(body.username),
    };
    save();
    c.audit(u, 'registry_auth.put', srv, 'success', requestId);
    return ok(requestId, { ...s().registryAuth[a.id], set: true });
  });

  // ---- deployments
  on('GET', '/applications/:id/deployments', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const items = s()
      .deployments.filter((d) => d.applicationId === a.id)
      .sort((x, y) => y.number - x.number)
      .map((d) => publicDep(d, u));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('POST', '/applications/:id/deployments/preflight', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    const image = String(body.image ?? '');
    return ok(requestId, {
      checks: preflight(a, image),
      approvalRequired: srv.environment === 'production',
    });
  });

  on('POST', '/applications/:id/deployments', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.deploy', p3Internals.serverOf(a.serverId));
    const key = req.headers.get('Idempotency-Key');
    const dup = key
      ? s().deployments.find((d) => (d as MockDeployment & { idem?: string }).idem === key)
      : null;
    if (dup) return ok(requestId, { deployment: publicDep(dup, u) }, 200);
    if (!a.compose && !body.image && body.composeVersion === undefined)
      throw new HttpError(
        422,
        'IMAGE_NOT_PINNED',
        'Container apps need an image pinned by digest.',
        [{ field: 'image', message: 'Required' }],
      );
    const d = createDeployment(u, a, String(body.image ?? ''), 'manual', requestId, {
      sourceRef: (body.sourceRef as Deployment['sourceRef']) ?? null,
      reason: typeof body.reason === 'string' ? body.reason : undefined,
    });
    (d as MockDeployment & { idem?: string }).idem = key ?? undefined;
    save();
    return ok(requestId, { deployment: publicDep(d, u) }, 202);
  });

  on('POST', '/applications/:id/redeploy', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.deploy', p3Internals.serverOf(a.serverId));
    const cur = s().deployments.find((d) => d.id === a.container.currentDeploymentId);
    if (!cur) throw new HttpError(409, 'NO_CURRENT_DEPLOYMENT', 'Nothing is deployed yet.');
    const d = createDeployment(u, a, cur.image, 'redeploy', requestId, {
      reason: body.reason as string | undefined,
    });
    return ok(requestId, { deployment: publicDep(d, u) }, 202);
  });

  on('POST', '/applications/:id/rollback', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.deploy', p3Internals.serverOf(a.serverId));
    const prev = s().deployments.find((d) => d.id === a.container.previousDeploymentId);
    if (!prev)
      throw new HttpError(
        409,
        'ROLLBACK_UNAVAILABLE',
        'The previous container no longer exists. Redeploy its image instead.',
      );
    const d = createDeployment(u, a, prev.image, 'rollback', requestId, {
      reason: body.reason as string | undefined,
    });
    return ok(requestId, { deployment: publicDep(d, u) }, 202);
  });

  const lifecycle = (path: string, action: 'restart' | 'start' | 'stop') =>
    on('POST', path, ({ req, params, requestId }) => {
      tick();
      const u = c.currentUser(req);
      const a = containerAppOf(params[0]!);
      const srv = p3Internals.serverOf(a.serverId);
      need(u, 'apps.deploy', srv);
      if (a.compose && action === 'restart')
        throw new HttpError(
          409,
          'OPERATION_NOT_SUPPORTED',
          'Compose apps support stop, start, redeploy and rollback.',
        );
      if (!a.container.currentDeploymentId)
        throw new HttpError(409, 'NO_CURRENT_DEPLOYMENT', 'Nothing is deployed yet.');
      if (srv.status !== 'online' && srv.status !== 'degraded')
        throw new HttpError(409, 'AGENT_OFFLINE', `Agent on ${srv.name} is ${srv.status}.`);
      if (action === 'start' && a.container.runtimeState === 'running')
        throw new HttpError(409, 'ALREADY_RUNNING', 'The container is already running.');
      if (action !== 'start' && a.container.runtimeState === 'stopped')
        throw new HttpError(409, 'CONTAINER_STOPPED', 'The container is stopped.');
      const job = p3Internals.newJob(
        srv.id,
        a.compose ? `compose.${action}` : `container.${action}`,
        1200,
      );
      a.container.runtimeState = action === 'stop' ? 'stopped' : 'running';
      if (a.compose) composeHooks.setState(a, action === 'stop' ? 'stopped' : 'running');
      a.updatedAt = iso(Date.now());
      p3Internals.save();
      s().logs[a.id] = [
        ...(s().logs[a.id] ?? []),
        `${iso(Date.now())} info  container ${action} requested by ${u.displayName}`,
      ];
      save();
      c.audit(u, `application.${action}`, srv, 'success', requestId);
      return ok(
        requestId,
        { jobId: job.id, operation: action, container: a.container.containerName },
        202,
      );
    });
  lifecycle('/applications/:id/restart', 'restart');
  lifecycle('/applications/:id/start', 'start');
  lifecycle('/applications/:id/stop', 'stop');

  on('GET', '/applications/:id/logs', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const tail = Math.min(1000, Math.max(1, Number(url.searchParams.get('tail') ?? 200) || 200));
    const cur = s().deployments.find((d) => d.id === a.container.currentDeploymentId);
    const all = s().logs[a.id] ?? [];
    return ok(requestId, {
      jobId: c.rid(),
      status: 'succeeded',
      lines: all.slice(-tail),
      truncated: all.length > tail,
      container: cur?.container?.name ?? null,
    });
  });

  // ---- auto-deploy policies
  on('GET', '/applications/:id/auto-deploy', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(a.serverId));
    const { slice, paginate } = c.paginate(
      s().policies.filter((p) => p.applicationId === a.id),
      url,
    );
    return ok(requestId, slice, 200, paginate);
  });

  const validatePolicy = (b: Record<string, unknown>, partial: boolean) => {
    const errs: Array<{ field: string; message: string }> = [];
    if (!partial || 'repo' in b)
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(b.repo ?? '')))
        errs.push({ field: 'repo', message: 'org/name' });
    if (!partial || 'branches' in b)
      if (!Array.isArray(b.branches) || !b.branches.length)
        errs.push({ field: 'branches', message: 'At least one branch' });
    const mode = b.mode ?? 'image';
    if (mode !== 'image' && mode !== 'build')
      errs.push({ field: 'mode', message: 'image or build' });
    if (mode === 'image' && (!partial || 'imageTemplate' in b))
      if (!/\{sha7?\}/.test(String(b.imageTemplate ?? '')))
        errs.push({ field: 'imageTemplate', message: 'Must contain {sha} or {sha7}' });
    if (!partial || 'integrationId' in b)
      if (!s().integrations.some((i) => i.id === b.integrationId))
        errs.push({ field: 'integrationId', message: 'Unknown integration' });
    if (errs.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
  };

  on('POST', '/applications/:id/auto-deploy', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    need(u, 'policies.manage', srv);
    validatePolicy(body, false);
    const mode = body.mode === 'build' ? 'build' : 'image';
    if (mode === 'build' && !a.build)
      throw new HttpError(
        422,
        'BUILD_CONFIG_MISSING',
        'Build mode needs a build config (Settings → Build settings).',
      );
    const p: AutoDeployPolicy = {
      id: c.rid(),
      applicationId: a.id,
      integrationId: String(body.integrationId),
      mode,
      repo: String(body.repo),
      branches: body.branches as string[],
      imageTemplate: mode === 'image' ? String(body.imageTemplate) : null,
      enabled: body.enabled !== false,
      createdBy: u.id,
      createdAt: iso(Date.now()),
      updatedAt: iso(Date.now()),
    };
    s().policies.push(p);
    save();
    c.audit(u, 'auto_deploy.create', srv, 'success', requestId);
    return ok(requestId, p, 201);
  });

  on('PATCH', '/applications/:id/auto-deploy/:pid', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'apps.deploy', srv);
    need(u, 'policies.manage', srv);
    const p = s().policies.find((x) => x.id === params[1] && x.applicationId === a.id);
    if (!p) throw new HttpError(404, 'NOT_FOUND', 'Policy not found');
    validatePolicy(body, true);
    Object.assign(p, body, { updatedAt: iso(Date.now()) });
    save();
    c.audit(u, 'auto_deploy.update', srv, 'success', requestId);
    return ok(requestId, p);
  });

  on('DELETE', '/applications/:id/auto-deploy/:pid', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = containerAppOf(params[0]!);
    const srv = p3Internals.serverOf(a.serverId);
    need(u, 'policies.manage', srv);
    s().policies = s().policies.filter((x) => !(x.id === params[1] && x.applicationId === a.id));
    save();
    c.audit(u, 'auto_deploy.delete', srv, 'success', requestId);
    return new Response(null, { status: 204, headers: { 'X-Request-ID': requestId } });
  });

  on('GET', '/deployments', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'apps.read');
    const p = url.searchParams;
    const items = s()
      .deployments.filter((d) => can(u, 'apps.read', p3Internals.serverOf(d.serverId)))
      .filter((d) => !p.get('status') || p.get('status')!.split(',').includes(d.status))
      .filter((d) => !p.get('server_id') || d.serverId === p.get('server_id'))
      .filter((d) => !p.get('application_id') || d.applicationId === p.get('application_id'))
      .filter((d) => !p.get('trigger') || d.trigger === p.get('trigger'))
      .sort((x, y) => y.createdAt.localeCompare(x.createdAt))
      .map((d) => publicDep(d, u));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('GET', '/deployments/:id', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const d = depOf(params[0]!);
    need(u, 'apps.read', p3Internals.serverOf(d.serverId));
    return ok(requestId, publicDep(d, u));
  });

  on('POST', '/deployments/:id/cancel', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const d = depOf(params[0]!);
    const srv = p3Internals.serverOf(d.serverId);
    need(u, 'apps.deploy', srv);
    const cancellable = ['awaiting_approval', 'queued', 'preflight', 'pulling', 'starting'];
    if (!cancellable.includes(d.status))
      throw new HttpError(
        409,
        'DEPLOYMENT_NOT_CANCELLABLE',
        `Cannot cancel a ${d.status} deployment (route already switching or finished).`,
      );
    const now = Date.now();
    if (d.plan.t0 === null) {
      d.status = 'cancelled';
      d.steps.forEach((x) => {
        if (x.status === 'pending') {
          x.status = 'skipped';
          x.message = 'Skipped — cancelled';
        }
      });
      d.finishedAt = iso(now);
      d.plan.settled = true;
    } else {
      d.plan.cancelledAt = now;
      settle(d, now);
    }
    save();
    c.audit(u, 'deployment.cancel', srv, 'success', requestId);
    return ok(requestId, { deployment: publicDep(d, u) });
  });

  on('POST', '/deployments/:id/approve', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const d = depOf(params[0]!);
    const srv = p3Internals.serverOf(d.serverId);
    need(u, 'approvals.decide', srv);
    if (d.createdBy === u.id) {
      c.audit(u, 'deployment.approve', srv, 'denied', requestId);
      throw new HttpError(
        403,
        'APPROVER_IS_CREATOR',
        'The creator of a deployment cannot approve it. Ask another approver.',
      );
    }
    stepUpOrThrow(req, u, srv, 'deployment.approve', requestId);
    if (d.status !== 'awaiting_approval')
      throw new HttpError(
        409,
        'DEPLOYMENT_STATE_INVALID',
        `Cannot approve a ${d.status} deployment.`,
      );
    if (body.planHash !== d.planHash)
      throw new HttpError(
        409,
        'PLAN_HASH_MISMATCH',
        'The plan changed since you reviewed it. Reload and review again.',
        { planHash: d.planHash },
      );
    const now = Date.now();
    d.approval = {
      ...d.approval,
      approvedBy: u.id,
      approvedByLabel: u.displayName,
      approvedAt: iso(now),
      expiresAt: iso(now + APPROVAL_TTL_MS),
    };
    d.status = 'queued';
    d.plan.t0 = now;
    save();
    c.audit(u, 'deployment.approve', srv, 'success', requestId);
    return ok(requestId, { deployment: publicDep(d, u) });
  });

  // ---- managed routing (server-level; approval rules as nginx revisions)
  const routingView = (srv: Server, u: U): ManagedRouting => {
    const r = s().routing[srv.id]!;
    const allowedActions: NonNullable<ManagedRouting['allowedActions']> = [];
    if (
      !r.enabled &&
      r.status !== 'applying' &&
      r.status !== 'awaiting_approval' &&
      can(u, 'nginx.write', srv)
    )
      allowedActions.push('enable');
    if (r.status === 'awaiting_approval' && r.createdBy !== u.id && can(u, 'approvals.decide', srv))
      allowedActions.push('approve');
    return {
      serverId: srv.id,
      enabled: r.enabled,
      status: r.status,
      revisionId: null,
      planHash: r.planHash,
      path: '/etc/nginx/conf.d/ppanel-managed.conf',
      applyJobId: null,
      approval: r.approval,
      error: null,
      createdBy: r.createdBy,
      allowedActions,
      updatedAt: r.updatedAt,
    };
  };

  on('GET', '/servers/:id/managed-routing', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const srv = p3Internals.serverOf(params[0]!);
    need(u, 'fleet.read', srv);
    return ok(requestId, routingView(srv, u));
  });

  on('POST', '/servers/:id/managed-routing', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const srv = p3Internals.serverOf(params[0]!);
    need(u, 'nginx.write', srv);
    const r = s().routing[srv.id]!;
    if (r.enabled)
      throw new HttpError(
        409,
        'MANAGED_ROUTING_ALREADY_ENABLED',
        'Managed routing is already enabled.',
      );
    if (r.status === 'applying' || r.status === 'awaiting_approval')
      throw new HttpError(
        409,
        'MANAGED_ROUTING_IN_PROGRESS',
        'Enabling managed routing is already in progress.',
      );
    if (srv.status !== 'online' && srv.status !== 'degraded')
      throw new HttpError(409, 'AGENT_OFFLINE', `Agent on ${srv.name} is ${srv.status}.`);
    const now = Date.now();
    const prod = srv.environment === 'production';
    Object.assign(r, {
      status: prod ? 'awaiting_approval' : 'applying',
      planHash: mockDigest(`${srv.id}|managed-routing|${now}`),
      approval: { required: prod, approvedBy: null, approvedAt: null, expiresAt: null },
      createdBy: u.id,
      applyUntil: prod ? null : now + 1500,
      updatedAt: iso(now),
    } satisfies Partial<MockRouting>);
    save();
    c.audit(u, 'managed_routing.enable', srv, 'success', requestId);
    return ok(requestId, routingView(srv, u), 202);
  });

  on('POST', '/servers/:id/managed-routing/approve', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const srv = p3Internals.serverOf(params[0]!);
    need(u, 'approvals.decide', srv);
    const r = s().routing[srv.id]!;
    if (r.createdBy === u.id) {
      c.audit(u, 'managed_routing.approve', srv, 'denied', requestId);
      throw new HttpError(
        403,
        'APPROVER_IS_CREATOR',
        'The requester cannot approve it. Ask another approver.',
      );
    }
    stepUpOrThrow(req, u, srv, 'managed_routing.approve', requestId);
    if (r.status !== 'awaiting_approval')
      throw new HttpError(409, 'REVISION_STATE_INVALID', `Cannot approve (${r.status}).`);
    if (body.planHash !== r.planHash)
      throw new HttpError(409, 'PLAN_HASH_MISMATCH', 'The plan changed since you reviewed it.', {
        planHash: r.planHash,
      });
    const now = Date.now();
    r.approval = {
      required: true,
      approvedBy: u.id,
      approvedAt: iso(now),
      expiresAt: iso(now + APPROVAL_TTL_MS),
    };
    r.status = 'applying';
    r.applyUntil = now + 1500;
    r.updatedAt = iso(now);
    save();
    c.audit(u, 'managed_routing.approve', srv, 'success', requestId);
    return ok(requestId, routingView(srv, u));
  });

  // ---- GitHub integrations
  on('GET', '/integrations', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'apps.read');
    const { slice, paginate } = c.paginate(s().integrations, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('GET', '/integrations/github/app', ({ req, requestId }) => {
    c.currentUser(req);
    return ok(requestId, {
      available: false,
      reason: 'No GitHub App credentials are configured in this installation.',
    });
  });

  on('POST', '/integrations/github', ({ req, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'policies.manage');
    const name = String(body.name ?? '').trim();
    const secret = String(body.webhookSecret ?? '');
    const errs = [];
    if (name.length < 2) errs.push({ field: 'name', message: 'Required' });
    if (secret.length < 16)
      errs.push({ field: 'webhookSecret', message: 'At least 16 characters' });
    if (errs.length) throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', errs);
    const id = c.rid();
    // The secret is not stored by the mock (the Center stores it encrypted and never returns it).
    const integ: Integration = {
      id,
      kind: 'github',
      name,
      webhookUrl: `/api/v1/webhooks/github/${id}`,
      webhookSecret: { set: true },
      enabled: true,
      createdBy: u.id,
      createdAt: iso(Date.now()),
    };
    s().integrations.push(integ);
    s().deliveries[id] = [];
    save();
    c.audit(u, 'integration.github.create', ctx.servers()[0]!, 'success', requestId);
    return ok(requestId, integ, 201);
  });

  on('GET', '/integrations/github/:id/deliveries', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'apps.read');
    if (!s().integrations.some((i) => i.id === params[0]))
      throw new HttpError(404, 'NOT_FOUND', 'Integration not found');
    const { slice, paginate } = c.paginate(s().deliveries[params[0]!] ?? [], url);
    return ok(requestId, slice, 200, paginate);
  });

  // ---- compose + detection
  on('POST', '/deploy/compose/validate', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'apps.deploy');
    const yaml = String(body.yaml ?? '');
    if (yaml.length > 256 * 1024)
      throw new HttpError(413, 'PAYLOAD_TOO_LARGE', 'Compose file exceeds 256 KiB.');
    return ok(requestId, validateComposeMock(yaml, String(body.environment ?? 'production')));
  });

  on('POST', '/deploy/detect', ({ req, body, requestId }) => {
    const u = c.currentUser(req);
    need(u, 'apps.deploy');
    return ok(requestId, detectFramework((body.files ?? {}) as Record<string, string>));
  });
}

/** Read-only accessors for tests. */
export const p4Debug = { state: () => s() };
