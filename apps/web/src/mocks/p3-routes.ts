/**
 * Mock routes for API_CONTRACTS §6 (P3): discovery scans + findings, import, applications and ownership,
 * Nginx revisions (validate / approve / apply / revert / cancel), drift acknowledge, typed job status.
 *
 * State is persisted in sessionStorage so full page loads and user switches (approver ≠ creator) keep
 * it. Async work (scan, nginx -t, apply, revert, read_files) completes on a time basis and is settled
 * lazily on every request (`tick`), so no timers survive reloads.
 */
import type { Permission, Server } from '@ppanel/shared-contracts';
import type {
  Application,
  AppKind,
  DiscoveryFinding,
  DiscoveryScan,
  DiscoverySource,
  NginxRevision,
  OwnershipChange,
  OwnershipMode,
  Postcheck,
  RevisionStatus,
} from '@/lib/api/p3-types';
import { OWNERSHIP_ORDER } from '@/lib/api/p3-types';
import { unifiedDiff } from '@/lib/diff';
import {
  LAB_EXTRA_FILES,
  LAB_FILES,
  LAB_INCLUDED_FROM,
  LAB_LISTENERS,
  LAB_PHP_POOL,
  LAB_SCAN_FILE_ORDER,
  LAB_SERVER_BLOCKS,
  LAB_UPSTREAM,
  mockDigest,
  mockNginxTest,
} from './p3-data';

const P3_KEY = 'ppanel.mock.p3';
const SCAN_MS = 2500;
const VALIDATE_MS = 1500;
const APPLY_MS = 1800;
const REVERT_MS = 1400;
const READ_FILES_MS = 900;
const APPROVAL_TTL_MS = 60 * 60e3;
const ALL_SOURCES: DiscoverySource[] = ['nginx', 'docker', 'systemd', 'php-fpm', 'ports'];

interface MockUserLike {
  id: string;
  displayName: string;
}

export interface P3Ctx {
  on: (
    method: string,
    pattern: string,
    h: (c: {
      req: Request;
      url: URL;
      params: string[];
      body: Record<string, unknown>;
      requestId: string;
    }) => Response | Promise<Response>,
  ) => void;
  ok: (
    requestId: string,
    data: unknown,
    status?: number,
    paginate?: { page: number; limit: number; total: number },
  ) => Response;
  HttpError: new (status: number, code: string, message: string, details?: unknown) => Error;
  currentUser: (req: Request) => MockUserLike;
  hasPermFor: (u: never, perm: Permission, s?: Server) => boolean;
  requirePerm: (u: never, perm: Permission, s?: Server) => void;
  servers: () => Server[];
  users: () => MockUserLike[];
  checkStepUp: (req: Request, u: MockUserLike) => boolean;
  audit: (
    u: MockUserLike,
    action: string,
    s: Server,
    result: 'success' | 'denied',
    rid: string,
  ) => void;
  rid: () => string;
  paginate: <T>(
    items: T[],
    url: URL,
  ) => { slice: T[]; paginate: { page: number; limit: number; total: number } };
}

interface MockJob {
  id: string;
  serverId: string;
  type: string;
  createdAt: number;
  doneAt: number;
  outcome: 'succeeded' | 'failed';
  result: unknown;
}

interface P3State {
  scans: Array<DiscoveryScan & { doneAt?: number; generated?: boolean }>;
  findings: DiscoveryFinding[];
  apps: Application[];
  history: OwnershipChange[];
  revisions: Array<
    NginxRevision & {
      contents: Array<{ path: string; before: string | null; after: string }>;
      busyUntil?: number;
    }
  >;
  /** Current host file contents per server (what `nginx.read_files` returns). */
  hostFiles: Record<string, Record<string, string>>;
  readFilesUntil: Record<string, number>;
  jobs: MockJob[];
}

let st: P3State | null = null;
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
    storage()?.setItem(P3_KEY, JSON.stringify(st));
  } catch {
    /* quota / private mode: keep in memory */
  }
}
export function resetP3State() {
  st = null;
  storage()?.removeItem(P3_KEY);
}

const iso = (ms: number) => new Date(ms).toISOString();
const slug = (s: string) =>
  s
    .replace(/^\*\./, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase() || 'default-catchall';

/** sites-enabled/X is a symlink to sites-available/X on the lab host. */
const toReal = (p: string) => p.replace('/sites-enabled/', '/sites-available/');
const canonical = (p: string) => p.replace('/sites-available/', '/sites-enabled/');

function contentsFor(serverId: string, path: string): string | null {
  return s().hostFiles[serverId]?.[path] ?? null;
}

// ---------- seed ----------

function findingsForScan(scanId: string, serverId: string, now: number): DiscoveryFinding[] {
  const out: DiscoveryFinding[] = [];
  const idOf = (key: string) => `${scanId.slice(0, 18)}-f-${key.slice(4)}`;
  for (const b of LAB_SERVER_BLOCKS) {
    const fingerprint = mockDigest(
      `nginx_server|${b.file}|${b.names.join(',')}|${b.listen.join(',')}`,
    );
    out.push({
      id: idOf(b.key),
      scanId,
      serverId,
      kind: 'nginx_server',
      fingerprint,
      externalId: null,
      title: b.names[0] === '_' ? '_ (default_server)' : b.names[0]!,
      domains: b.names,
      listen: b.listen,
      provenance: {
        file: b.file,
        line: b.line,
        includedFrom: LAB_INCLUDED_FROM,
        includeChain: [LAB_INCLUDED_FROM],
      },
      confidence: b.confidence,
      manualReviewRequired: b.manualReview,
      reasons: b.reasons,
      unsupportedDirectives: b.unsupported,
      conflicts: b.duplicateOf
        ? [{ type: 'duplicate_server_name', with: [idOf(b.duplicateOf)] }]
        : [],
      links: {
        upstream: b.upstream ?? null,
        proxyPass: b.upstream ? `http://${b.upstream}` : null,
        fastcgiPass: b.fastcgiPass ?? null,
        root: b.root ?? null,
        processes: [],
      },
      applicationId: null,
      data: { reportId: b.key, tls: b.listen.some((l) => l.includes('ssl')) },
    });
  }
  out.push({
    id: idOf('srv_upstream_legacy'),
    scanId,
    serverId,
    kind: 'upstream',
    fingerprint: mockDigest(`upstream|${LAB_UPSTREAM.file}|${LAB_UPSTREAM.name}`),
    externalId: null,
    title: LAB_UPSTREAM.name,
    domains: [],
    listen: [],
    provenance: {
      file: LAB_UPSTREAM.file,
      line: LAB_UPSTREAM.line,
      includedFrom: LAB_UPSTREAM.includedFrom,
      includeChain: [LAB_UPSTREAM.includedFrom],
    },
    confidence: 'high',
    manualReviewRequired: false,
    reasons: [],
    unsupportedDirectives: [],
    conflicts: [],
    links: { upstream: null, proxyPass: null, fastcgiPass: null, root: null, processes: [] },
    applicationId: null,
    data: { servers: LAB_UPSTREAM.servers },
  });
  out.push({
    id: idOf('srv_phpfpm_www0'),
    scanId,
    serverId,
    kind: 'php_fpm_pool',
    fingerprint: mockDigest(`php_fpm_pool|${LAB_PHP_POOL.file}|${LAB_PHP_POOL.name}`),
    externalId: null,
    title: `php${LAB_PHP_POOL.phpVersion}-fpm · ${LAB_PHP_POOL.name}`,
    domains: [],
    listen: [LAB_PHP_POOL.listen],
    provenance: { file: LAB_PHP_POOL.file, line: 1, includedFrom: null, includeChain: [] },
    confidence: 'high',
    manualReviewRequired: false,
    reasons: [],
    unsupportedDirectives: [],
    conflicts: [],
    links: {
      upstream: null,
      proxyPass: null,
      fastcgiPass: `unix:${LAB_PHP_POOL.listen}`,
      root: null,
      processes: ['php-fpm8.3'],
    },
    applicationId: null,
    data: { user: LAB_PHP_POOL.user, pm: 'dynamic' },
  });
  LAB_LISTENERS.forEach((l, i) => {
    out.push({
      id: idOf(`srv_listener_${i}000`),
      scanId,
      serverId,
      kind: 'listener',
      fingerprint: mockDigest(`listener|${l.address}|${l.port}`),
      externalId: null,
      title: `${l.address}:${l.port}`,
      domains: [],
      listen: [`${l.address}:${l.port}/tcp`],
      provenance: null,
      confidence: l.process ? 'high' : 'low',
      manualReviewRequired: false,
      reasons: l.process ? [] : ['process not identified'],
      unsupportedDirectives: [],
      conflicts: [],
      links: {
        upstream: null,
        proxyPass: null,
        fastcgiPass: null,
        root: null,
        processes: l.process ? [`${l.process} (pid ${l.pid})`] : [],
      },
      applicationId: null,
      data: {},
    });
  });
  void now;
  return out;
}

function labSummary(): DiscoveryScan['summary'] {
  return {
    nginxServers: 9,
    upstreams: 1,
    duplicates: 1,
    manualReview: 5,
    phpFpmPools: 1,
    listeners: 3,
    containers: 0,
    systemdUnits: 0,
    sourceStatus: {
      nginx: 'ok',
      'php-fpm': 'ok',
      ports: 'ok',
      docker: 'unavailable',
      systemd: 'skipped',
    },
  };
}

function configFilesFor(serverId: string) {
  const files = s().hostFiles[serverId] ?? {};
  return LAB_SCAN_FILE_ORDER.map((path) => ({
    path,
    sha256:
      files[path] !== undefined
        ? mockDigest(files[path]!)
        : (LAB_EXTRA_FILES.find((f) => f.path === path)?.sha256 ?? mockDigest(path)),
  }));
}

function appFromFinding(
  f: DiscoveryFinding,
  mode: OwnershipMode,
  server: Server,
  now: number,
): Application {
  const kind: AppKind = f.links.fastcgiPass
    ? 'nginx_php'
    : f.links.upstream
      ? 'nginx_proxy'
      : f.links.root
        ? 'nginx_static'
        : 'unknown';
  const file = f.provenance?.file;
  const reasons = [...f.reasons];
  return {
    id: ctx.rid(),
    serverId: server.id,
    serverName: server.name,
    name: slug(f.domains[0] ?? f.title),
    environment: server.environment,
    kind,
    domains: f.domains,
    ownershipMode: mode,
    flags: {
      unsupported: f.unsupportedDirectives.length > 0,
      conflict: f.conflicts.length > 0,
      manualReview: f.manualReviewRequired,
      driftDetected: false,
    },
    sourceFindingFingerprint: f.fingerprint,
    unsupportedDirectives: f.unsupportedDirectives,
    driftFiles: [],
    nginxFiles: file
      ? [
          {
            path: file,
            lastKnownSha256: contentsFor(server.id, file)
              ? mockDigest(contentsFor(server.id, file)!)
              : null,
            ...(file.includes('/sites-enabled/') ? { resolvedPath: toReal(file) } : {}),
          },
        ]
      : [],
    lastScanId: f.scanId,
    allowedActions: [],
    version: 1,
    createdAt: iso(now),
    updatedAt: iso(now),
    reasons,
  };
}

function seed(): P3State {
  const now = Date.now();
  const uat = ctx.servers().find((x) => x.name === 'app-uat-01')!;
  const legacy = ctx.servers().find((x) => x.name === 'web-legacy-02')!;
  const offline = ctx.servers().find((x) => x.name === 'worker-uat-01')!;
  const [owner, admin] = [ctx.users()[0]!, ctx.users()[1]!];
  st = {
    scans: [],
    findings: [],
    apps: [],
    history: [],
    revisions: [],
    hostFiles: {
      [uat.id]: Object.fromEntries(
        Object.entries(LAB_FILES).filter(([p]) => !p.endsWith('/shop.conf')),
      ),
      [legacy.id]: {
        '/etc/nginx/nginx.conf': LAB_FILES['/etc/nginx/nginx.conf']!,
        '/etc/nginx/sites-enabled/shop.conf': LAB_FILES['/etc/nginx/sites-enabled/shop.conf']!,
      },
    },
    readFilesUntil: {},
    jobs: [],
  };

  // Scan 1: the lab scan, on app-uat-01, completed yesterday.
  const s1 = '01934f2a-5c01-7000-8000-000000000001';
  st.scans.push({
    id: s1,
    serverId: uat.id,
    jobId: '01934f2a-5c01-7000-8000-00000000j001',
    status: 'completed',
    requestedBy: admin.id,
    startedAt: iso(now - 26 * 3600e3),
    completedAt: iso(now - 26 * 3600e3 + 9000),
    summary: labSummary(),
    configFiles: configFilesFor(uat.id),
    drift: [],
    sources: ['nginx', 'php-fpm', 'ports'],
    error: null,
  });
  st.findings.push(...findingsForScan(s1, uat.id, now));

  // Scan 2: production legacy host, external edit detected on shop.conf.
  const s2 = '01934f2a-5c01-7000-8000-000000000002';
  const shopPrev = mockDigest('previous shop.conf');
  st.scans.push({
    id: s2,
    serverId: legacy.id,
    jobId: '01934f2a-5c01-7000-8000-00000000j002',
    status: 'completed',
    requestedBy: owner.id,
    startedAt: iso(now - 3 * 3600e3),
    completedAt: iso(now - 3 * 3600e3 + 7000),
    summary: {
      nginxServers: 1,
      upstreams: 0,
      duplicates: 0,
      manualReview: 0,
      phpFpmPools: 0,
      listeners: 1,
      containers: 1,
      systemdUnits: 4,
      sourceStatus: {
        nginx: 'ok',
        docker: 'ok',
        ports: 'ok',
        systemd: 'ok',
        'php-fpm': 'unavailable',
      },
    },
    configFiles: [
      { path: '/etc/nginx/nginx.conf', sha256: mockDigest(LAB_FILES['/etc/nginx/nginx.conf']!) },
      {
        path: '/etc/nginx/sites-enabled/shop.conf',
        sha256: mockDigest(LAB_FILES['/etc/nginx/sites-enabled/shop.conf']!),
      },
    ],
    drift: [
      {
        path: '/etc/nginx/sites-enabled/shop.conf',
        previousSha256: shopPrev,
        currentSha256: mockDigest(LAB_FILES['/etc/nginx/sites-enabled/shop.conf']!),
        changedBy: 'external',
        revisionId: null,
      },
    ],
    sources: ALL_SOURCES,
    error: null,
  });
  const shopFinding: DiscoveryFinding = {
    id: '01934f2a-5c01-7000-f-shop00000001',
    scanId: s2,
    serverId: legacy.id,
    kind: 'nginx_server',
    fingerprint: mockDigest('nginx_server|/etc/nginx/sites-enabled/shop.conf|shop.w3.co|80'),
    externalId: null,
    title: 'shop.w3.co',
    domains: ['shop.w3.co'],
    listen: ['80'],
    provenance: {
      file: '/etc/nginx/sites-enabled/shop.conf',
      line: 2,
      includedFrom: LAB_INCLUDED_FROM,
      includeChain: [LAB_INCLUDED_FROM],
    },
    confidence: 'high',
    manualReviewRequired: false,
    reasons: [],
    unsupportedDirectives: [],
    conflicts: [],
    links: {
      upstream: null,
      proxyPass: null,
      fastcgiPass: null,
      root: null,
      processes: ['container shop-web (docker)'],
    },
    applicationId: null,
    data: {},
  };
  st.findings.push(shopFinding);

  // Scan 3: offline server → expired.
  st.scans.push({
    id: '01934f2a-5c01-7000-8000-000000000003',
    serverId: offline.id,
    jobId: '01934f2a-5c01-7000-8000-00000000j003',
    status: 'expired',
    requestedBy: admin.id,
    startedAt: iso(now - 50 * 3600e3),
    completedAt: iso(now - 50 * 3600e3 + 600e3),
    summary: null,
    configFiles: [],
    drift: [],
    sources: ['nginx'],
    error: {
      code: 'JOB_EXPIRED',
      message: 'Agent did not pick up the job before it expired (server offline).',
    },
  });

  // Applications imported earlier.
  const f = (key: string) => st!.findings.find((x) => x.scanId === s1 && x.data.reportId === key)!;
  const mk = (finding: DiscoveryFinding, mode: OwnershipMode, server: Server, ageH: number) => {
    const a = appFromFinding(finding, mode, server, now - ageH * 3600e3);
    finding.applicationId = a.id;
    st!.apps.push(a);
    return a;
  };
  const staticApp = mk(f('srv_bdeb57d131aa'), 'observed', uat, 25);
  staticApp.id = '01934f2a-a991-7000-8000-000000000001';
  f('srv_bdeb57d131aa').applicationId = staticApp.id;
  const api = mk(f('srv_cc77dcc3df48'), 'observed', uat, 25);
  api.id = '01934f2a-a991-7000-8000-000000000002';
  f('srv_cc77dcc3df48').applicationId = api.id;
  const secure = mk(f('srv_2735bc50ed3b'), 'managed', uat, 25);
  secure.id = '01934f2a-a991-7000-8000-000000000003';
  f('srv_2735bc50ed3b').applicationId = secure.id;
  const shop = mk(shopFinding, 'adopted', legacy, 70);
  shop.id = '01934f2a-a991-7000-8000-000000000004';
  shopFinding.applicationId = shop.id;
  shop.flags.driftDetected = true;
  shop.nginxFiles = [
    {
      path: '/etc/nginx/sites-enabled/shop.conf',
      lastKnownSha256: shopPrev,
      resolvedPath: toReal('/etc/nginx/sites-enabled/shop.conf'),
    },
  ];
  shop.driftFiles = [
    {
      path: '/etc/nginx/sites-enabled/shop.conf',
      lastKnownSha256: shopPrev,
      currentSha256: mockDigest(LAB_FILES['/etc/nginx/sites-enabled/shop.conf']!),
      detectedAt: iso(now - 3 * 3600e3),
    },
  ];
  shop.version = 3;

  const hist = (
    app: Application,
    from: OwnershipMode,
    to: OwnershipMode,
    u: MockUserLike,
    ageH: number,
    reason: string,
    ack: string[] = [],
  ) =>
    st!.history.push({
      id: ctx.rid(),
      applicationId: app.id,
      fromMode: from,
      toMode: to,
      actorId: u.id,
      actorLabel: u.displayName,
      reason,
      acknowledgedReasons: ack,
      stepUp: false,
      createdAt: iso(now - ageH * 3600e3),
    });
  hist(staticApp, 'discovered', 'observed', admin, 25, 'Imported from scan (Observe)');
  hist(api, 'discovered', 'observed', admin, 25, 'Imported from scan (Observe)');
  hist(secure, 'discovered', 'observed', admin, 25, 'Imported from scan (Observe)');
  hist(secure, 'observed', 'adopted', admin, 24, 'Owner confirmed by web team');
  hist(secure, 'adopted', 'managed', owner, 20, 'Config fully supported; hand over to pPanel');
  hist(shop, 'discovered', 'observed', owner, 70, 'Imported from scan (Observe)');
  hist(shop, 'observed', 'adopted', owner, 68, 'Storefront team confirmed ownership');

  // Revision history for secure-example-lab: one applied, one reverted.
  const sPath = '/etc/nginx/sites-enabled/04-tls-secure.conf';
  const base = LAB_FILES[sPath]!;
  const v1 = base.replace(
    '    root /var/www/secure;\n',
    '    root /var/www/secure;\n    add_header Strict-Transport-Security "max-age=31536000" always;\n',
  );
  const v2 = v1.replace('max-age=31536000', 'max-age=63072000; includeSubDomains');
  const rev = (
    id: string,
    status: RevisionStatus,
    before: string,
    after: string,
    ageH: number,
    creator: MockUserLike,
    approver: MockUserLike | null,
  ) => {
    const files = [
      {
        path: sPath,
        beforeSha256: mockDigest(before),
        afterSha256: mockDigest(after),
        diff: unifiedDiff(sPath, before, after),
      },
    ];
    const postchecks: Postcheck[] = [
      { hostHeader: 'secure.example.lab', path: '/', scheme: 'https', expectStatus: [200] },
    ];
    st!.revisions.push({
      id,
      serverId: uat.id,
      applicationId: secure.id,
      status,
      files,
      planHash: planHash(uat.id, files, postchecks),
      postchecks,
      validation: {
        jobId: ctx.rid(),
        valid: true,
        nginxTestOutput: mockNginxTest([{ path: sPath, content: after }]).output,
        error: null,
      },
      approval: {
        required: false,
        approvedBy: approver?.id ?? null,
        approvedByLabel: approver?.displayName ?? null,
        approvedAt: approver ? iso(now - ageH * 3600e3) : null,
        expiresAt: null,
      },
      validateJobId: null,
      applyJobId: ctx.rid(),
      revertJobId: status === 'reverted' ? ctx.rid() : null,
      result:
        status === 'reverted'
          ? { message: 'Restored backup; nginx -t ok; reloaded' }
          : {
              postchecks: [{ hostHeader: 'secure.example.lab', path: '/', status: 200, ok: true }],
            },
      createdBy: creator.id,
      createdByLabel: creator.displayName,
      createdAt: iso(now - ageH * 3600e3),
      updatedAt: iso(now - ageH * 3600e3 + 60e3),
      version: 3,
      contents: [{ path: sPath, before, after }],
    });
  };
  rev('01934f2a-7e01-7000-8000-000000000001', 'applied', base, v1, 19, admin, null);
  rev('01934f2a-7e01-7000-8000-000000000002', 'reverted', v1, v2, 6, admin, null);
  st.hostFiles[uat.id]![sPath] = v1;
  secure.nginxFiles = [
    { path: sPath, lastKnownSha256: mockDigest(v1), resolvedPath: toReal(sPath) },
  ];

  // Drift-blocked revision on the production shop app.
  const shopPath = '/etc/nginx/sites-enabled/shop.conf';
  const shopBefore = LAB_FILES[shopPath]!;
  const shopAfter = shopBefore.replace(
    '        proxy_set_header Host $host;\n',
    '        proxy_set_header Host $host;\n        proxy_read_timeout 60s;\n',
  );
  const shopFiles = [
    {
      path: shopPath,
      beforeSha256: shopPrev,
      afterSha256: mockDigest(shopAfter),
      diff: unifiedDiff(shopPath, shopBefore, shopAfter),
    },
  ];
  const shopChecks: Postcheck[] = [
    { hostHeader: 'shop.w3.co', path: '/', scheme: 'http', expectStatus: [200] },
  ];
  st.revisions.push({
    id: '01934f2a-7e01-7000-8000-000000000003',
    serverId: legacy.id,
    applicationId: shop.id,
    status: 'drift_blocked',
    files: shopFiles,
    planHash: planHash(legacy.id, shopFiles, shopChecks),
    postchecks: shopChecks,
    validation: null,
    approval: { required: true, approvedBy: null, approvedAt: null, expiresAt: null },
    validateJobId: null,
    applyJobId: null,
    revertJobId: null,
    result: {
      errorCode: 'DRIFT_DETECTED',
      message: 'shop.conf changed outside pPanel since this revision was drafted.',
    },
    createdBy: owner.id,
    createdByLabel: owner.displayName,
    createdAt: iso(now - 4 * 3600e3),
    updatedAt: iso(now - 3 * 3600e3),
    version: 2,
    contents: [{ path: shopPath, before: shopBefore, after: shopAfter }],
  });
  return st;
}

function s(): P3State {
  if (!st) {
    const raw = storage()?.getItem(P3_KEY);
    if (raw) {
      try {
        st = JSON.parse(raw) as P3State;
      } catch {
        st = null;
      }
    }
    if (!st) {
      seed();
      save();
    }
  }
  return st!;
}

function planHash(
  serverId: string,
  files: Array<{ path: string; beforeSha256: string | null; afterSha256: string }>,
  postchecks: Postcheck[],
) {
  const parts = [...files]
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((f) => `${f.path}|${f.beforeSha256 ?? 'null'}|${f.afterSha256}`);
  return mockDigest(`${serverId}\n${parts.join('\n')}\n${JSON.stringify(postchecks)}`);
}

// ---------- lazy settlement of async work ----------

function newJob(
  serverId: string,
  type: string,
  durationMs: number,
  outcome: MockJob['outcome'] = 'succeeded',
  result: unknown = null,
): MockJob {
  const now = Date.now();
  const j: MockJob = {
    id: ctx.rid(),
    serverId,
    type,
    createdAt: now,
    doneAt: now + durationMs,
    outcome,
    result,
  };
  s().jobs.push(j);
  if (s().jobs.length > 200) s().jobs.shift();
  return j;
}

function tick() {
  const state = s();
  const now = Date.now();
  let dirty = false;
  for (const scan of state.scans) {
    if (scan.status === 'running' && scan.doneAt && now >= scan.doneAt) {
      scan.status = 'completed';
      scan.completedAt = iso(scan.doneAt);
      scan.summary = labSummary();
      scan.configFiles = configFilesFor(scan.serverId);
      // drift vs. previous completed scan of the same server
      const prev = state.scans
        .filter((x) => x.serverId === scan.serverId && x.status === 'completed' && x.id !== scan.id)
        .sort((a, b) => (b.completedAt ?? '').localeCompare(a.completedAt ?? ''))[0];
      scan.drift = [];
      if (prev) {
        for (const cf of scan.configFiles) {
          const old = prev.configFiles.find((p) => p.path === cf.path);
          if (old && old.sha256 !== cf.sha256) {
            const byRev = state.revisions.find(
              (r) =>
                r.serverId === scan.serverId &&
                (r.status === 'applied' || r.status === 'reverted') &&
                r.files.some((f) => f.path === cf.path),
            );
            scan.drift.push({
              path: cf.path,
              previousSha256: old.sha256,
              currentSha256: cf.sha256,
              changedBy: byRev ? 'ppanel_revision' : 'external',
              revisionId: byRev?.id ?? null,
            });
          }
        }
      }
      const fresh = findingsForScan(scan.id, scan.serverId, now);
      for (const f of fresh) {
        const app = state.apps.find(
          (a) => a.serverId === scan.serverId && a.sourceFindingFingerprint === f.fingerprint,
        );
        f.applicationId = app?.id ?? null;
      }
      state.findings.push(...fresh);
      dirty = true;
    }
  }
  for (const r of state.revisions) {
    if (!r.busyUntil || now < r.busyUntil) continue;
    const app = state.apps.find((a) => a.id === r.applicationId);
    if (r.status === 'validating') {
      if (app?.flags.driftDetected) {
        r.status = 'drift_blocked';
        r.result = {
          errorCode: 'DRIFT_DETECTED',
          message: 'A file changed on the host since the draft was created.',
        };
      } else {
        const res = mockNginxTest(r.contents.map((c) => ({ path: c.path, content: c.after })));
        r.validation = {
          jobId: r.validation?.jobId ?? '',
          valid: res.valid,
          nginxTestOutput: res.output,
          error: res.valid ? null : { code: 'NGINX_TEST_FAILED' },
        };
        r.status = !res.valid ? 'invalid' : r.approval.required ? 'awaiting_approval' : 'valid';
        if (!res.valid)
          r.result = {
            errorCode: 'NGINX_TEST_FAILED',
            message: 'nginx -t failed; originals restored, nothing reloaded.',
          };
      }
    } else if (r.status === 'applying') {
      const failing = r.postchecks.find(
        (p) => !p.expectStatus.includes(200) || p.path.includes('fail'),
      );
      const manual = r.postchecks.some((p) => p.path.includes('manual-recovery'));
      if (app?.flags.driftDetected) {
        r.status = 'drift_blocked';
        r.result = {
          errorCode: 'DRIFT_DETECTED',
          message: 'expectedSha256Before did not match the file on the host. Nothing was written.',
          details: {
            files: r.files.map((f) => ({
              path: f.path,
              expected: f.beforeSha256,
              actual: mockDigest('external edit'),
            })),
          },
        };
      } else if (manual) {
        r.status = 'requires_manual_recovery';
        r.result = {
          errorCode: 'REVERT_FAILED_MANUAL_RECOVERY',
          message: 'Postcheck failed and restoring the backup also failed.',
          details: {
            backupDir: `/var/lib/ppanel-agent/nginx-backups/${r.id}`,
            problems: [
              `restore ${r.contents[0]?.path}: permission denied`,
              'nginx -t failed after restore',
            ],
          },
        };
      } else if (failing) {
        r.status = 'apply_failed';
        const pcs = r.postchecks.map((p) => ({
          hostHeader: p.hostHeader,
          path: p.path,
          status: p === failing ? 502 : 200,
          ok: p !== failing,
          ...(p === failing ? { error: 'unexpected status 502' } : {}),
        }));
        r.result = {
          errorCode: 'POSTCHECK_FAILED_REVERTED',
          message:
            'Postcheck failed after reload; originals were restored and Nginx reloaded again.',
          details: { postchecks: pcs, restored: true },
        };
      } else {
        r.status = 'applied';
        r.result = {
          applied: true,
          reloadMethod: 'systemctl',
          backupId: `bk-${r.id.slice(0, 8)}`,
          postchecks: r.postchecks.map((p) => ({
            hostHeader: p.hostHeader,
            path: p.path,
            status: 200,
            ok: true,
          })),
        };
        for (const c of r.contents) state.hostFiles[r.serverId]![c.path] = c.after;
        if (app) {
          app.nginxFiles = app.nginxFiles.map((nf) => {
            const c = r.contents.find((x) => x.path === nf.path);
            return c ? { ...nf, lastKnownSha256: mockDigest(c.after) } : nf;
          });
          for (const c of r.contents)
            if (!app.nginxFiles.some((nf) => nf.path === c.path))
              app.nginxFiles.push({ path: c.path, lastKnownSha256: mockDigest(c.after) });
          app.updatedAt = iso(now);
        }
        for (const other of state.revisions)
          if (
            other.id !== r.id &&
            other.applicationId === r.applicationId &&
            other.status === 'applied'
          )
            other.status = 'superseded';
      }
    } else if (r.status === 'reverting') {
      r.status = 'reverted';
      r.result = { message: 'Backup restored; nginx -t ok; reloaded.' };
      for (const c of r.contents) {
        if (c.before === null) delete state.hostFiles[r.serverId]![c.path];
        else state.hostFiles[r.serverId]![c.path] = c.before;
      }
      if (app) {
        app.nginxFiles = app.nginxFiles.map((nf) => {
          const c = r.contents.find((x) => x.path === nf.path);
          return c
            ? { ...nf, lastKnownSha256: c.before === null ? null : mockDigest(c.before) }
            : nf;
        });
      }
    }
    r.busyUntil = undefined;
    r.updatedAt = iso(now);
    r.version += 1;
    dirty = true;
  }
  if (dirty) save();
}

// ---------- helpers ----------

function serverOf(id: string): Server {
  const srv = ctx.servers().find((x) => x.id === id);
  if (!srv) throw new ctx.HttpError(404, 'NOT_FOUND', 'Server not found');
  return srv;
}
function appOf(id: string) {
  const a = s().apps.find((x) => x.id === id);
  if (!a) throw new ctx.HttpError(404, 'NOT_FOUND', 'Application not found');
  return a;
}
function revOf(id: string) {
  const r = s().revisions.find((x) => x.id === id);
  if (!r) throw new ctx.HttpError(404, 'NOT_FOUND', 'Revision not found');
  return r;
}
const can = (u: MockUserLike, perm: Permission, srv?: Server) =>
  ctx.hasPermFor(u as never, perm, srv);
const need = (u: MockUserLike, perm: Permission, srv?: Server) =>
  ctx.requirePerm(u as never, perm, srv);
const OPEN: RevisionStatus[] = [
  'draft',
  'validating',
  'valid',
  'awaiting_approval',
  'approved',
  'applying',
  'reverting',
];

const MODE_ACTION: Record<OwnershipMode, string> = {
  discovered: 'discover',
  observed: 'observe',
  adopted: 'adopt',
  managed: 'manage',
};

function decorate(u: MockUserLike, a: Application): Application {
  const srv = serverOf(a.serverId);
  const actions: string[] = [];
  const i = OWNERSHIP_ORDER.indexOf(a.ownershipMode);
  const up = OWNERSHIP_ORDER[i + 1];
  const down = OWNERSHIP_ORDER[i - 1];
  if (down && can(u, 'servers.operate', srv)) actions.push(MODE_ACTION[down]);
  if (up) {
    const perm: Permission = up === 'observed' ? 'servers.operate' : 'nginx.write';
    if (can(u, perm, srv) && !(up === 'managed' && a.flags.unsupported))
      actions.push(MODE_ACTION[up]);
  }
  if (
    can(u, 'nginx.write', srv) &&
    (a.ownershipMode === 'adopted' || a.ownershipMode === 'managed')
  ) {
    if (a.flags.driftDetected) actions.push('acknowledge_drift');
    else actions.push('create_revision');
  }
  return {
    ...a,
    serverName: srv.name,
    environment: srv.environment,
    allowedActions: actions as Application['allowedActions'],
  };
}

function publicRev(r: P3State['revisions'][number]): NginxRevision {
  const { contents: _c, busyUntil: _b, ...rest } = r;
  void _c;
  void _b;
  return rest;
}

function stepUp(req: Request, u: MockUserLike, srv: Server, action: string, rid: string) {
  if (!ctx.checkStepUp(req, u)) {
    ctx.audit(u, action, srv, 'denied', rid);
    throw new ctx.HttpError(
      403,
      'STEP_UP_REQUIRED',
      'This action requires a fresh 2FA confirmation (X-Step-Up).',
    );
  }
}

// ---------- routes ----------

export function registerP3Routes(c: P3Ctx) {
  ctx = c;
  const { on, ok, HttpError } = c;

  on('GET', '/discovery-scans', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const serverId = url.searchParams.get('server_id');
    const status = url.searchParams.get('status');
    const items = s()
      .scans.filter((x) => can(u, 'fleet.read', serverOf(x.serverId)))
      .filter((x) => !serverId || x.serverId === serverId)
      .filter((x) => !status || x.status === status)
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .map(({ doneAt: _d, generated: _g, ...rest }) => rest);
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('GET', '/discovery-scans/:id', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const scan = s().scans.find((x) => x.id === params[0]);
    if (!scan) throw new HttpError(404, 'NOT_FOUND', 'Scan not found');
    need(u, 'fleet.read', serverOf(scan.serverId));
    const { doneAt: _d, generated: _g, ...rest } = scan;
    return ok(requestId, rest);
  });

  on('GET', '/discovery-scans/:id/findings', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const scan = s().scans.find((x) => x.id === params[0]);
    if (!scan) throw new HttpError(404, 'NOT_FOUND', 'Scan not found');
    need(u, 'nginx.read', serverOf(scan.serverId));
    const kind = url.searchParams.get('kind');
    const mr = url.searchParams.get('manual_review');
    const items = s()
      .findings.filter((f) => f.scanId === scan.id)
      .filter((f) => !kind || f.kind === kind)
      .filter((f) => mr === null || String(f.manualReviewRequired) === mr);
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('POST', '/servers/:id/discovery-scans', ({ req, params, body, requestId }) => {
    const u = c.currentUser(req);
    const srv = serverOf(params[0]!);
    need(u, 'nginx.read', srv);
    if (srv.status === 'revoked') throw new HttpError(409, 'SERVER_REVOKED', 'Server is revoked');
    const sources =
      Array.isArray(body.sources) && body.sources.length
        ? (body.sources as DiscoverySource[])
        : ALL_SOURCES;
    const bad = sources.filter((x) => !ALL_SOURCES.includes(x));
    if (bad.length)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Unknown source', [
        { field: 'sources', message: `Unknown: ${bad.join(', ')}` },
      ]);
    const live = srv.status === 'online' || srv.status === 'degraded';
    const job = newJob(
      srv.id,
      'discovery.scan',
      live ? SCAN_MS : 600e3,
      live ? 'succeeded' : 'failed',
    );
    const now = Date.now();
    const scan: P3State['scans'][number] = {
      id: c.rid(),
      serverId: srv.id,
      jobId: job.id,
      status: 'running',
      requestedBy: u.id,
      startedAt: iso(now),
      completedAt: null,
      summary: null,
      configFiles: [],
      drift: [],
      sources,
      error: live ? null : null,
      doneAt: live ? now + SCAN_MS : undefined,
    };
    if (!s().hostFiles[srv.id]) s().hostFiles[srv.id] = { ...LAB_FILES };
    s().scans.push(scan);
    save();
    c.audit(u, 'discovery.scan.create', srv, 'success', requestId);
    return ok(requestId, { scanId: scan.id, jobId: job.id }, 202);
  });

  on('POST', '/discovery-scans/:id/import', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const scan = s().scans.find((x) => x.id === params[0]);
    if (!scan) throw new HttpError(404, 'NOT_FOUND', 'Scan not found');
    const srv = serverOf(scan.serverId);
    need(u, 'servers.operate', srv);
    const mode = (body.mode ?? 'observed') as OwnershipMode;
    if (mode !== 'observed' && mode !== 'discovered')
      throw new HttpError(
        422,
        'IMPORT_MODE_NOT_ALLOWED',
        'Import only supports discovered or observed; ownership is a separate step.',
        [{ field: 'mode', message: 'discovered | observed' }],
      );
    const ids = Array.isArray(body.findingIds) ? (body.findingIds as string[]) : [];
    if (!ids.length)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Select at least one finding', [
        { field: 'findingIds', message: 'Required' },
      ]);
    const now = Date.now();
    const result: Application[] = [];
    for (const id of ids) {
      const f = s().findings.find((x) => x.id === id && x.scanId === scan.id);
      if (!f)
        throw new HttpError(422, 'VALIDATION_FAILED', 'Unknown finding', [
          { field: 'findingIds', message: id },
        ]);
      if (f.kind !== 'nginx_server')
        throw new HttpError(
          422,
          'FINDING_NOT_IMPORTABLE',
          `Only nginx_server findings can be imported (${f.title}).`,
        );
      let app = s().apps.find(
        (a) => a.serverId === srv.id && a.sourceFindingFingerprint === f.fingerprint,
      );
      if (app) {
        app.lastScanId = scan.id; // never touches ownership
        app.updatedAt = iso(now);
      } else {
        app = appFromFinding(f, mode, srv, now);
        s().apps.push(app);
        s().history.push({
          id: c.rid(),
          applicationId: app.id,
          fromMode: 'discovered',
          toMode: mode,
          actorId: u.id,
          actorLabel: u.displayName,
          reason: `Imported from scan (${mode === 'observed' ? 'Observe' : 'Discover'})`,
          acknowledgedReasons: [],
          stepUp: false,
          createdAt: iso(now),
        });
      }
      f.applicationId = app.id;
      result.push(decorate(u, app));
    }
    save();
    c.audit(u, 'discovery.import', srv, 'success', requestId);
    return ok(requestId, { applications: result }, 201);
  });

  on('GET', '/applications', ({ req, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    need(u, 'apps.read');
    const p = url.searchParams;
    const q = p.get('q')?.toLowerCase();
    const items = s()
      .apps.filter((a) => can(u, 'apps.read', serverOf(a.serverId)))
      .filter((a) => !p.get('server_id') || a.serverId === p.get('server_id'))
      .filter((a) => !p.get('ownership_mode') || a.ownershipMode === p.get('ownership_mode'))
      .filter(
        (a) => !p.get('environment') || serverOf(a.serverId).environment === p.get('environment'),
      )
      .filter((a) => !q || a.name.includes(q) || a.domains.some((d) => d.toLowerCase().includes(q)))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((a) => decorate(u, a));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('GET', '/applications/:id', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    need(u, 'apps.read', serverOf(a.serverId));
    return ok(requestId, decorate(u, a));
  });

  on('GET', '/applications/:id/ownership-history', ({ req, params, url, requestId }) => {
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    need(u, 'apps.read', serverOf(a.serverId));
    const items = s()
      .history.filter((h) => h.applicationId === a.id)
      .sort((x, y) => y.createdAt.localeCompare(x.createdAt));
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('POST', '/applications/:id/ownership', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    const srv = serverOf(a.serverId);
    const ifMatch = req.headers.get('If-Match');
    if (ifMatch && Number(ifMatch) !== a.version)
      throw new HttpError(
        409,
        'VERSION_CONFLICT',
        'This application changed since you loaded it. Reload and try again.',
        { currentVersion: a.version },
      );
    const to = body.toMode as OwnershipMode;
    const from = a.ownershipMode;
    const di = OWNERSHIP_ORDER.indexOf(to) - OWNERSHIP_ORDER.indexOf(from);
    if (!OWNERSHIP_ORDER.includes(to) || Math.abs(di) !== 1)
      throw new HttpError(
        422,
        'OWNERSHIP_STEP_INVALID',
        `Ownership changes one step at a time (${from} → ${to} is not allowed).`,
      );
    const reason = String(body.reason ?? '').trim();
    if (!reason)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'reason', message: 'Required' },
      ]);
    if (di < 0) {
      need(u, 'servers.operate', srv);
    } else {
      need(u, to === 'observed' ? 'servers.operate' : 'nginx.write', srv);
      if (to === 'adopted' || to === 'managed') {
        if (srv.environment === 'production')
          stepUp(req, u, srv, 'application.ownership', requestId);
      }
      if (
        to === 'adopted' &&
        (a.flags.manualReview || a.flags.conflict) &&
        body.acknowledgeReasons !== true
      )
        throw new HttpError(
          422,
          'MANUAL_REVIEW_REQUIRED',
          'Acknowledge the manual-review reasons before adopting.',
          { reasons: a.reasons ?? [] },
        );
      if (to === 'managed' && a.flags.unsupported)
        throw new HttpError(
          422,
          'UNSUPPORTED_CONFIG',
          'Unsupported directives block Managed. Keep Adopted or rewrite the config.',
        );
    }
    const now = Date.now();
    if (di < 0)
      for (const r of s().revisions)
        if (
          r.applicationId === a.id &&
          ['draft', 'valid', 'awaiting_approval', 'approved'].includes(r.status)
        )
          r.status = 'cancelled';
    a.ownershipMode = to;
    a.version += 1;
    a.updatedAt = iso(now);
    s().history.push({
      id: c.rid(),
      applicationId: a.id,
      fromMode: from,
      toMode: to,
      actorId: u.id,
      actorLabel: u.displayName,
      reason,
      acknowledgedReasons: body.acknowledgeReasons === true ? (a.reasons ?? []) : [],
      stepUp: di > 0 && (to === 'adopted' || to === 'managed') && srv.environment === 'production',
      createdAt: iso(now),
    });
    save();
    c.audit(u, 'application.ownership', srv, 'success', requestId);
    return ok(requestId, decorate(u, a));
  });

  on('POST', '/applications/:id/drift/acknowledge', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    const srv = serverOf(a.serverId);
    need(u, 'nginx.write', srv);
    a.flags.driftDetected = false;
    a.driftFiles = [];
    a.nginxFiles = a.nginxFiles.map((nf) => {
      const cur = contentsFor(a.serverId, nf.path);
      return { ...nf, lastKnownSha256: cur === null ? null : mockDigest(cur) };
    });
    a.version += 1;
    save();
    c.audit(u, 'application.drift.acknowledge', srv, 'success', requestId);
    return ok(requestId, decorate(u, a));
  });

  on('GET', '/applications/:id/nginx/files', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    const srv = serverOf(a.serverId);
    need(u, 'nginx.read', srv);
    const now = Date.now();
    const until = s().readFilesUntil[a.id];
    if (!until || (now > until + 30e3 && until > 0)) {
      const job = newJob(srv.id, 'nginx.read_files', READ_FILES_MS);
      s().readFilesUntil[a.id] = now + READ_FILES_MS;
      save();
      return ok(requestId, { jobId: job.id, status: 'pending', files: [] }, 202);
    }
    if (now < until) {
      const job = [...s().jobs]
        .reverse()
        .find((j) => j.type === 'nginx.read_files' && j.serverId === srv.id);
      return ok(requestId, { jobId: job?.id ?? '', status: 'pending', files: [] }, 202);
    }
    const files = a.nginxFiles.map((nf) => {
      const content = contentsFor(a.serverId, nf.path);
      const link = nf.path.includes('/sites-enabled/');
      return {
        path: nf.path,
        sha256: content === null ? null : mockDigest(content),
        content,
        exists: content !== null,
        sizeBytes: content?.length ?? 0,
        isSymlink: link,
        resolvedPath: nf.resolvedPath ?? nf.path,
        truncated: false,
      };
    });
    const last = [...s().jobs]
      .reverse()
      .find((j) => j.type === 'nginx.read_files' && j.serverId === srv.id);
    return ok(requestId, { jobId: last?.id ?? '', status: 'succeeded', files });
  });

  on('GET', '/applications/:id/nginx/revisions', ({ req, params, url, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    need(u, 'nginx.read', serverOf(a.serverId));
    const items = s()
      .revisions.filter((r) => r.applicationId === a.id)
      .sort((x, y) => y.createdAt.localeCompare(x.createdAt))
      .map(publicRev);
    const { slice, paginate } = c.paginate(items, url);
    return ok(requestId, slice, 200, paginate);
  });

  on('POST', '/applications/:id/nginx/revisions', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const a = appOf(params[0]!);
    const srv = serverOf(a.serverId);
    need(u, 'nginx.write', srv);
    if (a.ownershipMode !== 'adopted' && a.ownershipMode !== 'managed')
      throw new HttpError(
        409,
        'OWNERSHIP_REQUIRED',
        'Adopt the application before proposing Nginx changes.',
      );
    if (a.flags.driftDetected)
      throw new HttpError(
        409,
        'DRIFT_REVIEW_REQUIRED',
        'Files changed outside pPanel. Acknowledge drift first.',
      );
    if (s().revisions.some((r) => r.applicationId === a.id && OPEN.includes(r.status)))
      throw new HttpError(
        409,
        'REVISION_IN_PROGRESS',
        'Another revision for this application is still open. Finish or cancel it first.',
      );
    const files = Array.isArray(body.files)
      ? (body.files as Array<{ path: string; content: string }>)
      : [];
    if (!files.length)
      throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
        { field: 'files', message: 'At least one file' },
      ]);
    const allowedDir = `/etc/nginx/ppanel-managed/${a.name}/`;
    for (const f of files) {
      if (
        !a.nginxFiles.some((nf) => nf.path === canonical(f.path)) &&
        !f.path.startsWith(allowedDir)
      )
        throw new HttpError(
          422,
          'PATH_NOT_ALLOWED',
          `Path is not part of this application: ${f.path}`,
          [{ field: 'files', message: f.path }],
        );
    }
    const contents = files.map((f) => ({
      path: canonical(f.path),
      before: contentsFor(a.serverId, canonical(f.path)),
      after: f.content,
    }));
    if (contents.every((x) => x.before === x.after))
      throw new HttpError(422, 'NO_CHANGES', 'The draft is identical to the current files.');
    const revFiles = contents.map((x, i) => ({
      path: files[i]!.path,
      beforeSha256: x.before === null ? null : mockDigest(x.before),
      afterSha256: mockDigest(x.after),
      diff: unifiedDiff(files[i]!.path, x.before, x.after),
    }));
    const postchecks = (Array.isArray(body.postchecks) ? body.postchecks : []) as Postcheck[];
    for (const p of postchecks) {
      if (
        !/^[A-Za-z0-9.-]{1,253}$/.test(p.hostHeader ?? '') ||
        !String(p.path ?? '/').startsWith('/')
      )
        throw new HttpError(422, 'VALIDATION_FAILED', 'Validation failed', [
          { field: 'postchecks', message: 'Host header and path (starting with /) required' },
        ]);
    }
    const now = Date.now();
    const r: P3State['revisions'][number] = {
      id: c.rid(),
      serverId: srv.id,
      applicationId: a.id,
      status: 'draft',
      files: revFiles,
      planHash: planHash(srv.id, revFiles, postchecks),
      postchecks,
      validation: null,
      approval: {
        required: srv.environment === 'production' || a.ownershipMode === 'adopted',
        approvedBy: null,
        approvedAt: null,
        expiresAt: null,
      },
      validateJobId: null,
      applyJobId: null,
      revertJobId: null,
      result: null,
      createdBy: u.id,
      createdByLabel: u.displayName,
      createdAt: iso(now),
      updatedAt: iso(now),
      version: 1,
      contents,
    };
    s().revisions.push(r);
    save();
    c.audit(u, 'nginx.revision.create', srv, 'success', requestId);
    return ok(requestId, publicRev(r), 201);
  });

  on('GET', '/nginx-revisions/:id', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = revOf(params[0]!);
    need(u, 'nginx.read', serverOf(r.serverId));
    return ok(requestId, publicRev(r));
  });

  on('POST', '/nginx-revisions/:id/validate', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = revOf(params[0]!);
    const srv = serverOf(r.serverId);
    need(u, 'nginx.write', srv);
    if (r.status !== 'draft')
      throw new HttpError(409, 'REVISION_STATE_INVALID', `Cannot validate a ${r.status} revision.`);
    const job = newJob(srv.id, 'nginx.validate', VALIDATE_MS);
    r.status = 'validating';
    r.validation = { jobId: job.id, valid: null, nginxTestOutput: null, error: null };
    r.validateJobId = job.id;
    r.busyUntil = Date.now() + VALIDATE_MS;
    r.version += 1;
    save();
    c.audit(u, 'nginx.revision.validate', srv, 'success', requestId);
    return ok(requestId, { jobId: job.id, status: 'queued' }, 202);
  });

  on('POST', '/nginx-revisions/:id/approve', ({ req, params, body, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = revOf(params[0]!);
    const srv = serverOf(r.serverId);
    need(u, 'approvals.decide', srv);
    if (r.createdBy === u.id) {
      c.audit(u, 'nginx.revision.approve', srv, 'denied', requestId);
      throw new HttpError(
        403,
        'APPROVER_IS_CREATOR',
        'The creator of a revision cannot approve it. Ask another approver.',
      );
    }
    stepUp(req, u, srv, 'nginx.revision.approve', requestId);
    if (r.status !== 'awaiting_approval')
      throw new HttpError(409, 'REVISION_STATE_INVALID', `Cannot approve a ${r.status} revision.`);
    if (body.planHash !== r.planHash)
      throw new HttpError(
        409,
        'PLAN_HASH_MISMATCH',
        'The plan changed since you reviewed it. Reload and review again.',
        { planHash: r.planHash },
      );
    const now = Date.now();
    r.status = 'approved';
    r.approval = {
      ...r.approval,
      approvedBy: u.id,
      approvedByLabel: u.displayName,
      approvedAt: iso(now),
      expiresAt: iso(now + APPROVAL_TTL_MS),
    };
    r.version += 1;
    r.updatedAt = iso(now);
    save();
    c.audit(u, 'nginx.revision.approve', srv, 'success', requestId);
    return ok(requestId, publicRev(r));
  });

  on('POST', '/nginx-revisions/:id/apply', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = revOf(params[0]!);
    const srv = serverOf(r.serverId);
    need(u, 'nginx.write', srv);
    if (srv.environment === 'production') stepUp(req, u, srv, 'nginx.revision.apply', requestId);
    const app = appOf(r.applicationId);
    if (app.flags.driftDetected)
      throw new HttpError(
        409,
        'DRIFT_REVIEW_REQUIRED',
        'Files changed outside pPanel. Acknowledge drift first.',
      );
    if (r.approval.required) {
      if (r.status !== 'approved')
        throw new HttpError(
          409,
          'APPROVAL_REQUIRED',
          'This revision needs approval by another user before it can be applied.',
        );
      if (r.approval.expiresAt && Date.parse(r.approval.expiresAt) < Date.now())
        throw new HttpError(
          409,
          'APPROVAL_EXPIRED',
          'The approval expired. Request a new approval.',
        );
    } else if (r.status !== 'valid') {
      throw new HttpError(409, 'REVISION_STATE_INVALID', `Cannot apply a ${r.status} revision.`);
    }
    const job = newJob(srv.id, 'nginx.apply', APPLY_MS);
    r.status = 'applying';
    r.applyJobId = job.id;
    r.busyUntil = Date.now() + APPLY_MS;
    r.version += 1;
    save();
    c.audit(u, 'nginx.revision.apply', srv, 'success', requestId);
    return ok(requestId, { jobId: job.id, status: 'queued' }, 202);
  });

  on('POST', '/nginx-revisions/:id/revert', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = revOf(params[0]!);
    const srv = serverOf(r.serverId);
    need(u, 'nginx.write', srv);
    if (srv.environment === 'production') stepUp(req, u, srv, 'nginx.revision.revert', requestId);
    if (r.status !== 'applied')
      throw new HttpError(409, 'REVISION_STATE_INVALID', `Cannot revert a ${r.status} revision.`);
    const job = newJob(srv.id, 'nginx.revert', REVERT_MS);
    r.status = 'reverting';
    r.revertJobId = job.id;
    r.busyUntil = Date.now() + REVERT_MS;
    r.version += 1;
    save();
    c.audit(u, 'nginx.revision.revert', srv, 'success', requestId);
    return ok(requestId, { jobId: job.id, status: 'queued' }, 202);
  });

  on('POST', '/nginx-revisions/:id/cancel', ({ req, params, requestId }) => {
    tick();
    const u = c.currentUser(req);
    const r = revOf(params[0]!);
    const srv = serverOf(r.serverId);
    need(u, 'nginx.write', srv);
    if (!['draft', 'valid', 'awaiting_approval', 'approved'].includes(r.status))
      throw new HttpError(409, 'REVISION_STATE_INVALID', `Cannot cancel a ${r.status} revision.`);
    r.status = 'cancelled';
    r.version += 1;
    save();
    c.audit(u, 'nginx.revision.cancel', srv, 'success', requestId);
    return ok(requestId, publicRev(r));
  });

  on('GET', '/servers/:id/jobs/:jobId', ({ req, params, requestId }) => {
    const u = c.currentUser(req);
    const srv = serverOf(params[0]!);
    need(u, 'fleet.read', srv);
    const j = s().jobs.find((x) => x.id === params[1] && x.serverId === srv.id);
    if (!j) throw new HttpError(404, 'NOT_FOUND', 'Job not found');
    const now = Date.now();
    const status = now >= j.doneAt ? j.outcome : now - j.createdAt < 300 ? 'queued' : 'running';
    return ok(requestId, {
      id: j.id,
      serverId: j.serverId,
      type: j.type,
      params: {},
      status,
      idempotencyKey: j.id,
      expiresAt: iso(j.createdAt + 600e3),
      leaseUntil: null,
      attempt: 1,
      desiredVersion: null,
      actorId: u.id,
      correlationId: requestId,
      result: status === j.outcome ? j.result : null,
      createdAt: iso(j.createdAt),
      updatedAt: iso(Math.min(now, j.doneAt)),
    });
  });
}

/** Read-only accessors for tests. */
export const p3Debug = {
  state: () => s(),
};
