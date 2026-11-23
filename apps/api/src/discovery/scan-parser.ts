/**
 * Pure mapping of a `discovery.scan` job output (agent report, see docs/evidence/…/e2e-discovery-job.json)
 * into Center read models. Never invents runtime/repo/ownership links: unknown stays null.
 */
import type {
  ApplicationKind,
  DiscoveryScanSummary,
  FindingConfidence,
  FindingKind,
} from '@ppanel/shared-contracts';
import { nginxPathSchema } from '@ppanel/shared-contracts';
import { sha256Hex, stableStringify } from '../common/crypto';
import { uuidv7 } from '../common/ids';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const strs = (v: unknown): string[] => arr(v).filter((x): x is string => typeof x === 'string');
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

export interface ParsedFinding {
  id: string;
  kind: FindingKind;
  fingerprint: string;
  externalId: string | null;
  title: string;
  domains: string[];
  listen: string[];
  provenance: {
    file: string | null;
    line: number | null;
    includedFrom: string | null;
    includeChain: string[];
  } | null;
  confidence: FindingConfidence;
  manualReviewRequired: boolean;
  reasons: string[];
  unsupportedDirectives: string[];
  conflicts: Array<{ type: 'duplicate_server_name'; with: string[]; name?: string; port?: number }>;
  links: Obj;
  data: Obj;
}

export interface ParsedScan {
  summary: DiscoveryScanSummary;
  configFiles: Array<{ path: string; sha256: string }>;
  findings: ParsedFinding[];
  /** true when the nginx section was present and parsed (drift is computed only then) */
  nginxOk: boolean;
}

function fingerprint(parts: unknown): string {
  return sha256Hex(stableStringify(parts));
}

function confidenceOf(level: unknown, score: unknown): FindingConfidence {
  if (level === 'high' || level === 'medium' || level === 'low') return level;
  const n = num(score);
  if (n === null) return 'low';
  return n >= 0.9 ? 'high' : n >= 0.5 ? 'medium' : 'low';
}

function provenanceOf(p: unknown): ParsedFinding['provenance'] {
  if (!isObj(p)) return null;
  const chain = strs(p.includedFrom);
  return {
    file: str(p.file),
    line: num(p.line),
    includedFrom: chain[0] ?? null,
    includeChain: chain,
  };
}

function section(result: Obj, key: string): { status: string; data: Obj } | null {
  const s = result[key];
  if (!isObj(s)) return null;
  return { status: str(s.status) ?? 'unknown', data: isObj(s.data) ? s.data : {} };
}

/** Resolve a (possibly relative) nginx include to an absolute /etc/nginx path, or null if not a valid nginx path. */
export function resolveNginxInclude(p: string): string | null {
  const abs = p.startsWith('/') ? p : `/etc/nginx/${p}`;
  return nginxPathSchema.safeParse(abs).success ? abs : null;
}

export function parseScanResult(raw: unknown, requestedSources: string[]): ParsedScan {
  const result = isObj(raw) ? raw : {};
  const findings: ParsedFinding[] = [];
  const sourceStatus: Record<string, string> = {};
  for (const src of requestedSources) sourceStatus[src] = section(result, src)?.status ?? 'missing';

  // ---------------------------------------------------------------- nginx
  const nginx = section(result, 'nginx');
  const report = nginx && isObj(nginx.data.report) ? nginx.data.report : null;
  const configFiles: ParsedScan['configFiles'] = [];
  let nginxServers = 0;
  let upstreamCount = 0;
  let duplicates = 0;
  let manualReview = 0;
  const poolsBySocket = new Map<string, string>();

  const php = section(result, 'php-fpm');
  const pools = php ? arr(php.data.pools).filter(isObj) : [];
  for (const p of pools) {
    const listen = str(p.listen);
    const name = str(p.name);
    if (listen && name) poolsBySocket.set(listen.replace(/^unix:/, ''), name);
  }

  if (report) {
    for (const f of arr(report.files).filter(isObj)) {
      const path = str(f.path);
      const sha = str(f.sha256);
      if (path && sha && /^[a-f0-9]{64}$/.test(sha)) configFiles.push({ path, sha256: sha });
    }
    const servers = arr(report.servers).filter(isObj);
    const idByExternal = new Map<string, string>();
    const seen = new Set<string>();
    const dupes = arr(report.duplicates).filter(isObj);
    duplicates = dupes.length;
    for (const s of servers) {
      const ext = str(s.id);
      const id = uuidv7();
      if (ext) idByExternal.set(ext, id);
      const names = arr(s.serverNames)
        .filter(isObj)
        .map((n) => ({ kind: str(n.kind) ?? 'exact', name: str(n.name) ?? '' }))
        .filter((n) => n.name !== '');
      const listen = arr(s.listen)
        .filter(isObj)
        .map((l) => str(l.raw) ?? `${num(l.port) ?? ''}`)
        .filter((x) => x !== '');
      const prov = provenanceOf(s.provenance);
      let fp = fingerprint({
        kind: 'nginx_server',
        file: prov?.file ?? null,
        serverNames: names.map((n) => `${n.kind}:${n.name}`).sort(),
        listen: [...listen].sort(),
      });
      if (seen.has(fp)) fp = fingerprint({ fp, line: prov?.line ?? null, ext });
      seen.add(fp);
      const domains = names
        .filter((n) => n.kind === 'exact' || n.kind === 'wildcard')
        .map((n) => n.name);
      const exact = names.find((n) => n.kind === 'exact')?.name;
      const fileBase =
        (prov?.file ?? '')
          .split('/')
          .pop()
          ?.replace(/\.conf$/, '') ?? '';
      const fastcgi = strs(s.fastcgiPass);
      const proxy = strs(s.proxyPass);
      const upstreams = strs(s.upstreams);
      const unsupported = [
        ...new Set(
          arr(s.unsupportedDirectives)
            .map((u) => (isObj(u) ? str(u.name) : str(u)))
            .filter((x): x is string => !!x),
        ),
      ];
      const manual = s.manualReviewRequired === true;
      if (manual) manualReview++;
      nginxServers++;
      const socket = fastcgi[0]?.replace(/^unix:/, '');
      findings.push({
        id,
        kind: 'nginx_server',
        fingerprint: fp,
        externalId: ext,
        title: exact ?? names[0]?.name ?? (fileBase || 'nginx server'),
        domains,
        listen,
        provenance: prov,
        confidence: confidenceOf(s.confidenceLevel, s.confidence),
        manualReviewRequired: manual,
        reasons: strs(s.reasons),
        unsupportedDirectives: unsupported,
        conflicts: [],
        links: {
          upstream: upstreams[0] ?? null,
          fastcgiPass: fastcgi[0] ?? null,
          root: str(s.root),
          proxyPass: proxy[0] ?? null,
          phpFpmPool: socket ? (poolsBySocket.get(socket) ?? null) : null,
          processes: [],
        },
        data: { ...s, confidenceScore: num(s.confidence) },
      });
    }
    // duplicate server_name conflicts (cross-reference by Center ids)
    for (const d of dupes) {
      const ids = strs(d.serverIds);
      for (const ext of ids) {
        const f = findings.find((x) => x.externalId === ext && x.kind === 'nginx_server');
        if (!f) continue;
        f.conflicts.push({
          type: 'duplicate_server_name',
          with: ids
            .filter((o) => o !== ext)
            .map((o) => idByExternal.get(o))
            .filter((x): x is string => !!x),
          ...(str(d.name) ? { name: str(d.name)! } : {}),
          ...(num(d.port) !== null ? { port: num(d.port)! } : {}),
        });
      }
    }
    for (const u of arr(report.upstreams).filter(isObj)) {
      const name = str(u.name) ?? 'upstream';
      const prov = provenanceOf(u.provenance);
      upstreamCount++;
      findings.push({
        id: uuidv7(),
        kind: 'upstream',
        fingerprint: fingerprint({ kind: 'upstream', file: prov?.file ?? null, name }),
        externalId: null,
        title: name,
        domains: [],
        listen: [],
        provenance: prov,
        confidence: 'high',
        manualReviewRequired: false,
        reasons: [],
        unsupportedDirectives: [],
        conflicts: [],
        links: { upstream: name, fastcgiPass: null, root: null, proxyPass: null, processes: [] },
        data: u,
      });
    }
  }

  // ---------------------------------------------------------------- php-fpm
  for (const p of pools) {
    const name = str(p.name) ?? 'pool';
    const file = str(p.file);
    findings.push(
      simple(
        'php_fpm_pool',
        { file, name },
        `${name}${p.phpVersion ? ` (php ${String(p.phpVersion)})` : ''}`,
        {
          listen: str(p.listen) ? [str(p.listen)!] : [],
          provenance: file ? { file, line: null, includedFrom: null, includeChain: [] } : null,
          data: p,
        },
      ),
    );
  }

  // ---------------------------------------------------------------- ports
  const ports = section(result, 'ports');
  const listeners = ports ? arr(ports.data.listeners).filter(isObj) : [];
  for (const l of listeners) {
    const proto = str(l.proto) ?? 'tcp';
    const address = str(l.address) ?? '*';
    const port = num(l.port);
    const proc = str(l.process);
    findings.push(
      simple(
        'listener',
        { proto, address, port },
        `${proto} ${address}:${port ?? '?'}${proc ? ` (${proc})` : ''}`,
        { listen: [`${address}:${port ?? ''}`], data: l },
      ),
    );
  }

  // ---------------------------------------------------------------- docker / systemd
  const docker = section(result, 'docker');
  const containers = docker ? arr(docker.data.containers).filter(isObj) : [];
  for (const c of containers) {
    const name = strs(c.names)[0]?.replace(/^\//, '') ?? str(c.id) ?? 'container';
    findings.push(simple('container', { name }, name, { data: c }));
  }
  const systemd = section(result, 'systemd');
  const units = systemd ? arr(systemd.data.units).filter(isObj).slice(0, 2000) : [];
  for (const u of units) {
    const unit = str(u.unit) ?? 'unit';
    findings.push(simple('systemd_unit', { unit }, unit, { data: u }));
  }

  return {
    nginxOk: !!report,
    configFiles,
    findings,
    summary: {
      nginxServers,
      upstreams: upstreamCount,
      duplicates,
      manualReview,
      phpFpmPools: pools.length,
      listeners: listeners.length,
      containers: containers.length,
      systemdUnits: units.length,
      sourceStatus,
    },
  };
}

function simple(
  kind: FindingKind,
  identity: Obj,
  title: string,
  extra: Partial<Pick<ParsedFinding, 'listen' | 'provenance' | 'data'>>,
): ParsedFinding {
  return {
    id: uuidv7(),
    kind,
    fingerprint: fingerprint({ kind, ...identity }),
    externalId: null,
    title,
    domains: [],
    listen: extra.listen ?? [],
    provenance: extra.provenance ?? null,
    confidence: 'high',
    manualReviewRequired: false,
    reasons: [],
    unsupportedDirectives: [],
    conflicts: [],
    links: { upstream: null, fastcgiPass: null, root: null, proxyPass: null, processes: [] },
    data: extra.data ?? {},
  };
}

/** Application kind from an nginx_server finding's links (never guessed beyond what nginx config says). */
export function applicationKindOf(links: Obj): ApplicationKind {
  if (links.fastcgiPass) return 'nginx_php';
  if (links.proxyPass) return 'nginx_proxy';
  if (links.root) return 'nginx_static';
  return 'unknown';
}

/** DNS-ish slug usable as a path segment under /etc/nginx/ppanel-managed/<name>/. */
export function slugify(s: string): string {
  const out = s
    .toLowerCase()
    .replace(/^\*\./, 'wildcard-')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/, '');
  return out || 'app';
}
