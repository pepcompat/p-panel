import { Injectable, type OnModuleInit } from '@nestjs/common';
import {
  type Application,
  type CreateDiscoveryScanInput,
  DISCOVERY_SOURCES,
  type DiscoveryDriftEntry,
  type DiscoveryFinding,
  type DiscoveryScan,
  type DiscoveryScanStatus,
  type DiscoveryScanSummary,
  ERROR_CODES,
  FINDING_KINDS,
  type FindingKind,
  type ImportFindingsInput,
} from '@ppanel/shared-contracts';
import type {
  DiscoveryFinding as FindingRow,
  DiscoveryScan as ScanRow,
  Prisma,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, paginate, type ParsedQuery } from '../common/query-builder';
import type { FinishedJob } from '../jobs/job-hooks';
import { JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import type { NginxFileEntry } from '../nginx/nginx-plan';
import {
  appInclude,
  type DriftFile,
  driftFilesOf,
  enforceOnServer,
  nginxFilesOf,
} from './p3-common';
import { ApplicationsService } from './applications.service';
import { applicationKindOf, parseScanResult, slugify } from './scan-parser';

const SCAN_TTL_SEC = 900;
/** revision states that are blocked when a file they touch drifted */
export const DRIFT_BLOCKABLE = ['draft', 'valid', 'awaiting_approval', 'approved'];

function toScan(r: ScanRow): DiscoveryScan {
  return {
    id: r.id,
    serverId: r.serverId,
    jobId: r.jobId,
    status: r.status as DiscoveryScanStatus,
    sources: r.sources as DiscoveryScan['sources'],
    requestedBy: r.requestedBy,
    startedAt: r.startedAt.toISOString(),
    completedAt: r.completedAt?.toISOString() ?? null,
    summary: (r.summary as DiscoveryScanSummary | null) ?? null,
    configFiles: (r.configFiles as DiscoveryScan['configFiles']) ?? [],
    drift: (r.drift as unknown as DiscoveryDriftEntry[]) ?? [],
    error: (r.error as DiscoveryScan['error']) ?? null,
  };
}

function toFinding(r: FindingRow): DiscoveryFinding {
  return {
    id: r.id,
    scanId: r.scanId,
    serverId: r.serverId,
    kind: r.kind as FindingKind,
    fingerprint: r.fingerprint,
    externalId: r.externalId,
    title: r.title,
    domains: r.domains,
    listen: r.listen,
    provenance: r.provenance as DiscoveryFinding['provenance'],
    confidence: r.confidence as DiscoveryFinding['confidence'],
    manualReviewRequired: r.manualReviewRequired,
    reasons: r.reasons,
    unsupportedDirectives: r.unsupportedDirectives,
    conflicts: r.conflicts as DiscoveryFinding['conflicts'],
    links: r.links as DiscoveryFinding['links'],
    applicationId: r.applicationId,
    data: r.data as Record<string, unknown>,
  };
}

@Injectable()
export class DiscoveryService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly apps: ApplicationsService,
  ) {}

  onModuleInit(): void {
    this.hooks.register('discovery.scan', (job) => this.onScanJobFinished(job));
    this.hooks.registerReconciler(() => this.reconcile());
  }

  // ---------------------------------------------------------------- scans

  async createScan(user: AuthUser, serverId: string, input: CreateDiscoveryScanInput) {
    const server = await this.prisma.server.findUnique({ where: { id: serverId } });
    if (!server) throw AppError.notFound('Server');
    await enforceOnServer(
      this.authz,
      user,
      server,
      'fleet.read',
      'nginx.read',
      { action: 'discovery_scans.create', targetType: 'server', targetId: serverId },
      'Server',
    );
    if (server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    const sources = input.sources ?? [...DISCOVERY_SOURCES];
    const scanId = uuidv7();
    const job = await this.prisma.$transaction(async (tx) => {
      const j = await this.jobs.createInternal(tx, {
        serverId,
        type: 'discovery.scan',
        params: { sources },
        actorId: user.id,
        ttlSec: SCAN_TTL_SEC,
        metadata: { scanId },
      });
      await tx.discoveryScan.create({
        data: {
          id: scanId,
          serverId,
          jobId: j.id,
          sources,
          requestedBy: user.id,
          status: 'running',
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'discovery_scans.create',
          targetType: 'discovery_scan',
          targetId: scanId,
          result: 'success',
          metadata: { serverId, jobId: j.id, sources },
        },
        tx,
      );
      return j;
    });
    this.jobs.notify(serverId);
    return { scanId, jobId: job.id };
  }

  private async loadScan(
    user: AuthUser,
    id: string,
  ): Promise<ScanRow & { server: { id: string; environment: string } }> {
    const row = await this.prisma.discoveryScan.findUnique({
      where: { id },
      include: { server: { select: { id: true, environment: true } } },
    });
    if (
      !row ||
      !this.authz.can(user, 'nginx.read', {
        serverId: row.serverId,
        environment: row.server.environment,
      })
    )
      throw AppError.notFound('Discovery scan');
    return row;
  }

  async getScan(user: AuthUser, id: string): Promise<DiscoveryScan> {
    let row = await this.loadScan(user, id);
    if (row.status === 'running') {
      await this.reconcileScan(row);
      row = await this.loadScan(user, id);
    }
    return toScan(row);
  }

  async listScans(user: AuthUser, pq: ParsedQuery) {
    const scope = this.authz.serverWhere(user, 'nginx.read');
    if (!scope) throw AppError.forbidden();
    const where: Prisma.DiscoveryScanWhereInput = {
      AND: [
        { server: scope },
        buildWhere(pq, {
          server_id: { prop: 'serverId', type: 'uuid' },
          status: { prop: 'status', type: 'string' },
          started_at: { prop: 'startedAt', type: 'date' },
          completed_at: { prop: 'completedAt', type: 'date' },
        }) as Prisma.DiscoveryScanWhereInput,
      ],
    };
    const sort = pq.sort === 'createdAt' ? 'startedAt' : pq.sort;
    const [total, rows] = await Promise.all([
      this.prisma.discoveryScan.count({ where }),
      this.prisma.discoveryScan.findMany({
        where,
        orderBy: [{ [sort]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(rows.map(toScan), paginate(pq, total));
  }

  async listFindings(user: AuthUser, scanId: string, pq: ParsedQuery) {
    await this.loadScan(user, scanId);
    for (const f of pq.filters)
      if (
        f.field === 'kind' &&
        !f.value.split(',').every((k) => (FINDING_KINDS as readonly string[]).includes(k))
      )
        throw AppError.badRequest(`kind must be one of: ${FINDING_KINDS.join(', ')}`);
    const where: Prisma.DiscoveryFindingWhereInput = {
      AND: [
        { scanId },
        buildWhere(pq, {
          kind: { prop: 'kind', type: 'string' },
          manual_review: { prop: 'manualReviewRequired', type: 'boolean' },
          confidence: { prop: 'confidence', type: 'string' },
          fingerprint: { prop: 'fingerprint', type: 'string' },
          application_id: { prop: 'applicationId', type: 'uuid' },
        }) as Prisma.DiscoveryFindingWhereInput,
        ...(pq.q
          ? [
              {
                OR: [
                  { title: { contains: pq.q, mode: 'insensitive' as const } },
                  { domains: { has: pq.q } },
                ],
              },
            ]
          : []),
      ],
    };
    const [total, rows] = await Promise.all([
      this.prisma.discoveryFinding.count({ where }),
      this.prisma.discoveryFinding.findMany({
        where,
        orderBy: [{ [pq.sort]: pq.order }, { id: 'asc' }],
        skip: pq.skip,
        take: pq.limit,
      }),
    ]);
    return new Paginated(rows.map(toFinding), paginate(pq, total));
  }

  // ---------------------------------------------------------------- ingest (job hook)

  private async onScanJobFinished(job: FinishedJob): Promise<void> {
    const scan = await this.prisma.discoveryScan.findUnique({ where: { jobId: job.id } });
    if (!scan || scan.status !== 'running') return;
    const truncated =
      typeof job.result === 'object' &&
      job.result !== null &&
      (job.result as { truncated?: unknown }).truncated === true;
    if (job.status === 'succeeded' && truncated) {
      // agent replayed a cached (truncated) output: never ingest a partial report as "nothing found"
      await this.prisma.discoveryScan.updateMany({
        where: { id: scan.id, status: 'running' },
        data: {
          status: 'failed',
          completedAt: new Date(),
          error: { code: 'RESULT_TRUNCATED', message: 'Agent replayed a truncated report; rescan' },
        },
      });
      return;
    }
    if (job.status === 'succeeded') {
      try {
        await this.ingest(scan, job.result);
      } catch (err) {
        logger.emit('error', 'discovery ingest failed', { scanId: scan.id, jobId: job.id, err });
        await this.prisma.discoveryScan.updateMany({
          where: { id: scan.id, status: 'running' },
          data: {
            status: 'failed',
            completedAt: new Date(),
            error: { code: 'INGEST_FAILED', message: 'Scan report could not be ingested' },
          },
        });
      }
      return;
    }
    const err = (job.error ?? {}) as { code?: string; message?: string };
    const status = job.status === 'failed' ? 'failed' : 'expired';
    const r = await this.prisma.discoveryScan.updateMany({
      where: { id: scan.id, status: 'running' },
      data: {
        status,
        completedAt: new Date(),
        error: {
          code: err.code ?? job.status.toUpperCase(),
          ...(err.message ? { message: err.message } : {}),
        },
      },
    });
    if (r.count === 1)
      await this.audit.record({
        actorType: 'system',
        action: 'discovery_scans.finish',
        targetType: 'discovery_scan',
        targetId: scan.id,
        result: 'failure',
        metadata: { status, jobStatus: job.status, errorCode: err.code },
      });
  }

  /**
   * Idempotent per job: the `running → completed` claim and all inserts share one transaction,
   * so a replayed/duplicated result never creates a second set of findings.
   */
  async ingest(scan: ScanRow, output: unknown): Promise<boolean> {
    const parsed = parseScanResult(output, scan.sources);
    return this.prisma.$transaction(
      async (tx) => {
        const claim = await tx.discoveryScan.updateMany({
          where: { id: scan.id, status: 'running' },
          data: { status: 'completed', completedAt: new Date() },
        });
        if (claim.count !== 1) return false;

        // link findings to already-imported applications (by stable fingerprint)
        const existingApps = await tx.application.findMany({
          where: { serverId: scan.serverId },
          select: { id: true, sourceFindingFingerprint: true },
        });
        const appByFp = new Map(existingApps.map((a) => [a.sourceFindingFingerprint, a.id]));
        if (parsed.findings.length > 0)
          await tx.discoveryFinding.createMany({
            data: parsed.findings.map((f) => ({
              id: f.id,
              scanId: scan.id,
              serverId: scan.serverId,
              kind: f.kind,
              fingerprint: f.fingerprint,
              externalId: f.externalId,
              title: f.title.slice(0, 500),
              domains: f.domains,
              listen: f.listen,
              provenance: (f.provenance ?? undefined) as Prisma.InputJsonValue | undefined,
              confidence: f.confidence,
              manualReviewRequired: f.manualReviewRequired,
              reasons: f.reasons,
              unsupportedDirectives: f.unsupportedDirectives,
              conflicts: f.conflicts as Prisma.InputJsonValue,
              links: f.links as Prisma.InputJsonValue,
              applicationId:
                f.kind === 'nginx_server' ? (appByFp.get(f.fingerprint) ?? null) : null,
              data: f.data as Prisma.InputJsonValue,
            })),
          });
        const linked = parsed.findings.filter(
          (f) => f.kind === 'nginx_server' && appByFp.has(f.fingerprint),
        );
        if (linked.length)
          await tx.application.updateMany({
            where: { id: { in: linked.map((f) => appByFp.get(f.fingerprint)!) } },
            data: { lastScanId: scan.id },
          });

        const drift = parsed.nginxOk ? await this.computeDrift(tx, scan, parsed.configFiles) : [];
        await tx.discoveryScan.update({
          where: { id: scan.id },
          data: {
            summary: parsed.summary as unknown as Prisma.InputJsonValue,
            configFiles: parsed.configFiles as Prisma.InputJsonValue,
            drift: drift as unknown as Prisma.InputJsonValue,
          },
        });
        await this.audit.record(
          {
            actorType: 'system',
            action: 'discovery_scans.ingest',
            targetType: 'discovery_scan',
            targetId: scan.id,
            result: 'success',
            metadata: {
              serverId: scan.serverId,
              findings: parsed.findings.length,
              nginxServers: parsed.summary.nginxServers,
              driftEntries: drift.length,
            },
          },
          tx,
        );
        return true;
      },
      { timeout: 30_000 },
    );
  }

  /** §6.4 — compare with the previous scan and with applications' lastKnownSha256. */
  private async computeDrift(
    tx: Tx,
    scan: ScanRow,
    files: Array<{ path: string; sha256: string }>,
  ): Promise<DiscoveryDriftEntry[]> {
    const current = new Map(files.map((f) => [f.path, f.sha256]));
    const prev = await tx.discoveryScan.findFirst({
      where: {
        serverId: scan.serverId,
        status: 'completed',
        id: { not: scan.id },
        NOT: { configFiles: { equals: [] } },
      },
      orderBy: { completedAt: 'desc' },
    });
    // revisions edit the real file (sites-available) while nginx -T reports the include path (sites-enabled symlink)
    const aliasRows = await tx.application.findMany({
      where: { serverId: scan.serverId },
      select: { nginxFiles: true },
    });
    const aliases = new Map<string, Set<string>>();
    for (const a of aliasRows)
      for (const f of nginxFilesOf(a))
        if (f.resolvedPath) {
          if (!aliases.has(f.resolvedPath)) aliases.set(f.resolvedPath, new Set());
          aliases.get(f.resolvedPath)!.add(f.path);
        }
    // revisions that produced a given checksum on a path (applied → after, reverted → before)
    const revisions = await tx.nginxConfigRevision.findMany({
      where: { serverId: scan.serverId, status: { in: ['applied', 'superseded', 'reverted'] } },
      orderBy: { updatedAt: 'desc' },
      select: { id: true, status: true, files: true },
    });
    const producedBy = (path: string, sha: string): string | null => {
      for (const r of revisions) {
        for (const f of r.files as Array<{
          path: string;
          beforeSha256: string | null;
          afterSha256: string;
        }>) {
          if (f.path !== path && !aliases.get(f.path)?.has(path)) continue;
          const result = r.status === 'reverted' ? f.beforeSha256 : f.afterSha256;
          if (result === sha) return r.id;
        }
      }
      return null;
    };

    const entries: DiscoveryDriftEntry[] = [];
    if (prev) {
      const before = new Map(
        (prev.configFiles as Array<{ path: string; sha256: string }>).map((f) => [
          f.path,
          f.sha256,
        ]),
      );
      for (const [path, sha] of current) {
        const was = before.get(path);
        if (was === sha) continue;
        const revisionId = producedBy(path, sha);
        entries.push({
          path,
          previousSha256: was ?? null,
          currentSha256: sha,
          changedBy: revisionId ? 'ppanel_revision' : 'external',
          revisionId,
        });
      }
    }

    // per application: on-host checksum vs accepted baseline (lastKnownSha256, updated by applied/reverted revisions)
    const apps = await tx.application.findMany({ where: { serverId: scan.serverId } });
    for (const app of apps) {
      const drifted: DriftFile[] = [];
      for (const f of nginxFilesOf(app)) {
        if (f.lastKnownSha256 === null) continue;
        const cur = current.get(f.path);
        if (cur === undefined || cur === f.lastKnownSha256) continue;
        drifted.push({ path: f.path, lastKnownSha256: f.lastKnownSha256, currentSha256: cur });
        if (!entries.some((e) => e.path === f.path))
          entries.push({
            path: f.path,
            previousSha256: f.lastKnownSha256,
            currentSha256: cur,
            changedBy: 'external',
            revisionId: null,
          });
      }
      if (drifted.length === 0) continue;
      await this.flagDrift(tx, app.id, drifted, { source: 'scan', scanId: scan.id });
    }
    return entries;
  }

  /** Mark an application drifted and block open revisions that touch a drifted file. Used by scan + agent DRIFT_DETECTED. */
  async flagDrift(
    tx: Tx,
    applicationId: string,
    drifted: DriftFile[],
    meta: Record<string, unknown>,
  ): Promise<void> {
    const app = await tx.application.findUniqueOrThrow({ where: { id: applicationId } });
    const merged = new Map(driftFilesOf(app).map((d) => [d.path, d]));
    const detectedAt = new Date().toISOString();
    for (const d of drifted) merged.set(d.path, { ...d, detectedAt });
    await tx.application.update({
      where: { id: applicationId },
      data: {
        flagDriftDetected: true,
        driftFiles: [...merged.values()] as unknown as Prisma.InputJsonValue,
        version: { increment: 1 },
      },
    });
    const paths = new Set(drifted.map((d) => d.path));
    const open = await tx.nginxConfigRevision.findMany({
      where: { applicationId, status: { in: DRIFT_BLOCKABLE } },
    });
    for (const r of open) {
      const touches = (r.files as Array<{ path: string }>).some((f) => paths.has(f.path));
      if (!touches) continue;
      await tx.nginxConfigRevision.update({
        where: { id: r.id },
        data: { status: 'drift_blocked', version: { increment: 1 } },
      });
      await this.audit.record(
        {
          actorType: 'system',
          action: 'nginx_revisions.drift_blocked',
          targetType: 'nginx_revision',
          targetId: r.id,
          result: 'success',
          metadata: { from: r.status, applicationId, ...meta },
        },
        tx,
      );
    }
    await this.audit.record(
      {
        actorType: 'system',
        action: 'applications.drift_detected',
        targetType: 'application',
        targetId: applicationId,
        result: 'success',
        metadata: { paths: [...paths], ...meta },
      },
      tx,
    );
  }

  // ---------------------------------------------------------------- reconcile

  private async reconcileScan(scan: ScanRow): Promise<void> {
    const job = await this.prisma.job.findUnique({ where: { id: scan.jobId } });
    if (job && this.jobs.isTerminal(job.status)) await this.jobs.dispatchFinished(job);
  }

  async reconcile(): Promise<number> {
    const stuck = await this.prisma.discoveryScan.findMany({
      where: { status: 'running' },
      take: 50,
      orderBy: { startedAt: 'asc' },
    });
    let n = 0;
    for (const s of stuck) {
      const before = s.status;
      await this.reconcileScan(s);
      const after = await this.prisma.discoveryScan.findUnique({
        where: { id: s.id },
        select: { status: true },
      });
      if (after && after.status !== before) n++;
    }
    return n;
  }

  // ---------------------------------------------------------------- import

  async importFindings(
    user: AuthUser,
    scanId: string,
    input: ImportFindingsInput,
  ): Promise<{ applications: Application[] }> {
    const scan = await this.prisma.discoveryScan.findUnique({
      where: { id: scanId },
      include: { server: { select: { id: true, environment: true, status: true } } },
    });
    if (!scan) throw AppError.notFound('Discovery scan');
    await enforceOnServer(
      this.authz,
      user,
      scan.server,
      'nginx.read',
      'servers.operate',
      { action: 'discovery_scans.import', targetType: 'discovery_scan', targetId: scanId },
      'Discovery scan',
    );
    if (input.mode === 'adopted' || input.mode === 'managed')
      throw new AppError(
        422,
        ERROR_CODES.IMPORT_MODE_NOT_ALLOWED,
        'Import only creates discovered/observed applications; adopt/manage is a separate reviewed step',
        { allowed: ['discovered', 'observed'] },
      );
    if (input.mode !== 'discovered' && input.mode !== 'observed')
      throw AppError.validation([
        { path: 'mode', message: "mode must be 'discovered' or 'observed'" },
      ]);
    if (scan.status !== 'completed')
      throw AppError.conflict(`Scan is ${scan.status}`, ERROR_CODES.SCAN_NOT_COMPLETED);
    if (scan.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);

    const ids = [...new Set(input.findingIds)];
    const findings = await this.prisma.discoveryFinding.findMany({
      where: { scanId, id: { in: ids } },
    });
    const missing = ids.filter((id) => !findings.some((f) => f.id === id));
    const wrongKind = findings.filter((f) => f.kind !== 'nginx_server').map((f) => f.id);
    if (missing.length || wrongKind.length)
      throw AppError.validation([
        ...missing.map((id) => ({
          path: 'findingIds',
          message: `finding ${id} is not part of this scan`,
        })),
        ...wrongKind.map((id) => ({
          path: 'findingIds',
          message: `finding ${id} is not an nginx_server finding`,
        })),
      ]);
    const shaByPath = new Map(
      (scan.configFiles as Array<{ path: string; sha256: string }>).map((f) => [f.path, f.sha256]),
    );

    const run = () =>
      this.prisma.$transaction(async (tx) => {
        const out: string[] = [];
        for (const f of findings)
          out.push(
            await this.importOne(
              tx,
              user,
              scan,
              f,
              input.mode as 'discovered' | 'observed',
              shaByPath,
            ),
          );
        return out;
      });
    let appIds: string[];
    try {
      appIds = await run();
    } catch (e) {
      if (!isUniqueViolation(e)) throw e;
      appIds = await run(); // concurrent import of the same fingerprint → retry resolves to update path
    }
    const rows = await this.prisma.application.findMany({
      where: { id: { in: appIds } },
      include: appInclude,
    });
    const views = await this.apps.views(user, rows);
    return { applications: appIds.map((id) => views.find((v) => v.id === id)!).filter(Boolean) };
  }

  private async importOne(
    tx: Tx,
    user: AuthUser,
    scan: ScanRow,
    f: FindingRow,
    mode: 'discovered' | 'observed',
    shaByPath: Map<string, string>,
  ): Promise<string> {
    const prov = f.provenance as { file?: string | null } | null;
    const links = f.links as Record<string, unknown>;
    const flags = {
      flagUnsupported: f.unsupportedDirectives.length > 0,
      flagConflict: Array.isArray(f.conflicts) && (f.conflicts as unknown[]).length > 0,
      flagManualReview: f.manualReviewRequired,
      reasons: f.reasons,
      unsupportedDirectives: f.unsupportedDirectives,
    };
    // Only the server block's own file is attributed to the application; shared includes are not.
    const files: NginxFileEntry[] = prov?.file
      ? [{ path: prov.file, lastKnownSha256: shaByPath.get(prov.file) ?? null }]
      : [];
    const existing = await tx.application.findUnique({
      where: {
        serverId_sourceFindingFingerprint: {
          serverId: scan.serverId,
          sourceFindingFingerprint: f.fingerprint,
        },
      },
    });
    if (existing) {
      // re-import: refresh metadata + lastScanId, add newly attributed files; NEVER change ownership or baselines
      const known = nginxFilesOf(existing);
      const merged = [...known, ...files.filter((x) => !known.some((k) => k.path === x.path))];
      await tx.application.update({
        where: { id: existing.id },
        data: {
          ...flags,
          domains: f.domains,
          kind: applicationKindOf(links),
          lastScanId: scan.id,
          nginxFiles: merged as unknown as Prisma.InputJsonValue,
          version: { increment: 1 },
        },
      });
      await tx.discoveryFinding.update({
        where: { id: f.id },
        data: { applicationId: existing.id },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'applications.reimport',
          targetType: 'application',
          targetId: existing.id,
          result: 'success',
          metadata: { scanId: scan.id, findingId: f.id, ownershipMode: existing.ownershipMode },
        },
        tx,
      );
      return existing.id;
    }
    const base = slugify(f.domains.find((d) => !d.startsWith('*')) ?? f.title);
    let name = base;
    for (
      let i = 2;
      await tx.application.findUnique({
        where: { serverId_name: { serverId: scan.serverId, name } },
      });
      i++
    )
      name = `${base.slice(0, 58)}-${i}`;
    const id = uuidv7();
    await tx.application.create({
      data: {
        id,
        serverId: scan.serverId,
        name,
        kind: applicationKindOf(links),
        domains: f.domains,
        ownershipMode: mode,
        ...flags,
        sourceFindingFingerprint: f.fingerprint,
        nginxFiles: files as unknown as Prisma.InputJsonValue,
        lastScanId: scan.id,
      },
    });
    await tx.discoveryFinding.update({ where: { id: f.id }, data: { applicationId: id } });
    await this.audit.record(
      {
        actorId: user.id,
        action: 'applications.import',
        targetType: 'application',
        targetId: id,
        result: 'success',
        diff: { mode, fingerprint: f.fingerprint },
        metadata: { scanId: scan.id, findingId: f.id, mode, name },
      },
      tx,
    );
    return id;
  }
}
