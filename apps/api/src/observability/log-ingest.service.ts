/**
 * Gateway `POST /agent/v1/logs` (AGENT_PROTOCOL "Telemetry (P5)", API_CONTRACTS §9.3):
 * size limits (413), per-server byte budget (429 + Retry-After), batch dedupe (24 h), Center-side
 * re-redaction (shared patterns + known secret values of the server's apps), label-spoofing drop,
 * labels from Center records only, Loki push (503 when Loki is down so the agent retries).
 */
import { Inject, Injectable } from '@nestjs/common';
import {
  type AgentLogBatch,
  type AgentLogBatchResponse,
  agentLogBatchSchema,
  ERROR_CODES,
  LOG_BATCH_MAX_COMPRESSED_BYTES,
  LOG_BATCH_MAX_DECOMPRESSED_BYTES,
  LOG_LINE_MAX_BYTES,
  LOG_TRUNCATED_SUFFIX,
  redactLine,
} from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { promisify } from 'node:util';
import zlib from 'node:zlib';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { parseWith } from '../common/zod.pipe';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { SecretsService } from '../deploy/secrets.service';
import { BackendUnavailableError, LokiClient, type LokiStream, logsUnavailable } from './backends';
import { ByteBucket } from './byte-bucket';
import { isoToNs, msToNs } from './query-templates';
import { type ManagedAppRef, TelemetryService } from './telemetry.service';

const gunzip = promisify(zlib.gunzip);
const SECRETS_CACHE_MS = 10_000;
const PENDING_RETRY_SEC = 2;
const PENDING_TAKEOVER_MS = 60_000;
const MAX_AGE_NS = msToNs(7 * 86_400_000 - 3_600_000); // Loki reject_old_samples_max_age 168h
const MAX_FUTURE_NS = msToNs(5 * 60_000);

function tooLarge(message: string): AppError {
  return new AppError(413, ERROR_CODES.PAYLOAD_TOO_LARGE, message);
}

/** Reads the raw body with a hard byte cap (no body-parser: it cannot cap gzip input + output). */
export async function readLogBody(req: Request): Promise<Buffer> {
  const declared = Number(req.header('content-length') ?? NaN);
  if (Number.isFinite(declared) && declared > LOG_BATCH_MAX_COMPRESSED_BYTES)
    throw tooLarge('Log batch exceeds 1 MiB compressed');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > LOG_BATCH_MAX_COMPRESSED_BYTES) {
      req.unpipe?.();
      throw tooLarge('Log batch exceeds 1 MiB compressed');
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const enc = (req.header('content-encoding') ?? 'identity').toLowerCase().trim();
  if (enc === 'identity' || enc === '') return raw;
  if (enc !== 'gzip') throw AppError.badRequest('Content-Encoding must be gzip or identity');
  try {
    return await gunzip(raw, { maxOutputLength: LOG_BATCH_MAX_DECOMPRESSED_BYTES });
  } catch (err) {
    if ((err as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' || err instanceof RangeError)
      throw tooLarge('Log batch exceeds 8 MiB decompressed');
    throw AppError.badRequest('Malformed gzip body');
  }
}

/** Truncates to LOG_LINE_MAX_BYTES (UTF-8) including the marker, on a character boundary. */
export function truncateLine(line: string): string {
  if (Buffer.byteLength(line, 'utf8') <= LOG_LINE_MAX_BYTES) return line;
  const budget = LOG_LINE_MAX_BYTES - Buffer.byteLength(LOG_TRUNCATED_SUFFIX, 'utf8');
  const cut = Buffer.from(line, 'utf8').subarray(0, budget).toString('utf8').replace(/�$/, '');
  return cut + LOG_TRUNCATED_SUFFIX;
}

/** Container label check: known deployment name of that app, or the ownership-name shape. */
export function containerBelongs(
  container: string,
  app: ManagedAppRef,
  known: Map<string, string>,
): boolean {
  const owner = known.get(container);
  if (owner) return owner === app.id;
  const esc = app.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^ppanel-${esc}-(?:[a-z0-9][a-z0-9_.-]{0,62}-)?[0-9a-f]{8}$`).test(container);
}

@Injectable()
export class LogIngestService {
  readonly bucket: ByteBucket;
  private readonly secretsCache = new Map<string, { at: number; values: string[] }>();
  private readonly lastRejectAudit = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly telemetry: TelemetryService,
    private readonly secrets: SecretsService,
    private readonly loki: LokiClient,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {
    this.bucket = new ByteBucket(
      config.PPANEL_LOG_INGEST_RATE_BYTES,
      config.PPANEL_LOG_INGEST_BURST_BYTES,
    );
  }

  /** Known secret values of every app on the server (redaction only, cached briefly). */
  async serverSecrets(serverId: string, apps: Map<string, ManagedAppRef>): Promise<string[]> {
    const hit = this.secretsCache.get(serverId);
    if (hit && Date.now() - hit.at < SECRETS_CACHE_MS) return hit.values;
    const all = await this.prisma.application.findMany({
      where: { serverId, secrets: { some: {} } },
      select: { id: true },
    });
    const ids = new Set([...all.map((a) => a.id), ...[...apps.values()].map((a) => a.id)]);
    const values: string[] = [];
    for (const id of ids) values.push(...(await this.secrets.knownValues(id)));
    this.secretsCache.set(serverId, { at: Date.now(), values });
    return values;
  }

  invalidateSecrets(): void {
    this.secretsCache.clear();
  }

  async ingest(serverId: string, body: Buffer): Promise<AgentLogBatchResponse> {
    const budget = this.bucket.take(serverId, body.length);
    if (!budget.ok) throw AppError.rateLimited(budget.retryAfterSec);
    let json: unknown;
    try {
      json = JSON.parse(body.toString('utf8'));
    } catch {
      throw AppError.badRequest('Malformed JSON body');
    }
    const batch = parseWith(agentLogBatchSchema, json);

    // dedupe (24 h): claim the batch id; a concurrent in-flight copy → retry shortly
    const claimed = await this.prisma.$queryRaw<Array<{ batch_id: string }>>`
      INSERT INTO log_batches (server_id, batch_id, status, accepted, received_at)
      VALUES (${serverId}::uuid, ${batch.batchId}::uuid, 'pending', 0, now())
      ON CONFLICT (server_id, batch_id) DO NOTHING
      RETURNING batch_id`;
    if (claimed.length === 0) {
      const existing = await this.prisma.logBatch.findUnique({
        where: { serverId_batchId: { serverId, batchId: batch.batchId } },
      });
      if (existing?.status === 'done') return { accepted: 0, duplicate: true };
      if (existing && Date.now() - existing.receivedAt.getTime() < PENDING_TAKEOVER_MS)
        throw AppError.rateLimited(PENDING_RETRY_SEC);
      await this.prisma.logBatch.upsert({
        where: { serverId_batchId: { serverId, batchId: batch.batchId } },
        create: { serverId, batchId: batch.batchId },
        update: { receivedAt: new Date(), status: 'pending' },
      });
    }

    try {
      const res = await this.process(serverId, batch);
      await this.prisma.$transaction([
        this.prisma.logBatch.update({
          where: { serverId_batchId: { serverId, batchId: batch.batchId } },
          data: { status: 'done', accepted: res.accepted },
        }),
        this.prisma.serverTelemetry.upsert({
          where: { serverId },
          create: {
            serverId,
            acceptedTotal: BigInt(res.accepted),
            centerDroppedTotal: BigInt(res.rejected ?? 0),
            lastBatchAt: new Date(),
          },
          update: {
            acceptedTotal: { increment: BigInt(res.accepted) },
            centerDroppedTotal: { increment: BigInt(res.rejected ?? 0) },
            // agent drops are counted from the heartbeat's cumulative logShipping.droppedEntries
            // (batch `dropped` is informational only — counting both would double count)
            lastBatchAt: new Date(),
          },
        }),
      ]);
      return res;
    } catch (err) {
      // release the claim so the agent's retry is processed
      await this.prisma.logBatch
        .delete({ where: { serverId_batchId: { serverId, batchId: batch.batchId } } })
        .catch(() => undefined);
      if (err instanceof BackendUnavailableError) {
        logger.emit('warn', 'log ingest: loki unavailable', {
          component: 'observability',
          serverId,
        });
        throw logsUnavailable();
      }
      throw err;
    }
  }

  private async process(serverId: string, batch: AgentLogBatch): Promise<AgentLogBatchResponse> {
    const server = await this.prisma.server.findUnique({
      where: { id: serverId },
      select: { id: true, environment: true },
    });
    if (!server) throw AppError.notFound('Server');
    const apps = await this.telemetry.managedApps(serverId);
    const needsContainers = batch.entries.some((e) => e.container);
    const known = needsContainers
      ? await this.telemetry.knownContainerNames([...apps.values()].map((a) => a.id))
      : new Map<string, string>();
    const secrets = await this.serverSecrets(serverId, apps);
    const nowNs = msToNs(Date.now());

    const streams = new Map<string, LokiStream>();
    let accepted = 0;
    let rejected = 0;
    for (const e of batch.entries) {
      let app: ManagedAppRef | undefined;
      if (e.app) {
        app = apps.get(e.app);
        if (!app) {
          rejected++; // not a managed app of THIS server (label spoofing / stale)
          continue;
        }
      }
      if (e.container && (!app || !containerBelongs(e.container, app, known))) {
        rejected++;
        continue;
      }
      if (e.source === 'container' && !app) {
        rejected++;
        continue;
      }
      let ns: bigint;
      try {
        ns = isoToNs(e.ts);
      } catch {
        rejected++;
        continue;
      }
      if (ns < nowNs - MAX_AGE_NS || ns > nowNs + MAX_FUTURE_NS) {
        rejected++;
        continue;
      }
      const labels: Record<string, string> = {
        server_id: server.id,
        environment: server.environment,
        source: e.source,
      };
      if (app) labels.app_id = app.id;
      if (e.level) labels.level = e.level;
      const key = JSON.stringify(labels);
      let s = streams.get(key);
      if (!s) streams.set(key, (s = { stream: labels, values: [] }));
      // defence in depth: the agent already redacted; the Center redacts again incl. known values
      s.values.push([ns.toString(), truncateLine(redactLine(e.line, secrets))]);
      accepted++;
    }
    for (const s of streams.values())
      s.values.sort((a, b) =>
        BigInt(a[0]) < BigInt(b[0]) ? -1 : BigInt(a[0]) > BigInt(b[0]) ? 1 : 0,
      );

    if (accepted > 0) {
      const res = await this.loki.push([...streams.values()]);
      if (!res.ok) {
        rejected += accepted;
        accepted = 0;
      }
    }
    if (rejected > 0) await this.auditRejected(serverId, rejected);
    return { accepted, duplicate: false, rejected };
  }

  /** At most one audit row per server per minute for dropped/spoofed entries (counts only). */
  private async auditRejected(serverId: string, count: number): Promise<void> {
    const last = this.lastRejectAudit.get(serverId) ?? 0;
    if (Date.now() - last < 60_000) return;
    this.lastRejectAudit.set(serverId, Date.now());
    await this.audit.record({
      actorId: serverId,
      actorType: 'agent',
      action: 'logs.ingest.rejected',
      targetType: 'server',
      targetId: serverId,
      result: 'denied',
      metadata: { rejected: count },
    });
  }
}
