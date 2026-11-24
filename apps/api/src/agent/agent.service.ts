import { Inject, Injectable } from '@nestjs/common';
import {
  type AgentEnrollInput,
  type AgentEnrollResponse,
  type ConnectionPolicy,
  ERROR_CODES,
  HEARTBEAT_INTERVAL_SEC,
  type HeartbeatInput,
  type HeartbeatResponse,
} from '@ppanel/shared-contracts';
import { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AppError } from '../common/app-error';
import { sha256Hex } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import { RateLimiter } from '../common/rate-limiter';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { JobsService } from '../jobs/jobs.service';
import { CaService, normalizeSerial } from '../pki/ca.service';
import { TelemetryService } from '../observability/telemetry.service';
import { agentProviderJson, upsertAgentInventory } from '../network/network-common';

export interface AgentIdentity {
  serverId: string;
  certId: string;
  serial: string;
  notBefore: Date;
  notAfter: Date;
  /** P9: the server's connection policy at request time (gateway path enforcement) */
  connectionPolicy: ConnectionPolicy;
}

const DEGRADED_PCT = 95;

@Injectable()
export class AgentService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly ca: CaService,
    private readonly audit: AuditService,
    private readonly limiter: RateLimiter,
    private readonly jobs: JobsService,
    private readonly telemetry: TelemetryService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /**
   * Public enrollment. Token is consumed atomically (`UPDATE … WHERE used_at IS NULL AND expires_at > now`)
   * in the same transaction that creates the server and its certificate. Unknown / used / expired tokens
   * all return the same 401 ENROLLMENT_TOKEN_INVALID (no oracle).
   */
  async enroll(input: AgentEnrollInput, ip: string | undefined): Promise<AgentEnrollResponse> {
    this.limiter.hit(`enroll:${ip ?? '-'}`, 10, 60_000);
    const csr = await this.ca.parseCsr(input.csrPem); // validate before consuming the token
    const tokenHash = sha256Hex(input.token);
    const now = new Date();
    const result = await this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<
        Array<{ id: string; name: string; environment: string; tags: string[] }>
      >`
        UPDATE agent_enrollments
           SET used_at = ${now}
         WHERE token_hash = ${tokenHash}
           AND used_at IS NULL
           AND expires_at > ${now}
     RETURNING id, name, environment, tags`;
      const enrollment = rows[0];
      if (!enrollment) return null;
      const serverId = uuidv7();
      await tx.server.create({
        data: {
          id: serverId,
          name: enrollment.name,
          hostname: input.hostname,
          environment: enrollment.environment,
          tags: enrollment.tags,
          status: 'enrolling',
          os: (input.facts?.os ?? undefined) as Prisma.InputJsonValue | undefined,
          provider: agentProviderJson(input.facts?.provider ?? null),
          ...(input.facts?.ssh ? { sshFacts: input.facts.ssh as Prisma.InputJsonValue } : {}),
          agentVersion: input.facts?.agentVersion ?? null,
          enrollmentId: enrollment.id,
        },
      });
      await tx.agentEnrollment.update({ where: { id: enrollment.id }, data: { serverId } });
      if (input.facts?.provider)
        await upsertAgentInventory(tx, serverId, input.facts.provider, now);
      const cert = await this.ca.issueAgentCert(csr, serverId);
      await tx.agentCertificate.create({
        data: {
          id: uuidv7(),
          serverId,
          serial: cert.serial,
          fingerprintSha256: cert.fingerprintSha256,
          certPem: cert.certPem,
          notBefore: cert.notBefore,
          notAfter: cert.notAfter,
        },
      });
      await this.audit.record(
        {
          actorId: serverId,
          actorType: 'agent',
          action: 'agent.enroll',
          targetType: 'server',
          targetId: serverId,
          result: 'success',
          metadata: { enrollmentId: enrollment.id, hostname: input.hostname, serial: cert.serial },
        },
        tx,
      );
      return { serverId, cert };
    });
    if (!result) {
      await this.audit.record({
        actorType: 'anonymous',
        action: 'agent.enroll',
        targetType: 'enrollment',
        result: 'denied',
      });
      throw AppError.unauthenticated(
        'Enrollment token is invalid or expired',
        ERROR_CODES.ENROLLMENT_TOKEN_INVALID,
      );
    }
    return {
      serverId: result.serverId,
      certificatePem: result.cert.certPem,
      caPem: this.ca.caPem,
      gatewayUrl: this.config.PPANEL_PUBLIC_GATEWAY_URL,
      gatewayEndpoints: this.config.gatewayEndpoints,
      heartbeatIntervalSec: HEARTBEAT_INTERVAL_SEC,
    };
  }

  /** Post-handshake check: serial known, not revoked/expired, server not revoked, CN matches. */
  async identify(
    serialRaw: string | undefined,
    subjectCn: string | undefined,
  ): Promise<AgentIdentity> {
    const fail = () =>
      AppError.unauthenticated(
        'Agent certificate is revoked or unknown',
        ERROR_CODES.AGENT_CERT_REVOKED,
      );
    if (!serialRaw) throw fail();
    const cert = await this.prisma.agentCertificate.findUnique({
      where: { serial: normalizeSerial(serialRaw) },
      include: { server: { select: { status: true, connectionPolicy: true } } },
    });
    if (!cert || cert.revokedAt || cert.notAfter <= new Date() || cert.server.status === 'revoked')
      throw fail();
    if (subjectCn !== `agent:${cert.serverId}`) throw fail();
    return {
      serverId: cert.serverId,
      certId: cert.id,
      serial: cert.serial,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      connectionPolicy: cert.server.connectionPolicy as ConnectionPolicy,
    };
  }

  async heartbeat(id: AgentIdentity, hb: HeartbeatInput): Promise<HeartbeatResponse> {
    const now = new Date();
    // Omitted metrics are unknown → stored as null, never 0.
    const m = hb.metrics;
    const metrics = {
      cpuPct: m.cpuPct ?? null,
      memPct: m.memPct ?? null,
      diskPct: m.diskPct ?? null,
      load1: m.load1 ?? null,
      uptimeSec: m.uptimeSec ?? null,
      // P5 extension (null = unknown)
      memTotalBytes: m.memTotalBytes ?? null,
      memAvailableBytes: m.memAvailableBytes ?? null,
      diskTotalBytes: m.diskTotalBytes ?? null,
      diskFreeBytes: m.diskFreeBytes ?? null,
      netRxBytes: m.netRxBytes ?? null,
      netTxBytes: m.netTxBytes ?? null,
    };
    const degraded = [m.cpuPct, m.memPct, m.diskPct].some(
      (v) => v !== undefined && v >= DEGRADED_PCT,
    );
    const policy = await this.prisma.$transaction(async (tx) => {
      await tx.agentHeartbeat.create({
        data: {
          serverId: id.serverId,
          seq: BigInt(hb.seq),
          sentAt: new Date(hb.sentAt),
          receivedAt: now,
          agentVersion: hb.agentVersion,
          metrics: metrics as Prisma.InputJsonValue,
        },
      });
      const srv = await tx.server.update({
        where: { id: id.serverId },
        select: { connectionPolicy: true },
        data: {
          status: degraded ? 'degraded' : 'online',
          lastHeartbeatAt: now,
          lastSeq: BigInt(hb.seq),
          agentVersion: hb.agentVersion,
          metrics: metrics as Prisma.InputJsonValue,
          metricsSampledAt: new Date(Math.min(new Date(hb.sentAt).getTime(), now.getTime())),
          ...(hb.os ? { os: hb.os as Prisma.InputJsonValue } : {}),
          // P9: provider facts — null = metadata absent (cleared), undefined = not reported (kept)
          ...(hb.provider !== undefined ? { provider: agentProviderJson(hb.provider) } : {}),
          // P10: sshd host key facts — null = none readable (cleared), undefined = not reported (kept)
          ...(hb.ssh !== undefined
            ? { sshFacts: hb.ssh === null ? Prisma.DbNull : (hb.ssh as Prisma.InputJsonValue) }
            : {}),
        },
      });
      if (hb.provider !== undefined) await upsertAgentInventory(tx, id.serverId, hb.provider, now);
      if (hb.connection) await this.storeConnection(tx, id.serverId, hb.connection, now);
      // detected addresses mirror the latest report; operator overrides are untouched
      const seen = hb.addresses.map((a) => a.address);
      await tx.serverAddress.deleteMany({
        where: { serverId: id.serverId, source: 'detected', address: { notIn: seen } },
      });
      for (const a of hb.addresses) {
        await tx.serverAddress.upsert({
          where: {
            serverId_address_source: {
              serverId: id.serverId,
              address: a.address,
              source: 'detected',
            },
          },
          create: {
            id: uuidv7(),
            serverId: id.serverId,
            family: a.family,
            scope: a.scope,
            address: a.address,
            interface: a.interface ?? null,
            source: 'detected',
          },
          update: { family: a.family, scope: a.scope, interface: a.interface ?? null },
        });
      }
      const caps = [...new Set(hb.capabilities)];
      await tx.serverCapability.deleteMany({
        where: { serverId: id.serverId, name: { notIn: caps } },
      });
      if (caps.length) {
        await tx.serverCapability.createMany({
          data: caps.map((name) => ({ serverId: id.serverId, name, detectedAt: now })),
          skipDuplicates: true,
        });
      }
      return srv.connectionPolicy as ConnectionPolicy;
    });
    await this.jobs.renewRunning(id.serverId, hb.runningJobIds);
    await this.telemetry.recordHeartbeat(id.serverId, hb, now);
    const life = id.notAfter.getTime() - id.notBefore.getTime();
    return {
      serverTime: now.toISOString(),
      heartbeatIntervalSec: HEARTBEAT_INTERVAL_SEC,
      certRenewAfter: new Date(id.notBefore.getTime() + Math.floor((life * 2) / 3)).toISOString(),
      connection: { policy, endpoints: this.config.gatewayEndpoints },
    };
  }

  /** P9: latest endpoint probe report (only advertised paths are kept; urls are informational). */
  private async storeConnection(
    tx: Prisma.TransactionClient,
    serverId: string,
    c: NonNullable<HeartbeatInput['connection']>,
    now: Date,
  ): Promise<void> {
    const endpoints = c.endpoints.map((e) => ({
      path: e.path,
      url: e.url,
      ok: e.ok,
      latencyMs: e.latencyMs ?? null,
      checkedAt: new Date(e.checkedAt).toISOString(),
      ...(e.error ? { error: e.error } : {}),
    }));
    const data = {
      activePath: c.activePath ?? null,
      endpoints: endpoints as Prisma.InputJsonValue,
      reportedAt: now,
    };
    await tx.serverConnection.upsert({
      where: { serverId },
      create: { serverId, ...data },
      update: data,
    });
  }

  /** Issues a new cert for the same server identity; the old one stays valid until expiry unless revoked. */
  async rotate(
    id: AgentIdentity,
    csrPem: string,
  ): Promise<{ certificatePem: string; notAfter: string }> {
    this.limiter.hit(`rotate:${id.serverId}`, 10, 3_600_000);
    const csr = await this.ca.parseCsr(csrPem);
    const cert = await this.ca.issueAgentCert(csr, id.serverId);
    await this.prisma.$transaction(async (tx) => {
      await tx.agentCertificate.create({
        data: {
          id: uuidv7(),
          serverId: id.serverId,
          serial: cert.serial,
          fingerprintSha256: cert.fingerprintSha256,
          certPem: cert.certPem,
          notBefore: cert.notBefore,
          notAfter: cert.notAfter,
        },
      });
      await this.audit.record(
        {
          actorId: id.serverId,
          actorType: 'agent',
          action: 'agent.certificate.rotate',
          targetType: 'server',
          targetId: id.serverId,
          result: 'success',
          metadata: { previousSerial: id.serial, serial: cert.serial },
        },
        tx,
      );
    });
    return { certificatePem: cert.certPem, notAfter: cert.notAfter.toISOString() };
  }
}
