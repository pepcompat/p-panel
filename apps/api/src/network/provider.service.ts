import { Inject, Injectable } from '@nestjs/common';
import {
  type CreateProviderIntegrationInput,
  DEFAULT_DO_API_BASE,
  ERROR_CODES,
  type ProviderIntegration,
  type ProviderStatus,
} from '@ppanel/shared-contracts';
import { Prisma, type ProviderIntegration as IntegrationRow } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import type { Resolver } from '../observability/ssrf';
import {
  checkApiBase,
  DoClient,
  type DoDroplet,
  type DoVpc,
  normalizeDroplet,
  ProviderError,
} from './do-client';

const aad = (id: string) => `provider_integration:${id}`;

/** Matching result of one sync (pure; unit-tested). */
export interface SyncMatch {
  serverId: string;
  dropletId: string;
  region: string | null;
  vpcUuid: string | null;
  vpcName: string | null;
  privateIpv4: string | null;
  publicIpv4: string | null;
  matchedBy: 'droplet_id' | 'private_ipv4';
}

export interface MatchableServer {
  id: string;
  /** droplet id from the agent's provider facts (servers.provider / agent inventory row) */
  dropletId: string | null;
  privateIpv4s: string[];
}

/**
 * Droplet → server: by droplet id (agent metadata) first, then by private IPv4 — only when exactly
 * one server carries that address. A server is matched at most once.
 */
export function matchDroplets(
  droplets: DoDroplet[],
  vpcs: DoVpc[],
  servers: MatchableServer[],
): { matches: SyncMatch[]; unmatched: number } {
  const vpcName = new Map(vpcs.map((v) => [v.id, typeof v.name === 'string' ? v.name : null]));
  const byDroplet = new Map<string, string>();
  const byIp = new Map<string, string[]>();
  for (const s of servers) {
    if (s.dropletId) byDroplet.set(s.dropletId, s.id);
    for (const ip of new Set(s.privateIpv4s)) byIp.set(ip, [...(byIp.get(ip) ?? []), s.id]);
  }
  const used = new Set<string>();
  const matches: SyncMatch[] = [];
  let unmatched = 0;
  const pending: Array<NonNullable<ReturnType<typeof normalizeDroplet>>> = [];
  for (const raw of droplets) {
    const d = normalizeDroplet(raw);
    if (!d) {
      unmatched++;
      continue;
    }
    const sid = byDroplet.get(d.dropletId);
    if (sid && !used.has(sid)) {
      used.add(sid);
      matches.push({
        serverId: sid,
        ...rest(d),
        vpcName: vpcName.get(d.vpcUuid ?? '') ?? null,
        matchedBy: 'droplet_id',
      });
    } else pending.push(d);
  }
  for (const d of pending) {
    const cands = d.privateIpv4 ? (byIp.get(d.privateIpv4) ?? []) : [];
    const sid = cands.length === 1 ? cands[0]! : null;
    if (sid && !used.has(sid)) {
      used.add(sid);
      matches.push({
        serverId: sid,
        ...rest(d),
        vpcName: vpcName.get(d.vpcUuid ?? '') ?? null,
        matchedBy: 'private_ipv4',
      });
    } else unmatched++;
  }
  return { matches, unmatched };
}

function rest(d: NonNullable<ReturnType<typeof normalizeDroplet>>) {
  return {
    dropletId: d.dropletId,
    region: d.region,
    vpcUuid: d.vpcUuid,
    privateIpv4: d.privateIpv4,
    publicIpv4: d.publicIpv4,
  };
}

@Injectable()
export class ProviderService {
  private readonly running = new Map<string, Promise<void>>();
  /** test seam: DNS resolver for the provider client */
  resolver: Resolver | undefined;

  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  private view(user: AuthUser, r: IntegrationRow): ProviderIntegration {
    const manage = this.authz.can(user, 'policies.manage');
    return {
      id: r.id,
      provider: r.provider as ProviderIntegration['provider'],
      name: r.name,
      apiBase: r.apiBase,
      status: r.status as ProviderStatus,
      lastSyncAt: r.lastSyncAt?.toISOString() ?? null,
      lastError: (r.lastError as ProviderIntegration['lastError']) ?? null,
      syncInProgress: this.running.has(r.id),
      lastSyncSummary: (r.lastSyncSummary as ProviderIntegration['lastSyncSummary']) ?? null,
      createdBy: r.createdBy,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      allowedActions: manage ? ['sync', 'delete'] : [],
    };
  }

  private client(apiBase: string, token: string): DoClient {
    return new DoClient({
      apiBase,
      token,
      timeoutMs: this.config.PPANEL_PROVIDER_TIMEOUT_MS,
      // only operator-listed (lab) bases may resolve to private addresses
      allowPrivate: apiBase !== DEFAULT_DO_API_BASE,
      resolver: this.resolver,
    });
  }

  private static providerErr(e: unknown): AppError {
    if (e instanceof AppError) return e;
    if (e instanceof ProviderError) {
      const status =
        e.code === ERROR_CODES.PROVIDER_UNAVAILABLE
          ? 502
          : e.code === ERROR_CODES.PROVIDER_AUTH_FAILED
            ? 422
            : 422;
      return new AppError(
        status,
        e.code,
        e.message,
        e.httpStatus ? { httpStatus: e.httpStatus } : undefined,
      );
    }
    return new AppError(502, ERROR_CODES.PROVIDER_UNAVAILABLE, 'provider API call failed');
  }

  /** Integrations are global objects: listing and every mutation need a GLOBAL policies.manage. */
  async list(user: AuthUser): Promise<ProviderIntegration[]> {
    if (!this.authz.can(user, 'policies.manage')) throw AppError.forbidden();
    const rows = await this.prisma.providerIntegration.findMany({ orderBy: { createdAt: 'asc' } });
    return rows.map((r) => this.view(user, r));
  }

  async create(
    user: AuthUser,
    input: CreateProviderIntegrationInput,
    stepUp: string | undefined,
  ): Promise<ProviderIntegration> {
    const audit = { action: 'provider_integrations.create', targetType: 'provider_integration' };
    await this.authz.enforce(user, 'policies.manage', undefined, audit);
    this.auth.assertStepUp(user, stepUp);
    const apiBase = (() => {
      try {
        return checkApiBase(input.apiBase, this.config.doApiBases, this.config.isProduction);
      } catch (e) {
        void this.audit.record({
          actorId: user.id,
          ...audit,
          result: 'denied',
          metadata: { reason: 'api_base_not_allowed' },
        });
        throw e;
      }
    })();
    // validate the token before storing anything (GET /v2/account)
    try {
      await this.client(apiBase, input.token).get('/v2/account');
    } catch (e) {
      await this.audit.record({
        actorId: user.id,
        ...audit,
        result: 'failure',
        metadata: { reason: e instanceof ProviderError ? e.code : 'error', apiBase },
      });
      throw ProviderService.providerErr(e);
    }
    const id = uuidv7();
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const r = await tx.providerIntegration.create({
          data: {
            id,
            provider: input.provider,
            name: input.name,
            tokenEnc: encryptSecret(this.config.masterKey, input.token, aad(id)),
            apiBase,
            status: 'ok',
            createdBy: user.id,
          },
        });
        await this.audit.record(
          {
            actorId: user.id,
            ...audit,
            targetId: id,
            result: 'success',
            metadata: { provider: input.provider, name: input.name, apiBase },
          },
          tx,
        );
        return r;
      });
      return this.view(user, row);
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict('An integration with this name already exists');
      throw e;
    }
  }

  private async load(user: AuthUser, id: string, action: string): Promise<IntegrationRow> {
    await this.authz.enforce(user, 'policies.manage', undefined, {
      action,
      targetType: 'provider_integration',
      targetId: id,
    });
    const r = await this.prisma.providerIntegration.findUnique({ where: { id } });
    if (!r) throw AppError.notFound('Provider integration');
    return r;
  }

  async remove(user: AuthUser, id: string): Promise<void> {
    const r = await this.load(user, id, 'provider_integrations.delete');
    if (this.running.has(id))
      throw AppError.conflict('A sync is running', ERROR_CODES.PROVIDER_SYNC_IN_PROGRESS);
    await this.prisma.$transaction(async (tx) => {
      await tx.providerIntegration.delete({ where: { id } });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'provider_integrations.delete',
          targetType: 'provider_integration',
          targetId: id,
          result: 'success',
          metadata: { name: r.name, provider: r.provider },
        },
        tx,
      );
    });
  }

  /** 202: the sync runs in the background (`syncInProgress`, then `lastSyncAt` / `lastError`). */
  async startSync(user: AuthUser, id: string): Promise<ProviderIntegration> {
    const r = await this.load(user, id, 'provider_integrations.sync');
    if (this.running.has(id))
      throw AppError.conflict('A sync is already running', ERROR_CODES.PROVIDER_SYNC_IN_PROGRESS);
    await this.audit.record({
      actorId: user.id,
      action: 'provider_integrations.sync',
      targetType: 'provider_integration',
      targetId: id,
      result: 'success',
    });
    const p = this.sync(r).finally(() => this.running.delete(id));
    this.running.set(id, p);
    return this.view(user, r);
  }

  /** Test seam: resolves when the running sync of `id` (if any) finished. */
  async waitForSync(id: string): Promise<void> {
    await this.running.get(id);
  }

  private async sync(r: IntegrationRow): Promise<void> {
    const now = new Date();
    try {
      const token = decryptSecret(this.config.masterKey, r.tokenEnc, aad(r.id)).toString('utf8');
      const client = this.client(r.apiBase, token);
      const [droplets, vpcs] = await Promise.all([
        client.listAll<DoDroplet>('/v2/droplets', 'droplets'),
        client.listAll<DoVpc>('/v2/vpcs', 'vpcs'),
      ]);
      const servers = await this.prisma.server.findMany({
        where: { status: { not: 'revoked' } },
        select: {
          id: true,
          provider: true,
          addresses: { where: { family: 'ipv4', scope: 'private' }, select: { address: true } },
          networkInventory: {
            where: { source: 'agent' },
            select: { dropletId: true, privateIpv4: true },
          },
        },
      });
      const { matches, unmatched } = matchDroplets(
        droplets,
        vpcs,
        servers.map((s) => {
          const facts = s.provider as { dropletId?: unknown } | null;
          const agentRow = s.networkInventory[0];
          return {
            id: s.id,
            dropletId:
              (typeof facts?.dropletId === 'string' ? facts.dropletId : null) ??
              agentRow?.dropletId ??
              null,
            privateIpv4s: [
              ...s.addresses.map((a) => a.address),
              ...(agentRow?.privateIpv4 ? [agentRow.privateIpv4] : []),
            ],
          };
        }),
      );
      await this.prisma.$transaction(async (tx) => {
        for (const m of matches) {
          const data = {
            region: m.region,
            vpcUuid: m.vpcUuid,
            vpcName: m.vpcName,
            dropletId: m.dropletId,
            privateIpv4: m.privateIpv4,
            publicIpv4: m.publicIpv4,
            integrationId: r.id,
            observedAt: now,
          };
          await tx.serverNetworkInventory.upsert({
            where: { serverId_source: { serverId: m.serverId, source: 'provider' } },
            create: { id: uuidv7(), serverId: m.serverId, source: 'provider', ...data },
            update: data,
          });
        }
        await tx.providerIntegration.update({
          where: { id: r.id },
          data: {
            status: 'ok',
            lastSyncAt: now,
            lastError: Prisma.DbNull,
            lastSyncSummary: {
              droplets: droplets.length,
              vpcs: vpcs.length,
              matched: matches.length,
              unmatched,
            } as Prisma.InputJsonValue,
          },
        });
        await this.audit.record(
          {
            actorType: 'system',
            action: 'provider_integrations.synced',
            targetType: 'provider_integration',
            targetId: r.id,
            result: 'success',
            metadata: {
              droplets: droplets.length,
              vpcs: vpcs.length,
              matched: matches.length,
              unmatched,
            },
          },
          tx,
        );
      });
    } catch (e) {
      const err = ProviderService.providerErr(e);
      logger.emit('warn', 'provider sync failed', { integrationId: r.id, code: err.code });
      await this.prisma.providerIntegration
        .update({
          where: { id: r.id },
          data: { status: 'error', lastError: { code: err.code, message: err.message } },
        })
        .catch(() => undefined);
      await this.audit
        .record({
          actorType: 'system',
          action: 'provider_integrations.synced',
          targetType: 'provider_integration',
          targetId: r.id,
          result: 'failure',
          metadata: { errorCode: err.code },
        })
        .catch(() => undefined);
    }
  }
}
