import { Inject, Injectable } from '@nestjs/common';
import {
  type AgentSecretsResponse,
  ENV_KEY_RE,
  ERROR_CODES,
  REGISTRY_AUTH_SECRET_KEY,
  type RegistryAuthInput,
  type RegistryAuthView,
  type SecretSummary,
} from '@ppanel/shared-contracts';
import type { ContainerApp, Job as JobRow } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret, safeEqual, sha256Hex } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { ApplicationsService } from '../discovery/applications.service';
import { type AppWithServer, serverScope } from '../discovery/p3-common';

export interface ContainerAppRef {
  app: AppWithServer;
  container: ContainerApp;
}

interface StoredRegistryAuth {
  serveraddress: string;
  username: string;
  password: string;
}

/** Loads a visible application and requires it to be a container app. */
export async function loadContainerApp(
  apps: ApplicationsService,
  prisma: PrismaService,
  user: AuthUser,
  id: string,
): Promise<ContainerAppRef> {
  const app = await apps.load(user, id);
  if (app.kind !== 'container')
    throw AppError.conflict('Not a container application', ERROR_CODES.NOT_CONTAINER_APP);
  const container = await prisma.containerApp.findUniqueOrThrow({ where: { applicationId: id } });
  return { app, container };
}

/**
 * Application secrets (§7.2). Values are encrypted with AES-256-GCM (PPANEL_MASTER_KEY, AAD binds
 * the ciphertext to `applicationId:key`), never returned by any endpoint, never put into job
 * params/results, audit rows or logs. The agent fetches them once per run job over mTLS.
 */
@Injectable()
export class SecretsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly apps: ApplicationsService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  private aad(appId: string, key: string): string {
    return `secret:${appId}:${key}`;
  }

  private encrypt(appId: string, key: string, value: string): string {
    return encryptSecret(this.config.masterKey, value, this.aad(appId, key));
  }

  private decrypt(appId: string, key: string, envelope: string): string {
    return decryptSecret(this.config.masterKey, envelope, this.aad(appId, key)).toString('utf8');
  }

  private async writable(user: AuthUser, appId: string, action: string, stepUp?: string) {
    const ref = await loadContainerApp(this.apps, this.prisma, user, appId);
    await this.authz.enforce(user, 'apps.deploy', serverScope(ref.app.server), {
      action,
      targetType: 'application',
      targetId: appId,
    });
    if (ref.app.server.status === 'revoked')
      throw AppError.conflict('Server is revoked', ERROR_CODES.SERVER_REVOKED);
    if (ref.app.server.environment === 'production') this.auth.assertStepUp(user, stepUp);
    return ref;
  }

  private assertKey(key: string): void {
    if (key === REGISTRY_AUTH_SECRET_KEY)
      throw new AppError(
        422,
        ERROR_CODES.SECRET_KEY_RESERVED,
        `${REGISTRY_AUTH_SECRET_KEY} is managed through /registry-auth`,
      );
    if (!ENV_KEY_RE.test(key))
      throw AppError.validation(
        [{ path: 'key', message: 'key must match ^[A-Z_][A-Z0-9_]{0,63}$' }],
        'Invalid secret key',
      );
  }

  // ---------------------------------------------------------------- user API

  async list(user: AuthUser, appId: string): Promise<SecretSummary[]> {
    await loadContainerApp(this.apps, this.prisma, user, appId);
    const rows = await this.prisma.secret.findMany({
      where: { applicationId: appId, key: { not: REGISTRY_AUTH_SECRET_KEY } },
      orderBy: { key: 'asc' },
      select: { key: true, version: true, updatedAt: true },
    });
    return rows.map((r) => ({
      key: r.key,
      set: true as const,
      version: r.version,
      updatedAt: r.updatedAt.toISOString(),
    }));
  }

  async put(user: AuthUser, appId: string, key: string, value: string, stepUp?: string) {
    this.assertKey(key);
    await this.writable(user, appId, 'secrets.set', stepUp);
    return this.store(user, appId, key, value, 'secrets.set');
  }

  private async store(
    user: AuthUser,
    appId: string,
    key: string,
    value: string,
    action: string,
    metadata: Record<string, unknown> = {},
  ): Promise<{ key: string; set: true; version: number }> {
    const enc = this.encrypt(appId, key, value);
    const row = await this.prisma.$transaction(async (tx) => {
      const r = await tx.secret.upsert({
        where: { applicationId_key: { applicationId: appId, key } },
        create: {
          id: uuidv7(),
          applicationId: appId,
          key,
          valueEncrypted: enc,
          createdBy: user.id,
          updatedBy: user.id,
        },
        update: { valueEncrypted: enc, version: { increment: 1 }, updatedBy: user.id },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action,
          targetType: 'application',
          targetId: appId,
          result: 'success',
          // only key + version are hashed/recorded — never the value or a hash of it
          diff: { key, version: r.version },
          metadata: { key, version: r.version, ...metadata },
        },
        tx,
      );
      return r;
    });
    return { key, set: true, version: row.version };
  }

  async remove(user: AuthUser, appId: string, key: string, stepUp?: string): Promise<void> {
    this.assertKey(key);
    await this.writable(user, appId, 'secrets.delete', stepUp);
    const r = await this.prisma.secret.deleteMany({ where: { applicationId: appId, key } });
    if (r.count === 0) throw AppError.notFound('Secret');
    await this.audit.record({
      actorId: user.id,
      action: 'secrets.delete',
      targetType: 'application',
      targetId: appId,
      result: 'success',
      metadata: { key },
    });
  }

  async putRegistryAuth(user: AuthUser, appId: string, input: RegistryAuthInput, stepUp?: string) {
    await this.writable(user, appId, 'secrets.registry_auth_set', stepUp);
    const r = await this.store(
      user,
      appId,
      REGISTRY_AUTH_SECRET_KEY,
      JSON.stringify(input satisfies StoredRegistryAuth),
      'secrets.registry_auth_set',
      { serveraddress: input.serveraddress, username: input.username },
    );
    return {
      serveraddress: input.serveraddress,
      username: input.username,
      set: true,
      version: r.version,
    };
  }

  async getRegistryAuth(user: AuthUser, appId: string): Promise<RegistryAuthView> {
    await loadContainerApp(this.apps, this.prisma, user, appId);
    const row = await this.prisma.secret.findUnique({
      where: { applicationId_key: { applicationId: appId, key: REGISTRY_AUTH_SECRET_KEY } },
    });
    if (!row) return { serveraddress: null, username: null, set: false };
    const v = this.registryFromRow(appId, row.valueEncrypted);
    return {
      serveraddress: v?.serveraddress ?? null,
      username: v?.username ?? null,
      set: true,
      version: row.version,
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  async removeRegistryAuth(user: AuthUser, appId: string, stepUp?: string): Promise<void> {
    await this.writable(user, appId, 'secrets.registry_auth_delete', stepUp);
    const r = await this.prisma.secret.deleteMany({
      where: { applicationId: appId, key: REGISTRY_AUTH_SECRET_KEY },
    });
    if (r.count === 0) throw AppError.notFound('Registry credential');
    await this.audit.record({
      actorId: user.id,
      action: 'secrets.registry_auth_delete',
      targetType: 'application',
      targetId: appId,
      result: 'success',
    });
  }

  // ---------------------------------------------------------------- internal

  private registryFromRow(appId: string, envelope: string): StoredRegistryAuth | null {
    try {
      return JSON.parse(
        this.decrypt(appId, REGISTRY_AUTH_SECRET_KEY, envelope),
      ) as StoredRegistryAuth;
    } catch (err) {
      logger.emit('error', 'registry credential undecryptable', { applicationId: appId, err });
      return null;
    }
  }

  async registryCredential(appId: string): Promise<StoredRegistryAuth | null> {
    const row = await this.prisma.secret.findUnique({
      where: { applicationId_key: { applicationId: appId, key: REGISTRY_AUTH_SECRET_KEY } },
    });
    return row ? this.registryFromRow(appId, row.valueEncrypted) : null;
  }

  /** Set keys (excluding the registry credential) and their versions — used for preflight + planHash. */
  async keyVersions(
    appId: string,
  ): Promise<{ versions: Record<string, number>; registry: boolean }> {
    const rows = await this.prisma.secret.findMany({
      where: { applicationId: appId },
      select: { key: true, version: true },
    });
    const versions: Record<string, number> = {};
    let registry = false;
    for (const r of rows) {
      if (r.key === REGISTRY_AUTH_SECRET_KEY) registry = true;
      else versions[r.key] = r.version;
    }
    return { versions, registry };
  }

  /** Decrypted values of all secrets of an app (for redaction only — never returned). */
  async knownValues(appId: string): Promise<string[]> {
    const rows = await this.prisma.secret.findMany({ where: { applicationId: appId } });
    const out: string[] = [];
    for (const r of rows) {
      try {
        if (r.key === REGISTRY_AUTH_SECRET_KEY) {
          const v = this.registryFromRow(appId, r.valueEncrypted);
          if (v) out.push(v.password);
        } else out.push(this.decrypt(appId, r.key, r.valueEncrypted));
      } catch {
        /* undecryptable rows cannot leak either */
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- agent fetch-once (mTLS gateway)

  /**
   * `POST /agent/v1/tasks/:jobId/secrets`: only for a leased/running, unexpired
   * `container.run_candidate` job of the calling server with a matching lease token; values are
   * delivered exactly once (`jobs.secrets_fetched_at` is set with a conditional update).
   */
  async fetchForJob(
    serverId: string,
    jobId: string,
    leaseToken: string,
  ): Promise<AgentSecretsResponse> {
    const now = new Date();
    const job = await this.prisma.job.findFirst({ where: { id: jobId, serverId } });
    const tokenOk = !!job?.leaseTokenHash && safeEqual(job.leaseTokenHash, sha256Hex(leaseToken));
    const deny = async (code: string, status: number, message: string, reason: string) => {
      await this.audit.record({
        actorId: serverId,
        actorType: 'agent',
        action: 'secrets.delivered',
        targetType: 'job',
        targetId: jobId,
        result: 'denied',
        metadata: { reason },
      });
      return new AppError(status, code, message);
    };
    if (!job || !tokenOk)
      throw await deny(
        ERROR_CODES.TASK_NOT_LEASED,
        409,
        'Task is not leased to this agent',
        'not_leased',
      );
    if (job.type !== 'container.run_candidate')
      throw await deny(
        ERROR_CODES.FORBIDDEN,
        403,
        'Secrets are only delivered to container.run_candidate tasks',
        'wrong_job_type',
      );
    if (job.status !== 'leased' && job.status !== 'running')
      throw await deny(
        ERROR_CODES.TASK_NOT_LEASED,
        409,
        'Task is not leased to this agent',
        `status_${job.status}`,
      );
    if ((job.leaseUntil && job.leaseUntil <= now) || job.expiresAt <= now)
      throw await deny(ERROR_CODES.TASK_EXPIRED, 409, 'Task lease or TTL expired', 'expired');
    const step = await this.prisma.deploymentStep.findFirst({
      where: { jobId, name: 'pull_start' },
      include: { deployment: { select: { id: true, applicationId: true, serverId: true } } },
    });
    if (!step || step.deployment.serverId !== serverId)
      throw await deny(ERROR_CODES.TASK_NOT_LEASED, 409, 'Task has no deployment', 'no_deployment');
    const claimed = await this.prisma.job.updateMany({
      where: { id: jobId, serverId, secretsFetchedAt: null },
      data: { secretsFetchedAt: now },
    });
    if (claimed.count !== 1)
      throw await deny(
        ERROR_CODES.SECRETS_ALREADY_FETCHED,
        409,
        'Secrets for this task were already delivered',
        'already_fetched',
      );
    return this.deliver(serverId, job, step.deployment.applicationId, step.deployment.id);
  }

  private async deliver(
    serverId: string,
    job: JobRow,
    appId: string,
    deploymentId: string,
  ): Promise<AgentSecretsResponse> {
    const params = job.params as { secretEnvKeys?: string[]; registryAuth?: boolean };
    const wanted = new Set(params.secretEnvKeys ?? []);
    const rows = await this.prisma.secret.findMany({ where: { applicationId: appId } });
    const env: Record<string, string> = {};
    let registryAuth: AgentSecretsResponse['registryAuth'];
    for (const r of rows) {
      if (r.key === REGISTRY_AUTH_SECRET_KEY) {
        if (params.registryAuth) {
          const v = this.registryFromRow(appId, r.valueEncrypted);
          if (v) registryAuth = v;
        }
      } else if (wanted.has(r.key)) {
        try {
          env[r.key] = this.decrypt(appId, r.key, r.valueEncrypted);
        } catch (err) {
          logger.emit('error', 'secret undecryptable', { applicationId: appId, key: r.key, err });
        }
      }
    }
    const delivered = Object.keys(env).sort();
    await this.audit.record({
      actorId: serverId,
      actorType: 'agent',
      action: 'secrets.delivered',
      targetType: 'deployment',
      targetId: deploymentId,
      result: 'success',
      metadata: {
        jobId: job.id,
        applicationId: appId,
        keys: delivered,
        missing: [...wanted].filter((k) => !(k in env)).sort(),
        registryAuth: !!registryAuth,
      },
    });
    return registryAuth ? { env, registryAuth } : { env };
  }
}
