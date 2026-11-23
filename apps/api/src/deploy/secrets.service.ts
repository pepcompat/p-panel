import { Inject, Injectable } from '@nestjs/common';
import {
  type AgentSecretsResponse,
  ENV_KEY_RE,
  ERROR_CODES,
  GIT_TOKEN_SECRET_KEY,
  gitAuthHeader,
  REGISTRY_AUTH_SECRET_KEY,
  RESERVED_SECRET_KEYS,
  type RegistryAuthInput,
  type RegistryAuthView,
  type SecretSummary,
} from '@ppanel/shared-contracts';
import type { ContainerApp, Job as JobRow } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { BackupCredentialsService } from '../backup/backup-credentials.service';
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

/** P6 job types whose secrets are repo credentials (+ DB passwords of DB targets). */
export const BACKUP_SECRET_JOB_TYPES = [
  'backup.run',
  'backup.snapshots',
  'backup.verify',
  'restore.run',
];

/** Job types the agent may fetch secrets for (fetch-once). */
export const SECRET_JOB_TYPES = [
  'container.run_candidate',
  'compose.apply',
  'image.build',
  'source.inspect',
  // P6: `{ restic: { repoPassword, restUser, restPassword }, env: { <passwordSecretKey>: value } }`
  ...BACKUP_SECRET_JOB_TYPES,
];

interface StoredRegistryAuth {
  serveraddress: string;
  username: string;
  password: string;
}

const RESERVED = RESERVED_SECRET_KEYS as readonly string[];

/**
 * Loads a visible managed application (container, or compose — compose apps keep their route/runtime
 * state in the same `container_apps` row) — `kinds` narrows it.
 */
export async function loadContainerApp(
  apps: ApplicationsService,
  prisma: PrismaService,
  user: AuthUser,
  id: string,
  kinds: ReadonlyArray<'container' | 'compose'> = ['container', 'compose'],
): Promise<ContainerAppRef> {
  const app = await apps.load(user, id);
  if (!(kinds as readonly string[]).includes(app.kind))
    throw AppError.conflict(
      kinds.length === 1 && kinds[0] === 'compose'
        ? 'Not a compose application'
        : 'Not a container application',
      kinds.length === 1 && kinds[0] === 'compose'
        ? ERROR_CODES.NOT_COMPOSE_APP
        : ERROR_CODES.NOT_CONTAINER_APP,
    );
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
    private readonly backupCreds: BackupCredentialsService,
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
    if (RESERVED.includes(key))
      throw new AppError(
        422,
        ERROR_CODES.SECRET_KEY_RESERVED,
        `${key} is managed through ${key === GIT_TOKEN_SECRET_KEY ? '/git-auth' : '/registry-auth'}`,
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
      where: { applicationId: appId, key: { notIn: [...RESERVED] } },
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

  // ---------------------------------------------------------------- git auth (P4b §8.1)

  async putGitAuth(user: AuthUser, appId: string, token: string, stepUp?: string) {
    await this.writable(user, appId, 'secrets.git_auth_set', stepUp);
    const r = await this.store(user, appId, GIT_TOKEN_SECRET_KEY, token, 'secrets.git_auth_set');
    return { set: true as const, version: r.version };
  }

  async getGitAuth(user: AuthUser, appId: string) {
    await loadContainerApp(this.apps, this.prisma, user, appId);
    const row = await this.prisma.secret.findUnique({
      where: { applicationId_key: { applicationId: appId, key: GIT_TOKEN_SECRET_KEY } },
      select: { version: true, updatedAt: true },
    });
    return row
      ? { set: true, version: row.version, updatedAt: row.updatedAt.toISOString() }
      : { set: false };
  }

  async removeGitAuth(user: AuthUser, appId: string, stepUp?: string): Promise<void> {
    await this.writable(user, appId, 'secrets.git_auth_delete', stepUp);
    const r = await this.prisma.secret.deleteMany({
      where: { applicationId: appId, key: GIT_TOKEN_SECRET_KEY },
    });
    if (r.count === 0) throw AppError.notFound('Git credential');
    await this.audit.record({
      actorId: user.id,
      action: 'secrets.git_auth_delete',
      targetType: 'application',
      targetId: appId,
      result: 'success',
    });
  }

  async hasGitToken(appId: string): Promise<boolean> {
    return !!(await this.prisma.secret.findUnique({
      where: { applicationId_key: { applicationId: appId, key: GIT_TOKEN_SECRET_KEY } },
      select: { id: true },
    }));
  }

  private gitHeader(appId: string, envelope: string): string | null {
    try {
      return gitAuthHeader(this.decrypt(appId, GIT_TOKEN_SECRET_KEY, envelope), (x) =>
        Buffer.from(x, 'utf8').toString('base64'),
      );
    } catch (err) {
      logger.emit('error', 'git credential undecryptable', { applicationId: appId, err });
      return null;
    }
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
      else if (!RESERVED.includes(r.key)) versions[r.key] = r.version;
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
        } else if (r.key === GIT_TOKEN_SECRET_KEY) {
          const token = this.decrypt(appId, r.key, r.valueEncrypted);
          out.push(token, Buffer.from(`x-access-token:${token}`, 'utf8').toString('base64'));
        } else out.push(this.decrypt(appId, r.key, r.valueEncrypted));
      } catch {
        /* undecryptable rows cannot leak either */
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- agent fetch-once (mTLS gateway)

  /**
   * `POST /agent/v1/tasks/:jobId/secrets`: only for a leased/running, unexpired job of the calling
   * server with a matching lease token and a secrets-bearing type — `container.run_candidate` and
   * `compose.apply` (env + registryAuth), `image.build` (gitAuth + registryAuth for the push),
   * `source.inspect` (gitAuth). Values are delivered exactly once (`jobs.secrets_fetched_at` is set
   * with a conditional update).
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
    if (!SECRET_JOB_TYPES.includes(job.type))
      throw await deny(
        ERROR_CODES.FORBIDDEN,
        403,
        `Secrets are only delivered to ${SECRET_JOB_TYPES.join(', ')} tasks`,
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
    if (BACKUP_SECRET_JOB_TYPES.includes(job.type)) {
      const repoId = (job.params as { repo?: { repositoryId?: string } }).repo?.repositoryId;
      const access = repoId ? await this.backupCreds.access(repoId, serverId) : null;
      if (!access)
        throw await deny(ERROR_CODES.TASK_NOT_LEASED, 409, 'Task has no owner', 'no_repo_access');
      const claimedB = await this.prisma.job.updateMany({
        where: { id: jobId, serverId, secretsFetchedAt: null },
        data: { secretsFetchedAt: now },
      });
      if (claimedB.count !== 1)
        throw await deny(
          ERROR_CODES.SECRETS_ALREADY_FETCHED,
          409,
          'Secrets for this task were already delivered',
          'already_fetched',
        );
      return this.deliverBackup(serverId, job, access);
    }
    const owner = await this.ownerOf(job);
    if (!owner || owner.serverId !== serverId)
      throw await deny(ERROR_CODES.TASK_NOT_LEASED, 409, 'Task has no owner', 'no_owner');
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
    return this.deliver(serverId, job, owner);
  }

  /**
   * P6: restic credentials of the server's repo access row + the DB password of every DB target
   * (app secret `passwordSecretKey` of the target's app on this server). Audited by key name only.
   */
  private async deliverBackup(
    serverId: string,
    job: JobRow,
    access: NonNullable<Awaited<ReturnType<BackupCredentialsService['access']>>>,
  ): Promise<AgentSecretsResponse> {
    let restic: AgentSecretsResponse['restic'];
    try {
      restic = this.backupCreds.credentials(access);
    } catch (err) {
      logger.emit('error', 'backup credential undecryptable', {
        repositoryId: access.repositoryId,
        serverId,
        err,
      });
    }
    const params = job.params as {
      targets?: Array<{ app?: string; passwordSecretKey?: string }>;
      target?: { app?: string; passwordSecretKey?: string };
    };
    const dbTargets = [...(params.targets ?? []), ...(params.target ? [params.target] : [])].filter(
      (t): t is { app: string; passwordSecretKey: string } => !!t.app && !!t.passwordSecretKey,
    );
    const env: Record<string, string> = {};
    const missing: string[] = [];
    for (const t of dbTargets) {
      const app = await this.prisma.application.findUnique({
        where: { serverId_name: { serverId, name: t.app } },
        select: { id: true },
      });
      const row = app
        ? await this.prisma.secret.findUnique({
            where: { applicationId_key: { applicationId: app.id, key: t.passwordSecretKey } },
          })
        : null;
      if (!app || !row) {
        missing.push(t.passwordSecretKey);
        continue;
      }
      try {
        env[t.passwordSecretKey] = this.decrypt(app.id, t.passwordSecretKey, row.valueEncrypted);
      } catch (err) {
        missing.push(t.passwordSecretKey);
        logger.emit('error', 'secret undecryptable', { applicationId: app.id, key: row.key, err });
      }
    }
    await this.audit.record({
      actorId: serverId,
      actorType: 'agent',
      action: 'secrets.delivered',
      targetType: 'backup_repository',
      targetId: access.repositoryId,
      result: 'success',
      metadata: {
        jobId: job.id,
        jobType: job.type,
        restUser: access.restUser,
        restic: !!restic,
        keys: Object.keys(env).sort(),
        missing: missing.sort(),
      },
    });
    return { env, ...(restic ? { restic } : {}) };
  }

  /** Workflow object that owns a secrets-bearing job (deployment / build / inspection). */
  private async ownerOf(
    job: JobRow,
  ): Promise<{ applicationId: string; serverId: string; type: string; id: string } | null> {
    if (job.type === 'container.run_candidate' || job.type === 'compose.apply') {
      const step = await this.prisma.deploymentStep.findFirst({
        where: {
          jobId: job.id,
          name: job.type === 'compose.apply' ? 'compose_apply' : 'pull_start',
        },
        include: { deployment: { select: { id: true, applicationId: true, serverId: true } } },
      });
      return step
        ? {
            applicationId: step.deployment.applicationId,
            serverId: step.deployment.serverId,
            type: 'deployment',
            id: step.deployment.id,
          }
        : null;
    }
    if (job.type === 'image.build') {
      const b = await this.prisma.build.findFirst({ where: { jobId: job.id } });
      return b
        ? { applicationId: b.applicationId, serverId: b.buildServerId, type: 'build', id: b.id }
        : null;
    }
    const i = await this.prisma.sourceInspection.findUnique({ where: { jobId: job.id } });
    return i
      ? {
          applicationId: i.applicationId,
          serverId: job.serverId,
          type: 'source_inspection',
          id: i.id,
        }
      : null;
  }

  private async deliver(
    serverId: string,
    job: JobRow,
    owner: { applicationId: string; type: string; id: string },
  ): Promise<AgentSecretsResponse> {
    const appId = owner.applicationId;
    const params = job.params as {
      secretEnvKeys?: string[];
      registryAuth?: boolean;
      services?: Array<{ secretEnv?: Record<string, string> }>;
      source?: { auth?: boolean };
    };
    const wanted = new Set(
      job.type === 'compose.apply'
        ? (params.services ?? []).flatMap((s) => Object.values(s.secretEnv ?? {}))
        : job.type === 'container.run_candidate'
          ? (params.secretEnvKeys ?? [])
          : [],
    );
    const rows = await this.prisma.secret.findMany({ where: { applicationId: appId } });
    const env: Record<string, string> = {};
    let registryAuth: AgentSecretsResponse['registryAuth'];
    let gitAuth: AgentSecretsResponse['gitAuth'];
    for (const r of rows) {
      if (r.key === REGISTRY_AUTH_SECRET_KEY) {
        if (params.registryAuth) {
          const v = this.registryFromRow(appId, r.valueEncrypted);
          if (v) registryAuth = v;
        }
      } else if (r.key === GIT_TOKEN_SECRET_KEY) {
        if (params.source?.auth) {
          const header = this.gitHeader(appId, r.valueEncrypted);
          if (header) gitAuth = { header };
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
      targetType: owner.type,
      targetId: owner.id,
      result: 'success',
      metadata: {
        jobId: job.id,
        jobType: job.type,
        applicationId: appId,
        keys: delivered,
        missing: [...wanted].filter((k) => !(k in env)).sort(),
        registryAuth: !!registryAuth,
        gitAuth: !!gitAuth,
      },
    });
    return {
      env,
      ...(registryAuth ? { registryAuth } : {}),
      ...(gitAuth ? { gitAuth } : {}),
    };
  }
}
