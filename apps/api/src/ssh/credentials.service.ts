import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import {
  type CreateSshCredentialInput,
  type DeploySshCredentialInput,
  ERROR_CODES,
  SSH_MANAGED_BLOCK_ID,
  SSH_MAX_KEYS_PER_SYNC,
  SSH_WS_CLOSE,
  type SshCredential,
  type SshDeployQueued,
  type SshJobsQueued,
  sshKeysSyncResultSchema,
} from '@ppanel/shared-contracts';
import type { Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { decryptSecret, encryptSecret } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { isUniqueViolation, PrismaService, type Tx } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { type FinishedJob, JobHooks } from '../jobs/job-hooks';
import { JobsService } from '../jobs/jobs.service';
import { scopeOf } from '../servers/servers.service';
import {
  credentialPublicSelect,
  serverNames,
  toCredentialView,
  toDeploymentView,
  userLabels,
} from './ssh-common';
import { credentialAad, generateEd25519, importPrivateKey, type NormalizedKey } from './ssh-keys';
import { SshSessionRegistry } from './ssh-registry';

const SYNC_TTL_SEC = 3600;
/** Deployment states whose key belongs in the managed block. */
const DESIRED = ['pending', 'installed'];

/** §2 credentials: Center-held keys, public-key deployment via `ssh.keys.sync`, rotate, revoke. */
@Injectable()
export class SshCredentialsService implements OnModuleInit {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly jobs: JobsService,
    private readonly hooks: JobHooks,
    private readonly registry: SshSessionRegistry,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    this.hooks.register('ssh.keys.sync', (j) => this.onSyncFinished(j));
  }

  // ---------------------------------------------------------------- reads

  async list(user: AuthUser): Promise<SshCredential[]> {
    const visible = this.authz.serverWhere(user, 'fleet.read');
    if (!visible) throw AppError.forbidden();
    const rows = await this.prisma.sshCredential.findMany({
      select: credentialPublicSelect,
      orderBy: { createdAt: 'desc' },
    });
    const deps = await this.prisma.sshKeyDeployment.findMany({
      where: { credentialId: { in: rows.map((r) => r.id) }, server: visible },
      orderBy: [{ serverId: 'asc' }, { sshUser: 'asc' }],
    });
    const names = await serverNames(
      this.prisma,
      deps.map((d) => d.serverId),
    );
    const labels = await userLabels(
      this.prisma,
      rows.flatMap((r) => [r.createdBy, r.revokedBy]),
    );
    return rows.map((r) =>
      toCredentialView(
        r,
        deps.filter((d) => d.credentialId === r.id).map((d) => toDeploymentView(d, names)),
        labels,
      ),
    );
  }

  async get(id: string): Promise<SshCredential> {
    const r = await this.prisma.sshCredential.findUnique({
      where: { id },
      select: credentialPublicSelect,
    });
    if (!r) throw AppError.notFound('SSH credential');
    const deps = await this.prisma.sshKeyDeployment.findMany({ where: { credentialId: id } });
    const names = await serverNames(
      this.prisma,
      deps.map((d) => d.serverId),
    );
    const labels = await userLabels(this.prisma, [r.createdBy, r.revokedBy]);
    return toCredentialView(
      r,
      deps.map((d) => toDeploymentView(d, names)),
      labels,
    );
  }

  /** Decrypted private key for the gateway (in memory only; never logged or returned). */
  async privateKeyFor(fingerprint: string): Promise<{ id: string; key: Buffer } | null> {
    const c = await this.prisma.sshCredential.findUnique({
      where: { fingerprintSha256: fingerprint },
      select: { id: true, status: true, privateKeyEnc: true },
    });
    if (!c || c.status !== 'active') return null;
    return {
      id: c.id,
      key: decryptSecret(this.config.masterKey, c.privateKeyEnc, credentialAad(c.id)),
    };
  }

  // ---------------------------------------------------------------- create / import

  /** Credentials are global objects: every mutation needs a *global* credentials.manage binding. */
  private async enforceGlobal(user: AuthUser, action: string, targetId: string | null) {
    await this.authz.enforce(user, 'credentials.manage', undefined, {
      action,
      targetType: 'ssh_credential',
      targetId,
    });
  }

  async create(
    user: AuthUser,
    input: CreateSshCredentialInput,
    stepUp: string | undefined,
  ): Promise<SshCredential> {
    const action = input.mode === 'generate' ? 'ssh.credential.create' : 'ssh.credential.import';
    await this.enforceGlobal(user, action, null);
    this.auth.assertStepUp(user, stepUp);
    let key: NormalizedKey;
    try {
      key =
        input.mode === 'generate'
          ? generateEd25519()
          : importPrivateKey(input.privateKey, input.passphrase);
    } catch (e) {
      await this.audit.record({
        actorId: user.id,
        action,
        targetType: 'ssh_credential',
        result: 'failure',
        metadata: { reason: e instanceof AppError ? e.code : 'invalid_key' },
      });
      throw e;
    }
    const id = uuidv7();
    try {
      await this.prisma.$transaction(async (tx) => {
        await this.insert(
          tx,
          id,
          input.name,
          input.mode === 'generate' ? 'generated' : 'imported',
          key,
          user.id,
          null,
        );
        await this.audit.record(
          {
            actorId: user.id,
            action,
            targetType: 'ssh_credential',
            targetId: id,
            result: 'success',
            metadata: {
              name: input.name,
              algorithm: key.algorithm,
              fingerprint: key.fingerprintSha256,
            },
          },
          tx,
        );
      });
    } catch (e) {
      if (isUniqueViolation(e))
        throw AppError.conflict('This key is already stored', ERROR_CODES.CONFLICT, {
          fingerprintSha256: key.fingerprintSha256,
        });
      throw e;
    }
    return this.get(id);
  }

  private async insert(
    tx: Tx,
    id: string,
    name: string,
    kind: 'generated' | 'imported',
    key: NormalizedKey,
    createdBy: string,
    rotatedFromId: string | null,
  ): Promise<void> {
    await tx.sshCredential.create({
      data: {
        id,
        name,
        kind,
        algorithm: key.algorithm,
        publicKey: key.publicKey,
        fingerprintSha256: key.fingerprintSha256,
        privateKeyEnc: encryptSecret(this.config.masterKey, key.privateOpenSsh, credentialAad(id)),
        status: 'active',
        rotatedFromId,
        createdBy,
      },
    });
  }

  // ---------------------------------------------------------------- deployments

  private async loadServer(user: AuthUser, serverId: string, action: string) {
    const s = await this.prisma.server.findUnique({
      where: { id: serverId },
      select: { id: true, environment: true, status: true, name: true },
    });
    if (!s || !this.authz.can(user, 'fleet.read', scopeOf(s))) throw AppError.notFound('Server');
    await this.authz.enforce(user, 'credentials.manage', scopeOf(s), {
      action,
      targetType: 'server',
      targetId: s.id,
    });
    return s;
  }

  async deploy(
    user: AuthUser,
    id: string,
    input: DeploySshCredentialInput,
  ): Promise<SshDeployQueued> {
    const server = await this.loadServer(user, input.serverId, 'ssh.key.deploy');
    if (server.status === 'revoked' || server.status === 'enrolling')
      throw AppError.conflict('Server is not active', ERROR_CODES.SSH_STATE_INVALID);
    if (input.sshUser === 'root')
      throw new AppError(422, ERROR_CODES.SSH_ROOT_FORBIDDEN, 'root is never an allowed SSH user');
    const cred = await this.prisma.sshCredential.findUnique({
      where: { id },
      select: { id: true, status: true, fingerprintSha256: true },
    });
    if (!cred) throw AppError.notFound('SSH credential');
    if (cred.status !== 'active')
      throw AppError.conflict(
        'Only active credentials can be deployed',
        ERROR_CODES.SSH_STATE_INVALID,
      );
    const { jobId, deploymentId } = await this.prisma.$transaction(async (tx) => {
      const dep = await tx.sshKeyDeployment.upsert({
        where: {
          serverId_credentialId_sshUser: {
            serverId: server.id,
            credentialId: id,
            sshUser: input.sshUser,
          },
        },
        create: {
          id: uuidv7(),
          serverId: server.id,
          credentialId: id,
          sshUser: input.sshUser,
          status: 'pending',
        },
        update: { status: 'pending', lastError: null },
      });
      const job = await this.queueSync(tx, server.id, input.sshUser, user.id);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.key.deploy',
          targetType: 'ssh_credential',
          targetId: id,
          result: 'success',
          metadata: {
            serverId: server.id,
            sshUser: input.sshUser,
            fingerprint: cred.fingerprintSha256,
            jobId: job,
          },
        },
        tx,
      );
      return { jobId: job, deploymentId: dep.id };
    });
    this.jobs.notify(server.id);
    const dep = await this.prisma.sshKeyDeployment.findUniqueOrThrow({
      where: { id: deploymentId },
    });
    return {
      jobId,
      deployment: toDeploymentView(dep, new Map([[server.id, { name: server.name }]])),
    };
  }

  async removeDeployment(
    user: AuthUser,
    id: string,
    deploymentId: string,
  ): Promise<{ jobId: string }> {
    const dep = await this.prisma.sshKeyDeployment.findUnique({ where: { id: deploymentId } });
    if (!dep || dep.credentialId !== id) throw AppError.notFound('SSH key deployment');
    await this.loadServer(user, dep.serverId, 'ssh.key.remove');
    const jobId = await this.prisma.$transaction(async (tx) => {
      await tx.sshKeyDeployment.update({
        where: { id: dep.id },
        data: { status: 'removing', lastError: null },
      });
      const job = await this.queueSync(tx, dep.serverId, dep.sshUser, user.id);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.key.remove',
          targetType: 'ssh_credential',
          targetId: id,
          result: 'success',
          metadata: { serverId: dep.serverId, sshUser: dep.sshUser, deploymentId, jobId: job },
        },
        tx,
      );
      return job;
    });
    this.jobs.notify(dep.serverId);
    return { jobId };
  }

  /**
   * Queues one `ssh.keys.sync` for (server, user) with the full desired key set: deployments that are
   * pending/installed of *active* credentials. Every deployment of that pair records the job id.
   */
  async queueSync(
    tx: Tx,
    serverId: string,
    sshUser: string,
    actorId: string | null,
  ): Promise<string> {
    const deps = await tx.sshKeyDeployment.findMany({
      where: { serverId, sshUser },
      include: {
        credential: { select: { status: true, fingerprintSha256: true, publicKey: true } },
      },
      orderBy: { updatedAt: 'desc' },
    });
    const keys = deps
      .filter((d) => DESIRED.includes(d.status) && d.credential.status === 'active')
      .map((d) => ({
        fingerprint: d.credential.fingerprintSha256,
        publicKey: d.credential.publicKey,
      }));
    if (keys.length > SSH_MAX_KEYS_PER_SYNC)
      throw AppError.conflict(
        `At most ${SSH_MAX_KEYS_PER_SYNC} keys per server user`,
        ERROR_CODES.SSH_STATE_INVALID,
      );
    const job = await this.jobs.createInternal(tx, {
      serverId,
      type: 'ssh.keys.sync',
      params: { user: sshUser, keys, managedBlockId: SSH_MANAGED_BLOCK_ID },
      actorId,
      ttlSec: SYNC_TTL_SEC,
      metadata: { sshUser, keyCount: keys.length },
    });
    await tx.sshKeyDeployment.updateMany({
      where: { serverId, sshUser, status: { in: ['pending', 'installed', 'removing', 'failed'] } },
      data: { jobId: job.id },
    });
    return job.id;
  }

  /** Idempotent per job id: only deployments still pointing at this job are updated. */
  async onSyncFinished(job: FinishedJob): Promise<void> {
    const deps = await this.prisma.sshKeyDeployment.findMany({
      where: { jobId: job.id },
      include: { credential: { select: { fingerprintSha256: true } } },
    });
    if (deps.length === 0) return;
    if (job.status === 'succeeded') {
      const parsed = sshKeysSyncResultSchema.safeParse(job.result);
      if (!parsed.success) {
        await this.prisma.sshKeyDeployment.updateMany({
          where: { jobId: job.id, status: { in: ['pending', 'removing'] } },
          data: { status: 'failed', lastError: 'malformed agent result' },
        });
        return;
      }
      const managed = new Set(parsed.data.managedFingerprints);
      for (const d of deps) {
        const has = managed.has(d.credential.fingerprintSha256);
        let status = d.status;
        let lastError: string | null = null;
        if (d.status === 'pending') status = has ? 'installed' : 'failed';
        else if (d.status === 'removing') status = has ? 'failed' : 'removed';
        else if (d.status === 'installed' && !has) status = 'failed';
        if (status === 'failed')
          lastError = has ? 'key still present after removal' : 'key not installed';
        if (status !== d.status || lastError !== d.lastError)
          await this.prisma.sshKeyDeployment.updateMany({
            where: { id: d.id, jobId: job.id },
            data: { status, lastError },
          });
      }
      return;
    }
    const err = (job.error ?? (job.result as { error?: unknown } | null)?.error) as
      { code?: string; message?: string } | string | null | undefined;
    const code = typeof err === 'string' ? err : (err?.code ?? job.status.toUpperCase());
    const message = typeof err === 'object' && err?.message ? `${code}: ${err.message}` : code;
    await this.prisma.sshKeyDeployment.updateMany({
      where: { jobId: job.id, status: { in: ['pending', 'removing'] } },
      data: { status: 'failed', lastError: message.slice(0, 500) },
    });
  }

  // ---------------------------------------------------------------- rotate / revoke

  async rotate(
    user: AuthUser,
    id: string,
    stepUp: string | undefined,
  ): Promise<SshCredential & SshJobsQueued> {
    await this.enforceGlobal(user, 'ssh.credential.rotate', id);
    this.auth.assertStepUp(user, stepUp);
    const old = await this.prisma.sshCredential.findUnique({
      where: { id },
      select: { id: true, name: true, status: true, fingerprintSha256: true },
    });
    if (!old) throw AppError.notFound('SSH credential');
    if (old.status !== 'active')
      throw AppError.conflict(
        'Only active credentials can be rotated',
        ERROR_CODES.SSH_STATE_INVALID,
      );
    const key = generateEd25519();
    const newId = uuidv7();
    const pairs = new Map<string, { serverId: string; sshUser: string }>();
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.sshCredential.updateMany({
        where: { id, status: 'active' },
        data: { status: 'rotated' },
      });
      if (r.count !== 1)
        throw AppError.conflict('Credential changed concurrently', ERROR_CODES.SSH_STATE_INVALID);
      await this.insert(tx, newId, old.name, 'generated', key, user.id, id);
      const installed = await tx.sshKeyDeployment.findMany({
        where: { credentialId: id, status: { in: ['installed', 'pending'] } },
      });
      for (const d of installed) {
        await tx.sshKeyDeployment.create({
          data: {
            id: uuidv7(),
            serverId: d.serverId,
            credentialId: newId,
            sshUser: d.sshUser,
            status: 'pending',
          },
        });
        pairs.set(`${d.serverId}|${d.sshUser}`, { serverId: d.serverId, sshUser: d.sshUser });
      }
      await tx.sshKeyDeployment.updateMany({
        where: { credentialId: id, status: { in: ['installed', 'pending', 'failed'] } },
        data: { status: 'removing' },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.credential.rotate',
          targetType: 'ssh_credential',
          targetId: id,
          result: 'success',
          metadata: {
            newCredentialId: newId,
            oldFingerprint: old.fingerprintSha256,
            newFingerprint: key.fingerprintSha256,
            servers: pairs.size,
          },
        },
        tx,
      );
    });
    // the Center never presents a rotated key again
    await this.registry.closeWhere(
      (s) => s.credentialFingerprint === old.fingerprintSha256,
      'credential_revoked',
      SSH_WS_CLOSE.FORBIDDEN,
      'credential rotated',
    );
    const jobIds = await this.resyncPairs([...pairs.values()], user.id);
    return { ...(await this.get(newId)), jobIds };
  }

  async revoke(
    user: AuthUser,
    id: string,
    stepUp: string | undefined,
  ): Promise<SshCredential & SshJobsQueued> {
    await this.enforceGlobal(user, 'ssh.credential.revoke', id);
    this.auth.assertStepUp(user, stepUp);
    const c = await this.prisma.sshCredential.findUnique({
      where: { id },
      select: { id: true, status: true, fingerprintSha256: true },
    });
    if (!c) throw AppError.notFound('SSH credential');
    if (c.status === 'revoked')
      throw AppError.conflict('Credential already revoked', ERROR_CODES.SSH_STATE_INVALID);
    const pairs = new Map<string, { serverId: string; sshUser: string }>();
    await this.prisma.$transaction(async (tx) => {
      await tx.sshCredential.update({
        where: { id },
        data: { status: 'revoked', revokedAt: new Date(), revokedBy: user.id },
      });
      const deps = await tx.sshKeyDeployment.findMany({
        where: { credentialId: id, status: { notIn: ['removed'] } },
      });
      for (const d of deps)
        pairs.set(`${d.serverId}|${d.sshUser}`, { serverId: d.serverId, sshUser: d.sshUser });
      await tx.sshKeyDeployment.updateMany({
        where: { credentialId: id, status: { notIn: ['removed'] } },
        data: { status: 'removing' },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'ssh.credential.revoke',
          targetType: 'ssh_credential',
          targetId: id,
          result: 'success',
          metadata: { fingerprint: c.fingerprintSha256, servers: pairs.size },
        },
        tx,
      );
    });
    await this.registry.closeWhere(
      (s) => s.credentialFingerprint === c.fingerprintSha256,
      'credential_revoked',
      SSH_WS_CLOSE.FORBIDDEN,
      'credential revoked',
    );
    const jobIds = await this.resyncPairs([...pairs.values()], user.id);
    return { ...(await this.get(id)), jobIds };
  }

  /** One job per (server, user); a host that cannot take a job keeps `removing` + lastError. */
  private async resyncPairs(
    pairs: Array<{ serverId: string; sshUser: string }>,
    actorId: string,
  ): Promise<string[]> {
    const out: string[] = [];
    for (const p of pairs) {
      try {
        const jobId = await this.prisma.$transaction((tx) =>
          this.queueSync(tx, p.serverId, p.sshUser, actorId),
        );
        out.push(jobId);
        this.jobs.notify(p.serverId);
      } catch (e) {
        logger.emit('warn', 'ssh.keys.sync not queued', { serverId: p.serverId, err: e });
        await this.prisma.sshKeyDeployment.updateMany({
          where: {
            serverId: p.serverId,
            sshUser: p.sshUser,
            status: { in: ['pending', 'removing'] },
          },
          data: { lastError: e instanceof AppError ? e.code : 'sync not queued' },
        });
      }
    }
    return out;
  }

  /** Active credential with an installed deployment for (server, user): newest first. */
  async usableCredential(
    db: PrismaService | Prisma.TransactionClient,
    serverId: string,
    sshUser: string,
  ): Promise<{ id: string; fingerprintSha256: string } | null> {
    const d = await db.sshKeyDeployment.findFirst({
      where: { serverId, sshUser, status: 'installed', credential: { status: 'active' } },
      include: { credential: { select: { id: true, fingerprintSha256: true } } },
      orderBy: { updatedAt: 'desc' },
    });
    return d ? d.credential : null;
  }
}
