import { Inject, Injectable } from '@nestjs/common';
import type { BackupRepoAccess, BackupRepository } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { decryptSecret, encryptSecret } from '../common/crypto';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';

export interface ResticCredentials {
  repoPassword: string;
  restUser: string;
  restPassword: string;
}

/** rest-server URL of a server's private repo (`<baseUrl>/<restUser>/`, never with credentials). */
export function repoUrl(baseUrl: string, restUser: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/${restUser}/`;
}

/**
 * Encrypted per-server restic credentials (AES-256-GCM with the master key; AAD binds each ciphertext
 * to repository + server + purpose). Decrypted values leave the Center only via the agent secrets
 * call (fetch-once, mTLS) and the step-up recovery export.
 */
@Injectable()
export class BackupCredentialsService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  private aad(repoId: string, serverId: string, purpose: 'rest' | 'repo'): string {
    return `backup_${purpose}:${repoId}:${serverId}`;
  }

  encrypt(repoId: string, serverId: string, purpose: 'rest' | 'repo', value: string): string {
    return encryptSecret(this.config.masterKey, value, this.aad(repoId, serverId, purpose));
  }

  decrypt(row: BackupRepoAccess, purpose: 'rest' | 'repo'): string {
    return decryptSecret(
      this.config.masterKey,
      purpose === 'rest' ? row.restPasswordEnc : row.repoPasswordEnc,
      this.aad(row.repositoryId, row.serverId, purpose),
    ).toString('utf8');
  }

  /** 32 random bytes, base64 (contract §10.1). */
  generateRepoPassword(): string {
    return randomBytes(32).toString('base64');
  }

  async access(
    repositoryId: string,
    serverId: string,
  ): Promise<(BackupRepoAccess & { repository: BackupRepository }) | null> {
    return this.prisma.backupRepoAccess.findUnique({
      where: { repositoryId_serverId: { repositoryId, serverId } },
      include: { repository: true },
    });
  }

  credentials(row: BackupRepoAccess): ResticCredentials {
    return {
      repoPassword: this.decrypt(row, 'repo'),
      restUser: row.restUser,
      restPassword: this.decrypt(row, 'rest'),
    };
  }
}
