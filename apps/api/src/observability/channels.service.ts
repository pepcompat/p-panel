/** Notification channels CRUD + test (perm `policies.manage`, global). Secrets are never returned. */
import { Injectable } from '@nestjs/common';
import {
  CHANNEL_CONFIG_SCHEMAS,
  type ChannelConfigView,
  type ChannelTestResult,
  type ChannelType,
  type CreateChannelInput,
  ERROR_CODES,
  type NotificationChannel,
  type UpdateChannelInput,
} from '@ppanel/shared-contracts';
import type { NotificationChannel as ChannelRow, Prisma } from '@prisma/client';
import { Inject } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { encryptSecret } from '../common/crypto';
import { zodDetails } from '../common/exception.filter';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { channelAad, NotifierService } from './notifier.service';
import { checkWebhookUrl } from './ssrf';

/** Origin + "/…" (paths of webhook URLs often embed tokens, e.g. chat webhooks). */
export function maskUrl(raw: string): string {
  try {
    const u = new URL(raw);
    const hasMore = (u.pathname && u.pathname !== '/') || u.search;
    return `${u.origin}${hasMore ? '/…' : '/'}`;
  } catch {
    return '…';
  }
}

function publicConfig(type: ChannelType, cfg: Record<string, unknown>): Record<string, unknown> {
  if (type === 'webhook') return { url: maskUrl(String(cfg.url)) };
  if (type === 'email') return { to: cfg.to };
  return { chatId: cfg.chatId };
}

function configView(type: ChannelType, pub: Record<string, unknown>): ChannelConfigView {
  if (type === 'webhook') return { url: String(pub.url ?? ''), signingSecret: { set: true } };
  if (type === 'email') return { to: (pub.to as string[]) ?? [] };
  return { chatId: String(pub.chatId ?? ''), botToken: { set: true } };
}

@Injectable()
export class ChannelsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly notifier: NotifierService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  private async enforce(user: AuthUser, action: string, targetId?: string): Promise<void> {
    await this.authz.enforce(user, 'policies.manage', undefined, {
      action,
      targetType: 'notification_channel',
      targetId: targetId ?? null,
    });
  }

  private validate(type: ChannelType, cfg: unknown): Record<string, unknown> {
    const r = CHANNEL_CONFIG_SCHEMAS[type].safeParse(cfg);
    if (!r.success)
      throw AppError.validation(
        zodDetails(r.error).map((d) => ({ ...d, path: `config.${d.path}` })),
      );
    const data = r.data as Record<string, unknown>;
    if (type === 'webhook') checkWebhookUrl(String(data.url), this.notifier.policy);
    return data;
  }

  async view(row: ChannelRow): Promise<NotificationChannel> {
    const last = await this.prisma.notificationDelivery.findFirst({
      where: { channelId: row.id, status: { in: ['delivered', 'failed'] } },
      orderBy: { updatedAt: 'desc' },
    });
    return {
      id: row.id,
      name: row.name,
      type: row.type as ChannelType,
      enabled: row.enabled,
      config: configView(row.type as ChannelType, row.configPublic as Record<string, unknown>),
      lastDelivery: last
        ? {
            at: last.updatedAt.toISOString(),
            status: last.status as 'delivered' | 'failed',
            error: last.error,
          }
        : null,
      version: row.version,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  async list(user: AuthUser): Promise<NotificationChannel[]> {
    if (!this.authz.can(user, 'policies.manage')) throw AppError.forbidden();
    const rows = await this.prisma.notificationChannel.findMany({ orderBy: { createdAt: 'asc' } });
    return Promise.all(rows.map((r) => this.view(r)));
  }

  private async load(user: AuthUser, id: string): Promise<ChannelRow> {
    if (!this.authz.can(user, 'policies.manage')) throw AppError.notFound('Notification channel');
    const row = await this.prisma.notificationChannel.findUnique({ where: { id } });
    if (!row) throw AppError.notFound('Notification channel');
    return row;
  }

  async get(user: AuthUser, id: string): Promise<NotificationChannel> {
    return this.view(await this.load(user, id));
  }

  async create(user: AuthUser, input: CreateChannelInput): Promise<NotificationChannel> {
    await this.enforce(user, 'notification_channel.create');
    const cfg = this.validate(input.type, input.config);
    const id = uuidv7();
    const pub = publicConfig(input.type, cfg);
    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.notificationChannel.create({
        data: {
          id,
          name: input.name,
          type: input.type,
          enabled: input.enabled,
          configPublic: pub as Prisma.InputJsonValue,
          configEncrypted: encryptSecret(
            this.config.masterKey,
            JSON.stringify(cfg),
            channelAad(id),
          ),
          createdBy: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'notification_channel.create',
          targetType: 'notification_channel',
          targetId: id,
          result: 'success',
          diff: { name: input.name, type: input.type, config: pub },
          metadata: { type: input.type },
        },
        tx,
      );
      return created;
    });
    return this.view(row);
  }

  async update(
    user: AuthUser,
    id: string,
    input: UpdateChannelInput,
    ifMatch?: number,
  ): Promise<NotificationChannel> {
    const row = await this.load(user, id);
    await this.enforce(user, 'notification_channel.update', id);
    if (ifMatch !== undefined && ifMatch !== row.version)
      throw AppError.conflict('Channel was modified', ERROR_CODES.VERSION_CONFLICT, {
        currentVersion: row.version,
      });
    const type = row.type as ChannelType;
    let data: Prisma.NotificationChannelUpdateManyMutationInput = {};
    let pub = row.configPublic as Record<string, unknown>;
    if (input.config) {
      const merged = { ...this.notifier.decryptConfig(row), ...input.config };
      const cfg = this.validate(type, merged);
      pub = publicConfig(type, cfg);
      data = {
        configPublic: pub as Prisma.InputJsonValue,
        configEncrypted: encryptSecret(this.config.masterKey, JSON.stringify(cfg), channelAad(id)),
      };
    }
    const updated = await this.prisma.$transaction(async (tx) => {
      const r = await tx.notificationChannel.updateMany({
        where: { id, version: row.version },
        data: {
          ...data,
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          version: { increment: 1 },
        },
      });
      if (r.count !== 1)
        throw AppError.conflict('Channel was modified', ERROR_CODES.VERSION_CONFLICT);
      await this.audit.record(
        {
          actorId: user.id,
          action: 'notification_channel.update',
          targetType: 'notification_channel',
          targetId: id,
          result: 'success',
          diff: { name: input.name, enabled: input.enabled, config: pub },
          metadata: {
            fields: Object.keys(input),
            secretsChanged: Object.keys(input.config ?? {}).filter((k) =>
              ['signingSecret', 'botToken', 'url'].includes(k),
            ),
          },
        },
        tx,
      );
      return tx.notificationChannel.findUniqueOrThrow({ where: { id } });
    });
    return this.view(updated);
  }

  async remove(user: AuthUser, id: string): Promise<void> {
    await this.load(user, id);
    await this.enforce(user, 'notification_channel.delete', id);
    await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`UPDATE alert_rules SET channel_ids = array_remove(channel_ids, ${id}), version = version + 1, updated_at = now() WHERE ${id} = ANY(channel_ids)`;
      await tx.notificationChannel.delete({ where: { id } });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'notification_channel.delete',
          targetType: 'notification_channel',
          targetId: id,
          result: 'success',
        },
        tx,
      );
    });
  }

  /** Sends a test message now (with retries) and records the delivery. */
  async test(user: AuthUser, id: string): Promise<ChannelTestResult> {
    const row = await this.load(user, id);
    await this.enforce(user, 'notification_channel.test', id);
    const deliveryId = uuidv7();
    await this.prisma.notificationDelivery.create({
      data: { id: deliveryId, channelId: id, event: 'test', status: 'sending' },
    });
    const r = await this.notifier.send(row, {
      event: 'test',
      channelName: row.name,
      incident: null,
    });
    await this.prisma.notificationDelivery.update({
      where: { id: deliveryId },
      data: {
        status: r.ok ? 'delivered' : 'failed',
        attempts: r.attempts,
        error: r.error ?? null,
        responseStatus: r.status ?? null,
        deliveredAt: r.ok ? new Date() : null,
      },
    });
    await this.audit.record({
      actorId: user.id,
      action: 'notification_channel.test',
      targetType: 'notification_channel',
      targetId: id,
      result: r.ok ? 'success' : 'failure',
      metadata: { deliveryId, ...(r.error ? { error: r.error } : {}) },
    });
    return { delivered: r.ok, ...(r.error ? { error: r.error } : {}), deliveryId };
  }
}
