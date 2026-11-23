/**
 * Notification senders (webhook / email / Telegram) + durable outbox dispatcher (P5.05).
 * Messages carry rule name, target name, severity, value and a dashboard link — never secrets or log
 * lines. Errors stored on deliveries are short codes/messages without URLs or tokens.
 */
import { Inject, Injectable } from '@nestjs/common';
import {
  type AlertKind,
  type AlertSeverity,
  type ChannelType,
  type IncidentStatus,
  type IncidentTargetType,
  type WebhookNotificationBody,
} from '@ppanel/shared-contracts';
import type { Incident as IncidentRow, NotificationChannel as ChannelRow } from '@prisma/client';
import { createHmac } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import nodemailer, { type Transporter } from 'nodemailer';
import { AppError } from '../common/app-error';
import { decryptSecret } from '../common/crypto';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { resolveWebhookTarget, type Resolver, type WebhookPolicy } from './ssrf';

export type NotifyEvent = 'fired' | 'resolved' | 'test';

export interface NotificationMessage {
  event: NotifyEvent;
  channelName: string;
  incident: WebhookNotificationBody['incident'];
}

export interface SendResult {
  ok: boolean;
  status?: number;
  error?: string;
  attempts: number;
}

interface DecryptedConfig {
  url?: string;
  signingSecret?: string;
  to?: string[];
  botToken?: string;
  chatId?: string;
}

export function channelAad(id: string): string {
  return `notification_channel:${id}`;
}

export function incidentPayload(
  i: IncidentRow,
  webBase: string,
): NonNullable<WebhookNotificationBody['incident']> {
  return {
    id: i.id,
    ruleId: i.ruleId,
    ruleName: i.ruleName,
    kind: i.kind as AlertKind,
    severity: i.severity as AlertSeverity,
    status: i.status as IncidentStatus,
    target: { type: i.targetType as IncidentTargetType, id: i.targetId, name: i.targetName },
    environment: i.environment,
    startedAt: i.startedAt.toISOString(),
    resolvedAt: i.resolvedAt?.toISOString() ?? null,
    lastValue: i.lastValue,
    url: `${webBase.replace(/\/+$/, '')}/incidents/${i.id}`,
  };
}

/** Plain-text rendering shared by email and Telegram. */
export function renderText(m: NotificationMessage): { subject: string; text: string } {
  const i = m.incident;
  if (!i)
    return {
      subject: '[pPanel] Test notification',
      text: `pPanel test notification for channel "${m.channelName}". No action is required.`,
    };
  const state = m.event === 'resolved' ? 'RESOLVED' : 'FIRING';
  const subject = `[pPanel] ${state} ${i.severity.toUpperCase()}: ${i.ruleName} on ${i.target.name}`;
  const lines = [
    `${state}: ${i.ruleName}`,
    `Severity: ${i.severity}`,
    `Target: ${i.target.type} ${i.target.name} (${i.environment})`,
    `Value: ${i.lastValue ?? 'n/a'}`,
    `Started: ${i.startedAt}`,
    ...(i.resolvedAt ? [`Resolved: ${i.resolvedAt}`] : []),
    `Open in pPanel: ${i.url}`,
  ];
  return { subject, text: lines.join('\n') };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

@Injectable()
export class NotifierService {
  private transport: Transporter | null = null;
  private dispatching = false;
  /** test hook: DNS resolver for the SSRF guard */
  resolver: Resolver | undefined;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  get policy(): WebhookPolicy {
    return {
      production: this.config.isProduction,
      httpAllowlist: this.config.webhookHttpAllowlist,
      privateAllowlist: this.config.webhookAllowlist,
    };
  }

  decryptConfig(row: ChannelRow): DecryptedConfig {
    return JSON.parse(
      decryptSecret(this.config.masterKey, row.configEncrypted, channelAad(row.id)).toString(
        'utf8',
      ),
    ) as DecryptedConfig;
  }

  /** One logical send with up to 3 retries (base, 2×base, 4×base backoff). */
  async send(row: ChannelRow, message: NotificationMessage): Promise<SendResult> {
    let cfg: DecryptedConfig;
    try {
      cfg = this.decryptConfig(row);
    } catch {
      return { ok: false, error: 'channel config undecryptable', attempts: 0 };
    }
    const base = this.config.PPANEL_NOTIFY_RETRY_BASE_MS;
    let last: { ok: boolean; status?: number; error?: string; retryable: boolean } = {
      ok: false,
      error: 'not sent',
      retryable: false,
    };
    let attempts = 0;
    for (let i = 0; i < 4; i++) {
      if (i > 0) await sleep(base * 2 ** (i - 1));
      attempts++;
      last = await this.sendOnce(row.type as ChannelType, cfg, message);
      if (last.ok || !last.retryable) break;
    }
    return { ok: last.ok, status: last.status, error: last.ok ? undefined : last.error, attempts };
  }

  private async sendOnce(
    type: ChannelType,
    cfg: DecryptedConfig,
    m: NotificationMessage,
  ): Promise<{ ok: boolean; status?: number; error?: string; retryable: boolean }> {
    try {
      if (type === 'webhook') return await this.sendWebhook(cfg, m);
      if (type === 'email') return await this.sendEmail(cfg, m);
      return await this.sendTelegram(cfg, m);
    } catch (err) {
      if (err instanceof AppError)
        return {
          ok: false,
          error: `${err.code}${(err.details as { reason?: string })?.reason ? `:${(err.details as { reason: string }).reason}` : ''}`,
          retryable: false,
        };
      const e = err as { code?: string; name?: string; message?: string };
      const code =
        e.name === 'TimeoutError' || e.code === 'ETIMEDOUT'
          ? 'timeout'
          : (e.code ?? 'network_error');
      return { ok: false, error: code, retryable: true };
    }
  }

  private async sendWebhook(cfg: DecryptedConfig, m: NotificationMessage) {
    const target = await resolveWebhookTarget(cfg.url ?? '', this.policy, this.resolver);
    const payload: WebhookNotificationBody = {
      event: m.event,
      sentAt: new Date().toISOString(),
      incident: m.incident,
    };
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const sig = createHmac('sha256', cfg.signingSecret ?? '')
      .update(body)
      .digest('hex');
    const mod = target.url.protocol === 'https:' ? https : http;
    // connect to the address we validated (no second DNS lookup → no rebinding window)
    const pinned: LookupFunction = (_host, opts, cb) => {
      if ((opts as { all?: boolean }).all)
        (cb as (e: null, a: Array<{ address: string; family: number }>) => void)(null, [
          { address: target.address, family: target.family },
        ]);
      else cb(null, target.address, target.family);
    };
    const status = await new Promise<number>((resolve, reject) => {
      const req = mod.request(
        target.url,
        {
          method: 'POST',
          lookup: pinned,
          timeout: this.config.PPANEL_NOTIFY_TIMEOUT_MS,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': body.length,
            'User-Agent': 'pPanel-Notifier/1',
            'X-PPanel-Event': m.event,
            'X-PPanel-Signature': `sha256=${sig}`,
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
          res.on('error', reject);
        },
      );
      req.on('timeout', () =>
        req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })),
      );
      req.on('error', reject);
      req.end(body);
    });
    if (status >= 200 && status < 300) return { ok: true, status, retryable: false };
    return {
      ok: false,
      status,
      error: `HTTP ${status}`,
      retryable: status >= 500 || status === 429 || status === 408,
    };
  }

  private mailer(): Transporter {
    if (!this.config.PPANEL_SMTP_URL)
      throw new AppError(503, 'SMTP_NOT_CONFIGURED', 'SMTP is not configured');
    if (!this.transport) {
      const t = this.config.PPANEL_NOTIFY_TIMEOUT_MS;
      this.transport = nodemailer.createTransport(this.config.PPANEL_SMTP_URL, {
        connectionTimeout: t,
        greetingTimeout: t,
        socketTimeout: t,
      } as never);
    }
    return this.transport;
  }

  private async sendEmail(cfg: DecryptedConfig, m: NotificationMessage) {
    const { subject, text } = renderText(m);
    try {
      await this.mailer().sendMail({
        from: this.config.PPANEL_SMTP_FROM,
        to: cfg.to ?? [],
        subject,
        text,
      });
      return { ok: true, retryable: false };
    } catch (err) {
      if (err instanceof AppError) throw err;
      const e = err as { responseCode?: number; code?: string };
      const permanent = typeof e.responseCode === 'number' && e.responseCode >= 500;
      return {
        ok: false,
        error: e.responseCode ? `SMTP ${e.responseCode}` : (e.code ?? 'smtp_error'),
        retryable: !permanent,
      };
    }
  }

  private async sendTelegram(cfg: DecryptedConfig, m: NotificationMessage) {
    const { text } = renderText(m);
    const base = this.config.PPANEL_TELEGRAM_API_BASE.replace(/\/+$/, '');
    let res: Response;
    try {
      res = await fetch(`${base}/bot${cfg.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: cfg.chatId,
          text,
          disable_web_page_preview: true,
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(this.config.PPANEL_NOTIFY_TIMEOUT_MS),
      });
    } catch (err) {
      // never surface the request URL (it contains the bot token)
      const e = err as { name?: string };
      return {
        ok: false,
        error: e.name === 'TimeoutError' ? 'timeout' : 'network_error',
        retryable: true,
      };
    }
    const json = (await res.json().catch(() => null)) as { ok?: boolean } | null;
    if (res.ok && json?.ok === true) return { ok: true, status: res.status, retryable: false };
    return {
      ok: false,
      status: res.status,
      error: `telegram HTTP ${res.status}`,
      retryable: res.status >= 500 || res.status === 429,
    };
  }

  // ------------------------------------------------------------------------------ outbox

  /** Processes due pending deliveries (claimed with SKIP LOCKED). Returns processed count. */
  async dispatchPending(limit = 20): Promise<number> {
    if (this.dispatching) return 0;
    this.dispatching = true;
    try {
      // crash recovery: a delivery stuck in `sending` is retried (at-least-once)
      await this.prisma.notificationDelivery.updateMany({
        where: { status: 'sending', updatedAt: { lt: new Date(Date.now() - 5 * 60_000) } },
        data: { status: 'pending' },
      });
      const claimed = await this.prisma.$queryRaw<Array<{ id: string }>>`
        UPDATE notification_deliveries SET status = 'sending', updated_at = now()
         WHERE id IN (SELECT id FROM notification_deliveries
                       WHERE status = 'pending' AND next_attempt_at <= now()
                       ORDER BY next_attempt_at LIMIT ${limit}
                       FOR UPDATE SKIP LOCKED)
     RETURNING id`;
      await Promise.all(claimed.map((c) => this.deliver(c.id)));
      return claimed.length;
    } finally {
      this.dispatching = false;
    }
  }

  private async deliver(id: string): Promise<void> {
    const d = await this.prisma.notificationDelivery.findUnique({
      where: { id },
      include: { channel: true },
    });
    if (!d) return;
    const incident = d.incidentId
      ? await this.prisma.incident.findUnique({ where: { id: d.incidentId } })
      : null;
    let result: SendResult;
    if (!d.channel.enabled) result = { ok: false, error: 'channel disabled', attempts: 0 };
    else
      result = await this.send(d.channel, {
        event: d.event as NotifyEvent,
        channelName: d.channel.name,
        incident: incident ? incidentPayload(incident, this.config.PPANEL_PUBLIC_WEB_URL) : null,
      });
    await this.prisma.$transaction(async (tx) => {
      await tx.notificationDelivery.update({
        where: { id },
        data: {
          status: result.ok ? 'delivered' : 'failed',
          attempts: { increment: result.attempts },
          error: result.error ?? null,
          responseStatus: result.status ?? null,
          deliveredAt: result.ok ? new Date() : null,
        },
      });
      if (incident)
        await tx.incidentEvent.create({
          data: {
            id: uuidv7(),
            incidentId: incident.id,
            type: result.ok ? 'notified' : 'notify_failed',
            detail: {
              channelId: d.channel.id,
              channelName: d.channel.name,
              channelType: d.channel.type,
              event: d.event,
              attempts: result.attempts,
              ...(result.error ? { error: result.error } : {}),
            },
          },
        });
    });
    if (!result.ok)
      logger.emit('warn', 'notification delivery failed', {
        component: 'alerts',
        deliveryId: id,
        channelId: d.channel.id,
        error: result.error,
      });
  }
}
