/**
 * Alert evaluator (durable worker, every 15 s) + incident lifecycle (P5.05, P5-T01).
 * State per (rule, target) lives in `alert_states`: condition true → pending (since) → firing after
 * forSec (one open incident per rule+target, partial unique index) → resolved when the condition
 * clears or the target leaves the rule's scope. Notifications go through the delivery outbox.
 * Stale data never fires `metric_threshold` (unknown → no transition).
 */
import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import {
  ACTIVE_ALERT_KINDS,
  type AlertKind,
  type IncidentTargetType,
  STALE_AFTER_SEC,
  type ThresholdMetric,
} from '@ppanel/shared-contracts';
import { Prisma, type AlertRule as RuleRow, type Incident as IncidentRow } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { uuidv7 } from '../common/ids';
import { logger } from '../common/logger';
import { PrismaService, type Tx } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { deriveStatus } from '../servers/server-view';
import { NotifierService } from './notifier.service';
import { currentContainersOf, MANAGED_APP_KINDS } from './telemetry.service';

const LOCK_KEY = 0x70_50_35_01; // "pP5" evaluator advisory lock

/** Evaluated condition for one target: true / false / unknown (no transition, never fires). */
export interface TargetEval {
  type: IncidentTargetType;
  id: string;
  name: string;
  serverId: string;
  environment: string;
  condition: boolean | 'unknown';
  value: number | null;
}

const METRIC_KEY: Record<ThresholdMetric, string> = {
  cpu: 'cpuPct',
  memory: 'memPct',
  disk: 'diskPct',
  load1: 'load1',
};

interface ServerSnap {
  id: string;
  name: string;
  environment: string;
  status: string;
  lastHeartbeatAt: Date | null;
  metrics: unknown;
  metricsSampledAt: Date | null;
  telemetry: {
    containersReportedAt: Date | null;
    lastDroppedAt: Date | null;
    agentDroppedTotal: bigint;
    centerDroppedTotal: bigint;
  } | null;
}

@Injectable()
export class AlertEngineService implements OnApplicationBootstrap, OnApplicationShutdown {
  private timer: NodeJS.Timeout | undefined;
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly notifier: NotifierService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.NODE_ENV === 'test') return; // tests drive ticks explicitly
    this.timer = setInterval(() => void this.tick(), this.config.PPANEL_ALERT_EVAL_INTERVAL_MS);
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** One evaluation round + outbox dispatch. Safe to call concurrently / from several instances. */
  async tick(now = new Date()): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.evaluate(now);
      await this.notifier.dispatchPending();
    } catch (err) {
      logger.emit('error', 'alert evaluation failed', { component: 'alerts', err });
    } finally {
      this.running = false;
    }
  }

  async evaluate(now = new Date()): Promise<boolean> {
    return this.prisma.$transaction(
      async (tx) => {
        const lock = await tx.$queryRaw<Array<{ ok: boolean }>>`
          SELECT pg_try_advisory_xact_lock(${LOCK_KEY}) AS ok`;
        if (!lock[0]?.ok) return false; // another instance is evaluating
        const rules = await tx.alertRule.findMany({
          where: { enabled: true, kind: { in: [...ACTIVE_ALERT_KINDS] } },
        });
        if (rules.length === 0) return true;
        const servers: ServerSnap[] = await tx.server.findMany({
          where: { status: { notIn: ['revoked', 'enrolling'] } },
          select: {
            id: true,
            name: true,
            environment: true,
            status: true,
            lastHeartbeatAt: true,
            metrics: true,
            metricsSampledAt: true,
            telemetry: {
              select: {
                containersReportedAt: true,
                lastDroppedAt: true,
                agentDroppedTotal: true,
                centerDroppedTotal: true,
              },
            },
          },
        });
        const appTargets = rules.some((r) => r.kind === 'app_down')
          ? await this.appDownTargets(tx, servers, now)
          : [];
        for (const rule of rules) {
          const targets = this.targetsFor(rule, servers, appTargets, now);
          await this.applyRule(tx, rule, targets, now);
        }
        return true;
      },
      { timeout: 60_000, maxWait: 10_000 },
    );
  }

  private inScope(rule: RuleRow, s: { id: string; environment: string }, appId?: string) {
    switch (rule.scopeType) {
      case 'global':
        return true;
      case 'environment':
        return s.environment === rule.scopeId;
      case 'server':
        return s.id === rule.scopeId;
      case 'app':
        return appId !== undefined && appId === rule.scopeId;
      default:
        return false;
    }
  }

  targetsFor(
    rule: RuleRow,
    servers: ServerSnap[],
    appTargets: TargetEval[],
    now: Date,
  ): TargetEval[] {
    const kind = rule.kind as AlertKind;
    const t = now.getTime();
    if (kind === 'app_down')
      return appTargets.filter((a) =>
        this.inScope(rule, { id: a.serverId, environment: a.environment }, a.id),
      );
    const out: TargetEval[] = [];
    for (const s of servers) {
      if (!this.inScope(rule, s)) continue;
      const status = deriveStatus(s.status, s.lastHeartbeatAt, t);
      const fresh = status === 'online' || status === 'degraded';
      const base = {
        type: 'server' as const,
        id: s.id,
        name: s.name,
        serverId: s.id,
        environment: s.environment,
      };
      if (kind === 'server_offline') {
        out.push({
          ...base,
          condition: !fresh,
          value: s.lastHeartbeatAt ? Math.round((t - s.lastHeartbeatAt.getTime()) / 1000) : null,
        });
      } else if (kind === 'metric_threshold') {
        const p = rule.params as { metric: ThresholdMetric; op: 'gt' | 'lt'; value: number };
        const v = (s.metrics as Record<string, unknown> | null)?.[METRIC_KEY[p.metric]];
        const sampleFresh =
          !!s.metricsSampledAt && t - s.metricsSampledAt.getTime() <= STALE_AFTER_SEC * 1000;
        if (!fresh || !sampleFresh || typeof v !== 'number') {
          out.push({ ...base, condition: 'unknown', value: null });
          continue;
        }
        out.push({ ...base, condition: p.op === 'gt' ? v > p.value : v < p.value, value: v });
      } else if (kind === 'log_dropped') {
        const p = rule.params as { windowSec?: number; minEntries?: number };
        const tel = s.telemetry;
        const total = tel ? Number(tel.agentDroppedTotal + tel.centerDroppedTotal) : 0;
        const recent =
          !!tel?.lastDroppedAt && t - tel.lastDroppedAt.getTime() <= (p.windowSec ?? 300) * 1000;
        out.push({ ...base, condition: recent && total >= (p.minEntries ?? 1), value: total });
      }
    }
    return out;
  }

  /** Managed apps: down when the last deployment needs manual recovery or a current container is not running/healthy. */
  private async appDownTargets(tx: Tx, servers: ServerSnap[], now: Date): Promise<TargetEval[]> {
    const byId = new Map(servers.map((s) => [s.id, s]));
    const apps = await tx.application.findMany({
      where: { serverId: { in: [...byId.keys()] }, kind: { in: MANAGED_APP_KINDS } },
      select: {
        id: true,
        name: true,
        serverId: true,
        container: { select: { currentDeploymentId: true } },
        deployments: {
          orderBy: { number: 'desc' },
          take: 1,
          select: { status: true },
        },
      },
    });
    const depIds = apps.map((a) => a.container?.currentDeploymentId).filter(Boolean) as string[];
    const deps = depIds.length
      ? await tx.deployment.findMany({
          where: { id: { in: depIds } },
          select: { id: true, containerName: true, serviceResults: true, plan: true },
        })
      : [];
    const depById = new Map(deps.map((d) => [d.id, d]));
    const samples = await tx.containerSample.findMany({
      where: { serverId: { in: [...byId.keys()] } },
      select: { serverId: true, name: true, state: true, health: true, sampledAt: true },
    });
    const sampleByName = new Map(samples.map((c) => [`${c.serverId}/${c.name}`, c]));
    const out: TargetEval[] = [];
    for (const a of apps) {
      const s = byId.get(a.serverId)!;
      const base = {
        type: 'app' as const,
        id: a.id,
        name: `${a.name} @ ${s.name}`,
        serverId: s.id,
        environment: s.environment,
      };
      if (a.deployments[0]?.status === 'requires_manual_recovery') {
        out.push({ ...base, condition: true, value: 1 });
        continue;
      }
      const depId = a.container?.currentDeploymentId;
      if (!depId) continue; // never deployed: nothing to watch
      const status = deriveStatus(s.status, s.lastHeartbeatAt, now.getTime());
      if ((status !== 'online' && status !== 'degraded') || !s.telemetry?.containersReportedAt) {
        out.push({ ...base, condition: 'unknown', value: null }); // server_offline covers it
        continue;
      }
      const current = currentContainersOf(
        depById.get(depId) ?? { containerName: null, serviceResults: null, plan: null },
      );
      if (current.length === 0) {
        out.push({ ...base, condition: 'unknown', value: null });
        continue;
      }
      let down = 0;
      for (const c of current) {
        const smp = sampleByName.get(`${s.id}/${c.name}`);
        const freshSample =
          smp && now.getTime() - smp.sampledAt.getTime() <= STALE_AFTER_SEC * 1000;
        if (!freshSample || smp!.state !== 'running' || smp!.health === 'unhealthy') down++;
      }
      out.push({ ...base, condition: down > 0, value: down });
    }
    return out;
  }

  private async applyRule(tx: Tx, rule: RuleRow, targets: TargetEval[], now: Date) {
    const states = await tx.alertState.findMany({ where: { ruleId: rule.id } });
    const stateByKey = new Map(states.map((s) => [`${s.targetType}/${s.targetId}`, s]));
    const seen = new Set<string>();
    for (const t of targets) {
      const key = `${t.type}/${t.id}`;
      seen.add(key);
      const st = stateByKey.get(key);
      const where = {
        ruleId_targetType_targetId: { ruleId: rule.id, targetType: t.type, targetId: t.id },
      };
      if (t.condition === 'unknown') {
        // never fire on unknown/stale data; an un-confirmed pending state is dropped,
        // a firing one is kept (no flapping resolve on missing data)
        if (st?.status === 'pending') await tx.alertState.delete({ where });
        else if (st) await tx.alertState.update({ where, data: { evaluatedAt: now } });
        continue;
      }
      if (t.condition === false) {
        if (st?.status === 'firing' && st.incidentId)
          await this.resolve(tx, st.incidentId, now, {});
        if (st) await tx.alertState.delete({ where });
        continue;
      }
      // condition true
      if (!st) {
        if (rule.forSec === 0) await this.fire(tx, rule, t, now, now);
        else
          await tx.alertState.create({
            data: {
              ruleId: rule.id,
              targetType: t.type,
              targetId: t.id,
              status: 'pending',
              since: now,
              lastValue: t.value,
              evaluatedAt: now,
            },
          });
        continue;
      }
      if (st.status === 'pending') {
        if (now.getTime() - st.since.getTime() >= rule.forSec * 1000)
          await this.fire(tx, rule, t, st.since, now);
        else await tx.alertState.update({ where, data: { lastValue: t.value, evaluatedAt: now } });
        continue;
      }
      // firing: refresh value (incident keeps the latest value)
      await tx.alertState.update({ where, data: { lastValue: t.value, evaluatedAt: now } });
      if (st.incidentId)
        await tx.incident.updateMany({
          where: { id: st.incidentId, status: { not: 'resolved' } },
          data: { lastValue: t.value },
        });
    }
    // targets that left the scope / disappeared → clear
    for (const st of states) {
      if (seen.has(`${st.targetType}/${st.targetId}`)) continue;
      if (st.status === 'firing' && st.incidentId)
        await this.resolve(tx, st.incidentId, now, { reason: 'target_out_of_scope' });
      await tx.alertState.delete({
        where: {
          ruleId_targetType_targetId: {
            ruleId: st.ruleId,
            targetType: st.targetType,
            targetId: st.targetId,
          },
        },
      });
    }
  }

  private async fire(tx: Tx, rule: RuleRow, t: TargetEval, since: Date, now: Date) {
    // dedupe: one open incident per (rule, target) — reuse it if one exists
    let incident = await tx.incident.findFirst({
      where: { ruleId: rule.id, targetType: t.type, targetId: t.id, status: { not: 'resolved' } },
    });
    if (!incident) {
      const id = uuidv7();
      try {
        incident = await tx.incident.create({
          data: {
            id,
            ruleId: rule.id,
            ruleName: rule.name,
            kind: rule.kind,
            targetType: t.type,
            targetId: t.id,
            targetName: t.name,
            serverId: t.serverId,
            environment: t.environment,
            severity: rule.severity,
            status: 'firing',
            startedAt: now,
            lastValue: t.value,
          },
        });
      } catch (err) {
        if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') return;
        throw err;
      }
      await tx.incidentEvent.create({
        data: {
          id: uuidv7(),
          incidentId: id,
          at: now,
          type: 'fired',
          detail: {
            value: t.value,
            pendingSince: since.toISOString(),
            forSec: rule.forSec,
          },
        },
      });
      await this.enqueue(tx, rule.channelIds, incident.id, 'fired');
      await this.audit.record(
        {
          actorType: 'system',
          action: 'incident.fired',
          targetType: 'incident',
          targetId: incident.id,
          result: 'success',
          metadata: { ruleId: rule.id, kind: rule.kind, targetType: t.type, targetId: t.id },
        },
        tx,
      );
    }
    await tx.alertState.upsert({
      where: {
        ruleId_targetType_targetId: { ruleId: rule.id, targetType: t.type, targetId: t.id },
      },
      create: {
        ruleId: rule.id,
        targetType: t.type,
        targetId: t.id,
        status: 'firing',
        since,
        firedAt: now,
        lastValue: t.value,
        incidentId: incident.id,
        evaluatedAt: now,
      },
      update: {
        status: 'firing',
        firedAt: now,
        lastValue: t.value,
        incidentId: incident.id,
        evaluatedAt: now,
      },
    });
  }

  async enqueue(tx: Tx, channelIds: string[], incidentId: string, event: 'fired' | 'resolved') {
    if (channelIds.length === 0) return;
    const channels = await tx.notificationChannel.findMany({
      where: { id: { in: channelIds }, enabled: true },
      select: { id: true },
    });
    if (channels.length)
      await tx.notificationDelivery.createMany({
        data: channels.map((c) => ({ id: uuidv7(), channelId: c.id, incidentId, event })),
      });
  }

  /** Resolves an open incident (+ timeline, notifications to the rule's channels). */
  async resolve(
    tx: Tx,
    incidentId: string,
    now: Date,
    detail: Record<string, unknown>,
  ): Promise<IncidentRow | null> {
    const r = await tx.incident.updateMany({
      where: { id: incidentId, status: { not: 'resolved' } },
      data: { status: 'resolved', resolvedAt: now },
    });
    if (r.count !== 1) return null;
    const incident = await tx.incident.findUniqueOrThrow({ where: { id: incidentId } });
    await tx.incidentEvent.create({
      data: {
        id: uuidv7(),
        incidentId,
        at: now,
        type: 'resolved',
        detail: detail as Prisma.InputJsonValue,
      },
    });
    const rule = incident.ruleId
      ? await tx.alertRule.findUnique({
          where: { id: incident.ruleId },
          select: { channelIds: true },
        })
      : null;
    if (rule) await this.enqueue(tx, rule.channelIds, incidentId, 'resolved');
    await this.audit.record(
      {
        actorType: 'system',
        action: 'incident.resolved',
        targetType: 'incident',
        targetId: incidentId,
        result: 'success',
        metadata: { ruleId: incident.ruleId, ...detail },
      },
      tx,
    );
    return incident;
  }

  /** Rule disabled / deleted / kind-scope change: resolve its open incidents and drop states. */
  async clearRule(tx: Tx, ruleId: string, reason: string, now = new Date()): Promise<void> {
    const open = await tx.incident.findMany({
      where: { ruleId, status: { not: 'resolved' } },
      select: { id: true },
    });
    for (const i of open) await this.resolve(tx, i.id, now, { reason });
    await tx.alertState.deleteMany({ where: { ruleId } });
  }
}
