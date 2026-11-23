/** §9.2 Metrics API: DB fleet summary + scope-enforced Prometheus series from fixed templates. */
import { Injectable } from '@nestjs/common';
import {
  APP_METRIC_UNITS,
  type AppMetric,
  type Environment,
  type FleetMetric,
  METRIC_AUTO_STEP_SECONDS,
  METRIC_RANGE_SECONDS,
  type MetricSeries,
  type MetricsSeriesQuery,
  SERVER_METRIC_UNITS,
  type ServerMetric,
  STALE_AFTER_SEC,
} from '@ppanel/shared-contracts';
import { AuthzService } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { RateLimiter } from '../common/rate-limiter';
import { deriveStatus } from '../servers/server-view';
import { BackendUnavailableError, metricsUnavailable, PrometheusClient } from './backends';
import { appPromQL, fillGrid, gapsOf, serverPromQL } from './query-templates';
import { MANAGED_APP_KINDS, TelemetryService } from './telemetry.service';

export const METRICS_RATE_LIMIT = 60;

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

@Injectable()
export class MetricsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly limiter: RateLimiter,
    private readonly telemetry: TelemetryService,
    private readonly prom: PrometheusClient,
  ) {}

  private limit(user: AuthUser): void {
    this.limiter.hit(`metrics:${user.id}`, METRICS_RATE_LIMIT, 60_000);
  }

  async fleet(user: AuthUser, now = Date.now()): Promise<FleetMetric[]> {
    this.limit(user);
    const servers = await this.telemetry.serversInScope(user, 'fleet.read');
    if (servers.length === 0) return [];
    const ids = servers.map((s) => s.id);
    const [samples, telemetry] = await Promise.all([
      this.prisma.containerSample.findMany({
        where: { serverId: { in: ids } },
        select: { serverId: true, state: true, health: true },
      }),
      this.prisma.serverTelemetry.findMany({ where: { serverId: { in: ids } } }),
    ]);
    const tel = new Map(telemetry.map((t) => [t.serverId, t]));
    return servers.map((s) => {
      const status = deriveStatus(s.status, s.lastHeartbeatAt, now);
      const stale = status !== 'online' && status !== 'degraded';
      const m = (s.metrics ?? null) as Record<string, unknown> | null;
      const own = samples.filter((c) => c.serverId === s.id);
      const t = tel.get(s.id);
      const ship = (t?.logShipping ?? null) as FleetMetric['logShipping'];
      return {
        serverId: s.id,
        name: s.name,
        environment: s.environment as Environment,
        status,
        sample:
          m && s.metricsSampledAt
            ? {
                cpuPct: num(m.cpuPct),
                memPct: num(m.memPct),
                diskPct: num(m.diskPct),
                load1: num(m.load1),
                sampledAt: s.metricsSampledAt.toISOString(),
              }
            : null,
        stale,
        containers: {
          total: own.length,
          running: own.filter((c) => c.state === 'running').length,
          unhealthy: own.filter((c) => c.health === 'unhealthy').length,
        },
        logShipping: ship
          ? {
              bufferedBytes: ship.bufferedBytes,
              bufferCapBytes: ship.bufferCapBytes ?? null,
              droppedEntries: ship.droppedEntries,
              lastShippedAt: ship.lastShippedAt ?? null,
            }
          : null,
        logDroppedTotal: t ? Number(t.agentDroppedTotal + t.centerDroppedTotal) : 0,
      };
    });
  }

  async series(user: AuthUser, q: MetricsSeriesQuery, now = Date.now()): Promise<MetricSeries> {
    this.limit(user);
    const step = q.step === 'auto' ? METRIC_AUTO_STEP_SECONDS[q.range] : q.step;
    const end = Math.floor(now / 1000 / step) * step;
    const start = end - Math.floor(METRIC_RANGE_SECONDS[q.range] / step) * step;
    let promql: string;
    let lastSampleAt: string | null;
    let stale: boolean;
    let unit;
    if (q.scope === 'server') {
      const s = await this.prisma.server.findUnique({
        where: { id: q.id },
        select: {
          id: true,
          environment: true,
          status: true,
          lastHeartbeatAt: true,
          metricsSampledAt: true,
        },
      });
      // out of scope looks exactly like missing (no existence oracle)
      if (!s || !this.authz.can(user, 'fleet.read', { serverId: s.id, environment: s.environment }))
        throw AppError.notFound('Server');
      const status = deriveStatus(s.status, s.lastHeartbeatAt, now);
      stale = status !== 'online' && status !== 'degraded';
      lastSampleAt = s.metricsSampledAt?.toISOString() ?? null;
      promql = serverPromQL(q.metric as ServerMetric, s.id, step);
      unit = SERVER_METRIC_UNITS[q.metric as ServerMetric];
    } else {
      const app = await this.prisma.application.findUnique({
        where: { id: q.id },
        select: {
          id: true,
          kind: true,
          server: { select: { id: true, environment: true, status: true, lastHeartbeatAt: true } },
        },
      });
      if (
        !app ||
        !MANAGED_APP_KINDS.includes(app.kind) ||
        !this.authz.can(user, 'apps.read', {
          serverId: app.server.id,
          environment: app.server.environment,
        })
      )
        throw AppError.notFound('Application');
      const latest = await this.prisma.containerSample.findFirst({
        where: { applicationId: app.id },
        orderBy: { sampledAt: 'desc' },
        select: { sampledAt: true },
      });
      const status = deriveStatus(app.server.status, app.server.lastHeartbeatAt, now);
      lastSampleAt = latest?.sampledAt.toISOString() ?? null;
      stale =
        (status !== 'online' && status !== 'degraded') ||
        !latest ||
        latest.sampledAt.getTime() < now - STALE_AFTER_SEC * 1000;
      promql = appPromQL(q.metric as AppMetric, app.id);
      unit = APP_METRIC_UNITS[q.metric as AppMetric];
    }
    let result;
    try {
      result = await this.prom.queryRange(promql, start, end, step);
    } catch (err) {
      if (err instanceof BackendUnavailableError) throw metricsUnavailable();
      throw err;
    }
    const values = result.flatMap((r) => r.values);
    const points = fillGrid(start, end, step, values);
    return {
      scope: q.scope,
      id: q.id,
      metric: q.metric,
      unit,
      range: q.range,
      step,
      from: start,
      to: end,
      points,
      gaps: gapsOf(points),
      lastSampleAt,
      stale,
    };
  }
}
