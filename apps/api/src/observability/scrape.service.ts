/**
 * `GET /internal/metrics` (Prometheus text exposition, NOT under /api/v1). Static bearer from
 * PPANEL_METRICS_SCRAPE_TOKEN(_FILE). Exports the latest heartbeat sample per server/container only
 * while fresh (≤ STALE_AFTER_SEC); stale servers are omitted (Prometheus shows a gap) except
 * `ppanel_server_up 0`. Label values come from Center records only.
 */
import { Inject, Injectable } from '@nestjs/common';
import { STALE_AFTER_SEC } from '@ppanel/shared-contracts';
import type { NextFunction, Request, Response } from 'express';
import { safeEqual } from '../common/crypto';
import { logger } from '../common/logger';
import { PrismaService } from '../common/prisma.service';
import { APP_CONFIG, type AppConfig } from '../config/config';
import { deriveStatus } from '../servers/server-view';
import { type ExpositionSample, renderFamily } from './query-templates';
import { currentContainersOf } from './telemetry.service';

type Num = number | null | undefined;
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

@Injectable()
export class ScrapeService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  /** Express handler mounted before the Nest router (bypasses the user AuthGuard on purpose). */
  handler() {
    return (req: Request, res: Response, next: NextFunction): void => {
      if ((req.method !== 'GET' && req.method !== 'HEAD') || (req.path !== '/' && req.path !== ''))
        return next();
      const token = this.config.metricsScrapeToken;
      if (!token) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Route not found' } });
        return;
      }
      const m = /^Bearer\s+(\S+)$/i.exec(req.header('authorization') ?? '');
      if (!m || !safeEqual(m[1]!, token)) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        res
          .status(401)
          .json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } });
        return;
      }
      this.render()
        .then((body) => {
          res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
          res.status(200).send(body);
        })
        .catch((err: unknown) => {
          logger.emit('error', 'metrics scrape failed', { component: 'observability', err });
          res
            .status(500)
            .json({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
        });
    };
  }

  async render(now = Date.now()): Promise<string> {
    const servers = await this.prisma.server.findMany({
      where: { status: { notIn: ['revoked', 'enrolling'] } },
      select: {
        id: true,
        environment: true,
        status: true,
        lastHeartbeatAt: true,
        metrics: true,
        telemetry: { select: { agentDroppedTotal: true, centerDroppedTotal: true } },
      },
    });
    const freshCut = now - STALE_AFTER_SEC * 1000;
    const fresh = servers.filter(
      (s) => s.lastHeartbeatAt && s.lastHeartbeatAt.getTime() >= freshCut,
    );
    const fam: Record<string, ExpositionSample[]> = {};
    const add = (name: string, labels: Record<string, string>, v: Num) => {
      if (v === null || v === undefined || !Number.isFinite(v)) return;
      (fam[name] ??= []).push({ labels, value: v });
    };

    for (const s of servers) {
      const status = deriveStatus(s.status, s.lastHeartbeatAt, now);
      const l = { server_id: s.id, environment: s.environment };
      add('ppanel_server_up', l, status === 'online' || status === 'degraded' ? 1 : 0);
      const t = s.telemetry;
      add(
        'ppanel_log_dropped_entries_total',
        l,
        t ? Number(t.agentDroppedTotal + t.centerDroppedTotal) : 0,
      );
    }
    for (const s of fresh) {
      const m = (s.metrics ?? {}) as Record<string, unknown>;
      const l = { server_id: s.id, environment: s.environment };
      add('ppanel_server_cpu_percent', l, num(m.cpuPct));
      add('ppanel_server_memory_percent', l, num(m.memPct));
      add('ppanel_server_disk_percent', l, num(m.diskPct));
      add('ppanel_server_load1', l, num(m.load1));
      add('ppanel_server_net_rx_bytes_total', l, num(m.netRxBytes));
      add('ppanel_server_net_tx_bytes_total', l, num(m.netTxBytes));
    }

    // containers: only the CURRENT containers of managed apps on fresh servers (app_id from the DB)
    const freshIds = fresh.map((s) => s.id);
    const env = new Map(fresh.map((s) => [s.id, s.environment]));
    if (freshIds.length) {
      const apps = await this.prisma.application.findMany({
        where: { serverId: { in: freshIds }, kind: { in: ['container', 'compose'] } },
        select: { id: true, serverId: true, container: { select: { currentDeploymentId: true } } },
      });
      const depIds = apps.map((a) => a.container?.currentDeploymentId).filter(Boolean) as string[];
      const deps = depIds.length
        ? await this.prisma.deployment.findMany({
            where: { id: { in: depIds } },
            select: {
              id: true,
              applicationId: true,
              containerName: true,
              serviceResults: true,
              plan: true,
            },
          })
        : [];
      const current = new Map<string, { appId: string; service: string }>();
      for (const d of deps)
        for (const c of currentContainersOf(d))
          current.set(c.name, { appId: d.applicationId, service: c.service });
      const samples = await this.prisma.containerSample.findMany({
        where: { serverId: { in: freshIds }, applicationId: { not: null } },
      });
      for (const c of samples) {
        const cur = current.get(c.name);
        if (!cur || cur.appId !== c.applicationId) continue;
        if (c.sampledAt.getTime() < freshCut) continue;
        const l = {
          server_id: c.serverId,
          environment: env.get(c.serverId) ?? '',
          app_id: cur.appId,
          service: cur.service,
        };
        add('ppanel_container_cpu_percent', l, c.cpuPct);
        add('ppanel_container_memory_bytes', l, c.memBytes === null ? null : Number(c.memBytes));
        add('ppanel_container_up', l, c.state === 'running' && c.health !== 'unhealthy' ? 1 : 0);
        add('ppanel_container_restarts_total', l, c.restartCount);
      }
    }

    const families: Array<[string, 'gauge' | 'counter', string]> = [
      ['ppanel_server_up', 'gauge', 'Server agent online (1) or stale/offline (0).'],
      ['ppanel_server_cpu_percent', 'gauge', 'Host CPU utilisation percent (fresh samples only).'],
      ['ppanel_server_memory_percent', 'gauge', 'Host memory utilisation percent.'],
      ['ppanel_server_disk_percent', 'gauge', 'Root filesystem utilisation percent.'],
      ['ppanel_server_load1', 'gauge', 'Host 1-minute load average.'],
      ['ppanel_server_net_rx_bytes_total', 'counter', 'Host received bytes.'],
      ['ppanel_server_net_tx_bytes_total', 'counter', 'Host transmitted bytes.'],
      ['ppanel_container_cpu_percent', 'gauge', 'Managed container CPU percent.'],
      ['ppanel_container_memory_bytes', 'gauge', 'Managed container memory usage in bytes.'],
      ['ppanel_container_up', 'gauge', 'Managed container running and not unhealthy.'],
      ['ppanel_container_restarts_total', 'counter', 'Managed container restart count.'],
      [
        'ppanel_log_dropped_entries_total',
        'counter',
        'Log entries dropped (agent buffer overflow + rejected by the Center).',
      ],
    ];
    return (
      families
        .filter(([name]) => fam[name]?.length)
        .map(([name, type, help]) => renderFamily(name, type, help, fam[name]!))
        .join('\n') + '\n'
    );
  }
}
