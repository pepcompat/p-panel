/** Alert rule CRUD (perm `policies.manage` covering the rule scope; If-Match) + incidents API. */
import { Injectable } from '@nestjs/common';
import {
  ACTIVE_ALERT_KINDS,
  type AlertKind,
  type AlertRule,
  type AlertRuleAction,
  type AlertScopeType,
  type AlertSeverity,
  type CreateAlertRuleInput,
  type Environment,
  ERROR_CODES,
  type Incident,
  type IncidentAction,
  type IncidentEvent,
  type IncidentEventType,
  type IncidentStatus,
  type IncidentTargetType,
  parseAlertParams,
  type UpdateAlertRuleInput,
  validateAlertRule,
} from '@ppanel/shared-contracts';
import type { AlertRule as RuleRow, Incident as IncidentRow, Prisma } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthzService, type ResourceScope } from '../auth/authz.service';
import { AppError } from '../common/app-error';
import { Paginated } from '../common/envelope';
import { uuidv7 } from '../common/ids';
import { PrismaService } from '../common/prisma.service';
import type { AuthUser } from '../common/principal';
import { buildWhere, type FieldMap, paginate, type ParsedQuery } from '../common/query-builder';
import { AlertEngineService } from './alert-engine.service';

const INCIDENT_FIELDS: FieldMap = {
  status: { prop: 'status', type: 'string' },
  severity: { prop: 'severity', type: 'string' },
  target_type: { prop: 'targetType', type: 'string' },
  target_id: { prop: 'targetId', type: 'uuid' },
  kind: { prop: 'kind', type: 'string' },
  server_id: { prop: 'serverId', type: 'uuid' },
  rule_id: { prop: 'ruleId', type: 'uuid' },
  environment: { prop: 'environment', type: 'string' },
  started_at: { prop: 'startedAt', type: 'date' },
};

@Injectable()
export class AlertsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authz: AuthzService,
    private readonly audit: AuditService,
    private readonly engine: AlertEngineService,
  ) {}

  // ------------------------------------------------------------------------------ rules

  /** Authorization target for a rule scope; undefined = global (only global bindings). */
  private async scopeTarget(
    scopeType: AlertScopeType,
    scopeId: string | null | undefined,
  ): Promise<ResourceScope | undefined | null> {
    if (scopeType === 'global') return undefined;
    if (scopeType === 'environment') return { environment: scopeId ?? '' };
    if (scopeType === 'server') {
      const s = await this.prisma.server.findUnique({
        where: { id: scopeId ?? '' },
        select: { id: true, environment: true },
      });
      return s ? { serverId: s.id, environment: s.environment } : null;
    }
    const a = await this.prisma.application.findUnique({
      where: { id: scopeId ?? '' },
      select: { server: { select: { id: true, environment: true } } },
    });
    return a ? { serverId: a.server.id, environment: a.server.environment } : null;
  }

  private async enforceScope(
    user: AuthUser,
    scopeType: AlertScopeType,
    scopeId: string | null | undefined,
    action: string,
    ruleId?: string,
  ): Promise<void> {
    const target = await this.scopeTarget(scopeType, scopeId);
    if (target === null)
      throw AppError.validation([{ path: 'scopeId', message: `${scopeType} not found` }]);
    await this.authz.enforce(user, 'policies.manage', target, {
      action,
      targetType: 'alert_rule',
      targetId: ruleId ?? null,
    });
  }

  private async checkChannels(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    const n = await this.prisma.notificationChannel.count({ where: { id: { in: ids } } });
    if (n !== new Set(ids).size)
      throw new AppError(422, ERROR_CODES.CHANNEL_NOT_FOUND, 'Unknown notification channel', {
        channelIds: ids,
      });
  }

  private ruleView(r: RuleRow, actions: AlertRuleAction[]): AlertRule {
    return {
      id: r.id,
      name: r.name,
      enabled: r.enabled,
      scopeType: r.scopeType as AlertScopeType,
      scopeId: r.scopeId,
      kind: r.kind as AlertKind,
      params: r.params as Record<string, unknown>,
      severity: r.severity as AlertSeverity,
      forSec: r.forSec,
      channelIds: r.channelIds,
      active: ACTIVE_ALERT_KINDS.includes(r.kind as AlertKind),
      createdBy: r.createdBy,
      version: r.version,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      allowedActions: actions,
    };
  }

  private async canManage(user: AuthUser, r: RuleRow): Promise<boolean> {
    const target = await this.scopeTarget(r.scopeType as AlertScopeType, r.scopeId);
    if (target === null) return this.authz.can(user, 'policies.manage'); // orphaned → global admins
    return this.authz.can(user, 'policies.manage', target);
  }

  async listRules(user: AuthUser): Promise<AlertRule[]> {
    const rows = await this.prisma.alertRule.findMany({ orderBy: { createdAt: 'asc' } });
    const out: AlertRule[] = [];
    for (const r of rows)
      if (await this.canManage(user, r)) out.push(this.ruleView(r, ['edit', 'delete']));
    return out;
  }

  private async loadRule(user: AuthUser, id: string): Promise<RuleRow> {
    const r = await this.prisma.alertRule.findUnique({ where: { id } });
    if (!r || !(await this.canManage(user, r))) throw AppError.notFound('Alert rule');
    return r;
  }

  async getRule(user: AuthUser, id: string): Promise<AlertRule> {
    return this.ruleView(await this.loadRule(user, id), ['edit', 'delete']);
  }

  async createRule(user: AuthUser, input: CreateAlertRuleInput): Promise<AlertRule> {
    await this.enforceScope(user, input.scopeType, input.scopeId, 'alert_rule.create');
    await this.checkChannels(input.channelIds);
    const params = parseAlertParams(input.kind, input.params);
    if (!params.success) throw AppError.validation(params.issues);
    const id = uuidv7();
    const row = await this.prisma.$transaction(async (tx) => {
      const r = await tx.alertRule.create({
        data: {
          id,
          name: input.name,
          enabled: input.enabled,
          scopeType: input.scopeType,
          scopeId: input.scopeType === 'global' ? null : (input.scopeId ?? null),
          kind: input.kind,
          params: params.data as Prisma.InputJsonValue,
          severity: input.severity,
          forSec: input.forSec,
          channelIds: [...new Set(input.channelIds)],
          createdBy: user.id,
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'alert_rule.create',
          targetType: 'alert_rule',
          targetId: id,
          result: 'success',
          diff: { ...input, params: params.data },
          metadata: { kind: input.kind, scopeType: input.scopeType },
        },
        tx,
      );
      return r;
    });
    return this.ruleView(row, ['edit', 'delete']);
  }

  async updateRule(
    user: AuthUser,
    id: string,
    input: UpdateAlertRuleInput,
    ifMatch?: number,
  ): Promise<AlertRule> {
    const r = await this.loadRule(user, id);
    await this.enforceScope(
      user,
      r.scopeType as AlertScopeType,
      r.scopeId,
      'alert_rule.update',
      id,
    );
    if (ifMatch !== undefined && ifMatch !== r.version)
      throw AppError.conflict('Alert rule was modified', ERROR_CODES.VERSION_CONFLICT, {
        currentVersion: r.version,
      });
    const scopeType = (input.scopeType ?? r.scopeType) as AlertScopeType;
    const scopeId =
      scopeType === 'global' ? null : input.scopeId !== undefined ? input.scopeId : r.scopeId;
    const merged = {
      kind: r.kind as AlertKind,
      scopeType,
      scopeId,
      params: input.params ?? r.params,
    };
    const issues = validateAlertRule(merged);
    if (issues.length) throw AppError.validation(issues);
    const params = parseAlertParams(merged.kind, merged.params);
    if (!params.success) throw AppError.validation(params.issues);
    if (input.scopeType !== undefined || input.scopeId !== undefined)
      await this.enforceScope(user, scopeType, scopeId, 'alert_rule.update', id);
    if (input.channelIds) await this.checkChannels(input.channelIds);
    const scopeChanged = scopeType !== r.scopeType || scopeId !== r.scopeId;
    const row = await this.prisma.$transaction(async (tx) => {
      const u = await tx.alertRule.updateMany({
        where: { id, version: r.version },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          ...(input.severity !== undefined ? { severity: input.severity } : {}),
          ...(input.forSec !== undefined ? { forSec: input.forSec } : {}),
          ...(input.channelIds !== undefined ? { channelIds: [...new Set(input.channelIds)] } : {}),
          scopeType,
          scopeId,
          params: params.data as Prisma.InputJsonValue,
          updatedBy: user.id,
          version: { increment: 1 },
        },
      });
      if (u.count !== 1)
        throw AppError.conflict('Alert rule was modified', ERROR_CODES.VERSION_CONFLICT);
      if (input.enabled === false && r.enabled)
        await this.engine.clearRule(tx, id, 'rule_disabled');
      else if (scopeChanged) await this.engine.clearRule(tx, id, 'rule_scope_changed');
      await this.audit.record(
        {
          actorId: user.id,
          action: 'alert_rule.update',
          targetType: 'alert_rule',
          targetId: id,
          result: 'success',
          diff: input,
          metadata: { fields: Object.keys(input) },
        },
        tx,
      );
      return tx.alertRule.findUniqueOrThrow({ where: { id } });
    });
    return this.ruleView(row, ['edit', 'delete']);
  }

  async deleteRule(user: AuthUser, id: string, ifMatch?: number): Promise<void> {
    const r = await this.loadRule(user, id);
    await this.enforceScope(
      user,
      r.scopeType as AlertScopeType,
      r.scopeId,
      'alert_rule.delete',
      id,
    );
    if (ifMatch !== undefined && ifMatch !== r.version)
      throw AppError.conflict('Alert rule was modified', ERROR_CODES.VERSION_CONFLICT, {
        currentVersion: r.version,
      });
    await this.prisma.$transaction(async (tx) => {
      await this.engine.clearRule(tx, id, 'rule_deleted');
      await tx.alertRule.delete({ where: { id } });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'alert_rule.delete',
          targetType: 'alert_rule',
          targetId: id,
          result: 'success',
          metadata: { kind: r.kind, name: r.name },
        },
        tx,
      );
    });
  }

  // ------------------------------------------------------------------------------ incidents

  private incidentScope(i: { serverId: string; environment: string }): ResourceScope {
    return { serverId: i.serverId, environment: i.environment };
  }

  private incidentActions(user: AuthUser, i: IncidentRow): IncidentAction[] {
    if (!this.authz.can(user, 'servers.operate', this.incidentScope(i))) return [];
    return i.status === 'firing' ? ['acknowledge', 'comment'] : ['comment'];
  }

  private async userNames(ids: string[]): Promise<Map<string, string>> {
    const uniq = [...new Set(ids.filter(Boolean))];
    if (!uniq.length) return new Map();
    const rows = await this.prisma.user.findMany({
      where: { id: { in: uniq } },
      select: { id: true, displayName: true },
    });
    return new Map(rows.map((u) => [u.id, u.displayName]));
  }

  private incidentView(
    user: AuthUser,
    i: IncidentRow,
    names: Map<string, string>,
    timeline?: IncidentEvent[],
  ): Incident {
    return {
      id: i.id,
      ruleId: i.ruleId,
      ruleName: i.ruleName,
      kind: i.kind as AlertKind,
      target: { type: i.targetType as IncidentTargetType, id: i.targetId, name: i.targetName },
      serverId: i.serverId,
      environment: i.environment as Environment,
      severity: i.severity as AlertSeverity,
      status: i.status as IncidentStatus,
      startedAt: i.startedAt.toISOString(),
      acknowledgedAt: i.acknowledgedAt?.toISOString() ?? null,
      acknowledgedBy: i.acknowledgedById
        ? { id: i.acknowledgedById, displayName: names.get(i.acknowledgedById) ?? 'unknown' }
        : null,
      resolvedAt: i.resolvedAt?.toISOString() ?? null,
      lastValue: i.lastValue,
      ...(timeline ? { timeline } : {}),
      allowedActions: this.incidentActions(user, i),
    };
  }

  async listIncidents(user: AuthUser, pq: ParsedQuery) {
    const scope = this.authz.serverWhere(user, 'fleet.read');
    if (!scope) throw AppError.forbidden();
    for (const f of pq.filters)
      if (!INCIDENT_FIELDS[f.field]) throw AppError.badRequest(`Unknown filter ${f.field}`);
    const where: Prisma.IncidentWhereInput = {
      AND: [{ server: scope }, buildWhere(pq, INCIDENT_FIELDS) as Prisma.IncidentWhereInput],
    };
    const sortProp = pq.sort === 'createdAt' ? 'startedAt' : pq.sort;
    const [rows, total] = await Promise.all([
      this.prisma.incident.findMany({
        where,
        orderBy: [{ [sortProp]: pq.order }, { id: pq.order }],
        skip: pq.skip,
        take: pq.limit,
      }),
      this.prisma.incident.count({ where }),
    ]);
    const names = await this.userNames(rows.map((r) => r.acknowledgedById ?? ''));
    return new Paginated(
      rows.map((r) => this.incidentView(user, r, names)),
      paginate(pq, total),
    );
  }

  private async loadIncident(user: AuthUser, id: string): Promise<IncidentRow> {
    const i = await this.prisma.incident.findUnique({ where: { id } });
    if (!i || !this.authz.can(user, 'fleet.read', this.incidentScope(i)))
      throw AppError.notFound('Incident');
    return i;
  }

  async getIncident(user: AuthUser, id: string): Promise<Incident> {
    const i = await this.loadIncident(user, id);
    const events = await this.prisma.incidentEvent.findMany({
      where: { incidentId: id },
      orderBy: [{ at: 'asc' }, { id: 'asc' }],
    });
    const names = await this.userNames([
      i.acknowledgedById ?? '',
      ...events.map((e) => e.actorId ?? ''),
    ]);
    const timeline: IncidentEvent[] = events.map((e) => ({
      at: e.at.toISOString(),
      type: e.type as IncidentEventType,
      actor: e.actorId ? { id: e.actorId, displayName: names.get(e.actorId) ?? 'unknown' } : null,
      detail: e.detail as Record<string, unknown>,
    }));
    return this.incidentView(user, i, names, timeline);
  }

  async acknowledge(user: AuthUser, id: string, comment?: string): Promise<Incident> {
    const i = await this.loadIncident(user, id);
    await this.authz.enforce(user, 'servers.operate', this.incidentScope(i), {
      action: 'incident.acknowledge',
      targetType: 'incident',
      targetId: id,
    });
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      const r = await tx.incident.updateMany({
        where: { id, status: 'firing' },
        data: { status: 'acknowledged', acknowledgedAt: now, acknowledgedById: user.id },
      });
      if (r.count !== 1)
        throw AppError.conflict(
          `Incident is ${i.status === 'firing' ? 'no longer firing' : i.status}`,
          ERROR_CODES.INCIDENT_STATE_INVALID,
          { status: i.status },
        );
      await tx.incidentEvent.create({
        data: {
          id: uuidv7(),
          incidentId: id,
          at: now,
          type: 'acknowledged',
          actorId: user.id,
          detail: comment ? { comment } : {},
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'incident.acknowledge',
          targetType: 'incident',
          targetId: id,
          result: 'success',
          metadata: { ruleId: i.ruleId, hasComment: !!comment },
        },
        tx,
      );
    });
    return this.getIncident(user, id);
  }

  async comment(user: AuthUser, id: string, comment: string): Promise<Incident> {
    const i = await this.loadIncident(user, id);
    await this.authz.enforce(user, 'servers.operate', this.incidentScope(i), {
      action: 'incident.comment',
      targetType: 'incident',
      targetId: id,
    });
    await this.prisma.$transaction(async (tx) => {
      await tx.incidentEvent.create({
        data: {
          id: uuidv7(),
          incidentId: id,
          type: 'comment',
          actorId: user.id,
          detail: { comment },
        },
      });
      await this.audit.record(
        {
          actorId: user.id,
          action: 'incident.comment',
          targetType: 'incident',
          targetId: id,
          result: 'success',
        },
        tx,
      );
    });
    return this.getIncident(user, id);
  }
}
