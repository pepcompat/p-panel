/** §9 HTTP surface: metrics, logs (query / tail token / SSE tail), alert rules, incidents, channels. */
import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import {
  acknowledgeIncidentSchema,
  createAlertRuleSchema,
  createChannelSchema,
  incidentCommentSchema,
  logsQuerySchema,
  logsTailParamsSchema,
  logsTailQuerySchema,
  metricsSeriesQuerySchema,
  updateAlertRuleSchema,
  updateChannelSchema,
} from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import type { z } from 'zod';
import { CurrentUser, Public, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { parseIfMatch } from '../servers/servers.service';
import { AlertsService } from './alerts.service';
import { ChannelsService } from './channels.service';
import { LogsService } from './logs.service';
import { MetricsService } from './metrics.service';

const uuid = new ParseUUIDPipe();

@Controller()
export class ObservabilityController {
  constructor(
    private readonly metrics: MetricsService,
    private readonly logs: LogsService,
    private readonly alerts: AlertsService,
    private readonly channels: ChannelsService,
  ) {}

  // ---------------------------------------------------------------- metrics (§9.2)

  @Get('metrics/fleet')
  @RequirePermission('fleet.read')
  fleet(@CurrentUser() user: AuthUser) {
    return this.metrics.fleet(user);
  }

  /** fleet.read (server) / apps.read (app) enforced per target in the service (out of scope → 404). */
  @Get('metrics/series')
  series(
    @CurrentUser() user: AuthUser,
    @Query(new ZodPipe(metricsSeriesQuerySchema)) q: z.infer<typeof metricsSeriesQuerySchema>,
  ) {
    return this.metrics.series(user, q);
  }

  // ---------------------------------------------------------------- logs (§9.3)

  @Get('logs/query')
  queryLogs(
    @CurrentUser() user: AuthUser,
    @Query(new ZodPipe(logsQuerySchema)) q: z.infer<typeof logsQuerySchema>,
  ) {
    return this.logs.query(user, q);
  }

  @Post('logs/tail-token')
  @HttpCode(201)
  tailToken(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(logsTailParamsSchema)) body: z.infer<typeof logsTailParamsSchema>,
  ) {
    return this.logs.createTailToken(user, body);
  }

  /** SSE; authorised by the single-use `token` query param (EventSource cannot send headers). */
  @Public()
  @Get('logs/tail')
  async tail(
    @Req() req: Request,
    @Res() res: Response,
    @Query(new ZodPipe(logsTailQuerySchema)) q: z.infer<typeof logsTailQuerySchema>,
    @Headers('last-event-id') lastEventIdHeader?: string,
  ) {
    const { token, lastEventId, ...params } = q;
    const lei =
      lastEventId ??
      (lastEventIdHeader && /^\d{1,20}$/.test(lastEventIdHeader) ? lastEventIdHeader : undefined);
    await this.logs.tail(req, res, token, params, lei);
  }

  // ---------------------------------------------------------------- alert rules (§9.4)

  @Get('alert-rules')
  @RequirePermission('policies.manage')
  listRules(@CurrentUser() user: AuthUser) {
    return this.alerts.listRules(user);
  }

  @Post('alert-rules')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createRule(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createAlertRuleSchema)) body: z.infer<typeof createAlertRuleSchema>,
  ) {
    return this.alerts.createRule(user, body);
  }

  @Get('alert-rules/:id')
  @RequirePermission('policies.manage')
  getRule(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.alerts.getRule(user, id);
  }

  @Patch('alert-rules/:id')
  @RequirePermission('policies.manage')
  updateRule(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateAlertRuleSchema)) body: z.infer<typeof updateAlertRuleSchema>,
    @Headers('if-match') ifMatch?: string,
  ) {
    return this.alerts.updateRule(user, id, body, parseIfMatch(ifMatch));
  }

  @Delete('alert-rules/:id')
  @HttpCode(204)
  @RequirePermission('policies.manage')
  async deleteRule(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers('if-match') ifMatch?: string,
  ) {
    await this.alerts.deleteRule(user, id, parseIfMatch(ifMatch));
  }

  // ---------------------------------------------------------------- incidents

  @Get('incidents')
  @RequirePermission('fleet.read')
  listIncidents(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.alerts.listIncidents(
      user,
      parseQuery(req.originalUrl, {
        sortable: ['startedAt', 'severity', 'status', 'createdAt'],
        defaultSort: 'startedAt',
      }),
    );
  }

  @Get('incidents/:id')
  @RequirePermission('fleet.read')
  getIncident(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.alerts.getIncident(user, id);
  }

  @Post('incidents/:id/acknowledge')
  @HttpCode(200)
  @RequirePermission('fleet.read')
  acknowledge(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(acknowledgeIncidentSchema)) body: z.infer<typeof acknowledgeIncidentSchema>,
  ) {
    return this.alerts.acknowledge(user, id, body.comment);
  }

  @Post('incidents/:id/comment')
  @HttpCode(201)
  @RequirePermission('fleet.read')
  comment(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(incidentCommentSchema)) body: z.infer<typeof incidentCommentSchema>,
  ) {
    return this.alerts.comment(user, id, body.comment);
  }

  // ---------------------------------------------------------------- notification channels

  @Get('notification-channels')
  @RequirePermission('policies.manage')
  listChannels(@CurrentUser() user: AuthUser) {
    return this.channels.list(user);
  }

  @Post('notification-channels')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createChannel(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createChannelSchema)) body: z.infer<typeof createChannelSchema>,
  ) {
    return this.channels.create(user, body);
  }

  @Get('notification-channels/:id')
  @RequirePermission('policies.manage')
  getChannel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.channels.get(user, id);
  }

  @Patch('notification-channels/:id')
  @RequirePermission('policies.manage')
  updateChannel(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateChannelSchema)) body: z.infer<typeof updateChannelSchema>,
    @Headers('if-match') ifMatch?: string,
  ) {
    return this.channels.update(user, id, body, parseIfMatch(ifMatch));
  }

  @Delete('notification-channels/:id')
  @HttpCode(204)
  @RequirePermission('policies.manage')
  async deleteChannel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    await this.channels.remove(user, id);
  }

  @Post('notification-channels/:id/test')
  @HttpCode(200)
  @RequirePermission('policies.manage')
  testChannel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.channels.test(user, id);
  }
}
