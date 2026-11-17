import { Body, Controller, Get, Headers, HttpCode, Param, ParseUUIDPipe, Post, Req, Res } from '@nestjs/common';
import { type CreateJobInput, createJobSchema, STEP_UP_HEADER } from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { JobsService } from './jobs.service';

const uuid = new ParseUUIDPipe();

@Controller('servers/:serverId/jobs')
export class JobsController {
  constructor(private readonly jobs: JobsService) {}

  /** 202 `{ jobId, status, job }` for a new job; 200 with the existing job for a repeated Idempotency-Key. */
  @Post()
  @RequirePermission('servers.operate')
  async create(
    @CurrentUser() user: AuthUser,
    @Param('serverId', uuid) serverId: string,
    @Body(new ZodPipe(createJobSchema)) body: CreateJobInput,
    @Headers('idempotency-key') idempotencyKey: string | undefined,
    @Headers(STEP_UP_HEADER.toLowerCase()) stepUp: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { created, job } = await this.jobs.create(user, serverId, body, idempotencyKey, stepUp);
    res.status(created ? 202 : 200);
    return { jobId: job.id, status: job.status, job };
  }

  @Get()
  @RequirePermission('fleet.read')
  list(@CurrentUser() user: AuthUser, @Param('serverId', uuid) serverId: string, @Req() req: Request) {
    return this.jobs.list(user, serverId, parseQuery(req.originalUrl, { sortable: ['createdAt', 'updatedAt', 'status'] }));
  }

  @Get(':jobId')
  @RequirePermission('fleet.read')
  get(@CurrentUser() user: AuthUser, @Param('serverId', uuid) serverId: string, @Param('jobId', uuid) jobId: string) {
    return this.jobs.get(user, serverId, jobId);
  }

  @Post(':jobId/cancel')
  @HttpCode(200)
  @RequirePermission('servers.operate')
  cancel(@CurrentUser() user: AuthUser, @Param('serverId', uuid) serverId: string, @Param('jobId', uuid) jobId: string) {
    return this.jobs.cancel(user, serverId, jobId);
  }
}
