import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import {
  approveNginxRevisionSchema,
  type CreateNginxRevisionInput,
  createNginxRevisionSchema,
  STEP_UP_HEADER,
} from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import { AppError } from '../common/app-error';
import { CurrentUser, RequirePermission } from '../common/decorators';
import { UUID_RE } from '../common/ids';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { NginxRevisionsService } from './nginx-revisions.service';

const uuid = new ParseUUIDPipe();
const STEP_UP = STEP_UP_HEADER.toLowerCase();

@Controller()
export class NginxRevisionsController {
  constructor(private readonly revisions: NginxRevisionsService) {}

  /** 200 `{ jobId, status: "succeeded", files }` or 202 `{ jobId, status: "pending", files: [] }` (poll with ?jobId=). */
  @Get('applications/:id/nginx/files')
  @RequirePermission('nginx.read')
  async files(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Query('jobId') jobId: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (jobId !== undefined && !UUID_RE.test(jobId))
      throw AppError.badRequest('jobId must be a uuid');
    const r = await this.revisions.readFiles(user, id, jobId);
    res.status(r.pending ? 202 : 200);
    return r.body;
  }

  @Post('applications/:id/nginx/revisions')
  @HttpCode(201)
  @RequirePermission('nginx.write')
  create(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(createNginxRevisionSchema)) body: CreateNginxRevisionInput,
  ) {
    return this.revisions.create(user, id, body);
  }

  @Get('applications/:id/nginx/revisions')
  @RequirePermission('nginx.read')
  list(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string, @Req() req: Request) {
    return this.revisions.list(
      user,
      id,
      parseQuery(req.originalUrl, { sortable: ['createdAt', 'updatedAt', 'status'] }),
    );
  }

  @Get('nginx-revisions/:id')
  @RequirePermission('nginx.read')
  get(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.revisions.get(user, id);
  }

  @Post('nginx-revisions/:id/validate')
  @HttpCode(202)
  @RequirePermission('nginx.write')
  validate(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.revisions.validate(user, id);
  }

  @Post('nginx-revisions/:id/approve')
  @HttpCode(200)
  @RequirePermission('approvals.decide')
  approve(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(approveNginxRevisionSchema)) body: { planHash: string },
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.revisions.approve(user, id, body.planHash, stepUp);
  }

  @Post('nginx-revisions/:id/apply')
  @HttpCode(202)
  @RequirePermission('nginx.write')
  apply(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.revisions.apply(user, id, stepUp);
  }

  @Post('nginx-revisions/:id/revert')
  @HttpCode(202)
  @RequirePermission('nginx.write')
  revert(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.revisions.revert(user, id, stepUp);
  }

  @Post('nginx-revisions/:id/cancel')
  @HttpCode(200)
  @RequirePermission('nginx.write')
  cancel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.revisions.cancel(user, id);
  }
}
