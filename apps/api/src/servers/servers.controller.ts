import {
  Body,
  Controller,
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
  STEP_UP_HEADER,
  type UpdateServerInput,
  updateServerSchema,
} from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { parseIfMatch, ServersService } from './servers.service';

const uuid = new ParseUUIDPipe();

@Controller('servers')
export class ServersController {
  constructor(private readonly servers: ServersService) {}

  @Get()
  @RequirePermission('fleet.read')
  list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.servers.list(
      user,
      parseQuery(req.originalUrl, {
        sortable: ['createdAt', 'name', 'lastHeartbeatAt', 'environment'],
      }),
    );
  }

  @Get(':id')
  @RequirePermission('fleet.read')
  async get(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const s = await this.servers.get(user, id);
    res.setHeader('ETag', `"${s.version}"`);
    return s;
  }

  @Patch(':id')
  @RequirePermission('servers.operate')
  async update(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateServerSchema)) body: UpdateServerInput,
    @Headers('if-match') ifMatch: string | undefined,
    @Headers(STEP_UP_HEADER.toLowerCase()) stepUp: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const s = await this.servers.update(user, id, body, parseIfMatch(ifMatch), stepUp);
    res.setHeader('ETag', `"${s.version}"`);
    return s;
  }

  @Post(':id/revoke')
  @HttpCode(200)
  @RequirePermission('servers.revoke')
  revoke(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP_HEADER.toLowerCase()) stepUp: string | undefined,
  ) {
    return this.servers.revoke(user, id, stepUp);
  }

  @Get(':id/heartbeats')
  @RequirePermission('fleet.read')
  heartbeats(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Query('limit') limit: string | undefined,
  ) {
    return this.servers.heartbeats(user, id, limit);
  }
}
