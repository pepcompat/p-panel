import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
} from '@nestjs/common';
import {
  type ChangeOwnershipInput,
  changeOwnershipSchema,
  STEP_UP_HEADER,
} from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { parseIfMatch } from '../servers/servers.service';
import { ApplicationsService } from './applications.service';

const uuid = new ParseUUIDPipe();

@Controller('applications')
export class ApplicationsController {
  constructor(private readonly apps: ApplicationsService) {}

  @Get()
  @RequirePermission('apps.read')
  list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.apps.list(
      user,
      parseQuery(req.originalUrl, {
        sortable: ['createdAt', 'updatedAt', 'name', 'ownershipMode'],
      }),
    );
  }

  @Get(':id')
  @RequirePermission('apps.read')
  get(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.apps.get(user, id);
  }

  /** One tier per call. →observed/downgrades: servers.operate; →adopted/managed: nginx.write (+X-Step-Up in production). */
  @Post(':id/ownership')
  @HttpCode(200)
  @RequirePermission('servers.operate')
  ownership(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(changeOwnershipSchema)) body: ChangeOwnershipInput,
    @Headers('if-match') ifMatch: string | undefined,
    @Headers(STEP_UP_HEADER.toLowerCase()) stepUp: string | undefined,
  ) {
    return this.apps.changeOwnership(user, id, body, parseIfMatch(ifMatch), stepUp);
  }

  @Get(':id/ownership-history')
  @RequirePermission('apps.read')
  history(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.apps.history(user, id);
  }

  @Post(':id/drift/acknowledge')
  @HttpCode(200)
  @RequirePermission('nginx.write')
  acknowledge(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers('if-match') ifMatch: string | undefined,
  ) {
    return this.apps.acknowledgeDrift(user, id, parseIfMatch(ifMatch));
  }
}
