import { Body, Controller, Get, HttpCode, Param, ParseUUIDPipe, Post, Req } from '@nestjs/common';
import {
  type CreateDiscoveryScanInput,
  createDiscoveryScanSchema,
  type ImportFindingsInput,
  importFindingsSchema,
} from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { DiscoveryService } from './discovery.service';

const uuid = new ParseUUIDPipe();

@Controller()
export class DiscoveryController {
  constructor(private readonly discovery: DiscoveryService) {}

  /** 202 `{ scanId, jobId }` — read-only scan; never changes ownership. */
  @Post('servers/:serverId/discovery-scans')
  @HttpCode(202)
  @RequirePermission('nginx.read')
  create(
    @CurrentUser() user: AuthUser,
    @Param('serverId', uuid) serverId: string,
    @Body(new ZodPipe(createDiscoveryScanSchema)) body: CreateDiscoveryScanInput,
  ) {
    return this.discovery.createScan(user, serverId, body);
  }

  @Get('discovery-scans')
  @RequirePermission('nginx.read')
  list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.discovery.listScans(
      user,
      parseQuery(req.originalUrl, {
        sortable: ['createdAt', 'startedAt', 'completedAt'],
        defaultSort: 'startedAt',
      }),
    );
  }

  @Get('discovery-scans/:id')
  @RequirePermission('nginx.read')
  get(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.discovery.getScan(user, id);
  }

  @Get('discovery-scans/:id/findings')
  @RequirePermission('nginx.read')
  findings(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string, @Req() req: Request) {
    return this.discovery.listFindings(
      user,
      id,
      parseQuery(req.originalUrl, {
        sortable: ['createdAt', 'kind', 'title', 'confidence'],
        defaultSort: 'createdAt',
      }),
    );
  }

  /** 201 `{ applications }` — Observe by default; adopted/managed rejected (422 IMPORT_MODE_NOT_ALLOWED). */
  @Post('discovery-scans/:id/import')
  @HttpCode(201)
  @RequirePermission('servers.operate')
  import(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(importFindingsSchema)) body: ImportFindingsInput,
  ) {
    return this.discovery.importFindings(user, id, body);
  }
}
