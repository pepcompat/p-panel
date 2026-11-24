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
  Req,
} from '@nestjs/common';
import {
  approveGatewayPlanSchema,
  type CreateConnectivityTestInput,
  createConnectivityTestSchema,
  type CreateGatewayInput,
  type CreateGatewayRouteInput,
  createGatewayRouteSchema,
  createGatewaySchema,
  type CreateNetworkDiagnosticsInput,
  createNetworkDiagnosticsSchema,
  type CreateProviderIntegrationInput,
  createProviderIntegrationSchema,
  type NetworkInventoryInput,
  networkInventoryInputSchema,
  type ShadowTestInput,
  shadowTestSchema,
  STEP_UP_HEADER,
  type UpdateGatewayRouteInput,
  updateGatewayRouteSchema,
} from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { DiagnosticsService } from './diagnostics.service';
import { GatewaysService } from './gateways.service';
import { NetworkService } from './network.service';
import { ProviderService } from './provider.service';

const uuid = new ParseUUIDPipe();
const STEP_UP = STEP_UP_HEADER.toLowerCase();

/**
 * P9 network API (docs/P9_NETWORK_CONTRACT.md). Permission mapping: contract `servers.manage` →
 * `servers.operate`, `settings.manage` → global `policies.manage` (no new permissions).
 */
@Controller()
export class NetworkController {
  constructor(
    private readonly providers: ProviderService,
    private readonly network: NetworkService,
    private readonly diagnostics: DiagnosticsService,
  ) {}

  // ---------------------------------------------------------------- §2 provider inventory

  @Get('provider-integrations')
  @RequirePermission('policies.manage')
  listProviders(@CurrentUser() user: AuthUser) {
    return this.providers.list(user);
  }

  @Post('provider-integrations')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createProvider(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createProviderIntegrationSchema)) body: CreateProviderIntegrationInput,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.providers.create(user, body, stepUp);
  }

  @Delete('provider-integrations/:id')
  @HttpCode(204)
  @RequirePermission('policies.manage')
  async deleteProvider(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
  ): Promise<void> {
    await this.providers.remove(user, id);
  }

  @Post('provider-integrations/:id/sync')
  @HttpCode(202)
  @RequirePermission('policies.manage')
  syncProvider(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.providers.startSync(user, id);
  }

  @Post('network/inventory')
  @HttpCode(200)
  @RequirePermission('servers.operate')
  importInventory(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(networkInventoryInputSchema)) body: NetworkInventoryInput,
  ) {
    return this.network.importInventory(user, body);
  }

  @Get('network/topology')
  @RequirePermission('fleet.read')
  topology(@CurrentUser() user: AuthUser) {
    return this.network.topology(user);
  }

  // ---------------------------------------------------------------- §4 diagnostics

  @Post('servers/:id/network-diagnostics')
  @HttpCode(202)
  @RequirePermission('servers.operate')
  diagnose(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(createNetworkDiagnosticsSchema)) body: CreateNetworkDiagnosticsInput,
  ) {
    return this.diagnostics.diagnose(user, id, body);
  }

  @Get('servers/:id/network-diagnostics')
  @RequirePermission('fleet.read')
  listDiagnostics(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Req() req: Request,
  ) {
    return this.diagnostics.list(
      user,
      id,
      parseQuery(req.originalUrl, { sortable: ['createdAt'] }),
    );
  }

  @Get('network-diagnostics/:testId')
  @RequirePermission('fleet.read')
  getDiagnostics(@CurrentUser() user: AuthUser, @Param('testId', uuid) testId: string) {
    return this.diagnostics.get(user, testId);
  }

  @Post('network/connectivity-tests')
  @HttpCode(202)
  @RequirePermission('servers.operate')
  pair(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createConnectivityTestSchema)) body: CreateConnectivityTestInput,
  ) {
    return this.diagnostics.pair(user, body);
  }
}

/** P9 §5 Gateway routing (`policies.manage`; approvals `approvals.decide`). */
@Controller()
export class GatewaysController {
  constructor(private readonly gateways: GatewaysService) {}

  @Get('gateways')
  @RequirePermission('fleet.read')
  list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.gateways.list(
      user,
      parseQuery(req.originalUrl, { sortable: ['createdAt', 'name'], defaultSort: 'createdAt' }),
    );
  }

  @Post('gateways')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  create(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createGatewaySchema)) body: CreateGatewayInput,
  ) {
    return this.gateways.create(user, body);
  }

  @Get('gateways/:id')
  @RequirePermission('fleet.read')
  get(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.gateways.get(user, id);
  }

  @Delete('gateways/:id')
  @HttpCode(204)
  @RequirePermission('policies.manage')
  async remove(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string): Promise<void> {
    await this.gateways.remove(user, id);
  }

  @Get('gateways/:id/routes')
  @RequirePermission('fleet.read')
  routes(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string, @Req() req: Request) {
    return this.gateways.listRoutes(
      user,
      id,
      parseQuery(req.originalUrl, { sortable: ['createdAt', 'domain'], defaultSort: 'domain' }),
    );
  }

  @Post('gateways/:id/routes')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createRoute(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(createGatewayRouteSchema)) body: CreateGatewayRouteInput,
  ) {
    return this.gateways.createRoute(user, id, body);
  }

  @Patch('gateways/:id/routes/:routeId')
  @RequirePermission('policies.manage')
  updateRoute(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('routeId', uuid) routeId: string,
    @Body(new ZodPipe(updateGatewayRouteSchema)) body: UpdateGatewayRouteInput,
  ) {
    return this.gateways.updateRoute(user, id, routeId, body);
  }

  @Delete('gateways/:id/routes/:routeId')
  @HttpCode(204)
  @RequirePermission('policies.manage')
  async removeRoute(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('routeId', uuid) routeId: string,
  ): Promise<void> {
    await this.gateways.removeRoute(user, id, routeId);
  }

  @Post('gateways/:id/plans')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createPlan(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.gateways.createPlan(user, id);
  }

  @Get('gateways/:id/plans')
  @RequirePermission('fleet.read')
  plans(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string, @Req() req: Request) {
    return this.gateways.listPlans(
      user,
      id,
      parseQuery(req.originalUrl, { sortable: ['createdAt'] }),
    );
  }

  @Get('gateway-plans/:id')
  @RequirePermission('fleet.read')
  plan(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.gateways.getPlan(user, id);
  }

  @Post('gateway-plans/:id/shadow-test')
  @HttpCode(202)
  @RequirePermission('policies.manage')
  shadowTest(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(shadowTestSchema)) body: ShadowTestInput,
  ) {
    return this.gateways.shadowTest(user, id, body);
  }

  @Post('gateway-plans/:id/approve')
  @HttpCode(200)
  @RequirePermission('approvals.decide')
  approve(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(approveGatewayPlanSchema)) body: { planHash: string },
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.gateways.approve(user, id, body.planHash, stepUp);
  }

  @Post('gateway-plans/:id/apply')
  @HttpCode(202)
  @RequirePermission('policies.manage')
  apply(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.gateways.apply(user, id, stepUp);
  }

  @Post('gateway-plans/:id/rollback')
  @HttpCode(202)
  @RequirePermission('policies.manage')
  rollback(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.gateways.rollback(user, id, stepUp);
  }

  @Post('gateway-plans/:id/cancel')
  @HttpCode(200)
  @RequirePermission('policies.manage')
  cancel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.gateways.cancel(user, id);
  }
}
