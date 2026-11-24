import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Req,
} from '@nestjs/common';
import {
  type ApproveSshGrantInput,
  approveSshGrantSchema,
  type CreateSshCredentialInput,
  createSshCredentialSchema,
  type CreateSshGrantInput,
  createSshGrantSchema,
  type CreateSshSessionInput,
  createSshSessionSchema,
  type DeploySshCredentialInput,
  deploySshCredentialSchema,
  type PutSshEndpointsInput,
  putSshEndpointsSchema,
  type ScanSshHostKeysInput,
  scanSshHostKeysSchema,
  STEP_UP_HEADER,
} from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { requestContext } from '../common/request-context';
import { ZodPipe } from '../common/zod.pipe';
import { SshCredentialsService } from './credentials.service';
import { SshEndpointsService } from './endpoints.service';
import { SshGrantsService } from './grants.service';
import { SshSessionsService } from './sessions.service';

const uuid = new ParseUUIDPipe();
const STEP_UP = STEP_UP_HEADER.toLowerCase();

/**
 * P10 SSH gateway API (docs/P10_SSH_CONTRACT.md). Coarse permissions here; resource scope, owner
 * checks, step-up and approver ≠ requester are enforced in the services. The terminal itself is the
 * WebSocket `GET /api/v1/ssh/stream` (SshGatewayService), not a Nest route.
 */
@Controller()
export class SshController {
  constructor(
    private readonly credentials: SshCredentialsService,
    private readonly endpoints: SshEndpointsService,
    private readonly grants: SshGrantsService,
    private readonly sessions: SshSessionsService,
  ) {}

  @Get('ssh/settings')
  @RequirePermission('fleet.read')
  settings() {
    return this.sessions.settings();
  }

  // ---------------------------------------------------------------- §2 credentials

  @Get('ssh/credentials')
  @RequirePermission('fleet.read')
  listCredentials(@CurrentUser() user: AuthUser) {
    return this.credentials.list(user);
  }

  @Post('ssh/credentials')
  @HttpCode(201)
  @RequirePermission('credentials.manage')
  createCredential(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createSshCredentialSchema)) body: CreateSshCredentialInput,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.credentials.create(user, body, stepUp);
  }

  @Post('ssh/credentials/:id/deploy')
  @HttpCode(202)
  @RequirePermission('credentials.manage')
  deploy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(deploySshCredentialSchema)) body: DeploySshCredentialInput,
  ) {
    return this.credentials.deploy(user, id, body);
  }

  @Delete('ssh/credentials/:id/deployments/:deploymentId')
  @HttpCode(202)
  @RequirePermission('credentials.manage')
  removeDeployment(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('deploymentId', uuid) deploymentId: string,
  ) {
    return this.credentials.removeDeployment(user, id, deploymentId);
  }

  @Post('ssh/credentials/:id/rotate')
  @HttpCode(201)
  @RequirePermission('credentials.manage')
  rotate(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.credentials.rotate(user, id, stepUp);
  }

  @Post('ssh/credentials/:id/revoke')
  @HttpCode(200)
  @RequirePermission('credentials.manage')
  revoke(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.credentials.revoke(user, id, stepUp);
  }

  // ---------------------------------------------------------------- §3 endpoints + host keys

  @Get('servers/:id/ssh/endpoints')
  @RequirePermission('fleet.read')
  getEndpoints(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.endpoints.getEndpoints(user, id);
  }

  @Put('servers/:id/ssh/endpoints')
  @RequirePermission('credentials.manage')
  putEndpoints(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(putSshEndpointsSchema)) body: PutSshEndpointsInput,
  ) {
    return this.endpoints.putEndpoints(user, id, body);
  }

  @Get('servers/:id/ssh/host-keys')
  @RequirePermission('fleet.read')
  hostKeys(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.endpoints.listHostKeys(user, id);
  }

  @Post('servers/:id/ssh/host-keys/scan')
  @HttpCode(200)
  @RequirePermission('credentials.manage')
  scan(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(scanSshHostKeysSchema)) body: ScanSshHostKeysInput,
  ) {
    return this.endpoints.scan(user, id, body.path);
  }

  @Post('ssh/host-keys/:id/trust')
  @HttpCode(200)
  @RequirePermission('credentials.manage')
  trust(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.endpoints.trust(user, id, stepUp);
  }

  @Post('ssh/host-keys/:id/reject')
  @HttpCode(200)
  @RequirePermission('credentials.manage')
  rejectKey(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.endpoints.reject(user, id);
  }

  // ---------------------------------------------------------------- §4 grants

  @Get('ssh/grants')
  listGrants(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.grants.list(
      user,
      parseQuery(req.originalUrl, {
        sortable: ['requestedAt', 'expiresAt'],
        defaultSort: 'requestedAt',
      }),
    );
  }

  @Post('ssh/grants')
  @HttpCode(201)
  @RequirePermission('ssh.connect')
  createGrant(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createSshGrantSchema)) body: CreateSshGrantInput,
  ) {
    return this.grants.create(user, body);
  }

  @Post('ssh/grants/:id/approve')
  @HttpCode(200)
  @RequirePermission('approvals.decide')
  approve(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(approveSshGrantSchema)) body: ApproveSshGrantInput,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.grants.approve(user, id, body.grantHash, stepUp);
  }

  @Post('ssh/grants/:id/reject')
  @HttpCode(200)
  @RequirePermission('approvals.decide')
  rejectGrant(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.grants.reject(user, id);
  }

  /** Requester (own grant) or `credentials.manage` on the server — enforced in the service. */
  @Post('ssh/grants/:id/revoke')
  @HttpCode(200)
  revokeGrant(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.grants.revoke(user, id);
  }

  // ---------------------------------------------------------------- §5 sessions

  @Get('ssh/sessions')
  listSessions(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.sessions.list(
      user,
      parseQuery(req.originalUrl, { sortable: ['createdAt'], defaultSort: 'createdAt' }),
    );
  }

  @Post('ssh/sessions')
  @HttpCode(201)
  @RequirePermission('ssh.connect')
  createSession(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createSshSessionSchema)) body: CreateSshSessionInput,
    @Headers(STEP_UP) stepUp: string | undefined,
    @Req() req: Request,
  ) {
    return this.sessions.create(user, body, stepUp, {
      ip: requestContext.getStore()?.ip ?? req.ip ?? null,
      userAgent: req.header('user-agent') ?? null,
    });
  }

  /** Owner or `credentials.manage` on the server — enforced in the service. */
  @Post('ssh/sessions/:id/terminate')
  @HttpCode(200)
  terminate(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.sessions.terminate(user, id);
  }
}
