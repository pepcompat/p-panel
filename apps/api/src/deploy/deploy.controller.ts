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
  Put,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import {
  approveDeploymentSchema,
  type AutoDeployPolicyInput,
  autoDeployPolicySchema,
  composeValidateSchema,
  type CreateContainerAppInput,
  createContainerAppSchema,
  type CreateDeploymentInput,
  createDeploymentSchema,
  createGithubIntegrationSchema,
  deploymentPreflightSchema,
  detectFramework,
  detectSchema,
  putSecretSchema,
  type RegistryAuthInput,
  registryAuthSchema,
  rollbackSchema,
  STEP_UP_HEADER,
  type UpdateContainerAppInput,
  updateAutoDeployPolicySchema,
  updateContainerAppSchema,
} from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import type { z } from 'zod';
import { AppError } from '../common/app-error';
import { CurrentUser, Public, RequirePermission } from '../common/decorators';
import { UUID_RE } from '../common/ids';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { parseIfMatch } from '../servers/servers.service';
import { validateComposeYaml } from './compose-validator';
import { ContainerAppsService } from './container-apps.service';
import { DeploymentsService } from './deployments.service';
import { ManagedRoutingService } from './managed-routing.service';
import { SecretsService } from './secrets.service';
import { WebhooksService } from './webhooks.service';

const uuid = new ParseUUIDPipe();
const STEP_UP = STEP_UP_HEADER.toLowerCase();
const SORTABLE = { sortable: ['createdAt', 'updatedAt', 'number', 'status'] };

/** §7.1–7.4: container applications, secrets, deployments, lifecycle operations. */
@Controller()
export class DeployController {
  constructor(
    private readonly containerApps: ContainerAppsService,
    private readonly deployments: DeploymentsService,
    private readonly secrets: SecretsService,
    private readonly routing: ManagedRoutingService,
  ) {}

  // ---------------------------------------------------------------- container apps

  @Post('applications')
  @HttpCode(201)
  @RequirePermission('apps.deploy')
  createApp(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createContainerAppSchema)) body: CreateContainerAppInput,
  ) {
    return this.containerApps.create(user, body);
  }

  @Patch('applications/:id/container')
  @RequirePermission('apps.deploy')
  updateApp(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateContainerAppSchema)) body: UpdateContainerAppInput,
    @Headers('if-match') ifMatch: string | undefined,
  ) {
    return this.containerApps.update(user, id, body, parseIfMatch(ifMatch));
  }

  // ---------------------------------------------------------------- secrets

  @Get('applications/:id/secrets')
  @RequirePermission('apps.read')
  listSecrets(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.secrets.list(user, id);
  }

  @Put('applications/:id/secrets/:key')
  @RequirePermission('apps.deploy')
  putSecret(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('key') key: string,
    @Body(new ZodPipe(putSecretSchema)) body: z.infer<typeof putSecretSchema>,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.secrets.put(user, id, key, body.value, stepUp);
  }

  @Delete('applications/:id/secrets/:key')
  @HttpCode(204)
  @RequirePermission('apps.deploy')
  async deleteSecret(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('key') key: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    await this.secrets.remove(user, id, key, stepUp);
  }

  @Get('applications/:id/registry-auth')
  @RequirePermission('apps.read')
  getRegistryAuth(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.secrets.getRegistryAuth(user, id);
  }

  @Put('applications/:id/registry-auth')
  @RequirePermission('apps.deploy')
  putRegistryAuth(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(registryAuthSchema)) body: RegistryAuthInput,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.secrets.putRegistryAuth(user, id, body, stepUp);
  }

  @Delete('applications/:id/registry-auth')
  @HttpCode(204)
  @RequirePermission('apps.deploy')
  async deleteRegistryAuth(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    await this.secrets.removeRegistryAuth(user, id, stepUp);
  }

  // ---------------------------------------------------------------- deployments

  @Post('applications/:id/deployments/preflight')
  @HttpCode(200)
  @RequirePermission('apps.deploy')
  preflight(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(deploymentPreflightSchema)) body: z.infer<typeof deploymentPreflightSchema>,
  ) {
    return this.deployments.runPreflight(user, id, body.image);
  }

  /** 202 `{ deployment }` (200 on Idempotency-Key replay). Failing preflight → deployment `failed`, no job. */
  @Post('applications/:id/deployments')
  @RequirePermission('apps.deploy')
  async deploy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(createDeploymentSchema)) body: CreateDeploymentInput,
    @Headers('idempotency-key') idem: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const r = await this.deployments.createManual(user, id, body, idem);
    res.status(r.created ? 202 : 200);
    return { deployment: r.deployment };
  }

  @Get('applications/:id/deployments')
  @RequirePermission('apps.read')
  listForApp(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string, @Req() req: Request) {
    return this.deployments.listForApp(user, id, parseQuery(req.originalUrl, SORTABLE));
  }

  @Get('deployments')
  @RequirePermission('apps.read')
  listAll(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.deployments.listAll(user, parseQuery(req.originalUrl, SORTABLE));
  }

  @Get('deployments/:id')
  @RequirePermission('apps.read')
  get(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.deployments.get(user, id);
  }

  @Post('deployments/:id/approve')
  @HttpCode(200)
  @RequirePermission('approvals.decide')
  approve(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(approveDeploymentSchema)) body: { planHash: string },
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.deployments.approve(user, id, body.planHash, stepUp);
  }

  @Post('deployments/:id/cancel')
  @HttpCode(200)
  @RequirePermission('apps.deploy')
  cancel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.deployments.cancel(user, id);
  }

  @Post('applications/:id/rollback')
  @HttpCode(202)
  @RequirePermission('apps.deploy')
  rollback(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(rollbackSchema)) body: z.infer<typeof rollbackSchema>,
  ) {
    return this.deployments.rollback(user, id, body.reason);
  }

  @Post('applications/:id/redeploy')
  @HttpCode(202)
  @RequirePermission('apps.deploy')
  redeploy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(rollbackSchema)) body: z.infer<typeof rollbackSchema>,
  ) {
    return this.deployments.redeploy(user, id, body.reason);
  }

  @Post('applications/:id/restart')
  @HttpCode(202)
  @RequirePermission('apps.deploy')
  restart(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.containerApps.operate(user, id, 'restart', stepUp);
  }

  @Post('applications/:id/start')
  @HttpCode(202)
  @RequirePermission('apps.deploy')
  start(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.containerApps.operate(user, id, 'start', stepUp);
  }

  @Post('applications/:id/stop')
  @HttpCode(202)
  @RequirePermission('apps.deploy')
  stop(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.containerApps.operate(user, id, 'stop', stepUp);
  }

  /** 200 `{ jobId, status:"succeeded", lines }` or 202 `{ status:"pending" }` (poll with ?jobId=). */
  @Get('applications/:id/logs')
  @RequirePermission('apps.read')
  async logs(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Query('tail') tailRaw: string | undefined,
    @Query('jobId') jobId: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tail = tailRaw === undefined ? 200 : Number(tailRaw);
    if (!Number.isInteger(tail) || tail < 1 || tail > 1000)
      throw AppError.badRequest('tail must be an integer 1–1000');
    if (jobId !== undefined && !UUID_RE.test(jobId))
      throw AppError.badRequest('jobId must be a uuid');
    const r = await this.containerApps.logs(user, id, tail, jobId);
    res.status(r.pending ? 202 : 200);
    return r.body;
  }

  // ---------------------------------------------------------------- managed routing

  @Get('servers/:id/managed-routing')
  @RequirePermission('nginx.read')
  getRouting(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.routing.get(user, id);
  }

  @Post('servers/:id/managed-routing')
  @HttpCode(202)
  @RequirePermission('nginx.write')
  enableRouting(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.routing.enable(user, id, stepUp);
  }

  @Post('servers/:id/managed-routing/approve')
  @HttpCode(202)
  @RequirePermission('approvals.decide')
  approveRouting(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(approveDeploymentSchema)) body: { planHash: string },
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.routing.approve(user, id, body.planHash, stepUp);
  }
}

/** §7.5 integrations, auto-deploy policies, public GitHub receiver; §7.6 compose/detect. */
@Controller()
export class IntegrationsController {
  constructor(private readonly webhooks: WebhooksService) {}

  @Get('integrations/github/app')
  @RequirePermission('apps.read')
  githubApp() {
    return {
      available: false,
      reason:
        'BLOCKED: GitHub App installation needs App credentials (app id, private key, client secret) that are not available in the lab. Use repository webhooks (POST /integrations/github) instead.',
    };
  }

  @Post('integrations/github')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createGithub(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createGithubIntegrationSchema))
    body: z.infer<typeof createGithubIntegrationSchema>,
  ) {
    return this.webhooks.createIntegration(user, body);
  }

  @Get('integrations')
  @RequirePermission('apps.deploy')
  list() {
    return this.webhooks.listIntegrations();
  }

  @Get('integrations/github/:id/deliveries')
  @RequirePermission('apps.deploy')
  deliveries(@Param('id', uuid) id: string, @Req() req: Request) {
    return this.webhooks.deliveries(id, parseQuery(req.originalUrl, { sortable: ['createdAt'] }));
  }

  @Get('applications/:id/auto-deploy')
  @RequirePermission('apps.read')
  listPolicies(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.webhooks.listPolicies(user, id);
  }

  @Post('applications/:id/auto-deploy')
  @HttpCode(201)
  @RequirePermission('apps.deploy')
  createPolicy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(autoDeployPolicySchema)) body: AutoDeployPolicyInput,
  ) {
    return this.webhooks.createPolicy(user, id, body);
  }

  @Patch('applications/:id/auto-deploy/:policyId')
  @RequirePermission('apps.deploy')
  updatePolicy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('policyId', uuid) policyId: string,
    @Body(new ZodPipe(updateAutoDeployPolicySchema))
    body: z.infer<typeof updateAutoDeployPolicySchema>,
  ) {
    return this.webhooks.updatePolicy(user, id, policyId, body);
  }

  @Delete('applications/:id/auto-deploy/:policyId')
  @HttpCode(204)
  @RequirePermission('apps.deploy')
  async deletePolicy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('policyId', uuid) policyId: string,
  ) {
    await this.webhooks.deletePolicy(user, id, policyId);
  }

  /** Public: authenticated by the HMAC signature over the raw body (1 MiB limit, rate-limited). */
  @Public()
  @Post('webhooks/github/:integrationId')
  @HttpCode(200)
  receive(@Param('integrationId', uuid) integrationId: string, @Req() req: Request) {
    const h = (k: string) => {
      const v = req.headers[k];
      return Array.isArray(v) ? v[0] : v;
    };
    return this.webhooks.receive(
      integrationId,
      {
        'x-hub-signature-256': h('x-hub-signature-256'),
        'x-github-delivery': h('x-github-delivery'),
        'x-github-event': h('x-github-event'),
        'content-type': h('content-type'),
      },
      req.body,
      req.ip,
    );
  }

  @Post('deploy/compose/validate')
  @HttpCode(200)
  @RequirePermission('apps.deploy')
  validateCompose(
    @Body(new ZodPipe(composeValidateSchema)) body: z.infer<typeof composeValidateSchema>,
  ) {
    return validateComposeYaml(body.yaml, { environment: body.environment });
  }

  @Post('deploy/detect')
  @HttpCode(200)
  @RequirePermission('apps.deploy')
  detect(@Body(new ZodPipe(detectSchema)) body: z.infer<typeof detectSchema>) {
    return detectFramework(body.files);
  }
}
