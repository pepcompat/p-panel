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
  approveRestoreSchema,
  BACKUP_TAG_RE,
  createBackupPolicySchema,
  createBackupRepositorySchema,
  createRestoreSchema,
  maintenanceReportSchema,
  markInitializedSchema,
  putBackupRepoAccessSchema,
  STEP_UP_HEADER,
  updateBackupPolicySchema,
  updateBackupRepositorySchema,
  verifyBackupRunSchema,
} from '@ppanel/shared-contracts';
import type { Request, Response } from 'express';
import type { z } from 'zod';
import { AppError } from '../common/app-error';
import { CurrentUser, Public, RequirePermission } from '../common/decorators';
import { UUID_RE } from '../common/ids';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { executeRestoreSchema, type ExecuteRestoreInput } from '@ppanel/shared-contracts';
import { parseIfMatch } from '../servers/servers.service';
import { BackupPoliciesService } from './backup-policies.service';
import { BackupReposService } from './backup-repos.service';
import { BackupRunsService } from './backup-runs.service';
import { RestoresService } from './restores.service';

const uuid = new ParseUUIDPipe();
const STEP_UP = STEP_UP_HEADER.toLowerCase();
const SORTABLE = { sortable: ['createdAt', 'updatedAt', 'status', 'name'] };

function intParam(v: string | undefined, def: number, min: number, max: number, name: string) {
  if (v === undefined) return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max)
    throw AppError.badRequest(`${name} must be an integer ${min}-${max}`);
  return n;
}

/** §10 backups and restores (P6). */
@Controller()
export class BackupController {
  constructor(
    private readonly repos: BackupReposService,
    private readonly policies: BackupPoliciesService,
    private readonly runs: BackupRunsService,
    private readonly restores: RestoresService,
  ) {}

  // ---------------------------------------------------------------- repositories (§10.1)

  @Get('backup-repositories')
  @RequirePermission('fleet.read')
  listRepos(@CurrentUser() user: AuthUser) {
    return this.repos.list(user);
  }

  @Post('backup-repositories')
  @HttpCode(201)
  @RequirePermission('policies.manage')
  createRepo(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createBackupRepositorySchema))
    body: z.infer<typeof createBackupRepositorySchema>,
  ) {
    return this.repos.create(user, body);
  }

  @Get('backup-repositories/:id')
  @RequirePermission('fleet.read')
  getRepo(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.repos.get(user, id);
  }

  @Patch('backup-repositories/:id')
  @RequirePermission('policies.manage')
  updateRepo(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateBackupRepositorySchema))
    body: z.infer<typeof updateBackupRepositorySchema>,
    @Headers('if-match') ifMatch: string | undefined,
  ) {
    return this.repos.update(user, id, body, parseIfMatch(ifMatch));
  }

  @Put('backup-repositories/:id/servers/:serverId')
  @RequirePermission('policies.manage')
  putAccess(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('serverId', uuid) serverId: string,
    @Body(new ZodPipe(putBackupRepoAccessSchema)) body: z.infer<typeof putBackupRepoAccessSchema>,
  ) {
    return this.repos.putAccess(user, id, serverId, body);
  }

  @Post('backup-repositories/:id/servers/:serverId/initialized')
  @HttpCode(200)
  @RequirePermission('policies.manage')
  markInitialized(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Param('serverId', uuid) serverId: string,
    @Body(new ZodPipe(markInitializedSchema)) body: z.infer<typeof markInitializedSchema>,
  ) {
    return this.repos.markInitialized(user, id, serverId, body.initialized);
  }

  @Get('backup-repositories/:id/recovery-export')
  @RequirePermission('policies.manage')
  async recoveryExport(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers(STEP_UP) stepUp: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    return this.repos.recoveryExport(user, id, stepUp);
  }

  /** Operator maintenance script (Bearer PPANEL_BACKUP_REPORT_TOKEN) — not a user session; can only report. */
  @Public()
  @Post('backup-maintenance/reports')
  @HttpCode(201)
  async report(@Headers('authorization') authorization: string | undefined, @Body() raw: unknown) {
    this.repos.assertReportToken(authorization);
    return this.repos.report(new ZodPipe(maintenanceReportSchema).transform(raw));
  }

  // ---------------------------------------------------------------- policies (§10.2)

  @Get('backup-policies')
  @RequirePermission('fleet.read')
  listPolicies(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.policies.list(user, parseQuery(req.originalUrl, SORTABLE));
  }

  @Post('backup-policies')
  @HttpCode(201)
  @RequirePermission('backups.create')
  createPolicy(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createBackupPolicySchema)) body: z.infer<typeof createBackupPolicySchema>,
  ) {
    return this.policies.create(user, body);
  }

  @Get('backup-policies/:id')
  @RequirePermission('fleet.read')
  getPolicy(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.policies.get(user, id);
  }

  @Patch('backup-policies/:id')
  @RequirePermission('backups.create')
  updatePolicy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(updateBackupPolicySchema)) body: z.infer<typeof updateBackupPolicySchema>,
    @Headers('if-match') ifMatch: string | undefined,
  ) {
    return this.policies.update(user, id, body, parseIfMatch(ifMatch));
  }

  @Delete('backup-policies/:id')
  @HttpCode(204)
  @RequirePermission('backups.create')
  async deletePolicy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers('if-match') ifMatch: string | undefined,
  ) {
    await this.policies.remove(user, id, parseIfMatch(ifMatch));
  }

  /** 202 `{ run }` (200 on an Idempotency-Key replay). */
  @Post('backup-policies/:id/run')
  @RequirePermission('backups.create')
  async runPolicy(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Headers('idempotency-key') idem: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    const r = await this.policies.runNow(user, id, idem);
    res.status(r.created ? 202 : 200);
    return { run: r.run, reused: !r.created };
  }

  // ---------------------------------------------------------------- runs (§10.3)

  @Get('backup-runs')
  @RequirePermission('fleet.read')
  listRuns(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.runs.list(user, parseQuery(req.originalUrl, SORTABLE));
  }

  @Get('backup-runs/:id')
  @RequirePermission('fleet.read')
  getRun(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Query('manifestPage') page: string | undefined,
    @Query('manifestLimit') limit: string | undefined,
  ) {
    return this.runs.get(
      user,
      id,
      intParam(page, 1, 1, 1_000_000, 'manifestPage'),
      intParam(limit, 100, 1, 1000, 'manifestLimit'),
    );
  }

  @Post('backup-runs/:id/verify')
  @HttpCode(202)
  @RequirePermission('backups.create')
  verifyRun(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(verifyBackupRunSchema)) body: z.infer<typeof verifyBackupRunSchema>,
  ) {
    return this.runs.verify(user, id, body.level);
  }

  /** Live `backup.snapshots` (read-only); 202 `{ pending: true, jobId }` when the agent is slow. */
  @Get('servers/:id/snapshots')
  @RequirePermission('backups.create')
  async snapshots(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Query('repository_id') repositoryId: string | undefined,
    @Query('tag') tag: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (repositoryId !== undefined && !UUID_RE.test(repositoryId))
      throw AppError.badRequest('repository_id must be a UUID');
    if (tag !== undefined && !BACKUP_TAG_RE.test(tag)) throw AppError.badRequest('invalid tag');
    const r = await this.runs.snapshots(user, id, repositoryId, tag);
    if (r.pending) res.status(202);
    return r.body;
  }

  // ---------------------------------------------------------------- restores (§10.4)

  @Get('restores')
  @RequirePermission('fleet.read')
  listRestores(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.restores.list(user, parseQuery(req.originalUrl, SORTABLE));
  }

  @Post('restores')
  @HttpCode(201)
  @RequirePermission('backups.restore')
  createRestore(
    @CurrentUser() user: AuthUser,
    @Body(new ZodPipe(createRestoreSchema)) body: z.infer<typeof createRestoreSchema>,
  ) {
    return this.restores.create(user, body);
  }

  @Get('restores/:id')
  @RequirePermission('fleet.read')
  getRestore(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.restores.get(user, id);
  }

  @Post('restores/:id/dry-run')
  @HttpCode(202)
  @RequirePermission('backups.restore')
  dryRun(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.restores.dryRun(user, id);
  }

  @Post('restores/:id/approve')
  @HttpCode(200)
  @RequirePermission('approvals.decide')
  approve(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(approveRestoreSchema)) body: z.infer<typeof approveRestoreSchema>,
    @Headers(STEP_UP) stepUp: string | undefined,
  ) {
    return this.restores.approve(user, id, body.planHash, stepUp);
  }

  @Post('restores/:id/execute')
  @HttpCode(202)
  @RequirePermission('backups.restore')
  execute(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(executeRestoreSchema)) body: ExecuteRestoreInput,
  ) {
    return this.restores.execute(user, id, body?.confirmImpact === true);
  }

  @Post('restores/:id/cancel')
  @HttpCode(200)
  @RequirePermission('backups.restore')
  cancel(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string) {
    return this.restores.cancel(user, id);
  }
}
