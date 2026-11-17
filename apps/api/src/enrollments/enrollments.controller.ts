import { Body, Controller, Get, HttpCode, Post, Req } from '@nestjs/common';
import { type CreateEnrollmentInput, createEnrollmentSchema } from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { EnrollmentsService } from './enrollments.service';

@Controller('enrollments')
@RequirePermission('servers.enroll')
export class EnrollmentsController {
  constructor(private readonly enrollments: EnrollmentsService) {}

  @Post()
  @HttpCode(201)
  create(@CurrentUser() user: AuthUser, @Body(new ZodPipe(createEnrollmentSchema)) body: CreateEnrollmentInput) {
    return this.enrollments.create(user, body);
  }

  @Get()
  list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.enrollments.list(user, parseQuery(req.originalUrl, { sortable: ['createdAt', 'expiresAt', 'name'] }));
  }
}
