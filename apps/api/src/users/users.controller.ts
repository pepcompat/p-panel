import { Body, Controller, Delete, Get, HttpCode, Param, ParseUUIDPipe, Post, Req } from '@nestjs/common';
import { type CreateRoleBindingInput, type CreateUserInput, createRoleBindingSchema, createUserSchema } from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { CurrentUser, RequirePermission } from '../common/decorators';
import type { AuthUser } from '../common/principal';
import { parseQuery } from '../common/query-builder';
import { ZodPipe } from '../common/zod.pipe';
import { UsersService } from './users.service';

const uuid = new ParseUUIDPipe({ version: undefined });

@Controller()
@RequirePermission('users.manage')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get('users')
  list(@CurrentUser() user: AuthUser, @Req() req: Request) {
    return this.users.list(user, parseQuery(req.originalUrl, { sortable: ['createdAt', 'email', 'displayName'] }));
  }

  @Post('users')
  @HttpCode(201)
  create(@CurrentUser() user: AuthUser, @Body(new ZodPipe(createUserSchema)) body: CreateUserInput) {
    return this.users.create(user, body);
  }

  @Post('users/:id/role-bindings')
  @HttpCode(201)
  addBinding(
    @CurrentUser() user: AuthUser,
    @Param('id', uuid) id: string,
    @Body(new ZodPipe(createRoleBindingSchema)) body: CreateRoleBindingInput,
  ) {
    return this.users.addBinding(user, id, body);
  }

  @Delete('role-bindings/:id')
  @HttpCode(204)
  async removeBinding(@CurrentUser() user: AuthUser, @Param('id', uuid) id: string): Promise<void> {
    await this.users.removeBinding(user, id);
  }
}
