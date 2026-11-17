import { Body, Controller, Get, HttpCode, Post, Req } from '@nestjs/common';
import { type BootstrapInput, bootstrapSchema } from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { Public } from '../common/decorators';
import { RateLimiter } from '../common/rate-limiter';
import { ZodPipe } from '../common/zod.pipe';
import { SetupService } from './setup.service';

@Public()
@Controller('setup')
export class SetupController {
  constructor(
    private readonly setup: SetupService,
    private readonly limiter: RateLimiter,
  ) {}

  @Get('status')
  async status() {
    return { bootstrapped: await this.setup.isBootstrapped() };
  }

  @Post('bootstrap')
  @HttpCode(201)
  bootstrap(@Body(new ZodPipe(bootstrapSchema)) body: BootstrapInput, @Req() req: Request) {
    this.limiter.hit(`setup:${req.ip ?? '-'}`, 5, 60_000);
    return this.setup.bootstrap(body);
  }
}
