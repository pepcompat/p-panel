import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import { type AgentEnrollInput, agentEnrollSchema } from '@ppanel/shared-contracts';
import type { Request } from 'express';
import { Public } from '../common/decorators';
import { ZodPipe } from '../common/zod.pipe';
import { AgentService } from './agent.service';

/** Public, rate-limited (10/min/IP) agent enrollment on the main API listener. */
@Public()
@Controller('agent')
export class AgentEnrollController {
  constructor(private readonly agent: AgentService) {}

  @Post('enroll')
  @HttpCode(201)
  enroll(@Body(new ZodPipe(agentEnrollSchema)) body: AgentEnrollInput, @Req() req: Request) {
    return this.agent.enroll(body, req.ip);
  }
}
