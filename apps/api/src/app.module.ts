import { type DynamicModule, Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { AgentEnrollController } from './agent/agent-enroll.controller';
import { AgentService } from './agent/agent.service';
import { AgentGatewayServer } from './agent/gateway.server';
import { AuditController } from './audit/audit.controller';
import { AuditService } from './audit/audit.service';
import { AuthController } from './auth/auth.controller';
import { AuthGuard } from './auth/auth.guard';
import { AuthService } from './auth/auth.service';
import { AuthzService } from './auth/authz.service';
import { MfaService } from './auth/mfa.service';
import { TokenService } from './auth/token.service';
import { ApplicationsController } from './discovery/applications.controller';
import { ApplicationsService } from './discovery/applications.service';
import { DiscoveryController } from './discovery/discovery.controller';
import { DiscoveryService } from './discovery/discovery.service';
import { NginxRevisionsController } from './nginx/nginx-revisions.controller';
import { NginxRevisionsService } from './nginx/nginx-revisions.service';
import { JobHooks } from './jobs/job-hooks';
import { ContainerAppsService } from './deploy/container-apps.service';
import { DeployController, IntegrationsController } from './deploy/deploy.controller';
import { DeploymentsService } from './deploy/deployments.service';
import { ManagedRoutingService } from './deploy/managed-routing.service';
import { PreflightService } from './deploy/preflight.service';
import { RegistryClient } from './deploy/registry.client';
import { SecretsService } from './deploy/secrets.service';
import { WebhooksService } from './deploy/webhooks.service';
import { EnvelopeInterceptor } from './common/envelope';
import { AllExceptionsFilter } from './common/exception.filter';
import { PrismaService } from './common/prisma.service';
import { RateLimiter } from './common/rate-limiter';
import { APP_CONFIG, type AppConfig } from './config/config';
import { EnrollmentsController } from './enrollments/enrollments.controller';
import { EnrollmentsService } from './enrollments/enrollments.service';
import { JobNotifier } from './jobs/job-notifier';
import { JobsController } from './jobs/jobs.controller';
import { JobsService } from './jobs/jobs.service';
import { SweeperService } from './jobs/sweeper.service';
import { CaService } from './pki/ca.service';
import { ServerGroupsController } from './servers/groups.controller';
import { ServersController } from './servers/servers.controller';
import { ServersService } from './servers/servers.service';
import { SetupController } from './setup/setup.controller';
import { SetupService } from './setup/setup.service';
import { UsersController } from './users/users.controller';
import { UsersService } from './users/users.service';

/** Center API modular monolith. Config is injected so tests can boot isolated instances. */
@Module({})
export class AppModule {
  static forRoot(config: AppConfig): DynamicModule {
    return {
      module: AppModule,
      controllers: [
        SetupController,
        AuthController,
        UsersController,
        AuditController,
        ServersController,
        ServerGroupsController,
        EnrollmentsController,
        JobsController,
        AgentEnrollController,
        DiscoveryController,
        ApplicationsController,
        NginxRevisionsController,
        DeployController,
        IntegrationsController,
      ],
      providers: [
        { provide: APP_CONFIG, useValue: config },
        PrismaService,
        RateLimiter,
        AuditService,
        TokenService,
        AuthzService,
        MfaService,
        AuthService,
        SetupService,
        UsersService,
        CaService,
        ServersService,
        EnrollmentsService,
        JobNotifier,
        JobHooks,
        JobsService,
        ApplicationsService,
        DiscoveryService,
        NginxRevisionsService,
        SecretsService,
        PreflightService,
        DeploymentsService,
        ContainerAppsService,
        ManagedRoutingService,
        RegistryClient,
        WebhooksService,
        SweeperService,
        AgentService,
        AgentGatewayServer,
        { provide: APP_GUARD, useClass: AuthGuard },
        { provide: APP_INTERCEPTOR, useClass: EnvelopeInterceptor },
        { provide: APP_FILTER, useClass: AllExceptionsFilter },
      ],
    };
  }
}
