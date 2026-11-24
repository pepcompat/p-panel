-- P9 private networking, provider inventory, diagnostics, Gateway routing. Expand-only (new tables,
-- widened CHECK). Generated part: `prisma migrate diff`; hand-written part below.

-- CreateTable
CREATE TABLE "server_connections" (
    "server_id" UUID NOT NULL,
    "active_path" TEXT,
    "endpoints" JSONB NOT NULL DEFAULT '[]',
    "reported_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "server_connections_pkey" PRIMARY KEY ("server_id")
);

-- CreateTable
CREATE TABLE "server_network_inventory" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "region" TEXT,
    "vpc_uuid" TEXT,
    "vpc_name" TEXT,
    "droplet_id" TEXT,
    "private_ipv4" TEXT,
    "public_ipv4" TEXT,
    "integration_id" UUID,
    "observed_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "server_network_inventory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "provider_integrations" (
    "id" UUID NOT NULL,
    "provider" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "token_enc" TEXT NOT NULL,
    "api_base" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'unverified',
    "last_sync_at" TIMESTAMPTZ(3),
    "last_error" JSONB,
    "last_sync_summary" JSONB,
    "created_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "provider_integrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "network_connectivity_tests" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "target_server_id" UUID,
    "kind" TEXT NOT NULL,
    "params" JSONB NOT NULL,
    "result" JSONB,
    "error" JSONB,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "job_id" UUID,
    "requested_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "network_connectivity_tests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "gateways" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "application_id" UUID NOT NULL,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "gateways_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "gateway_routes" (
    "id" UUID NOT NULL,
    "gateway_id" UUID NOT NULL,
    "domain" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "backends" JSONB NOT NULL,
    "health_path" TEXT NOT NULL DEFAULT '/',
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "gateway_routes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "gateway_change_plans" (
    "id" UUID NOT NULL,
    "gateway_id" UUID NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'draft',
    "routes_snapshot" JSONB NOT NULL,
    "rendered" JSONB NOT NULL,
    "plan_hash" TEXT NOT NULL,
    "nginx_revision_id" UUID,
    "shadow_results" JSONB,
    "shadow_run" JSONB,
    "verification" JSONB,
    "created_by" UUID NOT NULL,
    "approved_by" UUID,
    "approved_at" TIMESTAMPTZ(3),
    "approved_plan_hash" TEXT,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "gateway_change_plans_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "server_network_inventory_vpc_uuid_idx" ON "server_network_inventory"("vpc_uuid");

-- CreateIndex
CREATE UNIQUE INDEX "server_network_inventory_server_id_source_key" ON "server_network_inventory"("server_id", "source");

-- CreateIndex
CREATE UNIQUE INDEX "provider_integrations_name_key" ON "provider_integrations"("name");

-- CreateIndex
CREATE UNIQUE INDEX "network_connectivity_tests_job_id_key" ON "network_connectivity_tests"("job_id");

-- CreateIndex
CREATE INDEX "network_connectivity_tests_server_id_created_at_idx" ON "network_connectivity_tests"("server_id", "created_at" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "gateways_server_id_key" ON "gateways"("server_id");

-- CreateIndex
CREATE UNIQUE INDEX "gateways_name_key" ON "gateways"("name");

-- CreateIndex
CREATE UNIQUE INDEX "gateway_routes_domain_key" ON "gateway_routes"("domain");

-- CreateIndex
CREATE INDEX "gateway_routes_gateway_id_idx" ON "gateway_routes"("gateway_id");

-- CreateIndex
CREATE INDEX "gateway_change_plans_gateway_id_created_at_idx" ON "gateway_change_plans"("gateway_id", "created_at");

-- CreateIndex
CREATE INDEX "gateway_change_plans_nginx_revision_id_idx" ON "gateway_change_plans"("nginx_revision_id");

-- AddForeignKey
ALTER TABLE "server_connections" ADD CONSTRAINT "server_connections_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "server_network_inventory" ADD CONSTRAINT "server_network_inventory_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_connectivity_tests" ADD CONSTRAINT "network_connectivity_tests_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "network_connectivity_tests" ADD CONSTRAINT "network_connectivity_tests_target_server_id_fkey" FOREIGN KEY ("target_server_id") REFERENCES "servers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "gateways" ADD CONSTRAINT "gateways_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "gateway_routes" ADD CONSTRAINT "gateway_routes_gateway_id_fkey" FOREIGN KEY ("gateway_id") REFERENCES "gateways"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "gateway_change_plans" ADD CONSTRAINT "gateway_change_plans_gateway_id_fkey" FOREIGN KEY ("gateway_id") REFERENCES "gateways"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

-- Applications may now be gateway config holders (files rendered by gateway plans only).
ALTER TABLE "applications" DROP CONSTRAINT "applications_kind_check";
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown','container','compose','gateway'));

ALTER TABLE "server_connections" ADD CONSTRAINT "server_connections_active_path_check"
  CHECK ("active_path" IS NULL OR "active_path" IN ('public','private'));
ALTER TABLE "server_network_inventory" ADD CONSTRAINT "server_network_inventory_source_check"
  CHECK ("source" IN ('agent','provider','inventory'));
ALTER TABLE "provider_integrations" ADD CONSTRAINT "provider_integrations_provider_check"
  CHECK ("provider" IN ('digitalocean'));
ALTER TABLE "provider_integrations" ADD CONSTRAINT "provider_integrations_status_check"
  CHECK ("status" IN ('ok','error','unverified'));
ALTER TABLE "network_connectivity_tests" ADD CONSTRAINT "network_connectivity_tests_kind_check"
  CHECK ("kind" IN ('diagnose','pair'));
ALTER TABLE "network_connectivity_tests" ADD CONSTRAINT "network_connectivity_tests_status_check"
  CHECK ("status" IN ('queued','running','succeeded','failed','expired','cancelled'));
ALTER TABLE "gateway_routes" ADD CONSTRAINT "gateway_routes_mode_check"
  CHECK ("mode" IN ('direct','hybrid','gateway'));
ALTER TABLE "gateway_change_plans" ADD CONSTRAINT "gateway_change_plans_status_check"
  CHECK ("status" IN ('draft','validated','shadow_testing','shadow_tested','awaiting_approval',
                      'applying','applied','rolling_back','rolled_back','failed','cancelled'));
-- Servers' connection policy is a closed enum (the gateway enforces it fail-closed).
ALTER TABLE "servers" ADD CONSTRAINT "servers_connection_policy_check"
  CHECK ("connection_policy" IN ('auto','private_preferred','private_only','public_preferred','public_only'));
