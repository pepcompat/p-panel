-- P4a: container applications, secrets, deployments, approvals, managed routing, webhooks.

-- AlterTable
ALTER TABLE "jobs" ADD COLUMN     "secrets_fetched_at" TIMESTAMPTZ(3);

-- CreateTable
CREATE TABLE "container_apps" (
    "application_id" UUID NOT NULL,
    "container_port" INTEGER NOT NULL,
    "healthcheck" JSONB NOT NULL,
    "resources" JSONB NOT NULL,
    "env" JSONB NOT NULL DEFAULT '{}',
    "secret_keys" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "volumes" JSONB NOT NULL DEFAULT '[]',
    "tls" JSONB,
    "current_deployment_id" UUID,
    "previous_deployment_id" UUID,
    "route_sha256" TEXT,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "container_apps_pkey" PRIMARY KEY ("application_id")
);

-- CreateTable
CREATE TABLE "secrets" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "key" TEXT NOT NULL,
    "value_encrypted" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_by" UUID NOT NULL,
    "updated_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "secrets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "deployments" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "number" INTEGER NOT NULL,
    "trigger" TEXT NOT NULL,
    "image" TEXT NOT NULL,
    "source_ref" JSONB,
    "reason" TEXT,
    "status" TEXT NOT NULL,
    "preflight" JSONB NOT NULL DEFAULT '[]',
    "container_name" TEXT,
    "host_port" INTEGER,
    "container_removed_at" TIMESTAMPTZ(3),
    "previous_deployment_id" UUID,
    "rollback_of_deployment_id" UUID,
    "plan_hash" TEXT NOT NULL,
    "approval_required" BOOLEAN NOT NULL,
    "idempotency_key" TEXT,
    "commit_sha" TEXT,
    "webhook_delivery_id" UUID,
    "created_by" UUID,
    "error" JSONB,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "deployments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "deployment_steps" (
    "id" UUID NOT NULL,
    "deployment_id" UUID NOT NULL,
    "seq" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "job_id" UUID,
    "started_at" TIMESTAMPTZ(3),
    "finished_at" TIMESTAMPTZ(3),
    "message" TEXT,
    "error_code" TEXT,
    "log_tail" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "data" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "deployment_steps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "operation_approvals" (
    "id" UUID NOT NULL,
    "subject_type" TEXT NOT NULL,
    "subject_id" UUID NOT NULL,
    "approver_id" UUID NOT NULL,
    "plan_hash" TEXT NOT NULL,
    "approved_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "used_by_job_id" UUID,
    "invalidated_at" TIMESTAMPTZ(3),

    CONSTRAINT "operation_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "managed_routing" (
    "server_id" UUID NOT NULL,
    "status" TEXT NOT NULL,
    "revision_id" UUID NOT NULL,
    "plan_hash" TEXT NOT NULL,
    "approval_required" BOOLEAN NOT NULL,
    "apply_job_id" UUID,
    "error" JSONB,
    "created_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "managed_routing_pkey" PRIMARY KEY ("server_id")
);

-- CreateTable
CREATE TABLE "host_port_allocations" (
    "server_id" UUID NOT NULL,
    "port" INTEGER NOT NULL,
    "application_id" UUID,
    "deployment_id" UUID,
    "container_name" TEXT,
    "reason" TEXT NOT NULL DEFAULT 'container',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_port_allocations_pkey" PRIMARY KEY ("server_id","port")
);

-- CreateTable
CREATE TABLE "integrations" (
    "id" UUID NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'github',
    "name" TEXT NOT NULL,
    "webhook_secret_enc" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "integrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_deliveries" (
    "id" UUID NOT NULL,
    "integration_id" UUID NOT NULL,
    "delivery_id" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "repo" TEXT,
    "ref" TEXT,
    "after" TEXT,
    "signature_ok" BOOLEAN NOT NULL,
    "result" TEXT NOT NULL,
    "reasons" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "deployment_ids" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "received_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auto_deploy_policies" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "integration_id" UUID NOT NULL,
    "repo" TEXT NOT NULL,
    "branches" TEXT[],
    "image_template" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "auto_deploy_policies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "secrets_application_id_key_key" ON "secrets"("application_id", "key");

-- CreateIndex
CREATE INDEX "deployments_server_id_status_idx" ON "deployments"("server_id", "status");

-- CreateIndex
CREATE INDEX "deployments_status_updated_at_idx" ON "deployments"("status", "updated_at");

-- CreateIndex
CREATE INDEX "deployments_application_id_commit_sha_idx" ON "deployments"("application_id", "commit_sha");

-- CreateIndex
CREATE UNIQUE INDEX "deployments_application_id_number_key" ON "deployments"("application_id", "number");

-- CreateIndex
CREATE UNIQUE INDEX "deployments_application_id_idempotency_key_key" ON "deployments"("application_id", "idempotency_key");

-- CreateIndex
CREATE INDEX "deployment_steps_job_id_idx" ON "deployment_steps"("job_id");

-- CreateIndex
CREATE INDEX "deployment_steps_status_idx" ON "deployment_steps"("status");

-- CreateIndex
CREATE UNIQUE INDEX "deployment_steps_deployment_id_seq_key" ON "deployment_steps"("deployment_id", "seq");

-- CreateIndex
CREATE INDEX "operation_approvals_subject_type_subject_id_approved_at_idx" ON "operation_approvals"("subject_type", "subject_id", "approved_at");

-- CreateIndex
CREATE INDEX "host_port_allocations_deployment_id_idx" ON "host_port_allocations"("deployment_id");

-- CreateIndex
CREATE INDEX "webhook_deliveries_integration_id_received_at_idx" ON "webhook_deliveries"("integration_id", "received_at");

-- CreateIndex
CREATE UNIQUE INDEX "webhook_deliveries_integration_id_delivery_id_key" ON "webhook_deliveries"("integration_id", "delivery_id");

-- CreateIndex
CREATE INDEX "auto_deploy_policies_integration_id_repo_idx" ON "auto_deploy_policies"("integration_id", "repo");

-- CreateIndex
CREATE UNIQUE INDEX "auto_deploy_policies_application_id_integration_id_repo_key" ON "auto_deploy_policies"("application_id", "integration_id", "repo");

-- AddForeignKey
ALTER TABLE "container_apps" ADD CONSTRAINT "container_apps_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "deployments" ADD CONSTRAINT "deployments_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "deployment_steps" ADD CONSTRAINT "deployment_steps_deployment_id_fkey" FOREIGN KEY ("deployment_id") REFERENCES "deployments"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "managed_routing" ADD CONSTRAINT "managed_routing_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_port_allocations" ADD CONSTRAINT "host_port_allocations_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auto_deploy_policies" ADD CONSTRAINT "auto_deploy_policies_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auto_deploy_policies" ADD CONSTRAINT "auto_deploy_policies_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;



-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

-- Applications may now be managed container apps.
ALTER TABLE "applications" DROP CONSTRAINT "applications_kind_check";
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown','container'));

-- One active deployment per application (per-app deploy lock, P4.08).
CREATE UNIQUE INDEX "deployments_one_active_per_app"
  ON "deployments" ("application_id")
  WHERE "status" IN ('queued','preflight','pulling','starting','health_check','routing',
                     'rollback_pending','awaiting_approval');

ALTER TABLE "deployments" ADD CONSTRAINT "deployments_status_check"
  CHECK ("status" IN ('queued','preflight','pulling','starting','health_check','routing','succeeded',
                      'failed','rollback_pending','rolled_back','requires_manual_recovery','cancelled',
                      'expired','awaiting_approval'));
ALTER TABLE "deployments" ADD CONSTRAINT "deployments_trigger_check"
  CHECK ("trigger" IN ('manual','webhook','rollback','redeploy'));
ALTER TABLE "deployments" ADD CONSTRAINT "deployments_plan_hash_check"
  CHECK ("plan_hash" ~ '^[a-f0-9]{64}$');
ALTER TABLE "deployments" ADD CONSTRAINT "deployments_image_digest_check"
  CHECK ("image" ~ '@sha256:[a-f0-9]{64}$');
ALTER TABLE "deployments" ADD CONSTRAINT "deployments_host_port_check"
  CHECK ("host_port" IS NULL OR "host_port" BETWEEN 20000 AND 29999);
ALTER TABLE "deployment_steps" ADD CONSTRAINT "deployment_steps_status_check"
  CHECK ("status" IN ('pending','running','succeeded','failed','skipped'));
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_subject_check"
  CHECK ("subject_type" IN ('deployment','managed_routing'));
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_expiry_check"
  CHECK ("expires_at" > "approved_at");
ALTER TABLE "managed_routing" ADD CONSTRAINT "managed_routing_status_check"
  CHECK ("status" IN ('awaiting_approval','applying','enabled','failed','requires_manual_recovery'));
ALTER TABLE "host_port_allocations" ADD CONSTRAINT "host_port_allocations_range_check"
  CHECK ("port" BETWEEN 20000 AND 29999);
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_result_check"
  CHECK ("result" IN ('deployed','awaiting_approval','ignored','failed'));
ALTER TABLE "secrets" ADD CONSTRAINT "secrets_key_check"
  CHECK ("key" ~ '^([A-Z_][A-Z0-9_]{0,63})$');

-- Rollback (manual): see ROLLBACK.md next to this file.
