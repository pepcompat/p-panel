-- P4b: build nodes, build configs, builds, source inspections, compose app versions, build-mode auto-deploy.

-- AlterTable
ALTER TABLE "auto_deploy_policies" ADD COLUMN     "mode" TEXT NOT NULL DEFAULT 'image',
ALTER COLUMN "image_template" DROP NOT NULL;

-- AlterTable
ALTER TABLE "deployments" ADD COLUMN     "build_id" UUID,
ADD COLUMN     "compose_version_id" UUID,
ADD COLUMN     "plan" JSONB,
ADD COLUMN     "service_results" JSONB;

-- AlterTable
ALTER TABLE "servers" ADD COLUMN     "build_node" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "webhook_deliveries" ADD COLUMN     "build_ids" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- CreateTable
CREATE TABLE "build_configs" (
    "application_id" UUID NOT NULL,
    "repo_url" TEXT NOT NULL,
    "subdir" TEXT NOT NULL DEFAULT '',
    "dockerfile" TEXT,
    "template" TEXT,
    "build_args" JSONB NOT NULL DEFAULT '{}',
    "target" TEXT,
    "build_server_id" UUID NOT NULL,
    "push_repo" TEXT NOT NULL,
    "network" TEXT NOT NULL DEFAULT 'default',
    "limits" JSONB NOT NULL DEFAULT '{}',
    "created_by" UUID NOT NULL,
    "updated_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "build_configs_pkey" PRIMARY KEY ("application_id")
);

-- CreateTable
CREATE TABLE "builds" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "build_server_id" UUID NOT NULL,
    "status" TEXT NOT NULL,
    "commit_sha" TEXT NOT NULL,
    "branch" TEXT,
    "trigger" TEXT NOT NULL,
    "repo" TEXT,
    "dockerfile" TEXT,
    "template" TEXT,
    "push_repo" TEXT NOT NULL,
    "image" TEXT,
    "deploy_after" BOOLEAN NOT NULL,
    "force" BOOLEAN NOT NULL DEFAULT false,
    "log_tail" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "log" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "log_truncated" BOOLEAN NOT NULL DEFAULT false,
    "error" JSONB,
    "duration_ms" INTEGER,
    "job_id" UUID,
    "deployment_id" UUID,
    "deploy_error" JSONB,
    "idempotency_key" TEXT,
    "webhook_delivery_id" UUID,
    "created_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "builds_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "compose_app_versions" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "yaml" TEXT NOT NULL,
    "yaml_sha256" TEXT NOT NULL,
    "route_service" TEXT NOT NULL,
    "route_port" INTEGER NOT NULL,
    "health_path" TEXT NOT NULL DEFAULT '/',
    "plan" JSONB NOT NULL,
    "secret_keys" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "warnings" JSONB NOT NULL DEFAULT '[]',
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "compose_app_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "source_inspections" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "job_id" UUID NOT NULL,
    "commit_sha" TEXT NOT NULL,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "source_inspections_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "build_configs_build_server_id_idx" ON "build_configs"("build_server_id");

-- CreateIndex
CREATE INDEX "builds_application_id_commit_sha_idx" ON "builds"("application_id", "commit_sha");

-- CreateIndex
CREATE INDEX "builds_job_id_idx" ON "builds"("job_id");

-- CreateIndex
CREATE INDEX "builds_status_updated_at_idx" ON "builds"("status", "updated_at");

-- CreateIndex
CREATE UNIQUE INDEX "builds_application_id_idempotency_key_key" ON "builds"("application_id", "idempotency_key");

-- CreateIndex
CREATE UNIQUE INDEX "compose_app_versions_application_id_version_key" ON "compose_app_versions"("application_id", "version");

-- CreateIndex
CREATE UNIQUE INDEX "source_inspections_job_id_key" ON "source_inspections"("job_id");

-- CreateIndex
CREATE INDEX "source_inspections_application_id_created_at_idx" ON "source_inspections"("application_id", "created_at");

-- AddForeignKey
ALTER TABLE "build_configs" ADD CONSTRAINT "build_configs_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "builds" ADD CONSTRAINT "builds_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "compose_app_versions" ADD CONSTRAINT "compose_app_versions_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "source_inspections" ADD CONSTRAINT "source_inspections_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;



-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

-- Applications may now be managed compose apps.
ALTER TABLE "applications" DROP CONSTRAINT "applications_kind_check";
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown','container','compose'));

-- One active build per (application, commit) — dedupe for manual + webhook builds.
CREATE UNIQUE INDEX "builds_one_active_per_app_commit"
  ON "builds" ("application_id", "commit_sha")
  WHERE "status" IN ('queued','fetching','building','pushing');

ALTER TABLE "builds" ADD CONSTRAINT "builds_status_check"
  CHECK ("status" IN ('queued','fetching','building','pushing','succeeded','failed','cancelled','expired'));
ALTER TABLE "builds" ADD CONSTRAINT "builds_trigger_check"
  CHECK ("trigger" IN ('manual','webhook'));
ALTER TABLE "builds" ADD CONSTRAINT "builds_commit_sha_check"
  CHECK ("commit_sha" ~ '^[a-f0-9]{40}$');
ALTER TABLE "builds" ADD CONSTRAINT "builds_image_digest_check"
  CHECK ("image" IS NULL OR "image" ~ '@sha256:[a-f0-9]{64}$');
ALTER TABLE "build_configs" ADD CONSTRAINT "build_configs_source_check"
  CHECK (("dockerfile" IS NULL) <> ("template" IS NULL));
ALTER TABLE "build_configs" ADD CONSTRAINT "build_configs_network_check"
  CHECK ("network" IN ('default','none'));
ALTER TABLE "compose_app_versions" ADD CONSTRAINT "compose_app_versions_route_port_check"
  CHECK ("route_port" BETWEEN 1 AND 65535);
ALTER TABLE "source_inspections" ADD CONSTRAINT "source_inspections_commit_sha_check"
  CHECK ("commit_sha" ~ '^[a-f0-9]{40}$');

ALTER TABLE "auto_deploy_policies" ADD CONSTRAINT "auto_deploy_policies_mode_check"
  CHECK ("mode" IN ('image','build'));
ALTER TABLE "auto_deploy_policies" ADD CONSTRAINT "auto_deploy_policies_template_check"
  CHECK ("mode" = 'build' OR "image_template" IS NOT NULL);

ALTER TABLE "webhook_deliveries" DROP CONSTRAINT "webhook_deliveries_result_check";
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_result_check"
  CHECK ("result" IN ('deployed','awaiting_approval','ignored','failed','building'));

-- Rollback (manual): see ROLLBACK.md next to this file.
