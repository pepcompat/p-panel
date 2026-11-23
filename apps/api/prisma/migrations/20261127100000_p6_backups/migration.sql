-- P6: backup repositories, policies + scheduler state, runs/manifests/verifications, restores (API_CONTRACTS §10, ADR-0009).
-- DropIndex

-- CreateTable
CREATE TABLE "backup_repositories" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'rest',
    "base_url" TEXT NOT NULL,
    "offsite" JSONB,
    "created_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "backup_repositories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_repo_access" (
    "repository_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "rest_user" TEXT NOT NULL,
    "rest_password_enc" TEXT NOT NULL,
    "repo_password_enc" TEXT NOT NULL,
    "initialized_at" TIMESTAMPTZ(3),
    "initialized_by" UUID,
    "created_by" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "backup_repo_access_pkey" PRIMARY KEY ("repository_id","server_id")
);

-- CreateTable
CREATE TABLE "backup_maintenance_reports" (
    "id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "server_user" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "ok" BOOLEAN NOT NULL,
    "finished_at" TIMESTAMPTZ(3) NOT NULL,
    "detail" JSONB NOT NULL DEFAULT '{}',
    "received_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "backup_maintenance_reports_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_policies" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "server_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "targets" JSONB NOT NULL,
    "schedule_cron" TEXT NOT NULL,
    "timezone" TEXT NOT NULL,
    "retention" JSONB NOT NULL,
    "verify" JSONB NOT NULL,
    "helper_image" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "next_run_at" TIMESTAMPTZ(3),
    "last_scheduled_at" TIMESTAMPTZ(3),
    "last_restore_test_at" TIMESTAMPTZ(3),
    "deleted_at" TIMESTAMPTZ(3),
    "created_by" UUID NOT NULL,
    "updated_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "backup_policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_runs" (
    "id" UUID NOT NULL,
    "policy_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "trigger" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "verification" TEXT NOT NULL DEFAULT 'none',
    "verified_at" TIMESTAMPTZ(3),
    "targets" JSONB NOT NULL,
    "snapshots" JSONB NOT NULL DEFAULT '[]',
    "manifest_summary" JSONB NOT NULL DEFAULT '{}',
    "manifest" JSONB NOT NULL DEFAULT '[]',
    "restic_version" TEXT,
    "error" JSONB,
    "job_id" UUID,
    "idempotency_key" TEXT,
    "scheduled_for" TIMESTAMPTZ(3),
    "restore_id" UUID,
    "created_by" UUID,
    "started_at" TIMESTAMPTZ(3),
    "finished_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "backup_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_verifications" (
    "id" UUID NOT NULL,
    "run_id" UUID NOT NULL,
    "level" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'running',
    "job_ids" UUID[] DEFAULT ARRAY[]::UUID[],
    "results" JSONB NOT NULL DEFAULT '[]',
    "error" JSONB,
    "created_by" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "backup_verifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "restores" (
    "id" UUID NOT NULL,
    "run_id" UUID NOT NULL,
    "snapshot_id" TEXT NOT NULL,
    "server_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "application_id" UUID,
    "target" JSONB NOT NULL,
    "target_index" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'planned',
    "impact" JSONB NOT NULL,
    "dry_run" JSONB,
    "plan_hash" TEXT NOT NULL,
    "approval_required" BOOLEAN NOT NULL,
    "approval_reasons" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "safety_snapshot_run_id" UUID,
    "result" JSONB,
    "error" JSONB,
    "created_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "restores_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "restore_steps" (
    "id" UUID NOT NULL,
    "restore_id" UUID NOT NULL,
    "seq" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "job_id" UUID,
    "backup_run_id" UUID,
    "deployment_id" UUID,
    "message" TEXT,
    "error_code" TEXT,
    "started_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finished_at" TIMESTAMPTZ(3),

    CONSTRAINT "restore_steps_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "backup_repositories_name_key" ON "backup_repositories"("name");

-- CreateIndex
CREATE INDEX "backup_repo_access_server_id_idx" ON "backup_repo_access"("server_id");

-- CreateIndex
CREATE UNIQUE INDEX "backup_repo_access_repository_id_rest_user_key" ON "backup_repo_access"("repository_id", "rest_user");

-- CreateIndex
CREATE INDEX "backup_maintenance_reports_repository_id_server_user_kind_f_idx" ON "backup_maintenance_reports"("repository_id", "server_user", "kind", "finished_at");

-- CreateIndex
CREATE INDEX "backup_policies_server_id_idx" ON "backup_policies"("server_id");

-- CreateIndex
CREATE INDEX "backup_policies_enabled_next_run_at_idx" ON "backup_policies"("enabled", "next_run_at");

-- CreateIndex
CREATE UNIQUE INDEX "backup_runs_job_id_key" ON "backup_runs"("job_id");

-- CreateIndex
CREATE INDEX "backup_runs_server_id_created_at_idx" ON "backup_runs"("server_id", "created_at");

-- CreateIndex
CREATE INDEX "backup_runs_policy_id_created_at_idx" ON "backup_runs"("policy_id", "created_at");

-- CreateIndex
CREATE INDEX "backup_runs_status_updated_at_idx" ON "backup_runs"("status", "updated_at");

-- CreateIndex
CREATE UNIQUE INDEX "backup_runs_policy_id_idempotency_key_key" ON "backup_runs"("policy_id", "idempotency_key");

-- CreateIndex
CREATE INDEX "backup_verifications_run_id_created_at_idx" ON "backup_verifications"("run_id", "created_at");

-- CreateIndex
CREATE INDEX "backup_verifications_status_idx" ON "backup_verifications"("status");

-- CreateIndex
CREATE INDEX "restores_server_id_created_at_idx" ON "restores"("server_id", "created_at");

-- CreateIndex
CREATE INDEX "restores_run_id_idx" ON "restores"("run_id");

-- CreateIndex
CREATE INDEX "restores_status_updated_at_idx" ON "restores"("status", "updated_at");

-- CreateIndex
CREATE INDEX "restore_steps_job_id_idx" ON "restore_steps"("job_id");

-- CreateIndex
CREATE INDEX "restore_steps_backup_run_id_idx" ON "restore_steps"("backup_run_id");

-- CreateIndex
CREATE INDEX "restore_steps_deployment_id_idx" ON "restore_steps"("deployment_id");

-- CreateIndex
CREATE UNIQUE INDEX "restore_steps_restore_id_seq_key" ON "restore_steps"("restore_id", "seq");

-- AddForeignKey
ALTER TABLE "backup_repo_access" ADD CONSTRAINT "backup_repo_access_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "backup_repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_repo_access" ADD CONSTRAINT "backup_repo_access_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_maintenance_reports" ADD CONSTRAINT "backup_maintenance_reports_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "backup_repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_policies" ADD CONSTRAINT "backup_policies_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_policies" ADD CONSTRAINT "backup_policies_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "backup_repositories"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_runs" ADD CONSTRAINT "backup_runs_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "backup_policies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_verifications" ADD CONSTRAINT "backup_verifications_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "backup_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "restore_steps" ADD CONSTRAINT "restore_steps_restore_id_fkey" FOREIGN KEY ("restore_id") REFERENCES "restores"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Hand-written (not expressible in schema.prisma):
-- at most one queued/running run per policy (scheduler + manual run race safety)
CREATE UNIQUE INDEX "backup_runs_one_active_per_policy" ON "backup_runs" ("policy_id")
  WHERE "status" IN ('queued', 'running');
-- at most one running verification per run
CREATE UNIQUE INDEX "backup_verifications_one_running_per_run" ON "backup_verifications" ("run_id")
  WHERE "status" = 'running';
-- at most one executing restore per server (in-place restores stop/start apps)
CREATE UNIQUE INDEX "restores_one_running_per_server" ON "restores" ("server_id")
  WHERE "status" = 'running';

-- P6 widens two P4a/P5 checks: restores use operation approvals; backup_failed incidents target a policy
ALTER TABLE "operation_approvals" DROP CONSTRAINT "operation_approvals_subject_check";
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_subject_check"
  CHECK ("subject_type" IN ('deployment','managed_routing','restore'));
ALTER TABLE "incidents" DROP CONSTRAINT "incidents_target_type_check";
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_target_type_check"
  CHECK ("target_type" IN ('server','app','backup_policy'));

-- vocabularies (API_CONTRACTS §10)
ALTER TABLE "backup_runs" ADD CONSTRAINT "backup_runs_status_check"
  CHECK ("status" IN ('queued','running','uploaded','failed','expired','cancelled'));
ALTER TABLE "backup_runs" ADD CONSTRAINT "backup_runs_verification_check"
  CHECK ("verification" IN ('none','repository_checked','restore_verified','verify_failed'));
ALTER TABLE "backup_runs" ADD CONSTRAINT "backup_runs_trigger_check"
  CHECK ("trigger" IN ('schedule','manual','safety'));
ALTER TABLE "backup_verifications" ADD CONSTRAINT "backup_verifications_check"
  CHECK ("level" IN ('check','restore_test') AND "status" IN ('running','passed','failed'));
ALTER TABLE "backup_maintenance_reports" ADD CONSTRAINT "backup_maintenance_reports_kind_check"
  CHECK ("kind" IN ('prune','copy','check','unlock'));
ALTER TABLE "restores" ADD CONSTRAINT "restores_status_check"
  CHECK ("status" IN ('planned','impact_reviewed','awaiting_approval','approved','running','verified','failed','requires_manual_recovery','cancelled'));
ALTER TABLE "restore_steps" ADD CONSTRAINT "restore_steps_check"
  CHECK ("name" IN ('dry_run','safety_backup','stop_app','restore','start_app') AND "status" IN ('running','succeeded','failed','skipped'));
