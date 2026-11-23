-- CreateTable
CREATE TABLE "discovery_scans" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "job_id" UUID NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'running',
    "sources" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "requested_by" UUID,
    "started_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMPTZ(3),
    "summary" JSONB,
    "config_files" JSONB NOT NULL DEFAULT '[]',
    "drift" JSONB NOT NULL DEFAULT '[]',
    "error" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "discovery_scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "discovery_findings" (
    "id" UUID NOT NULL,
    "scan_id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "kind" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "external_id" TEXT,
    "title" TEXT NOT NULL,
    "domains" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "listen" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "provenance" JSONB,
    "confidence" TEXT NOT NULL,
    "manual_review_required" BOOLEAN NOT NULL DEFAULT false,
    "reasons" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "unsupported_directives" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "conflicts" JSONB NOT NULL DEFAULT '[]',
    "links" JSONB NOT NULL DEFAULT '{}',
    "application_id" UUID,
    "data" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "discovery_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "applications" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "domains" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "ownership_mode" TEXT NOT NULL DEFAULT 'observed',
    "flag_unsupported" BOOLEAN NOT NULL DEFAULT false,
    "flag_conflict" BOOLEAN NOT NULL DEFAULT false,
    "flag_manual_review" BOOLEAN NOT NULL DEFAULT false,
    "flag_drift_detected" BOOLEAN NOT NULL DEFAULT false,
    "reasons" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "unsupported_directives" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "source_finding_fingerprint" TEXT NOT NULL,
    "nginx_files" JSONB NOT NULL DEFAULT '[]',
    "drift_files" JSONB NOT NULL DEFAULT '[]',
    "last_scan_id" UUID,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "applications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "adoption_reviews" (
    "id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "from_mode" TEXT NOT NULL,
    "to_mode" TEXT NOT NULL,
    "actor_id" UUID NOT NULL,
    "reason" TEXT NOT NULL,
    "acknowledged_reasons" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "step_up" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "adoption_reviews_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "nginx_config_revisions" (
    "id" UUID NOT NULL,
    "server_id" UUID NOT NULL,
    "application_id" UUID NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'draft',
    "files" JSONB NOT NULL,
    "plan_hash" TEXT NOT NULL,
    "postchecks" JSONB NOT NULL DEFAULT '[]',
    "approval_required" BOOLEAN NOT NULL,
    "validate_job_id" UUID,
    "validation" JSONB,
    "apply_job_id" UUID,
    "revert_job_id" UUID,
    "result" JSONB,
    "created_by" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "nginx_config_revisions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "nginx_revision_approvals" (
    "id" UUID NOT NULL,
    "revision_id" UUID NOT NULL,
    "approver_id" UUID NOT NULL,
    "plan_hash" TEXT NOT NULL,
    "approved_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "used_by_job_id" UUID,
    "invalidated_at" TIMESTAMPTZ(3),

    CONSTRAINT "nginx_revision_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "discovery_scans_job_id_key" ON "discovery_scans"("job_id");

-- CreateIndex
CREATE INDEX "discovery_scans_server_id_completed_at_idx" ON "discovery_scans"("server_id", "completed_at" DESC);

-- CreateIndex
CREATE INDEX "discovery_scans_status_idx" ON "discovery_scans"("status");

-- CreateIndex
CREATE INDEX "discovery_findings_scan_id_kind_idx" ON "discovery_findings"("scan_id", "kind");

-- CreateIndex
CREATE INDEX "discovery_findings_server_id_fingerprint_idx" ON "discovery_findings"("server_id", "fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "discovery_findings_scan_id_fingerprint_key" ON "discovery_findings"("scan_id", "fingerprint");

-- CreateIndex
CREATE INDEX "applications_ownership_mode_idx" ON "applications"("ownership_mode");

-- CreateIndex
CREATE UNIQUE INDEX "applications_server_id_source_finding_fingerprint_key" ON "applications"("server_id", "source_finding_fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "applications_server_id_name_key" ON "applications"("server_id", "name");

-- CreateIndex
CREATE INDEX "adoption_reviews_application_id_created_at_idx" ON "adoption_reviews"("application_id", "created_at");

-- CreateIndex
CREATE INDEX "nginx_config_revisions_application_id_created_at_idx" ON "nginx_config_revisions"("application_id", "created_at");

-- CreateIndex
CREATE INDEX "nginx_config_revisions_server_id_status_idx" ON "nginx_config_revisions"("server_id", "status");

-- CreateIndex
CREATE INDEX "nginx_revision_approvals_revision_id_approved_at_idx" ON "nginx_revision_approvals"("revision_id", "approved_at");

-- AddForeignKey
ALTER TABLE "discovery_scans" ADD CONSTRAINT "discovery_scans_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "discovery_findings" ADD CONSTRAINT "discovery_findings_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "discovery_scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "discovery_findings" ADD CONSTRAINT "discovery_findings_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "applications" ADD CONSTRAINT "applications_server_id_fkey" FOREIGN KEY ("server_id") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "adoption_reviews" ADD CONSTRAINT "adoption_reviews_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "nginx_config_revisions" ADD CONSTRAINT "nginx_config_revisions_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "nginx_revision_approvals" ADD CONSTRAINT "nginx_revision_approvals_revision_id_fkey" FOREIGN KEY ("revision_id") REFERENCES "nginx_config_revisions"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

-- At most one open (non-terminal) Nginx revision per application.
CREATE UNIQUE INDEX "nginx_config_revisions_one_open_per_app"
  ON "nginx_config_revisions" ("application_id")
  WHERE "status" IN ('draft','validating','valid','awaiting_approval','approved','applying','reverting');

-- Data integrity checks for enum-like columns.
ALTER TABLE "discovery_scans" ADD CONSTRAINT "discovery_scans_status_check"
  CHECK ("status" IN ('running','completed','failed','expired'));
ALTER TABLE "discovery_findings" ADD CONSTRAINT "discovery_findings_kind_check"
  CHECK ("kind" IN ('nginx_server','php_fpm_pool','listener','container','systemd_unit','upstream'));
ALTER TABLE "discovery_findings" ADD CONSTRAINT "discovery_findings_confidence_check"
  CHECK ("confidence" IN ('high','medium','low'));
ALTER TABLE "applications" ADD CONSTRAINT "applications_ownership_mode_check"
  CHECK ("ownership_mode" IN ('discovered','observed','adopted','managed'));
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown'));
ALTER TABLE "adoption_reviews" ADD CONSTRAINT "adoption_reviews_mode_check"
  CHECK ("from_mode" IN ('discovered','observed','adopted','managed')
         AND "to_mode" IN ('discovered','observed','adopted','managed'));
ALTER TABLE "nginx_config_revisions" ADD CONSTRAINT "nginx_config_revisions_status_check"
  CHECK ("status" IN ('draft','validating','valid','invalid','awaiting_approval','approved','applying',
                      'applied','apply_failed','reverting','reverted','drift_blocked','superseded','cancelled',
                      'requires_manual_recovery'));
ALTER TABLE "nginx_config_revisions" ADD CONSTRAINT "nginx_config_revisions_plan_hash_check"
  CHECK ("plan_hash" ~ '^[a-f0-9]{64}$');
ALTER TABLE "nginx_revision_approvals" ADD CONSTRAINT "nginx_revision_approvals_expiry_check"
  CHECK ("expires_at" > "approved_at");
