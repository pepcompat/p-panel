-- P7 resilience fixes (F-6, F-7, F-14). Generated part: `prisma migrate diff`; hand-written part below.

-- CreateTable
CREATE TABLE "pending_webhook_deploys" (
    "application_id" UUID NOT NULL,
    "policy_id" UUID NOT NULL,
    "delivery_row_id" UUID NOT NULL,
    "repo" TEXT NOT NULL,
    "branch" TEXT NOT NULL,
    "commit_sha" TEXT NOT NULL,
    "queued_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pending_webhook_deploys_pkey" PRIMARY KEY ("application_id")
);

-- CreateIndex
CREATE INDEX "pending_webhook_deploys_delivery_row_id_idx" ON "pending_webhook_deploys"("delivery_row_id");

-- AddForeignKey
ALTER TABLE "pending_webhook_deploys" ADD CONSTRAINT "pending_webhook_deploys_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pending_webhook_deploys" ADD CONSTRAINT "pending_webhook_deploys_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "auto_deploy_policies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pending_webhook_deploys" ADD CONSTRAINT "pending_webhook_deploys_delivery_row_id_fkey" FOREIGN KEY ("delivery_row_id") REFERENCES "webhook_deliveries"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Hand-written (not expressible in Prisma schema)
-- ---------------------------------------------------------------------------

ALTER TABLE "pending_webhook_deploys" ADD CONSTRAINT "pending_webhook_deploys_commit_check"
  CHECK ("commit_sha" ~ '^[a-f0-9]{40}$');

-- F-7: coalesced webhook deliveries are `queued` (waiting for the running deployment) or
-- `superseded` (replaced by a newer push before they deployed).
ALTER TABLE "webhook_deliveries" DROP CONSTRAINT "webhook_deliveries_result_check";
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_result_check"
  CHECK ("result" IN ('deployed','awaiting_approval','ignored','failed','building','queued','superseded'));

-- F-6: at most one usable (unused, not invalidated) approval per nginx revision. Older duplicates
-- left by the race are invalidated first (keep the newest).
UPDATE "nginx_revision_approvals" a SET "invalidated_at" = CURRENT_TIMESTAMP
  WHERE a."used_at" IS NULL AND a."invalidated_at" IS NULL
    AND EXISTS (
      SELECT 1 FROM "nginx_revision_approvals" b
      WHERE b."revision_id" = a."revision_id" AND b."used_at" IS NULL AND b."invalidated_at" IS NULL
        AND (b."approved_at", b."id") > (a."approved_at", a."id"));
CREATE UNIQUE INDEX "nginx_revision_approvals_one_usable"
  ON "nginx_revision_approvals" ("revision_id")
  WHERE "used_at" IS NULL AND "invalidated_at" IS NULL;

-- Same invariant for operation approvals (deployments, managed routing, restores).
UPDATE "operation_approvals" a SET "invalidated_at" = CURRENT_TIMESTAMP
  WHERE a."used_at" IS NULL AND a."invalidated_at" IS NULL
    AND EXISTS (
      SELECT 1 FROM "operation_approvals" b
      WHERE b."subject_type" = a."subject_type" AND b."subject_id" = a."subject_id"
        AND b."used_at" IS NULL AND b."invalidated_at" IS NULL
        AND (b."approved_at", b."id") > (a."approved_at", a."id"));
CREATE UNIQUE INDEX "operation_approvals_one_usable"
  ON "operation_approvals" ("subject_type", "subject_id")
  WHERE "used_at" IS NULL AND "invalidated_at" IS NULL;

-- F-14: server_offline rules need forSec >= 90 (agents reconnect up to ~60 s after a Center
-- restart). Existing shorter rules are raised (the evaluator also clamps).
UPDATE "alert_rules" SET "for_sec" = 90, "version" = "version" + 1, "updated_at" = CURRENT_TIMESTAMP
  WHERE "kind" = 'server_offline' AND "for_sec" < 90;

-- Rollback (manual): see ROLLBACK.md next to this file.
