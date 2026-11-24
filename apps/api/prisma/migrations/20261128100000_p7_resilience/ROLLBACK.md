# Rollback plan — 20261128100000_p7_resilience

Adds `pending_webhook_deploys` (F-7 coalesced webhook commits), widens
`webhook_deliveries_result_check` with `queued` / `superseded`, adds partial unique indexes
`nginx_revision_approvals_one_usable` and `operation_approvals_one_usable` (F-6), and raises
`server_offline` alert rules below 90 s to `for_sec = 90` (F-14; not reverted — the old values were
unsafe and are not recorded).

Stop the Center first. Pending (queued) webhook commits are lost on rollback; re-push or deploy
them manually.

```sql
BEGIN;
DROP TABLE IF EXISTS "pending_webhook_deploys";
UPDATE "webhook_deliveries" SET "result" = 'ignored' WHERE "result" IN ('queued', 'superseded');
ALTER TABLE "webhook_deliveries" DROP CONSTRAINT "webhook_deliveries_result_check";
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_result_check"
  CHECK ("result" IN ('deployed','awaiting_approval','ignored','failed','building'));
DROP INDEX IF EXISTS "nginx_revision_approvals_one_usable";
DROP INDEX IF EXISTS "operation_approvals_one_usable";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261128100000_p7_resilience';
COMMIT;
```
