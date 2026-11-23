# Rollback plan — 20261127100000_p6_backups

Adds P6 tables only (`backup_repositories`, `backup_repo_access`, `backup_maintenance_reports`,
`backup_policies`, `backup_runs`, `backup_verifications`, `restores`, `restore_steps`) plus three
hand-written partial unique indexes and CHECK constraints. Existing tables: only the CHECK constraints
`operation_approvals_subject_check` (+ `restore`) and `incidents_target_type_check` (+ `backup_policy`)
are widened.

Rolling back destroys the Center's backup **metadata** only (policies, run history, manifests,
restore audit trail is kept in `audit_events`). The restic data in the repositories is untouched.
**Before rolling back, run `GET /api/v1/backup-repositories/:id/recovery-export` for every
repository and store the repo passwords offline** — `backup_repo_access` holds the only Center copy
of them (encrypted). Stop the Center first so the backup scheduler is not running.

```sql
BEGIN;
DROP TABLE IF EXISTS "restore_steps", "restores", "backup_verifications", "backup_runs",
  "backup_policies", "backup_maintenance_reports", "backup_repo_access", "backup_repositories" CASCADE;
DELETE FROM "operation_approvals" WHERE "subject_type" = 'restore';
DELETE FROM "incidents" WHERE "target_type" = 'backup_policy';
ALTER TABLE "operation_approvals" DROP CONSTRAINT "operation_approvals_subject_check";
ALTER TABLE "operation_approvals" ADD CONSTRAINT "operation_approvals_subject_check"
  CHECK ("subject_type" IN ('deployment','managed_routing'));
ALTER TABLE "incidents" DROP CONSTRAINT "incidents_target_type_check";
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_target_type_check"
  CHECK ("target_type" IN ('server','app'));
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261127100000_p6_backups';
COMMIT;
```
