# Rollback plan — 20261125100000_p4b_builds_compose

Adds P4b tables (`build_configs`, `builds`, `compose_app_versions`, `source_inspections`), columns
`servers.build_node`, `deployments.{build_id,compose_version_id,plan,service_results}`,
`webhook_deliveries.build_ids`, `auto_deploy_policies.mode` (and makes `image_template` nullable),
widens `applications_kind_check` with `compose` and `webhook_deliveries_result_check` with `building`.
Rolling back destroys build history and stored compose files — export first if needed
(`pg_dump -t build_configs -t builds -t compose_app_versions -t source_inspections`).

Before rolling back: no `image.build` / `source.inspect` / `compose.*` job may be `leased`/`running`,
and no build-mode auto-deploy policy may remain (they are deleted below). Containers, volumes and
images on hosts are unaffected.

```sql
BEGIN;
DROP TABLE IF EXISTS "source_inspections", "compose_app_versions", "builds", "build_configs" CASCADE;
DELETE FROM "auto_deploy_policies" WHERE "mode" = 'build';
ALTER TABLE "auto_deploy_policies" DROP CONSTRAINT IF EXISTS "auto_deploy_policies_template_check";
ALTER TABLE "auto_deploy_policies" DROP CONSTRAINT IF EXISTS "auto_deploy_policies_mode_check";
ALTER TABLE "auto_deploy_policies" DROP COLUMN "mode", ALTER COLUMN "image_template" SET NOT NULL;
UPDATE "webhook_deliveries" SET "result" = 'ignored' WHERE "result" = 'building';
ALTER TABLE "webhook_deliveries" DROP CONSTRAINT "webhook_deliveries_result_check";
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_result_check"
  CHECK ("result" IN ('deployed','awaiting_approval','ignored','failed'));
ALTER TABLE "webhook_deliveries" DROP COLUMN "build_ids";
ALTER TABLE "deployments" DROP COLUMN "build_id", DROP COLUMN "compose_version_id",
  DROP COLUMN "plan", DROP COLUMN "service_results";
ALTER TABLE "servers" DROP COLUMN "build_node";
DELETE FROM "applications" WHERE "kind" = 'compose';
ALTER TABLE "applications" DROP CONSTRAINT "applications_kind_check";
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown','container'));
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261125100000_p4b_builds_compose';
COMMIT;
```
