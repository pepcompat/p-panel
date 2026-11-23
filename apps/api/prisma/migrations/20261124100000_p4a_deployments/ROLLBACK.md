# Rollback plan — 20261124100000_p4a_deployments

Adds P4a tables (`container_apps`, `secrets`, `deployments`, `deployment_steps`, `operation_approvals`,
`managed_routing`, `host_port_allocations`, `integrations`, `webhook_deliveries`, `auto_deploy_policies`),
the nullable `jobs.secrets_fetched_at` column and widens `applications_kind_check` with `container`.
Rolling back destroys deployment history and **encrypted app secrets** — export first if needed
(`pg_dump -t container_apps -t secrets -t 'deployment*' -t integrations -t webhook_deliveries -t auto_deploy_policies`).

Before rolling back: no `container.*` / `nginx.apply` job may be `leased`/`running`. Containers and
route files on hosts are unaffected (remove them with the agent first if desired).

```sql
BEGIN;
DROP TABLE IF EXISTS "auto_deploy_policies", "webhook_deliveries", "integrations", "host_port_allocations",
  "managed_routing", "operation_approvals", "deployment_steps", "deployments", "secrets", "container_apps" CASCADE;
ALTER TABLE "jobs" DROP COLUMN IF EXISTS "secrets_fetched_at";
DELETE FROM "applications" WHERE "kind" = 'container';
ALTER TABLE "applications" DROP CONSTRAINT "applications_kind_check";
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown'));
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261124100000_p4a_deployments';
COMMIT;
```
