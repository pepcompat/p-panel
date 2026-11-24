# Rollback plan — 20261129100000_p9_network

Expand-only: adds `server_connections`, `server_network_inventory`, `provider_integrations`,
`network_connectivity_tests`, `gateways`, `gateway_routes`, `gateway_change_plans`; widens
`applications_kind_check` with `gateway`; adds closed-enum CHECKs on the new tables and on
`servers.connection_policy` (values were already Zod-validated).

Nothing on managed hosts is changed by rolling back the schema: Gateway Nginx files already applied
stay on the gateway hosts (revert them first with `POST /gateway-plans/:id/rollback` if wanted) and
the agents keep their last `connection.json`. Provider tokens are lost with the table (re-create the
integration after a roll-forward).

Stop the Center first, then:

```sql
BEGIN;
DROP TABLE IF EXISTS "gateway_change_plans";
DROP TABLE IF EXISTS "gateway_routes";
DROP TABLE IF EXISTS "gateways";
DROP TABLE IF EXISTS "network_connectivity_tests";
DROP TABLE IF EXISTS "provider_integrations";
DROP TABLE IF EXISTS "server_network_inventory";
DROP TABLE IF EXISTS "server_connections";
ALTER TABLE "servers" DROP CONSTRAINT IF EXISTS "servers_connection_policy_check";
-- gateway applications (and their nginx revisions, by cascade) cannot exist under the old CHECK
DELETE FROM "applications" WHERE "kind" = 'gateway';
ALTER TABLE "applications" DROP CONSTRAINT "applications_kind_check";
ALTER TABLE "applications" ADD CONSTRAINT "applications_kind_check"
  CHECK ("kind" IN ('nginx_static','nginx_php','nginx_proxy','unknown','container','compose'));
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261129100000_p9_network';
COMMIT;
```

Then deploy the previous Center image (0.8.x). Older Centers ignore the heartbeat `connection` /
`provider` fields and send no `connection` directive; set any `private_only` server back to `auto`
before rolling back so the agent's last persisted policy does not keep it off the public path.
