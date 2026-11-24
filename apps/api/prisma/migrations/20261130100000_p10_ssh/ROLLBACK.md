# Rollback plan — 20261130100000_p10_ssh

Expand-only: adds `ssh_credentials`, `ssh_endpoints`, `ssh_key_deployments`, `ssh_host_keys`,
`ssh_access_grants`, `ssh_sessions` (closed-enum CHECKs, partial unique index "one trusted host key
per endpoint + algorithm") and the nullable `servers.ssh_facts` column.

Rolling back the schema does not touch managed hosts: the pPanel-managed block in
`~user/.ssh/authorized_keys` stays as last written. Remove it first (revoke every credential and
wait for the `ssh.keys.sync` jobs to finish) if the keys must go. Center-held private keys are lost
with the table (they are never exported).

Stop the Center first (live terminals close with `center_shutdown`), then:

```sql
BEGIN;
DROP TABLE IF EXISTS "ssh_sessions";
DROP TABLE IF EXISTS "ssh_access_grants";
DROP TABLE IF EXISTS "ssh_host_keys";
DROP TABLE IF EXISTS "ssh_key_deployments";
DROP TABLE IF EXISTS "ssh_endpoints";
DROP TABLE IF EXISTS "ssh_credentials";
ALTER TABLE "servers" DROP COLUMN IF EXISTS "ssh_facts";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261130100000_p10_ssh';
COMMIT;
```

Then deploy the previous Center image. Queued `ssh.keys.sync` jobs of an older Center are unknown
job types for it and expire.
