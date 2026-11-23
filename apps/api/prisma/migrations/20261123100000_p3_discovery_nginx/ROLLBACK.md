# Rollback plan — 20261123100000_p3_discovery_nginx

Adds P3 tables only (`discovery_scans`, `discovery_findings`, `applications`, `adoption_reviews`,
`nginx_config_revisions`, `nginx_revision_approvals`). No existing table or column is altered, so the
rollback is a pure drop. It destroys scan history, ownership tiers and revision/approval history — export
them first (`pg_dump -t 'discovery_*' -t applications -t adoption_reviews -t 'nginx_*'`) if they matter.

Before rolling back: make sure no `nginx.validate|apply|revert` job is `leased`/`running`
(`SELECT id FROM jobs WHERE type LIKE 'nginx.%' AND status IN ('leased','running')`). Host-side backups
under the agent state dir are unaffected.

```sql
BEGIN;
DROP TABLE IF EXISTS "nginx_revision_approvals";
DROP TABLE IF EXISTS "nginx_config_revisions";
DROP TABLE IF EXISTS "adoption_reviews";
DROP TABLE IF EXISTS "discovery_findings";
DROP TABLE IF EXISTS "applications";
DROP TABLE IF EXISTS "discovery_scans";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261123100000_p3_discovery_nginx';
COMMIT;
```

Then deploy the previous API build (the P2 API ignores the P3 job types' results gracefully: they stay plain jobs).
