# pPanel — Database migration runbook (P8.04)

How Center schema changes are written, reviewed, shipped and — when something goes wrong — recovered.
Release-level policy: `docs/RELEASE_CONTRACT.md` §2. Operator procedure: `docs/UPGRADE_RUNBOOK.md`.
Team standard: migrations via Prisma with a rollback plan; snake_case tables/columns, pk `id`, fk
`<table>_id`.

## 1. How migrations run

- Source of truth: `apps/api/prisma/schema.prisma` + `apps/api/prisma/migrations/<timestamp>_<name>/`
  (`migration.sql` + `ROLLBACK.md`). The latest applied migration name is the Center's `schemaVersion`
  (`GET /api/v1/version`, `backup-center.sh dump` output).
- Production applies them with `prisma migrate deploy` only — never `migrate dev`, `db push` or
  `migrate reset`. In the release image: `ppanel-api migrate` (what `upgrade.sh` runs, step 6), and
  `ppanel-api serve` runs `migrate deploy` before boot (a no-op when already applied; set
  `PPANEL_SKIP_MIGRATE=1` to skip it). `ppanel-api migrate-status` = `prisma migrate status`.
- Prisma records each migration in `_prisma_migrations` (checksum, `finished_at`, `rolled_back_at`, logs).
  `migrate deploy` refuses to continue while any migration is recorded as failed.
- A migration file never changes after it has been released (the checksum would no longer match).

## 2. Expand / contract (mandatory)

Each release must leave the schema readable **and writable** by the previous release's Center code,
because a rollback window exists (`docs/UPGRADE_RUNBOOK.md` §6) and `rollback.sh` brings old code back.
Destructive changes are split over releases:

| Change                         | Release N (expand)                                                                                                                               | Release N+1 or later (contract)                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| add column                     | nullable, or `NOT NULL DEFAULT …`; old code ignores it                                                                                           | —                                                    |
| rename column / table          | add the new one, write both, backfill, read the new one                                                                                          | drop the old one once no supported release reads it  |
| drop column / table            | stop reading and writing it (code only)                                                                                                          | drop it                                              |
| change type / tighten          | add a new column with the new type, dual-write, backfill                                                                                         | swap reads, then drop the old column                 |
| new `CHECK` / enum value       | widen first (old values still valid); old code must tolerate the new value                                                                       | tighten only after every supported release writes it |
| new `NOT NULL` without default | add nullable + backfill + code always writes it                                                                                                  | `SET NOT NULL`                                       |
| big backfill / index           | separate migration; `CREATE INDEX CONCURRENTLY` is not possible inside Prisma's transaction — keep tables small or schedule a maintenance window | —                                                    |

"Supported release" = the current one and the one before it (the rollback target). Never drop or rename,
in the same release, anything the previous release reads.

## 3. Authoring checklist

- [ ] `pnpm --filter @ppanel/api exec prisma migrate dev --name <phase>_<what>` against a **dev** DB;
      the folder name is `<UTC timestamp>_<snake_case_name>`.
- [ ] Read the generated SQL. Add hand-written parts (partial indexes, `CHECK`s, data fixes) in the same
      `migration.sql`; allowlist objects Prisma cannot model in `apps/api/prisma/drift-allowlist.txt`.
- [ ] Expand/contract respected (§2); tables/columns snake_case, pk `id`, fk `<table>_id`; money as
      `numeric`, timestamps `timestamptz` (UTC), enums as text + `CHECK`.
- [ ] Idempotency where cheap (`IF NOT EXISTS` / `IF EXISTS`) — a re-run after a partial failure is then
      simpler (§5).
- [ ] Data-changing statements are deterministic and documented (e.g. P7 raised `server_offline.for_sec`
      < 90 to 90 — not reversible, said so in `ROLLBACK.md`).
- [ ] **`ROLLBACK.md`** next to `migration.sql` (§4).
- [ ] Drift check passes: CI step "Prisma migrate (fresh DB) + drift check" runs `prisma migrate deploy`
      on a fresh DB, then `apps/api/scripts/check-migration-drift.sh`, which runs `prisma migrate diff`
      from the migrations to `schema.prisma` against a shadow DB and fails on any non-allowlisted diff.
      Locally: `SHADOW_DATABASE_URL=postgresql://…/ppanel_shadow apps/api/scripts/check-migration-drift.sh`.
- [ ] Integration tests pass on the migrated schema (`pnpm test:integration`).
- [ ] Upgrade test from the previous release with data (`scripts/lab/e2e_p8_upgrade.py` pattern): tables
      retained, previous release still works after `rollback.sh`.
- [ ] Release notes list the migration, its expected duration on a large DB, and anything not reversible.

## 4. `ROLLBACK.md` convention

Every migration folder contains `ROLLBACK.md` (existing convention since P2, see
`apps/api/prisma/migrations/*/ROLLBACK.md`):

1. **What the migration adds/changes** in one paragraph, including data changes.
2. **What a rollback destroys** (tables, history, encrypted secrets) and how to export it first
   (`pg_dump -t …`).
3. **Preconditions** (stop the Center; no job of type X `leased`/`running` — with the SQL to check).
4. **The SQL**, in one `BEGIN; … COMMIT;` block, ending with
   `DELETE FROM "_prisma_migrations" WHERE "migration_name" = '<name>';` so a later `migrate deploy`
   re-applies it cleanly.
5. Which previous API build to deploy afterwards and how it behaves on leftovers.

The normal operator rollback does **not** use these files: `rollback.sh` restores the pre-upgrade dump,
which is exact and covers every migration of the release at once. `ROLLBACK.md` is for the cases where no
usable dump exists, for undoing a single migration in dev/lab, and as the reviewed statement of what is
reversible.

## 5. A migration failed (or was interrupted) during an upgrade

`upgrade.sh` stops with `database migration failed` and prints the rollback command. The API and web are
stopped; the old images are still on the host; the pre-upgrade dump is in `/opt/ppanel/backups`.

**Default: roll back, then investigate.**

```bash
sudo /opt/ppanel/rollback.sh /opt/ppanel/backups/pre-upgrade-<from>-<to>-<ts>.sql.gz <from>
```

This is always safe: the schema is reset and the dump restored in one transaction, whatever state the
failed migration left (Prisma wraps each migration in a transaction, but a failed migration still leaves a
`_prisma_migrations` row marked failed, and statements Prisma cannot run transactionally may be partial).

Then, with the Center back on `<from>`, find out why:

```bash
cd /opt/ppanel
docker compose logs --no-color api | tail -n 200                           # upgrade output also on stderr
docker compose exec -T postgres psql -U ppanel -d ppanel -c \
  "SELECT migration_name, started_at, finished_at, rolled_back_at, left(logs, 400) FROM _prisma_migrations ORDER BY started_at DESC LIMIT 5"
```

Typical causes: data that violates a new constraint (fix the data on `<from>`, or ship a fixed migration
in a patch release), lock timeouts on a busy table (retry in a quieter window), disk full.

**Only if you must go forward without a rollback** (and understand the failed statement):

1. Inspect the failed row and the migration SQL; determine exactly which statements were applied.
2. Either undo the partial changes by hand and mark the migration rolled back, then retry:
   ```bash
   docker compose run --rm --no-deps api node_modules/.bin/prisma migrate resolve --rolled-back <migration_name>
   sudo ./upgrade.sh <to>      # same version: resumes migrate + start
   ```
   or complete the remaining statements by hand and mark it applied:
   ```bash
   docker compose run --rm --no-deps api node_modules/.bin/prisma migrate resolve --applied <migration_name>
   ```
   (the image entrypoint runs any other command as given, from `/app`.)
3. `docker compose run --rm --no-deps api migrate-status` must say "Database schema is up to date".

Never edit `_prisma_migrations` checksums, never delete a failed row without undoing its effect, and keep
the pre-upgrade dump until the release has been in use for its whole rollback window.

## 6. Pre-flight failures

`upgrade.sh` refuses to start when `prisma migrate status` of the **current** image is not clean:

- **Pending migrations** on the current version: an earlier start did not finish `migrate deploy`. Run
  `docker compose run --rm --no-deps api migrate`, check `docker compose up -d --wait`, then upgrade.
- **Failed migration** recorded: handle it as in §5 on the current version before upgrading.
- **Drift** (the database has objects no migration created, e.g. a manual hotfix): capture it with
  `prisma migrate diff --from-url "$DATABASE_URL" --to-migrations prisma/migrations --script` in a dev
  checkout, turn it into a proper migration in the next release, or revert the manual change.

## 7. Release 0.8.0-rc.1

`0.8.0-rc.1` adds **no** migration: the schema stays at `20261128100000_p7_resilience`, so the
`0.7.0 → 0.8.0-rc.1` upgrade runs `migrate deploy` as a no-op and a rollback is schema-neutral (verified in
P8-T02). New P8 behaviour (`/version`, `/health`, `AGENT_OUTDATED`, `agentOutdated` in server facts) is
computed, not stored.
