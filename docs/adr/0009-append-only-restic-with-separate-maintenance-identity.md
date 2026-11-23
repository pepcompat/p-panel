# ADR-0009: Append-only restic repositories; deletion only by a separate maintenance identity

- Status: Accepted (2026-11-23)
- Context: The brief (§3, §6, P6.01) requires encrypted backups, an offsite copy, and a **delete ability separate from Center administration**, preferring immutable or append-only storage. A compromised node, or a compromised Center admin account, must not be able to destroy backups.
- Decision:
  - Repository format: **restic** (client-side encryption).
  - Storage: **rest-server** with `--private-repos --append-only` for agents. Each server has its own rest-server user and private repo path. Credentials are stored encrypted on the Center and delivered per job via the secrets call.
  - Retention (`forget --prune`) and the offsite copy (`restic copy` → S3-compatible bucket, ideally with object lock) run as a **maintenance identity**: a full-access rest-server listener on the same data, bound to the backup host only. An operator-run script uses it. The Center never stores it.
  - The Center records the retention policy and shows maintenance and offsite status reported by that script (`POST /api/v1/backup-maintenance/reports` with a dedicated report token, which cannot delete anything).
  - The restic repository passwords and the Center master key are exported to **offline recovery storage** (operator-held). Recovery must not depend on the Center DB alone (P6.06).
- Consequences:
  - Backups survive the compromise of an agent or of the Center API.
  - Pruning has an operational cost: it isn't automatic from the UI, and the UI says so.
  - restic's lock files can block after a crash (`REPO_LOCKED`). They are cleared via the maintenance identity.
