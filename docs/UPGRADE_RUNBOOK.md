# pPanel — Upgrade and rollback runbook (P8.04)

How to move an installed Center (`/opt/ppanel`, `docs/INSTALL.md`) and its agents to a new release, and
how to go back. Policies: `docs/RELEASE_CONTRACT.md` §2 (mixed versions) and §4 (scripts). Version
support matrix: `docs/COMPATIBILITY.md`. How migrations are written and what to do when one fails:
`docs/MIGRATION_RUNBOOK.md`.

> **Validation status.** `0.7.0 → 0.8.0-rc.1 → rollback to 0.7.0` was tested end to end with data and a
> mixed-version fleet on Ubuntu 24.04 **systemd containers** (`scripts/lab/e2e_p8_upgrade.py`, evidence
> `docs/evidence/2026-11-24/p8-t02-upgrade.json`): **PASS (lab substitute)**. On a real VM it is still
> **BLOCKED** until a VM is provided. The `0.7.0` used there is commit `aa92403` plus a minimal packaging
> patch (`docs/evidence/2026-11-24/p8-t02-v070-packaging.patch`), because no release before 0.8.0 had an
> installer (§9).

## 1. Rules

- **Center first, then agents.** A Center supports agents of its own minor and the previous minor
  (`minAgentVersion` = N-1, same protocol major). Never upgrade agents past the Center.
- **Rollback is the reverse order:** downgrade agents only if you have to (they keep working with an
  older Center of the same protocol major), then roll back the Center.
- **One release at a time** within a major: `0.7.x → 0.8.x`, then `0.8.x → 0.9.x`. Skipping minors is not
  supported (agents two minors behind become `outdated`, and expand/contract migrations assume each
  release ran once — `docs/COMPATIBILITY.md` §4).
- **No downgrade through `upgrade.sh`.** It refuses a lower version. Going back = `rollback.sh` with the
  pre-upgrade dump, which restores the database **exactly** as it was at that moment.
- The master key (`PPANEL_MASTER_KEY`) **never changes** in an upgrade or a rollback. A dump restored
  with a different key leaves every encrypted value (TOTP secrets, CA key, app secrets, backup repo
  passwords) unreadable; `rollback.sh` refuses when the key differs from the one in the dump's snapshot.

## 2. Before the maintenance window

| Check                | How                                                                                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Release notes read   | `docs/RELEASE_NOTES.md` of the target: new env keys, migrations, deprecations, agent changes                                                          |
| Supported path       | target is the next minor (or a patch/rc of the current one) — `docs/COMPATIBILITY.md` §4                                                              |
| Bundle verified      | `sha256sum -c --ignore-missing SHA256SUMS` + `openssl pkeyutl -verify -pubin -inkey ppanel-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig` |
| Images reachable     | registry reachable from the Center, or `docker save`d images copied next to the bundle (`--images-dir`)                                               |
| Center healthy       | `cd /opt/ppanel && docker compose ps` — every service `healthy`; no failed jobs you still need                                                        |
| Master key escrowed  | the offline copy exists and matches: `upgrade.sh` prints a 16-hex fingerprint (`sha256` of the key) — compare it with the escrowed copy's             |
| Independent backup   | the scheduled `backup-center.sh restic` ran recently (`RECOVERY_RUNBOOK.md` §3); the pre-upgrade dump is **in addition**, on the same host            |
| Disk                 | `/opt/ppanel/backups` ≥ 2 × DB size + 256 MB free (checked); Docker root has room for two more images (~1 GB)                                         |
| No long jobs running | no deployment, build, backup or restore in progress (Jobs / Backups views); they are interrupted when the API stops                                   |
| Agents               | all agents at the current version or N-1 (Servers list, `agentVersion`); fix `outdated` ones first                                                    |

Downtime: the web UI, API and agent gateway are stopped from the dump until the new API is healthy (dump
time + image start + `migrate deploy`). In the P8-T02 lab with a small database the whole `upgrade.sh`
took 13 s and `rollback.sh` 8 s; plan for minutes on a large database (the dump and restore scale with
its size). Agents keep running their workloads and reconnect by themselves (within one heartbeat in the
lab); heartbeats during the window are simply missing.

## 3. Upgrade the Center

```bash
# on the Center host, as root
tar xzf ppanel-center-<new>.tar.gz && cd ppanel-center-<new>
sudo ./upgrade.sh <new>                               # images from the registry (PPANEL_IMAGE_PREFIX)
sudo ./upgrade.sh <new> --images-dir /path/to/images  # offline: docker load the *.tar first
```

Run it **from the unpacked bundle of the target version** (its `VERSION` must equal `<new>`): that is
where the new `compose.yml`, `Caddyfile`, `env.template` and scripts come from. What it does, in order:

1. **Pre-flight (read-only):** root, `/opt/ppanel/.env` present, bundle version = target, PostgreSQL
   running, running Center version = `PPANEL_VERSION` in `.env` (`GET /api/v1/version`; Centers older
   than 0.8.0 have no `/version`, so it falls back to `/api/v1/health` and `.env`), target > installed
   (downgrades refused), `prisma migrate status` of the **current** image is clean (no pending or failed
   migration), master key present (fingerprint printed), disk space for the dump.
2. **New images:** `docker load` from `--images-dir`, else `docker pull`; each image's
   `org.opencontainers.image.version` label must equal the target. A missing tag or an image of another
   release stops here — **nothing has changed, the old version is still serving**.
3. **Maintenance:** `docker compose stop api web` (the proxy keeps answering 502), then the pre-upgrade
   dump `backups/pre-upgrade-<from>-<to>-<ts>.sql.gz` (`backup-center.sh dump`, plain SQL, gzip, 0600) and
   `…-<ts>.release.tar.gz` (0600: previous `compose.yml`, `Caddyfile`, `env.template`, `observability/`,
   `VERSION` and `.env` with the previous image pins). If the dump fails the old stack is restarted.
4. **New bundle files** are installed into `/opt/ppanel`; keys new in `env.template` are appended with
   their defaults (existing values are never changed).
5. **Pins:** `PPANEL_VERSION`, `PPANEL_API_IMAGE` / `PPANEL_WEB_IMAGE` (tag **and** digest) and the
   `*_IMAGE_ID`s in `.env`.
6. **Migrate:** `docker compose run --rm --no-deps api migrate` (= `prisma migrate deploy` with the new
   image).
7. **Start + verify:** `docker compose up -d --wait`; running image IDs = pins; `GET /api/v1/version`
   reports the target; `GET /api/v1/health` = 200.

Output on success: one JSON line (`{"upgraded":true,"from":…,"to":…,"schemaVersion":…,"dump":…}`) and the
exact rollback command for this upgrade. **Copy that command into the change ticket.**

On failure after step 3 the script prints, for example:

```text
[upgrade] FAILED after the Center was stopped. Restore 0.7.0 exactly with:
  sudo /opt/ppanel/rollback.sh /opt/ppanel/backups/pre-upgrade-0.7.0-0.8.0-rc.1-20261124T101500Z.sql.gz 0.7.0
[upgrade] (or fix the cause and re-run: sudo …/upgrade.sh 0.8.0-rc.1 — it resumes migrate + start)
```

Re-running `upgrade.sh <installed version>` is a **no-op** when the stack is healthy and runs the pinned
images; when it is not (an interrupted upgrade), it resumes at migrate + start without a new dump.

## 4. Verify the Center

```bash
curl -fsS https://<domain>/api/v1/version   # version, commit, agentProtocol "1", minAgentVersion, schemaVersion
cd /opt/ppanel && docker compose ps         # all healthy
docker compose logs --since 10m api | grep -E '"level":"(error|fatal)"' || echo "no errors"
```

Then in the UI (or API): log in **with 2FA**; Servers — every agent back `online` within a heartbeat or two, none
`outdated` (agents N-1 are fine); open one application, the alert rules and the backup policies; run one
read-only job (inventory refresh). If anything is wrong, decide **now** whether to roll back (§7) — every
minute of use adds data that the rollback discards.

## 5. Upgrade the agents

Only after the Center is verified. Per host, **no re-enrollment** (the identity and mTLS certificate in
`/var/lib/ppanel-agent` are kept):

```bash
sudo bash install-agent.sh --version <new> [--pubkey ppanel-release.pub]        # from the GitHub release
sudo bash install-agent.sh --from-dir /path/to/release --pubkey ppanel-release.pub  # offline
```

The script verifies the checksum (always) and the signature (when a key is given or embedded), replaces
the binary and restarts `ppanel-agent.service`; it prints `already enrolled …; not re-enrolling`. Do a
canary host first (one `uat` server), check it is `online` with the new `agentVersion`, then the rest in
batches. Agents still on N-1 keep working, including mutating jobs (`docs/COMPATIBILITY.md` §2); finish
the fleet before the **next** Center upgrade, which will mark them `outdated`.

## 6. Rollback window

The rollback restores the pre-upgrade dump, so its cost grows with time:

| What is LOST on rollback (written after the dump)                                     | What is kept                                                    |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| users, role changes, 2FA enrolments, sessions/refresh tokens created after the dump   | everything that existed at the dump (same IDs, same content)    |
| servers enrolled after the dump (their agents then fail mTLS — re-enroll them)        | agents enrolled before: same identity, certificate, server ID   |
| jobs, deployments, builds, nginx revisions and approvals, audit events after the dump | workloads on the hosts (containers, nginx config) — not touched |
| backup runs / restores recorded after the dump (snapshots stay in restic, unindexed)  | restic repositories and their snapshots                         |
| alert rules, channels, incidents, settings changed after the dump                     | metrics/logs in Prometheus/Loki (outside the DB)                |

Recommended window: **until the end of the maintenance window**, before users resume normal work. After
that, prefer a forward fix (patch release) over a rollback. `rollback.sh` always takes a safety dump of
the current database first (`backups/pre-rollback-<current>-<ts>.sql.gz`), so data written after the
upgrade can still be exported from it by hand if needed.

## 7. Roll back the Center

```bash
sudo /opt/ppanel/rollback.sh /opt/ppanel/backups/pre-upgrade-<from>-<to>-<ts>.sql.gz <from> [--images-dir DIR] [--yes]
```

1. **Checks (nothing changes yet):** dump is valid gzip with the pg_dump end marker; its schema version
   (last applied migration) is read from the dump; the `.release.tar.gz` next to it belongs to `<from>`
   and carries the **same master key** as `.env`; the previous images (`PPANEL_*_IMAGE` from the snapshot,
   else `<prefix>ppanel-{api,web}:<from>`) are present or pullable and labelled `<from>`. Without
   `--yes` it asks you to type the version.
2. **Safety dump** of the current database → `backups/pre-rollback-<current>-<ts>.sql.gz`.
3. **Stop api + web**, terminate remaining DB sessions.
4. **Restore** in one transaction: `DROP SCHEMA public CASCADE; CREATE SCHEMA public;` + the dump
   (`psql --single-transaction -v ON_ERROR_STOP=1`). The schema reset matters: `pg_dump --clean` only
   drops objects that exist in the dump, so tables added by the newer release's migrations would survive
   and break the next upgrade. A failing restore rolls back completely (database unchanged).
5. **Previous release files and pins:** `compose.yml`, `Caddyfile`, `env.template`, `observability/` from
   the snapshot; `PPANEL_VERSION`, image pins and IDs in `.env`. Other `.env` values are kept.
6. **Start + verify:** `docker compose up -d --wait`; running image IDs = pins; the Center reports
   `<from>` (`/version`, or `/health` for pre-0.8 Centers, or the image label); schema = the dump's.

Agents: an agent already upgraded to `<to>` keeps working against the rolled-back Center (same protocol
major). Downgrade it with `install-agent.sh --version <from>` only if you want a uniform fleet. Agents
enrolled after the dump must be re-enrolled (their server rows are gone).

## 8. Troubleshooting

| Symptom                                                         | Meaning / action                                                                                                                   |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `this bundle is 'X', not Y`                                     | you ran another release's `upgrade.sh`; unpack `ppanel-center-<Y>.tar.gz`                                                          |
| `cannot get image … nothing changed`                            | wrong version/prefix or no registry access; use `--images-dir`. The old Center is untouched                                        |
| `image … is labelled version 'X', expected Y … nothing changed` | the tag points at another build (retagged image, mirror mistake); fix the registry/tar                                             |
| `pending or failed migrations` in pre-flight                    | the **current** install is not clean — `docs/MIGRATION_RUNBOOK.md` §5 before upgrading                                             |
| `refusing to downgrade`                                         | use `rollback.sh` with the pre-upgrade dump                                                                                        |
| `database migration failed`                                     | run the printed `rollback.sh` command (restores the dump), then `docs/MIGRATION_RUNBOOK.md` §5 with the logs                       |
| `stack did not become healthy`                                  | `docker compose logs api` (config error? new required env key?) — fix and re-run `upgrade.sh <new>` (resumes), or roll back        |
| agents `outdated` after the upgrade                             | they are older than N-1 (`docs/COMPATIBILITY.md`); upgrade them (§5). Workloads keep running; only mutating jobs are refused (409) |
| `PPANEL_MASTER_KEY differs …` in rollback                       | `.env` was edited or replaced; put back the escrowed key used when the dump was taken                                              |

## 9. Lab substitute (P8-T02)

`python3 -I scripts/lab/e2e_p8_upgrade.py --worktree <dir outside the repo> --out docs/evidence/<date>/p8-t02-upgrade.json`
(needs `dist-release/<VERSION>` from `scripts/release/build.sh --save-images --sign-key …`). It builds
`0.7.0` from `aa92403` in a temporary git worktree with the minimal packaging patch — the P8 Dockerfiles
and entrypoint, `.dockerignore`, `prisma` moved to runtime dependencies (package.json + lockfile), the
Next.js standalone flag and a public `GET /api/v1/health` (status, db, version) — and removes the worktree.
`0.7.0` has no `/version`, so it is installed with the `0.8.0-rc.1` bundle's `install.sh --version 0.7.0
--no-start` followed by `docker compose up -d --wait`. It then covers: data with 2FA users, an imported
nginx application, an alert rule + channel, a backup repository + policies + run records; forced failures
(missing tag, mislabelled image) stopping before any change; the upgrade with checksums of 16 tables and 8
API listings unchanged; 2FA login; 0.7.0 agents reconnecting and not outdated; a mutating job on a 0.7.0
agent; re-run no-op; downgrade refusal; an agent upgrade without re-enrollment; the mixed fleet (and
`PPANEL_MIN_AGENT_VERSION` forcing `AGENT_OUTDATED`); and the rollback restoring the pre-upgrade snapshot
exactly while discarding post-upgrade writes. Differences from a real host: `docs/INSTALL.md` §11.
