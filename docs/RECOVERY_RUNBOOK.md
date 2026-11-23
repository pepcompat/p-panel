# pPanel Center — recovery runbook (P6.06)

This runbook covers the loss of the **Center** (API + PostgreSQL). Managed servers keep running
their applications during a Center outage. Agents queue telemetry locally and reconnect on their own.
Server data backups (restic repositories on the backup host) are covered by `API_CONTRACTS.md` §10
and ADR-0009. They do not depend on the Center database.

## 1. What is backed up, and where

| Item                                                                                                                      | Where                                                                  | How                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Center PostgreSQL (users, MFA factors, roles, servers, agent certificates, CA key, secrets, policies, run history, audit) | **separate** restic repository `center/` (`PPANEL_CENTER_BACKUP_REPO`) | `scripts/backup/center-backup.sh` (`pg_dump --format=custom`, checksum manifest, migration list) |
| Non-secret Center config                                                                                                  | same snapshot (`center.env.sanitized`)                                 | every secret value is replaced by `<removed: restore from offline escrow>`                       |
| `PPANEL_MASTER_KEY` (encrypts the CA key, TOTP secrets, app secrets, restic repo passwords, channel secrets)              | **offline escrow only**                                                | never in any backup                                                                              |
| `PPANEL_CENTER_BACKUP_PASSWORD` (restic password of the Center repo)                                                      | **offline escrow only**                                                | never in the repo                                                                                |
| restic repo passwords of every server repository                                                                          | **offline escrow** (plus encrypted in the Center DB)                   | `GET /api/v1/backup-repositories/:id/recovery-export` (step-up, audited)                         |
| `JWT_ACCESS_SECRET`, `PPANEL_BACKUP_REPORT_TOKEN`, SMTP / Telegram credentials                                            | offline escrow, or regenerate                                          | regenerating `JWT_ACCESS_SECRET` only logs everyone out                                          |

The Center repository is separate from the server repositories. Its rest-server user (`center`) is
append-only like the agents' users. Retention and the offsite copy of `center/` run from the same
maintenance identity (`scripts/backup/maintenance.sh`).

## 2. Offline escrow (do this once, then after every change)

1. Record `PPANEL_MASTER_KEY` and `PPANEL_CENTER_BACKUP_PASSWORD`. Use **one** of these methods:
   - print them once and seal the paper in two separate locations;
   - encrypt a file to an operator key, for example
     `printf 'PPANEL_MASTER_KEY=…\nPPANEL_CENTER_BACKUP_PASSWORD=…\n' | age -r <operator-pubkey> > ppanel-escrow.age`,
     then store it off the Center host.
2. For every backup repository, call the recovery export with step-up and add the result to the
   same escrow:
   `GET /api/v1/backup-repositories/:id/recovery-export` (header `X-Step-Up`).
   The response has `Cache-Control: no-store`. The call is audited as
   `backup_repositories.recovery_export`. Do it again after adding a server to a repository.
3. Never put escrow material into a ticket, the Center DB, the backup host, or any restic repository.

## 3. Taking Center backups

```bash
# once: initialise the separate Center repository (maintenance identity for rest-server)
PPANEL_CENTER_BACKUP_REPO=rest:https://center:<pw>@backup.internal:8000/center/ \
PPANEL_CENTER_BACKUP_PASSWORD=<escrowed> scripts/backup/center-backup.sh init

# schedule this (systemd timer / cron), e.g. hourly
DATABASE_URL=postgresql://…/ppanel?schema=public \
PPANEL_CENTER_BACKUP_REPO=… PPANEL_CENTER_BACKUP_PASSWORD=… \
PPANEL_CENTER_ENV_FILE=/etc/ppanel/center.env \
scripts/backup/center-backup.sh            # prints {"snapshot":…,"dumpBytes":…,"totalMs":…}
```

The script uses host `pg_dump`/`psql`/`restic` when they are on `PATH`. Otherwise it uses pinned
Docker images (`postgres:16.6-alpine`, `restic/restic:0.17.3`). Secrets reach the tools only through
environment variables. `pg_dump` must be the same major version as the server (16) or newer.

## 4. Data-loss window

- **Center metadata:** everything written after the last successful Center snapshot is lost. With
  the hourly schedule that is up to 1 hour. This includes new users, approvals, audit rows, run
  history and policy edits.
- **In-flight jobs are not replayed.** Jobs that were queued, leased or running at backup time come
  back as `queued` or `leased`, then expire through their TTL or lease (the sweeper marks them
  `expired`). A mutating job is never re-delivered after its lease lapsed. Workflows that were in
  progress (deployments, restores, backup runs) end as `expired`, `failed` or
  `requires_manual_recovery`. Re-run them deliberately.
- **Server data is not affected.** Snapshots taken by agents after the Center snapshot still exist
  in the restic repositories, but the recovered Center has no run rows for them. List them with
  `GET /api/v1/servers/:id/snapshots`. The Center does not re-import them as runs.

## 5. Recovery procedure

Timings were measured in the lab on 2026-11-23 (Docker Desktop, PostgreSQL 16.6, local restic
repository). Scale them with DB size.

| Step | Action                                                                                                                                                                                                                                                                                                       | Lab timing                                                                                                             |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| 1    | Provision the new Center host. Install the **same pPanel version** as the backup (`migrations.txt` in the snapshot lists the applied migrations)                                                                                                                                                             | —                                                                                                                      |
| 2    | Fetch the escrow: `PPANEL_MASTER_KEY`, `PPANEL_CENTER_BACKUP_PASSWORD`, repo URL                                                                                                                                                                                                                             | operator                                                                                                               |
| 3    | Create an **empty** database: `CREATE DATABASE ppanel_recovered;`                                                                                                                                                                                                                                            | < 1 s                                                                                                                  |
| 4    | `scripts/backup/center-backup.sh snapshots` to pick a snapshot (or use `latest`)                                                                                                                                                                                                                             | ~2 s                                                                                                                   |
| 5    | `scripts/backup/center-restore.sh <snapshot> postgresql://…/ppanel_recovered?schema=public`. This restores, verifies the dump sha256, refuses a non-empty target, runs `pg_restore --single-transaction --exit-on-error`, counts users / servers / CA keys / in-flight jobs and runs `prisma migrate status` | dev DB (495 KB dump, 25 users, 24 servers): **4.2 s** total (fetch 1.1 s, pg_restore 1.0 s). P6-T05 test DB: **3.6 s** |
| 6    | If `migrationStatus` is `pending_or_failed` because the new code is newer, run `DATABASE_URL=… pnpm --filter @ppanel/api prisma:migrate`                                                                                                                                                                     | ~2 s                                                                                                                   |
| 7    | Rebuild `.env` from `center.env.sanitized` plus the escrowed secrets. Use the **same** `PPANEL_MASTER_KEY`. Set `DATABASE_URL` to the recovered DB                                                                                                                                                           | operator                                                                                                               |
| 8    | Start the API. Boot decrypts the CA private key with the master key: a wrong key fails the boot                                                                                                                                                                                                              | ~2 s                                                                                                                   |
| 9    | Verify: login with TOTP (MFA secrets decrypt). Check `GET /servers`. Agents reconnect within one heartbeat with their **current certificates**: same CA, so no re-enrollment. A recovery export works (repo passwords decrypt)                                                                               | 1–2 heartbeat intervals                                                                                                |
| 10   | Point DNS / the gateway address at the new host if it changed. Agents use `PPANEL_PUBLIC_GATEWAY_URL` from their config; the gateway TLS certificate is re-issued from the restored CA for `PPANEL_GATEWAY_HOSTNAMES`                                                                                        | DNS TTL                                                                                                                |
| 11   | Review workflows that ended `expired` / `failed` / `requires_manual_recovery` and re-run them deliberately. Check the backup policies' next runs (a missed slot runs **once**)                                                                                                                               | operator                                                                                                               |

Backup timings: dev Center DB **2.9 s** (pg_dump 0.8 s). P6-T05 test DB **2.0 s**.

Automated proof (P6-T05): `apps/api/test/integration/center-recovery.spec.ts` backs up the Center
DB, restores it into a fresh `ppanel_recovered`, and boots a second API on it with the same master
key. It then asserts:

- the CA key decrypts;
- the existing agent certificate is accepted by the new mTLS gateway;
- login + TOTP works;
- the repo password decrypts;
- the in-flight job expires and is not delivered;
- a wrong master key cannot boot.

### Re-establishing agents

- **Normal case:** nothing to do. The restored `ca_keys` row and `agent_certificates` mean the
  agents' existing leaf certificates still chain to the CA, and the new gateway accepts them.
  Agents renew their certificates as usual (`PPANEL_AGENT_CERT_DAYS`, default 7 days).
- **An agent that renewed its certificate after the snapshot** presents a serial the recovered DB
  does not know. The gateway checks the serial against `agent_certificates`, so it rejects the agent
  with `AGENT_CERT_REVOKED`. Re-enroll that agent. With hourly Center backups and 7-day certificates
  this affects only agents that renewed in the last hour. List them from the agent logs (renewal
  timestamp later than the snapshot time).
- **A server enrolled after the snapshot** is unknown to the recovered Center. Its certificate
  chains to the CA but has no server row, so it is rejected. Re-enroll it with a new enrollment
  token, then revoke the stale identity on the host (`/var/lib/ppanel-agent`).
- **A server revoked after the snapshot** comes back as active. Revoke it again **before** opening
  the gateway to the network.
- **Certificates that expired during a long outage:** re-enroll the agent.
- **Lost master key:** the CA key cannot be decrypted. Generate a new CA (fresh Center) and
  re-enroll every agent. All app secrets, TOTP factors and repo passwords must be re-entered. Server
  backups remain readable **only** with the escrowed repo passwords. This is why the escrow in §2 is
  mandatory.

## 6. After recovery

- Rotate `JWT_ACCESS_SECRET`: all sessions are invalidated, and users log in again with MFA.
- Rotate the master key, out of scope for automation in v1:
  1. Stop the API.
  2. Run a one-off script that decrypts every envelope with the old key and re-encrypts it with
     the new one. The affected columns are:
     - `ca_keys.private_key_enc`;
     - `mfa_factors.secret_enc`;
     - `secrets.value_encrypted`;
     - `backup_repo_access.*_enc`;
     - `notification_channels` secrets;
     - `integrations` secrets.
  3. Update the escrow.
  4. Start the API.

  Plan it with a fresh Center backup first.

- Take a new Center backup immediately, then check that the schedule runs.
- Revoke any server or user that was removed after the snapshot.

## 7. Server data restores (for completeness)

Restoring **application data** is a separate flow from Center recovery: `POST /restores` (plan →
dry-run → approval → execute) in the UI/API. With the Center gone and no time to rebuild it, an
operator can still restore directly on the server with the escrowed repo password:

```bash
RESTIC_REPOSITORY=rest:https://<serverUser>:<restPassword>@backup:8000/<serverUser>/ \
RESTIC_PASSWORD=<escrowed repo password> restic snapshots
restic restore <snapshot> --target /tmp/restore-<id>
```

Restore into an isolated location first, then compare before overwriting live data.
