# Emergency recovery

What pPanel does when the Center or an agent is unavailable, how to read the "manual recovery" states,
and where to go when the Center itself must be rebuilt. Evidence: [RESILIENCE_REPORT.md](../RESILIENCE_REPORT.md)
(P7 chaos runs), `scripts/lab/e2e_p5.py` (P5-T04 Center outage buffering), and
`apps/api/test/integration/center-recovery.spec.ts` (P6-T05 Center recovery).

## Who may do what

| Task                                               | Permission                     | Built-in roles            |
| -------------------------------------------------- | ------------------------------ | ------------------------- |
| Read fleet, jobs, revisions, deployments, restores | `fleet.read` / `apps.read`     | all four                  |
| Rescan, acknowledge drift, new revisions           | `nginx.read` / `nginx.write`   | Platform Owner, Ops Admin |
| Redeploy / roll back after manual recovery         | `apps.deploy`                  | + Deployer                |
| Restore the safety snapshot                        | `backups.restore` (+ approval) | Platform Owner, Ops Admin |
| Center disaster recovery                           | host root + offline escrow     | operator                  |

Host-side steps need root on the managed server; there is no shell through the agent or the panel.

## 1. Center outage (API and/or database down)

What keeps working:

- **Applications keep serving.** The agent never stops, restarts or reconfigures workloads because the
  Center is gone; it only runs typed jobs on explicit grants. Lab: a 10-minute API outage had 100 %
  availability on all sites; API + PostgreSQL down 187 s also passed.
- **Agents reconnect by themselves** with exponential backoff (1 s → 60 s with jitter), usually within
  10–45 s of the Center returning, with their existing certificates.
- **Logs are buffered** on the agent (default cap 64 MiB) and shipped after reconnect; overflow drops the
  oldest entries and counts them ([logs.md](logs.md#buffering-during-a-center-or-loki-outage)).
- **No false offline alerts**: for 90 s after a Center start, stale servers are unknown for
  `server_offline`, and those rules need `forSec >= 90` ([alerts.md](alerts.md)).

What stops or changes:

- No UI, no new jobs, no deployments, no approvals.
- **Jobs are never replayed.** A mutating job whose lease or TTL lapsed becomes `expired` and needs a new
  request. Late results get 409 `TASK_EXPIRED`.
- While PostgreSQL is unreachable the API answers 503 `SERVICE_UNAVAILABLE` with `Retry-After: 5`.
- A deployment interrupted with an unknown outcome has its own **candidate** container stopped and removed
  by the Center; the serving container is never touched. Re-run the deployment deliberately.
- A backup slot missed during the outage runs **once** at startup.

After the Center returns: check **Servers** (all back to Online), review deployments, restores and backup
runs that ended `expired`, `failed` or `requires_manual_recovery`, and re-run them deliberately.

## 2. Agent offline

A server is `stale` after 45 s without a heartbeat and `offline` after 120 s. Metrics are shown as
last-known (`stale: true`), never zeroed, and charts show gaps. Actions that need the agent are disabled
(**Disabled while the agent is offline or stale**). Jobs queued meanwhile wait and expire after their TTL
(default 600 s); mutating jobs are not re-delivered later.

Recovery on the host:

```bash
systemctl status ppanel-agent
journalctl -u ppanel-agent --since "1 hour ago"
systemctl restart ppanel-agent
```

- 401 `AGENT_CERT_REVOKED` in the agent log: the certificate was revoked or expired → re-enroll
  ([enroll-servers.md](enroll-servers.md)).
- State directory full (`/var/lib/ppanel-agent`): the agent refuses new jobs with
  `AGENT_STATE_WRITE_FAILED` instead of running them blind. Free space and restart the agent.
- At restart, any job the previous agent process started but never finished is reported as
  `AGENT_INTERRUPTED` and **not** re-executed. An interrupted Nginx apply is rolled back from its journal
  first (see below).

## 3. Manual-recovery states

`requires_manual_recovery` means pPanel could not prove the host is in a safe, known state and stopped
instead of guessing. It appears on Nginx revisions, managed routing, deployments and restores.

### Nginx manual recovery

Shown as **Manual recovery required** on the revision (agent error `REVERT_FAILED_MANUAL_RECOVERY`). The
application gets a drift flag, so nothing more can be written until you recover.

1. Read the revision result: **Backup directory on the host** (`<stateDir>/nginx-backups/<revisionId>/`
   with `manifest.json`: path, sha256, mode, owner, existed). `details.restored: true` means the files were
   restored and verified and only `nginx -t` / reload failed.
2. On the host: `nginx -t`. Fix or restore the files from the backup directory, then reload
   (`systemctl reload nginx`). Confirm the sites answer.
3. In pPanel: run a new discovery scan ([import-nginx.md](import-nginx.md#1-run-a-read-only-scan)), check
   the drift, **Acknowledge drift…**, then create a new revision if a change is still needed.

If the agent died mid-apply it restores the backup and reloads at its next start, but only when every file
is still the original or the candidate. Otherwise it touches nothing and marks the backup
`interrupted-manual`: handle it with the same three steps.

### Deployment / managed-routing manual recovery

Shown as **Manual recovery required** when the route switch failed and the previous route could not be
restored automatically.

1. On the server: `nginx -t` to see the current state.
2. Restore the managed route file (`/etc/nginx/ppanel-managed/<app>/route.conf`, or
   `/etc/nginx/conf.d/ppanel-managed.conf` for managed routing) from the backup the agent reported, then
   reload Nginx.
3. Record what you did, then redeploy or roll back from the application ([deploy.md](deploy.md#3-lifecycle-rollback-redeploy-restart-stop-start)).
   An `app_down` alert fires while the last deployment is in this state.

### Restore manual recovery

Shown as **Requires manual recovery**: the restore stopped part-way; live data may be partly overwritten
and the app may be stopped. The safety snapshot run is shown on the restore.

1. Keep the app stopped; do not start another restore yet.
2. Restore the safety snapshot in place (or inspect it in staging first) through the normal restore flow
   ([backup-restore.md](backup-restore.md#4-restore)).
3. Record what you did in the incident.

## 4. Center disaster recovery

Losing the Center (API + database) is covered step by step in
[RECOVERY_RUNBOOK.md](../RECOVERY_RUNBOOK.md): separate Center backups with
`scripts/backup/center-backup.sh`, restore into a fresh database with
`scripts/backup/center-restore.sh <snapshot> <target-db-url>`, start the **same version** with the
**same master key**, verify login + TOTP, CA key and agent reconnect. Agents reconnect with their current
certificates; agents that renewed or enrolled after the snapshot must be re-enrolled, and servers revoked
after the snapshot must be revoked again before the gateway is opened.

### Master key escrow

`PPANEL_MASTER_KEY` encrypts the CA key, TOTP secrets, app secrets, restic repository passwords and
channel secrets. It is **never** in any backup. Keep it, `PPANEL_CENTER_BACKUP_PASSWORD` and every
repository's recovery export in **offline escrow** (printed and sealed in two places, or an age-encrypted
file to an operator key), never in a ticket, chat, the Center DB, the backup host or a restic repository.
**Settings → Security → Disaster recovery** shows when each repository was last exported.

A lost master key means a new CA, re-enrolling every agent, and re-entering every secret and TOTP factor.
Server backups stay readable only with the escrowed repository passwords. With the Center gone, data can
still be restored directly on a server with restic and the escrowed password
([RECOVERY_RUNBOOK.md](../RECOVERY_RUNBOOK.md) §7).

## Limitations

- Rotating the master key is manual in v1 (procedure in [RECOVERY_RUNBOOK.md](../RECOVERY_RUNBOOK.md) §6).
- Center recovery is proven by an integration test, not on a separate host; real-VM network partitions,
  clock skew and kernel disk quotas are not covered (container lab only).
- Several P7 chaos scenarios were fixed afterwards and covered by unit/integration tests but **not re-run**
  in the lab (F-3, F-7, F-8, F-9, F-10; see the fix status in [RESILIENCE_REPORT.md](../RESILIENCE_REPORT.md)).
- `service.restart` and real systemd behaviour were not testable in the container lab.
