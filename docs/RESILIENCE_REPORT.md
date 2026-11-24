# pPanel — Resilience & Disaster Report (P7.03–P7.05, P7-T01 / P7-T02 / P7-T04)

Lab run 2026-11-23 → 2026-11-24 on one Mac (Apple M4, 10 cores, 24 GB; Docker Desktop 29.0.4 VM with
10 CPUs / 11.7 GiB). Lab nodes are containers, not VMs (see `infra/lab/README.md`).

- **Center under test**: snapshot of `apps/api/dist/main.js` built from `43feb79` (P6 HEAD), copied to
  `.lab/chaos/api/` (sha256 `438a2631…`) and run with `node` (never watch mode) so concurrent edits by
  other agents could not change the code mid-scenario. The P7.01 security fixes in the working tree are
  **not** in this build.
- **Agent**: `apps/agent/bin/ppanel-agent-linux-arm64`, sha256 `b237b1f2…` (2026-11-24 runs; includes
  the P7.02 fixes) / `4bfd82a5…` (2026-11-23 runs).
- **Fleet** (`scripts/chaos/setup_fleet.py`): node-a (uat) with legacy nginx sites and the adopted
  `static.example.lab`; node-b (uat) with managed routing, a container app (`p7web-*`, web v1) and a compose
  app (`p7stack-*`, postgres + web). Every scenario writes JSON evidence to
  `docs/evidence/<date>/p7-*.json`.
- Harness shortcuts (all documented in the scripts): approval / job TTLs are fixed constants, so expiry was
  simulated by moving `expires_at` / `approved_at` back in the **dev DB**; certificate validity was
  shifted in `agent_certificates` (no clock faking); disk full uses a 6 MiB tmpfs in a dedicated chaos node.

## Results

| ID             | Scenario                                                                                                             | Result                                                          | Key numbers                                                                                                                                                                                                                                                                                                                                                                                                 | Evidence                                      |
| -------------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| P7-T01 / P7.03 | Center API down **10 min (601 s)**, traffic 5 req/s per site on 6 sites                                              | **PASS**                                                        | 100 % availability on all 6 sites (2 830 req each during the outage, p95 1.2–5.3 ms); agents same PID throughout; reconnect 10.0 s / 32.8 s after restart; backlog shipped in ~10 s (33 batches, all 200); 100 % of outage-window log lines in Loki (6 147/6 147, 5 050/5 050); no `server_offline` incident (forSec 60); persisted + derived status `online`                                               | `2026-11-24/p7-t01-outage-api.json`           |
| P7-T01         | first 10-min run (2026-11-23)                                                                                        | PASS except log check (see F-1)                                 | same availability (100 %, 2 851 req/site), reconnect 24.1 s / 42.6 s; only 22–28 % of lines in Loki because the probe sent byte-identical requests                                                                                                                                                                                                                                                          | `2026-11-23/p7-t01-outage-api.json`           |
| P7-T01         | Center API **+ Postgres** down 187 s                                                                                 | **PASS**                                                        | 100 % availability (≈885 req/site); DB back 5.6 s, Center start 1.3 s; reconnect 27.1 s / 38.2 s; 100 % log delivery (2 217/2 217, 2 287/2 287); `server_offline` went `pending` for node-a and was dropped when it reconnected, no incident                                                                                                                                                                | `2026-11-23/p7-t01-outage-api-db.json`        |
| P7-T02 A       | mutating jobs queued while agents down (nginx.apply, service.restart, container.restart), TTL expires, agents return | **PASS**                                                        | all 3 `expired` (TTL_EXPIRED); after reconnect + 40 s nothing delivered (no agent log line for the job ids), nginx tree hash, master PID and container StartedAt unchanged. See Q-1 (status naming)                                                                                                                                                                                                         | `2026-11-24/p7-t02-no-replay.json`            |
| P7-T02 B       | job leased, agent partitioned before ack                                                                             | **PASS**                                                        | `expired` LEASE_EXPIRED after 62 s; late ack and late result → 409 TASK_EXPIRED, nothing stored; never re-delivered                                                                                                                                                                                                                                                                                         | same                                          |
| P7-T02 C       | job acked (running), agent vanishes                                                                                  | **PASS**                                                        | running lease expired after 125 s; late `succeeded` → 409 TASK_EXPIRED                                                                                                                                                                                                                                                                                                                                      | same                                          |
| P7-T02 D       | agent SIGKILLed while `container.restart` runs                                                                       | **PASS** (no re-run) / **FAIL** (AGENT_INTERRUPTED expectation) | exactly one execution; Center ends `expired` LEASE_EXPIRED after ~123 s; never reported as AGENT_INTERRUPTED (F-5)                                                                                                                                                                                                                                                                                          | same                                          |
| P7-T04 1       | apply whose postcheck fails                                                                                          | **PASS**                                                        | POSTCHECK_FAILED_REVERTED; file + whole `/etc/nginx` tree byte-identical; sites 200; master PID unchanged                                                                                                                                                                                                                                                                                                   | `2026-11-24/p7-t04-nginx-failsafe-part1.json` |
| P7-T04 2       | new `listen` port held by another process (nginx -t OK, master bind() fails on reload)                               | **PASS**                                                        | POSTCHECK_FAILED_REVERTED; byte-identical; sites 200                                                                                                                                                                                                                                                                                                                                                        | same                                          |
| P7-T04 3       | reload command fails (stale pid file)                                                                                | **PASS (config)** / see F-4                                     | files restored byte-identical, sites 200, but reported `REVERT_FAILED_MANUAL_RECOVERY` + drift flag "checksum unknown"                                                                                                                                                                                                                                                                                      | same                                          |
| P7-T04 4       | tested revert of a good revision                                                                                     | **PASS**                                                        | applied (new location 200) → reverted → byte-identical, location 404                                                                                                                                                                                                                                                                                                                                        | `2026-11-24/p7-t04-nginx-failsafe.json`       |
| P7-T04 5       | agent SIGKILLed ~1 s after ack of an apply                                                                           | **FAIL** (F-3)                                                  | sites 200, but host keeps the candidate config live while the revision says `apply_failed` (LEASE_EXPIRED)                                                                                                                                                                                                                                                                                                  | same                                          |
| P7.04 1        | 2 admins / 10 concurrent deploys of one app                                                                          | **PASS**                                                        | exactly one 202, others 409 DEPLOYMENT_IN_PROGRESS (1+1, 1+9)                                                                                                                                                                                                                                                                                                                                               | `2026-11-24/p7-concurrency.json`              |
| P7.04 2        | 5 concurrent revision creates on one app                                                                             | **PASS**                                                        | one 201, four 409 REVISION_IN_PROGRESS                                                                                                                                                                                                                                                                                                                                                                      | same                                          |
| P7.04 3a       | two approvers approve the same plan concurrently                                                                     | **FAIL** (F-6)                                                  | both 200, two approval rows                                                                                                                                                                                                                                                                                                                                                                                 | same                                          |
| P7.04 3b       | one approval, two concurrent applies + a second app on the same server                                               | **PASS**                                                        | one apply 202 / one 409 APPROVAL_REQUIRED; jobs serialized (02:45:00.268→02:45:02.303, next leased 02:45:03.292)                                                                                                                                                                                                                                                                                            | same                                          |
| P7.04 4        | expired approval                                                                                                     | **PASS**                                                        | 409 APPROVAL_EXPIRED, no job (approval aged in dev DB)                                                                                                                                                                                                                                                                                                                                                      | same                                          |
| P7.04 5        | webhook storm: 50 concurrent deliveries for 5 commits                                                                | **FAIL** (F-7)                                                  | 1 deployment; the other 4 commits never deployed (49 deliveries `failed` / `deployment_in_progress`)                                                                                                                                                                                                                                                                                                        | same                                          |
| P7.05          | Redis stopped 90 s                                                                                                   | **PASS**                                                        | 18 samples of `/servers`, `/metrics/fleet`, `/auth/me`, jobs list: all 200; inventory job + app restart succeeded; heartbeats fresh. The API has no Redis client (rate limiter and log byte bucket are in-memory)                                                                                                                                                                                           | `2026-11-24/p7-disaster-redis.json`           |
| P7.05          | Postgres stopped 60 s, Center up                                                                                     | **PASS** (F-11)                                                 | every request answered in ≤ 7 ms with an enveloped error — but `500 INTERNAL_ERROR`, not 503; Center same PID; API 200 again 0.0 s after PG healthy (PG start 5.3 s); first heartbeat 28.4 s later (agent backoff); legacy site 100 % (316/316)                                                                                                                                                             | `2026-11-24/p7-disaster-postgres.json`        |
| P7.05          | Loki stopped 126 s under traffic                                                                                     | **PASS**                                                        | `/logs/query` 503 LOGS_BACKEND_UNAVAILABLE; agent buffered (heartbeat bytes grew 3.95→4.08 MB); after recovery 583/583 lines of the window in Loki, droppedEntries 0; Loki ready 21 s after start                                                                                                                                                                                                           | `2026-11-24/p7-disaster-loki.json`            |
| P7.05          | Prometheus stopped                                                                                                   | **PASS**                                                        | `/metrics/series` 200 → 503 METRICS_BACKEND_UNAVAILABLE; `/metrics/fleet` still 200 with real samples; after restart series 200 with the hole reported as `gaps` / 84 null points (never zeros); UI: `monitoring-view.tsx` renders `ErrorState` (static check)                                                                                                                                              | `2026-11-24/p7-disaster-prometheus.json`      |
| P7.05          | backup repo (rest-server) stopped                                                                                    | **PASS** (slow, F-12)                                           | baseline uploaded; with repo down the run failed `REPO_UNREACHABLE` only after **847 s** (restic's own retries), credentials masked `***` in the message; `backup_failed` incident fired 9 s later; repo back → next run uploaded, incident resolved                                                                                                                                                        | `2026-11-24/p7-disaster-backup-repo*.json`    |
| P7.05          | agent cert due for renewal (DB validity window)                                                                      | **PASS**                                                        | agent rotated by itself 14.5 s after the window moved, new serial, heartbeats continued                                                                                                                                                                                                                                                                                                                     | `2026-11-24/p7-disaster-cert-rotation.json`   |
| P7.05          | agent cert expired (Center side: `not_after = now`)                                                                  | **PASS**                                                        | gateway 401 AGENT_CERT_REVOKED, server `stale` after 82 s, agent alive, workloads untouched (200); validity restored → reconnected after 54.5 s (backoff at max after 401). A real expiry needs re-enrollment (no rotate without a valid cert)                                                                                                                                                              | `2026-11-24/p7-disaster-cert.json`            |
| P7.05          | gateway TLS cert expiry                                                                                              | **BLOCKED** (F-13, code inspection)                             | gateway cert issued once at start with 90-day validity, never re-issued while running                                                                                                                                                                                                                                                                                                                       | —                                             |
| P7.05          | aborted deploy, Center SIGKILLed at `pulling`, back after 20 s                                                       | **PASS**                                                        | agent delivered the result after reconnect, deployment finished `succeeded` (v1→v2), route switched once, previous container stopped; served v1 throughout the outage                                                                                                                                                                                                                                       | `2026-11-24/p7-disaster-aborted-deploy.json`  |
| P7.05          | aborted deploy, Center down 150 s (> running lease)                                                                  | **FAIL** (F-8)                                                  | deployment `failed` LEASE_EXPIRED, route untouched, v2 kept serving (good) — but the healthy candidate container started by the agent is left **running** as an orphan holding host port 20002                                                                                                                                                                                                              | same                                          |
| P7.05          | disk full on the agent state dir (6 MiB tmpfs, filled to 0 B)                                                        | **FAIL** (F-9, F-10)                                            | agent alive, heartbeats online, no workload impact; but a read-only job was acked and never answered ("cannot mark job started"), a backup run ended `expired` LEASE_EXPIRED after 124 s instead of a clear disk error, and **0 of 2 117** nginx lines produced while full ever reached Loki while `droppedEntries` said 11. After freeing space (no restart): logs 497/497, job succeeded, backup uploaded | `2026-11-24/p7-disaster-disk-full*.json`      |

## Findings for the lead (exact repro)

### F-1 (Medium) — identical log lines collapse in Loki: the agent stamps every line of a tail pass with one timestamp

- **Where**: `apps/agent/internal/logship/pipeline.go` `PollOnce`: `now := FormatTS(p.o.Now())` is computed
  once per pass and used as `ts` for every line read in that pass (container logs use Docker's timestamps,
  file sources do not). Loki de-duplicates entries with the same stream, timestamp **and** line, silently
  (`loki_discarded_samples_total` does not move).
- **Repro** (`scripts/chaos/log_dedup.py`, Center up, no outage): 60 s at 5 req/s of byte-identical requests
  to node-a `static.example.lab` → access.log 283 lines, Loki **120 (42.4 %)**; the same with a unique query
  string → 285/285 (100 %). Evidence `2026-11-24/p7-log-dedup.json` (Loki entries show the same ns
  timestamp for lines of different seconds).
- **This was the P7-T01 "22–28 %"**: the first 10-min run's probe sent identical requests. Backlog drain was
  not the cause: the Center log shows the whole 10-min backlog shipped in the first ~10 s after restart
  (33 batches, all 200, no 429/503), and with unique lines the 10-min rerun delivered 100 %.
- Real-world impact: health checks, monitoring probes, bots and retries produce identical lines; they are
  under-counted in Loki and in any error-rate view built on it.
- **Fix**: give each line a unique, monotonically increasing timestamp (e.g. `now + i ns` within a pass,
  and never reuse a ts across passes per source), or parse the nginx `$time_local`/`$msec` and add a per-second
  sequence. The Center could also add a ns tiebreaker per (stream, ts) when it builds the Loki push.

### F-2 (Low) — heartbeat `logShipping.bufferedBytes` counts already-shipped data

`Pipeline.Status()` reports `Buffer.Stats().Bytes` (on-disk size of all segments, including shipped records in
the active segment, up to 4 MiB) instead of the pending backlog. After the outage node-a showed 3.3–3.7 MB
"buffered" with nothing pending and `lastShippedAt` current. Report `Pending` (bytes or entries) as well.

### F-3 (High) — agent crash during `nginx.apply` strands the candidate config live, Center says `apply_failed`

- **Repro** (`scripts/chaos/nginx_failsafe.py` case 5): create + validate + approve a revision on an adopted
  site, apply, `pkill -KILL` the agent ~1 s after the job turns `running` (inside the 2 s post-reload settle),
  restart the agent.
- **Expected**: either the change is rolled back, or the Center records that the host state is unknown
  (`requires_manual_recovery` / drift) so operators look.
- **Actual**: the reload had already happened; the new `location` answers 200 and the file differs from
  baseline (`8e2e15c7…` vs `7c4a5e7e…`), the job ends `expired` LEASE_EXPIRED after the running lease and the
  revision becomes **`apply_failed`**. The agent does nothing on restart although
  `<stateDir>/nginx-backups/<revisionId>/` exists. Until a discovery scan flags drift, the UI shows a failed
  apply for a config that is live.
- **Fix**: (agent) journal mutating nginx jobs (`started`, `written`, `reloaded`) and on startup restore
  the backup + `nginx -t` + reload for any job without a final state; (Center) map LEASE_EXPIRED of
  `nginx.apply`/`nginx.revert` to `requires_manual_recovery` (or trigger an immediate read/rescan of the files)
  instead of `apply_failed`.

### F-4 (Low) — reload-failure path reports "could not restore" although the files were restored

Case 3 (stale `/run/nginx.pid`, so `nginx -s reload` fails): the agent restored the files byte-identically, but
the revert's own reload also failed, so it returned `REVERT_FAILED_MANUAL_RECOVERY` with message "could not
restore original nginx config". The revision became `requires_manual_recovery` and the app got a drift flag
with `currentSha256: "unknown"`, which then required a rescan before acknowledging. Manual attention is right
(nginx cannot be signalled), but the message should say _files restored and verified, reload failed_ (e.g.
`RELOAD_FAILED_FILES_RESTORED`) and include the verified sha256 so the Center does not mark the checksum unknown.

### F-5 (Medium, protocol gap) — a job interrupted by an agent crash is never reported as AGENT_INTERRUPTED

`jobs.Cache` marks `started` before execution and `ReplayResult` returns AGENT_INTERRUPTED — but only when the
same grant is delivered again, and the Center never re-delivers mutating jobs. Result: the job stays `running`
until the running lease lapses (~2 min) and ends `expired` LEASE_EXPIRED, indistinguishable from a network
partition. **Fix**: on startup the agent reports every cache entry still in `started` as
`failed/AGENT_INTERRUPTED` (store the lease token in the cache entry so the result is accepted), or the
heartbeat carries `interruptedJobIds` and the Center fails those jobs with AGENT_INTERRUPTED.

### F-6 (Medium) — concurrent approvals of the same plan both succeed

- **Repro** (`concurrency.py` 3a): revision `awaiting_approval`; two different approvers, each with a fresh
  step-up token, POST `/nginx-revisions/:id/approve` with the same `planHash` at the same instant → **both 200**,
  two rows in `nginx_revision_approvals`.
- Apply still consumed exactly one approval (3b: second apply 409 APPROVAL_REQUIRED), so no double execution was
  observed, but the audit shows two approvals and an unused valid approval remains until expiry.
- **Fix**: make approval a conditional transition (`UPDATE … WHERE status='awaiting_approval' AND plan_hash=$1`
  inside the transaction, or a partial unique index on unused, non-invalidated approvals per revision); the
  loser gets 409. Check deployments / managed-routing / restores approvals for the same pattern.

### F-7 (High for auto-deploy) — a webhook storm deploys only the first commit; the others are lost

- **Repro** (`concurrency.py` 5): auto-deploy policy (image mode) on the container app; tags `sha-<7>` exist for
  5 commits; 50 concurrent signed `push` deliveries (10 distinct delivery ids per commit).
- **Actual**: one deployment (first commit, succeeded); the other 49 deliveries → `failed` with reason
  `deployment_in_progress` (including 9 duplicates of the winning commit). Four commits were never deployed
  and nothing retries them (GitHub does not redeliver a 200).
- **Expected**: at most one deployment per commit, and the newest commit eventually deployed; duplicates of an
  in-progress commit reported as `ignored/already_deployed`.
- **Fix**: queue the latest pending commit per app (supersede older pending ones) and start it when the active
  deployment ends; classify same-commit duplicates as `ignored`.

### F-8 (Medium) — Center down longer than the running lease during a deploy leaves an orphan candidate running

- **Repro** (`disasters.py aborted-deploy`, variant 2): start a deployment, SIGKILL the Center when the deployment
  is `pulling`, keep it down 150 s, restart.
- **Actual**: the agent finished `container.run_candidate` (healthy) while the Center was down; its late result
  was rejected (lease expired), the deployment ended `failed` LEASE_EXPIRED, the route and the live version were
  untouched — but `ppanel-p7web-…-e0f82ae6` (label `ppanel.deployment=<failed deployment>`) is still `Up`, holding
  host port 20002 in `host_port_allocations`.
- **Fix**: when a `container.run_candidate` (or `compose.apply`) job of a deployment ends `expired`, enqueue a
  `container.stop`/`remove` for the deterministic candidate name and release the port; or let the deployment
  reconciler sweep containers labelled with failed deployment ids.

### F-9 (Medium) — after ack, a local persistence failure leaves the job silently unanswered

`agent.dispatch` acks, then `cache.MarkStarted` fails (ENOSPC) → "cannot mark job started; not executing" and
returns without a result. The Center shows `running` until the lease lapses; read-only jobs are re-leased every
~2 min until their TTL, mutating ones end `expired` LEASE_EXPIRED (backup run after 124 s). Operators never see
"disk full". **Fix**: check state-dir writability before ack (refuse the grant with a clear code, e.g.
`AGENT_STATE_UNWRITABLE`), or post a failed result when MarkStarted fails; also report state-dir free space in the
heartbeat (it already sends `diskPct` of `/`).

### F-10 (High, data loss) — lines read while the log buffer cannot be written are lost and not counted

- **Where**: `apps/agent/internal/logship/pipeline.go` `PollOnce`: on `buf.Append` error it skips
  `p.pos.SetFile` with the comment "lines are re-read next poll", but `Tailer.Poll` has already advanced its
  in-memory offset (`t.cur`), so the next poll continues after those lines.
- **Repro** (`scripts/chaos/disk_full.py`): chaos node-c (6 MiB tmpfs state dir), fill it, 10 req/s on
  `static.example.lab` for ~6 min, free the space. 240 "log buffer append failed" warnings; 2 117 access lines in
  that window, **0** in Loki; heartbeat `droppedEntries` 11. Lines after the space was freed: 497/497.
- **Fix**: rewind the tailer to the last committed position on append failure (or make `Poll` two-phase:
  read → append → commit), and count anything skipped in `droppedEntries`.

### F-11 (Low) — Postgres outage surfaces as 500 INTERNAL_ERROR (also on `/setup/status` and `/auth/login`)

Fast and enveloped (≤ 7 ms), no crash, recovers by itself — but a DB connectivity error should be
`503 SERVICE_UNAVAILABLE` + `Retry-After` so load balancers, the UI and agents treat it as transient. Map Prisma
connection errors (P1001/P1017, `PrismaClientInitializationError`) to 503 in the exception filter.

### F-12 (Low) — backup with an unreachable repo takes ~14 min to fail

restic retries backend errors with backoff (7 retries, 37–84 s each) before exiting; the run failed after 847 s.
Correct result, but slow feedback and a held per-repo mutex. Suggest a short preflight (`restic cat config` with a
~30 s timeout) or restic's `--stuck-request-timeout` / a retry cap, then REPO_UNREACHABLE.

### F-13 (Medium, latent) — gateway TLS certificate is never renewed while the Center runs

`gateway.server.ts` calls `ca.issueGatewayCert` once at startup (90-day validity, `ca.service.ts`); there is no
re-issue / `setSecureContext`. A Center running > 90 days without restart loses every agent at once.
Re-issue at 2/3 of the lifetime and hot-swap with `server.setSecureContext`, and alert when < 14 days remain.

### F-14 (Low) — `server_offline` after a Center restart is only safe because of forSec ≥ 60

After every outage the first evaluation (~15 s after start) sees all servers > 120 s since their last heartbeat and
puts them `pending` (observed: node-b pending at 02:20:27, reconnected 02:20:44; node-a pending 10:40:15,
reconnected 10:40:38). Agents reconnect 10–43 s after restart (backoff max 60 s + jitter), so a rule with
`forSec` below ~60 s — the lab already has three with `forSec: 15` — fires a false incident for every server after
any outage > 45 s. **Fix**: suppress `server_offline` evaluation for `max backoff + heartbeat interval` (~90 s)
after Center start, or measure offline time from `max(lastHeartbeatAt, centerStartedAt)`.

### Q-1 (question) — TTL-expired `nginx.apply` leaves the revision `apply_failed`

In P7-T02 A the queued apply expired before any agent saw it; the revision became `apply_failed` with
`errorCode: TTL_EXPIRED`. Nothing ran, so `expired` (or returning the revision to `approved`/`valid` for a fresh
apply) would describe it better. Not a safety issue.

### Lab hygiene

Twelve orphaned `tsup --watch` API dev servers from earlier E2E runs were still alive when this phase started
(their `stop_api` kills the listener but not the watcher); any `apps/api/src` edit would have restarted an API on
:4000 in the middle of an outage test. They were killed. The chaos scripts never use watch mode.

## BLOCKED / not covered

- Real VMs: systemd `service.restart` cannot succeed in the container lab (no systemd PID 1); kernel-level disk
  quota, real network partitions and clock skew need VMs.
- Gateway TLS certificate expiry (code inspection only — see the cert row).
- UI rendering of backend-unavailable states was checked statically (`monitoring-view.tsx` renders `ErrorState` on
  errors), not in a browser.

## How to re-run

```
python3 -I scripts/chaos/setup_fleet.py            # snapshot Center + fleet
python3 -I scripts/chaos/center_outage.py --variant api --minutes 10
python3 -I scripts/chaos/center_outage.py --variant api-db --minutes 3
python3 -I scripts/chaos/no_replay.py
python3 -I scripts/chaos/nginx_failsafe.py          # P7_T04_FROM=4 to resume after case 3
python3 -I scripts/chaos/concurrency.py
python3 -I scripts/chaos/disasters.py all
python3 -I scripts/chaos/disk_full.py
python3 -I scripts/chaos/log_dedup.py
```

## Fix status (2026-11-24)

All findings were fixed in the P7 commit. Each fix is covered by unit and/or integration tests. The lab E2Es
`e2e_p3` … `e2e_p6` were re-run green afterwards. The chaos scenarios marked FAIL above were **not** re-run in the
lab against the fixed build; the table keeps the original results.

| Finding | Fix                                                                                                                                                                 |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-1     | agent gives every log line a unique, strictly increasing timestamp per file, persisted with the read position                                                       |
| F-2     | heartbeat `bufferedBytes` reports only unshipped bytes                                                                                                              |
| F-3     | nginx apply/revert/validate write an fsynced inflight journal; on startup the agent restores the backup (only if files are still original or candidate) and reloads |
| F-4     | reload-failure result says files were restored and carries `restoredFiles[].sha256`; Center uses them in the drift flag                                             |
| F-5     | agent persists the lease token of started jobs and posts `AGENT_INTERRUPTED` at startup; Center maps interrupted nginx apply to "not applied"                       |
| F-6     | approval is a compare-and-set plus partial unique indexes; loser gets 409 `APPROVAL_ALREADY_EXISTS`                                                                 |
| F-7     | webhook deliveries during a running deployment coalesce into one pending commit per app (latest wins, `queued` / `superseded`), deployed when the running one ends  |
| F-8     | unknown-outcome candidate runs trigger `container.stop` + `container.remove` of the candidate; port released after removal                                          |
| F-9     | a failed "mark started" write is answered immediately with `AGENT_STATE_WRITE_FAILED` (job not executed)                                                            |
| F-10    | tailer rewinds on append failure; buffer append is all-or-nothing; unbufferable entries are counted as dropped                                                      |
| F-11    | database-unreachable errors return 503 `SERVICE_UNAVAILABLE` with `Retry-After`                                                                                     |
| F-12    | backup preflight `restic cat config` with a 60 s deadline → `REPO_UNREACHABLE`                                                                                      |
| F-13    | gateway checks its certificate every 6 h, renews below 30 days and hot-swaps with `setSecureContext`                                                                |
| F-14    | `server_offline` rules need `forSec >= 90` (migration raises old rules) plus a 90 s startup grace                                                                   |
| Q-1     | TTL-expired nginx apply returns the revision to `awaiting_approval` / `valid` instead of `apply_failed`                                                             |
