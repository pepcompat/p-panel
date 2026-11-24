# pPanel — Agent ↔ Center Protocol v1 (authoritative)

Implemented by `apps/api` (Center side, module `agent-gateway`) and `apps/agent` (Go). Change only by editing this file first.

## Transport

- Agent **always initiates**. No listener on the managed host.
- Enrollment: plain HTTPS (dev: HTTP allowed only when `PPANEL_DEV_INSECURE_ENROLL=1`) to Center API `:4000`.
- All post-enrollment calls: **mutual TLS** to the Agent Gateway `:4443` (separate Node `https` server inside the API process, `requestCert: true, rejectUnauthorized: true`, CA = pPanel internal agent CA).
- Center internal CA: ECDSA P-256, self-signed root generated at first start, private key stored **encrypted** (AES-256-GCM, key from env `PPANEL_MASTER_KEY`, 32 bytes base64) in table `ca_keys`. Agent leaf certs: 7-day validity (configurable), CN = `agent:<serverId>`, URI SAN `ppanel://agent/<serverId>`.
- Gateway TLS server certificate: issued by the same CA with SAN `localhost`, `127.0.0.1`, and hostnames in env `PPANEL_GATEWAY_HOSTNAMES`.
- After TLS handshake the gateway additionally checks: cert serial present in `agent_certificates` with `revokedAt IS NULL`, server not `revoked`. Otherwise 401 `AGENT_CERT_REVOKED`.

## Enrollment (`POST /api/v1/agent/enroll`, public, rate-limited 10/min/IP)

Request:

```json
{
  "token": "ppe_<base64url 32B>",
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "hostname": "node-a",
  "facts": {
    "os": { "id": "ubuntu", "version": "24.04", "arch": "arm64", "kernel": "6.8" },
    "agentVersion": "0.1.0"
  }
}
```

Center: lookup `sha256(token)` in `agent_enrollments`; reject if not found / `usedAt` set / expired → 401 `ENROLLMENT_TOKEN_INVALID` (same message for all three, no oracle). Mark used **in the same transaction** that creates the server + certificate (row lock / conditional update `WHERE used_at IS NULL`). CSR must be ECDSA P-256 and its signature valid; Center ignores CSR subject and sets its own.

Response 201 (envelope `data`):

```json
{
  "serverId": "uuid",
  "certificatePem": "...",
  "caPem": "...",
  "gatewayUrl": "https://center.example:4443",
  "heartbeatIntervalSec": 15
}
```

Agent stores key (0600, generated locally, never leaves host), cert, CA under `/var/lib/ppanel-agent/` (dev: configurable dir).

## Gateway endpoints (mTLS, JSON, no envelope needed but use the same envelope for consistency)

| Method | Path                            | Body                                                                                                                                             | Response data                                                                         |
| ------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| POST   | `/agent/v1/heartbeat`           | `{ seq, sentAt, agentVersion, metrics: {cpuPct, memPct, diskPct, load1, uptimeSec}, addresses: [...], capabilities: [...] , runningJobIds: [] }` | `{ serverTime, heartbeatIntervalSec, certRenewAfter }`                                |
| GET    | `/agent/v1/tasks?waitSec=25`    | long-poll, max 1 task batch                                                                                                                      | `{ tasks: TaskGrant[] }` (empty array on timeout)                                     |
| POST   | `/agent/v1/tasks/:jobId/ack`    | `{ leaseToken }`                                                                                                                                 | `{ status: "running" }` or 409 `TASK_EXPIRED` / `TASK_NOT_LEASED`                     |
| POST   | `/agent/v1/tasks/:jobId/result` | `{ leaseToken, status: "succeeded"                                                                                                               | "failed", output, error? }`                                                           | `{ accepted: true }` (idempotent per jobId) |
| POST   | `/agent/v1/certificate/rotate`  | `{ csrPem }`                                                                                                                                     | `{ certificatePem, notAfter }` old cert remains valid until its expiry unless revoked |

`TaskGrant`:

```json
{
  "jobId": "uuid",
  "type": "inventory.collect",
  "params": {},
  "idempotencyKey": "...",
  "issuedAt": "iso",
  "expiresAt": "iso",
  "leaseToken": "random",
  "desiredVersion": 3,
  "serverId": "uuid"
}
```

Rules:

- Agent **must** refuse a grant with `expiresAt < now` (clock skew tolerance 30 s), wrong `serverId`, or unknown `type` → posts result `failed` with error `REJECTED_EXPIRED` / `REJECTED_UNKNOWN_TYPE`.
- Agent keeps a bounded on-disk set of completed jobIds (last 1000) and never re-executes a completed jobId (returns cached result instead).
- Center never re-delivers a job whose lease expired while `type` is classified `mutating`; it transitions to `expired` and requires a new human/API request (TEST P2-T02 / E2E-11).
- Read-only types may be re-leased.
- Before executing, the agent durably records the job as `started` (with its `leaseToken`, kept only until completion). If that write fails after the ack (e.g. state dir full) the agent does **not** run the job and immediately posts `failed` with `AGENT_STATE_WRITE_FAILED` (`details: { stateDir, diskFull }`).
- At start the agent posts `failed` / `AGENT_INTERRUPTED` for every job a previous agent process recorded as `started` but never completed (it died mid-job), using the persisted lease token. If the lease is already gone the Center answers 409 `TASK_EXPIRED` and the agent drops the result. Such a job is never re-executed.

## Reconnect

Exponential backoff 1 s → 60 s with jitter. Agent failure or Center outage **never** stops, restarts or reconfigures workloads on the host (agent only runs typed handlers on explicit grants).

## Versioning

Header `X-Agent-Protocol: 1`. Center rejects unknown major with 426 `AGENT_PROTOCOL_UNSUPPORTED`.

## Nginx typed jobs (P3) — authoritative

Schemas: `packages/shared-contracts/src/jobs.ts` (`nginx.read_files`, `nginx.validate`, `nginx.apply`, `nginx.revert`). The agent re-validates every field in Go (strict decode) — the Center's validation is not trusted.

### Path policy (agent-enforced)

- Path must match `^/etc/nginx/[A-Za-z0-9._/-]{1,200}$`, contain no `..` or `//`, and after `filepath.EvalSymlinks` of the **parent directory** still resolve under `/etc/nginx/`. The target itself must not be a symlink (sites-enabled symlinks are edited via their real path in sites-available; the agent rejects writing through a symlink with `PATH_NOT_ALLOWED`).
- Creating a new file (`expectedSha256Before: null`) is allowed **only** under `/etc/nginx/ppanel-managed/` (directory created 0755 if absent). Editing an existing file anywhere under `/etc/nginx/` is allowed only if its current sha256 equals `expectedSha256Before`.
- Max 256 KiB per file, max 20 files per job; content must be valid UTF-8 and must not contain NUL.
- Optional agent config `nginx.allowedRoots` can narrow (never widen) the roots.

### `nginx.read_files` (read-only, re-leasable)

Output: `{ files: [{ path, exists, sha256|null, sizeBytes, content|null, isSymlink, resolvedPath }] }` (content omitted if > 256 KiB → `truncated: true`).

### `nginx.validate` (mutating, dry-run, never reloads)

1. Preflight every file (path policy + `expectedSha256Before`) → `DRIFT_DETECTED` with `details.files[{path, expected, actual}]` on mismatch; nothing written.
2. Backup originals to `<stateDir>/nginx-backups/<jobId>/` (manifest.json with path, sha256, mode, uid, gid, existed).
3. Atomic write (temp file in same dir + fsync + rename, preserve mode/owner; new files 0644).
4. `nginx -t` (fixed argv, 30 s timeout, output capped 16 KiB).
5. **Always** restore originals (delete created files) and verify restored sha256 == original. If restore fails → `REVERT_FAILED_MANUAL_RECOVERY` (critical).
6. Output: `{ valid: bool, nginxTestOutput, filesChecked: [{path, sha256Before, sha256After}] }`. `valid:false` is a **succeeded** job with `valid:false` (the validation ran), not an error.

The running nginx process is never signalled by validate. Window during which candidate files are on disk is bounded by the `nginx -t` duration; documented as a risk (another actor reloading nginx in that window would load the candidate).

### `nginx.apply` (mutating)

Steps 1–4 as validate (backup kept at `<stateDir>/nginx-backups/<revisionId>/`, retained for the last 20 revisions). Then:

- `nginx -t` fails → restore, return error `NGINX_TEST_FAILED` (details.nginxTestOutput). No reload.
- Reload: `systemctl reload nginx` when systemd is PID 1 and the unit is active; otherwise `nginx -s reload`. Fixed argv. Failure → restore + `nginx -t` + reload → `RELOAD_FAILED_REVERTED`.
- Postchecks (after a 2 s settle): each probe is an HTTP(S) GET to **127.0.0.1** (port default 80/443) with `Host: <hostHeader>`, TLS verification off for loopback, SNI = hostHeader, 5 s timeout, no redirects followed. Also verify the nginx master PID is alive. Any failure → restore + `nginx -t` + reload → `POSTCHECK_FAILED_REVERTED` with per-probe results.
- Success output: `{ applied: true, files: [{path, sha256Before, sha256After}], nginxTestOutput, reloadMethod, postchecks: [{hostHeader, path, status, ok}], backupId }`.

### `nginx.revert` (mutating)

Preflight: each `expectedCurrent[i].sha256` must equal what is on disk (null = must not exist) → else `DRIFT_DETECTED`. Backup for `revisionId` must exist → else `BACKUP_NOT_FOUND`. Restore → `nginx -t` (fail → put the pre-revert content back, `NGINX_TEST_FAILED`) → reload. Output like apply.

### Interrupted nginx jobs and manual-recovery reports

- Mutating nginx jobs write a journal `<stateDir>/nginx-backups/inflight.json` (fsync, no-follow dir fd) after the backup and **before** the first change to `/etc/nginx`; it is removed once the job reaches a final state. A journal found at agent start means the agent died mid-job: before accepting jobs the agent restores that backup and, for `nginx.apply` / `nginx.revert`, runs `nginx -t` + reload, so the host matches "not applied" / "not reverted" (what the Center records for a job that never reported success). It only does so when every file is still either the original or the interrupted job's candidate; otherwise nothing is touched and the backup is marked `interrupted-manual`. The job itself is reported as `AGENT_INTERRUPTED` (see Rules above) when its lease is still valid.
- `REVERT_FAILED_MANUAL_RECOVERY` with `details.restored: true` means the files **were** restored and verified and only `nginx -t` / reload of the restored config failed; `details.restoredFiles: [{ path, sha256|null }]` carries the verified checksums (null = file absent).

### Concurrency

The agent holds a process-wide mutex for all `nginx.*` mutating jobs. The Center also locks resource `nginx:<serverId>` (one in-flight mutating nginx job per server).

## Containers (P4) — authoritative

Schemas: `packages/shared-contracts/src/jobs.ts` (`container.*`). Strict decode on the agent; Center validation is not trusted. Docker access only through the Docker Engine API on the local unix socket (`/var/run/docker.sock`, configurable `docker.socket`); **no `docker` CLI, no shell**. Non-GET Docker API calls are allowed **only** from the `container.*` handlers, never from discovery/inventory.

### Ownership rule

The agent touches only containers that carry **all** labels `ppanel.managed=true`, `ppanel.app=<app>` and whose name matches `ppanel-<app>-<8hex>`. Anything else → `CONTAINER_NOT_MANAGED` (no Docker call made beyond the inspect).

### Hardened run (`container.run_candidate`)

1. Preflight: name not already present (`CONTAINER_EXISTS`); `127.0.0.1:<hostPort>` not listening (`PORT_IN_USE`); Docker reachable (`DOCKER_UNAVAILABLE`).
2. Secrets: if `secretEnvKeys` non-empty or `registryAuth`, call `POST /agent/v1/tasks/:jobId/secrets {leaseToken}` → `{ env: {KEY: value}, registryAuth?: {username, password, serveraddress} }`. The Center returns them **once** per job (second call → 409 `SECRETS_ALREADY_FETCHED`). Values live only in memory, are never logged, never written to disk or results, and are redacted (replaced by `[REDACTED]`) from any container log text the agent returns. Any key missing → `SECRETS_UNAVAILABLE`, nothing created.
3. Pull `image` (digest reference only) → `IMAGE_PULL_FAILED` (message only, no credentials).
4. Network `ppanel-<app>` (bridge, created if absent, label `ppanel.managed=true`).
5. Create with: `HostConfig.PortBindings` `{containerPort/tcp: [{HostIp: "127.0.0.1", HostPort: hostPort}]}` only; `Privileged=false`; `CapDrop=["ALL"]`, `CapAdd` only `["CHOWN","SETUID","SETGID","NET_BIND_SERVICE","DAC_OVERRIDE"]`; `SecurityOpt=["no-new-privileges:true"]`; `Memory`, `NanoCpus`, `PidsLimit` from `resources`; `ReadonlyRootfs` per params; `RestartPolicy=unless-stopped`; `NetworkMode=ppanel-<app>`; mounts: named volumes `ppanel-<app>-<name>` only; **never** host binds, `/var/run/docker.sock`, host network/PID/IPC, devices. Labels: `ppanel.managed=true`, `ppanel.app`, `ppanel.deployment=<deploymentId>`, `ppanel.image=<digest ref>`.
6. Start, then health loop: HTTP GET `http://127.0.0.1:<hostPort><path>` every `intervalSec` until a status in `expectStatus` or `startPeriodSec` elapses (also fail fast if the container exits).
7. Unhealthy/exited → capture last 50 log lines (redacted), **remove the candidate**, result error `CANDIDATE_UNHEALTHY` with `details: {exitCode?, lastStatus?, logTail}`.
8. Success output: `{ containerId, name, image, imageId, hostPort, health: {status, attempts, elapsedMs} }`.

`container.start` / `container.restart`: ownership rule, then start/restart and the same health loop → `CANDIDATE_UNHEALTHY` (left stopped, not removed) or `{ name, health }`. `container.stop` (10 s grace) and `container.remove` (refuses if running → stop first; volumes never removed) return `{ name, state }`. `container.list` → `{ containers: [{name, id, image, state, status, hostPort, deploymentId, createdAt}] }`. `container.logs` → `{ lines: [...], truncated }` (≤ 1000 lines, ≤ 256 KiB, ANSI stripped, redacted with any secret values the agent still holds for that app — none after the run job ends, so the Center also redacts).

### Managed Nginx routing bootstrap

In addition to `/etc/nginx/ppanel-managed/**`, the nginx path policy allows **creating** exactly one more file: `/etc/nginx/conf.d/ppanel-managed.conf` (expected content `include /etc/nginx/ppanel-managed/*/*.conf;`). This is a one-time, approval-gated per-server operation ("enable managed routing") done through a normal `nginx.apply`. Routes for managed apps live in `/etc/nginx/ppanel-managed/<app>/route.conf` (upstream + server block generated by the Center from a fixed template), switched by `nginx.apply` with postchecks against the new upstream.

### Concurrency

One mutating `container.*` job per app at a time (agent mutex per app; Center lock `app:<applicationId>`), and nginx mutations remain globally serialized.

## Builds (P4b) — authoritative

`image.build` and `source.inspect` run **only** on agents whose local config sets `build.enabled: true` (operator decision on the host, not Center-controlled) → otherwise `NOT_A_BUILD_NODE` before ack. The Center never builds. A Dockerfile's `RUN` steps execute as containers on the build node: **the build node must be a dedicated, trusted host** (documented; not an isolation guarantee).

- **Source fetch** (no shell): `git` binary via `execx` with fixed argv in a fresh temp dir under `<stateDir>/builds/<buildId>`: `git init -q`, `git remote add origin <url>`, `git -c protocol.version=2 fetch --depth 1 --no-tags origin <commitSha>`, `git checkout -q --detach FETCH_HEAD`, then verify `git rev-parse HEAD` == `commitSha` (else `SOURCE_FETCH_FAILED`). Env: `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `HOME=<tempdir>`, `GIT_ALLOW_PROTOCOL=https:git` (git only if allowlisted); auth header (from the secrets call, `gitAuth: {header}`) passed via `GIT_CONFIG_COUNT/KEY_0=http.extraHeader/VALUE_0` env — never argv, never logged. Submodules and LFS are not fetched. URL host must be in `build.gitHostsAllowlist` (exact host[:port]) → `GIT_HOST_NOT_ALLOWED`. Timeout counts toward `limits.timeoutSec`.
- **Context**: `subdir` resolved inside the checkout (symlinks escaping the checkout → `SOURCE_FETCH_FAILED`), tarred without `.git`, ≤ 500 MiB. `dockerfile` must exist inside the context (`DOCKERFILE_NOT_FOUND`); `template` uses the agent-embedded Dockerfile (`templates/<name>/Dockerfile` in the repo, `go:embed`), written into the tar as `Dockerfile.ppanel`.
- **Build**: Docker Engine `POST /build` (classic builder API) with `t=<pushRepo>:build-<buildId12>`, `dockerfile`, `buildargs`, `target`, `memory`, `cpuperiod/cpuquota`, `networkmode` (`default`|`none`), `rm=1`, `forcerm=1`, `pull=1`, labels `ppanel.build=<buildId>`, `ppanel.app`, `ppanel.commit`. Stream decoded; `errorDetail` → `BUILD_FAILED`; over time → cancel request + `BUILD_TIMEOUT`. Build log kept ≤ 2000 lines / 512 KiB, ANSI stripped, secret values redacted.
- **Push**: `POST /images/<name>/push?tag=build-<id12>` with `X-Registry-Auth`; digest taken from the stream's `aux.Digest` → `PUSH_FAILED` if absent. Local build image then removed (`DELETE /images/<tag>?noprune=0`); dangling build cache is not pruned automatically (operator task, documented).
- **Output**: `{ image: "<pushRepo>@sha256:…", tag, commitSha, durationMs, logTail: [last 200 lines], template?: name }`. Full log lines are returned in `output.log` (bounded) for the Center to store.
- Engine allowlist additions (build-node agents only): `POST /build`, `POST /build/cancel`, `POST /images/{name}/push`, `DELETE /images/{name}` (only tags matching `build-<hex12>` created by this job).
- **`source.inspect`** (read-only): same fetch, then returns `{ commitSha, files: { "<name>": content } }` only for names in `SOURCE_INSPECT_FILES` at the context root, each ≤ 64 KiB (larger → omitted with `truncated:[names]`). Temp dir removed after.

## Compose (P4b) — authoritative

The agent never parses YAML. The Center validates the compose file (§7.6 rules), resolves every image to a digest, topologically sorts services, and sends a normalised `compose.apply` plan.

`compose.apply` (per-app mutex, ownership rules from §Containers, hardened HostConfig as in `run_candidate` for every service; only `routeService` gets `127.0.0.1:<hostPort>`; all services join network `ppanel-<app>` with DNS alias = service name):

1. Fetch secrets once if any `secretEnv` or `registryAuth`.
2. For each service in order: find the running managed container labelled `ppanel.service=<service>`. If its `ppanel.spec` label == `specHash` and it is running → **keep** (status `unchanged`). Else:
   - **route service**: create the new container (new name) alongside the old one, wait health → `COMPOSE_SERVICE_UNHEALTHY` (new removed, old untouched, stop processing). The old container is left running; the Center switches the route and then stops it (`container.stop`).
   - **other services**: wait for `dependsOn` services to be healthy, stop the old container (10 s grace), create + start the new one, wait health. Unhealthy → stop the new one, restart the old one, `COMPOSE_SERVICE_UNHEALTHY` with `details.service` (brief downtime for that service is inherent and reported).
3. Output: `{ services: [{ service, name, action: "unchanged"|"created"|"replaced", previousName?, hostPort?, health }] }`.

Health types: `http` (loopback for the route service, container IP on the app network otherwise — probed from the agent), `tcp` (connect to container IP:port), `running` (state running for `startPeriodSec` without restarts). Volumes are named `ppanel-<app>-<name>`, created if absent, **never removed** by any job. `compose.stop` stops all managed containers of the app (volumes kept) → `{ stopped: [names] }`.

### P4b implementation notes (as built, 2026-11-23)

- **Push digest**: Docker Engine 29 with the containerd image store sends no `aux.Digest` on push; the agent falls back to the status line `build-<id12>: digest: sha256:<64> size: N` for its own tag only, else `PUSH_FAILED`.
- `image.build` output: `{ image, tag ("build-<id12>"), commitSha, durationMs, logTail, log, template? }`; failure details `{ logTail, log }`. A git-fetch timeout inside a build → `BUILD_TIMEOUT`; a push timeout → `PUSH_FAILED`; oversized context or escaping symlink → `SOURCE_FETCH_FAILED`. Git config also forces `core.hooksPath=/dev/null` and `http.followRedirects=false` (renamed GitHub repos therefore fail — use the canonical URL).
- `source.inspect` output: `{ commitSha, files, truncated }` (`truncated` always present).
- Compose service containers are named `ppanel-<app>-<service>-<8hex>` (accepted by the ownership name check, verified against the `ppanel.service` label). An `unchanged` service reports `health: {status:"running", attempts:0, elapsedMs:0}`. On `COMPOSE_SERVICE_UNHEALTHY` the failed new container is **removed** and details carry `{ service, services, logTail, reason, attempts, elapsedMs, exitCode?, lastStatus?, removed, restored, previousName?, dependency? }`.
- Known gaps: classic builder only (no BuildKit secrets/`--mount`), dangling build cache not pruned automatically, Docker Hub short refs with tag+digest (`postgres:16-alpine@sha256:…`) are not normalised by the Center yet — use `docker.io/library/postgres@sha256:…`.

## Telemetry: metrics and logs (P5) — authoritative

Decision: ADR-0008 — the agent is the telemetry adapter (no per-node Alloy in v1). One outbound mTLS channel; the Center enforces scope, redaction and labels before anything reaches Prometheus/Loki.

### Metrics (heartbeat extension)

Heartbeat gains optional fields (omitted, never zero, when unknown):

```json
"metrics": { "cpuPct": 12.1, "memPct": 40.2, "diskPct": 63.0, "load1": 0.4, "uptimeSec": 1234,
             "memTotalBytes": 0, "memAvailableBytes": 0, "diskTotalBytes": 0, "diskFreeBytes": 0,
             "netRxBytes": 0, "netTxBytes": 0 },
"containers": [ { "name": "ppanel-web-1a2b3c4d", "app": "web", "service": "app|null", "deploymentId": "uuid|null",
                  "state": "running|exited|restarting|paused|created|dead", "health": "healthy|unhealthy|starting|none",
                  "restartCount": 0, "cpuPct": 1.2, "memBytes": 12345678, "memLimitBytes": 536870912 } ],
"logShipping": { "bufferedBytes": 0, "bufferCapBytes": 67108864, "droppedEntries": 0, "lastShippedAt": "iso|null" }
```

Only **pPanel-managed** containers (ownership labels) are reported. Container stats via Docker Engine `GET /containers/{id}/stats?stream=false&one-shot=true` (GET only, existing read client), at most every heartbeat, bounded to 50 containers.

### Logs (`POST /agent/v1/logs`, mTLS gateway)

Request: `Content-Encoding: gzip`, JSON body ≤ 1 MiB compressed / 8 MiB decompressed (Center rejects bigger with 413):

```json
{
  "batchId": "uuid",
  "seq": 42,
  "sentAt": "iso",
  "entries": [
    {
      "ts": "iso (nanosecond precision allowed)",
      "source": "nginx_access|nginx_error|container|agent",
      "app": "web|null",
      "service": "app|null",
      "container": "ppanel-web-1a2b3c4d|null",
      "file": "/var/log/nginx/access.log|null",
      "stream": "stdout|stderr|null",
      "level": "debug|info|warn|error|fatal|null",
      "line": "≤ 16 KiB, UTF-8, already redacted"
    }
  ],
  "dropped": { "entries": 0, "since": "iso|null" }
}
```

Max 5000 entries per batch. Response `{ accepted: n, duplicate: bool }` (dedupe by `batchId` for 24 h). **429** with `Retry-After` = Center backpressure → the agent keeps the batch and retries later (never drops on 429 alone). 401/403 → stop shipping, back off at max.

Agent rules:

- Sources (config `logs.sources`, defaults): `nginx_access` `/var/log/nginx/access.log`, `nginx_error` `/var/log/nginx/error.log` (tail with inode/offset tracking, rotation-aware, positions persisted in `<stateDir>/logs/positions.json`), `container` for every managed container (Docker `GET /containers/{id}/logs?follow=1&stdout=1&stderr=1&timestamps=1&since=<last ts>` demuxed), `agent` (own structured log, level ≥ info). No other files, no journald in v1. Paths are config-only (never from the Center).
- **Redaction before buffering** (shared pattern list in `packages/shared-contracts/src/redaction.ts`, mirrored in Go with golden tests): bearer tokens, `Authorization:` headers, `api[_-]?key|token|secret|passw(or)?d|client_secret` key/value pairs (`=`, `:`, JSON), JWTs, AWS access keys (`AKIA…`), GitHub tokens (`gh[pousr]_…`), Slack tokens, private key blocks, `ppe_` enrollment tokens, URL userinfo (`scheme://user:pass@`). Replacement `[REDACTED]`. Plus any in-memory secret values the agent holds for a running job.
- **Bounded buffer**: append-only segment files under `<stateDir>/logs/buffer/` with total cap `logs.bufferCapBytes` (default 64 MiB, min 1 MiB) and memory cap (in-flight batch only). When full → **drop oldest segments**, count `droppedEntries` and report it in the next batch `dropped` and in heartbeat `logShipping`. Never block workloads; tailing pauses for a source if its reader falls behind (positions keep the place), so disk usage is bounded by the cap.
- Lines > 16 KiB truncated with ` …[truncated]`. Level detection: nginx error log severity; JSON `level`/`severity` fields; stderr → `error` only if no better signal; else `null`.
- Ship every 2 s or 1000 entries, whichever first; exponential backoff on failure (1 s → 60 s).

### P5 implementation notes (as built, 2026-11-23)

- Every log entry always carries all keys (`ts, source, app, service, container, file, stream, level, line`), with unknown values as JSON `null`.
- The agent drops a batch only on 400/413/422 (counted in `droppedEntries`). The Center therefore returns 4xx only for genuinely invalid batches, and 503 for transient problems (for example Loki down).
- Spoofed `app`/`container` entries are dropped **per entry** by the Center: the batch still returns 200, with a `rejected` count.
- `logShipping.bufferedBytes` is the **unshipped** backlog (bytes of buffered entries not yet accepted by the Center), not the on-disk buffer size.
- File sources (nginx logs) get a unique, strictly increasing `ts` per file: `max(now, previous + 1 ns)`, persisted with the read position, so byte-identical lines are never de-duplicated by Loki. A file's read position advances only after its lines are durably buffered; if the buffer cannot be written (disk full) the lines are re-read on the next poll instead of being lost. Container and agent entries that cannot be buffered are counted in `droppedEntries`.
- The Center computes log-drop totals from **deltas of the heartbeat's cumulative `logShipping.droppedEntries`**. The batch `dropped` field is informational only.
- Delivery is at-least-once: up to ~1 s of lines can repeat after an agent crash.
- `cpuPct` for containers appears from the second heartbeat onwards.

## Backups and restores (P6) — authoritative

Repository model (ADR-0009): **restic** repositories behind **rest-server with `--private-repos --append-only`** for agents. Each server has its own rest-server user and private path (`/<serverUser>/`). An agent's credential can **create** snapshots and **read** its own repo; it can never forget/prune/delete. Retention (`forget --prune`) and the offsite copy (`restic copy` → S3-compatible) run from a separate **maintenance identity** (a full-access rest-server instance on the same data), driven by an operator script (`scripts/backup/maintenance.sh`). Neither the agents nor the Center API hold that credential.

### Secrets for backup jobs

`POST /agent/v1/tasks/:jobId/secrets` for `backup.*` / `restore.run` returns `{ restic: { repoPassword, restUser, restPassword }, env: { <passwordSecretKey>: value, … } }`. Passed to restic **only via env** (`RESTIC_PASSWORD`, `RESTIC_REST_USERNAME`, `RESTIC_REST_PASSWORD`; DB tools `PGPASSWORD` / `MYSQL_PWD`), never argv, never logged, redacted from outputs.

### Execution (no shell anywhere)

- **paths** targets: host `restic` binary (version ≥ 0.17, path from config `backup.resticPath`, verified at startup) via `execx` fixed argv: `restic -r <url> backup --json --tag ppanel --tag run=<runId> --tag policy=<policyId> [--exclude …] [--limit-upload] -- <paths…>`. Paths must exist and must not be under the agent state dir; symlinks are stored as symlinks (restic default).
- **volume / postgres / mysql** targets: a hardened **helper container** (`backup.helperImage` from local agent config — the job's `helperImage` must equal it, else `HELPER_IMAGE_NOT_ALLOWED`), with the same hardening as `run_candidate` (no published ports, CapDrop ALL, no-new-privileges, limits), labels `ppanel.managed=true, ppanel.app, ppanel.backup=<runId>`, removed after the run:
  - volume: mount `ppanel-<app>-<volume>` **read-only** at `/backup/<volume>`, `restic backup --json … /backup/<volume>`.
  - postgres: join `ppanel-<app>`, `restic backup --json --stdin-filename <db>.sql --stdin-from-command -- pg_dump --no-password --format=plain --clean --if-exists -h <service> -U <user> <db>`.
  - mysql: `… --stdin-from-command -- mysqldump --single-transaction --routines --triggers -h <service> -u <user> <db>`.
- **Manifest**: for paths/volume targets the agent records `{ path, size, sha256 }` for up to 10 000 files (beyond → `truncated: true`), computed from the source **during** backup and stored in the result (not in the repo). For DB targets: `{ database, bytes, sha256 of dump stream, tables: [{ name, rows }] }` — table row counts come from a read-only query in the helper (`psql -At -c "select relname, n_live_tup …"` after `ANALYZE` is **not** run; exact counts via `select count(*)` per table, ≤ 200 tables).
- `backup.run` first checks the repository with `restic cat config` (no lock) bounded to 60 s; no answer in time (restic would otherwise retry backend errors for ~15 min) or a connectivity error → `REPO_UNREACHABLE`, nothing backed up.
- Result `backup.run`: `{ snapshots: [{ target, snapshotId, shortId, sizeBytes, filesNew, filesChanged, durationMs }], manifest: [...], resticVersion }`. **A run that does not finish all targets is a failure** (`BACKUP_PARTIAL`, with the completed target list), never success. An interrupted agent never reports success (the job expires on the Center; restic leaves no snapshot for an aborted run; a stale restic lock → `REPO_LOCKED` on the next run, cleared only by the maintenance identity).
- `backup.snapshots` → `{ snapshots: [{ id, shortId, time, tags, paths, hostname, sizeBytes? }] }` (restic `snapshots --json`).
- `backup.verify` → `restic check --read-data-subset=<pct>%` + `restic dump`/`restore` of the snapshot into a temp dir and re-hash against the manifest supplied by the Center in the job params (`manifest` field) → `{ repoCheckOk, filesCompared, mismatches: [...], level: "repository_checked" | "restore_verified" }`.
- `restore.run`:
  - paths `staging` → `<stateDir>/restores/<restoreId>/` (mode 0700). `in_place` → restic restore `--target /` with `--include` for the listed paths, then verify.
  - volume `staging` → a **new** volume `ppanel-<app>-restore-<8hex>`. `in_place` → the original volume; the Center stops the app first.
  - postgres/mysql `scratch` → a new helper DB container (scratch image, random password, no ports, app-independent network `ppanel-restore-<8hex>`), restore the dump (`restic dump … | psql` via `--stdin-from-command` is not available for restore, so the helper runs `restic dump <snap> <file>` to a temp file in the container, then `psql -f`), compare table row counts with the manifest, then **remove** the scratch container. `in_place` → restore into the app DB service (the Center has approved and taken a pre-restore safety snapshot).
  - `dryRun: true` → restic `restore --dry-run` / `--verbose` listing (paths) or dump size + table list (DB); nothing written.
  - Result: `{ restored: [...], verify: { ok, compared, mismatches }, stagingPath?, volume?, scratch?: { removed: true } }`.

All mutating backup/restore jobs hold the per-app mutex (DB/volume targets) and a per-repo mutex on the agent.

### P6 implementation notes (as built, 2026-11-23)

- **Manifest** (one entry per target, returned by `backup.run` and passed back in `backup.verify` / `restore.run` params as `manifest`): `{ target, type, snapshotId, paths?, app?, volume?, files?: [{ path, size, sha256 }], fileCount, truncated, database?, bytes?, sha256?, tables?: [{ name (schema-qualified, e.g. "public.orders"), rows }], constraints?: ["<schema.table>:<constraint>"] }`. DB row counts are exact but come from a read-only session after the dump, so they are not transactionally consistent with it.
- **DB restore without a shell**: a restic helper runs `dump --target /work/<db>.sql`. The file is streamed through the Docker archive API into a not-yet-started psql/mysql helper, which then runs `psql -f` or `mysql -e "source …"`.
- **Scratch image**: when `target.scratchImage` is omitted, the Center defaults it to the source DB service's own image. A dump from a newer server minor can contain settings an older server rejects (lab: pg 16.16 dump into 16.10 failed).
- **Repo host**: helper containers get the repo host as an `ExtraHosts` entry, resolved by the agent.
- restic exit 10 ("repository does not exist") → `REPO_UNREACHABLE`. P6 jobs can also return `SECRETS_UNAVAILABLE`, `DOCKER_UNAVAILABLE`, `IMAGE_PULL_FAILED` and `CONTAINER_NOT_MANAGED`.
- Known gaps: in-place restores of paths/volumes are covered by unit tests only, not in the lab. A failed volume staging restore leaves its new volume behind (agents never delete volumes). `backup.snapshots` / `backup.verify` need host restic even on Docker-only nodes.

## Private networking and network jobs (P9) — authoritative

Contract: `docs/P9_NETWORK_CONTRACT.md` §1, §2, §4, §5. Implemented by `apps/agent/internal/connpath`, `internal/provider`, `internal/netdiag`.

### Management paths

- Enrollment response (additive): `gatewayEndpoints: [{ path: "public"|"private", url }]` (≤ 8, `https://host[:port]`, no userinfo/query/fragment/path, no duplicate URL; an invalid list fails the enrollment like an invalid `gatewayUrl`). The agent writes a fresh `<stateDir>/connection.json` (0600, `internal/safefs`, no symlink following) at every enrollment: the endpoints (or `gatewayUrl` as the only `public` endpoint), no policy, nothing forbidden. A state dir without `connection.json` (enrolled before P9) behaves exactly as before: `gatewayUrl` is the single public endpoint.
- Heartbeat response (additive): `connection: { policy, endpoints: [{ path, url }] }`. An unknown policy or an invalid endpoint list is ignored (the last good state is kept); an empty `endpoints` list keeps the current endpoints. Changes are persisted; the last received state is used during a Center outage and across restarts.
- Dial order: `private_only` → [private]; `public_only` → [public]; `private_preferred` → [private, public]; `public_preferred` → [public, private]; `auto` → [private, public] when a private endpoint exists, else [public]. **No policy received yet** (fresh enrollment, older Center) → like `public_preferred`. **`private_only` never dials and never probes a public endpoint**, even when every private endpoint is down: requests then fail and back off (fail closed).
- Selection: the first endpoint in dial order that is not forbidden and probed healthy; else the first not yet probed; else rotation through the allowed endpoints. A transport-level failure (dial/TLS/timeout) of any gateway request marks that endpoint unhealthy and re-selects; HTTP error answers and undecodable 2xx bodies do not. Fail-back to a preferred path happens after the next successful probe.
- **`GET /agent/v1/ping`** (new gateway route, mTLS, no body): the probe target. Response `data: { path, serverTime, policyAllows }`. The Center answers it on **every** listener, also where the server's policy forbids the path (so a path can be verified before switching to it), and never treats it as heartbeat/liveness.
- Probing: every 60 s and once at start before the first heartbeat: TCP connect + TLS handshake (agent client cert, pinned CA, SNI = URL host) + `GET /agent/v1/ping`, 5 s, no proxy, no redirects, `Connection: close`. `ok` = 2xx. Error codes: `DIAL_TIMEOUT`, `TLS_FAILED`, `REFUSED`, `DNS_FAILED`, `UNREACHABLE`, `PATH_FORBIDDEN` (403 `CONNECTION_PATH_NOT_ALLOWED`), `HTTP_<status>`, `CONNECTION_FAILED`. All endpoints are probed except public ones under `private_only`. The ping's `policyAllows` is recorded with the result (`policyAllows` in the report); an endpoint whose last ping said `policyAllows: false` is never selected as the active path (it is still probed and reported).
- Heartbeat body (additive): `connection: { policy, activePath: "public"|"private"|null, endpoints: [{ path, url, ok, latencyMs|null, checkedAt, error?, policyAllows? }] }` (`latencyMs` is null when `ok` is false; only probed endpoints are listed; `policy` is informational, `""` = none received).
- 403 `CONNECTION_PATH_NOT_ALLOWED` on any request: the path is marked forbidden (persisted with the policy known at that time) and not dialled again until a heartbeat delivers a **different** policy that allows it. If every allowed endpoint is forbidden and no new policy arrives, the first is retried at most once per 10 min (the Center audits such requests once per 10 min) — never a path the policy does not allow.

### Provider facts (DigitalOcean metadata)

- Source: `http://169.254.169.254/metadata/v1.json` (agent config `provider.metadataUrl` overrides it — lab only; `provider.metadataDisabled: true` turns it off). GET, no proxy, no redirects (3xx = absent), 2 s, body ≤ 64 KiB, HTTP 200 only.
- Fact: `provider: { name: "digitalocean", dropletId: <int>, region, interfaces: { private: [ipv4], public: [ipv4] } }` (≤ 8 addresses each, `droplet_id` a positive integer ≤ 2^53, region `^[a-z0-9][a-z0-9-]{0,31}$`), otherwise `provider: null`. The agent never derives a VPC from it.
- Sent in enrollment `facts.provider` and in every heartbeat (`provider`, refreshed every 10 min and at start; omitted only when the source is disabled).

### `network.diagnose` (read-only, re-leasable, 60 s)

Params (strict, JSON null refused): `{ resolve?: string[] (≤ 10 DNS host names, no IP literals, no duplicates), tcp?: [{ host: IP literal, port }] (≤ 20, no duplicates), includeRoutes?: bool, allowedPorts?: int[] (≤ 32, 1..65535) }`.

- `tcp.host` must be in 10/8, 172.16/12, 192.168/16, 100.64/10 or fd00::/8 (IPv4-mapped forms are unmapped first; zones refused), **or** equal an advertised Center endpoint address (IP-literal URL host, or the resolved addresses of a host name, looked up only when needed). Loopback, link-local (metadata) and other public addresses → `REJECTED_INVALID_PARAMS` before ack.
- `tcp.port` must be in {22, 80, 443, 4443, 4444, 5432, 6379, 3306} ∪ `allowedPorts` (∪ the endpoint's own port for a Center endpoint address).
- Result: `{ interfaces: [{ name, mtu, up, addresses }], routes: [{ dst, gateway, iface, metric }] (from /proc/net/route + ipv6_route, ≤ 512; [] unless includeRoutes), routesError?: "UNSUPPORTED_OS"|"ROUTES_UNAVAILABLE", dns: [{ host, addresses, error?: NOT_FOUND|TIMEOUT|DNS_FAILED }], tcp: [{ host, port, ok, latencyMs|null, error? }], centerEndpoints: [same as heartbeat probe, probed now], checkedAt }`. DNS 3 s and TCP connect 3 s per target, run in parallel. Nothing is ever changed on the host.

### `http.probe` (read-only, re-leasable, ≤ 10 s)

Params (strict; the Center's `httpProbeParams` shape plus `allowedPorts`): `{ url, resolveTo, port?, method?: "GET"|"HEAD" (default GET), expectStatus?: int | int[] (1..10 codes 100..599, default [200]), timeoutSec?: 1..10 (default 10), allowedPorts?: int[] (≤ 32) }`.

- `url`: `http(s)://<host>[:port][/path?query]`, ≤ 2048 bytes, printable ASCII only, no backslash, userinfo, `@` or fragment. The host is a DNS name, or an IP literal that must equal `resolveTo`.
- `resolveTo`: IP literal in the same private ranges as `network.diagnose` (no loopback, no link-local, no public). **The only address the agent connects to**: a custom dialer ignores the URL host; Host header and TLS SNI = URL host; no DNS lookup, no proxy.
- Port: `port`, else the URL port, else 80/443; must be in {80, 443, 8080, 8443} ∪ `allowedPorts` (a `port` differing from an explicit URL port is refused).
- Redirects are never followed (a 3xx is reported with its `Location` header); at most 1 MiB of the body is read (sha256 of what was read); TLS certificates are reported (`tls.verified` against the system roots), never enforced; no request body, no cookies, no credentials.
- Result (the job **succeeds** whenever the probe ran): `{ url, resolveTo, method, ok, status|null, expectStatus, statusMatch, latencyMs, bodySha256|null, bytesRead, truncated, headers: {Content-Type, Content-Length, Server, Location, Cache-Control, Etag (≤ 512 B each, when present)}, remoteAddr, tls?: { version, verified, verifyError?, subject, notAfter }, error?: TIMEOUT|REFUSED|UNREACHABLE|DIAL_TIMEOUT|TLS_FAILED|HTTP_ERROR }`. `ok` = no error and status ∈ expectStatus.

### Gateway route files (nginx path policy addition)

`nginx.validate|apply|revert` may also **create** `/etc/nginx/ppanel-gateway/<name>` (depth 1 only; the directory is created 0755 and removed again when a revert empties it; a symlinked `ppanel-gateway` is refused) and exactly `/etc/nginx/conf.d/ppanel-gateway.conf`. `nginx.read_files` of such a file before its directory exists reports `exists: false` (instead of `PATH_NOT_ALLOWED`). Everything else of the P3 path policy is unchanged. No new file-writing job type.
