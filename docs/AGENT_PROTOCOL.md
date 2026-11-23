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
