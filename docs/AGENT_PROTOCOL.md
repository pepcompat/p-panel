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
