# P10 contract — secure central SSH gateway

Brief §P10 + §13.1 item 2 + §15 (SSH row). Every P10 workstream codes against this file; changes go through the
lead. All routes under `/api/v1`, COMPATTANA envelopes, camelCase bodies, snake_case filter fields.
**Gate: a terminal exists only through the Center SSH gateway (browser ↔ Center ↔ sshd). No shell through the Go
agent, no shell tool for MCP. Lab only — never touch production hosts or their sshd.**

## 0. Shape

```
browser (xterm.js) ──wss /api/v1/ssh/stream──▶ Center API (ws + ssh2 client) ──TCP──▶ server sshd (public-key auth)
                       Origin check + single-use ticket          private key decrypted in memory only
```

- Private keys live only in the Center DB, AES-256-GCM under `PPANEL_MASTER_KEY` (existing `common/crypto.ts`).
  No API response, log line, audit row, job param or WebSocket frame ever contains private material. The agent
  never receives a private key; it only installs **public** keys.
- New dependencies (exact pins): API `ssh2@1.16.0`, `ws@8.18.3`, dev `@types/ssh2@1.15.5`, `@types/ws@8.18.1`;
  web `@xterm/xterm@5.5.0`, `@xterm/addon-fit@0.10.0`.
- Permissions (already in `PERMISSIONS`): `ssh.connect` (request grants, open sessions — scope-checked against the
  server via `authz.has(user, perm, serverScope)`), `credentials.manage` (keys, key deployment, endpoints, host-key
  trust), `approvals.decide` (approve production grants). `fleet.read` sees metadata lists.

## 1. Data model (migration `20261130100000_p10_ssh`)

| Model (table)                              | Fields                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SshCredential` (`ssh_credentials`)        | `id, name, kind ('generated'\|'imported'), algorithm ('ssh-ed25519'\|'rsa-sha2-512'\|'ecdsa-sha2-nistp256'), public_key (OpenSSH one-line), fingerprint_sha256 ('SHA256:…'), private_key_enc, status ('active'\|'rotated'\|'revoked'), rotated_from_id?, created_by, created_at, revoked_at?, revoked_by?`                         |
| `SshEndpoint` (`ssh_endpoints`)            | `id, server_id, path ('private'\|'public'), host (IP literal), port (default 22), allowed_users text[], created_at, updated_at`; unique `(server_id, path)`                                                                                                                                                                        |
| `SshKeyDeployment` (`ssh_key_deployments`) | `id, server_id, credential_id, ssh_user, status ('pending'\|'installed'\|'removing'\|'removed'\|'failed'), job_id?, last_error?, updated_at`; unique `(server_id, credential_id, ssh_user)`                                                                                                                                        |
| `SshHostKey` (`ssh_host_keys`)             | `id, server_id, endpoint_id, algorithm, fingerprint_sha256, public_key, status ('pending'\|'trusted'\|'rejected'\|'superseded'), seen_via ('scan'\|'connect'), agent_match (bool\|null), first_seen_at, last_seen_at, trusted_by?, trusted_at?`                                                                                    |
| `SshAccessGrant` (`ssh_access_grants`)     | `id, user_id, server_id, ssh_user, endpoint_path, reason, duration_min, status ('awaiting_approval'\|'active'\|'expired'\|'revoked'\|'rejected'), grant_hash, requested_at, approved_by?, approved_at?, starts_at?, expires_at?, revoked_at?, revoked_by?`                                                                         |
| `SshSession` (`ssh_sessions`)              | `id, grant_id, user_id, server_id, ssh_user, endpoint_path, endpoint_host, endpoint_port, credential_fingerprint, host_key_fingerprint, status ('pending'\|'open'\|'closed'\|'failed'), end_reason?, exit_code?, client_ip, user_agent, bytes_in, bytes_out, created_at, opened_at?, closed_at?, ticket_hash?, ticket_expires_at?` |

`end_reason`: `client_closed | server_closed | idle_timeout | max_duration | grant_expired | grant_revoked |
credential_revoked | host_key_mismatch | auth_failed | connect_failed | center_shutdown | center_restart | limit`.

## 2. Credentials (P10-02)

- `GET /ssh/credentials` (`fleet.read`) → metadata only: `{ id, name, kind, algorithm, publicKey, fingerprintSha256,
status, rotatedFromId, createdAt, createdByLabel, revokedAt, deployments: [{ serverId, serverName, sshUser,
status }] }`. **Never** `privateKey*`.
- `POST /ssh/credentials { name, mode: 'generate' }` (`credentials.manage`, step-up) → Center generates ed25519
  (`ssh2.utils.generateKeyPairSync('ed25519')`), stores encrypted, returns metadata (201).
- `POST /ssh/credentials { name, mode: 'import', privateKey, passphrase? }` (`credentials.manage`, step-up) →
  parse with `ssh2.utils.parseKey`; reject encrypted-without-passphrase (422 `SSH_KEY_ENCRYPTED`), unsupported
  type or RSA < 3072 (422 `SSH_KEY_UNSUPPORTED`), > 16 KiB body (413). Stored re-encrypted, passphrase discarded.
  The request body is redacted from logs (`privateKey`, `passphrase` added to the redaction list).
- `POST /ssh/credentials/:id/deploy { serverId, sshUser }` (`credentials.manage`) → upsert `SshKeyDeployment`
  pending + queue agent job `ssh.keys.sync` for (server, user) with the full desired key set. 202 `{ jobId }`.
- `DELETE /ssh/credentials/:id/deployments/:deploymentId` → status `removing`, re-sync. 202.
- `POST /ssh/credentials/:id/rotate` (`credentials.manage`, step-up) → new ed25519 credential
  (`rotatedFromId`), copies every installed deployment to the new key and re-syncs each server (one job per
  server+user, adds new and removes old in the same write). Old key → `rotated` immediately (gateway refuses it).
- `POST /ssh/credentials/:id/revoke` (`credentials.manage`, step-up) → `revoked`; open sessions using it are
  closed (`credential_revoked`); every deployment → `removing` + re-sync. Revocation is effective at the Center
  instantly even if a host is offline (the Center never presents a revoked/rotated key).

### Agent job `ssh.keys.sync` (typed, allowlisted)

Params `{ user: string, keys: [{ fingerprint, publicKey }] (≤ 20), managedBlockId: 'ppanel' }`. The agent:

- validates `user` (`^[a-z_][a-z0-9_-]{0,31}$`, must exist via `/etc/passwd`, uid ≥ 1000 **or** listed in agent
  config `ssh.allowedUsers`; `root` refused unless `ssh.allowRoot: true` — default false) → else `SSH_USER_INVALID`;
- validates each public key (one line, allowed types `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, no options,
  no newlines) and recomputes the SHA256 fingerprint (must match) → else `SSH_KEY_INVALID`;
- rewrites only the block between `# >>> ppanel managed keys (do not edit) >>>` and `# <<< ppanel managed keys <<<`
  in `~user/.ssh/authorized_keys`, every managed line prefixed `restrict,pty ` (no forwarding of any kind);
  preserves every other line byte-for-byte; creates `.ssh` 0700 / file 0600 owned by the user; atomic
  write (tmp + fsync + rename) via `safefs`; refuses symlinks for `.ssh` and the file;
- result `{ user, managedFingerprints: [...], preservedLines: n, fileSha256 }`.

Agent facts add `ssh: { hostKeys: [{ algorithm, fingerprintSha256 }], port }` read from
`/etc/ssh/ssh_host_*_key.pub` (and `Port` in `/etc/ssh/sshd_config`, default 22); absent → `ssh: null`. This is the
independent (mTLS) channel used to cross-check host keys.

## 3. Endpoints and host keys (P10-03)

- `GET/PUT /servers/:id/ssh/endpoints` (`PUT` = `credentials.manage`): `[{ path, host, port, allowedUsers }]`.
  `host` must be an IP literal equal to a known address of that scope for the server (P9 inventory/provider or
  agent facts) — otherwise 422 `SSH_ENDPOINT_UNVERIFIED`. Lab/dev only (`NODE_ENV !== 'production'`): addresses
  in `PPANEL_SSH_LAB_ENDPOINTS` (comma list of `host:port`) are also accepted. `root` in `allowedUsers` → 422
  `SSH_ROOT_FORBIDDEN`.
- Path selection respects the P9 connection policy: `private_only` → private endpoint only; `public_only` →
  public only; others → the grant's `endpointPath`. **No automatic fallback** from a failed private endpoint to
  public; the user must request a grant for the other path, which is audited.
- `POST /servers/:id/ssh/host-keys/scan { path }` (`credentials.manage`) → Center opens TCP + SSH handshake, records
  the offered host key in `hostVerifier`, aborts before authentication. Upserts `SshHostKey` (`pending` if new),
  sets `agentMatch` by comparing with agent facts. Returns the key list.
- `GET /servers/:id/ssh/host-keys` (`fleet.read`).
- `POST /ssh/host-keys/:id/trust` (`credentials.manage`, **step-up always**) → `trusted`; any previously trusted key
  for the same endpoint+algorithm → `superseded`. `POST /ssh/host-keys/:id/reject`.
- On every connect the presented key must equal a `trusted` key for that endpoint. No trusted key → refuse
  `SSH_HOST_KEY_UNTRUSTED`. Different key → refuse `SSH_HOST_KEY_MISMATCH` (store the observed key as `pending`
  with `seenVia: 'connect'`, audit `ssh.host_key.mismatch`, end session `host_key_mismatch`). Never TOFU.

## 4. Grants, RBAC, MFA and approvals (P10-04)

- `POST /ssh/grants { serverId, sshUser, endpointPath, durationMinutes (15–480, default 60), reason (3–500) }`
  (`ssh.connect` on that server). Checks: server active, endpoint exists and allows `sshUser`, an `installed`
  deployment of an `active` credential exists for (server, sshUser) → else 422 `SSH_NO_CREDENTIAL`.
  - non-production server → `active` now (`startsAt = now`, `expiresAt = now + duration`);
  - production → `awaiting_approval`; `grant_hash = sha256(userId|serverId|sshUser|endpointPath|durationMin)`.
- `POST /ssh/grants/:id/approve` (`approvals.decide`, step-up, approver ≠ requester → 403 `SELF_APPROVAL_FORBIDDEN`,
  hash compare-and-set, single use; approval expires if unused 30 min after → `expired`), `POST …/reject`.
  On approve: `active`, window starts at approval.
- `POST /ssh/grants/:id/revoke` (requester or `credentials.manage`) → `revoked`; open sessions closed
  (`grant_revoked`). A sweeper (every 30 s) expires grants and closes their sessions (`grant_expired`).
- `GET /ssh/grants?status=&server_id=&user_id=` (own grants for everyone; all with `credentials.manage` or
  `approvals.decide`). Response adds `userLabel, serverName, approvedByLabel, environment`.

## 5. Sessions and the WebSocket gateway (P10-01)

- `POST /ssh/sessions { grantId, cols, rows }` (`ssh.connect`) → validates grant active + owned by caller; production
  also needs **step-up within the last 10 minutes** (`assertStepUp`). Limits (429 `SSH_SESSION_LIMIT`):
  `SSH_MAX_SESSIONS_PER_USER=3`, `SSH_MAX_SESSIONS_PER_SERVER=5`, `SSH_MAX_SESSIONS_GLOBAL=50`. Creates a
  `pending` session with a single-use ticket (32 random bytes, base64url; stored as sha256; TTL 30 s) →
  201 `{ sessionId, ticket, wsUrl, expiresAt, idleTimeoutSec, maxDurationSec }`. `wsUrl` = API origin with
  `ws(s)://…/api/v1/ssh/stream` — **the ticket is never in the URL**.
- WebSocket `GET /api/v1/ssh/stream` on the API HTTP server (`ws` `noServer`, upgrade handled before Nest):
  - `Origin` must be in `WEB_ORIGIN` list, else HTTP 403 before upgrade. `maxPayload` 64 KiB.
  - First message within 5 s must be text `{ "type": "auth", "ticket": "…", "sessionId": "…" }`; ticket valid,
    unexpired, unused, for that session → consumed atomically. Otherwise close 4401.
  - Center then: resolves endpoint + credential (must be `active`, deployment `installed`), connects with
    `readyTimeout` 10 s, strict `hostVerifier`, `algorithms` default ssh2 secure set, no agent, no forwarding, no
    X11, opens `shell` with `pty` (`xterm-256color`, cols/rows). Sends `{ type: 'ready', sessionId,
hostKeyFingerprint, endpoint: { path, host, port }, sshUser }`.
  - Client → server: binary = stdin bytes; text JSON `{ type: 'resize', cols (1–500), rows (1–200) }`,
    `{ type: 'ping' }`, `{ type: 'close' }`. Anything else → close 4400.
  - Server → client: binary = stdout/stderr bytes; text JSON `ready`, `pong`, `{ type: 'exit', code, signal? }`,
    `{ type: 'closing', reason }`, `{ type: 'error', code, message }`.
  - Idle timeout `SSH_IDLE_TIMEOUT_SEC=900` (no stdin and no stdout), max duration = min(grant expiry,
    `SSH_MAX_SESSION_SEC=28800`), WebSocket ping every 20 s (dead peer → close). Backpressure: pause the SSH
    stream when `ws.bufferedAmount > 1 MiB`.
  - Close codes: 1000 normal, 4400 protocol, 4401 auth, 4403 forbidden (grant/credential), 4408 idle/max/expired,
    4409 host key, 4429 limit, 4500 internal. Any close ends the SSH channel and connection (no orphan
    processes); session row → `closed` with `end_reason`, `bytes_in/out`, `exit_code`.
  - On Center shutdown every session closes with `center_shutdown`; at startup `pending/open` rows → `closed`
    `center_restart`.
- `GET /ssh/sessions?status=&server_id=&user_id=` (own; all with `credentials.manage`) and
  `POST /ssh/sessions/:id/terminate` (owner or `credentials.manage`).

## 6. Audit (P10-05)

Audit actions (metadata only — **no keystrokes, no output**): `ssh.credential.create|import|rotate|revoke`,
`ssh.key.deploy|remove`, `ssh.endpoint.update`, `ssh.host_key.scan|trust|reject|mismatch`,
`ssh.grant.request|approve|reject|revoke|expire`, `ssh.session.open|close|denied` (with end reason, bytes,
duration, endpoint, credential fingerprint, host key fingerprint, client IP). Terminal recording is **not**
implemented; settings expose `recording: 'disabled'` and the docs state that enabling it needs an explicit
policy + retention decision (future).

## 7. Errors

`SSH_KEY_ENCRYPTED`, `SSH_KEY_UNSUPPORTED`, `SSH_ENDPOINT_UNVERIFIED`, `SSH_ROOT_FORBIDDEN`, `SSH_NO_CREDENTIAL`,
`SSH_HOST_KEY_UNTRUSTED`, `SSH_HOST_KEY_MISMATCH`, `SSH_GRANT_INVALID` (403: not active / not owner / expired),
`SSH_SESSION_LIMIT` (429), `SSH_CONNECT_FAILED` (502), `SSH_AUTH_FAILED` (502), `SELF_APPROVAL_FORBIDDEN`,
`STEP_UP_REQUIRED` (existing).

## 8. Lab (P10-T1..T4)

- New lab node `lab-node-s` (profile `p10`, container `ppanel-lab-node-s`): the node image built with
  `WITH_SSHD=1` (openssh-server; `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `PermitRootLogin no`, `AllowTcpForwarding no`, `X11Forwarding no`, `PubkeyAuthentication yes`; user `ops`
  uid 1001 with no password), minimal extra caps for sshd only on this node (`SETUID, SETGID, CHOWN,
SYS_CHROOT, AUDIT_WRITE, KILL, DAC_OVERRIDE, FOWNER`), on `labnet`, port `127.0.0.1:52222→22`. Agent binary
  mounted like the other nodes. node-a/node-b are untouched. Script `scripts/lab/p10-ssh.sh up|down|rekey|status`
  (`rekey` regenerates the host keys and restarts sshd = "changed host key").
- Center for the E2E: `PPANEL_SSH_LAB_ENDPOINTS=127.0.0.1:52222`.
- `scripts/lab/e2e_p10.py` (WebSocket client = a small Node script using the API's `ws` dependency, invoked from
  Python; no new Python packages):
  - **T1** enroll node-s, generate key, deploy to `ops`, scan + trust host key (agentMatch true), grant
    (non-prod) → session → `echo`/`id -un` = `ops` round-trip, resize, exit code 0.
  - **T2** denied: revoked key (`credential_revoked`/4403), server without grant scope (403), expired grant
    (shorten `expires_at` in DB → 4403/`SSH_GRANT_INVALID`), production grant without approval, self-approval
    (403), changed host key after `rekey` (4409 `SSH_HOST_KEY_MISMATCH`, no auth attempted).
  - **T3** wrong Origin → 403 on upgrade; no ticket / reused ticket / other user's ticket → 4401; ticket only
    usable once; every API response in the run scanned for `PRIVATE KEY` / `privateKey` (none);
    the authorized_keys block contains only public keys with `restrict,pty`.
  - **T4** idle timeout (Center run with `SSH_IDLE_TIMEOUT_SEC=5`) and grant expiry close the session;
    afterwards `docker exec ppanel-lab-node-s ps` shows no `sshd: ops` session process; the session row has
    `end_reason` and no credential material.
  - Evidence `docs/evidence/<date>/p10-*.json`.

## 9. Ownership

| Workstream  | Owns                                                                                                                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Agent + lab | `apps/agent/**`, `infra/lab/**`, `infra/compose/lab.yml`, `scripts/lab/p10-ssh.sh`, `scripts/lab/e2e_p10.py` (+ its Node WS helper under `scripts/lab/`), `docs/AGENT_PROTOCOL.md` (P10 section) |
| API         | `apps/api/**`, `packages/shared-contracts/**`, `tests/security/**` (P10 cases), `docs/API_CONTRACTS.md` (P10 section)                                                                            |
| Web         | `apps/web/**` (SSH & Credentials page, terminal, server card/detail "Open Terminal", mocks, EN/TH)                                                                                               |
| Lead        | this file, `docs/SSH_SECURITY.md`, `docs/guides/ssh-terminal.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/TEST_REPORT.md`                                                                         |

## 10. As built (deviations agreed by the lead)

- `servers.ssh_facts` (JSONB, nullable) stores the agent's `ssh` fact for the host-key `agentMatch` check. The agent
  omits `port` when `sshd_config` is unreadable (the Center then assumes 22).
- End reason `terminated` (from `POST /ssh/sessions/:id/terminate`); error `SSH_STATE_INVALID` (409) for actions
  on a credential, grant or session in the wrong state. Agent job errors also include `SSH_PATH_UNSAFE` and
  `SSH_KEYS_FILE_MALFORMED` (file left untouched).
- A server the caller cannot see gives **404** (`NOT_FOUND`), not 403, so its existence isn't revealed (repo
  convention for out-of-scope objects).
- Status codes the contract left open: no trusted host key at `POST /ssh/sessions` → 422 `SSH_HOST_KEY_UNTRUSTED`;
  SSH auth failure → error frame `SSH_AUTH_FAILED` + close 4403; connect failure → `SSH_CONNECT_FAILED` + 4500;
  scan failure → 502; Center shutdown → 1001; grant expiry → 4408; any query string on the upgrade → 400.
- Step-up for production sessions uses the existing step-up token (5-minute lifetime), stricter than "10 minutes".
- An approved production grant with no session 30 minutes after approval becomes `expired`.
- Credentials are global objects: create/import/rotate/revoke need a **global** `credentials.manage` binding;
  deploy/remove/endpoints/host keys are checked against the server's scope.
- Session registry is in-process: terminate/revoke reach live sessions on the same Center process (single Center,
  as elsewhere).
- Lab endpoint for `lab-node-s`: `{ path: 'public', host: '127.0.0.1', port: 52222 }` (port-forwarded sshd).
- The shipped systemd unit keeps `ProtectHome=read-only`; operators add a `ReadWritePaths=/home/<user>/.ssh`
  drop-in for each managed SSH user (see the guide).
