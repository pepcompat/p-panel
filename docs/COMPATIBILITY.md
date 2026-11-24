# pPanel — Version compatibility (P8.04)

Which Center and agent versions work together, how the Center enforces it, and which upgrade paths are
supported. Policy source: `docs/RELEASE_CONTRACT.md` §1–§2. Procedures: `docs/UPGRADE_RUNBOOK.md`.

## 1. Versions and protocol

- **One product version** for Center API, web UI and agent: SemVer `MAJOR.MINOR.PATCH[-rc.N]` (root
  `VERSION`). Precedence follows SemVer 2.0: `0.8.0-rc.1 < 0.8.0 < 0.8.1 < 0.9.0`.
- **Agent protocol major** (`X-Agent-Protocol` header on every agent request, `agentProtocol` in
  `GET /api/v1/version`) is **`1`** for every release so far. It changes only for a wire-incompatible
  change of the agent ↔ Center protocol (`docs/AGENT_PROTOCOL.md`). An agent speaking a major the
  Center does not know is refused with **426 `AGENT_PROTOCOL_UNSUPPORTED`** (enrollment and gateway).
- The Center publishes its policy without authentication:

  ```bash
  curl -fsS https://<center>/api/v1/version
  # {"success":true,…,"data":{"version":"0.8.0-rc.1","commit":"…","buildDate":"…","agentProtocol":"1",
  #   "minAgentVersion":"0.7.0","schemaVersion":"20261128100000_p7_resilience"}}
  ```

  Centers before 0.8.0 have no `/version` (404); `upgrade.sh`/`rollback.sh` then use `/api/v1/health` and
  `.env`.

## 2. `minAgentVersion` and `AGENT_OUTDATED`

- Default: **N-1 minor** of the Center version, `<major>.<minor-1>.0` (`<major>.0.0` for a `.0` minor).
  Center `0.8.0-rc.1` → `0.7.0`; `0.9.x` → `0.8.0`; `1.0.0` → `1.0.0` (a major bump does not carry the
  previous major's agents). Development/test builds default to `0.0.0` (nothing enforced).
- Override: **`PPANEL_MIN_AGENT_VERSION`** in `/opt/ppanel/.env` (SemVer; empty = default), then
  `docker compose up -d --wait api proxy`. Raise it to force a fleet upgrade before a deadline; lowering it
  below N-1 is unsupported (older agents may lack job types the Center sends).
- An agent whose reported `agentVersion` (heartbeat) is lower than `minAgentVersion`:
  - is shown with **`agentOutdated: true`** in server facts (`GET /servers`, `/servers/{id}`; UI badge);
  - **keeps running** its workloads, heartbeats, telemetry and logs — nothing is stopped;
  - gets **read-only jobs** (inventory, discovery scans, nginx file reads, …) as usual;
  - is refused **new mutating jobs** (`service.restart`, `nginx.validate|apply|revert`, container/compose
    operations, builds, `backup.run`, `restore.run`, …) with **409 `AGENT_OUTDATED`**
    (`details: { agentVersion, minAgentVersion, jobType }`) — whether they come from the API, a schedule
    (backup policy), a webhook or an approval. Jobs already queued before it became outdated are not
    cancelled.
- Agents that never reported a version, or report a non-SemVer one (ad-hoc dev builds), are **not**
  flagged — the Center cannot judge them.

## 3. Mixed-version matrix (Center × agent)

✓ = supported, tested · ✓\* = supported (same protocol major), not a target state · ⚠ = runs but
`outdated` (no mutating jobs) · ✗ = refused (426).

| Center ↓ / agent → | 0.7.0       | 0.8.0-rc.1  | 0.9.x (future, protocol 1) | any, protocol ≠ 1 |
| ------------------ | ----------- | ----------- | -------------------------- | ----------------- |
| **0.7.0**          | ✓           | ✓\* (T02)   | ✓\*                        | ✗ 426             |
| **0.8.0-rc.1**     | ✓ (T02) N-1 | ✓ (T01/T02) | ✓\*                        | ✗ 426             |
| **0.9.x** (future) | ⚠ outdated  | ✓ N-1       | ✓                          | ✗ 426             |

- **Agent newer than the Center** (e.g. agent 0.8.0-rc.1 after the Center was rolled back to 0.7.0) is
  accepted as long as the protocol major is known; new agent features are simply not used. P8-T02 verified
  this right after `rollback.sh`.
- **Agent N-1** (0.7.0 on a 0.8.0-rc.1 Center): fully functional, including mutating jobs (P8-T02:
  `backup.run` accepted and executed). Upgrade it before the next Center release, where it becomes
  outdated.
- **Agent N-2 or older**: outdated (⚠). Upgrade with `install-agent.sh --version <center version>` —
  no re-enrollment needed.
- Web UI and API are one release (same image version, same origin); they are never mixed.

## 4. Supported upgrade paths

| From → to                                     | Supported         | Notes                                                                                            |
| --------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------ |
| `x.y.z → x.y.z+1` (patch)                     | yes               | agents optional                                                                                  |
| `x.y.z-rc.N → x.y.z-rc.M` (M > N) / `→ x.y.z` | yes               | release candidates of the same minor                                                             |
| `x.y.* → x.(y+1).*` (next minor)              | yes               | Center first, then agents (`UPGRADE_RUNBOOK.md`); agents x.y stay N-1                            |
| `0.7.0 → 0.8.0-rc.1`                          | yes               | P8-T02 (lab substitute); no migrations in 0.8.0-rc.1                                             |
| skipping a minor (`x.y → x.(y+2)`)            | no                | upgrade through each minor; agents of x.y would be outdated and expand/contract steps skipped    |
| major (`0.x → 1.0`)                           | per release notes | announced ≥ 6 months ahead (§5), with its own runbook                                            |
| any downgrade                                 | no                | `upgrade.sh` refuses; use `rollback.sh <pre-upgrade dump> <previous>` within the rollback window |

## 5. Deprecation policy (team standard: ≥ 6 months)

- **HTTP API**: every route is under `/api/v1`. A breaking change ships as `/api/v2` next to `/api/v1`;
  the old version stays available for **at least 6 months** after the new one is released, with the
  change recorded in `docs/API_CONTRACTS.md` and the release notes. Additive changes (new fields, new
  routes, new enum values that clients must tolerate) stay in `v1`.
- **Agent protocol**: a new protocol major is announced in the release notes **≥ 6 months** before
  agents of the old major are refused. During that period the Center accepts both majors, and
  `minAgentVersion` is not raised past the last release that speaks the old major.
- **Environment keys / install layout**: renamed or removed `.env` keys keep working (read as aliases)
  for ≥ 6 months; `upgrade.sh` appends new keys from `env.template` with their defaults and never deletes
  or rewrites existing values.
- **Database**: expand/contract (`docs/MIGRATION_RUNBOOK.md` §2) — nothing the previous release reads is
  dropped or renamed in the same release.
- Deprecations are listed in `docs/RELEASE_NOTES.md` with the earliest removal date.
