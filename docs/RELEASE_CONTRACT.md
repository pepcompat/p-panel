# P8 release contract

Shared contract for P8 (release, install, upgrade, docs). Every P8 workstream codes against this file;
changes go through the lead.

## 1. Versioning

- One version for the whole product: SemVer `MAJOR.MINOR.PATCH[-rc.N]`, single source of truth = root
  `VERSION` file (no `v`). `package.json` versions, `apps/agent/VERSION` and image tags follow it
  (`scripts/release/set-version.sh <ver>` updates all of them).
- Git tag `v<version>` triggers `.github/workflows/release.yml`.
- This phase ships **`0.8.0-rc.1`**. The upgrade test's "previous version" is **`0.7.0`** = commit
  `aa92403` (P7, CI green) built with the P8 Dockerfiles (no earlier release had an installer).
- Agent protocol major stays `1` (`X-Agent-Protocol`). Center reports `GET /api/v1/version` (public, no auth):
  `{ version, commit, buildDate, agentProtocol: "1", minAgentVersion, schemaVersion }` where `schemaVersion`
  = name of the latest applied Prisma migration.

## 2. Mixed-version policy

- Center N supports agents N and N-1 minor (same protocol major). Agents newer than the Center are refused
  only if their protocol major is unknown (existing 426 `AGENT_PROTOCOL_UNSUPPORTED`).
- Agents older than `minAgentVersion` keep running workloads but the Center marks them `outdated` in
  server facts (`agentVersion` already reported in heartbeat) and refuses new mutating jobs with 409
  `AGENT_OUTDATED`; read-only jobs still run.
- Upgrade order is always **Center first, then agents**. Rollback order is the reverse.
- Migrations must be expand/contract: a release's migrations never break the previous release's Center
  code running against the new schema during a rollback window (no drop/rename of columns the previous
  release reads, in the same release). Each migration ships `ROLLBACK.md` (existing convention).

## 3. Release artifacts (`release.yml`, also buildable locally with `scripts/release/build.sh`)

| Artifact         | Name                                                                                                                                                                                                                                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Center API image | `ghcr.io/pepcompat/ppanel-api:<version>` (linux/amd64 + linux/arm64)                                                                                                                                                                          |
| Web image        | `ghcr.io/pepcompat/ppanel-web:<version>`                                                                                                                                                                                                      |
| Agent binaries   | `ppanel-agent-linux-amd64`, `ppanel-agent-linux-arm64`                                                                                                                                                                                        |
| Checksums        | `SHA256SUMS` (agent binaries + `ppanel-center-<version>.tar.gz` + `install-agent.sh`)                                                                                                                                                         |
| Signature        | `SHA256SUMS.sig` — ed25519 over `SHA256SUMS`, verified with `openssl pkeyutl -verify -rawin`; public key `ppanel-release.pub` (PEM). Produced only when secret `PPANEL_RELEASE_SIGNING_KEY` exists; otherwise the release is marked unsigned. |
| Center bundle    | `ppanel-center-<version>.tar.gz` = `infra/release/` (compose, env template, install/upgrade/rollback/backup scripts)                                                                                                                          |

Local builds use image names `ppanel-api:<version>` / `ppanel-web:<version>` (no registry) and
`PPANEL_IMAGE_PREFIX` selects the registry in compose.

## 4. Center install layout (`infra/release/`)

- `compose.yml`: services `postgres` (16, volume `pgdata`), `api` (runs `prisma migrate deploy` then the
  API; healthcheck `/api/v1/health`), `web`, `proxy` (Caddy, pinned digest; TLS for web+API on 443, optional
  internal CA mode for lab) — gateway :4443 is **published directly** (mTLS, never through the proxy).
  Optional profile `observability` (Prometheus + Loki, pinned). Images pinned by tag **and** digest in
  `.env` (`PPANEL_VERSION`, `PPANEL_API_IMAGE`, `PPANEL_WEB_IMAGE`). Redis is not used by the API (P7) and is
  not shipped.
- Default install root `/opt/ppanel`; data under named volumes; `/opt/ppanel/.env` mode 0600 root.
- `install.sh` (idempotent, `set -euo pipefail`, no curl|bash requirement): checks prerequisites (Docker
  Engine ≥ 24 + compose v2, ports 443/4443 free, ≥ 2 GB RAM), generates secrets with `openssl rand`
  (`PPANEL_MASTER_KEY`, `JWT_ACCESS_SECRET`, `POSTGRES_PASSWORD`, `PPANEL_SETUP_TOKEN`), writes `.env` from
  `env.template`, prints where the master key must be escrowed (separate from DB backups), starts the stack,
  waits for health, prints the first-boot URL + setup token once.
- `upgrade.sh <version>`: pre-flight (`/api/v1/version`), DB backup via `pg_dump` to
  `/opt/ppanel/backups/pre-upgrade-<from>-<to>-<ts>.sql.gz`, pull/load new images, `migrate deploy`, start,
  health + version check; on failure prints the rollback command.
- `rollback.sh <backup-file> <previous-version>`: stop api/web, restore DB from the pre-upgrade dump, pin
  previous images, start, verify version + health.
- `backup-center.sh` reuses the P6.06 Center backup (`scripts/backup/center-*.sh`) where possible.

## 5. Agent install (`infra/release/install-agent.sh`, also published standalone)

- `install-agent.sh --center-url <https://…> --token <enrollment token> [--version <v>] [--from-dir <dir>]
[--pubkey <file>]`. Downloads binary + `SHA256SUMS` (+ `.sig`) from the release (or `--from-dir` for
  offline/lab), verifies checksum (mandatory) and signature (mandatory when a pubkey is given or embedded),
  installs to `/usr/local/bin/ppanel-agent`, creates state dir `/var/lib/ppanel-agent` (0700), config
  `/etc/ppanel-agent/`, runs `ppanel-agent enroll`, installs and starts `ppanel-agent.service`.
- systemd unit `infra/release/systemd/ppanel-agent.service`: `Restart=always`, `NoNewPrivileges=yes`,
  `ProtectSystem=strict` with explicit `ReadWritePaths=` (state dir, `/etc/nginx`, nginx run/log dirs,
  backup staging), `ProtectHome=read-only`, `PrivateTmp=yes`, `RestrictSUIDSGID=yes`,
  `LockPersonality=yes`, `SystemCallArchitectures=native`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
AF_NETLINK`. The agent runs as root (it must reload nginx and talk to the Docker socket); every
  privilege it needs is listed in `docs/INSTALL.md` §least privileges, with what each one is used for.
- `--uninstall` stops/disables the unit and removes the binary; state dir only with `--purge`.

## 6. Lab substitute for a fresh Ubuntu VM

No VMs are available. `infra/lab/ubuntu/` builds an **Ubuntu 24.04 image with systemd as PID 1** and Docker
Engine inside (privileged, lab only, profile `ubuntu`), plus two Ubuntu systemd "nodes" for agent installs.
Results from it are reported as **PASS (lab substitute)**; P8-T01 on a real VM stays BLOCKED until one is
provided. Never touch amas-* containers; never fill the host disk.

## 7. Ownership (P8 workstreams)

| Workstream                                      | Owns                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A — installer & packaging (P8.01/02, P8-T01)    | `infra/release/**`, `infra/lab/ubuntu/**`, `apps/api/Dockerfile`, `apps/web/Dockerfile`, `.dockerignore`, `scripts/release/**`, `scripts/lab/e2e_p8_install.py`, root `VERSION`, `.github/workflows/release.yml`, `docs/INSTALL.md`, `GET /api/v1/version` + `AGENT_OUTDATED` in apps/api |
| B — CI & journeys (P8.03, P8-T03)               | `.github/workflows/ci.yml`, `apps/web/tests/e2e/journeys/**`, `apps/web/playwright*.config.ts`, `scripts/lab/journeys*`, `docs/ACCEPTANCE.md`                                                                                                                                             |
| C — upgrade & rollback (P8.04, P8-T02), after A | `infra/release/upgrade.sh`, `rollback.sh`, `scripts/lab/e2e_p8_upgrade.py`, `docs/UPGRADE_RUNBOOK.md`, `docs/MIGRATION_RUNBOOK.md`, `docs/COMPATIBILITY.md`                                                                                                                               |
| Lead — docs (P8.05/06)                          | `docs/guides/**`, `docs/RELEASE_NOTES.md`, `docs/KNOWN_LIMITATIONS.md`, status/test reports                                                                                                                                                                                               |
