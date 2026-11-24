# pPanel — Production install (P8.01 / P8.02)

This guide installs one pPanel **Center** (web UI, API, agent gateway, PostgreSQL) with Docker Compose and
the **agent** on each managed Linux host with systemd. Release layout and policies: `docs/RELEASE_CONTRACT.md`.
Upgrades and rollbacks: `docs/UPGRADE_RUNBOOK.md`. Center disaster recovery: `docs/RECOVERY_RUNBOOK.md`.

> **Validation status.** The installer was tested end to end on Ubuntu 24.04 **systemd containers**
> (`infra/lab/ubuntu`, evidence `docs/evidence/2026-11-24/p8-t01-install.json`): **PASS (lab substitute)**.
> P8-T01 on a real VM is **BLOCKED** until one is available. See §11.

## 1. What gets installed

| Where             | What                                                                                                                                                                                         |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Center host       | `/opt/ppanel/` (compose.yml, Caddyfile, `.env`, scripts, `secrets/`, `backups/`), Docker volumes `ppanel_pgdata`, `ppanel_caddy_data`, `ppanel_caddy_config` (+ `promdata`, `lokidata`)      |
| Center containers | `postgres` (16), `api` (`ppanel-api:<v>`, runs `prisma migrate deploy` then the API, mTLS gateway :4443), `web` (`ppanel-web:<v>`), `proxy` (Caddy, TLS :443); optional `prometheus`, `loki` |
| Each managed host | `/usr/local/bin/ppanel-agent`, `/etc/ppanel-agent/` (config, Center CA), `/var/lib/ppanel-agent/` (0700: key, certificate, job cache, log buffer), `ppanel-agent.service`                    |

Release artifacts (GitHub release `v<version>`): `ppanel-center-<version>.tar.gz`, `install-agent.sh`,
`ppanel-agent-linux-{amd64,arm64}`, `SHA256SUMS`, and when signed `SHA256SUMS.sig` + `ppanel-release.pub`.
Images: `ghcr.io/pepcompat/ppanel-api:<version>`, `ghcr.io/pepcompat/ppanel-web:<version>` (amd64 + arm64).

## 2. Prerequisites

**Center host**

- Linux x86_64 or arm64 (Ubuntu 22.04/24.04 tested in the lab), **2 GB RAM minimum** (4 GB recommended),
  2 vCPU, 20 GB free disk for images, database and logs.
- **Docker Engine ≥ 24** and the **Compose v2 plugin ≥ 2.20** (`docker compose version`). Ubuntu:
  `apt install docker.io docker-compose-v2`, or Docker's own repository.
- `openssl`, `curl`, `awk`, `sed` (present on Ubuntu). Root (sudo).
- A DNS name for the UI/API (for example `panel.example.com`). For public ACME certificates it must resolve
  to the host and ports 80/443 must be reachable from the internet. Otherwise use `--tls internal`.
- Ports **443** (and 80 for ACME/redirect) and **4443** free. `install.sh` checks all of this.

**Managed host (agent)**

- Linux amd64/arm64 with **systemd**, `curl`, `sha256sum`, **OpenSSL 3** (`openssl pkeyutl -rawin`, for the
  release signature), outbound HTTPS to the Center (443) and to the gateway (4443).
- nginx and/or Docker Engine only if you want pPanel to manage them.

## 3. Network and firewall

| Port         | Direction                  | Who                                                        | Notes                                                                                                                       |
| ------------ | -------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| 443/tcp+udp  | inbound to Center          | operators' browsers, API clients, agents (enrollment only) | Caddy terminates TLS; `/api/*` → API, everything else → web. `/internal/*` is never proxied.                                |
| 80/tcp       | inbound to Center          | ACME HTTP-01, redirect to 443                              | close it with `--tls internal` if not needed                                                                                |
| **4443/tcp** | inbound to Center          | **managed hosts only**                                     | agent gateway, **mutual TLS end to end** (never through a proxy or load balancer that terminates TLS; TCP passthrough only) |
| 55432/tcp    | Center loopback only       | `backup-center.sh`, `upgrade.sh`                           | PostgreSQL is published on `127.0.0.1` only                                                                                 |
| outbound     | agents → Center 443 + 4443 | —                                                          | agents open **no** listening port                                                                                           |

- Prefer a **private network** for 4443 (VPC / WireGuard): install with `--gateway-host <private name>` and
  `--gateway-bind <private IP>` so the gateway is not published on the public interface at all.
- Otherwise restrict it in the firewall. Docker publishes ports through its own iptables chains, so use the
  `DOCKER-USER` chain (ufw rules alone do not apply to published container ports):

```bash
# allow 4443 only from the managed hosts' network, drop the rest
iptables -I DOCKER-USER -p tcp --dport 4443 ! -s 10.20.0.0/16 -j DROP
# persist with iptables-persistent / your config management
```

- The API trusts `X-Forwarded-For` from the bundled proxy only (`TRUST_PROXY=1`; the API port 4000 is not
  published). Do not publish 4000 or put another proxy in front without adjusting this.

## 4. Secrets bootstrap and master-key escrow

`install.sh` generates every secret with `openssl rand` on first install and writes them to
`/opt/ppanel/.env` (mode **0600**, root). They are never printed, except the one-time setup token.

| Secret                        | Purpose                                                                                                         | If lost                                                                            |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `PPANEL_MASTER_KEY`           | AES-256-GCM key for the agent CA private key, TOTP secrets, app secrets, backup repo passwords, channel secrets | **every encrypted value in the DB and in DB backups is unrecoverable** — escrow it |
| `JWT_ACCESS_SECRET`           | signs access tokens                                                                                             | regenerate; everyone is logged out                                                 |
| `POSTGRES_PASSWORD`           | DB password (URL-safe hex)                                                                                      | reset in PostgreSQL + `.env`                                                       |
| `PPANEL_SETUP_TOKEN`          | first-boot owner creation (ignored once an owner exists)                                                        | irrelevant after first boot                                                        |
| `PPANEL_METRICS_SCRAPE_TOKEN` | Prometheus → `/internal/metrics` (also `secrets/scrape-token`, uid 65534, 0400)                                 | regenerate both                                                                    |

**Escrow the master key right after installing** (and `PPANEL_CENTER_BACKUP_PASSWORD` once you configure
Center backups), **separately from database backups** — a DB dump plus the key is a full compromise, a DB dump
alone is not:

```bash
sudo grep '^PPANEL_MASTER_KEY=' /opt/ppanel/.env | age -r <operator-age-pubkey> > ppanel-escrow.age
# store ppanel-escrow.age off the Center host (or print + seal in two places); never in a ticket, the repo,
# the backup host or a restic repository
```

Details and the recovery procedure: `docs/RECOVERY_RUNBOOK.md` §2. `install.sh` never overwrites an existing
secret; changing the master key is a manual re-encryption task (out of scope for v1).

## 5. Install the Center

```bash
VERSION=0.8.0-rc.1
BASE=https://github.com/pepcompat/ppanel/releases/download/v$VERSION
curl -fsSLO $BASE/ppanel-center-$VERSION.tar.gz -O $BASE/SHA256SUMS -O $BASE/SHA256SUMS.sig -O $BASE/ppanel-release.pub
sha256sum -c --ignore-missing SHA256SUMS                       # mandatory
# signed releases: compare ppanel-release.pub with the key published in the repository / release notes
openssl pkeyutl -verify -pubin -inkey ppanel-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
tar xzf ppanel-center-$VERSION.tar.gz && cd ppanel-center-$VERSION

sudo ./install.sh --domain panel.example.com --tls ops@example.com \
     --gateway-host panel-gw.internal.example.com --gateway-bind 10.20.0.5
```

What it does (idempotent, `set -euo pipefail`, no `curl | bash`):

1. checks root, Docker ≥ 24, Compose ≥ 2.20, RAM ≥ 2 GB, ports 443/4443 free (ignores ports held by an
   already running pPanel stack);
2. copies the bundle to `/opt/ppanel`, writes `.env` from `env.template`, generates missing secrets;
3. pulls `ghcr.io/pepcompat/ppanel-{api,web}:<version>` and **pins them by tag and digest** in `.env`
   (`PPANEL_API_IMAGE=…:<v>@sha256:…`), records the image IDs and verifies the running containers use them;
4. `docker compose up -d --wait` (the API runs `prisma migrate deploy` first), then checks
   `https://<domain>/api/v1/health` and `/api/v1/version` through the proxy;
5. prints the escrow reminder, the first-boot URL and the **one-time setup token** (first install only;
   afterwards it stays in `.env` as `PPANEL_SETUP_TOKEN` until the owner exists).

Options: `--tls internal` (Caddy's own CA, for private networks/labs; the root CA is exported to
`/opt/ppanel/secrets/caddy-root.crt`), `--images-dir DIR` (offline: `docker load` image tarballs first),
`--image-prefix ''` (locally built images `ppanel-api:<v>`), `--no-start`, `--dir`. Re-running `install.sh`
converges the stack and never changes the installed version (`upgrade.sh <version>` does that).

**First boot**: open `https://<domain>/setup`, enter the setup token, create the owner (platform owner role),
then immediately enable **TOTP 2FA** for the owner (Settings → Security). Create further users with least
privilege. The dev seed users (`dev`/`superadmin`/`admin`/`user1`) are **never** created by the installer.

Day-2: `cd /opt/ppanel && sudo docker compose ps | logs -f api`. Observability (Prometheus + Loki, pinned):
set `COMPOSE_PROFILES=observability` in `.env` and `sudo docker compose up -d`. Without it, metric series and
log search answer 503 `METRICS_BACKEND_UNAVAILABLE` / `LOGS_BACKEND_UNAVAILABLE`; fleet metrics from
heartbeats still work.

## 6. Certificates and the enrollment flow

- **Web/API TLS (443)**: Caddy, ACME (`--tls <email>`) or internal CA (`--tls internal`). HSTS is sent.
- **Agent PKI**: at first start the API creates an internal ECDSA P-256 CA (private key encrypted with the
  master key, stored in the DB). It issues the gateway server certificate (SAN = `PPANEL_GATEWAY_HOST`) and
  the agents' client certificates.
- **Enrollment** (`docs/AGENT_PROTOCOL.md`): an operator with `servers.enroll` creates a token in
  Servers → Enroll (`POST /api/v1/enrollments`, TTL 5–60 min, single use, only its sha256 is stored).
  The response has `installCommand` (the `install-agent.sh` one-liner below) and `enrollCommand` (binary
  already installed). On the host the agent generates its private key locally (0600, never leaves the host),
  sends a CSR over **HTTPS to 443** (`/api/v1/agent/enroll`, verified against the system roots or `--ca-file`)
  and receives its certificate (CN `agent:<serverId>`, 7-day validity), the agent CA and the gateway URL.
- From then on every call is **mutual TLS to :4443**. Certificates rotate automatically before expiry;
  revoking a server in the UI revokes its certificate immediately (401 `AGENT_CERT_REVOKED`).

## 7. Install / uninstall the agent

On each managed host, with a fresh enrollment token:

```bash
# the command shown by Servers → Enroll (installCommand):
curl -fsSLO https://github.com/pepcompat/ppanel/releases/download/v0.8.0-rc.1/install-agent.sh \
  && sudo bash install-agent.sh --center-url https://panel.example.com --token ppe_… --version 0.8.0-rc.1
# signed releases: add --pubkey ppanel-release.pub (published with the release) to make the signature mandatory
# Center installed with --tls internal: add --ca-file caddy-root.crt (copy of /opt/ppanel/secrets/caddy-root.crt)
```

`install-agent.sh` downloads `ppanel-agent-linux-<arch>` + `SHA256SUMS` (+ `.sig`), verifies the checksum
(**always**) and the ed25519 signature (**mandatory** when a public key is passed with `--pubkey` or embedded
in a signed release's `install-agent.sh`), installs `/usr/local/bin/ppanel-agent`, creates
`/var/lib/ppanel-agent` (0700) and `/etc/ppanel-agent` (0750, `config.yaml`), enrolls once (the token is passed
through the environment, never on the command line), installs `ppanel-agent.service` and starts it.
Re-running it is safe: an enrolled host is not re-enrolled (no token needed), the binary is replaced only after
verification. Offline/air-gapped: `--from-dir DIR` with the binary, `SHA256SUMS` and `SHA256SUMS.sig`.
Mirror: `--download-base https://…` (and `PPANEL_AGENT_DOWNLOAD_BASE` on the Center so `installCommand` uses it).

Uninstall: `sudo bash install-agent.sh --uninstall` (stops/disables the unit, removes unit + binary, keeps the
identity) or `--uninstall --purge` (also deletes `/var/lib/ppanel-agent` and `/etc/ppanel-agent`). Then
**revoke** the server in the Center so its certificate stops working.

Optional features are operator decisions in `/etc/ppanel-agent/config.yaml` (see
`apps/agent/packaging/config.example.yaml`): `ownedUnits`, `build.enabled`, `backup.enabled` + `helperImage`,
`logs.sources`. Restart the agent after changes.

## 8. Volumes, data and backups

| Data                             | Location                                           | Backup                                                                                                             |
| -------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Center DB                        | volume `ppanel_pgdata`                             | `sudo /opt/ppanel/backup-center.sh dump` (gzip SQL, 0600, `/opt/ppanel/backups/`) or `backup-center.sh restic init | backup` (P6.06 separate restic repo, RECOVERY_RUNBOOK §3) |
| Config + secrets                 | `/opt/ppanel/.env`                                 | secrets → offline escrow (§4); non-secret config is copied sanitized by the restic backup                          |
| Caddy certificates / internal CA | volumes `ppanel_caddy_data`, `ppanel_caddy_config` | re-issued automatically; back up `caddy_data` if you use `--tls internal` and agents pin its CA                    |
| Metrics / logs (optional)        | volumes `ppanel_promdata`, `ppanel_lokidata`       | not backed up (retention-bounded telemetry)                                                                        |
| Agent identity                   | `/var/lib/ppanel-agent` on each host               | not needed: re-enroll a lost host with a new token                                                                 |

Schedule `backup-center.sh` (systemd timer or cron, hourly). Never run `docker compose down -v` in
`/opt/ppanel`: it deletes the database volume.

## 9. Least privileges of the agent

The agent runs as **root** under a hardened unit (`infra/release/systemd/ppanel-agent.service`), because
reloading nginx, reading root-only nginx includes and talking to the Docker socket need it. Everything else is
taken away:

| Privilege / access                                                                        | Used for                                                                              | Without it                             |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | -------------------------------------- |
| root UID, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`                                       | `nginx -T`/`-t` on root-only config and TLS key paths; reading other users' log files | discovery and nginx jobs fail          |
| `CAP_CHOWN`, `CAP_FOWNER`                                                                 | `nginx -t` temp paths; restoring file ownership in backups/restores                   | restores lose ownership                |
| `CAP_SYS_PTRACE` (read-only use)                                                          | mapping listening sockets to processes (`/proc/<pid>/fd`) for port discovery          | ports discovery shows no process names |
| write `/etc/nginx`, `/var/log/nginx`, `/var/lib/nginx`, `/var/cache/nginx`, `/run/nginx*` | typed nginx jobs (candidate files, apply/revert, `nginx -t`)                          | nginx jobs fail                        |
| write `/var/lib/ppanel-agent` (+ optional `/var/backups/ppanel-agent`)                    | identity, job cache, log buffer, backup work dir, restore staging                     | agent cannot run                       |
| `/var/run/docker.sock` (**host-root equivalent**)                                         | container inventory (GET), typed container/compose/build/backup-helper jobs           | docker features unavailable            |
| D-Bus → systemd                                                                           | `service.restart` for units in `ownedUnits` only; nginx reload                        | restarts unavailable                   |
| outbound AF_INET/AF_INET6, AF_UNIX, AF_NETLINK                                            | Center (443/4443), docker.sock + D-Bus, interface addresses                           | —                                      |

Everything else is denied by the unit: `ProtectSystem=strict` (the rest of the filesystem is read-only),
`ProtectHome=read-only`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, `RestrictSUIDSGID`,
`LockPersonality`, `RestrictRealtime`, `RestrictNamespaces`, `SystemCallArchitectures=native`,
`SystemCallFilter=@system-service`, kernel tunables/modules/logs/clock/hostname protected, `MemoryMax=512M`,
`TasksMax=128`. It opens **no listening socket**. Check on a host:
`systemctl show ppanel-agent -p NoNewPrivileges,ProtectSystem,CapabilityBoundingSet,ReadWritePaths`.
Restores into paths outside the list need a drop-in (`systemctl edit ppanel-agent` → `ReadWritePaths=/srv/app/data`).
If a host does not use a feature, drop the matching capability in a drop-in. The agent never creates privileged
containers (`Privileged=false`, `CapDrop=ALL`, `no-new-privileges`).

## 10. Uninstall the Center

```bash
cd /opt/ppanel
sudo ./backup-center.sh dump /root/ppanel-final.sql.gz     # keep a last dump (+ the escrowed master key)
sudo docker compose down                                   # stops and removes containers, KEEPS volumes
# permanent removal of all data (irreversible):
sudo docker compose down -v && sudo rm -rf /opt/ppanel
```

Uninstall the agents first (§7) or revoke the servers; agents of a removed Center keep retrying with backoff.

## 11. Lab substitute (P8-T01)

The installer is validated by `scripts/lab/e2e_p8_install.py` on `infra/lab/ubuntu` (Ubuntu 24.04 containers
with systemd as PID 1; the center runs its own Docker Engine; privileged, lab only). It builds the release
locally (`scripts/release/build.sh --save-images --sign-key <throw-away key>`), verifies checksums and the
signature, copies the bundle and `docker save` images into the center, runs `install.sh --tls internal`,
completes first boot with 2FA, installs both agents with `install-agent.sh --from-dir --pubkey --ca-file`,
runs a smoke suite, checks the systemd hardening and a `systemctl restart`, re-runs both installers
(idempotency) and uninstalls one agent. Differences from a VM: shared kernel, no public DNS/ACME, no real
firewall (see `infra/lab/ubuntu/README.md`). **Run P8-T01 again on a real VM before any production use.**
