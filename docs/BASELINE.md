# pPanel — Baseline (P0.01)

Recorded: **2026-11-17** · Product: **pPanel** (formerly "W3 Server Panel") · Repo: `/Volumes/DevStorages/ppanel`

## 1. Repository at start

- Git repository initialised on branch `main` with **no commits** (`git log` → "does not have any commits yet").
- Only pre-existing inputs: `design/W3_SERVER_PANEL_CLAUDE_CODE_V3.md` (master brief),
  `design/W3_SERVER_PANEL_CLAUDE_DESIGN_V3.md` (design brief), `design/W3 Server Panel.dc.html` (+ `support.js`) design prototype.
- No application code, CI, infrastructure or secrets existed. Everything else is bootstrapped in P0
  (monorepo, `packages/shared-contracts`, `infra/compose/dev.yml`, lab, docs, CI).

## 2. Development host

| Item           | Value (command)                                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------------------------------- |
| OS             | macOS 27.2.1 (build 26B131), Darwin 27.2.0, **arm64** (`sw_vers`, `uname -a`)                                    |
| Node.js        | v24.11.0 (`node -v`) — repo `engines.node >=22`; CI uses Node 22                                                 |
| pnpm           | 10.33.0 (`pnpm -v`), pinned via `packageManager`                                                                 |
| Go             | go1.25.6 darwin/arm64 (`go version`)                                                                             |
| Docker         | client 29.7.2 / server 29.7.2 linux/arm64 (`docker version --format …`) — Docker Desktop, LinuxKit kernel 7.0.12 |
| Docker Compose | v5.5.1 (`docker compose version`)                                                                                |

## 3. pPanel-owned local resources

| Resource                                       | Binding            | Notes                                             |
| ---------------------------------------------- | ------------------ | ------------------------------------------------- |
| `ppanel-dev-postgres-1` (postgres:16.6-alpine) | `127.0.0.1:55432`  | project `ppanel-dev`, `infra/compose/dev.yml`     |
| `ppanel-dev-redis-1` (redis:7.4.1-alpine)      | `127.0.0.1:56379`  | project `ppanel-dev`                              |
| Center API (NestJS)                            | `:4000`            | `apps/api`                                        |
| Agent mTLS gateway                             | `:4443`            | inside API process                                |
| Web (Next.js)                                  | `:3100`            | `apps/web`                                        |
| Lab (`ppanel-lab`)                             | no published ports | `infra/compose/lab.yml`, network `ppanel-lab-net` |

## 4. Unrelated containers on this host — NOT OURS, NEVER TOUCH

Observed with `docker ps` on 2026-11-17. pPanel scripts must never stop, remove, inspect-modify,
prune, or connect networks to these. Port choices above avoid all of them.

| Container          | Image                   | Published ports                        |
| ------------------ | ----------------------- | -------------------------------------- |
| amas-backend-dev   | node:22-alpine          | 0.0.0.0:9101→3000                      |
| amas-frontend-dev  | node:22-alpine          | 0.0.0.0:9100→3000                      |
| amas-pgbouncer-dev | edoburu/pgbouncer       | 0.0.0.0:6446→6436                      |
| amas-redis-dev     | redis:7.4.0-alpine      | 0.0.0.0:6391→6379                      |
| amas-rabbitmq-dev  | rabbitmq:3-management   | 0.0.0.0:5683→5672, 0.0.0.0:15683→15672 |
| amas-postgres-dev  | imresamu/postgis:17-3.5 | 0.0.0.0:5447→5432                      |
| amas-mongo-dev     | mongo:6.0.10            | 0.0.0.0:27030→27017                    |

Rules: no `docker system prune`, no `docker volume prune`, no `docker network prune`, no
`docker compose down` without `-p ppanel-dev` / `-p ppanel-lab`. Lab `down.sh` is project-scoped.

## 5. No-touch rules (until explicit, scoped, per-operation authorization)

- **No production hosts**: no SSH, agent install, nginx reload, package install, reboot on any real Droplet.
- **No DNS** record changes, no domain registrar access.
- **No DigitalOcean** Cloud Firewall, VPC, route, Droplet, volume, snapshot, or billing changes;
  DO API use is **read-only** and only if the user supplies read-only credentials (not supplied → P9-01 BLOCKED).
- **No host networking** changes: netplan, routes, public IPs, `sshd_config`, host firewall (UFW/nftables).
- **No money**: no paid services, no cloud resources.
- No restore over real data, no volume deletion outside `ppanel-lab`/`ppanel-dev` projects.
- All privileged/network-changing tests run in the disposable lab (`ppanel-lab`) or are marked BLOCKED.

## 6. Deployment constraints known at baseline

- Targets: DigitalOcean Droplets, Ubuntu 22.04/24.04, same region, private IPs pingable between them
  (user statement). **Shared VPC UUID is unverified** (ping ≠ same VPC) — see `NETWORK_TOPOLOGY.md`.
- Existing Nginx on targets is the source of truth (ADR-0004). Center must not become a runtime
  dependency for existing workloads.
- Real test VMs and DO read-only credentials: **not available** at baseline → live E2E BLOCKED.
