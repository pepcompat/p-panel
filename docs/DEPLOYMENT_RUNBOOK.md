# pPanel — Deployment runbook

Status: **Dev setup = documented (P0)**. **Production install = TODO (P8.01–P8.02).**
Every command here targets localhost or disposable lab containers only.

## 1. Dev setup from a clean checkout (macOS arm64 / Linux)

Prerequisites: Node ≥22, pnpm 10.33.0 (`corepack enable`), Go 1.25, Docker + Compose v2. See `BASELINE.md`.

```bash
# 1. dependencies
pnpm install --frozen-lockfile

# 2. local Postgres (127.0.0.1:55432) + Redis (127.0.0.1:56379), project ppanel-dev
docker compose -p ppanel-dev -f infra/compose/dev.yml up -d --wait

# 3. environment (never commit .env; values below are generated locally)
cp .env.example apps/api/.env
#   fill in apps/api/.env:
#     PPANEL_MASTER_KEY=$(openssl rand -base64 32)
#     JWT_ACCESS_SECRET=$(openssl rand -base64 48)
#     PPANEL_SETUP_TOKEN=$(openssl rand -hex 24)
cp apps/web/.env.example apps/web/.env.local   # NEXT_PUBLIC_API_BASE=http://localhost:4000/api/v1

# 4. database schema + dev seed (seed users dev/superadmin/admin/user1, password `password` — DEV ONLY)
pnpm --filter ./apps/api prisma:migrate
pnpm --filter ./apps/api seed

# 5. run Center API (:4000, agent gateway :4443) and web (:3100) — separate terminals
pnpm --filter ./apps/api dev
pnpm --filter ./apps/web dev

# 6. checks
pnpm lint && pnpm typecheck && pnpm test
(cd apps/agent && go vet ./... && go test ./... -race)
```

Health: `curl -s http://localhost:4000/api/v1/setup/status` → envelope with `data.bootstrapped`.

## 2. Agent in the lab

```bash
# build the linux/arm64 agent for the lab nodes (output dir is mounted read-only at /opt/ppanel-agent)
(cd apps/agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/ppanel-agent-linux-arm64 ./cmd/ppanel-agent)

scripts/lab/up.sh          # 2 nodes + upstreams, no published ports
scripts/lab/status.sh
scripts/lab/smoke.sh

# create an enrollment token via UI (Servers → Enroll) or POST /api/v1/enrollments, then inside a node:
docker exec -it ppanel-lab-node-a /opt/ppanel-agent/ppanel-agent-linux-arm64 --help
#   enroll against http://host.docker.internal:4000 (requires PPANEL_DEV_INSECURE_ENROLL=1 on the API)
#   gateway https://host.docker.internal:4443 (PPANEL_GATEWAY_HOSTNAMES must include host.docker.internal)
#   exact flags: see apps/agent README (owned by the agent team)

scripts/lab/checksum-nginx.sh --out .lab/evidence/before.txt   # P3-T01 baseline
scripts/lab/down.sh
```

## 3. Stopping / cleaning

```bash
scripts/lab/down.sh                                   # ppanel-lab only
docker compose -p ppanel-dev -f infra/compose/dev.yml down   # keeps the pgdata volume
# add -v ONLY if you intend to wipe local dev data; never prune globally (unrelated amas-* containers live here)
```

## 4. Production install — TODO (P8)

- [ ] P8.01 Versioned Center installer (`docker compose`, pinned images) and Agent installer
      (signed checksummed binaries, systemd unit, enrollment).
- [ ] P8.02 Secrets bootstrap (`PPANEL_MASTER_KEY` escrow separate from DB backup), TLS reverse proxy in
      front of :3100/:4000, :4443 reachable only from managed hosts (prefer private path), firewall prerequisites.
- [ ] P8.04 Upgrade + rollback procedure → `UPGRADE_RUNBOOK.md`, `MIGRATION_RUNBOOK.md`.
- [ ] P6.06 Center DB + config + key recovery → `RECOVERY_RUNBOOK.md`.

Until P8 passes on a fresh Ubuntu VM (P8-T01), **do not install pPanel on any production host.**
