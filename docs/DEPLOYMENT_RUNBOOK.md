# pPanel — Deployment runbook

Status: **Dev setup = documented (P0)**. **Production install = `docs/INSTALL.md` (P8.01–P8.02).**
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

## 4. Production install

See **`docs/INSTALL.md`** (P8.01/P8.02): prerequisites, network/firewall, secrets bootstrap and master-key
escrow, Center install (`infra/release/install.sh`), agent install (`install-agent.sh`), least privileges,
uninstall. Upgrades/rollbacks: `docs/UPGRADE_RUNBOOK.md`. Center recovery: `docs/RECOVERY_RUNBOOK.md`.
Release artifacts are built by `.github/workflows/release.yml` or locally with `scripts/release/build.sh`.

The installer passed P8-T01 only on the lab substitute (`infra/lab/ubuntu`); re-run it on a real VM before
installing pPanel on a production host.

## Behind a reverse proxy (production)

- Set `TRUST_PROXY=1` on the Center API when it runs behind a reverse proxy or load balancer that sets `X-Forwarded-For`. Without it, every request appears to come from the proxy's IP, so the per-IP login limit (30/min, SEC-P7-07) would throttle **all** users at once, and audit rows would record the proxy instead of the client.
- Only trust the proxy you control. Never set `TRUST_PROXY=1` when clients can reach the API directly, because they could then spoof `X-Forwarded-For`.
- The rate limiter is in memory (one Center process). Running several API replicas needs a shared limiter (Redis), which is not implemented in v1.
- Terminate TLS at the proxy for web/API (HSTS is sent in production). The **agent gateway (:4443) must be passed through as TCP (TLS passthrough)** and not terminated at the proxy, because it authenticates agents with mutual TLS.
