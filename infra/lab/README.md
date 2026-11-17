# pPanel lab (P0.04)

Disposable **container approximations** of two Ubuntu 24.04 managed hosts, for discovery,
agent and read-only-import tests. Compose project name is fixed to **`ppanel-lab`**.

| Container               | Role                           | Contents                                                                                           |
| ----------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------- |
| `ppanel-lab-node-a`     | legacy native host             | Ubuntu 24.04 (pinned digest), nginx 1.24, php8.3-fpm, fixtures 00–08                               |
| `ppanel-lab-node-b`     | container-style host           | Ubuntu 24.04, nginx 1.24, proxy to a compose-like app, `/opt/apps/shop/docker-compose.yml` fixture |
| `ppanel-lab-upstream-a` | upstream for `api.example.lab` | busybox httpd :8080 (read-only rootfs)                                                             |
| `ppanel-lab-upstream-b` | the "shop" compose app         | busybox httpd :8080 (read-only rootfs)                                                             |

Network `ppanel-lab-net` (bridge). **No ports are published** on any host interface; probes run
inside the nodes with `docker exec … curl -H 'Host: …' http://127.0.0.1/`.
Each node has `extra_hosts: host.docker.internal:host-gateway` so an in-container agent can
reach the Center on the Mac (`https://host.docker.internal:4443`, API `:4000`).

## Commands

```bash
scripts/lab/up.sh              # compose config --quiet, build, up -d --wait
scripts/lab/status.sh          # containers, OS/nginx/php versions, nginx -t, agent mount
scripts/lab/smoke.sh           # 17 Host-header probes, exit≠0 on any mismatch
scripts/lab/checksum-nginx.sh [--out FILE]   # P3-T01 evidence (config sha256 + nginx master start time + worker PIDs)
scripts/lab/down.sh [--images] # removes ONLY ppanel-lab containers/network/volumes
```

Evidence files go to `.lab/evidence/` (gitignored).

## Fixtures (`infra/nginx/fixtures/`)

| File (node-a unless noted)                       | Exercises                                                                                                                                                                                                                             |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `00-default-catchall.conf`                       | `default_server`, `return 444`                                                                                                                                                                                                        |
| `01-static-multi.conf`                           | multiple `server_name` on one block, shared `include`                                                                                                                                                                                 |
| `02-php-legacy.conf`                             | wildcard `*.php.example.lab`, `fastcgi_pass unix:` php-fpm                                                                                                                                                                            |
| `03-proxy-api.conf` + `conf.d/00-upstreams.conf` | named `upstream`, nested include, `limit_req`                                                                                                                                                                                         |
| `04-tls-secure.conf`                             | TLS with self-signed cert (generated at image build, never committed), 80→443 redirect                                                                                                                                                |
| `05-duplicate-a.conf` / `06-duplicate-b.conf`    | **same domain in two files** (nginx warns "conflicting server name … ignored")                                                                                                                                                        |
| `07-unusual-directives.conf`                     | regex `server_name` with capture, `split_clients`, `geo`, `if`, `rewrite`, `sub_filter`, named location; **commented** `perl_*`/`lua_*` lines marked `PPANEL-FIXTURE-UNSUPPORTED` (modules not installed, so `nginx -t` still passes) |
| `08-legacy-old.disabled.conf`                    | in `sites-available` but not enabled                                                                                                                                                                                                  |
| node-b `10-shop-compose.conf`                    | reverse proxy to compose-like app                                                                                                                                                                                                     |
| node-b `11-api-dup-of-node-a.conf`               | **cross-server duplicate** of `api.example.lab`                                                                                                                                                                                       |
| node-b `conf.d/status.conf`                      | loopback-only `stub_status` on `127.0.0.1:8088`                                                                                                                                                                                       |

Fixtures are **copied into the image** (not bind-mounted) so every `down`/`up` cycle starts from
identical config — verified: file hashes identical across container re-creation.

## Agent mount

`/opt/ppanel-agent` is bind-mounted **read-only** from `apps/agent/bin/` when that directory
exists (expected binary: `ppanel-agent-linux-arm64`), otherwise from the gitignored
placeholder `.lab/agent-bin/`. Override with `PPANEL_AGENT_BIN_DIR=/abs/path`. The agent is never
auto-started; tests run it explicitly with `docker exec -d ppanel-lab-node-a /opt/ppanel-agent/ppanel-agent-linux-arm64 …`
using the flags documented by `apps/agent` (Center URL `http://host.docker.internal:4000` for
enrollment, gateway `https://host.docker.internal:4443`, state dir `/var/lib/ppanel-agent`).

Agent state lives in the per-node named volume (`/var/lib/ppanel-agent`), removed by `down.sh`.

## Limitations — containers are NOT VMs

| Aspect         | Lab reality                                                   | Consequence                                                                                                             |
| -------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Kernel         | Shared LinuxKit kernel of Docker Desktop (arm64)              | No kernel-level isolation tests; `uname -r` is not Ubuntu's                                                             |
| Init / systemd | `tini` as PID 1, **no systemd**                               | systemd unit discovery, `systemctl reload nginx`, agent systemd packaging cannot be tested here                         |
| Docker         | No Docker engine in nodes; no docker.sock mounted (by design) | Docker/Compose discovery of _running_ containers and real deploys are BLOCKED here; compose file is static fixture only |
| Firewall       | `cap_drop: ALL` (+ minimal caps); no NET_ADMIN                | UFW/nftables adapter tests (P11) BLOCKED                                                                                |
| sshd           | not installed                                                 | SSH gateway tests (P10) BLOCKED                                                                                         |
| Network        | single bridge, no VPC, no public IP                           | DO VPC / private-vs-public path tests (P9) only partially simulated                                                     |
| Reboot         | container restart ≠ host reboot                               | reboot reconciliation evidence is approximate                                                                           |
| Arch           | arm64 only on this Mac                                        | amd64 behaviour not exercised locally (CI cross-builds the agent)                                                       |
| Packages       | Ubuntu archive at build time (not pinned per-package)         | versions recorded by `status.sh` output; rebuilds can drift                                                             |

Tests that therefore stay **BLOCKED until real disposable Ubuntu VMs** are supplied:
P1-T04 (real network drop), P2-T03 partially, P3-T03 with `systemctl reload`, P4-T01/T03 (real Docker deploys),
P7-T01/P7-T03 (outage under real traffic), P8-T01/T02, P10-T1…T4, P11-T1…T4, P12-T1/T4,
P9-T1/T3/T4 (real VPC), E2E-02 (3 agents on VMs), E2E-05…E2E-07, E2E-10, E2E-17.
Tests that **can** run here: P1-T01/T02 (enrollment/mTLS via host.docker.internal), P2-T01/T02,
P3-T01/T02/T04/T05 (nginx-level, using `nginx -s reload` instead of systemd), P2-T04.

## Safety

- `down.sh` uses `docker compose -p ppanel-lab … down --volumes --remove-orphans` only; it never
  touches `ppanel-dev` or unrelated projects (e.g. `amas-*`), then asserts no `ppanel-lab` container remains.
- No host ports, no privileged mode, no docker.sock, `no-new-privileges`, all caps dropped except
  CHOWN/SETUID/SETGID/NET_BIND_SERVICE/DAC_OVERRIDE/KILL for nginx/php-fpm masters.
- External network use: Docker Hub (pinned images) and the Ubuntu apt archive during image build.
  No production host, DNS, or cloud API is contacted.
