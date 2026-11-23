# pPanel lab (P0.04)

Disposable **container approximations** of two Ubuntu 24.04 managed hosts, for discovery,
agent and read-only-import tests. Compose project name is fixed to **`ppanel-lab`**.

| Container               | Role                           | Contents                                                                                           |
| ----------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------- |
| `ppanel-lab-node-a`     | legacy native host             | Ubuntu 24.04 (pinned digest), nginx 1.24, php8.3-fpm, fixtures 00–08                               |
| `ppanel-lab-node-b`     | container-style host           | Ubuntu 24.04, nginx 1.24, proxy to a compose-like app, `/opt/apps/shop/docker-compose.yml` fixture |
| `ppanel-lab-upstream-a` | upstream for `api.example.lab` | busybox httpd :8080 (read-only rootfs)                                                             |
| `ppanel-lab-upstream-b` | the "shop" compose app         | busybox httpd :8080 (read-only rootfs)                                                             |
| `ppanel-lab-dind`       | **P4** Docker engine of node-b | `docker:29.0.4-dind` (pinned digest), **privileged (lab only)**, shares node-b's network namespace |
| `ppanel-lab-registry`   | **P4** local OCI registry      | `registry:2.8.3` (pinned digest), `lab-registry:5000` in the lab, `127.0.0.1:55000` on the Mac     |

Network `ppanel-lab-net` (bridge). The **only** published port is the lab registry on
**`127.0.0.1:55000`** (loopback only, for pushing test images from the Mac). Site probes run inside
the nodes with `docker exec … curl -H 'Host: …' http://127.0.0.1/`.
Each node has `extra_hosts: host.docker.internal:host-gateway` so an in-container agent can
reach the Center on the Mac (`https://host.docker.internal:4443`, API `:4000`).

## Commands

```bash
scripts/lab/up.sh              # compose config --quiet, build, up -d --wait
scripts/lab/status.sh          # containers, OS/nginx/php versions, nginx -t, agent mount
scripts/lab/smoke.sh           # 17 Host-header probes, exit≠0 on any mismatch
scripts/lab/checksum-nginx.sh [--out FILE]   # P3-T01 evidence (config sha256 + nginx master start time + worker PIDs)
scripts/lab/images.sh          # P4: build+push test images, write digest refs to .lab/images.env
scripts/lab/agent_containers_lab.sh   # P4: agent container.* ops against the real lab-dind engine
scripts/lab/down.sh [--images] # removes ONLY ppanel-lab containers/network/volumes (incl. dind + registry volumes)
```

## docker-in-docker deploy target (P4)

> **WARNING — LAB ONLY.** `ppanel-lab-dind` runs with `privileged: true`. Docker-in-docker cannot
> work otherwise (it needs cgroups, mounts, iptables). This is allowed **only** for this disposable
> lab sidecar so node-b has a real Docker Engine to deploy to. It is **never** a production pattern:
> pPanel never creates privileged containers (the agent hard-codes `Privileged=false`,
> `CapDrop=ALL`, `no-new-privileges`) and real hosts run the distribution's dockerd natively.

- `lab-dind` uses `network_mode: service:lab-node-b`, i.e. it **shares node-b's network namespace**:
  a container published by the agent on `127.0.0.1:<hostPort>` (20000–29999) listens on node-b's
  loopback, exactly like on a real host where nginx proxies to `127.0.0.1:<port>`. It is not reachable
  from node-b's lab-network address (verified by the lab test).
- dockerd listens only on `unix:///run/dind/docker.sock` (no TCP, `DOCKER_TLS_CERTDIR=''`) on the
  shared volume `node-b-dind-sock`, mounted at `/run/dind` in node-b; node-b's entrypoint links
  `/var/run/docker.sock -> /run/dind/docker.sock`, the agent's default `docker.socket`.
  **No docker CLI is installed in node-b** — the agent uses the Engine API only.
- dind bridge networks use `10.213.0.0/24` / `10.214.0.0/16` to avoid clashing with Docker Desktop.
- Engine data is in the `node-b-dind-data` volume: `down.sh` removes it, and with it every container
  ever deployed inside dind.
- Node-a is unchanged (legacy nginx only). Node-b keeps its legacy sites and its nginx includes
  `/etc/nginx/conf.d/*.conf`, so the managed-routing bootstrap file
  `/etc/nginx/conf.d/ppanel-managed.conf` works there.

### Local registry and test images

`lab-registry` (registry:2, storage volume `registry-data`) is reachable from dind as
`lab-registry:5000` (`--insecure-registry lab-registry:5000`, lab network only) and from the Mac as
`127.0.0.1:55000` (Docker Desktop treats loopback registries as insecure by default).
`scripts/lab/images.sh` builds `infra/lab/images/*` for **linux/arm64 only**, pushes
`127.0.0.1:55000/ppanel-test/<name>:<tag>`, reads each manifest digest from the registry and writes
`.lab/images.env` (gitignored):

```bash
PPANEL_LAB_IMAGE_WEB_V1=lab-registry:5000/ppanel-test/web@sha256:<64hex>
PPANEL_LAB_IMAGE_WEB_V2=lab-registry:5000/ppanel-test/web@sha256:<64hex>
PPANEL_LAB_IMAGE_BROKEN=lab-registry:5000/ppanel-test/broken@sha256:<64hex>
PPANEL_LAB_IMAGE_ENVECHO=lab-registry:5000/ppanel-test/envecho@sha256:<64hex>
```

| Image     | Behaviour                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------- |
| `web`     | busybox httpd :8080, runs as 65534; `/` = `ppanel-test web v1` / `v2` (build arg), `/healthz` 200 |
| `broken`  | prints `broken: fatal: missing configuration, exiting` and exits 1 after 2 s                      |
| `envecho` | prints `APP_SECRET=<value>` at start (deliberately leaky), serves 200 on `/` and `/healthz`       |

Use these digest refs as `image` in `container.run_candidate` / Center deployments (container port 8080).

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

| Aspect         | Lab reality                                                   | Consequence                                                                                                     |
| -------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Kernel         | Shared LinuxKit kernel of Docker Desktop (arm64)              | No kernel-level isolation tests; `uname -r` is not Ubuntu's                                                     |
| Init / systemd | `tini` as PID 1, **no systemd**                               | systemd unit discovery, `systemctl reload nginx`, agent systemd packaging cannot be tested here                 |
| Docker         | node-a: none. node-b: **dind sidecar** (privileged, lab only) | P4 deploys run against a real Engine, but nested in Docker Desktop's VM (no real host dockerd/systemd/iptables) |
| Firewall       | `cap_drop: ALL` (+ minimal caps); no NET_ADMIN                | UFW/nftables adapter tests (P11) BLOCKED                                                                        |
| sshd           | not installed                                                 | SSH gateway tests (P10) BLOCKED                                                                                 |
| Network        | single bridge, no VPC, no public IP                           | DO VPC / private-vs-public path tests (P9) only partially simulated                                             |
| Reboot         | container restart ≠ host reboot                               | reboot reconciliation evidence is approximate                                                                   |
| Arch           | arm64 only on this Mac                                        | amd64 behaviour not exercised locally (CI cross-builds the agent)                                               |
| Packages       | Ubuntu archive at build time (not pinned per-package)         | versions recorded by `status.sh` output; rebuilds can drift                                                     |

Tests that therefore stay **BLOCKED until real disposable Ubuntu VMs** are supplied:
P1-T04 (real network drop), P2-T03 partially, P3-T03 with `systemctl reload`, P4 on a real (non-nested) dockerd host,
P7-T01/P7-T03 (outage under real traffic), P8-T01/T02, P10-T1…T4, P11-T1…T4, P12-T1/T4,
P9-T1/T3/T4 (real VPC), E2E-02 (3 agents on VMs), E2E-05…E2E-07, E2E-10, E2E-17.
Tests that **can** run here: P1-T01/T02 (enrollment/mTLS via host.docker.internal), P2-T01/T02,
P3-T01/T02/T04/T05 (nginx-level, using `nginx -s reload` instead of systemd), P2-T04, P4 container deploy/rollback/redaction tests against lab-dind (node-b).

## Safety

- `down.sh` uses `docker compose -p ppanel-lab … down --volumes --remove-orphans` only; it never
  touches `ppanel-dev` or unrelated projects (e.g. `amas-*`), then asserts no `ppanel-lab` container remains.
- Nodes: no privileged mode, no host docker.sock, `no-new-privileges`, all caps dropped except
  CHOWN/SETUID/SETGID/NET_BIND_SERVICE/DAC_OVERRIDE/KILL for nginx/php-fpm masters.
- **Exception (P4): `ppanel-lab-dind` is privileged** — lab-only, never a production pattern (see above).
  The Mac's own Docker socket is never mounted anywhere.
- One host port: `127.0.0.1:55000` (lab registry), loopback only.
- External network use: Docker Hub (pinned images) and the Ubuntu apt archive during image build.
  No production host, DNS, or cloud API is contacted.
