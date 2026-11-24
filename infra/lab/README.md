# pPanel lab (P0.04)

Disposable **container approximations** of two Ubuntu 24.04 managed hosts, for discovery,
agent and read-only-import tests. Compose project name is fixed to **`ppanel-lab`**.

| Container                 | Role                           | Contents                                                                                                    |
| ------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `ppanel-lab-node-a`       | legacy native host             | Ubuntu 24.04 (pinned digest), nginx 1.24, php8.3-fpm, fixtures 00–08                                        |
| `ppanel-lab-node-b`       | container-style host           | Ubuntu 24.04, nginx 1.24, proxy to a compose-like app, `/opt/apps/shop/docker-compose.yml` fixture          |
| `ppanel-lab-upstream-a`   | upstream for `api.example.lab` | busybox httpd :8080 (read-only rootfs)                                                                      |
| `ppanel-lab-upstream-b`   | the "shop" compose app         | busybox httpd :8080 (read-only rootfs)                                                                      |
| `ppanel-lab-dind`         | **P4** Docker engine of node-b | `docker:29.0.4-dind` (pinned digest), **privileged (lab only)**, shares node-b's network namespace          |
| `ppanel-lab-registry`     | **P4** local OCI registry      | `registry:2.8.3` (pinned digest), `lab-registry:5000` in the lab, `127.0.0.1:55000` on the Mac              |
| `ppanel-lab-backup`       | **P6** agents' backup repo     | `restic/rest-server:0.14.0` (pinned digest) `--private-repos --append-only`, `lab-backup:8000`              |
| `ppanel-lab-backup-admin` | **P6** maintenance identity    | same image + SAME data volume, full access, `127.0.0.1:58001` only (not on the nodes' network)              |
| `ppanel-lab-minio`        | **P6** offsite S3              | `pgsty/minio:RELEASE.2026-08-04T00-00-00Z` (pinned digest), `127.0.0.1:59000` only, bucket `ppanel-offsite` |

Network `ppanel-lab-net` (bridge). Published ports are all loopback-only: the lab registry on
**`127.0.0.1:55000`** (pushing test images from the Mac) and, P6, the backup maintenance listener
**`127.0.0.1:58001`** and MinIO **`127.0.0.1:59000`** (both on the separate `ppanel-lab-backup-admin`
network, which the nodes are NOT attached to). Site probes run inside
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
scripts/lab/git-fixtures.sh    # P4b: deterministic fixture repos -> .lab/git/*.git + .lab/git.env
scripts/lab/agent_build_lab.sh # P4b: image.build + compose.apply on the build node (node-b) against dind/lab-git/registry
scripts/lab/backup-secrets.sh  # P6: lab backup credentials -> .lab/backup/ (called by up.sh; --bucket after up)
scripts/lab/backup-images.sh   # P6: build+push helper image + scratch postgres, digests -> .lab/backup.env + node configs
scripts/backup/maintenance.sh --lab init node-a   # P6: restic init via the maintenance listener (agents cannot)
scripts/lab/agent_backup_lab.sh  # P6: real-lab backups/restores (P6-T01/T02/T04, append-only, prune, offsite copy)
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

## Build node and lab git server (P4b)

- **node-b is the lab build node.** Its image installs `git` (`WITH_GIT=1`) and
  `infra/lab/node/agent-config/node-b.yaml` is mounted read-only at `/etc/ppanel-agent/config.yaml`
  (`build.enabled: true`, `build.gitHostsAllowlist: [lab-git]`). The agent therefore reports the `build`
  capability and accepts `image.build` / `source.inspect`. node-a has no config file → builds disabled →
  `NOT_A_BUILD_NODE` before ack. Builds run `RUN` steps as containers on `lab-dind`: a real build node
  must be a **dedicated, trusted host** (not an isolation guarantee).
- **`lab-git`** (`infra/lab/git-daemon/Dockerfile`, alpine + `git-daemon`, runs as 65534, read-only rootfs,
  `cap_drop: ALL`) serves `.lab/git/*.git` read-only as `git://lab-git/<name>.git` on the lab network
  only (not published). **git:// is lab-only**: unauthenticated and unencrypted; the agent accepts it
  only because node-b's allowlist names `lab-git`. Production sources are https hosts.
- `scripts/lab/git-fixtures.sh` builds one bare repo per `infra/lab/git/<name>/` with one commit per
  `v1`, `v2`, … snapshot, fixed author/committer/date → the SHAs are identical on every machine, and
  writes `.lab/git.env` (gitignored):

```bash
PPANEL_LAB_GIT_URL_WEBSRC=git://lab-git/websrc.git
PPANEL_LAB_GIT_SHA_WEBSRC=5fafd3e53f7b40461dede446d79e429b31ac1588      # v1
PPANEL_LAB_GIT_SHA_WEBSRC_V2=cba86a019c675e4ca8810ce533f0730e529df0c4   # v2
PPANEL_LAB_GIT_URL_STACK=git://lab-git/stack.git
PPANEL_LAB_GIT_SHA_STACK=c400385f690d22fae14c6658cc1fa052d099dbc1
PPANEL_LAB_GIT_SHA_STACK_V2=67c9071f6b7bbe6b5055f527b02640af59e362b8
PPANEL_LAB_GIT_URL_NESTJS_MIN=git://lab-git/nestjs-min.git
PPANEL_LAB_GIT_SHA_NESTJS_MIN=835407782b691d33da83da39fcf8f0cc408532d6
```

- Fixture repos (`infra/lab/git/README.md`): `websrc` (busybox httpd :8080, `/healthz`, v1/v2 bodies),
  `stack` (`compose.yml`: `app` PHP 8.3 + pdo_pgsql `php -S :8080`, `worker` heartbeat row every 2 s,
  `db` postgres:16-alpine by digest + volume `pgdata`, `${DB_PASSWORD}` secret), `nestjs-min` (built-in
  `nestjs` template; needs the npm registry from the build containers).
- Builds push to `lab-registry:5000/ppanel-build/<app>` (dind `--insecure-registry`); the local
  `build-<id12>` tag is deleted after the push. Dangling build cache in dind is **not** pruned
  automatically (operator task; `down.sh` drops the whole dind data volume).

## Backups and restores (P6)

Model (ADR-0009, `docs/AGENT_PROTOCOL.md` "Backups and restores (P6)"): agents write to **restic**
repositories behind **rest-server `--private-repos --append-only`** with their own credential; retention
(`forget --prune`), the offsite copy, `check` and `unlock` run only as a separate **maintenance identity**.

| Piece            | Lab                                                                                                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| host restic      | **0.19.1** in both node images (`/usr/local/bin/restic`, official release binary, sha256 checked in `infra/lab/node/Dockerfile`; Ubuntu 24.04's apt restic is 0.16.4 < 0.17)                                                                                                          |
| agent config     | `infra/lab/node/agent-config/node-{a,b}.yaml` (mounted read-only): `backup.enabled: true`, `resticPath`, `helperImage` (digest written in place by `backup-images.sh`; restart the agents after it changes)                                                                           |
| helper image     | `infra/backup/helper/Dockerfile`: ubuntu 24.04 (pinned) + restic 0.19.1 (sha256) + postgresql-client-16 + mariadb-client, user 10001, `ENTRYPOINT restic`; pushed as `lab-registry:5000/ppanel-backup/helper@sha256:…`                                                                |
| scratch DB image | `postgres:16.10-bookworm` (pinned digest) re-pushed as `lab-registry:5000/ppanel-backup/postgres@sha256:…`                                                                                                                                                                            |
| agents' repo     | `http://lab-backup:8000/<serverUser>/` (`node-a`, `node-b`), lab network only. Helper containers in lab-dind cannot resolve lab names, so the agent passes `ExtraHosts: lab-backup:<ip>` resolved on the host (also done in production: helpers resolve the repo host like the agent) |
| maintenance      | `lab-backup-admin` on the same `backup-data` volume, one `admin` user, `127.0.0.1:58001` (Mac) / `lab-backup-admin:8000` (admin network)                                                                                                                                              |
| offsite          | `lab-minio` S3 `ppanel-offsite/<serverUser>` (restic `s3:` repo, same repo password as the primary)                                                                                                                                                                                   |

Generated, gitignored **`.lab/backup/`** (`scripts/lab/backup-secrets.sh`, idempotent, values never in argv):
`htpasswd` (bcrypt, node-a/node-b), `admin-htpasswd` (admin), `servers/<user>.env`
(`PPANEL_LAB_BK_USER`, `_REST_PASSWORD`, `_REPO_PASSWORD` — what the Center would deliver in the job
secrets `restic: {restUser, restPassword, repoPassword}`), `admin.env`, `minio.env`.
**`.lab/backup.env`** (`backup-images.sh`): `PPANEL_LAB_BACKUP_HELPER_IMAGE`, `PPANEL_LAB_BACKUP_SCRATCH_PG`, URLs.

```bash
scripts/lab/up.sh && scripts/lab/backup-images.sh
scripts/backup/maintenance.sh --lab init node-a && scripts/backup/maintenance.sh --lab init node-b
scripts/lab/agent_backup_lab.sh
scripts/backup/maintenance.sh --lab prune node-a --keep-daily 7 --keep-weekly 4 --keep-monthly 6
scripts/backup/maintenance.sh --lab copy node-a          # → MinIO; then: --lab offsite-snapshots node-a
scripts/backup/maintenance.sh --lab check node-a ; scripts/backup/maintenance.sh --lab unlock node-a
PPANEL_BACKUP_REPORT_TOKEN=… scripts/backup/maintenance.sh --lab --report http://127.0.0.1:4000 \
  --repository-id <uuid> check node-a                    # POST /api/v1/backup-maintenance/reports
```

`maintenance.sh --lab` runs restic in the helper image on the admin network (no restic needed on the Mac);
in production it uses `restic` from PATH (or `RESTIC_BIN`) with `PPANEL_BACKUP_ADMIN_URL/_USER/_PASSWORD`,
`PPANEL_BACKUP_REPO_PASSWORD_FILE` and `PPANEL_BACKUP_S3_*` + `AWS_*`.

**Lab-only shortcuts**: rest-server and MinIO speak **http** (production: https with a real certificate);
credentials are files under `.lab/`; the maintenance listener is "protected" by being on a separate
network + Mac loopback (production: a separate host/port reachable only by the operator); MinIO has no
object lock; the offsite repo is not pruned by `copy` (run `prune` against it separately if needed).
The real-lab test leaves its fixtures: app `p6lab` (network `ppanel-p6lab`, volume `ppanel-p6lab-files`,
staging volumes `ppanel-p6lab-restore-*` — the agent never deletes volumes), `/var/lib/ppanel-p6-labtest`
in the nodes, and snapshots in the repos; `down.sh` removes them all with the volumes.

## Private networking, fake DigitalOcean and the Gateway (P9)

Profile `p9` in `infra/compose/lab.yml`, **not** started by `scripts/lab/up.sh` (which behaves exactly as before).
Started/stopped only by `scripts/lab/p9-net.sh`:

```sh
scripts/lab/p9-net.sh up              # lab-center-private + lab-do-fake + lab-gateway; attach node-a/node-b to their VPC
scripts/lab/p9-net.sh status
scripts/lab/p9-net.sh cut node-a      # "private path offline" (docker network disconnect)
scripts/lab/p9-net.sh restore node-a
scripts/lab/p9-net.sh down            # detach, remove p9 services, networks and the gateway state volume
python3 -I scripts/lab/e2e_p9.py --out docs/evidence/<date>/p9-e2e.json   # P9-T1..T4 against the real Center
```

| Piece                         | What                                                                                                                                                                                                                                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ppanel-lab-vpc-a` / `-vpc-b` | `internal` bridges (no route out), 10.110.0.0/24 and 10.120.0.0/24, one "region" `lab1`. node-a .11 + lab-gateway .20 on vpc-a, node-b .12 on vpc-b.                                                                                                                                              |
| `lab-center-private`          | `alpine/socat` (pinned) on both VPCs (.2) + its own egress network: TCP `:4444` → `host.docker.internal:4444` (the Center's `private` gateway listener). mTLS stays end-to-end.                                                                                                                   |
| `lab-do-fake`                 | `infra/lab/do-fake/server.mjs` on the pinned `node:22-alpine` image (already on disk): `/v2/account`, `/v2/droplets` and `/v2/vpcs` (bearer token, GET only, **2 per page** so the Center must paginate), `/metadata/<node>/v1.json`. `127.0.0.1:58090` on the Mac, `lab-do-fake:8080` on labnet. |
| `lab-gateway`                 | `ppanel-lab-node-a:dev` (no extra image) with the node-a fixture sites removed at start; labnet (public path) + vpc-a. Agent config `agent-config/p9-gateway.yaml`.                                                                                                                               |

node-a / node-b are **never recreated** for P9: `p9-net.sh` uses `docker network connect --ip` (a `compose up` of node-b would
make lab-dind lose its network namespace). Their P9 agent configs (`agent-config/p9-node-{a,b}.yaml`) are copied to
`/etc/ppanel-agent/p9.yaml` by `e2e_p9.py` and passed with `--config`; the mounted `config.yaml` stays untouched.

Center env for the lab (set by `e2e_p9.py`): `PPANEL_GATEWAY_LISTENERS=public=0.0.0.0:4443,private=0.0.0.0:4444`,
`PPANEL_PUBLIC_GATEWAY_URL=https://host.docker.internal:4443`, `PPANEL_PRIVATE_GATEWAY_URL=https://lab-center-private:4444`,
`PPANEL_GATEWAY_HOSTNAMES=localhost,host.docker.internal,lab-center-private`, `PPANEL_DO_API_BASE=http://127.0.0.1:58090`.

**Lab substitutes** (not equivalent to DigitalOcean): the "VPCs" are Docker bridges on one Docker VM; the metadata service
is an HTTP server on labnet instead of link-local `169.254.169.254`; the public "path" is `host.docker.internal` from
labnet and public IPv4s in the fake are TEST-NET-3 placeholders; isolation between VPCs is Docker's inter-bridge
isolation, not a cloud firewall. Every node is also on labnet (172.20/16, RFC 1918), so pair tests rely on the Center
picking the provider-verified VPC address (`privateIpv4`).

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
| Network        | bridges only (P9: two internal "VPC" bridges), no public IP   | DO VPC / private-vs-public path tests (P9) simulated with Docker networks, see the P9 section                   |
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
- Host ports, loopback only: `127.0.0.1:55000` (lab registry), P6 `127.0.0.1:58001` (backup maintenance
  listener), `127.0.0.1:59000` (MinIO) and P9 `127.0.0.1:58090` (fake DigitalOcean, profile `p9`). The backup services run read-only (rest-server) with `cap_drop: ALL`.
- External network use: Docker Hub (pinned images), the Ubuntu apt archive and (P6) the restic release on
  GitHub (sha256-verified) during image build.
  No production host, DNS, or cloud API is contacted.
