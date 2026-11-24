# Deploy applications

Run applications on enrolled servers as pPanel-managed containers behind the host's Nginx: single
container apps from a registry image pinned by digest, Compose apps, and images built from Git on a
designated build node. The live version is never touched until the new candidate is healthy.

Verified end to end by `scripts/lab/e2e_p4.py` (container apps, secrets, rollback, webhooks) and
`scripts/lab/e2e_p4b.py` (Git builds, Compose apps, Compose rollback).

## Prerequisites and permissions

| Task                                                | Permission         | Built-in roles                      | Extra                             |
| --------------------------------------------------- | ------------------ | ----------------------------------- | --------------------------------- |
| Enable managed routing on a server                  | `nginx.write`      | Platform Owner, Ops Admin           | approval rules as Nginx revisions |
| Create apps, set secrets, deploy, rollback, restart | `apps.deploy`      | Platform Owner, Ops Admin, Deployer | production: step-up and approval  |
| Approve a production deployment                     | `approvals.decide` | Platform Owner, Ops Admin           | step-up; approver ≠ creator       |
| Designate a build node                              | `policies.manage`  | Platform Owner, Ops Admin           | agent must report `build`         |
| Read deployments and logs                           | `apps.read`        | all four                            | —                                 |

The target server must be online with the Docker capability and **managed routing** enabled.

## 1. Enable managed routing (once per server)

In the deploy wizard **Target** step, or `POST /servers/:id/managed-routing`. pPanel writes one include
file, `/etc/nginx/conf.d/ppanel-managed.conf`, through a validated Nginx revision (`nginx -t` + reload);
existing sites are not changed. In production it waits for another approver
(`POST /servers/:id/managed-routing/approve { planHash }` with `X-Step-Up`). Status:
`GET /servers/:id/managed-routing` → **Not enabled / Awaiting approval / Applying… / Enabled / Failed /
Manual recovery required**.

## 2. Create and deploy a container app

UI: **Deployments → New deployment** (`/deployments/new`). Steps: **Source → Detect → Target → Configure
→ Domain → Review → Execution**.

1. **Source**: **Registry image**. Enter the repository and a `sha256:` digest. Tags are refused
   (`IMAGE_NOT_PINNED`); resolve the tag and paste `repo@sha256:<digest>`.
2. **Detect** (optional): paste or upload `package.json`, `composer.json` or a Dockerfile to suggest the
   port and health check (`POST /deploy/detect`).
3. **Target**: server (environment comes from the server).
4. **Configure**: container port, health check, resources, plain env, **secret environment variables**,
   named volumes (host paths are refused), registry credential.
5. **Domain**: hostnames and TLS (HTTP only, or existing certificate paths; ACME is BLOCKED, see
   [nginx-changes-and-tls.md](nginx-changes-and-tls.md#tls)).
6. **Review**: **Create application & run preflight**, read the exact plan and risk flags, then
   **Deploy** (non-production) or **Request deployment** (production).

API equivalent:

```http
POST /applications
{ "serverId": "…", "name": "shop-api", "environment": "uat", "domains": ["api.shop.example"],
  "containerPort": 3000, "secretKeys": ["DATABASE_URL"] }
PUT  /applications/:id/secrets/DATABASE_URL          { "value": "…" }    (production: X-Step-Up)
PUT  /applications/:id/registry-auth                 { "serveraddress": "…", "username": "…", "password": "…" }
POST /applications/:id/deployments/preflight
POST /applications/:id/deployments                   { "image": "registry/repo@sha256:…", "reason": "…" }
Idempotency-Key: <uuid>
```

What you should see on **Execution** / the deployment page (`/deployments/:id`): **Preflight checks →
Pull image & start candidate → Health check → Switch Nginx route → Stop previous container**, then
**Deployment #n is live.** The previous container is kept (stopped) for rollback; older ones beyond the
last two are removed.

### Secrets

Secrets are write-only (AES-256-GCM at rest, delivered once to the agent per job, redacted from logs).
**Env & Secrets** tab shows `set ✓ v<version>`, never values (`GET /applications/:id/secrets`). A new
value applies on the next deploy or redeploy. Changing a secret changes the plan hash of a pending
deployment, so its approval must be repeated.

### Preflight checks

| Check            | Blocks with                                | Fix                                                  |
| ---------------- | ------------------------------------------ | ---------------------------------------------------- |
| Agent online     | `AGENT_OFFLINE`                            | Wait for the agent, re-run preflight                 |
| Managed routing  | `MANAGED_ROUTING_DISABLED`                 | Enable managed routing (step 1)                      |
| Image pinned     | `IMAGE_NOT_PINNED`                         | Use `repo@sha256:<digest>`                           |
| Secrets present  | `SECRETS_MISSING`                          | Set them in Env & Secrets                            |
| Domain conflicts | `DOMAIN_CONFLICT`                          | Another app or a discovered Nginx site uses the name |
| Host port        | `NO_PORT_AVAILABLE`                        | Free managed ports 20000–29999                       |
| Disk             | `DISK_LOW` (≥ 90 %), `DISK_UNKNOWN` (prod) | Free space / wait for a fresh heartbeat              |
| Deployment lock  | `DEPLOYMENT_IN_PROGRESS`                   | Wait for or cancel the running deployment            |

A failing check fails the deployment at preflight; no job is sent.

### Production approval

Production deployments start as **Awaiting approval**. Another user with `approvals.decide` opens it
from **Approvals** (`/approvals`) or the deployment page → **Approve plan {hash}** with a 2FA code
(`POST /deployments/:id/approve { planHash }` + `X-Step-Up`). Approval starts execution immediately and is
single use (60 minutes).

## 3. Lifecycle: rollback, redeploy, restart, stop, start

Application **Overview** or **Deployments** tab → **Lifecycle**:

| Action   | API                               | Effect                                                                                           |
| -------- | --------------------------------- | ------------------------------------------------------------------------------------------------ |
| Rollback | `POST /applications/:id/rollback` | Starts the kept previous container, health-checks it, switches the route back, stops the current |
| Redeploy | `POST /applications/:id/redeploy` | Fresh container from the current digest; old one serves until the switch                         |
| Restart  | `POST /applications/:id/restart`  | Restarts the current container; brief downtime; no deployment record                             |
| Stop     | `POST /applications/:id/stop`     | Stops the current container: downtime for every domain                                           |
| Start    | `POST /applications/:id/start`    | Starts the stopped current container                                                             |

Production rollback and redeploy create a deployment that waits for approval; restart/start/stop need
`X-Step-Up`. **Rollback never restores data, volumes or databases**; restoring data is a separate backup
operation ([backup-restore.md](backup-restore.md)). If the previous container no longer exists →
409 `ROLLBACK_UNAVAILABLE`: redeploy an older digest instead.

**Cancel deployment** (`POST /deployments/:id/cancel`) is possible only before the route switch; the
candidate is removed and the live version keeps serving.

## 4. Compose apps

Wizard **Source → Compose**: paste `docker-compose.yml` (≤ 256 KiB). The Center validates it as you type
(`POST /deploy/compose/validate`) and refuses privileged mode, host namespaces, the Docker socket, host
bind mounts, extra capabilities, non-loopback published ports, `build:`, external `extends`/`include` and
alias bombs. Choose the route service and port.

```http
POST /applications
{ "kind": "compose", "serverId": "…", "name": "shop", "environment": "uat", "domains": ["shop.example"],
  "yaml": "…", "routeService": "app", "routePort": 8080 }
```

- `${SECRET_NAME}` placeholders become declared secrets; set them in **Env & Secrets** before deploying.
- Tags are resolved to digests at deploy time and recorded. Deployment steps: **Resolve image digests →
  Apply compose plan → Switch Nginx route** (only if the route service changed) **→ Stop previous**.
- Edit in the **Compose** tab → **Save as v{n}** (`PUT /applications/:id/compose` with `If-Match`), then
  **Deploy v{n}**. Unchanged services keep running; only replaced or created services restart.
- **Rollback** re-applies the previous successful plan (images + specs). Data is not restored
  (`rollback.dataRestored: false`). Non-route services restart with brief downtime.
- `restart` is not supported for compose (409 `OPERATION_NOT_SUPPORTED`); use stop/start or redeploy.

## 5. Git builds on build nodes

1. Designate a trusted server: **Server → Settings → Build node → Designate as build node** (tick the
   trust warning; `PATCH /servers/:id { buildNode: true }`, `policies.manage`). The agent must report the
   `build` capability (enabled in its local config), else 409 `NO_BUILD_NODE`. Dockerfile `RUN` steps
   execute on that host.
2. Wizard **Source → Git source (build)**: repository URL (host must be in `PPANEL_GIT_HOST_ALLOWLIST`),
   full 40-character commit SHA, build method (**Built-in template** or **Dockerfile in repo**, never
   both), build node, push repository (registry allowlist), optional git token (write-only).
3. **Build & deploy**: `PUT /applications/:id/build-config`, `PUT /applications/:id/git-auth { token }`,
   then `POST /applications/:id/builds { commitSha, deployAfter: true }` + `Idempotency-Key`.

What you should see: build `queued → building → succeeded`, then a normal deployment pinned to the
pushed digest (production → awaiting approval). The **Builds** tab lists builds with the redacted log
(`GET /builds/:id/log`). A commit that was already built is reused (no rebuild) unless `force: true`. A
failed build creates no deployment and leaves the live version untouched.

## Failure modes

| Symptom                                 | Meaning / recovery                                                                                                   |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `CANDIDATE_UNHEALTHY`                   | New container failed its health check and was removed; live version untouched                                        |
| `IMAGE_PULL_FAILED`                     | Wrong digest or missing registry credential                                                                          |
| `POSTCHECK_FAILED_REVERTED`             | Route switch failed its postcheck and was reverted; candidate removed                                                |
| `SECRETS_UNAVAILABLE`                   | The agent could not fetch the job's secrets (fetch-once; retry with a new deployment)                                |
| Deployment **Manual recovery required** | Route switch failed and the previous route could not be restored, see [emergency-recovery.md](emergency-recovery.md) |
| Center or agent lost mid-deploy         | Unknown-outcome candidates are stopped and removed by the Center; the serving container is never touched             |
| Build `PUSH_FAILED` / `expired`         | Output was not `<pushRepo>@sha256:…` / no build node picked up the job; nothing deployed                             |

## Limitations

- **GitHub App** source is BLOCKED (no App credentials); use repository webhooks
  ([auto-deploy.md](auto-deploy.md)).
- ACME / Let’s Encrypt is BLOCKED; HTTP or existing certificate paths only.
- Builds report `queued → building` only (no separate fetching/pushing progress); no test stage.
- Auto-deploy is not available for Compose apps.
- Rollback and Compose rollback never restore volumes or database data.
- HTTPS end-to-end and real Laravel were not exercised in the lab (`docs/TEST_REPORT.md` P4-T01, P4-T03).
