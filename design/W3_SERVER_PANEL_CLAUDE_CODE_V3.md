> **CONSOLIDATED EDITION v3.0 (2026-11-17)** — Replaces prior code briefs and includes DigitalOcean VPC, Gateway option, SSH gateway, firewall federation, software plugins, and secure MCP/AI operations.

# W3 Server Panel — Claude Code Execution Master Plan

> Role: **Claude Code / Principal Platform Engineer + DevSecOps + QA Lead**  
> Project: W3 Server Panel — Centralized Infrastructure, Legacy Nginx Adoption, Deployment, Monitoring, Logs, Backups  
> Output: **working self-hosted software with automated tests and reproducible installation**  
> Primary environment: Ubuntu 22.04/24.04 LTS; Debian support after capability testing  
> Status: implementation instructions, no code is assumed to exist yet

---

## 0. Mandatory execution rules

1. **Build, run and test**: implement a working product rather than only generating scaffolds, speculative docs or screenshots.
2. Inspect existing repo, tools, infrastructure and `git status` before changes. Preserve user code and secrets. If repository is empty, bootstrap as specified.
3. Execute phases **P0 → P8** in order. Each phase has atomic TODO IDs, explicit commands/examples, test outcomes, and a gate. Do not mark PASS without running tests; log exact commands, results, artifacts and failures.
4. Keep `docs/IMPLEMENTATION_STATUS.md`, `docs/TEST_REPORT.md`, `docs/DECISIONS.md`, `docs/RISKS.md`, and `docs/DEPLOYMENT_RUNBOOK.md` current after every task/phase. Persist execution state so work can resume between sessions.
5. **Do not touch production hosts, alter DNS, reload existing Nginx, expose ports, deploy to cloud, delete volumes, restore a database or spend money** without explicit authorization and a per-operation plan. Use disposable lab VMs/containers and mocked integrations first.
6. Production-changing features require **dry-run → impact analysis → validation → scoped approval → execution → postcheck → audit**. No unrestricted shell exposed via web/API/agent.
7. Prefer official stable releases, pin dependencies and container images by version/digest where practical. Before implementing, check actual docs/API behavior for selected versions; record validated versions in `docs/DEPENDENCIES.md`.
8. Never state that an unexecuted test is PASS. If external credentials or 3 real test VMs are unavailable, provide mock/integration evidence and mark live E2E `BLOCKED`, not complete.
9. Implement security controls **as engineering requirements**, not TODOs deferred after functionality.
10. Run the next unblocked task without requesting repetitive confirmation. Stop only for genuinely destructive/privileged external changes or missing essential credentials.

**Primary engineering principle:** **Center failure and agent disconnection must not stop existing workloads. Legacy import must not mutate production by default.**

---

## 1. Deliverables and scope

### 1.1 MVP-A: usable deployment and legacy adoption
- [ ] Center UI/API with admin bootstrap, MFA/2FA, scoped RBAC, audit, sessions.
- [ ] Agent installation, short-lived one-time enrollment, rotating/revocable identity; outbound-initiated secure connection to Center.
- [ ] Multi-server inventory/heartbeat/capabilities, online/offline/stale states, queues and job reconciliation.
- [ ] Read-only discovery of Nginx, Docker, Compose, systemd, PHP-FPM and website mappings.
- [ ] Import statuses `discovered → observed → adopted → managed`; conflicts/unsupported/manual-review representation.
- [ ] Policy-controlled Nginx configuration ownership, preview, backups, `nginx -t`, atomic write/reload, postcheck and revert.
- [ ] Application management: start/stop/restart only for allowlisted owned resources.
- [ ] Guided deploy: GitHub, registry image, Dockerfile, restricted Compose; domain/TLS via validated local Nginx configuration.
- [ ] Health checks, deployment metadata, safe rollback of stateless versions, build/runtime logs, webhook-driven auto-deploy with policies.

### 1.2 MVP-B: operations ready
- [ ] Fleet/host/service metrics with alerting.
- [ ] Central logs with scope-based access, sanitization, retention and backpressure.
- [ ] File/volume backup and DB-aware backup (PostgreSQL, MySQL/MariaDB; MongoDB as separate capability phase if validated).
- [ ] Scheduled jobs, retention, offsite backup, verified restore into isolated target, approval on destructive restore.
- [ ] Recovery runbooks, center outage tests, agent disconnected tests, security tests, installer/upgrade and rollback procedures.

### 1.3 Deferred or gated beyond core MVP
Kubernetes, arbitrary untrusted multi-tenancy, root unrestricted browser terminal, shared hosting mail/DNS panel, arbitrary command execution, zero-downtime guarantee for Compose/native apps, automatic universal DB schema rollback, guaranteed lossless conversion of every Nginx directive. Show capability flags and explain limitations in UI.

---

## 2. Architecture

```text
Browser / Next.js Dashboard
          |
       HTTPS
          |
NestJS Center API + Auth/RBAC/Audit + REST/SSE
          |
PostgreSQL  | Redis/BullMQ Workers | Secrets Envelope Encryption
          |
Job Scheduler / Desired State / Command & Event Store
          |
Mutual TLS + short-lived scoped task grants + outbound agent connection
          |
+-------------------+-------------------+--------------------+
| Ubuntu Node A     | Ubuntu Node B     | Ubuntu Node C      |
| Go W3 Agent       | Go W3 Agent       | Go W3 Agent        |
| Nginx/PHP-FPM     | Docker/Compose    | mixed workloads    |
| existing apps     | apps and volumes  | existing nginx     |
+-------------------+-------------------+--------------------+
          | Central metrics/logs/backup metadata
          v
Prometheus/Alloy/Loki + Restic repositories (NAS/S3-compatible offsite)
```

### 2.1 Technology decisions

| Layer | Baseline | Requirements |
|---|---|---|
| UI | Next.js, TypeScript, Tailwind, shadcn/ui | server/client access checks, accessible flows |
| API | NestJS, Prisma, PostgreSQL | input validation, auth, OpenAPI, audit |
| Jobs | BullMQ + Redis | idempotency, timeout, locks, revalidation |
| Agent | Go, systemd | signed/enrolled identity, allowlisted typed commands |
| Protocol | outbound mTLS, gRPC stream or HTTPS long-poll | cert rotation, reconnect, task expiry, bounded buffering |
| Runtime | Docker Engine/Compose + native Nginx/PHP/systemd discovery | capability detection, no blanket root shell |
| Proxy | existing Nginx first | validate config then reload, no automatic Traefik takeover |
| Git | GitHub App (preferred), webhook | signature validation, installation/repo scope, pinned SHA |
| Metrics | Prometheus + Alloy | retention, labels, resource sizing |
| Logs | Alloy + Loki | tenant/role filtering at API boundary, log redaction |
| Backup | Restic + DB-native dumps | encrypted restic repo, offsite copy, restore verification |
| Tests | Vitest/Jest, Playwright, Go test, Testcontainers/lab VMs | deterministic CI + separate live E2E |

Use **monorepo**, modular monolith for Center API, independent Agent. Avoid implementing a generic agent-side arbitrary command runner; each operation is a typed capability with validated inputs and fixed handlers.

### 2.2 Initial repo layout

```text
w3-server-panel/
  apps/web/                   # Next.js
  apps/api/                   # NestJS
  apps/worker/                # background jobs
  apps/agent/                 # Go module and systemd unit
  packages/shared-contracts/ # TS API/events schemas
  packages/ui/               # reusable design components
  infra/compose/             # center + lab stacks
  infra/nginx/               # config validation/templates
  infra/observability/       # Prometheus, Alloy, Loki
  infra/backup/              # restic & database tools
  templates/{nextjs,nestjs,laravel,compose}/
  scripts/{install,upgrade,backup,restore,lab}/
  tests/{integration,e2e,security,disaster-recovery}/
  docs/{adr,runbooks}/
  .github/workflows/
```

### 2.3 Minimum persistence model

`users`, `sessions`, `mfa_factors`, `roles`, `permissions`, `role_bindings`, `servers`, `agent_enrollments`, `agent_certificates`, `agent_heartbeats`, `server_capabilities`, `projects`, `environments`, `applications`, `app_endpoints`, `app_runtime_bindings`, `discovery_scans`, `discovery_findings`, `adoption_reviews`, `nginx_config_revisions`, `deployments`, `deployment_steps`, `deployment_artifacts`, `job_leases`, `webhook_deliveries`, `secrets`, `backup_policies`, `backup_snapshots`, `restore_jobs`, `alert_rules`, `incidents`, `audit_events`.

Model all cross-node operations with `server_id`, immutable `job_id`, actor, scope, authorization snapshot, expiration, desired state version, result and timestamps; secrets are encrypted, never stored in plaintext logs.

### 2.4 Critical state machines

**Server:** `enrolling → online ↔ degraded/offline → revoked` (plus unknown/stale heartbeat).  
**Legacy app:** `discovered → observed → adopted → managed`; `unsupported/conflict/manual-review` as independent flags; no implicit upgrades in ownership.  
**Deploy job:** `queued → preflight → building/pulling → starting → health_check → routing → succeeded`; failure branch `failed / rollback_pending / rolled_back / requires_manual_recovery`; expired/cancelled distinct.  
**Backup:** `scheduled → running → uploaded → verified / failed`; distinguish `verified_restore` from mere successful snapshot.  
**Restore:** `planned → impact_reviewed → approved → running → verified / failed / requires_manual_recovery`.

---

## 3. Security architecture and authorization

- Center/agent **mutual TLS**, per-agent identity and certificate rotation/revocation; agent initiates connection, no public agent listener.
- One-time enrollment token: short TTL, hashed server-side, used once, bound to server request and approved where required.
- Scoped RBAC permissions: `fleet.read`, `servers.enroll`, `servers.operate`, `apps.read`, `apps.deploy`, `nginx.read`, `nginx.write`, `backups.create`, `backups.restore`, `policies.manage`, `audit.read`; scope to env/project/server.
- Mandatory MFA for privileged production actions; sensitive restore/NGINX edits require separate approval when policy demands.
- No `docker.sock` access in web/API; only protected local Agent component handles Docker. Restrict agent operation policies and validate mounts, image sources, capabilities, host network/PID, privileged mode, port exposure and resource limits.
- Docker root access grants host-equivalent power: run managed agents on appropriately trusted dedicated nodes, and never promise complete isolation for arbitrary workloads. Consider rootless/stronger sandbox only as an explicitly validated future capability.
- Nginx ownership: canonicalize paths, reject traversal/symlinks outside configured roots, guard duplicate server_names, ensure config snapshot + `nginx -t` + approved reload + postcheck/revert.
- Protect against SSRF (healthcheck URL/server host targets), webhook replay, path injection, shell injection, malicious compose/config files, secret exposure, cross-tenant log access.
- All work jobs have **idempotency key, expiry, lease, preflight, state version validation, concurrency guard**; offline jobs cannot blindly replay on reconnect.
- Least privilege for metrics/log/backup credentials. Offsite backup delete ability separate from Center administration; prefer immutable/append-only/WORM options where supported.
- Read-only import and all queries must not reload, modify, restart or migrate anything.
- Audit: authenticated actor, target, before/after metadata/diff hash, approval, result and correlation ID; redact secrets.

---

## 4. Legacy Nginx discovery and safe adoption design

**Discovery sources:** `nginx -T` (read-only parsing), site config paths, certificate metadata, Unix listeners, upstream/proxy_pass/root/fastcgi_pass, Docker container labels, Compose files, systemd units, PHP-FPM pools, process-to-port mapping. Parse/include effective config carefully; do not assume all Nginx configs can be round-tripped safely.

**Mapping strategy:** finding objects include provenance, raw excerpt/reference, confidence, linked process/container, unresolved dependencies and `manual_review_required`. Scanner does not change ownership. Existing Nginx remains source of truth until separately adopted.

**Manage strategy:** don't automatically regenerate all existing config. For each supported modification generate a targeted managed include or bounded supported edit, save original and checksum, obtain approval, run `nginx -t`, perform atomic change and `nginx -s reload`/systemctl reload, healthcheck affected sites, revert if error. Out-of-band edits detect drift and block overwrite pending review.

**Import tiers:**
1. Discover = inventory only.
2. Observe = metrics/logs/health, no config writes.
3. Adopt = controlled actions on confirmed known service ownership.
4. Managed = deployment version control and config lifecycle after preflight and explicit operator approval.

For unsupported directives or ambiguous upstream mappings, keep Observe mode and require manual migration plan. Do not claim universal zero downtime.

---

## 5. Deployment engine and wizard requirements

### Inputs
- GitHub App selected repo, branch/commit (record exact commit SHA); webhook signature verified.
- Docker registry image pinned by digest; authenticate via protected secrets.
- Dockerfile build using a safely isolated builder, resource limits and least privilege. Never blindly execute untrusted builds on Center; use trusted dedicated build nodes or constrained builder with documented limits.
- Compose import with static YAML analysis, reject unsafe `privileged`, host sockets, host mounts, network/PID escalation or disallowed image registries. Be explicit that Compose does not guarantee zero downtime or atomic rollback.

### Wizard phases
`source → detect → target → env/secrets/volumes → domain/proxy/tls → preflight → review/approval → job timeline → verify`.

### Deployment requirements
- Safe default resource limits, isolated per-app networks/volumes, nonconflicting ports, secure image registry and secret handling.
- Existing Nginx 80/443 ownership preserved. Domain conflict checks; configure approved Nginx routes only, do not start competing proxy daemon.
- Atomic switch where possible for stateless container deployments using candidate+healthcheck+route update. Rollback image digest and route configuration on failure.
- Native Laravel/PHP or arbitrary Compose routes can experience downtime; display risk and do not imply atomicity.
- DB migrations must require policy decisions and separate recovery strategy; code rollback does not automatically roll back database schema/data.
- Redeploy, restart, rollback, restore are distinct typed operations.
- Auto-deploy policies: branch allowlist, environment rules, concurrency lock, webhook dedupe, approvals for prod, rollback on health failure when supported.

---

## 6. Monitoring, logs and backup operations

**Monitoring:** agent heartbeat and host resource inventory; Prometheus collection via appropriately secured exporters/Alloy, service/container health, alert rule evaluation. Center storage sizing and retention configurable. Missing data ≠ 0.

**Logs:** Alloy forwarding (or agent adapter) to centralized Loki, consistent labels (`server_id`, `app_id`, `environment`, `source`), rate limiting/backpressure, sanitization, configurable retention. All queries authorized against server/app scope; no arbitrary Loki cross-scope query exposure.

**Backups:** Restic with encryption; DB-native consistent backups (`pg_dump`/`pg_restore`, `mysqldump` or `mariadb-dump`, validate compatibility); app volumes/config backups; scheduled policy/timezone, retention, immutable/offsite copy strategy, checksum verification, restore drills and evidence. Restoring production always requires impact/diff, isolated test target by default and approval before overwrite. Back up **Center PostgreSQL and encryption key material** via separated, documented recovery method; keys cannot rely only on the Center's own database.

**Operational SLO tests (initial lab criteria, adjust after benchmark):** application availability unaffected by a 10-minute Center outage; no deploy side effect from read-only import; visible offline within heartbeat threshold; backup restore results verified; log ingestion recovers after brief link loss subject to configured buffer and retention ceilings.

---

## 7. Phase-by-phase implementation TODO, test cases and gates

> Each checkbox must correspond to a commit/PR or file change and a verifiable test record. Maintain `docs/IMPLEMENTATION_STATUS.md` with `TODO/IN_PROGRESS/PASS/BLOCKED/FAIL`, owner, timestamp, evidence, and next action.

### P0 — Repository, design intake, risk and reproducible lab
- [ ] P0.01 Inspect repo, dependencies, tooling, deployment constraints, and existing assets; record baseline and no-touch rules.
- [ ] P0.02 Incorporate Claude Design screen contracts; where unavailable, implement minimal functional UI and track open design dependencies.
- [ ] P0.03 Initialize monorepo, conventions, lint/format/typecheck, CI skeleton, lockfiles, `.env.example` without secrets.
- [ ] P0.04 Start lab Center + 2 disposable nodes or documented local VM/container approximations; label limitations of containers vs actual VMs.
- [ ] P0.05 Record threat model, trust boundaries, operation classifications and ADRs.
- [ ] **TEST P0-T01:** clean checkout installs dependencies and lint/typecheck run.
- [ ] **TEST P0-T02:** local lab starts/stops repeatably; no secret committed; no production host contacted.
- [ ] **GATE P0:** reproducible local environment and threat model.

### P1 — Center identity, API and enrollment
- [ ] P1.01 PostgreSQL schema/migrations; seed least-privilege first admin via secure setup.
- [ ] P1.02 Login, session, password hashing, MFA/TOTP + recovery codes, API auth, scoped RBAC, CSRF where applicable.
- [ ] P1.03 Agent Go binary, systemd packaging, config validation, lifecycle.
- [ ] P1.04 One-use short TTL enrollment, peer identity, mTLS, rotation/revocation.
- [ ] P1.05 Outbound stream/poll, heartbeat, capabilities, no inbound public management listener.
- [ ] P1.06 Server registry UI and audit events.
- [ ] **TEST P1-T01:** valid agent registers once; reused/expired token rejected.
- [ ] **TEST P1-T02:** spoofed/revoked certificate rejected, rotated certificate accepted.
- [ ] **TEST P1-T03:** unauthorized viewer cannot enroll, revoke or operate hosts.
- [ ] **TEST P1-T04:** agent reconnect after network drop without restarting apps.
- [ ] **GATE P1:** 2 or more nodes controllable from Center; auth/agent trust tests pass.

### P2 — Job orchestrator + inventory
- [ ] P2.01 Typed job schema, idempotency keys, task lease/TTL, timeout, cancellation, audit correlation.
- [ ] P2.02 Agent allowlisted handlers, input schema validation and local authority boundaries.
- [ ] P2.03 Host CPU/RAM/Disk/Network, Docker/container, systemd, Nginx/PHP inventory.
- [ ] P2.04 UI fleet list/detail, stale/offline states, job progress/events.
- [ ] P2.05 Resource ownership + concurrency locks; auto-reconciliation after reboot/disconnect.
- [ ] **TEST P2-T01:** duplicate job request has one effect and multiple notifications are safe.
- [ ] **TEST P2-T02:** expired privileged job not executed after agent reconnect.
- [ ] **TEST P2-T03:** forced worker crash/restart retains durable job state and does not duplicate destructive actions.
- [ ] **TEST P2-T04:** disconnected host shows stale/unknown, not healthy zero metrics.
- [ ] **GATE P2:** consistent fleet inventory and fault-tolerant jobs.

### P3 — Legacy Nginx discovery/import
- [ ] P3.01 Scanner for `nginx -T` effective config, server blocks, includes, domains, roots, upstream and SSL references.
- [ ] P3.02 Docker/Compose/PHP-FPM/systemd/process/port discovery; provenance and confidence.
- [ ] P3.03 Model scan snapshots, unsupported directives and collisions; no config mutation.
- [ ] P3.04 Import UI: Preview, mappings, Observe default, Adopt/Managed with explicit permissions.
- [ ] P3.05 Safe supported Nginx operations: file snapshot, diff, syntax validation, apply/reload, postcheck and revert; drift detection.
- [ ] **TEST P3-T01:** checksum Nginx config before/after Discover+Observe is identical; nginx process uptime unchanged.
- [ ] **TEST P3-T02:** fixtures include multiple `server_name`, wildcard, include files, fastcgi, TLS, reverse proxy, duplicate domains, unsupported directives.
- [ ] **TEST P3-T03:** invalid generated config blocks reload; backup permits recovery.
- [ ] **TEST P3-T04:** unauthorized ownership upgrade/host path traversal rejected.
- [ ] **TEST P3-T05:** external config drift blocks automated overwrite and prompts manual review.
- [ ] **GATE P3:** 2+ legacy app types imported without interruption; risky cases blocked safely.

### P4 — Deploy wizard + application lifecycle
- [ ] P4.01 GitHub App integration with scoped repo permissions, webhook signature/replay protection, commit SHA pinning.
- [ ] P4.02 Registry image deploy; Dockerfile build on separated/constrained builder; safe Compose parser/policy validator.
- [ ] P4.03 Framework detection Next.js/NestJS/Laravel/Dockerfile/Compose; explicit override.
- [ ] P4.04 Full wizard APIs and UI: source, runtime, server, env/secrets, domain, preflight, review, progress.
- [ ] P4.05 Nginx route management, TLS approach, DNS/port collision checks; preserve existing Nginx.
- [ ] P4.06 Deployment history, immutable artifact digest, per-step logs, application healthchecks.
- [ ] P4.07 Rollback for supported stateless deployments; Compose/native limitations prominently documented.
- [ ] P4.08 Branch rules, auto-deploy, prod approval and per-app deploy locks.
- [ ] **TEST P4-T01:** GitHub → Next.js → domain → HTTPS works in lab with controlled DNS/TLS fixture or explicitly scoped staging cert.
- [ ] **TEST P4-T02:** NestJS env secret injected without appearing in API response/build logs.
- [ ] **TEST P4-T03:** Laravel + worker + database Compose survives redeploy with persistent test data.
- [ ] **TEST P4-T04:** unhealthy candidate does not replace healthy deployment; rollback documented and verified.
- [ ] **TEST P4-T05:** malicious Compose privileged/host mounts/host-network rejected.
- [ ] **TEST P4-T06:** duplicate webhook delivery results in single deployment; wrong branch ignored.
- [ ] **TEST P4-T07:** port/domain/agent-offline/disk preflight blocks unsafe execution.
- [ ] **GATE P4 = MVP-A:** from one dashboard, import legacy site and deploy a new app successfully with audit and safe failure recovery.

### P5 — Monitoring, logs and alerts
- [ ] P5.01 Deploy/secure Alloy, Prometheus, Loki; define retention and size limits.
- [ ] P5.02 Fleet/server/application charts and status, last-known sample with stale marker.
- [ ] P5.03 Central log search/live tail by server/app/source/time/severity; role-scoped queries.
- [ ] P5.04 Secret redaction, query rate limits, retention, stream backpressure and limited buffering.
- [ ] P5.05 Alert rule CRUD, incidents, Telegram/email/webhook channel validation and test notifications.
- [ ] **TEST P5-T01:** loss of agent or app health triggers intended alert; acknowledgment recorded.
- [ ] **TEST P5-T02:** viewer assigned to one server cannot access other server's logs/metrics via API or direct query route.
- [ ] **TEST P5-T03:** injected fake API key never appears in centralized logs; redaction verified.
- [ ] **TEST P5-T04:** temporary network outage gives bounded buffer/recovery, never uncontrolled memory/disk growth.
- [ ] **GATE P5:** fleet view, actionable alerts and searchable authorized logs operational.

### P6 — Backup/restore and central recovery
- [ ] P6.01 Restic encrypted repository integration with controlled credentials and independent delete policy.
- [ ] P6.02 File/volume backups and DB-native logical dumps with transaction-consistent settings.
- [ ] P6.03 Backup policy UI/API: schedules, timezone, exclusions, retention, destination/offsite status.
- [ ] P6.04 Snapshot list, validation, manifest and job logs; mark verification levels accurately.
- [ ] P6.05 Restore wizard: target, impact, dry-run, approval, staged restore, integrity and application postcheck.
- [ ] P6.06 Center DB + config + encryption-key recovery runbook and separate recovery storage.
- [ ] **TEST P6-T01:** backup known files, delete in isolated test workspace, restore and compare checksums.
- [ ] **TEST P6-T02:** PostgreSQL seeded tables → dump → restore to isolated DB → compare rows and constraints.
- [ ] **TEST P6-T03:** unauthorized production restore rejected; approved operation has full audit trail.
- [ ] **TEST P6-T04:** interrupted backup/resume/failure recovery does not report false success.
- [ ] **TEST P6-T05:** simulated Center loss → restore Center from backups and reestablish agent identities safely.
- [ ] **GATE P6:** backup/restore proven, not merely scheduled; documented recovery works.

### P7 — Security, resilience and performance hardening
- [ ] P7.01 Threat-model tests: IDOR, broken access control, CSRF, XSS, SSRF, injection, path traversal, webhook spoof/replay, secret leakage.
- [ ] P7.02 Agent permission boundaries and policy bypass attempts; Compose/config allowlist fuzz tests.
- [ ] P7.03 Center 10-minute outage while apps serve traffic; agent reconnect and reconcile.
- [ ] P7.04 Deploy concurrency, 2 admins changing same app, lock contention and expired approvals.
- [ ] P7.05 Disaster tests: full disk, lost Redis, stale TLS cert, Loki unavailable, backup repo unavailable, aborted deploy.
- [ ] P7.06 Load-test target fleet size and log volume based on available lab resources; report actual limits and sizing, do not assert arbitrary scale.
- [ ] **TEST P7-T01:** old workloads continue serving during Center downtime.
- [ ] **TEST P7-T02:** destructive jobs never silently replay after reconnect.
- [ ] **TEST P7-T03:** secrets not printed in terminal/API/UI/audit; unauthorized cross-project access denied.
- [ ] **TEST P7-T04:** failed Nginx apply does not strand active config and has tested revert.
- [ ] **GATE P7:** critical/high security issues fixed or explicitly block release; recovery evidence available.

### P8 — Release, install, upgrade and docs
- [ ] P8.01 Versioned Center installer (`docker compose`) and Agent installer (signed binary checksums, systemd, enrollment); least privileges documented.
- [ ] P8.02 `.env.example`, secrets bootstrap, network/firewall prerequisites, certificate enrollment, volume mounts.
- [ ] P8.03 Automated CI: typecheck/lint/unit/integration/security scans/build; Playwright E2E in isolated lab.
- [ ] P8.04 Versioned migrations, upgrade test and safe rollback procedure for Center/Agent; mixed-version compatibility policy.
- [ ] P8.05 Operator guides: enroll, import, deploy, auto deploy, TLS/Nginx, logs, alerts, backup, restore, emergency recovery.
- [ ] P8.06 Final acceptance matrix, release notes, known limitations and evidence package.
- [ ] **TEST P8-T01:** clean install on fresh Ubuntu lab VM; enroll 2 nodes; execute smoke suite.
- [ ] **TEST P8-T02:** upgrade from previous test version retains projects/config/backup metadata; rollback recovery path documented.
- [ ] **TEST P8-T03:** end-to-end J01–J12 user journeys executed and linked to logs/videos/reports as available.
- [ ] **GATE P8 = MVP-B RELEASE CANDIDATE:** no untested critical path; limitations/blocked externals disclosed.

---

## 8. End-to-end acceptance matrix (link to evidence)

| ID | Scenario | Expected | Status |
|---|---|---|---|
| E2E-01 | First boot + 2FA | secure admin setup | NOT RUN |
| E2E-02 | Enroll 3 agents | nodes visible, reconnect works | NOT RUN |
| E2E-03 | Import existing Nginx | no config changes or downtime | NOT RUN |
| E2E-04 | Invalid Nginx change | preflight blocks reload | NOT RUN |
| E2E-05 | GitHub Next.js deploy | healthy app via HTTPS | NOT RUN |
| E2E-06 | NestJS secrets | no leakage, app starts | NOT RUN |
| E2E-07 | Laravel + DB Compose | persistent data survives redeploy | NOT RUN |
| E2E-08 | GitHub auto deploy | single job per commit under rules | NOT RUN |
| E2E-09 | Broken release | stable app preserved/reverted | NOT RUN |
| E2E-10 | Center outage | managed apps remain up | NOT RUN |
| E2E-11 | Agent reconnect | no replay of stale privileged job | NOT RUN |
| E2E-12 | Central logs | scoped search and sanitization | NOT RUN |
| E2E-13 | Fleet monitoring alert | actionable alert and acknowledgment | NOT RUN |
| E2E-14 | Backups | file/DB restored and verified | NOT RUN |
| E2E-15 | Center disaster recovery | center state recoverable | NOT RUN |
| E2E-16 | Unauthorized operation | denied and audited | NOT RUN |
| E2E-17 | Clean Ubuntu install | scripted deploy repeatable | NOT RUN |
| E2E-18 | Center/agent upgrade | data/config preserved | NOT RUN |

### Suggested commands (adapt to actual scripts, do not fabricate output)

```bash
# Only after implementing these scripts/configs
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm test:e2e

go test ./... -race -cover

docker compose -f infra/compose/lab.yml config --quiet
docker compose -f infra/compose/lab.yml up -d
# Run explicit curl/health/smoke scripts supplied by the project
# Keep all lab tests sandboxed; no public production mutations.
```

CI should always fail on lint/typecheck/test errors, schema migration drift, known critical vulnerabilities according to release policy, secret leaks and unexpected privileged permissions.

---

## 9. Quality gates, nonfunctional requirements and observability

- All sensitive actions authenticated, authorized, audited; 2FA for privileged production operations.
- Every remote command has durable job ID, scoped task grant, TTL, idempotency and state/lock recheck.
- Agent loss and Center outage do not terminate running applications.
- Import in Discover/Observe is *actually* read-only as verified by filesystem checksums and process stability.
- Explicit `unknown/stale/offline` states instead of false healthy data.
- Scope-specific secrets/log access with no plaintext leakage in UI or events.
- Domain, port, mounts, image trust, storage and Nginx syntax preflight.
- Tested file/DB restore; database rollback limitations explicitly documented.
- Cross-host failure visibility: trace/correlation IDs shared across UI/API/worker/agent.
- API documentation/OpenAPI generated and versioned; agent protocol backwards compatibility specified.
- User-facing docs and scripts can be followed on a clean host; no hidden manual steps.

---

## 10. Suggested execution tracking files

`docs/IMPLEMENTATION_STATUS.md` example:

```markdown
# Status
Current phase: P0
Last verified revision: <commit>

| Task ID | Status | Change/PR | Test command | Evidence | Notes |
|---|---|---|---|---|---|
| P0.01 | TODO | | | | |

## Blockers
- None recorded

## Next atomic task
- P0.01
```

`docs/TEST_REPORT.md` example:

```markdown
| Test ID | Environment | Command/Scenario | Expected | Actual | Result | Evidence |
|---|---|---|---|---|---|---|
| P0-T01 | Lab | pnpm lint | exit 0 | NOT RUN | NOT RUN | |
```

Record schema migration/upgrade risk, secret handling, compatibility and rollback steps as ADR/runbook artifacts. Every failed test must link to an issue or corrective TODO and be rerun.

---

## 11. Coordination contract with Claude Design

- Design owns screen routes, components, interaction/approval patterns and UX state matrices.
- Code owns API contracts, security enforcement, domain model, tests and production behavior.
- Shared vocabulary: `server`, `application`, `project`, `environment`, `discovery`, `adoption`, `deployment`, `backup`, `restore`, `approval`, `audit`.
- Frontend must derive capability/button availability from actual server policy and API authorization, not just hide buttons based on UI role.
- If Design proposes a screen that cannot be supported safely by backend, record a discrepancy and implement a clearly labeled unsupported state rather than fake success.

---

## 12. Required response format after EVERY task and phase

```text
Phase / Task ID:
Files changed:
Behavior implemented:
Tests actually executed (exact commands):
Test results (PASS/FAIL/BLOCKED/NOT RUN):
Evidence (logs, paths, URLs, screenshots):
Security/production risks:
Outstanding TODOs:
Next atomic task:
```

**Do not report full completion** until all MVP-A and MVP-B release gates have actually passed and E2E evidence is attached. If time/context/tools are limited, persist status, finish the current safe atomic unit and stop with a precise resumable next task.

**START NOW:** Inspect the current repo and environment, implement P0, run P0 tests, update tracking docs and continue into P1 if the gate passes. Never deploy to live production without permission.


---

## 13. Consolidated v3.0 expansion and precedence

This section **supersedes earlier deferrals when inconsistent**. Preserve P0–P8 as core milestones; add P9–P14 below and treat each as gated. User-required additions: **server card view, English default/Thai optional, Production/UAT/Development groups, public/private IP, DigitalOcean VPC, central SSH by public key, host + shared firewalls, software/plugin marketplace, runtimes/databases and an MCP server for AI-controlled operations**.

### 13.1 Revised targets and network assumptions

- DigitalOcean Droplets are in the same **region** and currently have private IPs; user has successfully pinged across their private addresses. **Do not infer shared VPC UUID from ping alone**. Verify real VPC UUIDs and routes read-only through DigitalOcean API (if credentials available) or from a user-provided inventory; VPC peering might already exist.
- No DNS, public IP, netplan, default route, Nginx, host firewall or DO Cloud Firewall changes on existing production nodes without explicit scoped authorization, a preflight and recovery plan.
- Use existing private connectivity for Center↔Agent and gateway↔backends when available. Keep public connectivity only where required; Private-only must fail closed instead of silently falling back to Public.
- **Control Plane and optional Gateway are independent processes**: dedicated Gateway Droplet recommended for production, stateless routing config resilient to Center outage. Initially support Direct/Hybrid/Gateway per domain; cutover uses shadow-test, TLS, routing, health verification, rollout/rollback. No blanket promise of zero downtime for DNS cutover.
- Agent uses **outbound-initiated TLS/mTLS**, not publicly exposed inbound shell. Distinguish management transport path from app routing and SSH gateway path.

### 13.2 Additional domain entities / contracts

Implement or migrate entities and API schemas for:

`ServerGroup`, `ServerAddress`, `NetworkInterface`, `NetworkConnectivityTest`, `ProviderIntegration`, `Gateway`, `GatewayRoute`, `GatewayChangePlan`, `SSHCredential`, `SSHHostKey`, `SSHAccessGrant`, `SSHSession`, `FirewallBackend`, `FirewallPolicy`, `FirewallPolicyVersion`, `FirewallAssignment`, `FirewallRule`, `FirewallChangeJob`, `PluginManifest`, `PluginRelease`, `PluginInstallation`, `RuntimeInstallation`, `RuntimeBinding`, `DatabaseInstance`, `DatabaseCredentialRef`, `MCPClient`, `MCPIdentity`, `MCPToolPermission`, `MCPToolInvocation`, `AIAutomationPolicy`, `ApprovalRequest`, `ApprovalDecision`, `AIAuditEvent`.

- Refer to existing Server, User, Application, Deployment, Job and Audit entities; do not create duplicate sources of truth.
- Contracts use stable typed IDs, scoped server/project/environment IDs, expected version/ETag for writes, job ID, correlation ID, idempotency key and secret references (not secret values in read responses).
- Add **`docs/FEATURE_MATRIX.md`**, mapping `feature_id → UI screen → API → Agent capability → permissions → phase → test IDs → evidence`.

## 14. Security reference implementation constraints

1. **No generic root command execution via MCP or Agent.** Allowed operations are typed command handlers with validated arguments; plugin package installation uses trusted manifests/adapters and strict OS/package allowlists.
2. **Central SSH for humans only**: browser ↔ authenticated WebSocket over HTTPS ↔ Center SSH gateway ↔ server `sshd`; support public-key authentication; encrypted private keys remain in backend secret store (or approved HSM/KMS), never returned to browser. Verify pinned/approved host keys, block mismatch; scoped server/user/port, expiring grant, MFA/approval for Production, idle timeout, session limits, audit; protect against SSH/WS origin and CSRF-like abuses. Do not log keystrokes by default; recording requires explicit policy and retention.
3. **Firewall policy safety**: host adapters UFW/nftables and DigitalOcean Cloud Firewall adapter separately; preserve existing rules on import; read/normalize/diff then dry-run, enforce management-path reachability, commit with independent timed rollback mechanism and post-apply probe. Restore previous rules on timeout/failure. Canary fleet rollout before Production. Do not execute unsafe generic rules from user/plugin/AI free text.
4. **MCP remote access**: official MCP SDK, validated negotiated protocol version, Streamable HTTP transport, OAuth 2.x resource-server semantics for clients where supported, audience and issuer checks, least-privilege scopes, origin validation, rate limits, request size limits, anti-CSRF controls as appropriate, revocation, structured logging and protocol conformance tests. Never pass bearer tokens through query strings, logs or to managed Agents. If interoperable OAuth cannot be configured in the lab, mark external auth E2E BLOCKED; do not replace it silently with an unsafe production-wide static token.
5. **Prompt injection boundary**: retrieved code, logs, websites, MCP tool results, manifests and generated AI plans are untrusted data. Policy engine validates every mutation independently of agent instructions or tool annotations.
6. **Approval binding**: approval is single-use, time-bound, bound to exact actor, action, immutable commit/image digest, target, expected version and plan hash; a changed plan requires new approval. Only authenticated human policy-approved actors approve Production mutations. Telegram notifications link to W3 Dashboard, not approval by mere message receipt.
7. Sensitive operations include backup restore, firewall modifications, plugin system package changes, sshd modification, server reboot/shutdown, production deployments, network cutover, DB permissions and secret rotation. Provide risk categorization and safe defaults.

## 15. MCP tools and automation contract

Build `apps/mcp/` as a distinct adapter or well-isolated module exposing **the same Center application services** as the UI. **Do not implement a second Deployment Engine.** All writes are jobs; clients poll for status, fetch bounded/redacted logs and use server-side permissions.

### 15.1 Tool groups (stable canonical names)

| Area | Read / plan tools | Mutation tools (policy gated) |
|---|---|---|
| Fleet | `w3_servers_list`, `w3_server_get`, `w3_server_health`, `w3_server_network`, `w3_network_diagnostics` | `w3_server_restart_service` |
| Deploy | `w3_deployment_plan`, `w3_deployment_validate`, `w3_deployment_status`, `w3_deployment_logs`, `w3_deployment_history` | `w3_deployment_create`, `w3_deployment_rollback` |
| Operations | `w3_monitoring_summary`, `w3_monitoring_alerts`, `w3_logs_query`, `w3_incident_diagnose` | No unreviewed repair shell |
| Firewall | `w3_firewall_rules_list`, `w3_firewall_policy_list`, `w3_firewall_plan`, `w3_firewall_validate` | `w3_firewall_apply`, `w3_firewall_rollback` |
| Backups | `w3_backup_list`, `w3_backup_status`, `w3_restore_plan` | `w3_backup_create`, `w3_restore_execute` |
| Plugins | `w3_plugins_list`, `w3_plugin_details`, `w3_plugin_install_plan`, `w3_plugin_status` | `w3_plugin_install`, `w3_plugin_update`, `w3_plugin_uninstall` |
| Runtime/DB | `w3_runtime_list`, `w3_database_status` | `w3_runtime_install` (approved) |
| SSH | `w3_ssh_connection_status`, `w3_ssh_test_connection`, `w3_ssh_credentials_list_metadata` | **No arbitrary interactive shell exposed to MCP** |
| Approvals | `w3_approval_status`, `w3_operations_job_status` | `w3_approval_request` (requests only, no self-approval) |

Return structured `job_id`, `status`, `resource_id`, `required_approval`, `expires_at`, `correlation_id`, safe error category and optional progress. Define schemas (Zod/JSON Schema) for all tools; resource scope checks are per-tool **and** per-entity **and** per-execution.

### 15.2 Policy examples

- Agent with `servers:read`, `logs:read` → diagnosis only; cannot mutate.
- `deploy:uat` + scoped project/server → UAT deploy after build/test, health checks and locks, auto rollback where safe.
- `deploy:production` alone is **insufficient**: human approval bound to plan and immutable artifact required for production writes.
- `firewall:write`, `plugins:install`, `restore:execute` additionally require risk policy and approval; avoid broad `admin:*` AI defaults.
- No auto fallback from failed private management route to public SSH without explicit policy approval and audit.

### 15.3 Automated deployment pipeline

`GitHub signed webhook → dedupe event → resolve immutable SHA → build/test (isolated runner) → signed/pinned artifact → plan & preflight → UAT deploy → health/log smoke tests → production approval (if requested) → production deploy → verification/rollback → audit/notification`.

Do not trust README, workflow text, commit messages or AI-generated instructions to change permissions. Keep secret access per job, environment and target. Cancel stale jobs on revoked scopes or changed target state.

## 16. Additional implementation phases and evidence-based gates

### P9 — DigitalOcean private networking and card/group API
- [ ] P9-01 Inventory real private/public endpoints, VPC UUID and public DNS; optional read-only DO provider integration.
- [ ] P9-02 Build `ServerGroup` (Production/UAT/Development) + tags and server card API fields.
- [ ] P9-03 Build connection preference policy with verified private/public health and fail-closed Private-only.
- [ ] P9-04 Network diagnostics without modifying OS configuration, public IP or routes.
- [ ] P9-05 Per-domain Direct/Hybrid/Gateway routing plan and dedicated Gateway config adapter (shadow test only before cutover).
- [ ] P9-T1 Same-region/different-VPC inventory is detected rather than assumed; verify route in a lab.
- [ ] P9-T2 Private offline with Private-only refuses public fallback.
- [ ] P9-T3 Center outage leaves existing Gateway routing/workloads unchanged.
- [ ] P9-T4 Shadow-test via host/SNI override before DNS; rollback plan documented.
**Gate:** no production route changes; network diagnosis and Gateway routing isolated and repeatable.

### P10 — Secure central SSH gateway
- [ ] P10-01 Browser WebSocket terminal gateway, pty resize, disconnect/idle handling and per-session limits.
- [ ] P10-02 SSH key enrollment/rotation/revoke; encrypted key storage and never exposing private material to browser.
- [ ] P10-03 SSH host-key verification and mandatory mismatch block.
- [ ] P10-04 Per-server user/endpoint policy, RBAC, MFA and Production approvals.
- [ ] P10-05 SSH access metadata auditing without unconditional terminal recording.
- [ ] P10-T1 Legitimate approved key opens a session on disposable VM.
- [ ] P10-T2 Revoked key, unauthorized server, expired grant and changed host key are denied.
- [ ] P10-T3 XSS/WebSocket hijack tests cannot obtain private SSH keys.
- [ ] P10-T4 Session expires cleanly without leaking credentials or orphaned process.
**Gate:** terminal only through Center SSH gateway; never arbitrary MCP shell.

### P11 — Federated firewall policies and safe changes
- [ ] P11-01 Implement distinct host and DO Cloud Firewall adapters with capability flags.
- [ ] P11-02 Read-only rule discovery, immutable policy versioning, diff, drift detection and group assignment.
- [ ] P11-03 Preflight risk and protected management path validator.
- [ ] P11-04 Timed rollback outside request lifecycle + canary apply + per-server verification.
- [ ] P11-05 Implement safe partial-failure reconciliation, human approval and audit.
- [ ] P11-T1 Rule proposal blocking Center/SSH fails before apply.
- [ ] P11-T2 Simulated disconnect after apply triggers timed rollback.
- [ ] P11-T3 Production shared policy requires approval and canary.
- [ ] P11-T4 External drift is surfaced without silently overwriting existing rules.
**Gate:** management lockout is prevented or deterministically recovered in lab.

### P12 — Trusted plugin catalog, runtimes and DB operations
- [ ] P12-01 Signed/verified manifest schema, source trust list, explicit capabilities/dependencies/OS support.
- [ ] P12-02 Plugin preflight (OS, disk, ports, package conflicts, existing services) and structured install/verify/uninstall jobs.
- [ ] P12-03 Implement first adapters **Fail2ban, Docker Engine/Compose, Node.js, PHP/PHP-FPM, PostgreSQL**; subsequent catalog entries listed but **unsupported** until tested.
- [ ] P12-04 Runtime inventory/version changes and server-wide vs app-scoped policy.
- [ ] P12-05 Database lifecycle via narrowly scoped adapters, secret refs, backups and isolated restore tests.
- [ ] P12-T1 Fail2ban install/verify/restart on disposable supported VM.
- [ ] P12-T2 Unsupported distro/version, dependency conflict, and occupied port produce safe failures.
- [ ] P12-T3 Package operations cannot inject untrusted shell commands.
- [ ] P12-T4 PostgreSQL provision → backup → isolated restore; no public DB port exposed.
**Gate:** only verified adapters appear as installable; failed installs report state and recovery instructions.

### P13 — MCP Server, read tools, approvals and AI Deploy
- [ ] P13-01 Implement `apps/mcp` and protocol conformance for Streamable HTTP using current official SDK.
- [ ] P13-02 OAuth/token scopes, client binding, revocation, rate limits, Origin and input/schema validation.
- [ ] P13-03 Implement read-only tools first, permission-filtered tool discovery and audit.
- [ ] P13-04 Tool adapters to existing Center services with structured error codes, pagination and redaction.
- [ ] P13-05 Approval Engine binding exact plan hash, immutable artifact, resource scope and expiration.
- [ ] P13-06 UAT deployment MCP flow; production request/approval → deploy → verify/rollback.
- [ ] P13-07 MCP operations UI: clients, tools, scopes, automation policies, approvals, job timeline.
- [ ] P13-T1 Anonymous/expired/wrong-audience and forbidden scopes denied.
- [ ] P13-T2 AI with UAT scope cannot deploy Production even using direct tool invocation.
- [ ] P13-T3 Modified commit after approval invalidates grant; AI cannot self-approve.
- [ ] P13-T4 Replayed webhook and duplicate MCP action do not create duplicate deploy.
- [ ] P13-T5 Prompt injection inside Git repo/logs cannot change production policy.
- [ ] P13-T6 Claude Code/Codex or spec-compatible test MCP client can discover read tools and create authorized UAT job (when client credentials supplied); otherwise `BLOCKED`.
**Gate:** MCP is an adapter, not an alternate ungoverned management path.

### P14 — Integrated security, UX parity and production certification
- [ ] P14-01 Cross-reference `docs/FEATURE_MATRIX.md` with design IDs D0–D10 and API/agent/test IDs.
- [ ] P14-02 English default and Thai optional UI with locale coverage tests.
- [ ] P14-03 End-to-end fleet: enroll → private path → legacy import → deploy → logs → backup → restore drill.
- [ ] P14-04 End-to-end privileged: SSH MFA → firewall canary → plugin install → AI UAT → Production approval.
- [ ] P14-05 Faults: Center down, Agent offline, job redelivery, Gateway unavailable, storage full, revoked client, host key mismatch, firewall lockout recovery.
- [ ] P14-06 Install/upgrade/migration and disaster-recovery runbooks, SLO targets measured in lab.
- [ ] P14-T1 Production websites remain accessible during Center/Agent downtime (Gateway operational).
- [ ] P14-T2 Gateway failure is correctly documented as potential outage; HA is not claimed without a working failover ingress design.
- [ ] P14-T3 No private keys, API tokens or database passwords in API payloads, logs or MCP tool outputs.
- [ ] P14-T4 All high-risk production mutations show approval, audit and reconciliation.
**Gate:** deployable release only after all mandatory security, migration and restore acceptance tests pass; exceptions must be explicit sign-off, never hidden.

## 17. Test harness, reproducibility and reporting

Recommended scripts (implement for actual stack; commands are targets, not assertions that scripts already exist):

```bash
pnpm lint && pnpm typecheck && pnpm test
pnpm test:integration
pnpm test:e2e
cd apps/agent && go test ./... -race
# optional dedicated lab security and chaos suites
pnpm test:security
pnpm test:chaos
```

All privileged/network-changing E2E tests run only in an **isolated disposable VM/VPC lab** unless user authorizes a specific production change. Use safe mocked DO API and mocked MCP/OAuth issuer tests for CI. Keep verification artifacts (JUnit, structured logs, screenshots, metrics and pre/post state diffs). Never fabricate external cloud/credential validations.

Acceptance states: `TODO | IN_PROGRESS | PASS | FAIL | BLOCKED | NOT_APPLICABLE`; `PASS` requires executed evidence (command/time/commit/target/artifact). `BLOCKED` requires missing prerequisite, affected scope and exact next action. Prevent concurrent state-changing work without target locks.

## 18. Required output structure / cross-team deliverables

- `docs/ARCHITECTURE.md` and `docs/NETWORK_TOPOLOGY.md` (Center/Gateway separation, VPC evidence, routing and rollback)
- `docs/FEATURE_MATRIX.md`, `docs/API_CONTRACTS.md`, `docs/AGENT_PROTOCOL.md`, `docs/SECURITY_THREAT_MODEL.md`
- `docs/SSH_SECURITY.md`, `docs/FIREWALL_POLICY.md`, `docs/PLUGIN_SPEC.md`, `docs/RUNTIME_ADAPTERS.md`
- `docs/MCP_ARCHITECTURE.md`, `docs/MCP_TOOL_CATALOG.md`, `docs/MCP_AUTH.md`, `docs/MCP_CLIENT_SETUP.md`, `docs/AI_APPROVAL_POLICY.md`
- `docs/IMPLEMENTATION_STATUS.md`, `docs/TEST_REPORT.md`, `docs/SECURITY_TEST_REPORT.md`, `docs/DECISIONS.md`, `docs/RISKS.md`
- `docs/DEPLOYMENT_RUNBOOK.md`, `docs/MIGRATION_RUNBOOK.md`, `docs/RECOVERY_RUNBOOK.md`, `docs/UPGRADE_RUNBOOK.md`
- Source for Center, Gateway config controller, Agent, Web SSH terminal, host/DO Firewall adapters, Plugin adapters, MCP adapter and AI Operations UI.

### Mandatory Claude Code operating loop

1. Read both consolidated briefs and current repo; detect existing `W3 Server Panel.dc.html` and coordinate contracts with designer.
2. Create/update feature matrix and dependency map; execute phase order P0–P14, with P9–P13 safely staged as adjacent services become available.
3. For each TODO: implement minimal working slice → unit test → integration test → targeted E2E → check permissions/error states → record evidence → mark status.
4. Never modify production hosts, DNS, Cloud Firewalls, routes, SSH service, backup data or billable infrastructure without explicit authorization.
5. After each phase provide completed IDs, test commands/results, live blockers, changed files, known risks and next atomic TODO.
6. Continue unfinished unblocked tasks until scope is complete; do not turn TODO lists into fake `PASS` entries.

**Definition of Done:** The same guarded Center APIs drive web UI and MCP tools; live operations are policy-controlled and auditable, existing Nginx applications remain operational on import, supported plugins and SSH work through secured adapters, and the Center can manage multiple DigitalOcean servers over verified private endpoints while not becoming a compulsory runtime dependency for existing workloads.
