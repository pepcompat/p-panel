# Status

> Tracking skeleton created in P0 (2026-11-17). **Maintained by the lead.** States: `TODO | IN_PROGRESS | PASS | FAIL | BLOCKED | NOT_APPLICABLE` (brief §17). PASS requires executed evidence.

Current phase: P3 (UI finishing)
Last verified revision: (no commits yet)

## P0

| Task ID | Status | Change/PR | Test command                            | Evidence                                            | Notes                                                                                                                                 |
| ------- | ------ | --------- | --------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| P0.01   | PASS   |           |                                         | docs/BASELINE.md                                    | Inspect repo, dependencies, tooling, deployment constraints, and existing assets; record baseline and no-touch rules.                 |
| P0.02   | TODO   |           |                                         |                                                     | Incorporate Claude Design screen contracts; where unavailable, implement minimal functional UI and track open design dependencies.    |
| P0.03   | PASS   |           | GitHub Actions ci.yml                   | run 45103621625 all 4 jobs green (2026-11-23)       | Initialize monorepo, conventions, lint/format/typecheck, CI skeleton, lockfiles, `.env.example` without secrets.                      |
| P0.04   | PASS   |           | scripts/lab/up.sh, smoke.sh, down.sh x3 | smoke 17/17; containers ≠ VMs (infra/lab/README.md) | Start lab Center + 2 disposable nodes or documented local VM/container approximations; label limitations of containers vs actual VMs. |
| P0.05   | PASS   |           |                                         | docs/SECURITY_THREAT_MODEL.md, docs/adr/0001-0007   | Record threat model, trust boundaries, operation classifications and ADRs.                                                            |

Phase tests: P0-T01, P0-T02 (see `TEST_REPORT.md`) · Gate: TODO

## P1

| Task ID | Status      | Change/PR | Test command                                | Evidence                                                           | Notes                                                                                                      |
| ------- | ----------- | --------- | ------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| P1.01   | PASS        |           | pnpm --filter @ppanel/api test:integration  | apps/api/prisma/migrations/20261117102042_init                     | PostgreSQL schema/migrations; seed least-privilege first admin via secure setup.                           |
| P1.02   | PASS        |           | pnpm --filter @ppanel/api test:integration  | auth.spec 69/69 integration total                                  | Login, session, password hashing, MFA/TOTP + recovery codes, API auth, scoped RBAC, CSRF where applicable. |
| P1.03   | PASS        |           | cd apps/agent && go test ./... -race -cover | 15 pkgs PASS, 67.8% cov; systemd unit not verified on real systemd | Agent Go binary, systemd packaging, config validation, lifecycle.                                          |
| P1.04   | PASS        |           | integration P1-T01/T02 + lab E2E            | docs/evidence/2026-11-17                                           | One-use short TTL enrollment, peer identity, mTLS, rotation/revocation.                                    |
| P1.05   | PASS        |           | lab E2E heartbeat over mTLS :4443           | docs/evidence/2026-11-17 e2e-servers.json                          | Outbound stream/poll, heartbeat, capabilities, no inbound public management listener.                      |
| P1.06   | IN_PROGRESS |           |                                             | backend PASS (servers/users/audit); UI by apps/web                 | Server registry UI and audit events.                                                                       |

Phase tests: P1-T01, P1-T02, P1-T03, P1-T04 (see `TEST_REPORT.md`) · Gate: TODO

## P2

| Task ID | Status      | Change/PR | Test command                                | Evidence                                                     | Notes                                                                                         |
| ------- | ----------- | --------- | ------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| P2.01   | PASS        |           | pnpm --filter @ppanel/api test:integration  | jobs.spec                                                    | Typed job schema, idempotency keys, task lease/TTL, timeout, cancellation, audit correlation. |
| P2.02   | PASS        |           | go test ./internal/jobs ./internal/handlers | typed allowlist, no shell                                    | Agent allowlisted handlers, input schema validation and local authority boundaries.           |
| P2.03   | IN_PROGRESS |           |                                             | agent inventory.collect done; Center inventory views pending | Host CPU/RAM/Disk/Network, Docker/container, systemd, Nginx/PHP inventory.                    |
| P2.04   | TODO        |           |                                             |                                                              | UI fleet list/detail, stale/offline states, job progress/events.                              |
| P2.05   | IN_PROGRESS |           |                                             | locks + lease durability PASS; reboot reconciliation pending | Resource ownership + concurrency locks; auto-reconciliation after reboot/disconnect.          |

Phase tests: P2-T01, P2-T02, P2-T03, P2-T04 (see `TEST_REPORT.md`) · Gate: TODO

## P3

| Task ID | Status      | Change/PR | Test command                                    | Evidence                                                                           | Notes                                                                                                                         |
| ------- | ----------- | --------- | ----------------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| P3.01   | PASS        |           | go test ./internal/nginx; scripts/lab/e2e_p3.py | docs/evidence/2026-11-23/p3-e2e.json                                               | Scanner for `nginx -T` effective config, server blocks, includes, domains, roots, upstream and SSL references.                |
| P3.02   | PASS        |           | lab scan                                        | docs/evidence/2026-11-23/p3-e2e.json (docker/systemd unavailable in container lab) | Docker/Compose/PHP-FPM/systemd/process/port discovery; provenance and confidence.                                             |
| P3.03   | PASS        |           | pnpm --filter @ppanel/api test:integration      | discovery-nginx.spec + docs/evidence/2026-11-23/p3-e2e.json                        | Model scan snapshots, unsupported directives and collisions; no config mutation.                                              |
| P3.04   | IN_PROGRESS |           |                                                 | backend PASS (import/ownership); UI by apps/web                                    | Import UI: Preview, mappings, Observe default, Adopt/Managed with explicit permissions.                                       |
| P3.05   | PASS        |           | go test ./internal/nginxops; e2e_p3.py          | docs/evidence/2026-11-23/p3-e2e.json; docs/evidence/2026-11-23/agent-nginx-lab     | Safe supported Nginx operations: file snapshot, diff, syntax validation, apply/reload, postcheck and revert; drift detection. |

Phase tests: P3-T01, P3-T02, P3-T03, P3-T04, P3-T05 (see `TEST_REPORT.md`) · Gate: TODO

## P4

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                           |
| ------- | ------ | --------- | ------------ | -------- | --------------------------------------------------------------------------------------------------------------- |
| P4.01   | TODO   |           |              |          | GitHub App integration with scoped repo permissions, webhook signature/replay protection, commit SHA pinning.   |
| P4.02   | TODO   |           |              |          | Registry image deploy; Dockerfile build on separated/constrained builder; safe Compose parser/policy validator. |
| P4.03   | TODO   |           |              |          | Framework detection Next.js/NestJS/Laravel/Dockerfile/Compose; explicit override.                               |
| P4.04   | TODO   |           |              |          | Full wizard APIs and UI: source, runtime, server, env/secrets, domain, preflight, review, progress.             |
| P4.05   | TODO   |           |              |          | Nginx route management, TLS approach, DNS/port collision checks; preserve existing Nginx.                       |
| P4.06   | TODO   |           |              |          | Deployment history, immutable artifact digest, per-step logs, application healthchecks.                         |
| P4.07   | TODO   |           |              |          | Rollback for supported stateless deployments; Compose/native limitations prominently documented.                |
| P4.08   | TODO   |           |              |          | Branch rules, auto-deploy, prod approval and per-app deploy locks.                                              |

Phase tests: P4-T01, P4-T02, P4-T03, P4-T04, P4-T05, P4-T06, P4-T07 (see `TEST_REPORT.md`) · Gate: TODO

## P5

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                         |
| ------- | ------ | --------- | ------------ | -------- | --------------------------------------------------------------------------------------------- |
| P5.01   | TODO   |           |              |          | Deploy/secure Alloy, Prometheus, Loki; define retention and size limits.                      |
| P5.02   | TODO   |           |              |          | Fleet/server/application charts and status, last-known sample with stale marker.              |
| P5.03   | TODO   |           |              |          | Central log search/live tail by server/app/source/time/severity; role-scoped queries.         |
| P5.04   | TODO   |           |              |          | Secret redaction, query rate limits, retention, stream backpressure and limited buffering.    |
| P5.05   | TODO   |           |              |          | Alert rule CRUD, incidents, Telegram/email/webhook channel validation and test notifications. |

Phase tests: P5-T01, P5-T02, P5-T03, P5-T04 (see `TEST_REPORT.md`) · Gate: TODO

## P6

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                   |
| ------- | ------ | --------- | ------------ | -------- | ------------------------------------------------------------------------------------------------------- |
| P6.01   | TODO   |           |              |          | Restic encrypted repository integration with controlled credentials and independent delete policy.      |
| P6.02   | TODO   |           |              |          | File/volume backups and DB-native logical dumps with transaction-consistent settings.                   |
| P6.03   | TODO   |           |              |          | Backup policy UI/API: schedules, timezone, exclusions, retention, destination/offsite status.           |
| P6.04   | TODO   |           |              |          | Snapshot list, validation, manifest and job logs; mark verification levels accurately.                  |
| P6.05   | TODO   |           |              |          | Restore wizard: target, impact, dry-run, approval, staged restore, integrity and application postcheck. |
| P6.06   | TODO   |           |              |          | Center DB + config + encryption-key recovery runbook and separate recovery storage.                     |

Phase tests: P6-T01, P6-T02, P6-T03, P6-T04, P6-T05 (see `TEST_REPORT.md`) · Gate: TODO

## P7

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                                                        |
| ------- | ------ | --------- | ------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| P7.01   | TODO   |           |              |          | Threat-model tests: IDOR, broken access control, CSRF, XSS, SSRF, injection, path traversal, webhook spoof/replay, secret leakage.           |
| P7.02   | TODO   |           |              |          | Agent permission boundaries and policy bypass attempts; Compose/config allowlist fuzz tests.                                                 |
| P7.03   | TODO   |           |              |          | Center 10-minute outage while apps serve traffic; agent reconnect and reconcile.                                                             |
| P7.04   | TODO   |           |              |          | Deploy concurrency, 2 admins changing same app, lock contention and expired approvals.                                                       |
| P7.05   | TODO   |           |              |          | Disaster tests: full disk, lost Redis, stale TLS cert, Loki unavailable, backup repo unavailable, aborted deploy.                            |
| P7.06   | TODO   |           |              |          | Load-test target fleet size and log volume based on available lab resources; report actual limits and sizing, do not assert arbitrary scale. |

Phase tests: P7-T01, P7-T02, P7-T03, P7-T04 (see `TEST_REPORT.md`) · Gate: TODO

## P8

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                                                          |
| ------- | ------ | --------- | ------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| P8.01   | TODO   |           |              |          | Versioned Center installer (`docker compose`) and Agent installer (signed binary checksums, systemd, enrollment); least privileges documented. |
| P8.02   | TODO   |           |              |          | `.env.example`, secrets bootstrap, network/firewall prerequisites, certificate enrollment, volume mounts.                                      |
| P8.03   | TODO   |           |              |          | Automated CI: typecheck/lint/unit/integration/security scans/build; Playwright E2E in isolated lab.                                            |
| P8.04   | TODO   |           |              |          | Versioned migrations, upgrade test and safe rollback procedure for Center/Agent; mixed-version compatibility policy.                           |
| P8.05   | TODO   |           |              |          | Operator guides: enroll, import, deploy, auto deploy, TLS/Nginx, logs, alerts, backup, restore, emergency recovery.                            |
| P8.06   | TODO   |           |              |          | Final acceptance matrix, release notes, known limitations and evidence package.                                                                |

Phase tests: P8-T01, P8-T02, P8-T03 (see `TEST_REPORT.md`) · Gate: TODO

## P9

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                                 |
| ------- | ------ | --------- | ------------ | -------- | --------------------------------------------------------------------------------------------------------------------- |
| P9-01   | TODO   |           |              |          | Inventory real private/public endpoints, VPC UUID and public DNS; optional read-only DO provider integration.         |
| P9-02   | TODO   |           |              |          | Build `ServerGroup` (Production/UAT/Development) + tags and server card API fields.                                   |
| P9-03   | TODO   |           |              |          | Build connection preference policy with verified private/public health and fail-closed Private-only.                  |
| P9-04   | TODO   |           |              |          | Network diagnostics without modifying OS configuration, public IP or routes.                                          |
| P9-05   | TODO   |           |              |          | Per-domain Direct/Hybrid/Gateway routing plan and dedicated Gateway config adapter (shadow test only before cutover). |

Phase tests: P9-T1, P9-T2, P9-T3, P9-T4 (see `TEST_REPORT.md`) · Gate: TODO

## P10

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                     |
| ------- | ------ | --------- | ------------ | -------- | --------------------------------------------------------------------------------------------------------- |
| P10-01  | TODO   |           |              |          | Browser WebSocket terminal gateway, pty resize, disconnect/idle handling and per-session limits.          |
| P10-02  | TODO   |           |              |          | SSH key enrollment/rotation/revoke; encrypted key storage and never exposing private material to browser. |
| P10-03  | TODO   |           |              |          | SSH host-key verification and mandatory mismatch block.                                                   |
| P10-04  | TODO   |           |              |          | Per-server user/endpoint policy, RBAC, MFA and Production approvals.                                      |
| P10-05  | TODO   |           |              |          | SSH access metadata auditing without unconditional terminal recording.                                    |

Phase tests: P10-T1, P10-T2, P10-T3, P10-T4 (see `TEST_REPORT.md`) · Gate: TODO

## P11

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                              |
| ------- | ------ | --------- | ------------ | -------- | -------------------------------------------------------------------------------------------------- |
| P11-01  | TODO   |           |              |          | Implement distinct host and DO Cloud Firewall adapters with capability flags.                      |
| P11-02  | TODO   |           |              |          | Read-only rule discovery, immutable policy versioning, diff, drift detection and group assignment. |
| P11-03  | TODO   |           |              |          | Preflight risk and protected management path validator.                                            |
| P11-04  | TODO   |           |              |          | Timed rollback outside request lifecycle + canary apply + per-server verification.                 |
| P11-05  | TODO   |           |              |          | Implement safe partial-failure reconciliation, human approval and audit.                           |

Phase tests: P11-T1, P11-T2, P11-T3, P11-T4 (see `TEST_REPORT.md`) · Gate: TODO

## P12

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                                                                               |
| ------- | ------ | --------- | ------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P12-01  | TODO   |           |              |          | Signed/verified manifest schema, source trust list, explicit capabilities/dependencies/OS support.                                                                  |
| P12-02  | TODO   |           |              |          | Plugin preflight (OS, disk, ports, package conflicts, existing services) and structured install/verify/uninstall jobs.                                              |
| P12-03  | TODO   |           |              |          | Implement first adapters **Fail2ban, Docker Engine/Compose, Node.js, PHP/PHP-FPM, PostgreSQL**; subsequent catalog entries listed but **unsupported** until tested. |
| P12-04  | TODO   |           |              |          | Runtime inventory/version changes and server-wide vs app-scoped policy.                                                                                             |
| P12-05  | TODO   |           |              |          | Database lifecycle via narrowly scoped adapters, secret refs, backups and isolated restore tests.                                                                   |

Phase tests: P12-T1, P12-T2, P12-T3, P12-T4 (see `TEST_REPORT.md`) · Gate: TODO

## P13

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                            |
| ------- | ------ | --------- | ------------ | -------- | ------------------------------------------------------------------------------------------------ |
| P13-01  | TODO   |           |              |          | Implement `apps/mcp` and protocol conformance for Streamable HTTP using current official SDK.    |
| P13-02  | TODO   |           |              |          | OAuth/token scopes, client binding, revocation, rate limits, Origin and input/schema validation. |
| P13-03  | TODO   |           |              |          | Implement read-only tools first, permission-filtered tool discovery and audit.                   |
| P13-04  | TODO   |           |              |          | Tool adapters to existing Center services with structured error codes, pagination and redaction. |
| P13-05  | TODO   |           |              |          | Approval Engine binding exact plan hash, immutable artifact, resource scope and expiration.      |
| P13-06  | TODO   |           |              |          | UAT deployment MCP flow; production request/approval → deploy → verify/rollback.                 |
| P13-07  | TODO   |           |              |          | MCP operations UI: clients, tools, scopes, automation policies, approvals, job timeline.         |

Phase tests: P13-T1, P13-T2, P13-T3, P13-T4, P13-T5, P13-T6 (see `TEST_REPORT.md`) · Gate: TODO

## P14

| Task ID | Status | Change/PR | Test command | Evidence | Notes                                                                                                                                                |
| ------- | ------ | --------- | ------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| P14-01  | TODO   |           |              |          | Cross-reference `docs/FEATURE_MATRIX.md` with design IDs D0–D10 and API/agent/test IDs.                                                              |
| P14-02  | TODO   |           |              |          | English default and Thai optional UI with locale coverage tests.                                                                                     |
| P14-03  | TODO   |           |              |          | End-to-end fleet: enroll → private path → legacy import → deploy → logs → backup → restore drill.                                                    |
| P14-04  | TODO   |           |              |          | End-to-end privileged: SSH MFA → firewall canary → plugin install → AI UAT → Production approval.                                                    |
| P14-05  | TODO   |           |              |          | Faults: Center down, Agent offline, job redelivery, Gateway unavailable, storage full, revoked client, host key mismatch, firewall lockout recovery. |
| P14-06  | TODO   |           |              |          | Install/upgrade/migration and disaster-recovery runbooks, SLO targets measured in lab.                                                               |

Phase tests: P14-T1, P14-T2, P14-T3, P14-T4 (see `TEST_REPORT.md`) · Gate: TODO

## Blockers

- None recorded

## Next atomic task

- P0.01
