# pPanel release notes

## 0.8.0-rc.1 — MVP-B release candidate (2026-11-24)

First installable release candidate of pPanel, a self-hosted control panel for a fleet of Linux servers.
It completes the core milestones P0–P8. Read [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) before
installing: real-VM install tests, ACME/HTTPS and the GitHub App are still BLOCKED on external inputs.

### Install and upgrade (P8)

- Center install with Docker Compose: `infra/release/install.sh` (Postgres, API, web, Caddy TLS proxy,
  optional Prometheus + Loki), pinned images, generated secrets, master-key escrow prompt. See
  [`INSTALL.md`](INSTALL.md).
- Agent install: `install-agent.sh` verifies `SHA256SUMS` (and the ed25519 signature when a public key is
  given), installs a hardened systemd unit and enrolls. The enrollment screen now shows this command.
- Upgrade and rollback: `upgrade.sh` takes a pre-upgrade database dump, migrates and verifies;
  `rollback.sh` restores the dump and the previous images. See [`UPGRADE_RUNBOOK.md`](UPGRADE_RUNBOOK.md),
  [`MIGRATION_RUNBOOK.md`](MIGRATION_RUNBOOK.md) and [`COMPATIBILITY.md`](COMPATIBILITY.md).
- `GET /api/v1/version` and `GET /api/v1/health` (public). Agents older than `minAgentVersion` get
  `AGENT_OUTDATED` for mutating jobs and keep serving.
- Release workflow on `v*` tags: multi-arch images to GHCR, agent binaries, checksums, optional signing.
- CI now builds the production images and runs Playwright user journeys against the real API.
- Operator guides for every flow in [`guides/`](guides/README.md); acceptance matrix in
  [`ACCEPTANCE.md`](ACCEPTANCE.md).

### Security, resilience and performance (P7)

- Security test suite (114 tests) and fixes for SSRF (incl. IPv6 and registry), webhook delivery scope,
  CSP/HSTS, malformed input, per-IP login rate limit. Report: [`SECURITY_TEST_REPORT.md`](SECURITY_TEST_REPORT.md).
- Agent hardening from 20 fuzzers: symlink-safe file access, Docker API allowlist, process-group kill,
  git environment allowlist, redaction fixes.
- Resilience fixes from chaos testing: no lost or deduplicated log lines, nginx apply recovery after an
  agent crash, interrupted jobs reported, atomic approvals, webhook commits coalesced ("latest wins"),
  orphan candidate cleanup, 503 on database outage, gateway certificate renewal. Reports:
  [`RESILIENCE_REPORT.md`](RESILIENCE_REPORT.md), [`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md).

### Features (P0–P6)

- Server enrollment over outbound mTLS, Production/UAT/Development groups, public/private addresses.
- Legacy Nginx discovery and import (Discover → Observe → Adopt → Managed), revisions with validate,
  second-person approval with step-up 2FA, apply with postchecks and automatic revert, drift detection.
- Container deployments with secrets, preflight, approval, rollback; Git builds on build nodes; Compose
  applications; signed webhook auto-deploy.
- Metrics, central logs with redaction, alert rules, incidents, email/Telegram/webhook notifications.
- Backups with append-only restic, verification levels, restore wizard with dry-run and approval,
  Center disaster recovery runbook.
- RBAC with scoped role bindings, audit log, English UI with Thai option.

### Upgrade notes

- Upgrade order: Center first, then agents. Supported path: 0.7.0 → 0.8.0-rc.1.
- `server_offline` alert rules with `forSec` below 90 are raised to 90 by migration
  `20261128100000_p7_resilience`.
