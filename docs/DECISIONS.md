# pPanel — Decisions log

Architecture Decision Records live in `docs/adr/`. Small decisions are recorded inline below.
Add a row for every decision; supersede rather than edit accepted ADRs.

## ADR index

| ADR                                                | Title                                                          | Status   | Date       |
| -------------------------------------------------- | -------------------------------------------------------------- | -------- | ---------- |
| [0001](adr/0001-monorepo-modular-monolith.md)      | pnpm monorepo, modular-monolith Center, independent Go agent   | Accepted | 2026-11-17 |
| [0002](adr/0002-outbound-mtls-long-poll.md)        | Outbound mTLS HTTPS long-poll agent protocol (not gRPC) for v1 | Accepted | 2026-11-17 |
| [0003](adr/0003-postgres-durable-job-leases.md)    | Postgres-durable job leases; BullMQ for scheduling later       | Accepted | 2026-11-17 |
| [0004](adr/0004-existing-nginx-source-of-truth.md) | Existing Nginx is source of truth; targeted managed includes   | Accepted | 2026-11-17 |
| [0005](adr/0005-typed-handlers-no-generic-exec.md) | Typed handlers only — no generic command execution             | Accepted | 2026-11-17 |
| [0006](adr/0006-internal-ecdsa-ca.md)              | Internal ECDSA P-256 CA with encrypted private key             | Accepted | 2026-11-17 |
| [0007](adr/0007-compattana-api-envelope.md)        | COMPATTANA API envelope/error/query standard                   | Accepted | 2026-11-17 |

## Small decisions

| ID    | Date       | Decision                                                                                                                                                                        | Rationale                                                                                       |
| ----- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| D-001 | 2026-11-17 | Product name **pPanel** (formerly "W3 Server Panel"); package scope/binaries `ppanel-*`. Brief/MCP tool names prefixed `w3_` are kept as written until P13 decides on aliasing. | user rename                                                                                     |
| D-002 | 2026-11-17 | Dev ports: web **3100**, API **4000**, agent mTLS gateway **4443**, Postgres **127.0.0.1:55432**, Redis **127.0.0.1:56379**                                                     | avoid collisions with unrelated `amas-*` containers (9100/9101/6446/6391/5683/15683/5447/27030) |
| D-003 | 2026-11-17 | Compose project names `ppanel-dev` and `ppanel-lab`; scripts always pass `-p`                                                                                                   | never affect other projects on the host                                                         |
| D-004 | 2026-11-17 | Lab nodes are containers (Ubuntu 24.04 pinned by digest), not VMs; VM-only tests marked BLOCKED                                                                                 | no VMs available; see `infra/lab/README.md`                                                     |
| D-005 | 2026-11-17 | Lab publishes **no** host ports; probes via `docker exec curl -H Host:`                                                                                                         | no exposure on host interfaces                                                                  |
| D-006 | 2026-11-17 | Lab nginx fixtures copied into image at build (not bind-mounted)                                                                                                                | pristine state per cycle; agent may write inside the node without touching the repo             |
| D-007 | 2026-11-17 | Lab TLS cert generated at image build; never committed (`*.pem`/`*.key` gitignored)                                                                                             | no key material in git                                                                          |
| D-008 | 2026-11-17 | Secret scanning with gitleaks v8.21.2 pinned by digest (local + CI)                                                                                                             | brief P0-T02                                                                                    |
| D-009 | 2026-11-17 | CI on `ubuntu-24.04`, Node 22, pnpm 10.33.0, Go 1.25.x; CI-only DB password; per-run generated secrets                                                                          | deterministic, no real secrets                                                                  |
| D-010 | 2026-11-17 | Default UI locale `en`, optional `th`                                                                                                                                           | brief §13 / design §10.1                                                                        |
| D-011 | 2026-11-17 | IDs are UUID v7 strings; enums lowercase snake strings                                                                                                                          | API_CONTRACTS §0                                                                                |
| D-012 | 2026-11-17 | Screen IDs `SCR-*` defined in `FEATURE_MATRIX.md` (design prototype has routes but no screen IDs) — to be reconciled with design handoff (D10-05)                               | design §12 needs `screen_id`                                                                    |
