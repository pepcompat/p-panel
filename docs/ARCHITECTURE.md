# pPanel — Architecture

Status: v1 baseline (2026-11-17). Source: brief §2, §13–15; ADRs in `docs/adr/`.

## 1. Principles

1. **Center failure and agent disconnection must not stop existing workloads.** The agent only acts on
   explicit, unexpired task grants; it never stops/reconfigures workloads on disconnect.
2. **Legacy import never mutates production by default** (Discover → Observe → Adopt → Managed).
3. **Typed operations only** — no generic shell through API, agent or MCP (ADR-0005).
4. One set of guarded Center application services drives **both** the web UI and the MCP adapter.

## 2. Components

```text
Browser ──HTTPS──> apps/web (Next.js, :3100)
   │                     │ server-side fetch with user's Bearer
   └──────HTTPS──────────┴──> apps/api (NestJS modular monolith, :4000, /api/v1)
                                ├─ modules: auth, users/rbac, audit, servers, enrollment,
                                │  jobs, discovery, nginx, deploy*, monitoring*, logs*, backups*,
                                │  network*, ssh*, firewall*, plugins*, approvals*, mcp*   (*later phases)
                                ├─ agent-gateway: Node https server :4443, mTLS (same process)
                                ├─ PostgreSQL 16 (Prisma)  — durable state, job leases, audit
                                └─ Redis 7 (BullMQ later)  — scheduling / rate limits, non-authoritative
apps/agent (Go, one per managed host) ──outbound mTLS long-poll──> :4443
   └─ typed handlers: inventory.collect, discovery.scan, service.restart, nginx.validate/apply …
packages/shared-contracts — TS types/Zod schemas for API envelope, permissions, job types
apps/mcp (P13) — Streamable HTTP adapter over the same Center services
optional Gateway (P9) — independent reverse-proxy process; stateless routing config
```

## 3. Repository layout (as built)

| Path                                                           | Owner      | Contents                                                         |
| -------------------------------------------------------------- | ---------- | ---------------------------------------------------------------- |
| `apps/api`                                                     | API team   | NestJS, Prisma schema/migrations, agent gateway                  |
| `apps/web`                                                     | Web team   | Next.js dashboard (routes per design `/overview`, `/servers`, …) |
| `apps/agent`                                                   | Agent team | Go module, `cmd/ppanel-agent`, packaging                         |
| `packages/shared-contracts`                                    | Lead       | shared TS contracts                                              |
| `infra/compose/dev.yml`                                        | Lead       | Postgres :55432, Redis :56379 (127.0.0.1)                        |
| `infra/compose/lab.yml`, `infra/lab/`, `infra/nginx/fixtures/` | P0         | disposable lab nodes + nginx fixtures                            |
| `scripts/lab/`                                                 | P0         | lab up/down/status/smoke/checksum                                |
| `docs/`                                                        | all        | contracts, ADRs, runbooks, tracking                              |
| `.github/workflows/ci.yml`                                     | P0         | CI skeleton                                                      |

Planned (brief §2.2): `apps/worker` (if job processing is split out), `apps/mcp`, `packages/ui`,
`infra/observability`, `infra/backup`, `templates/`, `scripts/{install,upgrade,backup,restore}`,
`tests/{integration,e2e,security,disaster-recovery}`.

## 4. Key flows

**Enrollment:** operator `POST /enrollments` → one-time token (shown once) → agent generates key + CSR
locally → `POST /api/v1/agent/enroll` → Center marks token used + creates server + issues 7-day cert
in one transaction → agent switches to mTLS on `:4443`.

**Heartbeat & tasks:** agent `POST /agent/v1/heartbeat` every 15 s; `GET /agent/v1/tasks?waitSec=25`
long-poll; `ack` with lease token; `result` idempotent per jobId. Status: `stale` > 45 s, `offline` > 120 s;
metrics of stale servers returned flagged, never zeroed.

**Jobs:** API creates job (Postgres, idempotency key, `expiresAt`, `desiredVersion`) → gateway leases to
agent → agent validates type/params/expiry/serverId → executes typed handler → result. Mutating jobs whose
lease expires become `expired`, never re-delivered (ADR-0003).

**Legacy nginx:** `discovery.scan` runs `nginx -T` read-only → findings with provenance/confidence →
Observe default → explicit Adopt/Managed → changes only via targeted managed includes with
snapshot, `nginx -t`, approved reload, postcheck, revert (ADR-0004).

## 5. State machines

Per brief §2.4 (server, legacy app, deploy job, backup, restore) and `API_CONTRACTS.md` §5 (job:
`queued → leased → running → succeeded|failed|expired|cancelled`).

## 6. Cross-cutting

- API envelope + error format: COMPATTANA standard (ADR-0007).
- Correlation: `X-Request-ID` generated/echoed by API, propagated into job `correlationId` and agent logs.
- Logging: structured JSON `{level,message,timestamp,requestId}`; secrets/PII redacted.
- Time: ISO-8601 UTC everywhere; UI localises.
- i18n: `en` default, `th` optional (P14-02).

## 7. Deployment topologies

See `NETWORK_TOPOLOGY.md`. v1 dev: everything on the Mac; lab nodes are containers.
Production install (single-host Center via docker compose + agents via systemd) is **P8 — TODO**.
