# pPanel

Self-hosted control plane for managing multiple Ubuntu/Debian servers through outbound-connecting Go agents —
legacy-Nginx-friendly discovery, fleet inventory, typed jobs, and (planned) deployments, logs, backups, firewall,
SSH gateway and MCP/AI operations.

> **Status: v0.1.0 — early development (P0–P2 + start of P3).** Not production ready. See
> [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) and [docs/TEST_REPORT.md](docs/TEST_REPORT.md).

## Principles

- Center or agent failure never stops existing workloads.
- Discovery/import is read-only by default; existing Nginx stays the source of truth.
- Agents connect outbound over mTLS; no management port is opened on hosts.
- No generic shell: every operation is a typed, allowlisted job with expiry, lease and idempotency key.

## Layout

| Path                         | What                                                                |
| ---------------------------- | ------------------------------------------------------------------- |
| `apps/api`                   | Center API (NestJS, Prisma/PostgreSQL), auth/MFA/RBAC, CA, gateway  |
| `apps/agent`                 | Go agent (enrollment, mTLS heartbeat, typed handlers, nginx parser) |
| `apps/web`                   | Next.js dashboard (EN/TH), built from the Claude Design prototype   |
| `packages/shared-contracts`  | Shared TS types and Zod schemas                                     |
| `infra/compose`, `infra/lab` | Dev dependencies and a 2-node container lab                         |
| `docs/`                      | Contracts, architecture, threat model, ADRs, status, runbooks       |
| `design/`                    | Imported design prototype and briefs                                |

## Quick start (dev)

See [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md). In short:

```bash
docker compose -f infra/compose/dev.yml up -d
pnpm install
cp .env.example apps/api/.env   # fill PPANEL_MASTER_KEY, JWT_ACCESS_SECRET
pnpm --filter @ppanel/api prisma:migrate && pnpm --filter @ppanel/api seed
pnpm --filter @ppanel/api dev
pnpm --filter @ppanel/web dev   # http://localhost:3100
```

Dev seed users (development only): `dev`, `superadmin`, `admin`, `user1` @ppanel.local, password `password`.
