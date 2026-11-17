# ADR-0001: pnpm monorepo with a modular-monolith Center and an independent Go agent

- Status: Accepted · Date: 2026-11-17 · Deciders: lead

## Context

Brief §2.1 recommends a monorepo, NestJS Center, Next.js UI, Go agent. Team is small; contracts
(API, agent protocol, permissions) must stay in sync; microservices would multiply auth/audit surfaces.

## Decision

- Single pnpm workspace (`apps/*`, `packages/*`): `apps/api` (NestJS modular monolith incl. agent
  gateway), `apps/web` (Next.js), `packages/shared-contracts` (TS types/Zod).
- `apps/agent` is an independent Go module in the same repo, built as static binaries, versioned with
  the protocol (`X-Agent-Protocol`).
- Background workers start inside the API process; split to `apps/worker` only when load requires it.
- `apps/mcp` (P13) is an adapter over the same services, not a second engine.

## Consequences

- One PR can change contract + both sides; one CI. + Single audit/RBAC implementation.
  − API process is a larger blast radius; mitigated by module boundaries and typed jobs.
  − Go and Node toolchains both required in CI (handled by separate jobs).
