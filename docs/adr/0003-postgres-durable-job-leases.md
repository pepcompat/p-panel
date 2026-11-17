# ADR-0003: Postgres-durable job leases; BullMQ only for scheduling later

- Status: Accepted · Date: 2026-11-17

## Context

Jobs need idempotency keys, expiry, leases, desired-state version checks, and must never silently replay
privileged work after worker crash or agent reconnect (brief §3, P2-T01…T03, E2E-11). Redis is not a
durable source of truth under failure (lost Redis is a P7.05 disaster case).

## Decision

- Job rows (`jobs` / `job_leases`) in PostgreSQL are authoritative: state transitions via conditional
  `UPDATE … WHERE status = … AND version = …` inside transactions.
- Agents lease via the gateway; mutating jobs whose lease/expiry lapses go to `expired` and are never
  re-delivered; read-only jobs may be re-leased.
- BullMQ/Redis is introduced later only for **scheduling and fan-out** (cron backups, alert evaluation),
  always resolving to a Postgres job row before any effect.

## Consequences

- Crash-safe, auditable, testable with plain SQL. + Redis loss degrades scheduling, never duplicates effects.
  − Polling/locking load on Postgres; acceptable at target fleet sizes, measure in P7.06.
