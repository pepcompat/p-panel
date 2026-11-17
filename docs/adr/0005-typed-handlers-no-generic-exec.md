# ADR-0005: Typed handlers only — no generic command execution

- Status: Accepted · Date: 2026-11-17

## Context

Brief §2.1, §14.1: no unrestricted shell via web/API/agent/MCP. A compromised Center or prompt-injected
AI must not gain arbitrary root execution on the fleet.

## Decision

- The agent exposes a closed allowlist of job `type`s, each with a typed parameter schema validated on
  the Center (Zod) **and** in Go, and a fixed handler implementation. Unknown types → `REJECTED_UNKNOWN_TYPE`.
- Handlers invoke binaries with argv arrays (no `sh -c`), canonicalised paths within configured roots,
  and owned-resource allowlists (e.g. `service.restart` only for units pPanel owns).
- MCP tools map to the same Center services; there is **no** MCP shell tool. Human terminal is the
  separate P10 SSH gateway.

## Consequences

- Bounded blast radius; testable policy. − Each new capability needs code + tests (intended).
