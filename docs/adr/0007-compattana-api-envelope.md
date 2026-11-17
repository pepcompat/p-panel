# ADR-0007: COMPATTANA API envelope, error and query standards

- Status: Accepted · Date: 2026-11-17

## Context

Team standard (COMPATTANA standard documents) mandates a uniform response envelope, error shape,
versioned routes, camelCase bodies and Query Builder parameters.

## Decision

- All routes under `/api/v1`. Success `{ success: true, statusCode: 0, message, data, meta: { requestId } }`;
  lists add `paginate: { page, limit, total }`. Errors `{ error: { code, message, details }, meta }`.
- HTTP codes per standard (+409 for version conflicts). `X-Request-ID` echoed; camelCase JSON keys;
  snake_case DB via Prisma maps; ISO-8601 UTC; enums as strings; money as decimal.
- Query: `page`, `limit` (1–100), `sort`, `order`, `q`, `field[op]=value`.
- Agent gateway uses the same envelope for consistency. Details: `docs/API_CONTRACTS.md` §0.

## Consequences

- Consistent clients (web, MCP, tests). − Slight verbosity; shared helpers in `packages/shared-contracts`.
