# ADR-0004: Existing Nginx is the source of truth; changes only via targeted managed includes

- Status: Accepted · Date: 2026-11-17

## Context

Legacy hosts have hand-written nginx configs with includes, wildcards, duplicates, and directives that
cannot be round-tripped safely (brief §4). Regenerating configs risks outages.

## Decision

- Discovery parses `nginx -T` read-only; nothing is written or reloaded in Discover/Observe
  (proof: `scripts/lab/checksum-nginx.sh` before/after, P3-T01).
- pPanel never regenerates whole configs. Each supported change is a **targeted managed include** or a
  bounded edit under a pPanel-owned path, with: original snapshot + checksum → diff → approval →
  `nginx -t` → atomic rename → reload → postcheck → automatic revert on failure.
- Out-of-band edits (checksum drift) block automated overwrite pending manual review (P3-T05).
- No competing proxy daemon on 80/443; Traefik/Caddy takeover is out of scope.

## Consequences

- Import is safe by construction. − Some sites stay Observe-only (unsupported directives, ambiguity).
