# ADR-0006: Internal ECDSA P-256 CA with encrypted private key

- Status: Accepted · Date: 2026-11-17

## Context

Agents need per-host identities with rotation and revocation; public CAs are unsuitable for private
client certs. Brief §3 requires mTLS and revocation; §6 requires key material recoverable outside the DB.

## Decision

- Center generates a self-signed ECDSA P-256 root at first start. Private key stored in `ca_keys`,
  encrypted with AES-256-GCM using `PPANEL_MASTER_KEY` (32 B, env, never in DB).
- Agent leaf certs: CN `agent:<serverId>`, URI SAN `ppanel://agent/<serverId>`, 7-day validity, renewed
  via `POST /agent/v1/certificate/rotate`; revocation = DB flag checked on every gateway request.
- Gateway server cert issued from the same CA with configured SANs.
- `PPANEL_MASTER_KEY` must be backed up **separately** from the database (P6.06 runbook).

## Alternatives

HSM/KMS (deferred, future capability); step-ca (extra service to operate).

## Consequences

- No external dependency; short-lived certs limit exposure. − CA key compromise = fleet impersonation
  until re-key (risk R-04); re-key procedure required in recovery runbook.
