# ADR-0002: Outbound mTLS HTTPS long-poll agent protocol (not gRPC) for v1

- Status: Accepted · Date: 2026-11-17

## Context

Brief §2.1 allows "gRPC stream or HTTPS long-poll". Requirements: agent-initiated, no inbound listener
on hosts, mTLS identity, reconnect with backoff, task expiry, bounded buffering, easy debugging through
proxies/NAT, minimal dependencies on Node side.

## Decision

HTTPS/1.1 JSON with mutual TLS to a dedicated agent gateway (`:4443`, Node `https` with
`requestCert/rejectUnauthorized`). Long-poll `GET /agent/v1/tasks?waitSec=25`, heartbeat every 15 s,
explicit `ack`/`result` with lease tokens. Authoritative spec: `docs/AGENT_PROTOCOL.md`.

## Alternatives

- gRPC bidi stream: better latency/streaming, but adds protobuf toolchain, HTTP/2 proxy issues and
  harder curl-level debugging; revisit for log streaming (P5) if needed.
- WebSocket: similar complexity to gRPC without schema benefits.

## Consequences

- Works through ordinary egress firewalls; trivial to test with curl + client certs.
- Stateless gateway per request → simple revocation check per call.
  − Task latency up to one poll round-trip (acceptable for ops jobs).
  − High-volume logs/metrics will use Alloy/Loki (P5), not this channel.
