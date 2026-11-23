# ADR-0008: The agent is the telemetry adapter (no per-node Alloy in v1)

- Status: Accepted (2026-11-23)
- Context: The brief (§2.1, §6) lists Prometheus + Alloy + Loki and allows "Alloy forwarding (or agent adapter)". Each node already runs the pPanel agent with an outbound, mutually-authenticated channel to the Center. Adding Alloy per node means a second outbound credential per host, a second binary to patch, and log/metric data that reaches Loki/Prometheus without passing the Center's scope and redaction boundary.
- Decision:
  - Agents ship **metrics in the heartbeat** and **logs via `POST /agent/v1/logs`** over the existing mTLS gateway.
  - The Center redacts again, sets labels from its own records (never from agent-supplied labels), pushes logs to **Loki**, and exposes a scrape endpoint for **Prometheus** (Center → Prometheus pull).
  - Users never send PromQL/LogQL: the Center builds every query from typed parameters and always injects the caller's scope selector.
  - Prometheus and Loki listen on 127.0.0.1 only and are not reachable from browsers or agents.
- Consequences:
  - One credential per node and a single choke point for redaction and authorization (P5-T02, P5-T03).
  - The Center is in the telemetry path. A Center outage stops ingestion but **not workloads**; agents buffer logs up to a bounded cap and report drops (P5-T04).
  - Metric resolution is the heartbeat interval (15 s). That is enough for v1 fleet views; high-cardinality app metrics are out of scope.
  - Alloy remains a valid future option (e.g. for very high log volume). Labels and query APIs would not change.
