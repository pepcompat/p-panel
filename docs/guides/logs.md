# Central logs

Search and live-tail logs from servers and managed applications, scoped to what you may see and
redacted before storage. The agent is the log shipper ([ADR-0008](../adr/0008-agent-as-telemetry-adapter.md));
the Center stores logs in Loki. Verified by `scripts/lab/e2e_p5.py` (P5-T02 scoping, P5-T03 redaction,
P5-T04 buffering during a Center outage).

## Prerequisites and permissions

| Task                                 | Permission                           | Built-in roles       |
| ------------------------------------ | ------------------------------------ | -------------------- |
| Query or tail logs of a server       | `fleet.read` covering that server    | all four             |
| Query or tail logs of an application | `apps.read` covering the application | all four             |
| Query without choosing a server/app  | global `fleet.read`                  | global bindings only |

The Center needs Loki reachable at `PPANEL_LOKI_URL` (the optional observability profile, see
[INSTALL.md](../INSTALL.md)). Without it queries return 503 `LOGS_BACKEND_UNAVAILABLE`; agents keep
buffering.

## What is collected

| Source         | From                                              |
| -------------- | ------------------------------------------------- |
| `nginx_access` | `/var/log/nginx/access.log` (rotation-aware tail) |
| `nginx_error`  | `/var/log/nginx/error.log`                        |
| `container`    | stdout/stderr of every pPanel-managed container   |
| `agent`        | the agent's own structured log (level ≥ info)     |

Paths come from the agent's local config only, never from the Center. No other files and no journald in
this release.

## 1. Query

UI: **Logs** (`/logs`), or the **Logs** tab of a server or application. Choose **Server** /
**Application**, **Source**, **Min level**, **Text contains** (plain text, up to 200 characters — not a
query language), a time range (presets up to **Last 7 days**, or custom, max 7 days) and **Order**, then
**Run query**. **Load more** pages through results.

API:

```http
GET /logs/query?serverId=<uuid>&source=nginx_error&level=warn&q=upstream&from=2026-11-24T00:00:00Z&to=2026-11-24T06:00:00Z&limit=200&direction=backward
```

→ `data: [{ ts, serverId, appId, source, level, line }]`, `paginate: { limit, hasMore, nextCursor }`,
`meta.retention.days`. Pass `cursor=<nextCursor>` with the same parameters for the next page. The Center
builds the LogQL itself; unknown parameters (for example a raw `query`) → 422.

## 2. Live tail

**● Live tail** on the Logs page. The browser first gets a single-use token
(`POST /logs/tail-token` → `{ token, expiresAt, url }`, 60 s TTL, bound to you and the filters), then opens
the Server-Sent Events stream `GET /logs/tail?…&token=…`.

Limits: 200 lines/s per connection (excess reported as dropped), 3 concurrent tails per user
(429 `TAIL_LIMIT_REACHED`), auto-close after 15 minutes (**Restart tail**). Your access is re-checked
every 60 s; losing scope ends the tail (`forbidden`). A Center restart ends it with `server_shutdown`.

## Scoping

- Callers without global `fleet.read` must pass `serverId` or `appId` (else 422); out-of-scope ids → 404.
- With global access and no filter, the Center restricts the query to the servers in your scope.
- Labels (`server_id`, `environment`, `source`, `app_id`, `level`) are set by the Center from its own
  records. Entries claiming an app or container that does not belong to that server's managed apps are
  dropped (label spoofing) and counted as rejected.

## Redaction

Lines are redacted three times: by the agent before buffering, by the Center at ingest (shared patterns
plus the known secret values of that server's apps), and again on read. Patterns cover bearer tokens,
`Authorization:` headers, `api_key` / `token` / `secret` / `password` style pairs, JWTs, AWS access keys,
GitHub and Slack tokens, private key blocks, `ppe_` enrollment tokens and URL credentials. Matches become
`[REDACTED]`. Application **Container logs** (`GET /applications/:id/logs?tail=`) are fetched live from
the agent and redacted the same way.

## Retention and limits

- Loki retention: `LOKI_RETENTION_PERIOD` (default `168h`, 7 days). A range that ends before the oldest
  stored entry shows **Outside log retention** — the data expired, it is not missing. Prometheus metrics:
  `PROM_RETENTION_TIME` (default 15 days) / `PROM_RETENTION_SIZE` (default 2 GB).
- Lines longer than 16 KiB are truncated. Per-server ingest limit 2 MiB/s (burst 10 MiB) → the agent backs
  off and retries.
- Query rate limit: 30 queries per minute per user, shared with tail-token creation (429 with
  `Retry-After`).

## Buffering during a Center or Loki outage

The agent keeps logs in an on-disk buffer under its state directory (`logs.bufferCapBytes`, default
64 MiB) and retries with backoff (1 s → 60 s). After the Center or Loki returns, the backlog is shipped
automatically. When the buffer is full, the **oldest** segments are dropped and counted in
`droppedEntries` (heartbeat `logShipping`, the `ppanel_log_dropped_entries_total` metric, and
**Monitoring** "{n} log entries dropped"). Workloads are never blocked by log shipping.

Lab evidence: a 10-minute Center outage delivered 100 % of the outage-window lines after reconnect;
Loki stopped for 126 s lost nothing (`docs/RESILIENCE_REPORT.md`). Delivery is at-least-once: about a
second of lines can repeat after an agent crash.

To be told about drops, create a `log_dropped` alert rule ([alerts.md](alerts.md)).

## Failure modes

| Symptom                           | Meaning / recovery                                                                                                                       |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 503 `LOGS_BACKEND_UNAVAILABLE`    | Loki down or overloaded; agents buffer. Bring Loki back; retry after `Retry-After`.                                                      |
| **{name} is offline** empty state | Lines after the last heartbeat have not reached the Center yet; they ship on reconnect                                                   |
| 429 rate limited                  | Wait for the countdown                                                                                                                   |
| 404 on a server/app id            | Outside your scope                                                                                                                       |
| Drops reported                    | Buffer cap reached during a long outage, or entries rejected by the Center. Raise `logs.bufferCapBytes` on the agent if outages are long |

## Limitations

- Plain substring filter only; no LogQL from clients.
- No journald or arbitrary log files in this release.
- One Loki retention for all logs (no per-environment retention).
