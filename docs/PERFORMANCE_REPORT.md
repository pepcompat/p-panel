# pPanel — Performance Report (P7.06)

Measured on 2026-11-24 in the lab. These are the numbers **this hardware** supports, not a scale claim.
Evidence: `docs/evidence/2026-11-24/p7-load-ramp-main.json` (50 → 200 → 500 agents) and
`p7-load-ramp-extended.json` (1 000 → 2 000 agents); raw per-phase output in `.lab/load/`.

## Hardware and setup

| Item                         | Value                                                                                                                                            |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Host                         | Apple M4, 10 cores, 24 GB RAM, macOS 27.2.1                                                                                                      |
| Center                       | one Node v24.11.0 process (snapshot build of `43feb79`, `node dist/main.js`, not watch mode), API :4000 + mTLS gateway :4443 in the same process |
| Postgres / Loki / Prometheus | Docker Desktop VM (10 vCPU, 11.7 GiB), dev compose Postgres 16, Loki 3.5.7, Prometheus 3.5.0                                                     |
| Load generator               | `tests/load/cmd/fakefleet` on the **same Mac** (it competes for CPU with the Center — numbers are conservative)                                  |

## Method

- **Fake agents** (`tests/load`, a separate Go module, stdlib only) enroll through the real flow
  (`POST /api/v1/enrollments` as admin, then `POST /api/v1/agent/enroll` with a locally generated ECDSA P-256
  CSR) and then speak the real mTLS gateway protocol: heartbeat every **15 s** (jittered start; realistic body with
  metrics, address, capabilities, logShipping), a held `GET /agent/v1/tasks?waitSec=25` long-poll per agent (as
  the real agent does), and gzip `POST /agent/v1/logs` batches every 2 s carrying the agent's share of the
  fleet-wide line rate (unique lines, `source=nginx_access`).
- **Admin API probe** in the same process: `GET /servers?limit=100` every 1 s, `GET /metrics/fleet` every 2 s,
  `GET /logs/query` (5-min window, 200 lines) every 4 s — below the per-user limits (60/min metrics, 30/min logs).
- **Driver** `tests/load/run_ramp.py`: restarts the snapshot Center with `TRUST_PROXY=1` (existing config switch)
  so each fake agent's enrollment carries its own `X-Forwarded-For` (the public enroll endpoint is limited to
  10/min per IP); each phase runs 180 s; samples the Center process (`ps` RSS / CPU every 5 s, CPU average from
  process CPU time), Postgres (`pg_database_size`, hot tables, `docker stats`), Loki
  (`loki_distributor_lines_received_total`) and `/internal/metrics` scrape latency.
- Stop criteria: heartbeat errors > 5 % or heartbeat p95 > 2 s.
- "Lines accepted/s" is lines ÷ the whole phase wall time (180 s + start jitter + wind-down ≈ 205 s), so a
  500 lines/s target shows as ~418/s; every line sent was accepted (`linesSent == linesAccepted`, 0 × 429)
  except where noted.

## Results

Latencies in ms (p50 / p95 / p99). CPU = Center process average over the phase (100 % = one core; the process
also uses libuv/GC/TLS threads, so it can exceed 100 %).

|    Agents | Target lines/s | Heartbeats/s | Heartbeat                 | Log batch             | `/servers`            | `/metrics/fleet`  | `/logs/query`              |       Lines accepted/s |      Center CPU avg | Center RSS max | Errors                         |
| --------: | -------------: | -----------: | ------------------------- | --------------------- | --------------------- | ----------------- | -------------------------- | ---------------------: | ------------------: | -------------: | ------------------------------ |
|        50 |              0 |          2.9 | 18 / 28 / 36              | –                     | 32 / 40 / 43          | 16 / 27 / 32      | 24 / 39 / 40               |                      0 |                14 % |         280 MB | 0                              |
|        50 |            500 |          2.9 | 14 / 27 / 32              | 11 / 21 / 25          | 25 / 32 / 42          | 10 / 15 / 16      | 28 / 35 / 51               |                    418 |                25 % |         369 MB | 0                              |
|       200 |              0 |         11.7 | 12 / 19 / 27              | –                     | 20 / 25 / 31          | 17 / 23 / 25      | 35 / 45 / 68               |                      0 |                28 % |         413 MB | 0                              |
|       200 |            500 |         11.7 | 7 / 15 / 24               | 5 / 10 / 15           | 14 / 21 / 33          | 11 / 18 / 28      | 35 / 56 / 74               |                    418 |                39 % |         439 MB | 0                              |
|       200 |          2 000 |         11.7 | 7 / 15 / 25               | 6 / 10 / 17           | 10 / 18 / 22          | 10 / 16 / 20      | 50 / 67 / 69               |                  1 674 |                39 % |         438 MB | 0                              |
|       500 |              0 |         29.2 | 10 / 17 / 27              | –                     | 18 / 25 / 28          | 23 / 29 / 31      | 71 / 96 / 123              |                      0 |                45 % |         491 MB | 0                              |
|       500 |            500 |         29.2 | 7 / 15 / 23               | 5 / 11 / 17           | 10 / 15 / 17          | 14 / 23 / 24      | 71 / 90 / 128              |                    418 |                63 % |         556 MB | 0                              |
|       500 |          2 000 |         29.2 | 7 / 15 / 27               | 5 / 11 / 21           | 12 / 19 / 24          | 17 / 23 / 28      | 90 / 129 / 139             |                  1 671 |                64 % |         554 MB | 0                              |
|     1 000 |              0 |         58.5 | 6 / 13 / 20               | –                     | 13 / 19 / 30          | 25 / 40 / –       | 33 / 54 / –                |                      0 |                50 % |         589 MB | 0                              |
| **1 000** |      **2 000** |         58.5 | 12 / 37 / 105             | 8 / 31 / 118          | 15 / 30 / 77          | 32 / 50 / –       | 147 / 301 / –              |                  1 673 |           **136 %** |         723 MB | 0                              |
|     2 000 |          2 000 |        122.2 | **1 574 / 1 999 / 2 215** | 2 681 / 3 476 / 3 892 | 1 519 / 1 909 / 2 065 | 2 046 / 2 628 / – | 831 / **60 000** (timeout) | 1 298 (client-limited) | 230 % (peaks 292 %) |       1 286 MB | `/logs/query` 1 of 6 timed out |
|     2 000 |          5 000 |        122.4 | 1 472 / 1 778 / 1 901     | 2 457 / 3 059 / 3 394 | 1 439 / 1 736 / 1 854 | 1 965 / 2 327 / – | 23 584 / 26 446            |                  3 512 |               239 % |       1 378 MB | 0                              |

Other measurements:

- **Enrollment**: 300 agents enrolled in 0.62 s of server time (≈ 480/s, 8 parallel clients); 1 000 more in 2.4 s.
- **Long-polls**: 1 agent = 1 held connection; 2 000 concurrent long-polls held fine (p50 25.0 s at ≤ 1 000 agents,
  25.9 s at 2 000 — only the event-loop delay added).
- **`/internal/metrics`** (Prometheus scrape): 0.9 MB / 31–62 ms at 1 000 servers; 1.8 MB / 1.9–2.9 s at 2 000
  (event loop saturated).
- **Loki ingest**: Loki's received-lines counter matched the lines the Center accepted in every phase (up to
  3 510 lines/s), no 429 from the Center's per-server budget (2 MiB/s per server is far above one agent's share).
- **Postgres CPU** (docker stats): < 3 % up to 500 agents, 6–10 % at 1 000, spikes to 120–130 % at 2 000.

## Postgres growth

| Phase                         | DB growth during phase (extrapolated per hour) | Driver                                                                                                                                                       |
| ----------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 500 agents, 0 lines/s         | 67 MB/h                                        | `agent_heartbeats` (~500 B/row, 33 rows/s) — **capped** at `PPANEL_HEARTBEAT_KEEP`=500 rows per server (≈ 2 h at 15 s), so it plateaus at ~250 KB per server |
| 500 agents, 500–2 000 lines/s | 182–188 MB/h                                   | + `log_batches` dedupe rows (~170 B per batch, one per agent batch, 238 batches/s), kept 24 h                                                                |
| 1 000 agents, 2 000 lines/s   | 266 MB/h                                       | same; 500 batches/s                                                                                                                                          |
| 2 000 agents                  | 625–647 MB/h                                   | same; ~700 batches/s + heartbeats                                                                                                                            |

Steady-state estimates (retention as configured, excluding Loki): heartbeats ≈ 250 KB × servers
(1 000 servers ≈ 250 MB, then flat); `log_batches` ≈ 170 B × batches/s × 86 400 (24 h dedupe window) — at
1 000 agents shipping every 2 s that is ≈ **7.3 GB** of short-lived rows plus index/vacuum churn. This, not
metrics, dominates DB size once log shipping is enabled. Agents that batch less often (e.g. 5–10 s when idle)
or a shorter dedupe window would shrink it proportionally.

Cleanup of fake servers: `python3 -I tests/load/run_ramp.py --cleanup` (runs automatically at the end of a
ramp) = `DELETE FROM servers WHERE name LIKE 'p7load-%'` (FK cascades: certificates, heartbeats, telemetry,
jobs, …) + `DELETE FROM agent_enrollments WHERE name LIKE 'p7load-%'`. Both ramps ended with 0 rows left
(500 and 2 000 deleted in 0.2 s / 0.4 s). Their Loki lines age out with Loki retention.

## Limits and first bottleneck

- **Supported on this Mac with good latency: 1 000 agents at a 15 s heartbeat + 2 000 log lines/s** — heartbeat
  p95 37 ms, admin API p95 ≤ 50 ms except `/logs/query` 301 ms, Center ~1.4 cores average, 723 MB RSS, 0 errors.
  500 agents + 2 000 lines/s used ~0.64 core.
- **First bottleneck: the single Center Node process (event loop).** At 2 000 agents (≈ 122 heartbeats/s + 2 000
  held long-polls + ~640 log batches/s + per-request mTLS identity lookups in Postgres) the process sat at 230–290 %
  CPU and _every_ endpoint — heartbeats, log ingest, admin API, the Prometheus scrape — queued behind it with
  uniform 1.5–2.6 s latency (p95 heartbeat 1 999 ms, right at the stop threshold). Postgres was not the limit
  (≤ 130 % CPU spikes, ~290 MB). `/logs/query` degraded first and worst (one 60 s timeout).
- Nothing was dropped: 0 heartbeat errors and 0 rejected log lines at every step; overload shows up as latency.
- The generator ran on the same 10-core Mac, so a dedicated Center host would do somewhat better.
- Not measured here: real WAN latency / TLS handshake storms after a Center restart with 1 000+ agents
  reconnecting at once (agents back off with jitter, see the resilience report), Loki/Prometheus on separate hosts.

## Recommended sizing (initial, revisit with production telemetry)

| Fleet           | Center                              | Postgres                                               | Notes                                                                                                                                                                       |
| --------------- | ----------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ≤ 200 servers   | 1 vCPU, 1 GB RAM                    | 1 vCPU, 2 GB, 20 GB disk                               | measured: < 0.4 core, < 450 MB RSS                                                                                                                                          |
| ≤ 500 servers   | 2 vCPU, 2 GB                        | 2 vCPU, 4 GB, 40 GB disk                               | measured: 0.64 core, 560 MB RSS at 2 000 lines/s                                                                                                                            |
| ≤ 1 000 servers | 2–4 vCPU, 2 GB                      | 2 vCPU, 4–8 GB, ≥ 50 GB disk (log_batches churn ~7 GB) | measured: 1.4 cores avg, 723 MB                                                                                                                                             |
| > 1 000 servers | not supported by one Center process | –                                                      | needs horizontal gateway/ingest workers (Node cluster or separate ingest process) and shared Redis for the in-memory rate limiter / byte bucket, before claiming this scale |

Tuning levers already in the code: `PPANEL_HEARTBEAT_KEEP` (heartbeat rows per server), per-server log ingest
budget (`PPANEL_LOG_INGEST_RATE_BYTES` / `_BURST_BYTES`), and the agent's `logs.shipIntervalMs`.

## Re-run

```
python3 -I tests/load/run_ramp.py --phase-sec 180                       # 50 → 500 agents
python3 -I tests/load/run_ramp.py --phase-sec 180 --plan 1000:0,1000:2000,2000:2000,2000:5000
python3 -I tests/load/run_ramp.py --cleanup                              # if a run was interrupted
```
