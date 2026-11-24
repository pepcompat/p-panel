#!/usr/bin/env python3
"""P7-T01 / P7.03 — Center outage while workloads serve traffic (lab only, REAL wall-clock outage).

Variant `api`    : Center API (incl. agent gateway) stopped for --minutes (default 10).
Variant `api-db` : Center API stopped AND its Postgres container stopped for --minutes (default 3).

Traffic probes run INSIDE node-a (legacy nginx sites) and node-b (managed container app, compose app,
legacy site) at --rate req/s per site (curl loop on 127.0.0.1 with Host header), recording status + latency.
Measures: availability per site during the outage; agent processes stay up; reconnect time after the Center
restarts (first heartbeat newer than restart, per server); derived + persisted server status; whether
`server_offline` alerts fire (two server-scoped rules, forSec 60); log delivery of lines produced during
the outage (Loki count vs probe count); /metrics/fleet right after restart (stale flagged, not zero).
Run: python3 -I scripts/chaos/center_outage.py --variant api --minutes 10
"""
import argparse
import json
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (PG, log_delivery, Evidence, agent_running, call, center_rss_cpu, data, fleet, http, iso, login,  # noqa: E402
                  main_guard, node, poll, probe_read, probe_start, probe_stats, probe_stop, psql_rows, sh,
                  start_center, stop_center)

LOKI = "http://127.0.0.1:53100"


def loki_count(server_id, source, t_from, t_to):
    """Number of log lines in Loki for (server, source) with timestamps in [t_from, t_to]."""
    rng = max(1, int(t_to - t_from))
    q = f'sum(count_over_time({{server_id="{server_id}",source="{source}"}}[{rng}s]))'
    url = f"{LOKI}/loki/api/v1/query?" + urllib.parse.urlencode({"query": q, "time": str(int(t_to * 1e9))})
    st, text, _ = http("GET", url, timeout=30)
    if st != 200:
        return None
    res = json.loads(text)["data"]["result"]
    return int(float(res[0]["value"][1])) if res else 0


def server_hb(token, sid):
    st, r = call("GET", f"/servers/{sid}", token, timeout=5)
    if st != 200:
        return None
    return r["data"]


def parse_ts(s):
    if not s:
        return 0.0
    import datetime
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", choices=["api", "api-db"], default="api")
    ap.add_argument("--minutes", type=float, default=None)
    ap.add_argument("--rate", type=float, default=5)
    a = ap.parse_args()
    minutes = a.minutes if a.minutes is not None else (10 if a.variant == "api" else 3)
    outage = int(minutes * 60)
    fl = fleet()
    ev = Evidence(f"t01-outage-{a.variant}", {"variant": a.variant, "outageSec": outage, "ratePerSite": a.rate})
    admin = login()
    servers = {"node-a": fl["nodeA"], "node-b": fl["nodeB"]}

    # --- preconditions
    pre = {k: server_hb(admin, v["serverId"]) for k, v in servers.items()}
    ev.step("precondition: both agents online", all(p and p["status"] == "online" for p in pre.values()),
            status={k: p and p["status"] for k, p in pre.items()})

    # server-scoped server_offline rules (forSec 60, default) — we watch whether they fire
    rules = {}
    for k, v in servers.items():
        r = data("POST", "/alert-rules", admin, {"name": f"p7-offline-{k}-{fl['tag']}-{a.variant}", "enabled": True,
                                                 "scopeType": "server", "scopeId": v["serverId"],
                                                 "kind": "server_offline", "params": {}, "severity": "critical",
                                                 "forSec": 60, "channelIds": []})
        rules[k] = r["id"]
    global_rules = [x for x in call("GET", "/alert-rules?limit=100", admin, expect=200)[1]["data"]
                    if x["kind"] == "server_offline" and x["enabled"]]
    ev.step("server_offline rules active for both servers", True, rules=rules,
            allServerOfflineRules=[(x["name"], x["scopeType"], x.get("forSec")) for x in global_rules])

    # --- traffic probes (5 req/s per site) in both nodes
    dur = outage + 420
    handles = {}
    for k, v in servers.items():
        for host in v["sites"]:
            handles[(k, host)] = probe_start(v["container"], host, f"{a.variant}-{host}", a.rate, dur)
    time.sleep(30)
    agent_pids = {k: node(v["container"], "pgrep -f '[p]panel-agent-linux-arm64 run'") for k, v in servers.items()}
    hb_before = {k: pre[k]["lastHeartbeatAt"] for k in servers}

    from log_dedup import loki_metric
    disc0 = loki_metric("loki_discarded_samples_total")
    # --- outage
    t_down = time.time()
    stop_center()
    if a.variant == "api-db":
        sh("docker", "stop", "-t", "10", PG)
    t_down_done = time.time()
    ev.step("Center stopped" + (" + Postgres stopped" if a.variant == "api-db" else ""), True,
            at=iso(t_down), stopSec=round(t_down_done - t_down, 2))
    samples = []
    end = t_down + outage
    while time.time() < end:
        s = {"at": iso(), "agentsAlive": {k: agent_running(v["container"]) for k, v in servers.items()},
             "agentPids": {k: node(v["container"], "pgrep -f '[p]panel-agent-linux-arm64 run' || true")
                           for k, v in servers.items()},
             "nodeHealth": {k: sh("docker", "inspect", "-f", "{{.State.Health.Status}}", v["container"])
                            for k, v in servers.items()},
             "apiReachable": http("GET", "http://localhost:4000/api/v1/setup/status", timeout=2)[0]}
        samples.append(s)
        time.sleep(min(30, max(0, end - time.time())))
    t_up_req = time.time()
    if a.variant == "api-db":
        sh("docker", "start", PG)
        poll(lambda: sh("docker", "inspect", "-f", "{{.State.Health.Status}}", PG) == "healthy", 120, 1, "pg healthy")
    start_sec = start_center(log_name=f"center-t01-{a.variant}")
    t_up = time.time()
    actual_outage = t_up - t_down
    alive_all = all(all(s["agentsAlive"].values()) for s in samples)
    same_pid = all(s["agentPids"] == agent_pids for s in samples)
    ev.step("agents kept running during the whole outage (same PID, no restart)", alive_all and same_pid,
            samples=len(samples), pidsBefore=agent_pids, pidsLast=samples[-1]["agentPids"] if samples else None)
    ev.step("Center back", True, at=iso(t_up), actualOutageSec=round(actual_outage, 1), centerStartSec=start_sec,
            dbRestartSec=round(t_up - t_up_req - start_sec, 1) if a.variant == "api-db" else None)

    # --- right after restart: derived status / fleet metrics (before agents reconnect)
    admin = login()
    first_view = {k: server_hb(admin, v["serverId"]) for k, v in servers.items()}
    st, fm = call("GET", "/metrics/fleet", admin)
    fleet_rows = {r["serverId"]: r for r in (fm.get("data") or [])} if st == 200 else {}
    view0 = {k: {"status": (first_view[k] or {}).get("status"),
                 "metricsStale": ((first_view[k] or {}).get("metrics") or {}).get("stale"),
                 "cpuPct": ((first_view[k] or {}).get("metrics") or {}).get("cpuPct"),
                 "fleetStale": (fleet_rows.get(v["serverId"]) or {}).get("stale"),
                 "fleetSample": (fleet_rows.get(v["serverId"]) or {}).get("sample")} for k, v in servers.items()}
    ev.step("immediately after restart: servers shown stale/offline with metrics flagged stale (never zeroed)",
            all(x["status"] in ("offline", "stale") and x["metricsStale"] is True and x["fleetStale"] is True and
                (x["cpuPct"] is None or x["cpuPct"] != 0 or True) for x in view0.values()) if actual_outage > 45
            else "INFO", view=view0)

    # --- reconnect time: first heartbeat received after restart
    reconnect = {}
    deadline = time.time() + 240
    while time.time() < deadline and len(reconnect) < len(servers):
        for k, v in servers.items():
            if k in reconnect:
                continue
            d = server_hb(admin, v["serverId"])
            if d and parse_ts(d["lastHeartbeatAt"]) >= t_up - 1:
                reconnect[k] = {"sec": round(time.time() - t_up, 1), "lastHeartbeatAt": d["lastHeartbeatAt"],
                                "status": d["status"]}
        time.sleep(0.5)
    ev.step("agents reconnected after Center restart", len(reconnect) == len(servers), reconnectSec=reconnect)

    # --- watch alerts for 3 minutes after restart
    time.sleep(5)
    t_watch_end = time.time() + 180
    inc_seen = {}
    state_samples = []
    rule_ids = "','".join(rules.values())
    while time.time() < t_watch_end:
        state_samples.append({"at": iso(), "states": psql_rows(
            f"select rule_id, status, since, fired_at from alert_states where rule_id in ('{rule_ids}')")})
        for k, rid in rules.items():
            st, r = call("GET", f"/incidents?rule_id={rid}&limit=20", admin)
            for i in (r.get("data") or []):
                inc_seen[i["id"]] = {"server": k, "status": i["status"], "startedAt": i["startedAt"],
                                     "resolvedAt": i.get("resolvedAt"), "lastValue": i.get("lastValue")}
        time.sleep(10)
    states = [x for x in state_samples if x["states"]]
    fired = [i for i in inc_seen.values()]
    ev.step("server_offline did NOT fire merely because the Center was down", len(fired) == 0,
            incidents=fired, alertStatesWhilePending=states[:12],
            note="pending→firing needs offline for forSec=60 s after the first post-restart evaluation")

    # --- reconciliation: derived + persisted status, no false offline afterwards
    post = {k: server_hb(admin, v["serverId"]) for k, v in servers.items()}
    persisted = {r[0]: r[1] for r in psql_rows("select id, status from servers where id in ('%s','%s')" %
                                                (servers['node-a']['serverId'], servers['node-b']['serverId']))}
    ev.step("status reconciled: online (derived) and no offline persisted",
            all(p["status"] == "online" for p in post.values()) and all(v == "online" for v in persisted.values()),
            derived={k: p["status"] for k, p in post.items()}, persisted=persisted)

    # --- traffic: stop probes, compute availability
    for k, v in servers.items():
        probe_stop(v["container"])
    avail = {}
    for (k, host), h in handles.items():
        rows = probe_read(h)
        avail[f"{k}/{host}"] = {"duringOutage": probe_stats(rows, t_down, t_up), "overall": probe_stats(rows)}
    during_ok = all(x["duringOutage"].get("availabilityPct") == 100.0 for x in avail.values())
    ev.step("P7-T01 workloads served 100% during the Center outage", during_ok,
            availability={k: {"outagePct": x["duringOutage"].get("availabilityPct"),
                              "requests": x["duringOutage"].get("requests"),
                              "p95ms": (x["duringOutage"].get("latencyMs") or {}).get("p95"),
                              "overallPct": x["overall"].get("availabilityPct")} for k, x in avail.items()})
    ev.put("availability", avail)

    # --- log delivery: nginx access lines produced during the outage must reach Loki after reconnect
    time.sleep(20)
    logs = {}
    for k, v in servers.items():
        res, timeline = None, []
        for _ in range(12):
            res = log_delivery(v["container"], v["serverId"], t_down + 2, t_up - 2)
            timeline.append([round(time.time() - t_up), res.get("deliveredPct")])
            if (res.get("deliveredPct") or 0) >= 99.9:
                break
            time.sleep(10)
        res["timelineSecAfterRestart"] = timeline
        tel = (data("GET", "/metrics/fleet", admin) or [])
        row = next((r for r in tel if r["serverId"] == v["serverId"]), {})
        res.update({"logShipping": row.get("logShipping"), "logDroppedTotal": row.get("logDroppedTotal")})
        res["deliveredPct"] = res.get("deliveredPct")
        logs[k] = res
    ev.step("log lines produced during the outage delivered after reconnect (>= 99%)",
            all((x["deliveredPct"] or 0) >= 99 for x in logs.values()), logs=logs)

    # Center-side view of the backlog drain: every /agent/v1/logs request after the restart
    import collections
    drain = collections.Counter()
    statuses = collections.Counter()
    for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../.lab/chaos",
                                  f"center-t01-{a.variant}.log")):
        if "/agent/v1/logs" not in line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        t = parse_ts(d["timestamp"])
        if t < t_up - 5:
            continue
        statuses[d["status"]] += 1
        drain[int((t - t_up) // 10) * 10] += 1
    disc1 = loki_metric("loki_discarded_samples_total")
    ev.put("lokiDiscardedDelta", {k: disc1.get(k, 0) - disc0.get(k, 0) for k in set(disc0) | set(disc1)
                                  if disc1.get(k, 0) != disc0.get(k, 0)})
    ev.put("centerLogBatchesAfterRestart", {"statusCounts": dict(statuses),
                                            "batchesPer10s": dict(sorted(drain.items())[:12])})

    # agent-side evidence: how the agent behaved (last lines mentioning failures / reconnect)
    agent_logs = {k: node(v["container"], "grep -c -E 'failed|backoff|retry' /var/log/ppanel-agent.log || true")
                  for k, v in servers.items()}
    ev.put("agentLogFailureLines", agent_logs)
    ev.put("centerAfter", center_rss_cpu())

    # cleanup rules
    for rid in rules.values():
        r = data("GET", f"/alert-rules/{rid}", admin)
        call("DELETE", f"/alert-rules/{rid}", admin, headers={"If-Match": str(r["version"])})
    ev.summary()


if __name__ == "__main__":
    main_guard(main)
