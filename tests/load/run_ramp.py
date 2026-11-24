#!/usr/bin/env python3
"""P7.06 load ramp driver (lab only): fake agents 50 → 200 → 500, log lines 0 → 500 → 2000 /s.

For every phase it (1) enrolls fake agents up to N (persisted identities, reused by later phases), (2) runs
`fakefleet` for --phase-sec with the requested log rate and the admin API probe, while sampling the Center
process (RSS/CPU), Postgres size + hot tables, Loki ingest counters and /internal/metrics scrape latency,
and (3) records everything in docs/evidence/<date>/p7-load-ramp.json. A phase that breaks the stop criteria
(heartbeat error > 5 % or heartbeat p95 > 2 s) ends the ramp.

The Center is restarted with TRUST_PROXY=1 (existing config switch) so each fake agent's enrollment uses its own
X-Forwarded-For — the public enroll endpoint is rate-limited to 10/min per IP. Restored without it at the end.
Cleanup (fake servers only): python3 -I tests/load/run_ramp.py --cleanup
  = DELETE FROM servers WHERE name LIKE 'p7load-%' (FK cascades: certificates, heartbeats, telemetry, jobs, …)
  + DELETE FROM agent_enrollments WHERE name LIKE 'p7load-%' ; identities file .lab/load/identities.json removed.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts", "chaos"))
from _lib import (EVID, Evidence, center_pid, center_rss_cpu, http, iso, psql, psql_rows, sh,  # noqa: E402
                  start_center, stop_center)

BIN = os.path.join(ROOT, ".lab/load/fakefleet")
IDS = os.path.join(ROOT, ".lab/load/identities.json")
TABLES = ["agent_heartbeats", "server_telemetry", "container_samples", "log_batches", "audit_events", "servers",
          "agent_certificates", "jobs"]


def pg_sizes():
    db = int(psql("select pg_database_size('ppanel')"))
    rows = psql_rows("select c.relname, pg_total_relation_size(c.oid), coalesce(s.n_live_tup,0) from pg_class c "
                     "left join pg_stat_user_tables s on s.relid=c.oid where c.relname in ('" + "','".join(TABLES) + "')")
    return {"dbBytes": db, "tables": {r[0]: {"bytes": int(r[1]), "rows": int(r[2])} for r in rows}}


def loki_lines():
    st, text, _ = http("GET", "http://127.0.0.1:53100/metrics", timeout=10)
    tot = 0.0
    for line in text.splitlines():
        if line.startswith("loki_distributor_lines_received_total"):
            tot += float(line.split()[-1])
    return tot


def scrape_ms():
    tok = open(os.path.join(ROOT, ".lab/observability/scrape-token")).read().strip()
    st, text, dt = http("GET", "http://localhost:4000/internal/metrics", headers={"Authorization": "Bearer " + tok},
                        timeout=30)
    return st, round(dt * 1000), len(text)


class Sampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.rows = []

    def run(self):
        last_scrape = 0
        while not self.stop.is_set():
            r = {"at": iso(), "center": center_rss_cpu()}
            try:
                cpu = sh("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}",
                         "ppanel-dev-postgres-1", check=False, timeout=20)
                r["postgres"] = cpu
            except Exception:  # noqa: BLE001
                pass
            if time.time() - last_scrape > 15:
                r["scrape"] = scrape_ms()
                last_scrape = time.time()
            self.rows.append(r)
            self.stop.wait(5)


def cpu_secs(t):
    # ps TIME like 1:23.45 or 01:02:03
    p = [float(x) for x in t.split(":")]
    return sum(v * 60 ** i for i, v in enumerate(reversed(p)))


def run_phase(agents, rate, sec):
    if not os.path.exists(IDS) or len(json.load(open(IDS))) < agents:
        t0 = time.time()
        subprocess.run([BIN, "-agents", str(agents), "-enroll-only", "-state", IDS, "-enroll-concurrency", "8"],
                       cwd=ROOT, check=True, capture_output=True, timeout=1800)
        enroll_sec = round(time.time() - t0, 1)
    else:
        enroll_sec = 0
    before = pg_sizes()
    loki0 = loki_lines()
    c0 = center_rss_cpu()
    smp = Sampler()
    smp.start()
    out = os.path.join(ROOT, f".lab/load/phase-{agents}-{int(rate)}.json")
    t0 = time.time()
    p = subprocess.run([BIN, "-agents", str(agents), "-log-rate", str(rate), "-duration", f"{sec}s", "-state", IDS,
                        "-out", out, "-window", "30s"], cwd=ROOT, capture_output=True, text=True, timeout=sec + 600)
    el = time.time() - t0
    smp.stop.set()
    smp.join()
    after = pg_sizes()
    loki1 = loki_lines()
    c1 = center_rss_cpu()
    res = json.load(open(out)) if os.path.exists(out) else {"error": p.stderr[-800:]}
    res.pop("windows", None)
    rss = [r["center"]["rssMb"] for r in smp.rows if r.get("center")]
    cpu_avg = round(100 * (cpu_secs(c1["cpuTime"]) - cpu_secs(c0["cpuTime"])) / el, 1) if c0 and c1 else None
    scr = [r["scrape"] for r in smp.rows if r.get("scrape")]
    return {"agents": agents, "logRate": rate, "phaseSec": round(el), "enrollSec": enroll_sec, "fakefleet": res,
            "center": {"cpuAvgPct": cpu_avg, "rssMbMax": max(rss) if rss else None, "rssMbEnd": rss[-1] if rss else None,
                       "psCpuSamples": [r["center"]["cpuPct"] for r in smp.rows if r.get("center")][-6:]},
            "postgres": {"dbBytesDelta": after["dbBytes"] - before["dbBytes"],
                         "dbBytesPerHour": int((after["dbBytes"] - before["dbBytes"]) * 3600 / el),
                         "dbBytes": after["dbBytes"],
                         "tablesDelta": {k: after["tables"][k]["bytes"] - before["tables"].get(k, {"bytes": 0})["bytes"]
                                         for k in after["tables"]},
                         "rows": {k: v["rows"] for k, v in after["tables"].items()},
                         "dockerStats": [r.get("postgres") for r in smp.rows][-3:]},
            "loki": {"linesReceived": loki1 - loki0, "linesPerSec": round((loki1 - loki0) / el, 1)},
            "scrape": {"samples": scr[-5:], "maxMs": max((s[1] for s in scr), default=None)}}


def cleanup(ev=None):
    n = psql("select count(*) from servers where name like 'p7load-%'")
    t0 = time.time()
    psql("DELETE FROM servers WHERE name LIKE 'p7load-%'")
    psql("DELETE FROM agent_enrollments WHERE name LIKE 'p7load-%'")
    if os.path.exists(IDS):
        os.remove(IDS)
    msg = {"deletedServers": int(n), "sec": round(time.time() - t0, 1),
           "left": psql("select count(*) from servers where name like 'p7load-%'")}
    print("cleanup", msg)
    if ev:
        ev.step("cleanup fake servers from the DB", msg["left"] == "0", **msg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase-sec", type=int, default=180)
    ap.add_argument("--plan", default="50:0,50:500,200:0,200:500,200:2000,500:0,500:500,500:2000")
    ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--keep", action="store_true", help="do not delete fake servers at the end")
    a = ap.parse_args()
    os.chdir(ROOT)
    if a.cleanup:
        cleanup()
        return
    subprocess.run(["go", "build", "-o", BIN, "./cmd/fakefleet"], cwd=os.path.join(ROOT, "tests/load"), check=True)
    hw = {"cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "cores": sh("sysctl", "-n", "hw.ncpu"),
          "memGb": round(int(sh("sysctl", "-n", "hw.memsize")) / 2**30), "os": sh("sw_vers", "-productVersion"),
          "node": sh("node", "--version"), "dockerCpus": sh("docker", "info", "--format", "{{.NCPU}}"),
          "dockerMemGb": round(int(sh("docker", "info", "--format", "{{.MemTotal}}")) / 2**30, 1)}
    ev = Evidence("load-ramp", {"hardware": hw, "phaseSec": a.phase_sec, "plan": a.plan,
                                "note": "Center, fake agents, Postgres (Docker VM) and Loki share one Mac"})
    stop_center()
    start_center({"TRUST_PROXY": "1"}, log_name="center-load")
    ev.step("Center started with TRUST_PROXY=1 for per-agent enrollment IPs", True, pid=center_pid())
    phases = []
    for item in a.plan.split(","):
        n, r = item.split(":")
        ph = run_phase(int(n), float(r), a.phase_sec)
        phases.append(ph)
        ev.put("phases", phases)
        hb = ph["fakefleet"].get("heartbeat") or {}
        ok = hb.get("count", 0) > 0 and hb.get("errorPct", 100) <= 5 and hb.get("p95Ms", 1e9) <= 2000
        ev.step(f"phase {n} agents / {r} lines/s", ok, heartbeatP95=hb.get("p95Ms"), heartbeatErr=hb.get("errorPct"),
                hbPerSec=ph["fakefleet"].get("heartbeatsPerSec"), linesAccepted=ph["fakefleet"].get("linesAcceptedPerSec"),
                cpu=ph["center"]["cpuAvgPct"], rss=ph["center"]["rssMbMax"],
                api={k: (v.get("p95Ms"), v.get("errorPct")) for k, v in (ph["fakefleet"].get("api") or {}).items()})
        if not ok:
            ev.step("stop criteria reached — ramp ended", "INFO", at=item)
            break
    if not a.keep:
        cleanup(ev)
    stop_center()
    start_center(log_name="center")
    ev.step("Center restarted with the normal lab env", True)
    ev.summary()


if __name__ == "__main__":
    main()
