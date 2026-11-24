#!/usr/bin/env python3
"""P7 log-delivery root cause check (lab only, no outage): identical vs unique nginx access lines.

60 s of 5 req/s with byte-identical requests (same path, same UA marker) and 60 s of 5 req/s with a unique
query string per request, both on node-a static.example.lab with the Center UP. Counts lines in the node's
access.log vs lines in Loki for that server (LogQL line filter on the marker), plus Loki's own
discarded-samples counters and the Center's log batch rows. Shows whether identical lines collapse.
Run: python3 -I scripts/chaos/log_dedup.py
"""
import json
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import Evidence, fleet, http, main_guard, node  # noqa: E402

LOKI = "http://127.0.0.1:53100"


def loki_metric(prefix):
    st, text, _ = http("GET", LOKI + "/metrics", timeout=10)
    out = {}
    for line in text.splitlines():
        if line.startswith(prefix):
            k, v = line.rsplit(" ", 1)
            out[k] = float(v)
    return out


def loki_lines(sid, marker, t0, t1):
    q = f'sum(count_over_time({{server_id="{sid}",source="nginx_access"}} |= "{marker}" [{int(t1 - t0)}s]))'
    st, text, _ = http("GET", f"{LOKI}/loki/api/v1/query?" + urllib.parse.urlencode({"query": q, "time": str(int(t1 * 1e9))}))
    r = json.loads(text)["data"]["result"] if st == 200 else []
    return int(float(r[0]["value"][1])) if r else 0


def sample_ts(sid, marker, t0, t1):
    q = f'{{server_id="{sid}",source="nginx_access"}} |= "{marker}"'
    st, text, _ = http("GET", f"{LOKI}/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": q, "start": str(int(t0 * 1e9)), "end": str(int(t1 * 1e9)), "limit": "12", "direction": "forward"}))
    return [(v[0], v[1][:80]) for s in json.loads(text)["data"]["result"] for v in s["values"]][:6] if st == 200 else []


def main():
    fl = fleet()
    A = fl["nodeA"]
    ev = Evidence("log-dedup")
    disc0 = loki_metric("loki_discarded_samples_total")
    tag = str(int(time.time()))
    res = {}
    for mode in ("same", "uniq"):
        marker = f"p7dedup-{mode}-{tag}"
        url = "http://127.0.0.1/" if mode == "same" else "http://127.0.0.1/?u=$i"
        t0 = time.time()
        node(A["container"], f"i=0; end=$(( $(date +%s) + 60 )); while [ $(date +%s) -lt $end ]; do i=$((i+1)); "
                             f"curl -s -o /dev/null -A '{marker}' -H 'Host: static.example.lab' \"{url}\"; sleep 0.2; done",
             timeout=120)
        t1 = time.time()
        time.sleep(20)
        in_file = int(node(A["container"], f"grep -c -F '{marker}' /var/log/nginx/access.log || true") or 0)
        in_loki = loki_lines(A["serverId"], marker, t0 - 30, t1 + 60)
        res[mode] = {"inFile": in_file, "inLoki": in_loki, "pct": round(100.0 * in_loki / in_file, 1) if in_file else None,
                     "sample": sample_ts(A["serverId"], marker, t0 - 30, t1 + 60)}
    disc1 = loki_metric("loki_discarded_samples_total")
    ev.step("identical access lines collapse in Loki (same timestamp + same line = Loki dedup)",
            "INFO", identical=res["same"], unique=res["uniq"],
            lokiDiscardedDelta={k: disc1.get(k, 0) - disc0.get(k, 0) for k in set(disc0) | set(disc1)
                                if disc1.get(k, 0) != disc0.get(k, 0)})
    ev.step("unique lines fully delivered in steady state", (res["uniq"]["pct"] or 0) >= 99.9, **res["uniq"])
    ev.summary()


if __name__ == "__main__":
    main_guard(main)
