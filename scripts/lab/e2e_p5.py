#!/usr/bin/env python3
"""pPanel P5 lab E2E: real Center API + real Go agents + Prometheus/Loki/Mailpit/receiver.

Covers P5-T01 (agent loss -> alert -> signed webhook -> ack recorded -> resolved), P5-T02 (server-scoped
viewer cannot read another server's logs/metrics/incidents), P5-T03 (secrets in real nginx access logs
never reach Loki or the API unredacted), P5-T04 (Center outage: agent buffers within its cap and
delivers after reconnect), metrics via Prometheus scrape with stale gaps, email + telegram channel tests.

Prereqs: lab up; scripts/observability/up.sh; agent with P5 telemetry copied to .lab/agent-bin;
NO Center running on :4000 (this script starts and restarts it with the P5 env).
Run: python3 -I scripts/lab/e2e_p5.py [--out docs/evidence/<date>/p5-e2e.json]
"""
import hashlib
import hmac
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + "/../..")
API = "http://localhost:4000/api/v1"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
RECEIVER = "http://127.0.0.1:58080"
TAG = str(int(time.time()) % 100000)
results, responses = [], []
api_proc = None


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:320] if info else ""), flush=True)
    if not ok:
        finish(1)


def finish(code):
    if "--out" in sys.argv:
        with open(sys.argv[sys.argv.index("--out") + 1], "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": results}, f, indent=2)
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def http(method, url, body=None, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return 0, ""  # not listening (yet) / connection dropped


def call(method, path, token=None, body=None, headers=None, expect=None):
    h = {"X-Request-ID": str(uuid.uuid4())}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    st, text = http(method, API + path, body, h)
    responses.append(text)
    payload = json.loads(text) if text else {}
    if expect is not None and st not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {st} (expected {expect}): {text[:600]}")
    return st, payload


def sh(*argv, check=True):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=300)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {p.stderr[:300]}")
    return p.stdout.strip()


def node(n, cmd):
    return sh("docker", "exec", n, "sh", "-c", cmd)


def poll(fn, timeout, every=3, what="condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(every)
    raise SystemExit(f"timeout waiting for {what}")


def start_api():
    global api_proc
    env = dict(os.environ,
               API_HOST="0.0.0.0",
               PPANEL_PUBLIC_GATEWAY_URL="https://host.docker.internal:4443",
               PPANEL_PUBLIC_API_URL="http://host.docker.internal:4000",
               PPANEL_PUBLIC_WEB_URL="http://localhost:3100",
               PPANEL_PROMETHEUS_URL="http://127.0.0.1:59090",
               PPANEL_LOKI_URL="http://127.0.0.1:53100",
               PPANEL_METRICS_SCRAPE_TOKEN_FILE=f"{ROOT}/.lab/observability/scrape-token",
               PPANEL_WEBHOOK_HTTP_ALLOWLIST="127.0.0.1:58080",
               PPANEL_WEBHOOK_ALLOWLIST="127.0.0.1:58080",
               PPANEL_SMTP_URL="smtp://127.0.0.1:51025",
               PPANEL_SMTP_FROM="ppanel-lab@ppanel.local",
               PPANEL_TELEGRAM_API_BASE=f"{RECEIVER}/telegram")
    log = open(f"{ROOT}/.lab/evidence/e2e-p5-api.log", "a")
    api_proc = subprocess.Popen(["pnpm", "--filter", "@ppanel/api", "dev"], cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
    poll(lambda: http("GET", API + "/setup/status")[0] == 200, 90, 1, "API start")


def stop_api():
    if api_proc and api_proc.poll() is None:
        os.killpg(api_proc.pid, signal.SIGTERM)
        api_proc.wait(timeout=30)
    for port in ("4000", "4443"):
        pids = sh("lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN", check=False).split()
        for p in pids:
            os.kill(int(p), signal.SIGTERM)
    time.sleep(2)


def login(email, pw):
    return call("POST", "/auth/login", body={"email": email, "password": pw}, expect=200)[1]["data"]["accessToken"]


def enroll(token, container, name):
    _, e = call("POST", "/enrollments", token, {"name": name, "environment": "uat", "ttlMinutes": 10}, expect=201)
    node(container, "pkill -f '[p]panel-agent-linux-arm64 run' || true; find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", container, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["data"]["token"], "--state-dir", "/var/lib/ppanel-agent")
    start_agent(container)
    return out.split("serverId=")[1].split()[0]


def start_agent(container):
    sh("docker", "exec", "-d", container, "sh", "-c",
       f"{AGENT} run --state-dir /var/lib/ppanel-agent > /var/log/ppanel-agent.log 2>&1")


def logs(token, **params):
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return call("GET", f"/logs/query?{q}", token)


def main():
    stop_api()
    start_api()
    admin = login("superadmin@ppanel.local", "password")
    sa = enroll(admin, "ppanel-lab-node-a", f"p5-node-a-{TAG}")
    sb = enroll(admin, "ppanel-lab-node-b", f"p5-node-b-{TAG}")
    for sid in (sa, sb):
        poll(lambda: call("GET", f"/servers/{sid}", admin, expect=200)[1]["data"]["status"] == "online", 90,
             what="online")
    step("two agents with P5 telemetry online", True, serverA=sa, serverB=sb)

    # --- P5-T03: secrets in real nginx access log lines are redacted end to end
    marker = f"p5probe{TAG}"
    raw_key = "sk_live_" + secrets.token_hex(12)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwNSJ9." + secrets.token_hex(8)
    node("ppanel-lab-node-a",
         f"curl -s -o /dev/null 'http://127.0.0.1/{marker}?api_key={raw_key}&token={jwt}' -H 'Host: static.example.lab' || true")

    def found():
        st, r = logs(admin, serverId=sa, source="nginx_access", q=marker)
        return r.get("data") if st == 200 and r.get("data") else None

    entries = poll(found, 120, 3, "log line in Loki via API")
    line = entries[0]["line"]
    lq = urllib.parse.urlencode({"query": '{server_id="%s"} |= "%s"' % (sa, marker), "limit": "50"})
    _, loki_raw = http("GET", f"http://127.0.0.1:53100/loki/api/v1/query_range?{lq}")
    step("P5-T03 api_key and JWT redacted in API result AND in Loki storage",
         "[REDACTED]" in line and raw_key not in line and jwt not in line
         and marker in loki_raw and raw_key not in loki_raw and jwt not in loki_raw,
         line=line[:160])

    # --- metrics via Prometheus scrape
    def series():
        st, r = call("GET", f"/metrics/series?scope=server&id={sa}&metric=cpu&range=1h", admin)
        pts = [p for p in (r.get("data") or {}).get("points", []) if p[1] is not None]
        return r["data"] if st == 200 and pts else None

    s = poll(series, 120, 5, "cpu series from Prometheus")
    _, prom = http("GET", "http://127.0.0.1:59090/api/v1/query?" + urllib.parse.urlencode(
        {"query": f'ppanel_server_up{{server_id="{sa}"}}'}))
    step("metrics: Prometheus scrapes the Center; series has real points",
         '"1"' in prom and any(p[1] is not None for p in s["points"]),
         points=sum(1 for p in s["points"] if p[1] is not None), unit=s.get("unit"))

    # --- P5-T02: viewer scoped to server B
    pw = secrets.token_urlsafe(16)
    vemail = f"p5-viewer-{TAG}@ppanel.local"
    call("POST", "/users", admin, {"email": vemail, "password": pw, "displayName": "P5 scoped viewer",
                                   "bindings": [{"roleKey": "viewer", "scopeType": "server", "scopeId": sb}]},
         expect=201)
    viewer = login(vemail, pw)
    st_logs_a, _ = logs(viewer, serverId=sa, q=marker)
    st_met_a, _ = call("GET", f"/metrics/series?scope=server&id={sa}&metric=cpu&range=1h", viewer)
    st_logs_b, _ = logs(viewer, serverId=sb)
    st_inj, inj = logs(viewer, serverId=sb, q='"} |= "" or {server_id=~".+')
    leaked = marker in (inj and json.dumps(inj) or "")
    st_q, _ = call("GET", f"/logs/query?serverId={sb}&query=%7Bserver_id%3D~%22.%2B%22%7D", viewer)
    step("P5-T02 server-scoped viewer: other server 404, own server ok, LogQL injection contained",
         st_logs_a == 404 and st_met_a == 404 and st_logs_b == 200 and not leaked and st_q in (400, 422),
         logsA=st_logs_a, metricsA=st_met_a, logsB=st_logs_b, injection=st_inj, rawQueryParam=st_q)

    # --- channels: webhook (signed), email (Mailpit), telegram (fake API)
    http("DELETE", f"{RECEIVER}/_requests")
    signing = secrets.token_hex(24)
    _, wh = call("POST", "/notification-channels", admin, {"type": "webhook", "name": f"lab-hook-{TAG}",
                                                           "config": {"url": f"{RECEIVER}/hook", "signingSecret": signing}},
                 expect=201)
    _, em = call("POST", "/notification-channels", admin, {"type": "email", "name": f"lab-mail-{TAG}",
                                                           "config": {"to": ["oncall@ppanel.local"]}}, expect=201)
    _, tg = call("POST", "/notification-channels", admin, {"type": "telegram", "name": f"lab-tg-{TAG}",
                                                           "config": {"botToken": "123456:" + "A" * 30,
                                                                      "chatId": "-1001234567"}}, expect=201)
    _, mail_before = http("GET", "http://127.0.0.1:58025/api/v1/messages")
    t_email = call("POST", f"/notification-channels/{em['data']['id']}/test", admin, expect=200)[1]["data"]
    t_tg = call("POST", f"/notification-channels/{tg['data']['id']}/test", admin, expect=200)[1]["data"]
    _, mail_after = http("GET", "http://127.0.0.1:58025/api/v1/messages")
    secret_in_api = any(signing in t or ("A" * 30) in t for t in responses)
    step("email + telegram test deliveries; channel secrets never returned",
         t_email.get("delivered") and t_tg.get("delivered")
         and json.loads(mail_after).get("total", 0) > json.loads(mail_before).get("total", 0) and not secret_in_api,
         email=t_email, telegram=t_tg)

    # --- P5-T01: agent loss -> alert -> signed webhook -> ack -> resolved
    _, rule = call("POST", "/alert-rules", admin, {"name": f"node-b offline {TAG}", "kind": "server_offline",
                                                   "scopeType": "server", "scopeId": sb, "severity": "critical",
                                                   "forSec": 15, "channelIds": [wh["data"]["id"]]}, expect=201)
    node("ppanel-lab-node-b", "pkill -f '[p]panel-agent-linux-arm64 run' || true")
    t0 = time.time()

    def firing():
        _, r = call("GET", "/incidents?status=firing", admin, expect=200)
        return next((i for i in r["data"] if i.get("ruleId") == rule["data"]["id"]), None)

    inc = poll(firing, 300, 5, "incident firing")
    hooks = poll(lambda: [x for x in json.loads(http("GET", f"{RECEIVER}/_requests")[1])["requests"]
                          if x["path"] == "/hook" and x["headers"].get("x-ppanel-event") == "fired"], 60, 3, "webhook")
    hk = hooks[-1]
    expected = "sha256=" + hmac.new(signing.encode(), hk["body"].encode(), hashlib.sha256).hexdigest()
    sig_ok = hmac.compare_digest(expected, hk["headers"].get("x-ppanel-signature", ""))
    st_vack, _ = call("POST", f"/incidents/{inc['id']}/acknowledge", viewer, {"comment": "viewer"})
    _, ack = call("POST", f"/incidents/{inc['id']}/acknowledge", admin, {"comment": "on it (lab)"}, expect=200)
    start_agent("ppanel-lab-node-b")

    def resolved():
        _, r = call("GET", f"/incidents/{inc['id']}", admin, expect=200)
        return r["data"] if r["data"]["status"] == "resolved" else None

    done = poll(resolved, 240, 5, "incident resolved")
    types = [e["type"] for e in done.get("timeline", [])]
    step("P5-T01 node-b agent loss -> incident -> HMAC-signed webhook -> ack recorded -> auto-resolved",
         sig_ok and st_vack in (403, 404) and ack["data"]["status"] == "acknowledged"
         and done.get("acknowledgedBy") and {"fired", "notified", "acknowledged", "resolved"} <= set(types)
         and marker not in hk["body"] and raw_key not in hk["body"] and signing not in hk["body"],
         firedAfterSec=int(time.time() - t0), signatureValid=sig_ok, viewerAck=st_vack, timeline=types)

    # --- P5-T04: Center outage; agent buffers within cap and delivers after reconnect
    stop_api()
    outage_marker = f"p5outage{TAG}"
    node("ppanel-lab-node-a",
         f"for i in $(seq 1 300); do curl -s -o /dev/null http://127.0.0.1/{outage_marker}-$i -H 'Host: static.example.lab'; done")
    time.sleep(20)
    buf = node("ppanel-lab-node-a", "du -sb /var/lib/ppanel-agent/logs/buffer | cut -f1")
    nginx_ok = node("ppanel-lab-node-a", "curl -s -o /dev/null -w '%{http_code}' -H 'Host: static.example.lab' http://127.0.0.1/")
    start_api()
    admin = login("superadmin@ppanel.local", "password")

    def delivered():
        st, r = logs(admin, serverId=sa, source="nginx_access", q=outage_marker, limit=1000)
        return r.get("data") if st == 200 and len(r.get("data") or []) >= 300 else None

    got = poll(delivered, 180, 5, "outage lines delivered")
    _, srv = call("GET", f"/metrics/fleet", admin, expect=200)
    ship = next((x.get("logShipping") for x in srv["data"] if x.get("serverId") == sa), None) or {}
    step("P5-T04 Center down: site kept serving, agent buffered within cap, all lines delivered after reconnect",
         nginx_ok == "200" and int(buf) <= int(ship.get("bufferCapBytes", 67108864)) and len(got) >= 300,
         bufferedDuringOutageBytes=int(buf), cap=ship.get("bufferCapBytes"), delivered=len(got),
         dropped=ship.get("droppedEntries"))
    finish(0)


if __name__ == "__main__":
    os.chdir(ROOT)
    try:
        main()
    finally:
        pass
