"""Shared helpers for the P7 chaos / resilience scripts (lab only).

Talks only to localhost (Center API :4000, gateway :4443, dev Postgres container) and to the
`ppanel-*` lab containers. Never touches any other container. Every scenario writes a JSON evidence
file under docs/evidence/<date>/p7-*.json via `Evidence`.

The Center under test is a *snapshot* of apps/api/dist/main.js copied to .lab/chaos/api/ so that
other agents rebuilding apps/api cannot change the code between restarts of a scenario. It runs with
cwd=apps/api (its .env) and NODE_PATH=apps/api/node_modules. Its PID is kept in .lab/chaos/center.pid
so any chaos script can stop/restart the Center another one started.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import signal
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
API = "http://localhost:4000/api/v1"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
NODE_A, NODE_B = "ppanel-lab-node-a", "ppanel-lab-node-b"
DIND = ["docker", "exec", "ppanel-lab-dind", "docker", "-H", "unix:///run/dind/docker.sock"]
PG = "ppanel-dev-postgres-1"
CHAOS = os.path.join(ROOT, ".lab", "chaos")
SNAP = os.path.join(CHAOS, "api")
PIDFILE = os.path.join(CHAOS, "center.pid")
FLEET = os.path.join(CHAOS, "fleet.json")
DATE = time.strftime("%Y-%m-%d", time.gmtime())
EVID = os.path.join(ROOT, "docs", "evidence", DATE)
os.makedirs(CHAOS, exist_ok=True)
os.makedirs(EVID, exist_ok=True)

# Env of the Center under test: lab gateway URLs + P5 observability + P6 backups.
CENTER_ENV = {
    "API_HOST": "0.0.0.0",
    "PPANEL_PUBLIC_GATEWAY_URL": "https://host.docker.internal:4443",
    "PPANEL_PUBLIC_API_URL": "http://host.docker.internal:4000",
    "PPANEL_PUBLIC_WEB_URL": "http://localhost:3100",
    "PPANEL_PROMETHEUS_URL": "http://127.0.0.1:59090",
    "PPANEL_LOKI_URL": "http://127.0.0.1:53100",
    "PPANEL_METRICS_SCRAPE_TOKEN_FILE": os.path.join(ROOT, ".lab/observability/scrape-token"),
    "PPANEL_WEBHOOK_HTTP_ALLOWLIST": "127.0.0.1:58080",
    "PPANEL_WEBHOOK_ALLOWLIST": "127.0.0.1:58080",
    "PPANEL_SMTP_URL": "smtp://127.0.0.1:51025",
    "PPANEL_SMTP_FROM": "ppanel-lab@ppanel.local",
    "PPANEL_TELEGRAM_API_BASE": "http://127.0.0.1:58080/telegram",
    "PPANEL_BACKUP_SCHEDULER_INTERVAL_MS": "5000",
    "NODE_USE_SYSTEM_CA": "1",
}


# ------------------------------------------------------------------ evidence
class Evidence:
    def __init__(self, name, meta=None):
        self.name = name
        self.path = os.path.join(EVID, f"p7-{name}.json")
        self.data = {"scenario": name, "startedAt": iso(), "meta": meta or {}, "steps": []}
        self.data["meta"]["center"] = center_build_info()
        self.data["meta"]["agentSha256"] = sh("docker", "exec", NODE_A, "sha256sum", AGENT, check=False)[:64]

    def step(self, name, verdict, **info):
        """verdict: True/False or 'PASS'|'FAIL'|'BLOCKED'|'INFO'."""
        v = verdict if isinstance(verdict, str) else ("PASS" if verdict else "FAIL")
        self.data["steps"].append({"step": name, "result": v, "at": iso(), **info})
        print(f"{v:7} {name}  " + json.dumps(info, default=str)[:400], flush=True)
        self.save()
        return v == "PASS"

    def put(self, key, value):
        self.data[key] = value
        self.save()

    def save(self):
        self.data["updatedAt"] = iso()
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)

    def summary(self):
        c = {}
        for s in self.data["steps"]:
            c[s["result"]] = c.get(s["result"], 0) + 1
        self.data["summary"] = c
        self.save()
        print("SUMMARY", c, "->", os.path.relpath(self.path, ROOT))
        return c


def iso(t=None):
    t = time.time() if t is None else t
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"


# ------------------------------------------------------------------ http
def http(method, url, body=None, headers=None, raw=None, timeout=60):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), time.time() - t0
    except Exception:  # noqa: BLE001 - connection refused / reset / timeout
        return 0, "", time.time() - t0


def call(method, path, token=None, body=None, headers=None, expect=None, raw=None, timeout=60):
    h = {"X-Request-ID": str(uuid.uuid4())}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    st, text, _ = http(method, API + path, body, h, raw, timeout)
    try:
        payload = json.loads(text) if text else {}
    except ValueError:
        payload = {"raw": text[:500]}
    if expect is not None and st not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {st} (expected {expect}): {text[:600]}")
    return st, payload


def data(method, path, token=None, body=None, headers=None, expect=(200, 201, 202)):
    return call(method, path, token, body, headers, expect)[1]["data"]


def login(email="superadmin@ppanel.local", pw="password"):
    return call("POST", "/auth/login", body={"email": email, "password": pw}, expect=200)[1]["data"]["accessToken"]


def poll(fn, timeout, every=2.0, what="condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
        except SystemExit:
            last = None
        if last:
            return last
        time.sleep(every)
    raise SystemExit(f"timeout waiting for {what}")


def poll_get(path, token, done, timeout=180, every=2.0):
    def f():
        st, r = call("GET", path, token)
        return r["data"] if st == 200 and done(r["data"]) else None
    return poll(f, timeout, every, path)


def totp(secret_b32, offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30 + offset), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


class Approver:
    """ops_admin user with TOTP, for approval + step-up (approver != creator)."""

    def __init__(self, admin, tag):
        pw = base64.urlsafe_b64encode(os.urandom(15)).decode()
        self.email = f"p7-approver-{tag}-{os.urandom(3).hex()}@ppanel.local"
        call("POST", "/users", admin, {"email": self.email, "password": pw, "displayName": "P7 approver",
                                       "bindings": [{"roleKey": "ops_admin", "scopeType": "global"}]}, expect=201)
        self.token = login(self.email, pw)
        _, s = call("POST", "/auth/mfa/totp/setup", self.token, expect=200)
        self.secret = urllib.parse.parse_qs(urllib.parse.urlparse(s["data"]["otpauthUrl"]).query)["secret"][0]
        call("POST", "/auth/mfa/totp/confirm", self.token, {"code": totp(self.secret)}, expect=200)
        self._last_window = int(time.time()) // 30

    def step_up(self):
        # TOTP codes are single-use: wait for a fresh 30 s window
        while int(time.time()) // 30 <= self._last_window:
            time.sleep(0.5)
        self._last_window = int(time.time()) // 30
        return call("POST", "/auth/step-up", self.token, {"code": totp(self.secret)},
                    expect=200)[1]["data"]["stepUpToken"]


# ------------------------------------------------------------------ shell / lab
def sh(*argv, check=True, timeout=300, input_=None):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, input=input_)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {p.stderr[:400]}")
    return p.stdout.strip()


def node(n, cmd, check=True, timeout=120):
    return sh("docker", "exec", n, "sh", "-c", cmd, check=check, timeout=timeout)


def psql(sql):
    return sh("docker", "exec", "-i", PG, "psql", "-U", "ppanel", "-d", "ppanel", "-At", "-F", "\t", "-c", sql)


def psql_rows(sql):
    out = psql(sql)
    return [line.split("\t") for line in out.splitlines() if line]


def start_agent(n):
    node(n, "pgrep -f '[p]panel-agent-linux-arm64 run' >/dev/null || true")
    sh("docker", "exec", "-d", n, "sh", "-c",
       f"{AGENT} run --state-dir /var/lib/ppanel-agent >> /var/log/ppanel-agent.log 2>&1")


def stop_agent(n, sig="TERM"):
    node(n, f"pkill -{sig} -f '[p]panel-agent-linux-arm64 run' || true")
    for _ in range(40):
        if not node(n, "pgrep -f '[p]panel-agent-linux-arm64 run' || true"):
            return
        time.sleep(0.25)


def agent_running(n):
    return bool(node(n, "pgrep -f '[p]panel-agent-linux-arm64 run' || true"))


def site_code(n, host, path="/"):
    return node(n, f"curl -s -o /dev/null -m 5 -w '%{{http_code}}' -H 'Host: {host}' http://127.0.0.1{path} || true")


def site_body(n, host, path="/"):
    return node(n, f"curl -s -m 5 -H 'Host: {host}' http://127.0.0.1{path} || true")


def nginx_hash(n):
    return node(n, "find /etc/nginx -type f -o -type l | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -c1-16")


# ------------------------------------------------------------------ traffic probes inside the nodes
PROBE_SCRIPT = r"""
host="$1"; out="$2"; rate="$3"; dur="$4"
gap=$(awk "BEGIN{print 1/$rate}")
end=$(( $(date +%s) + dur ))
: > "$out"
i=0
while [ "$(date +%s)" -lt "$end" ]; do
  t=$(date +%s%3N)
  i=$((i+1))
  r=$(curl -s -o /dev/null -m 2 -w '%{http_code} %{time_total}' -H "Host: $host" "http://127.0.0.1/?p7probe=$t-$i" 2>/dev/null || echo "000 2")
  echo "$t $r" >> "$out"
  sleep "$gap"
done
echo done >> "$out.done"
"""


def probe_start(n, host, tag, rate=5, duration=900):
    out = f"/tmp/p7probe-{tag}.log"
    sh("docker", "exec", "-i", n, "sh", "-c", "cat > /tmp/p7probe.sh", input_=PROBE_SCRIPT)
    sh("docker", "exec", "-d", n, "bash", "/tmp/p7probe.sh", host, out, str(rate), str(duration))
    return (n, out)


def probe_stop(n):
    node(n, "pkill -f '[p]7probe.sh' || true", check=False)


def probe_read(handle):
    n, out = handle
    rows = []
    for line in node(n, f"cat {out} 2>/dev/null || true").splitlines():
        p = line.split()
        if len(p) == 3:
            rows.append((int(p[0]) / 1000.0, p[1], float(p[2])))
    return rows


def probe_stats(rows, t_from=None, t_to=None):
    sel = [r for r in rows if (t_from is None or r[0] >= t_from) and (t_to is None or r[0] <= t_to)]
    if not sel:
        return {"requests": 0}
    ok = [r for r in sel if r[1].startswith("2") or r[1].startswith("3")]
    lat = sorted(r[2] * 1000 for r in sel)
    return {"requests": len(sel), "ok": len(ok), "availabilityPct": round(100.0 * len(ok) / len(sel), 3),
            "statuses": {s: sum(1 for r in sel if r[1] == s) for s in sorted({r[1] for r in sel})},
            "latencyMs": {"p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99), "max": round(lat[-1], 1)},
            "ratePerSec": round(len(sel) / max(1e-9, sel[-1][0] - sel[0][0]), 2) if len(sel) > 1 else None}


def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    k = max(0, min(len(sorted_vals) - 1, int(round(p / 100.0 * len(sorted_vals) + 0.5)) - 1))
    return round(sorted_vals[k], 1)


# ------------------------------------------------------------------ Center lifecycle (snapshot build)
def snapshot_center(force=False):
    src = os.path.join(ROOT, "apps/api/dist/main.js")
    dst = os.path.join(SNAP, "main.js")
    if force or not os.path.exists(dst):
        os.makedirs(SNAP, exist_ok=True)
        shutil.copy2(src, dst)
        if os.path.exists(src + ".map"):
            shutil.copy2(src + ".map", dst + ".map")
        info = {"sourceCommit": sh("git", "-C", ROOT, "rev-parse", "HEAD"),
                "sourceDirty": bool(sh("git", "-C", ROOT, "status", "--porcelain", "apps/api", "packages")),
                "distMtime": iso(os.path.getmtime(src)), "snapshotAt": iso(),
                "sha256": hashlib.sha256(open(dst, "rb").read()).hexdigest()}
        json.dump(info, open(os.path.join(SNAP, "info.json"), "w"), indent=2)
    return center_build_info()


def center_build_info():
    p = os.path.join(SNAP, "info.json")
    return json.load(open(p)) if os.path.exists(p) else None


def center_pid():
    try:
        pid = int(open(PIDFILE).read().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def listening_pids(port):
    return [int(p) for p in sh("lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN", check=False).split()]


def center_up():
    return http("GET", API + "/setup/status", timeout=3)[0] == 200


def start_center(extra=None, log_name="center", wait=True):
    """Start the snapshot Center. Returns seconds until /setup/status answered 200."""
    if center_pid() or listening_pids(4000):
        raise SystemExit("a Center is already running on :4000 — stop it first")
    snapshot_center()
    env = dict(os.environ, **CENTER_ENV, **(extra or {}))
    env["NODE_PATH"] = os.path.join(ROOT, "apps/api/node_modules")
    log = open(os.path.join(CHAOS, f"{log_name}.log"), "a")
    log.write(f"\n===== start {iso()} extra={json.dumps(extra or {})}\n")
    log.flush()
    p = subprocess.Popen(["node", "--enable-source-maps", os.path.join(SNAP, "main.js")],
                         cwd=os.path.join(ROOT, "apps/api"), env=env, stdout=log, stderr=subprocess.STDOUT,
                         start_new_session=True)
    open(PIDFILE, "w").write(str(p.pid))
    t0 = time.time()
    if wait:
        poll(center_up, 90, 0.25, "Center start")
    return round(time.time() - t0, 2)


def stop_center(sig=signal.SIGTERM, timeout=30):
    """Stop the Center (ours via pidfile, or whatever listens on :4000/:4443 — lab only)."""
    pids = set(listening_pids(4000) + listening_pids(4443))
    pid = center_pid()
    if pid:
        pids.add(pid)
    for p in pids:
        try:
            os.kill(p, sig)
        except OSError:
            pass
    end = time.time() + timeout
    while time.time() < end and (listening_pids(4000) or listening_pids(4443)):
        time.sleep(0.2)
    for p in listening_pids(4000) + listening_pids(4443):
        os.kill(p, signal.SIGKILL)
    try:
        os.remove(PIDFILE)
    except OSError:
        pass
    time.sleep(0.5)


def ensure_center(extra=None):
    if not center_up():
        stop_center()
        start_center(extra)


def center_rss_cpu():
    pid = center_pid()
    if not pid:
        return None
    out = sh("ps", "-o", "rss=,%cpu=,time=", "-p", str(pid), check=False).split()
    return {"rssMb": round(int(out[0]) / 1024, 1), "cpuPct": float(out[1]), "cpuTime": out[2]} if out else None


# ------------------------------------------------------------------ fleet state
def fleet():
    if not os.path.exists(FLEET):
        raise SystemExit("no fleet state: run scripts/chaos/setup_fleet.py first")
    return json.load(open(FLEET))


def save_fleet(f):
    json.dump(f, open(FLEET, "w"), indent=2)


def job(token, sid, jtype, params, ttl=None, headers=None, expect=(200, 202)):
    body = {"type": jtype, "params": params}
    if ttl:
        body["ttlSec"] = ttl
    return call("POST", f"/servers/{sid}/jobs", token, body, headers, expect)[1]["data"]


def job_get(token, sid, jid):
    """Job read model; the API puts an expiry/failure error under result.error — normalised into `error`."""
    j = call("GET", f"/servers/{sid}/jobs/{jid}", token, expect=200)[1]["data"]
    if not j.get("error") and isinstance(j.get("result"), dict) and isinstance(j["result"].get("error"), dict):
        j["error"] = j["result"]["error"]
        j["resultOnlyError"] = set(j["result"].keys()) == {"error"}
    return j


def main_guard(fn):
    os.chdir(ROOT)
    try:
        fn()
    except SystemExit as e:
        if e.code not in (0, None):
            print("ABORT:", e.code, file=sys.stderr)
        raise


# ------------------------------------------------------------------ exact log delivery (probe ids)
def _loki_probe_ids(server_id, t_from, t_to):
    import re
    ids, start = set(), int(t_from * 1e9)
    end = int(t_to * 1e9)
    q = f'{{server_id="{server_id}",source="nginx_access"}} |= "p7probe="'
    while start < end:
        u = "http://127.0.0.1:53100/loki/api/v1/query_range?" + urllib.parse.urlencode(
            {"query": q, "start": str(start), "end": str(end), "limit": "5000", "direction": "forward"})
        st, text, _ = http("GET", u, timeout=60)
        if st != 200:
            return None
        vals = [v for s in json.loads(text)["data"]["result"] for v in s["values"]]
        if not vals:
            break
        before = len(ids)
        for v in vals:
            m = re.search(r"p7probe=([0-9]+-[0-9]+)", v[1])
            if m:
                ids.add(m.group(1))
        last = max(int(v[0]) for v in vals)
        if len(vals) < 5000 or len(ids) == before:
            break
        # many lines share one timestamp (one per agent poll): restart AT the last timestamp, not after it,
        # or the rest of that timestamp group is skipped at the page boundary
        start = last
    return ids


def log_delivery(container, server_id, t_from, t_to):
    """Exact delivery ratio of probe access-log lines whose probe send time is in [t_from, t_to]:
    ids found in the node's access.log vs ids present in Loki for that server."""
    import re
    file_ids = set()
    for line in node(container, "grep -o 'p7probe=[0-9]*-[0-9]*' /var/log/nginx/access.log || true",
                     timeout=120).splitlines():
        m = re.match(r"p7probe=([0-9]+)-([0-9]+)", line)
        if m and t_from * 1000 <= int(m.group(1)) <= t_to * 1000:
            file_ids.add(f"{m.group(1)}-{m.group(2)}")
    loki = _loki_probe_ids(server_id, t_from - 60, t_to + 900)
    if loki is None:
        return {"inFile": len(file_ids), "inLoki": None}
    got = len(file_ids & loki)
    return {"inFile": len(file_ids), "inLoki": got,
            "deliveredPct": round(100.0 * got / len(file_ids), 2) if file_ids else None}
