#!/usr/bin/env python3
"""pPanel P9 lab E2E: real Center API (two gateway listeners) + real Go agents + the P9 lab networks.

Covers docs/P9_NETWORK_CONTRACT.md §6:
  P9-T1  provider sync (fake DigitalOcean) detects same region / different VPC; topology finding
         SAME_REGION_DIFFERENT_VPC; pair connectivity test fails across VPCs and passes within one.
  P9-T2  node-a on private_only, cut off the private network -> never connects over public; the Center
         answers 403 CONNECTION_PATH_NOT_ALLOWED on the public listener; reconnects when restored.
  P9-T4  gateway plan -> validate (nginx -t) -> shadow test via Host/SNI override -> approve (second person,
         step-up, production gateway) -> apply -> post-apply verification; documented cutover/rollback.
  P9-T3  Center stopped -> the gateway still serves the hybrid route; route files and nginx unchanged.
  P9-T4  rollback restores the gateway (route no longer served).

Prereqs: dev compose up + prisma migrations applied; scripts/lab/up.sh; scripts/lab/p9-net.sh up; agent built
(make -C apps/agent build; the lab mounts apps/agent/bin or .lab/agent-bin); Center API built
(pnpm --filter @ppanel/api build); NOTHING listening on :4000/:4443/:4444 (this script starts the Center with the
P9 env, stops/restarts it for P9-T3 and stops it at the end).
Run: python3 -I scripts/lab/e2e_p9.py [--build] [--out docs/evidence/<date>/p9-e2e.json]
Lab only: talks to localhost, the ppanel-lab containers and the lab fake DigitalOcean API.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import struct
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
NODE_A, NODE_B, GW = "ppanel-lab-node-a", "ppanel-lab-node-b", "ppanel-lab-gateway"
P9_CFG = "/etc/ppanel-agent/p9.yaml"
DO_BASE = "http://127.0.0.1:58090"
DO_TOKEN = os.environ.get("PPANEL_LAB_DO_TOKEN", "lab-do-token-not-a-secret")
DOMAIN = "static.example.lab"  # node-a fixture site; the gateway proxies it to node-a's VPC address
IP = {"node-a": "10.110.0.11", "node-b": "10.120.0.12", "gateway": "10.110.0.20"}
TAG = str(int(time.time()) % 100000)
results = []
api_proc = None
started_agents = []


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:400] if info else ""), flush=True)
    if not ok:
        finish(1)


def finish(code):
    cleanup()
    if "--out" in sys.argv:
        out = sys.argv[sys.argv.index("--out") + 1]
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "suite": "p9-e2e",
                       "steps": results}, f, indent=2)
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed", flush=True)
    sys.exit(code)


# ---------------------------------------------------------------- helpers

def http(method, url, body=None, headers=None, timeout=60):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return 0, ""


class User:
    def __init__(self, email, password, totp_secret=None):
        self.email, self.password, self.totp_secret = email, password, totp_secret
        self.token, self.last_step = None, 0
        self.login()

    def login(self):
        st, text = http("POST", API + "/auth/login", {"email": self.email, "password": self.password})
        if st != 200:
            raise SystemExit(f"login {self.email} -> {st}: {text[:300]}")
        data = json.loads(text)["data"]
        if "accessToken" not in data and data.get("mfaToken") and self.totp_secret:
            st, text = http("POST", API + "/auth/mfa/verify", {"mfaToken": data["mfaToken"], "code": self.code()})
            if st != 200:
                raise SystemExit(f"mfa verify {self.email} -> {st}: {text[:300]}")
            data = json.loads(text)["data"]
        self.token = data["accessToken"]

    def code(self):
        """A TOTP code from a window not used before (codes are single-use per 30 s window)."""
        if time.time() // 30 == self.last_step // 30:
            time.sleep(31 - (time.time() % 30))
        self.last_step = time.time()
        return totp(self.totp_secret)

    def step_up(self):
        """Fresh step-up token bound to the current session."""
        _, r = call("POST", "/auth/step-up", self, {"code": self.code()}, expect=200)
        return {"X-Step-Up": r["data"]["stepUpToken"]}


def call(method, path, user=None, body=None, headers=None, expect=None):
    for attempt in (0, 1):
        h = {"X-Request-ID": str(uuid.uuid4())}
        if user:
            h["Authorization"] = "Bearer " + user.token
        h.update(headers or {})
        st, text = http(method, API + path, body, h)
        if st == 401 and user and attempt == 0:
            user.login()
            continue
        break
    payload = json.loads(text) if text else {}
    if expect is not None and st not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {st} (expected {expect}): {text[:700]}")
    return st, payload


def sh(*argv, check=True, timeout=300):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {(p.stderr or p.stdout)[:400]}")
    return p.stdout.strip()


def node(n, cmd, check=True):
    return sh("docker", "exec", n, "sh", "-c", cmd, check=check)


def poll(fn, timeout, every=3, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise SystemExit(f"timeout waiting for {what}")


def totp(secret_b32, step_offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int(time.time()) // 30 + step_offset
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def listening(port):
    return sh("lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN", check=False).split()


def start_api():
    global api_proc
    env = dict(os.environ,
               API_HOST="0.0.0.0",
               PPANEL_PUBLIC_GATEWAY_URL="https://host.docker.internal:4443",
               PPANEL_PRIVATE_GATEWAY_URL="https://lab-center-private:4444",
               PPANEL_GATEWAY_LISTENERS="public=0.0.0.0:4443,private=0.0.0.0:4444",
               PPANEL_GATEWAY_HOSTNAMES="localhost,host.docker.internal,lab-center-private",
               PPANEL_PUBLIC_API_URL="http://host.docker.internal:4000",
               PPANEL_DO_API_BASE=DO_BASE)
    os.makedirs(f"{ROOT}/.lab/evidence", exist_ok=True)
    log = open(f"{ROOT}/.lab/evidence/e2e-p9-api.log", "a")
    api_proc = subprocess.Popen(["node", "--enable-source-maps", "apps/api/dist/main.js"], cwd=ROOT, env=env,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    poll(lambda: http("GET", API + "/setup/status")[0] == 200, 90, 1, "API start")
    poll(lambda: listening(4443) and listening(4444), 30, 1, "gateway listeners :4443 + :4444")


def stop_api():
    global api_proc
    if api_proc and api_proc.poll() is None:
        os.killpg(api_proc.pid, signal.SIGTERM)
        try:
            api_proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(api_proc.pid, signal.SIGKILL)
    api_proc = None
    time.sleep(1)


def stop_agent(n):
    node(n, "pkill -f '[p]panel-agent-linux-arm64 run' || true", check=False)


def cleanup():
    for n in started_agents:
        try:
            stop_agent(n)
        except Exception:  # noqa: BLE001 - best effort
            pass
    stop_api()
    left = {p: listening(p) for p in ("4000", "4443", "4444")}
    print("cleanup: agents stopped, Center stopped; listeners left: " + json.dumps(left), flush=True)


def agent_cfg(n):
    return {NODE_A: P9_CFG, NODE_B: P9_CFG, GW: "/etc/ppanel-agent/config.yaml"}[n]


def enroll(admin, container, name, environment):
    _, e = call("POST", "/enrollments", admin, {"name": name, "environment": environment, "ttlMinutes": 10},
                expect=201)
    stop_agent(container)
    node(container, "find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", container, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--config",
             agent_cfg(container), "--center", "http://host.docker.internal:4000", "--token", e["data"]["token"])
    start_agent(container)
    return out.split("serverId=")[1].split()[0]


def start_agent(container):
    sh("docker", "exec", "-d", container, "sh", "-c",
       f"{AGENT} run --config {agent_cfg(container)} >> /var/log/ppanel-agent.log 2>&1")
    if container not in started_agents:
        started_agents.append(container)


def server(admin, sid):
    return call("GET", f"/servers/{sid}", admin, expect=200)[1]["data"]


def conn_json(container):
    return json.loads(node(container, "cat /var/lib/ppanel-agent/connection.json"))


def connectivity(admin, frm, to, port):
    _, r = call("POST", "/network/connectivity-tests", admin, {"fromServerId": frm, "toServerId": to, "port": port},
                expect=(201, 202))
    tid = r["data"]["testId"]

    def done():
        d = call("GET", f"/network-diagnostics/{tid}", admin, expect=200)[1]["data"]
        return d if d["status"] in ("succeeded", "failed", "expired", "cancelled") else None

    return poll(done, 120, 3, f"connectivity test {tid}")


def plan_of(admin, pid):
    return call("GET", f"/gateway-plans/{pid}", admin, expect=200)[1]["data"]


def wait_plan(admin, pid, statuses, timeout=180):
    return poll(lambda: (lambda p: p if p["status"] in statuses else None)(plan_of(admin, pid)), timeout, 3,
                f"plan {pid} in {statuses}")


def gw_curl(path="/"):
    return node(GW, f"curl -s -m 5 -o /tmp/p9-body -w '%{{http_code}}' -H 'Host: {DOMAIN}' http://127.0.0.1{path}; "
                    "printf ' '; sha256sum /tmp/p9-body | cut -c1-64", check=False)


def gateway_state():
    files = node(GW, "ls /etc/nginx/ppanel-gateway 2>/dev/null | sort; "
                     "cat /etc/nginx/ppanel-gateway/*.conf /etc/nginx/conf.d/ppanel-gateway.conf 2>/dev/null | sha256sum | cut -c1-16",
                 check=False)
    return {"files": files, "masterPid": node(GW, "cat /run/nginx.pid", check=False)}


# ---------------------------------------------------------------- preflight + cleanup of earlier runs

def preflight():
    for c in (NODE_A, NODE_B, GW, "ppanel-lab-center-private", "ppanel-lab-do-fake", "ppanel-lab-dind"):
        if sh("docker", "inspect", "-f", "{{.State.Running}}", c, check=False) != "true":
            raise SystemExit(f"{c} not running: run scripts/lab/up.sh and scripts/lab/p9-net.sh up")
    status = sh(f"{ROOT}/scripts/lab/p9-net.sh", "status")
    if "NOT on" in status:
        sh(f"{ROOT}/scripts/lab/p9-net.sh", "restore", "node-a")
        sh(f"{ROOT}/scripts/lab/p9-net.sh", "restore", "node-b")
    for p in ("4000", "4443", "4444"):
        if listening(p):
            raise SystemExit(f"something is already listening on :{p}; stop it first")
    if not os.path.exists(f"{ROOT}/apps/api/dist/main.js"):
        raise SystemExit("apps/api/dist/main.js missing: pnpm --filter @ppanel/api build (or pass --build)")
    for n, cfg in ((NODE_A, "p9-node-a.yaml"), (NODE_B, "p9-node-b.yaml")):
        sh("docker", "cp", f"{ROOT}/infra/lab/node/agent-config/{cfg}", f"{n}:{P9_CFG}")
    # a previous run may have left gateway route files on the lab gateway
    node(GW, "if [ -e /etc/nginx/conf.d/ppanel-gateway.conf ] || [ -d /etc/nginx/ppanel-gateway ]; then "
             "rm -rf /etc/nginx/ppanel-gateway /etc/nginx/conf.d/ppanel-gateway.conf && nginx -s reload; fi")


def retire_previous(admin, operator):
    """Revoke servers / delete gateways and provider integrations left by earlier P9 runs (names p9-*)."""
    _, gws = call("GET", "/gateways?limit=100", admin, expect=200)
    for g in gws.get("data") or []:
        if g["name"].startswith("p9-gw-"):
            _, rs = call("GET", f"/gateways/{g['id']}/routes", admin)
            for r in (rs.get("data") or []):
                call("DELETE", f"/gateways/{g['id']}/routes/{r['id']}", admin)
            call("DELETE", f"/gateways/{g['id']}", admin)
    _, pis = call("GET", "/provider-integrations", admin, expect=200)
    for p in pis.get("data") or []:
        if p["name"].startswith("p9-lab-do"):
            call("DELETE", f"/provider-integrations/{p['id']}", admin)
    page, old = 1, []
    while True:
        _, ss = call("GET", f"/servers?limit=100&page={page}", admin, expect=200)
        data = ss.get("data") or []
        old += [s for s in data if s["name"].startswith("p9-") and s["status"] != "revoked"]
        if len(data) < 100:
            break
        page += 1
    if old:
        hdr = operator.step_up()
        for s in old:
            call("POST", f"/servers/{s['id']}/revoke", operator, None, hdr)
    return len(old)


# ---------------------------------------------------------------- main

def main():
    if "--build" in sys.argv:
        sh("pnpm", "--filter", "@ppanel/api", "build", timeout=600)
    preflight()
    start_api()
    admin = User("superadmin@ppanel.local", "password")

    # operator/approver: ops_admin with TOTP (step-up actions; approves plans created by superadmin)
    pw = secrets.token_urlsafe(18)
    email = f"p9-operator-{TAG}@ppanel.local"
    call("POST", "/users", admin, {"email": email, "password": pw, "displayName": "P9 operator",
                                   "bindings": [{"roleKey": "ops_admin", "scopeType": "global"}]}, expect=201)
    op = User(email, pw)
    _, s = call("POST", "/auth/mfa/totp/setup", op, expect=200)
    op.totp_secret = urllib.parse.parse_qs(urllib.parse.urlparse(s["data"]["otpauthUrl"]).query)["secret"][0]
    call("POST", "/auth/mfa/totp/confirm", op, {"code": op.code()}, expect=200)
    retired = retire_previous(admin, op)
    step("Center up with public :4443 + private :4444 listeners; operator with TOTP", True, operator=email,
         retiredPreviousServers=retired)

    # ---- enroll node-a (uat), node-b (uat), gateway (production)
    sa = enroll(admin, NODE_A, f"p9-node-a-{TAG}", "uat")
    sb = enroll(admin, NODE_B, f"p9-node-b-{TAG}", "uat")
    sg = enroll(admin, GW, f"p9-gateway-{TAG}", "production")
    ids = {"node-a": sa, "node-b": sb, "gateway": sg}
    for sid in ids.values():
        poll(lambda: server(admin, sid)["status"] == "online", 120, 3, f"{sid} online")
    cj = conn_json(NODE_A)
    paths = sorted(e["path"] for e in cj["endpoints"])
    step("three agents enrolled + online; enrollment advertised public + private endpoints (connection.json 0600)",
         paths == ["private", "public"] and node(NODE_A, "stat -c %a /var/lib/ppanel-agent/connection.json") == "600",
         servers=ids, endpoints=cj["endpoints"])

    # agent probes reported: private path healthy on every node (auto policy → private preferred)
    def private_ok(sid):
        c = server(admin, sid).get("connection") or {}
        eps = {e["path"]: e for e in c.get("endpoints", [])}
        return c if eps.get("private", {}).get("ok") and c.get("activePath") == "private" else None

    conns = {k: poll(lambda: private_ok(v), 150, 5, f"{k} private probe ok") for k, v in ids.items()}
    step("probes every 60 s: private endpoint healthy, auto policy uses the private path",
         all(c["activePath"] == "private" for c in conns.values()),
         connection={k: {"activePath": c["activePath"], "endpoints": c["endpoints"]} for k, c in conns.items()})

    # ---- P9-T1 provider sync + topology + pair connectivity
    def agent_facts():
        out = {k: server(admin, v) for k, v in ids.items()}
        if all((s.get("provider") or {}).get("region") == "lab1" for s in out.values()):
            return {k: {"provider": s["provider"], "network": s.get("network")} for k, s in out.items()}
        return None

    facts = poll(agent_facts, 90, 5, "agent provider facts (region lab1)")
    _, topo0 = call("GET", "/network/topology", admin, expect=200)
    mine = set(ids.values())
    pre_unknown = [f for f in topo0["data"]["findings"] if f["code"] == "VPC_UNKNOWN" and mine & set(f["serverIds"])]
    step("agent DigitalOcean metadata facts reported; VPC unknown before provider sync (agent facts never set a VPC)",
         all((n["network"] or {}).get("vpcSource") is None and (n["network"] or {}).get("vpcUuid") is None
             for n in facts.values()) and bool(pre_unknown),
         network=facts)

    st, bad = call("POST", "/provider-integrations", op, {"provider": "digitalocean", "name": f"p9-lab-do-bad-{TAG}",
                                                          "token": "wrong-token-123", "apiBase": DO_BASE}, op.step_up())
    _, pi = call("POST", "/provider-integrations", op, {"provider": "digitalocean", "name": f"p9-lab-do-{TAG}",
                                                        "token": DO_TOKEN, "apiBase": DO_BASE}, op.step_up(),
                 expect=201)
    token_leak = DO_TOKEN in json.dumps(pi)
    step("provider integration validated with GET /v2/account; wrong token refused; token never returned",
         st in (400, 401, 422) and pi["data"]["status"] == "ok" and not token_leak,
         badStatus=st, badCode=(bad.get("error") or {}).get("code"), integration=pi["data"].get("id"))
    pid = pi["data"]["id"]
    call("POST", f"/provider-integrations/{pid}/sync", admin, expect=202)

    def synced():
        _, r = call("GET", "/provider-integrations", admin, expect=200)
        p = next((x for x in r["data"] if x["id"] == pid), None)
        return p if p and p.get("lastSyncAt") and not p.get("syncInProgress") else None

    pis = poll(synced, 90, 3, "provider sync")
    _, topo = call("GET", "/network/topology", admin, expect=200)
    region = next((r for r in topo["data"]["regions"] if r["region"] == "lab1"), {"vpcs": []})
    vpc_of = {}
    for v in region["vpcs"]:
        for s in v["servers"]:
            vpc_of[s] = v["vpcName"] or v["vpcUuid"]
    diff_vpc = [f for f in topo["data"]["findings"]
                if f["code"] == "SAME_REGION_DIFFERENT_VPC" and {sa, sb} <= set(f["serverIds"])]
    step("P9-T1 provider sync: one region lab1, node-a + gateway in vpc-a, node-b in vpc-b; finding SAME_REGION_DIFFERENT_VPC",
         vpc_of.get(sa) == vpc_of.get(sg) and vpc_of.get(sa) != vpc_of.get(sb) and vpc_of.get(sb) is not None
         and bool(diff_vpc) and pis.get("status") == "ok",
         summary=pis.get("lastSyncSummary"), vpcs={k: vpc_of.get(v) for k, v in ids.items()},
         finding=diff_vpc[0] if diff_vpc else None)

    srv_a = server(admin, sa)
    across = connectivity(admin, sb, sa, 80)
    within = connectivity(admin, sg, sa, 80)
    step("P9-T1 pair connectivity: node-b -> node-a:80 fails across VPCs, gateway -> node-a:80 passes within vpc-a",
         srv_a.get("privateIpv4") == IP["node-a"] and across["reachable"] is False and within["reachable"] is True,
         target=srv_a.get("privateIpv4"),
         across={"status": across["status"], "tcp": (across.get("result") or {}).get("tcp")},
         within={"status": within["status"], "tcp": (within.get("result") or {}).get("tcp")})

    # ---- P9-T2 private_only: fail closed, Center 403 on public, reconnect over private
    call("PATCH", f"/servers/{sa}", admin, {"connectionPolicy": "private_only"}, expect=200)
    poll(lambda: conn_json(NODE_A).get("policy") == "private_only", 90, 3, "agent received private_only")
    code = node(NODE_A, "cd /var/lib/ppanel-agent && curl -s -m 10 --cacert ca.crt --cert agent.crt --key agent.key "
                        "-H 'X-Agent-Protocol: 1' -o /tmp/p9-403 -w '%{http_code}' "
                        "'https://host.docker.internal:4443/agent/v1/tasks?waitSec=0'; printf ' '; cat /tmp/p9-403",
                check=False)
    step("P9-T2 Center enforces the listener path: public request of a private_only server -> 403 CONNECTION_PATH_NOT_ALLOWED",
         code.startswith("403") and "CONNECTION_PATH_NOT_ALLOWED" in code, response=code[:200])

    marker = f"p9-cut-{TAG}"
    node(NODE_A, f"echo '{{\"marker\":\"{marker}\"}}' >> /var/log/ppanel-agent.log")
    sh(f"{ROOT}/scripts/lab/p9-net.sh", "cut", "node-a")
    seen_public, samples = set(), 0
    end = time.time() + 75  # > one 60 s probe cycle + several heartbeat retries
    while time.time() < end:
        out = node(NODE_A, "ss -Htn exclude time-wait '( dport = :4443 )'", check=False)
        samples += 1
        for line in out.splitlines():
            if line.strip():
                seen_public.add(" ".join(line.split()))
        time.sleep(1.5)
    log_after = node(NODE_A, f"sed -n '/{marker}/,$p' /var/log/ppanel-agent.log", check=False)
    dial_public = "host.docker.internal:4443" in log_after
    tried_private = "lab-center-private" in log_after
    srv_cut = server(admin, sa)
    step("P9-T2 private network cut: agent never dials public (no new socket to :4443 in 75 s, no public URL in its log)",
         not seen_public and not dial_public and tried_private,
         samples=samples, publicSockets=sorted(seen_public), privateRetriesLogged=tried_private,
         serverStatus=srv_cut["status"])

    hb_before = srv_cut.get("lastHeartbeatAt")
    sh(f"{ROOT}/scripts/lab/p9-net.sh", "restore", "node-a")

    def back():
        s = server(admin, sa)
        seen = s.get("lastHeartbeatAt")
        c = s.get("connection") or {}
        return s if s["status"] == "online" and seen != hb_before and c.get("activePath") == "private" else None

    srv_back = poll(back, 150, 5, "node-a reconnect over private")
    step("P9-T2 private network restored: node-a reconnects over the private path",
         srv_back["connection"]["activePath"] == "private" and srv_back["connectionPolicy"] == "private_only",
         connection=srv_back["connection"])
    call("PATCH", f"/servers/{sa}", admin, {"connectionPolicy": "auto"}, expect=200)

    # ---- P9-T4 gateway plan: validate -> shadow test -> approve -> apply
    _, g = call("POST", "/gateways", admin, {"serverId": sg, "name": f"p9-gw-{TAG}"}, expect=201)
    gid = g["data"]["id"]
    _, rt = call("POST", f"/gateways/{gid}/routes", admin,
                 {"domain": DOMAIN, "mode": "hybrid", "backends": [{"serverId": sa, "address": IP["node-a"], "port": 80}],
                  "healthPath": "/"}, expect=201)
    _, pl = call("POST", f"/gateways/{gid}/plans", admin, expect=201)
    plan_id = pl["data"]["id"]
    before_gw = gateway_state()
    p1 = wait_plan(admin, plan_id, {"validated", "failed"})
    step("P9-T4 plan rendered under /etc/nginx/ppanel-gateway/ and validated with nginx -t (nothing left on the gateway)",
         p1["status"] == "validated" and any(f["path"].startswith("/etc/nginx/ppanel-gateway/") for f in p1["rendered"])
         and gateway_state() == before_gw,
         status=p1["status"], rendered=[f["path"] for f in p1["rendered"]],
         validation=p1.get("validation"))

    call("POST", f"/gateway-plans/{plan_id}/shadow-test", admin, {}, expect=202)
    p2 = wait_plan(admin, plan_id, {"awaiting_approval", "shadow_tested", "failed"})
    sr = (p2.get("shadowResults") or [{}])[0]
    step("P9-T4 pre-apply shadow test via Host/SNI override (http.probe, no DNS change): direct origin answers 200",
         p2["status"] == "awaiting_approval" and (sr.get("direct") or {}).get("status") == 200,
         shadowResults=p2.get("shadowResults"))

    st, d = call("POST", f"/gateway-plans/{plan_id}/apply", admin)
    st2, d2 = call("POST", f"/gateway-plans/{plan_id}/approve", admin, {"planHash": p2["planHash"]})
    _, ap = call("POST", f"/gateway-plans/{plan_id}/approve", op, {"planHash": p2["planHash"]}, op.step_up(),
                 expect=200)
    step("P9-T4 production gateway: apply before approval refused, creator cannot approve, second person approves (step-up)",
         st in (403, 409) and st2 == 403 and ap["data"]["approval"]["approvedBy"] is not None,
         applyBefore=(st, (d.get("error") or {}).get("code")), creatorApprove=(st2, (d2.get("error") or {}).get("code")))

    call("POST", f"/gateway-plans/{plan_id}/apply", op, None, op.step_up(), expect=202)
    p3 = wait_plan(admin, plan_id, {"applied", "failed"}, 240)
    served = gw_curl()
    direct = node(NODE_A, f"curl -s -m 5 -o /tmp/p9-body -w '%{{http_code}}' -H 'Host: {DOMAIN}' http://127.0.0.1/; "
                          "printf ' '; sha256sum /tmp/p9-body | cut -c1-64", check=False)
    step("P9-T4 apply: nginx revision applied with postchecks; gateway serves the hybrid route like the origin",
         p3["status"] == "applied" and served.startswith("200") and served == direct,
         status=p3["status"], viaGateway=served, direct=direct, nginxRevision=p3.get("nginxRevisionStatus"))

    call("POST", f"/gateway-plans/{plan_id}/shadow-test", admin, {}, expect=202)
    p4 = poll(lambda: (lambda p: p if p.get("verification") else None)(plan_of(admin, plan_id)), 120, 3,
              "post-apply verification")
    v = p4["verification"][0]
    cut = p4.get("cutover") or {}
    step("P9-T4 post-apply shadow test matches (status + body hash); cutover documents DNS, TTL, verification, rollback",
         v.get("match") is True and bool(cut.get("dnsChanges")) and bool(cut.get("rollback"))
         and bool(cut.get("verification")) and bool(cut.get("ttlAdvice")),
         verification=p4["verification"], cutover=cut)

    # ---- P9-T3 Center outage: the gateway keeps serving, nothing changes
    routes_before = call("GET", f"/gateways/{gid}/routes", admin, expect=200)[1]["data"]
    gw_before = gateway_state()
    stop_api()
    time.sleep(20)
    during = [gw_curl() for _ in range(5)]
    gw_during = gateway_state()
    step("P9-T3 Center stopped: gateway still serves the hybrid route; route files + nginx master unchanged",
         all(x == served for x in during) and gw_during == gw_before and not listening(4443),
         responses=during, gateway=gw_during)
    start_api()
    admin.login()
    op.login()
    routes_after = call("GET", f"/gateways/{gid}/routes", admin, expect=200)[1]["data"]
    poll(lambda: server(admin, sg)["status"] == "online", 150, 5, "gateway agent back online")
    step("P9-T3 Center back: routes unchanged, plan still applied, gateway agent reconnected",
         json.dumps(routes_before, sort_keys=True) == json.dumps(routes_after, sort_keys=True)
         and plan_of(admin, plan_id)["status"] == "applied" and gateway_state() == gw_before,
         routes=len(routes_after))

    # ---- P9-T4 rollback
    call("POST", f"/gateway-plans/{plan_id}/rollback", op, None, op.step_up(), expect=202)
    p5 = wait_plan(admin, plan_id, {"rolled_back", "failed"}, 240)
    after = gw_curl()
    step("P9-T4 rollback: nginx revision reverted, the gateway no longer serves the route (direct origin untouched)",
         p5["status"] == "rolled_back" and not after.startswith("200")
         and node(NODE_A, f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {DOMAIN}' http://127.0.0.1/") == "200",
         status=p5["status"], viaGatewayAfter=after, gateway=gateway_state())
    finish(0)


if __name__ == "__main__":
    os.chdir(ROOT)
    try:
        main()
    except SystemExit as e:
        if e.code not in (0, 1, None):
            results.append({"step": "aborted", "ok": False, "error": str(e.code)[:600]})
            print(f"ABORT {e.code}", flush=True)
            finish(1)
        raise
    except BaseException as e:  # noqa: BLE001 - always stop what we started
        results.append({"step": "aborted", "ok": False, "error": repr(e)[:600]})
        print(f"ABORT {e!r}", flush=True)
        finish(1)
