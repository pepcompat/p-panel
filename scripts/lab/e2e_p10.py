#!/usr/bin/env python3
"""pPanel P10 lab E2E: real Center API (SSH gateway) + real Go agent on lab-node-s + real OpenSSH server.

Covers docs/P10_SSH_CONTRACT.md §8:
  T1  enroll node-s, generate key, deploy to `ops` (agent ssh.keys.sync), scan + trust host key (agentMatch true),
      non-production grant -> session -> WebSocket: echo / `id -un` = ops round-trip, resize, exit code 0.
  T2  denied: server outside the user's grant scope (403), expired grant (SSH_GRANT_INVALID), production grant
      without approval, self-approval (403 SELF_APPROVAL_FORBIDDEN), revoked key (4403 credential_revoked),
      changed host key after `p10-ssh.sh rekey` (4409 SSH_HOST_KEY_MISMATCH, no authentication attempted).
  T3  wrong Origin -> 403 before upgrade; no ticket / bogus / reused / other user's ticket -> 4401; ticket never in
      the URL; no API response or WebSocket frame of the run contains private key material; the authorized_keys
      managed block holds only `restrict,pty` public keys and foreign lines are preserved.
  T4  Center shutdown/restart closes sessions; idle timeout (Center restarted with SSH_IDLE_TIMEOUT_SEC=5) and grant
      expiry close the session; no `sshd: ops` process remains; session rows carry end_reason, no key material.

Prereqs: dev compose up + prisma migrations applied (incl. 20261130100000_p10_ssh); agent built (make -C apps/agent
build); Center API built (pnpm --filter @ppanel/api build, or pass --build); NOTHING listening on :4000/:4443.
lab-node-s is started by this script if needed (scripts/lab/p10-ssh.sh up; --no-deps, node-a/node-b untouched).
The WebSocket client is scripts/lab/p10-ws-client.mjs (Node, `ws` from apps/api/node_modules).
Run: python3 -I scripts/lab/e2e_p10.py [--build] [--out docs/evidence/<date>/p10-e2e.json]
Lab only: talks to localhost, the ppanel-lab containers and the dev Postgres container (to shorten grant expiry).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + "/../..")
API = "http://localhost:4000/api/v1"
WS_CLIENT = f"{ROOT}/scripts/lab/p10-ws-client.mjs"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
NODE_S = "ppanel-lab-node-s"
AGENT_CFG = "/etc/ppanel-agent/config.yaml"
SSH_ENDPOINT = {"path": "public", "host": "127.0.0.1", "port": 52222}
SSH_USER = "ops"
PG = os.environ.get("PPANEL_E2E_PG_CONTAINER", "ppanel-dev-postgres-1")
ORIGIN = os.environ.get("PPANEL_E2E_WEB_ORIGIN", "http://localhost:3100")
FOREIGN_LINE = "# p10-e2e foreign line: must survive every ssh.keys.sync byte-for-byte"
# Key material or a private-key field, not prose: error messages such as "The private key is encrypted" are fine.
LEAK_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\"privateKey(Enc)?\"\s*:|\"private_key(_enc)?\"\s*:|b3BlbnNzaC1rZXktdjE")
TAG = str(int(time.time()) % 100000)
results = []
responses = []  # every API / WebSocket payload of the run (scanned for private key material in T3)
api_proc = None
agent_started = False


def step(name, ok, fatal=True, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info, default=str)[:500] if info else ""),
          flush=True)
    if not ok and fatal:
        finish(1)
    return ok


def finish(code):
    cleanup()
    if "--out" in sys.argv:
        out = sys.argv[sys.argv.index("--out") + 1]
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "suite": "p10-e2e",
                       "contract": "docs/P10_SSH_CONTRACT.md §8", "steps": results}, f, indent=2, default=str)
    failed = [r["step"] for r in results if not r["ok"]]
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed" +
          (f"; FAILED: {failed}" if failed else ""), flush=True)
    sys.exit(1 if failed else code)


# ---------------------------------------------------------------- helpers

def http(method, url, body=None, headers=None, timeout=60):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
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


def totp(secret_b32, step_offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int(time.time()) // 30 + step_offset
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


class User:
    def __init__(self, email, password, totp_secret=None):
        self.email, self.password, self.totp_secret = email, password, totp_secret
        self.token, self.id, self.last_step = None, None, 0
        self._step_up, self._step_up_at = None, 0
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
        self.id = (data.get("user") or {}).get("id") or self.id
        self._step_up = None  # bound to the session

    def code(self):
        """A TOTP code from a window not used before (codes are single-use per 30 s window)."""
        if time.time() // 30 == self.last_step // 30:
            time.sleep(31 - (time.time() % 30))
        self.last_step = time.time()
        return totp(self.totp_secret)

    def step_up(self, fresh=False):
        """Step-up header (the token is reusable for its lifetime; refreshed after 4 min or on demand)."""
        if fresh or not self._step_up or time.time() - self._step_up_at > 240:
            _, r = call("POST", "/auth/step-up", self, {"code": self.code()}, expect=200)
            self._step_up, self._step_up_at = r["data"]["stepUpToken"], time.time()
        return {"X-Step-Up": self._step_up}


def call(method, path, user=None, body=None, headers=None, expect=None, step_up=False):
    for attempt in (0, 1, 2):
        h = {"X-Request-ID": str(uuid.uuid4())}
        if user:
            h["Authorization"] = "Bearer " + user.token
            if step_up:
                h.update(user.step_up(fresh=attempt > 0))
        h.update(headers or {})
        st, text = http(method, API + path, body, h)
        if st == 401 and user and attempt == 0:
            user.login()
            continue
        if step_up and st == 403 and "STEP_UP_REQUIRED" in text and attempt < 2:
            continue
        break
    responses.append(text)
    try:
        payload = json.loads(text) if text else {}
    except ValueError:
        payload = {"raw": text[:300]}
    if expect is not None and st not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {st} (expected {expect}): {text[:700]}")
    return st, payload


def err(payload):
    return (payload.get("error") or {}).get("code") if isinstance(payload, dict) else None


def data_list(payload, *keys):
    d = payload.get("data")
    if isinstance(d, dict):
        for k in keys:
            if isinstance(d.get(k), list):
                return d[k]
    return d if isinstance(d, list) else []


def sh(*argv, check=True, timeout=300, stdin=None):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, input=stdin)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {(p.stderr or p.stdout)[:400]}")
    return p.stdout.strip()


def node(cmd, check=True):
    return sh("docker", "exec", NODE_S, "sh", "-c", cmd, check=check)


def psql(sql):
    return sh("docker", "exec", PG, "psql", "-U", "ppanel", "-d", "ppanel", "-v", "ON_ERROR_STOP=1", "-Atc", sql)


def poll(fn, timeout, every=3, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise SystemExit(f"timeout waiting for {what}")


def listening(port):
    return sh("lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN", check=False).split()


# ---------------------------------------------------------------- Center + agent

def start_api(**extra):
    global api_proc
    env = dict(os.environ,
               API_HOST="0.0.0.0",
               PPANEL_PUBLIC_GATEWAY_URL="https://host.docker.internal:4443",
               PPANEL_GATEWAY_HOSTNAMES="localhost,host.docker.internal",
               PPANEL_PUBLIC_API_URL="http://host.docker.internal:4000",
               PPANEL_SSH_LAB_ENDPOINTS=f"{SSH_ENDPOINT['host']}:{SSH_ENDPOINT['port']}",
               WEB_ORIGIN=ORIGIN,
               **extra)
    os.makedirs(f"{ROOT}/.lab/evidence", exist_ok=True)
    log = open(f"{ROOT}/.lab/evidence/e2e-p10-api.log", "a")
    log.write(f"\n=== start {time.strftime('%H:%M:%S')} extra={extra}\n")
    log.flush()
    api_proc = subprocess.Popen(["node", "--enable-source-maps", "apps/api/dist/main.js"], cwd=ROOT, env=env,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    poll(lambda: http("GET", API + "/setup/status")[0] == 200, 90, 1, "API start")
    poll(lambda: listening(4443), 30, 1, "gateway listener :4443")


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


def stop_agent():
    node("pkill -f '[p]panel-agent-linux-arm64 run' || true", check=False)


def start_agent():
    global agent_started
    sh("docker", "exec", "-d", NODE_S, "sh", "-c", f"{AGENT} run --config {AGENT_CFG} >> /var/log/ppanel-agent.log 2>&1")
    agent_started = True


def cleanup():
    if agent_started:
        try:
            stop_agent()
        except Exception:  # noqa: BLE001 - best effort
            pass
    stop_api()
    print("cleanup: agent stopped, Center stopped; listeners left: " +
          json.dumps({p: listening(p) for p in ("4000", "4443")}), flush=True)


def enroll(admin, name, environment):
    _, e = call("POST", "/enrollments", admin, {"name": name, "environment": environment, "ttlMinutes": 10},
                expect=201)
    stop_agent()
    node("find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", NODE_S, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--config", AGENT_CFG,
             "--center", "http://host.docker.internal:4000", "--token", e["data"]["token"])
    start_agent()
    return out.split("serverId=")[1].split()[0]


def server(admin, sid):
    return call("GET", f"/servers/{sid}", admin, expect=200)[1]["data"]


# ---------------------------------------------------------------- SSH helpers

def host_fps():
    out = node("for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done")
    return {line.split()[1] for line in out.splitlines() if line.strip()}


def authorized_keys():
    return node(f"cat /home/{SSH_USER}/.ssh/authorized_keys 2>/dev/null || true", check=False)


def managed_block(text):
    lines = text.splitlines()
    try:
        b = lines.index("# >>> ppanel managed keys (do not edit) >>>")
        e = lines.index("# <<< ppanel managed keys <<<")
    except ValueError:
        return None
    return lines[b + 1:e]


def sshd_ops_sessions():
    out = node("ps -eo pid,user,args | grep -E 'sshd: ops' | grep -v grep || true", check=False)
    return [line for line in out.splitlines() if line.strip()]


def credential(admin, cid):
    _, r = call("GET", "/ssh/credentials", admin, expect=200)
    return next((c for c in data_list(r, "items") if c["id"] == cid), None)


def deployment(admin, cid, sid):
    c = credential(admin, cid) or {}
    return next((d for d in c.get("deployments") or [] if d.get("serverId") == sid and d.get("sshUser") == SSH_USER),
                None)


def new_credential(admin, op, sid, name):
    _, c = call("POST", "/ssh/credentials", op, {"name": name, "mode": "generate"}, expect=201, step_up=True)
    cid = c["data"]["id"]
    _, d = call("POST", f"/ssh/credentials/{cid}/deploy", op, {"serverId": sid, "sshUser": SSH_USER}, expect=202)

    def installed():
        dep = deployment(admin, cid, sid)
        if dep and dep["status"] == "failed":
            raise SystemExit(f"deployment failed: {dep.get('lastError')}")
        return dep if dep and dep["status"] == "installed" else None

    dep = poll(installed, 120, 3, f"deployment of {name} installed")
    return c["data"], d["data"], dep


def scan(op, sid):
    _, r = call("POST", f"/servers/{sid}/ssh/host-keys/scan", op, {"path": SSH_ENDPOINT["path"]}, expect=(200, 201))
    return data_list(r, "keys", "hostKeys", "items")


def host_keys(admin, sid):
    _, r = call("GET", f"/servers/{sid}/ssh/host-keys", admin, expect=200)
    return data_list(r, "keys", "hostKeys", "items")


def scan_and_trust(op, sid, want_fps, timeout=90):
    """Scan until the scanned keys are exactly the node's current keys and agentMatch is true, then trust them."""
    def ready():
        ks = [k for k in scan(op, sid) if k["fingerprintSha256"] in want_fps]
        return ks if ks and all(k.get("agentMatch") is True for k in ks) else None

    ks = poll(ready, timeout, 5, "host key scan with agentMatch true")
    for k in ks:
        if k["status"] != "trusted":
            call("POST", f"/ssh/host-keys/{k['id']}/trust", op, {}, expect=200, step_up=True)
    return ks


def grant(user, sid, reason, expect=201):
    st, g = call("POST", "/ssh/grants", user, {"serverId": sid, "sshUser": SSH_USER,
                                              "endpointPath": SSH_ENDPOINT["path"], "durationMinutes": 15,
                                              "reason": reason}, expect=expect)
    return st, g


def session(user, gid, step_up=False, expect=201):
    return call("POST", "/ssh/sessions", user, {"grantId": gid, "cols": 80, "rows": 24}, expect=expect,
                step_up=step_up)


def sessions_of(admin, sid):
    _, r = call("GET", f"/ssh/sessions?server_id={sid}&limit=100", admin, expect=200)
    return data_list(r, "items")


def session_row(admin, sid, sess_id):
    return next((s for s in sessions_of(admin, sid) if s["id"] == sess_id), None)


def terminate_open(op, sid):
    for s in sessions_of(op, sid):
        if s["status"] in ("pending", "open"):
            call("POST", f"/ssh/sessions/{s['id']}/terminate", op, {})


def ws_cfg(sess, steps, origin=ORIGIN, timeout_ms=60000, auth=True):
    pre = [{"text": {"type": "auth", "ticket": sess["ticket"], "sessionId": sess["sessionId"]}}] if auth else []
    # wsUrl is built from PPANEL_PUBLIC_API_URL (host.docker.internal, for the agent); the Mac can't resolve that
    # name, so dial the same path on the local API. Path and scheme still come from the Center's response.
    url = urllib.parse.urlsplit(sess["wsUrl"])
    url = urllib.parse.urlunsplit((url.scheme, urllib.parse.urlsplit(API).netloc, url.path, url.query, ""))
    return {"url": url, "origin": origin, "timeoutMs": timeout_ms, "steps": pre + steps}


def ws(cfg, background=False):
    p = subprocess.Popen(["node", WS_CLIENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    p.stdin.write(json.dumps(cfg))
    p.stdin.close()
    return p if background else ws_result(p, cfg.get("timeoutMs", 60000) / 1000 + 30)


def ws_result(p, timeout=120):
    out, errout = p.communicate(timeout=timeout)
    try:
        r = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise SystemExit(f"ws client failed: {errout[:400]}")
    responses.append(json.dumps(r["messages"]))
    responses.append(r.get("stdout", ""))
    return r


def ws_summary(r):
    return {k: r.get(k) for k in ("upgradeStatus", "closeCode", "closeReason", "closedBy", "error", "stdoutBytes")} | {
        "messages": [m for m in r.get("messages", []) if m.get("type") != "pong"][:6]}


def msg(r, typ):
    return next((m for m in r.get("messages", []) if m.get("type") == typ), None)


def closing_reason(r):
    m = msg(r, "closing")
    return m.get("reason") if m else None


# ---------------------------------------------------------------- preflight + earlier runs

def preflight():
    if sh("docker", "inspect", "-f", "{{.State.Health.Status}}", NODE_S, check=False) != "healthy":
        sh(f"{ROOT}/scripts/lab/p10-ssh.sh", "up", timeout=900)
    for p in ("4000", "4443"):
        if listening(p):
            raise SystemExit(f"something is already listening on :{p}; stop it first")
    if not os.path.exists(f"{ROOT}/apps/api/dist/main.js"):
        raise SystemExit("apps/api/dist/main.js missing: pnpm --filter @ppanel/api build (or pass --build)")
    if not os.path.exists(f"{ROOT}/apps/api/node_modules/ws"):
        raise SystemExit("apps/api/node_modules/ws missing (pnpm install)")
    if psql("select to_regclass('ssh_access_grants') is not null") != "t":
        raise SystemExit("P10 migration not applied (ssh_access_grants missing): pnpm --filter @ppanel/api prisma migrate deploy")
    # pristine target: no authorized_keys except one foreign line that must survive every sync
    node(f"install -d -o {SSH_USER} -g {SSH_USER} -m 0700 /home/{SSH_USER}/.ssh && "
         f"printf '%s\\n' '{FOREIGN_LINE}' > /home/{SSH_USER}/.ssh/authorized_keys && "
         f"chown {SSH_USER}:{SSH_USER} /home/{SSH_USER}/.ssh/authorized_keys && "
         f"chmod 0600 /home/{SSH_USER}/.ssh/authorized_keys")


def retire_previous(admin, op):
    _, cs = call("GET", "/ssh/credentials", admin, expect=200)
    old_c = [c for c in data_list(cs, "items") if c["name"].startswith("p10-e2e-") and c["status"] == "active"]
    for c in old_c:
        call("POST", f"/ssh/credentials/{c['id']}/revoke", op, {}, step_up=True)
    page, old = 1, []
    while True:
        _, ss = call("GET", f"/servers?limit=100&page={page}", admin, expect=200)
        data = ss.get("data") or []
        old += [s for s in data if s["name"].startswith("p10-") and s["status"] != "revoked"]
        if len(data) < 100:
            break
        page += 1
    for s in old:
        call("POST", f"/servers/{s['id']}/revoke", op, None, step_up=True)
    return {"credentials": len(old_c), "servers": len(old)}


def make_user(admin, label, bindings):
    pw = secrets.token_urlsafe(18)
    email = f"p10-{label}-{TAG}@ppanel.local"
    call("POST", "/users", admin, {"email": email, "password": pw, "displayName": f"P10 {label}",
                                   "bindings": bindings}, expect=201)
    u = User(email, pw)
    _, s = call("POST", "/auth/mfa/totp/setup", u, expect=200)
    u.totp_secret = urllib.parse.parse_qs(urllib.parse.urlparse(s["data"]["otpauthUrl"]).query)["secret"][0]
    call("POST", "/auth/mfa/totp/confirm", u, {"code": u.code()}, expect=200)
    return u


# ---------------------------------------------------------------- main

def main():
    if "--build" in sys.argv:
        sh("pnpm", "--filter", "@ppanel/api", "build", timeout=900)
    preflight()
    start_api()
    admin = User("superadmin@ppanel.local", "password")
    op = make_user(admin, "operator", [{"roleKey": "ops_admin", "scopeType": "global"}])
    retired = retire_previous(admin, op)
    step("Center up with PPANEL_SSH_LAB_ENDPOINTS; operator (ops_admin, TOTP) created", True,
         operator=op.email, retired=retired)

    # ================================================================ T1
    sid = enroll(admin, f"p10-node-s-{TAG}", "uat")
    poll(lambda: server(admin, sid)["status"] == "online", 120, 3, "node-s online")
    eng = make_user(admin, "engineer", [{"roleKey": "ops_admin", "scopeType": "server", "scopeId": sid}])
    step("T1 node-s enrolled (uat) and online; engineer scoped to this server only", True, serverId=sid,
         engineer=eng.email)

    st_root, r_root = call("PUT", f"/servers/{sid}/ssh/endpoints", op, [dict(SSH_ENDPOINT, allowedUsers=["root"])])
    st_unv, r_unv = call("PUT", f"/servers/{sid}/ssh/endpoints", op,
                         [dict(SSH_ENDPOINT, host="203.0.113.9", port=22, allowedUsers=[SSH_USER])])
    _, ep = call("PUT", f"/servers/{sid}/ssh/endpoints", op, [dict(SSH_ENDPOINT, allowedUsers=[SSH_USER])],
                 expect=200)
    step("T1 endpoint 127.0.0.1:52222 accepted via PPANEL_SSH_LAB_ENDPOINTS; root -> SSH_ROOT_FORBIDDEN; "
         "unknown address -> SSH_ENDPOINT_UNVERIFIED",
         st_root == 422 and err(r_root) == "SSH_ROOT_FORBIDDEN" and st_unv == 422
         and err(r_unv) == "SSH_ENDPOINT_UNVERIFIED", fatal=False, endpoints=ep.get("data"),
         root=(st_root, err(r_root)), unverified=(st_unv, err(r_unv)))

    cred, dep_job, dep = new_credential(admin, op, sid, f"p10-e2e-{TAG}-a")
    ak = authorized_keys()
    block = managed_block(ak) or []
    step("T1 ed25519 credential generated (metadata only) and deployed to ops by the agent (ssh.keys.sync)",
         cred["algorithm"] == "ssh-ed25519" and not LEAK_RE.search(json.dumps(cred))
         and len(block) == 1 and cred["fingerprintSha256"] in block[0] and block[0].startswith("restrict,pty ")
         and ak.splitlines()[0] == FOREIGN_LINE,
         credential={k: cred.get(k) for k in ("id", "kind", "algorithm", "fingerprintSha256", "status")},
         jobId=dep_job.get("jobId"), deployment=dep, managedBlock=block)

    fps = host_fps()
    trusted = scan_and_trust(op, sid, fps)
    step("T1 host keys scanned (no auth), agentMatch true via agent facts, trusted with step-up",
         {k["fingerprintSha256"] for k in trusted} <= fps and all(k.get("agentMatch") is True for k in trusted),
         nodeFingerprints=sorted(fps), trusted=[{k: h.get(k) for k in ("algorithm", "fingerprintSha256", "agentMatch")}
                                                for h in trusted])

    _, g = grant(eng, sid, "p10 e2e T1 round-trip")
    gid = g["data"]["id"]
    _, s = session(eng, gid)
    sess = s["data"]
    r = ws(ws_cfg(sess, [
        {"waitMessage": "ready"},
        {"stdin": f"echo p10-rt-{TAG}; id -un\n"},
        {"waitOutput": f"p10-rt-{TAG}\\r?\\n(\\x1b\\[[0-9;?]*[A-Za-z])*{SSH_USER}"},
        {"text": {"type": "resize", "cols": 132, "rows": 43}},
        {"sleepMs": 300},
        {"stdin": "stty size\n"},
        {"waitOutput": "43 132"},
        {"text": {"type": "ping"}},
        {"waitMessage": "pong"},
        {"stdin": "exit 0\n"},
        {"waitClose": 15000},
    ]))
    ready, ex = msg(r, "ready"), msg(r, "exit")
    row = poll(lambda: (lambda x: x if x and x["status"] == "closed" else None)(session_row(admin, sid,
                                                                                            sess["sessionId"])),
               30, 2, "T1 session row closed")
    step("T1 grant (uat, active now) -> session -> WebSocket: echo + `id -un` = ops, resize 132x43, exit code 0",
         g["data"]["status"] == "active" and sess["ticket"] not in sess["wsUrl"] and ready
         and ready.get("hostKeyFingerprint") in {k["fingerprintSha256"] for k in trusted}
         and ready.get("sshUser") == SSH_USER and r["error"] is None and ex and ex.get("code") == 0
         and r["closeCode"] == 1000 and row.get("exitCode") == 0 and row.get("bytesOut", 0) > 0,
         ws=ws_summary(r), ready=ready, sessionRow={k: row.get(k) for k in
                                                     ("status", "endReason", "exitCode", "bytesIn", "bytesOut",
                                                      "hostKeyFingerprint", "credentialFingerprint")})

    # ================================================================ T2
    others = [x for x in (call("GET", "/servers?limit=100", admin, expect=200)[1].get("data") or []) if x["id"] != sid]
    other_id = others[0]["id"] if others else str(uuid.uuid4())
    st, rr = grant(eng, other_id, "p10 e2e T2 out of scope", expect=None)
    # 404 (not 403) for a server the user can't see: the API doesn't reveal that it exists (repo IDOR convention).
    step("T2 grant for a server outside the user's ssh.connect scope -> 403/404", st in (403, 404), fatal=False,
         status=st, code=err(rr), otherServer=other_id)

    _, g2 = grant(eng, sid, "p10 e2e T2 expired grant")
    psql(f"update ssh_access_grants set expires_at = now() - interval '1 minute' where id = '{g2['data']['id']}'")
    st, rr = session(eng, g2["data"]["id"], expect=None)
    step("T2 expired grant (expires_at shortened in DB) -> session refused 403 SSH_GRANT_INVALID",
         st == 403 and err(rr) == "SSH_GRANT_INVALID", fatal=False, status=st, code=err(rr))

    call("PATCH", f"/servers/{sid}", admin, {"environment": "production"}, expect=200)
    _, gp = grant(eng, sid, "p10 e2e T2 production access")
    st_s, rr_s = session(eng, gp["data"]["id"], expect=None)
    _, gs = grant(op, sid, "p10 e2e T2 self approval")
    st_self, rr_self = call("POST", f"/ssh/grants/{gs['data']['id']}/approve", op, {}, step_up=True)
    step("T2 production: grant awaits approval and cannot open a session; self-approval -> 403 SELF_APPROVAL_FORBIDDEN",
         gp["data"]["status"] == "awaiting_approval" and st_s == 403 and st_self == 403
         and err(rr_self) == "SELF_APPROVAL_FORBIDDEN", fatal=False,
         grantStatus=gp["data"]["status"], sessionBeforeApproval=(st_s, err(rr_s)),
         selfApproval=(st_self, err(rr_self)))
    call("POST", f"/ssh/grants/{gs['data']['id']}/reject", admin, {})
    _, ap = call("POST", f"/ssh/grants/{gp['data']['id']}/approve", op, {"grantHash": gp["data"]["grantHash"]},
                 expect=200, step_up=True)
    st_ns, rr_ns = session(eng, gp["data"]["id"], expect=None)
    _, sp = session(eng, gp["data"]["id"], step_up=True)
    rp = ws(ws_cfg(sp["data"], [{"waitMessage": "ready"}, {"stdin": "id -un\n"}, {"waitOutput": SSH_USER},
                                {"text": {"type": "close"}}, {"waitClose": 10000}]))
    step("T2 production: second person approves (step-up) -> session needs a fresh step-up -> terminal works",
         ap["data"]["status"] == "active" and st_ns == 403 and msg(rp, "ready") is not None and rp["error"] is None,
         fatal=False, approval={k: ap["data"].get(k) for k in ("status", "approvedBy", "startsAt", "expiresAt")},
         sessionWithoutStepUp=(st_ns, err(rr_ns)), ws=ws_summary(rp))
    call("PATCH", f"/servers/{sid}", admin, {"environment": "uat"}, expect=200)
    terminate_open(op, sid)

    # revoked key: an open session is closed (4403 credential_revoked), the key leaves authorized_keys
    _, g3 = grant(eng, sid, "p10 e2e T2 revoked key")
    _, s3 = session(eng, g3["data"]["id"])
    bg = ws(ws_cfg(s3["data"], [{"waitMessage": "ready"}, {"waitClose": 90000}], timeout_ms=95000), background=True)
    poll(lambda: (session_row(admin, sid, s3["data"]["sessionId"]) or {}).get("status") == "open", 30, 1,
         "revocation victim session open")
    call("POST", f"/ssh/credentials/{cred['id']}/revoke", op, {}, expect=(200, 202), step_up=True)
    rv = ws_result(bg)
    dep_gone = poll(lambda: (lambda d: d if d and d["status"] in ("removed",) else None)(
        deployment(admin, cred["id"], sid)), 120, 3, "revoked deployment removed")
    ak2 = authorized_keys()
    st_ng, rr_ng = grant(eng, sid, "p10 e2e T2 no credential", expect=None)
    row3 = session_row(admin, sid, s3["data"]["sessionId"]) or {}
    step("T2 revoked key: open session closed 4403 credential_revoked; key removed from authorized_keys "
         "(foreign line kept); new grant -> 422 SSH_NO_CREDENTIAL",
         rv["closeCode"] == 4403 and (closing_reason(rv) == "credential_revoked"
                                       or row3.get("endReason") == "credential_revoked")
         and cred["fingerprintSha256"] not in ak2 and ak2.splitlines()[:1] == [FOREIGN_LINE]
         and st_ng == 422 and err(rr_ng) == "SSH_NO_CREDENTIAL", fatal=False,
         ws=ws_summary(rv), sessionEndReason=row3.get("endReason"), deployment=dep_gone,
         authorizedKeys=ak2.splitlines(), newGrant=(st_ng, err(rr_ng)))

    cred2, _, _ = new_credential(admin, op, sid, f"p10-e2e-{TAG}-b")

    # changed host key: refused before authentication, observed key stored as pending (seenVia connect)
    old_fps = fps
    sh(f"{ROOT}/scripts/lab/p10-ssh.sh", "rekey")
    new_fps = host_fps()
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))
    _, g4 = grant(eng, sid, "p10 e2e T2 host key changed")
    _, s4 = session(eng, g4["data"]["id"])
    rk = ws(ws_cfg(s4["data"], [{"waitClose": 25000}], timeout_ms=30000))
    time.sleep(1)
    sshd_log = sh("sh", "-c", f"docker logs --since {since} {NODE_S} 2>&1", check=False)
    auth_lines = [x for x in sshd_log.splitlines()
                  if re.search(r"publickey|Accepted|Failed|authenticating user|Invalid user|Postponed", x)]
    pend = [k for k in host_keys(admin, sid) if k["fingerprintSha256"] in new_fps and k["status"] == "pending"]
    errm = msg(rk, "error") or {}
    step("T2 host key changed (p10-ssh.sh rekey): close 4409 SSH_HOST_KEY_MISMATCH before any authentication; "
         "observed key stored pending (seenVia connect)",
         not (old_fps & new_fps) and rk["closeCode"] == 4409
         and (errm.get("code") == "SSH_HOST_KEY_MISMATCH" or closing_reason(rk) == "host_key_mismatch")
         and not auth_lines and any(k.get("seenVia") == "connect" for k in pend), fatal=False,
         ws=ws_summary(rk), sshdAuthLines=auth_lines[:5], pendingKeys=[
             {k: p.get(k) for k in ("algorithm", "fingerprintSha256", "seenVia", "agentMatch")} for p in pend],
         oldFingerprints=sorted(old_fps), newFingerprints=sorted(new_fps))
    trusted2 = scan_and_trust(op, sid, new_fps, timeout=120)
    statuses = {k["fingerprintSha256"]: k["status"] for k in host_keys(admin, sid)}
    step("T2 new host keys re-scanned (agentMatch true after the agent's next heartbeat) and trusted; old -> superseded",
         all(statuses.get(f) == "trusted" for f in {k["fingerprintSha256"] for k in trusted2})
         and all(statuses.get(f) in ("superseded", "rejected") for f in old_fps if f in statuses), fatal=False,
         statuses=statuses)

    # ================================================================ T3
    _, g5 = grant(eng, sid, "p10 e2e T3 tickets")
    gid5 = g5["data"]["id"]
    _, s5 = session(eng, gid5)
    s5 = s5["data"]
    r_origin = ws(ws_cfg(s5, [], origin="https://evil.example", timeout_ms=10000))
    step("T3 wrong Origin -> HTTP 403 before the WebSocket upgrade",
         r_origin["upgradeStatus"] == 403 and not r_origin["opened"], fatal=False, ws=ws_summary(r_origin))
    r_none = ws(ws_cfg(s5, [{"waitClose": 15000}], auth=False, timeout_ms=20000))
    r_bogus = ws(ws_cfg({**s5, "ticket": secrets.token_urlsafe(32)}, [{"waitClose": 10000}], timeout_ms=15000))
    r_ping = ws(ws_cfg(s5, [{"text": {"type": "ping"}}, {"waitClose": 10000}], auth=False, timeout_ms=15000))
    step("T3 no auth message within 5 s / bogus ticket / non-auth first message -> close 4401",
         r_none["closeCode"] == 4401 and r_bogus["closeCode"] == 4401 and r_ping["closeCode"] in (4401, 4400),
         fatal=False, noTicket=ws_summary(r_none), bogus=ws_summary(r_bogus), pingFirst=ws_summary(r_ping))
    r_ok = ws(ws_cfg(s5, [{"waitMessage": "ready"}, {"text": {"type": "close"}}, {"waitClose": 10000}]))
    r_reuse = ws(ws_cfg(s5, [{"waitClose": 10000}], timeout_ms=15000))
    step("T3 ticket is single-use: first use ready, reuse -> 4401; ticket never in wsUrl",
         msg(r_ok, "ready") is not None and r_reuse["closeCode"] == 4401 and s5["ticket"] not in s5["wsUrl"]
         and "ticket" not in urllib.parse.urlparse(s5["wsUrl"]).query, fatal=False,
         first=ws_summary(r_ok), reuse=ws_summary(r_reuse), wsUrl=s5["wsUrl"])
    _, go = grant(op, sid, "p10 e2e T3 other user's ticket")
    _, so = session(op, go["data"]["id"])
    _, se = session(eng, gid5)
    r_other = ws(ws_cfg({**se["data"], "ticket": so["data"]["ticket"]}, [{"waitClose": 10000}], timeout_ms=15000))
    step("T3 another user's ticket for my session -> 4401", r_other["closeCode"] == 4401, fatal=False,
         ws=ws_summary(r_other))
    terminate_open(op, sid)

    # import path (response must not echo the key) + encrypted-without-passphrase refusal
    tmp = tempfile.mkdtemp(prefix="p10-e2e-")
    try:
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "p10-import", "-f", f"{tmp}/k")
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "p10-pass", "-C", "p10-enc", "-f", f"{tmp}/e")
        priv, enc = open(f"{tmp}/k").read(), open(f"{tmp}/e").read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    st_i, ri = call("POST", "/ssh/credentials", op, {"name": f"p10-e2e-{TAG}-imp", "mode": "import",
                                                     "privateKey": priv}, step_up=True)
    st_e, re_ = call("POST", "/ssh/credentials", op, {"name": f"p10-e2e-{TAG}-enc", "mode": "import",
                                                      "privateKey": enc}, step_up=True)
    body_echo = priv.splitlines()[1] in json.dumps(ri)
    if st_i == 201:
        call("POST", f"/ssh/credentials/{ri['data']['id']}/revoke", op, {}, step_up=True)
    del priv, enc
    step("T3 import: response is metadata only (no key echo); encrypted key without passphrase -> 422 SSH_KEY_ENCRYPTED",
         st_i == 201 and not body_echo and st_e == 422 and err(re_) == "SSH_KEY_ENCRYPTED", fatal=False,
         imported=(st_i, (ri.get("data") or {}).get("fingerprintSha256")), encrypted=(st_e, err(re_)))

    ak3 = authorized_keys()
    block3 = managed_block(ak3) or []
    leaks = [x[:120] for x in responses if LEAK_RE.search(x or "")]
    step("T3 no API response / WebSocket frame of the run contains private key material; managed block = only "
         "`restrict,pty` public keys; foreign line preserved",
         not leaks and block3 and all(re.match(r"^restrict,pty (ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) "
                                               r"[A-Za-z0-9+/]+=* ppanel:SHA256:[A-Za-z0-9+/]{43}$", x)
                                      for x in block3)
         and ak3.splitlines()[0] == FOREIGN_LINE and cred2["fingerprintSha256"] in "\n".join(block3), fatal=False,
         scannedPayloads=len(responses), leaks=leaks[:3], managedBlock=block3)

    # ================================================================ T4
    _, g6 = grant(eng, sid, "p10 e2e T4 shutdown")
    _, s6 = session(eng, g6["data"]["id"])
    bg = ws(ws_cfg(s6["data"], [{"waitMessage": "ready"}, {"waitClose": 90000}], timeout_ms=95000), background=True)
    poll(lambda: (session_row(admin, sid, s6["data"]["sessionId"]) or {}).get("status") == "open", 30, 1,
         "shutdown victim open")
    stop_api()
    rs = ws_result(bg)
    start_api(SSH_IDLE_TIMEOUT_SEC="5")
    for u in (admin, op, eng):
        u.login()
    row6 = poll(lambda: (lambda x: x if x and x["status"] == "closed" else None)(
        session_row(admin, sid, s6["data"]["sessionId"])), 30, 2, "shutdown session row closed")
    procs = poll(lambda: (lambda p: ["none"] if not p else None)(sshd_ops_sessions()), 20, 1, "no sshd: ops")
    step("T4 Center shutdown closes the open session (center_shutdown/center_restart); no sshd session left",
         rs["closeCode"] is not None and row6.get("endReason") in ("center_shutdown", "center_restart")
         and procs == ["none"], fatal=False, ws=ws_summary(rs), endReason=row6.get("endReason"))

    poll(lambda: server(admin, sid)["status"] == "online", 120, 3, "node-s online after Center restart")
    _, g7 = grant(eng, sid, "p10 e2e T4 idle")
    _, s7 = session(eng, g7["data"]["id"])
    t0 = time.time()
    ri7 = ws(ws_cfg(s7["data"], [{"waitMessage": "ready"}, {"waitClose": 40000}], timeout_ms=45000))
    idle_after = round(time.time() - t0, 1)
    left7 = poll(lambda: (lambda p: ["none"] if not p else None)(sshd_ops_sessions()), 20, 1, "no sshd: ops")
    row7 = session_row(admin, sid, s7["data"]["sessionId"]) or {}
    step("T4 idle timeout (SSH_IDLE_TIMEOUT_SEC=5): close 4408 idle_timeout; no `sshd: ops` process remains",
         msg(ri7, "ready") is not None and ri7["closeCode"] == 4408
         and "idle_timeout" in (closing_reason(ri7), row7.get("endReason")) and left7 == ["none"] and idle_after < 30,
         fatal=False, ws=ws_summary(ri7), secondsToClose=idle_after, endReason=row7.get("endReason"))

    _, g8 = grant(eng, sid, "p10 e2e T4 grant expiry")
    _, s8 = session(eng, g8["data"]["id"])
    bg = ws(ws_cfg(s8["data"], [{"waitMessage": "ready"}, {"keepalive": {"everyMs": 2000, "forMs": 80000}},
                                {"waitClose": 5000}], timeout_ms=90000), background=True)
    poll(lambda: (session_row(admin, sid, s8["data"]["sessionId"]) or {}).get("status") == "open", 30, 1,
         "expiry victim open")
    psql(f"update ssh_access_grants set expires_at = now() where id = '{g8['data']['id']}'")
    re8 = ws_result(bg)
    left8 = poll(lambda: (lambda p: ["none"] if not p else None)(sshd_ops_sessions()), 20, 1, "no sshd: ops")
    row8 = session_row(admin, sid, s8["data"]["sessionId"]) or {}
    step("T4 grant expiry (sweeper <= 30 s, keepalive traffic so idle never fires): close 4408 (or 4403) grant_expired; "
         "no `sshd: ops` process remains",
         re8["closeCode"] in (4408, 4403) and "grant_expired" in (closing_reason(re8), row8.get("endReason"))
         and left8 == ["none"], fatal=False, ws=ws_summary(re8), endReason=row8.get("endReason"))

    rows = [x for x in sessions_of(admin, sid)]
    bad_rows = [x["id"] for x in rows if x["status"] == "closed" and not x.get("endReason")]
    leaks = [x[:120] for x in responses if LEAK_RE.search(x or "")]
    step("T4 every closed session row has end_reason; rows carry fingerprints only; whole-run payload scan clean",
         rows and not bad_rows and not leaks
         and all((x.get("credentialFingerprint") or "SHA256:").startswith("SHA256:") for x in rows), fatal=False,
         sessions=len(rows), withoutEndReason=bad_rows, scannedPayloads=len(responses), leaks=leaks[:3],
         endReasons=sorted({x.get("endReason") or "-" for x in rows}))
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
