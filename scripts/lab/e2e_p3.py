#!/usr/bin/env python3
"""pPanel P3 lab E2E: real Center API + real Go agent + real nginx in the ppanel-lab containers.

Journey (J02/J03): enroll -> read-only scan (checksums unchanged) -> import Observe -> adopt ->
broken revision blocked by `nginx -t` -> good revision -> approval (creator refused, second user with
step-up) -> apply + postcheck -> revert -> external edit detected as drift -> RBAC denial.

Prereqs (see docs/DEPLOYMENT_RUNBOOK.md): dev compose up, `prisma:migrate`, lab up
(scripts/lab/up.sh), agent built (apps/agent/bin/ppanel-agent-linux-arm64), Center API running with
API_HOST=0.0.0.0 PPANEL_PUBLIC_GATEWAY_URL=https://host.docker.internal:4443.

Run: python3 -I scripts/lab/e2e_p3.py [--out docs/evidence/<date>/p3-e2e.json]
Lab only: talks to localhost and the ppanel-lab containers. Never point it at a real host.
"""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

API = "http://localhost:4000/api/v1"
NODE = "ppanel-lab-node-a"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
HOST = "static.example.lab"
results = []


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:300] if info else ""))
    if not ok:
        finish(1)


def finish(code):
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else None
    if out:
        with open(out, "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": results}, f, indent=2)
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def call(method, path, token=None, body=None, headers=None, expect=None):
    h = {"Content-Type": "application/json", "X-Request-ID": str(uuid.uuid4())}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    payload = json.loads(raw) if raw else {}
    if expect is not None and status != expect:
        raise SystemExit(f"{method} {path} -> {status} (expected {expect}): {json.dumps(payload)[:600]}")
    return status, payload


def sh(*argv, check=True):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=120)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {p.stderr[:400]}")
    return p.stdout.strip()


def node(cmd):
    return sh("docker", "exec", NODE, "sh", "-c", cmd)


def nginx_state():
    sums = node("find /etc/nginx -type f -o -type l | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -c1-16")
    return {"configHash": sums, "masterPid": node("cat /run/nginx.pid")}


def http_code(path, host=HOST):
    return node(f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {host}' http://127.0.0.1{path}")


def totp(secret_b32, step_offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int(time.time()) // 30 + step_offset
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def wait_next_window():
    time.sleep(31 - (time.time() % 30))


def login(email, password):
    _, r = call("POST", "/auth/login", body={"email": email, "password": password}, expect=200)
    return r["data"]["accessToken"]


def poll(path, token, done, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        _, r = call("GET", path, token, expect=200)
        if done(r["data"]):
            return r["data"]
        time.sleep(1.5)
    raise SystemExit(f"timeout waiting on {path}: {json.dumps(r)[:400]}")


TERMINAL = {"valid", "invalid", "applied", "apply_failed", "reverted", "drift_blocked",
            "requires_manual_recovery", "cancelled", "awaiting_approval"}


def main():
    creator = login("superadmin@ppanel.local", "password")

    # --- approver: dedicated ops_admin with TOTP (approver != creator, step-up required)
    pw = secrets.token_urlsafe(18)
    email = f"e2e-approver-{int(time.time())}@ppanel.local"
    call("POST", "/users", creator, {"email": email, "password": pw, "displayName": "E2E approver",
                                     "bindings": [{"roleKey": "ops_admin", "scopeType": "global"}]}, expect=201)
    approver = login(email, pw)
    _, s = call("POST", "/auth/mfa/totp/setup", approver, expect=200)
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(s["data"]["otpauthUrl"]).query)["secret"][0]
    call("POST", "/auth/mfa/totp/confirm", approver, {"code": totp(secret)}, expect=200)
    step("approver user with TOTP", True, email=email)

    # --- enroll lab node-a (uat) and start the agent
    _, e = call("POST", "/enrollments", creator, {"name": f"p3-node-a-{int(time.time()) % 100000}",
                                                  "environment": "uat", "ttlMinutes": 10}, expect=201)
    node("pkill -f '[p]panel-agent-linux-arm64 run' || true; find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", NODE, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["data"]["token"], "--state-dir", "/var/lib/ppanel-agent")
    server_id = out.split("serverId=")[1].split()[0]
    sh("docker", "exec", "-d", NODE, "sh", "-c",
       f"{AGENT} run --state-dir /var/lib/ppanel-agent > /var/log/ppanel-agent.log 2>&1")
    poll(f"/servers/{server_id}", creator, lambda d: d["status"] == "online", 60)
    step("enroll + online", True, serverId=server_id)

    baseline = nginx_state()
    site_before = http_code("/")

    # --- P3-T01: read-only scan
    _, sc = call("POST", f"/servers/{server_id}/discovery-scans", creator, {}, expect=202)
    scan = poll(f"/discovery-scans/{sc['data']['scanId']}", creator, lambda d: d["status"] != "running")
    after_scan = nginx_state()
    step("P3-T01 scan completed, nginx config + master PID unchanged",
         scan["status"] == "completed" and after_scan == baseline, summary=scan["summary"], before=baseline, after=after_scan)

    _, f = call("GET", f"/discovery-scans/{scan['id']}/findings?limit=100", creator, expect=200)
    findings = f["data"]
    target = next(x for x in findings if x["kind"] == "nginx_server" and HOST in x.get("domains", []))
    dups = [x["title"] for x in findings if x.get("conflicts")]
    step("P3-T02 findings incl. duplicate conflict", bool(dups), target=target["title"], conflicts=dups[:4])

    # --- import (Observe default) never changes the host
    _, im = call("POST", f"/discovery-scans/{scan['id']}/import", creator,
                 {"findingIds": [target["id"]], "mode": "observed"}, expect=201)
    app = im["data"]["applications"][0]
    st, bad = call("POST", f"/discovery-scans/{scan['id']}/import", creator,
                   {"findingIds": [target["id"]], "mode": "managed"})
    step("import Observe; managed via import refused; host unchanged",
         app["ownershipMode"] == "observed" and st == 422 and nginx_state() == baseline,
         appId=app["id"], refusedCode=bad.get("error", {}).get("code"))

    # --- RBAC: viewer cannot change ownership
    viewer = login("user1@ppanel.local", "password")
    st, d = call("POST", f"/applications/{app['id']}/ownership", viewer, {"toMode": "adopted", "reason": "x"})
    step("viewer ownership change denied", st == 403, code=d.get("error", {}).get("code"))

    # --- adopt (ack reasons if flagged)
    _, cur = call("GET", f"/applications/{app['id']}", creator, expect=200)
    body = {"toMode": "adopted", "reason": "P3 lab E2E", "acknowledgeReasons": True}
    _, ad = call("POST", f"/applications/{app['id']}/ownership", creator, body,
                 {"If-Match": str(cur["data"]["version"])}, expect=200)
    step("adopt (observed -> adopted)", ad["data"]["ownershipMode"] == "adopted" and nginx_state() == baseline)

    # --- current files
    _, fl = call("GET", f"/applications/{app['id']}/nginx/files", creator, expect=200)
    file0 = fl["data"]["files"][0]
    path, content = (file0.get("resolvedPath") or file0["path"]), file0["content"]
    step("read current nginx files", content is not None, path=path, sha=file0["sha256"][:12])

    # --- P3-T03: broken revision is blocked by nginx -t; nothing changes
    anchor = "    index index.html;"
    assert anchor in content, "fixture anchor missing"
    broken = content.replace(anchor, anchor + "\n    p3_broken_directive on;", 1)
    _, rv = call("POST", f"/applications/{app['id']}/nginx/revisions", creator,
                 {"files": [{"path": path, "content": broken}]}, expect=201)
    call("POST", f"/nginx-revisions/{rv['data']['id']}/validate", creator, expect=202)
    r1 = poll(f"/nginx-revisions/{rv['data']['id']}", creator, lambda d: d["status"] in TERMINAL)
    st, ap = call("POST", f"/nginx-revisions/{r1['id']}/apply", creator)
    step("P3-T03 broken config: validate invalid, apply refused, host unchanged",
         r1["status"] == "invalid" and st in (409, 422) and nginx_state() == baseline and http_code("/") == site_before,
         nginxTest=(r1.get("validation") or {}).get("nginxTestOutput", "")[-160:], applyCode=ap.get("error", {}).get("code"))
    # `invalid` is terminal: it does not block a new revision and cannot be cancelled.
    st, d = call("POST", f"/nginx-revisions/{r1['id']}/cancel", creator)
    step("invalid revision is terminal (cancel not applicable)", st == 409, code=d.get("error", {}).get("code"))

    # --- good revision: validate -> approval -> apply with postcheck
    good = content.replace(anchor, anchor + "\n    location = /p3-e2e { return 200 'p3 ok'; }", 1)
    _, rv = call("POST", f"/applications/{app['id']}/nginx/revisions", creator,
                 {"files": [{"path": path, "content": good}],
                  "postchecks": [{"hostHeader": HOST, "path": "/p3-e2e", "expectStatus": [200]},
                                 {"hostHeader": HOST, "path": "/", "expectStatus": [200]}]}, expect=201)
    rid = rv["data"]["id"]
    call("POST", f"/nginx-revisions/{rid}/validate", creator, expect=202)
    r2 = poll(f"/nginx-revisions/{rid}", creator, lambda d: d["status"] in TERMINAL)
    step("good revision validates; host unchanged after dry-run",
         r2["status"] in ("valid", "awaiting_approval") and nginx_state() == baseline, status=r2["status"])

    st, d = call("POST", f"/nginx-revisions/{rid}/apply", creator)
    step("apply without approval refused", st == 409, code=d.get("error", {}).get("code"))
    st, d = call("POST", f"/nginx-revisions/{rid}/approve", creator, {"planHash": r2["planHash"]})
    step("creator cannot approve own revision", st == 403, code=d.get("error", {}).get("code"))

    wait_next_window()  # TOTP steps are single-use
    _, su = call("POST", "/auth/step-up", approver, {"code": totp(secret)}, expect=200)
    _, ok = call("POST", f"/nginx-revisions/{rid}/approve", approver, {"planHash": r2["planHash"]},
                 {"X-Step-Up": su["data"]["stepUpToken"]}, expect=200)
    step("second user approves with step-up (planHash-bound)", True, planHash=r2["planHash"][:16])

    pid_before = node("cat /run/nginx.pid")
    call("POST", f"/nginx-revisions/{rid}/apply", creator, expect=202)
    r3 = poll(f"/nginx-revisions/{rid}", creator, lambda d: d["status"] in TERMINAL)
    probe = http_code("/p3-e2e")
    step("apply: nginx -t + reload + postchecks, master PID kept",
         r3["status"] == "applied" and probe == "200" and node("cat /run/nginx.pid") == pid_before,
         status=r3["status"], probe=probe, postchecks=(r3.get("result") or {}).get("postchecks"))

    st, d = call("POST", f"/nginx-revisions/{rid}/approve", approver, {"planHash": r2["planHash"]},
                 {"X-Step-Up": su["data"]["stepUpToken"]})
    step("approval is single-use (re-approve after apply refused)", st in (409, 403), code=d.get("error", {}).get("code"))

    # --- revert restores the exact original
    call("POST", f"/nginx-revisions/{rid}/revert", creator, expect=202)
    r4 = poll(f"/nginx-revisions/{rid}", creator, lambda d: d["status"] in {"reverted", "apply_failed", "drift_blocked",
                                                                            "requires_manual_recovery"})
    step("revert restores original config", r4["status"] == "reverted" and nginx_state()["configHash"] == baseline["configHash"]
         and http_code("/p3-e2e") == "404", status=r4["status"])

    # --- P3-T05: external edit -> drift detected, writes blocked until acknowledged
    real = node(f"readlink -f {path}")
    node(f"cp {real} /tmp/p3-orig.conf && printf '\\n# external edit by operator\\n' >> {real}")
    _, sc2 = call("POST", f"/servers/{server_id}/discovery-scans", creator, {}, expect=202)
    scan2 = poll(f"/discovery-scans/{sc2['data']['scanId']}", creator, lambda d: d["status"] != "running")
    _, a2 = call("GET", f"/applications/{app['id']}", creator, expect=200)
    st, d = call("POST", f"/applications/{app['id']}/nginx/revisions", creator,
                 {"files": [{"path": path, "content": good}]})
    step("P3-T05 external edit flagged as drift; new revision blocked",
         a2["data"]["flags"]["driftDetected"] and st == 409 and any(x.get("changedBy") == "external" for x in scan2.get("drift", [])),
         code=d.get("error", {}).get("code"), drift=scan2.get("drift"))

    # cleanup: restore the operator file exactly, rescan, acknowledge
    node(f"cp /tmp/p3-orig.conf {real} && rm -f /tmp/p3-orig.conf")
    _, sc3 = call("POST", f"/servers/{server_id}/discovery-scans", creator, {}, expect=202)
    poll(f"/discovery-scans/{sc3['data']['scanId']}", creator, lambda d: d["status"] != "running")
    _, a3 = call("GET", f"/applications/{app['id']}", creator, expect=200)
    if a3["data"]["flags"]["driftDetected"]:
        call("POST", f"/applications/{app['id']}/drift/acknowledge", creator, None,
             {"If-Match": str(a3["data"]["version"])}, expect=200)
    final = nginx_state()
    step("lab restored to baseline", final["configHash"] == baseline["configHash"] and http_code("/") == site_before,
         final=final)
    finish(0)


if __name__ == "__main__":
    main()
