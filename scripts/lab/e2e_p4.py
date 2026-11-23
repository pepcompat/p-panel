#!/usr/bin/env python3
"""pPanel P4a lab E2E: real Center API + real Go agent + dind Docker + nginx on ppanel-lab-node-b.

Journey: enroll node-b -> enable managed routing -> preflight blocks (tag-only image, legacy domain
conflict, missing secret) -> deploy web v1 -> v2 (route switch) -> broken candidate fails while v2 keeps
serving -> rollback to v1 -> redeploy vs restart -> secret never leaks (envecho logs the secret) ->
GitHub webhook auto-deploy (signature, dedupe, wrong branch, one deploy per commit) -> RBAC denial.

Prereqs: dev compose up + `prisma:migrate`; lab up (scripts/lab/up.sh) + `scripts/lab/images.sh`;
agent built; Center API running with API_HOST=0.0.0.0
PPANEL_PUBLIC_GATEWAY_URL=https://host.docker.internal:4443.
Run: python3 -I scripts/lab/e2e_p4.py [--out docs/evidence/<date>/p4-e2e.json]
Lab only: talks to localhost and the ppanel-lab containers.
"""
import base64
import hashlib
import hmac
import json
import os
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
NODE = "ppanel-lab-node-b"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
REG_PUSH = "127.0.0.1:55000"  # same reference works for the Center and for dind (lab-registry-fwd)
TAG = str(int(time.time()) % 100000)
results = []
all_responses = []  # every API response body, scanned for the secret at the end


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:280] if info else ""))
    if not ok:
        finish(1)


def finish(code):
    if "--out" in sys.argv:
        with open(sys.argv[sys.argv.index("--out") + 1], "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": results}, f, indent=2)
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def raw_call(method, path, token=None, body=None, headers=None, raw=None):
    h = {"Content-Type": "application/json", "X-Request-ID": str(uuid.uuid4())}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    all_responses.append(text)
    return status, (json.loads(text) if text else {})


def call(method, path, token=None, body=None, headers=None, expect=None):
    status, payload = raw_call(method, path, token, body, headers)
    if expect is not None and status not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {status} (expected {expect}): {json.dumps(payload)[:600]}")
    return status, payload


def sh(*argv, check=True):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=300)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {p.stderr[:400]}")
    return p.stdout.strip()


def node(cmd):
    return sh("docker", "exec", NODE, "sh", "-c", cmd)


def site(host, path="/"):
    return node(f"curl -s -m 5 -H 'Host: {host}' http://127.0.0.1{path} || true")


def totp(secret_b32, offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30 + offset), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def login(email, pw):
    return call("POST", "/auth/login", body={"email": email, "password": pw}, expect=200)[1]["data"]["accessToken"]


def poll(path, token, done, timeout=180):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        _, r = call("GET", path, token, expect=200)
        last = r["data"]
        if done(last):
            return last
        time.sleep(2)
    raise SystemExit(f"timeout on {path}: {json.dumps(last)[:500]}")


DEPLOY_DONE = {"succeeded", "failed", "rolled_back", "requires_manual_recovery", "cancelled", "expired",
               "awaiting_approval"}


def deploy(token, app_id, image, key=None):
    _, d = call("POST", f"/applications/{app_id}/deployments", token, {"image": image},
                {"Idempotency-Key": key or str(uuid.uuid4())}, expect=(200, 202))
    dep = d["data"]["deployment"]
    return poll(f"/deployments/{dep['id']}", token, lambda x: x["status"] in DEPLOY_DONE)


def images():
    env = {}
    for line in open(".lab/images.env"):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            env[k] = v.replace("lab-registry:5000", REG_PUSH)
    return env


def lab_reset():
    """Remove pPanel artifacts left on node-b by previous E2E runs (lab only), so a fresh enrollment
    starts from a host that pPanel has never touched. Legacy nginx sites are not modified."""
    dk = ["docker", "exec", "ppanel-lab-dind", "docker", "-H", "unix:///run/dind/docker.sock"]
    ids = sh(*dk, "ps", "-aq", "--filter", "label=ppanel.managed=true", check=False).split()
    if ids:
        sh(*dk, "rm", "-f", *ids, check=False)
    node("rm -rf /etc/nginx/ppanel-managed /etc/nginx/conf.d/ppanel-managed.conf && nginx -t -q && nginx -s reload")
    time.sleep(2)


def main():
    lab_reset()
    img = images()
    creator = login("superadmin@ppanel.local", "password")

    # approver (used only if an approval is required in this environment)
    pw = secrets.token_urlsafe(18)
    approver_email = f"e2e-p4-approver-{int(time.time())}@ppanel.local"
    call("POST", "/users", creator, {"email": approver_email, "password": pw, "displayName": "E2E P4 approver",
                                     "bindings": [{"roleKey": "ops_admin", "scopeType": "global"}]}, expect=201)
    approver = login(approver_email, pw)
    _, s = call("POST", "/auth/mfa/totp/setup", approver, expect=200)
    otp_secret = urllib.parse.parse_qs(urllib.parse.urlparse(s["data"]["otpauthUrl"]).query)["secret"][0]
    call("POST", "/auth/mfa/totp/confirm", approver, {"code": totp(otp_secret)}, expect=200)

    def step_up():
        time.sleep(31 - (time.time() % 30))
        return call("POST", "/auth/step-up", approver, {"code": totp(otp_secret)}, expect=200)[1]["data"]["stepUpToken"]

    # --- enroll node-b (uat) and start the agent
    _, e = call("POST", "/enrollments", creator, {"name": f"p4-node-b-{TAG}", "environment": "uat", "ttlMinutes": 10},
                expect=201)
    node("pkill -f '[p]panel-agent-linux-arm64 run' || true; find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", NODE, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["data"]["token"], "--state-dir", "/var/lib/ppanel-agent")
    sid = out.split("serverId=")[1].split()[0]
    sh("docker", "exec", "-d", NODE, "sh", "-c",
       f"{AGENT} run --state-dir /var/lib/ppanel-agent > /var/log/ppanel-agent.log 2>&1")
    srv = poll(f"/servers/{sid}", creator, lambda d: d["status"] == "online" and "docker" in d["capabilities"], 90)
    step("enroll node-b online with docker capability", True, serverId=sid, caps=srv["capabilities"])

    # legacy discovery so preflight knows node-b's existing nginx domains
    _, sc = call("POST", f"/servers/{sid}/discovery-scans", creator, {}, expect=202)
    poll(f"/discovery-scans/{sc['data']['scanId']}", creator, lambda d: d["status"] != "running")

    # --- app + preflight blocked while managed routing disabled
    app_name = f"web-{TAG}"
    domain = f"{app_name}.lab.test"
    _, a = call("POST", "/applications", creator, {"serverId": sid, "name": app_name, "environment": "uat",
                                                   "domains": [domain], "containerPort": 8080,
                                                   "healthcheck": {"path": "/healthz"}}, expect=201)
    app = a["data"]
    _, pf = call("POST", f"/applications/{app['id']}/deployments/preflight", creator, {"image": img["PPANEL_LAB_IMAGE_WEB_V1"]},
                 expect=200)
    codes = [c.get("code") for c in pf["data"]["checks"] if not c["ok"]]
    step("P4-T07 preflight blocks: managed routing disabled", "MANAGED_ROUTING_DISABLED" in codes, failing=codes)

    st, d = call("POST", "/applications", creator, {"serverId": sid, "name": f"shop-{TAG}", "environment": "uat",
                                                    "domains": ["shop.b.lab"], "containerPort": 8080})
    step("P4-T07 domain conflict with legacy nginx server_name", st in (409, 422) and
         d.get("error", {}).get("code") == "DOMAIN_CONFLICT", code=d.get("error", {}).get("code"))

    st, d = call("POST", f"/applications/{app['id']}/deployments", creator,
                 {"image": f"{REG_PUSH}/ppanel-test/web:v1"})
    step("P4-T07 tag-only image refused", st == 422 and d["error"]["code"] in ("IMAGE_NOT_PINNED", "VALIDATION_FAILED"),
         code=d["error"]["code"])

    # --- enable managed routing (one-time, approval if required)
    call("POST", f"/servers/{sid}/managed-routing", creator, expect=202)
    mr = poll(f"/servers/{sid}/managed-routing", creator,
              lambda x: x["enabled"] or x["status"] in ("awaiting_approval", "failed"))
    if not mr["enabled"] and mr["status"] == "awaiting_approval":
        call("POST", f"/servers/{sid}/managed-routing/approve", approver, {"planHash": mr["planHash"]},
             {"X-Step-Up": step_up()}, expect=202)
        mr = poll(f"/servers/{sid}/managed-routing", creator, lambda x: x["enabled"] or x["status"] == "failed")
    inc = node("cat /etc/nginx/conf.d/ppanel-managed.conf")
    step("managed routing enabled on node-b", mr["enabled"] and "ppanel-managed" in inc, include=inc)

    # --- deploy v1
    d1 = deploy(creator, app["id"], img["PPANEL_LAB_IMAGE_WEB_V1"])
    body = site(domain)
    step("J04 deploy v1: candidate healthy, route switched, site serves v1",
         d1["status"] == "succeeded" and "v1" in body, status=d1["status"], body=body[:60],
         container=d1.get("container"))

    # --- deploy v2 (route switch, previous stopped and kept for rollback)
    d2 = deploy(creator, app["id"], img["PPANEL_LAB_IMAGE_WEB_V2"])
    body = site(domain)
    step("deploy v2: route switched to v2", d2["status"] == "succeeded" and "v2" in body, body=body[:60])

    # --- P4-T04 broken candidate must not replace v2
    d3 = deploy(creator, app["id"], img["PPANEL_LAB_IMAGE_BROKEN"])
    body = site(domain)
    step("P4-T04 broken candidate fails; v2 keeps serving",
         d3["status"] == "failed" and (d3.get("error") or {}).get("code") == "CANDIDATE_UNHEALTHY" and "v2" in body,
         status=d3["status"], code=(d3.get("error") or {}).get("code"), body=body[:60])

    # --- rollback to v1
    _, rb = call("POST", f"/applications/{app['id']}/rollback", creator, {"reason": "e2e"}, expect=202)
    r = poll(f"/deployments/{rb['data']['deployment']['id']}", creator, lambda x: x["status"] in DEPLOY_DONE)
    body = site(domain)
    step("rollback to previous version (v1)", r["status"] == "succeeded" and "v1" in body, status=r["status"],
         body=body[:60])

    # --- restart vs redeploy are distinct
    _, cur = call("GET", f"/applications/{app['id']}", creator, expect=200)
    before_name = cur["data"]["container"]["containerName"]
    _, rs = call("POST", f"/applications/{app['id']}/restart", creator, expect=202)
    poll(f"/servers/{sid}/jobs/{rs['data']['jobId']}", creator, lambda x: x["status"] in ("succeeded", "failed"))
    _, after = call("GET", f"/applications/{app['id']}", creator, expect=200)
    _, deps_before = call("GET", f"/applications/{app['id']}/deployments", creator, expect=200)
    _, rd = call("POST", f"/applications/{app['id']}/redeploy", creator, expect=202)
    rdd = poll(f"/deployments/{rd['data']['deployment']['id']}", creator, lambda x: x["status"] in DEPLOY_DONE)
    _, after_rd = call("GET", f"/applications/{app['id']}", creator, expect=200)
    step("restart keeps container (no deployment); redeploy creates a fresh container",
         after["data"]["container"]["containerName"] == before_name and rdd["status"] == "succeeded"
         and after_rd["data"]["container"]["containerName"] != before_name and "v1" in site(domain),
         restartContainer=before_name, redeployContainer=after_rd["data"]["container"]["containerName"],
         deploymentsBeforeRedeploy=deps_before.get("paginate", {}).get("total"))

    # --- P4-T02 secrets never leak (envecho prints APP_SECRET to stdout)
    secret_value = "e2e-" + secrets.token_hex(16)
    ename = f"envecho-{TAG}"
    _, ea = call("POST", "/applications", creator, {"serverId": sid, "name": ename, "environment": "uat",
                                                    "domains": [f"{ename}.lab.test"], "containerPort": 8080,
                                                    "healthcheck": {"path": "/healthz"},
                                                    "secretKeys": ["APP_SECRET"]}, expect=201)
    eapp = ea["data"]
    _, pf = call("POST", f"/applications/{eapp['id']}/deployments/preflight", creator,
                 {"image": img["PPANEL_LAB_IMAGE_ENVECHO"]}, expect=200)
    step("P4-T07 preflight blocks: secret declared but not set",
         "SECRETS_MISSING" in [c.get("code") for c in pf["data"]["checks"] if not c["ok"]])
    call("PUT", f"/applications/{eapp['id']}/secrets/APP_SECRET", creator, {"value": secret_value}, expect=200)
    de = deploy(creator, eapp["id"], img["PPANEL_LAB_IMAGE_ENVECHO"])
    _, logs = call("GET", f"/applications/{eapp['id']}/logs?tail=200", creator, expect=200)
    log_text = json.dumps(logs)
    call("GET", f"/applications/{eapp['id']}/secrets", creator, expect=200)
    call("GET", f"/deployments/{de['id']}", creator, expect=200)
    call("GET", f"/servers/{sid}/jobs?limit=100", creator, expect=200)
    call("GET", "/audit-events?limit=100", creator, expect=200)
    agent_log = node("cat /var/log/ppanel-agent.log")
    leaked = [i for i, t in enumerate(all_responses) if secret_value in t]
    step("P4-T02 secret delivered to the container but never in API/logs/audit/agent log",
         de["status"] == "succeeded" and "[REDACTED]" in log_text and not leaked and secret_value not in agent_log,
         status=de["status"], redactedInLogs="[REDACTED]" in log_text, leakedResponses=len(leaked))

    # --- P4-T06 GitHub webhook auto-deploy
    wh_secret = secrets.token_hex(20)
    _, ig = call("POST", "/integrations/github", creator, {"name": f"e2e-{TAG}", "webhookSecret": wh_secret},
                 expect=201)
    integ = ig["data"]
    sha = hashlib.sha1(TAG.encode()).hexdigest()
    sh("docker", "tag", f"{REG_PUSH}/ppanel-test/web:v2", f"{REG_PUSH}/ppanel-test/web:sha-{sha[:7]}")
    sh("docker", "push", "-q", f"{REG_PUSH}/ppanel-test/web:sha-{sha[:7]}")
    call("POST", f"/applications/{app['id']}/auto-deploy", creator,
         {"integrationId": integ["id"], "repo": "lab-org/web", "branches": ["main"],
          "imageTemplate": f"{REG_PUSH}/ppanel-test/web:sha-{{sha7}}", "enabled": True}, expect=201)

    def hook(ref, delivery, signature_secret=wh_secret):
        payload = json.dumps({"ref": ref, "after": sha, "repository": {"full_name": "lab-org/web"}}).encode()
        sig = "sha256=" + hmac.new(signature_secret.encode(), payload, hashlib.sha256).hexdigest()
        return raw_call("POST", f"/webhooks/github/{integ['id']}", None, None,
                        {"X-GitHub-Event": "push", "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig},
                        raw=payload)

    st_bad, _ = hook("refs/heads/main", str(uuid.uuid4()), "wrong-secret")
    dlv = str(uuid.uuid4())
    st1, h1 = hook("refs/heads/main", dlv)
    st2, h2 = hook("refs/heads/main", dlv)
    st3, h3 = hook("refs/heads/feature-x", str(uuid.uuid4()))
    dep_ids = (h1.get("data") or {}).get("deploymentIds") or []
    wd = poll(f"/deployments/{dep_ids[0]}", creator, lambda x: x["status"] in DEPLOY_DONE) if dep_ids else {}
    st4, h4 = hook("refs/heads/main", str(uuid.uuid4()))  # same commit again
    step("P4-T06 webhook: bad sig 401, one deploy per commit, duplicate delivery no-op, wrong branch ignored",
         st_bad == 401 and len(dep_ids) == 1 and wd.get("status") == "succeeded" and "v2" in site(domain)
         and (h2.get("data") or {}).get("duplicate") is True
         and (h3.get("data") or {}).get("result") == "ignored"
         and not (h4.get("data") or {}).get("deploymentIds"),
         badSig=st_bad, first=(h1.get("data") or {}).get("result"), duplicate=(h2.get("data") or {}).get("duplicate"),
         wrongBranch=(h3.get("data") or {}).get("result"), sameCommitAgain=(h4.get("data") or {}).get("reasons"),
         deployedImage=wd.get("image"), commit=sha)

    # --- RBAC: viewer cannot deploy
    viewer = login("user1@ppanel.local", "password")
    st, d = call("POST", f"/applications/{app['id']}/deployments", viewer, {"image": img["PPANEL_LAB_IMAGE_WEB_V1"]})
    step("viewer cannot deploy", st == 403, code=d.get("error", {}).get("code"))

    # --- legacy sites on node-b untouched throughout
    legacy = node("curl -s -o /dev/null -w '%{http_code}' -H 'Host: shop.b.lab' http://127.0.0.1/")
    exposed = node("ss -ltnH | awk '{print $4}' | grep -E ':2[0-9]{4}$' | grep -v '^127.0.0.1' || true")
    step("legacy site still 200; managed ports bound to 127.0.0.1 only", legacy == "200" and exposed == "",
         legacy=legacy, nonLoopbackManagedPorts=exposed)
    finish(0)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/../..")
    main()
