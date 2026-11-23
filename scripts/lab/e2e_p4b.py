#!/usr/bin/env python3
"""pPanel P4b lab E2E: builds from Git on a designated build node + Compose execution, driven through
the real Center API, real Go agent, lab-git, dind and the lab registry on ppanel-lab-node-b.

Journey: enroll node-b -> designate build node -> inspect source (detection) -> build websrc@v1 from Git
-> auto deploy -> same commit reused -> bad commit fails with no deployment -> GitHub webhook in build
mode deploys v2 -> build the stack image -> Compose app (postgres + worker + app, DB_PASSWORD secret)
-> data written -> Compose v2 (only app changed): db/worker unchanged, data persists -> rollback
re-applies v1 plan, data NOT restored (still growing) -> RBAC.

Prereqs: scripts/lab/up.sh, scripts/lab/git-fixtures.sh (writes .lab/git.env), agent built and copied
to .lab/agent-bin, Center API running with API_HOST=0.0.0.0
PPANEL_PUBLIC_GATEWAY_URL=https://host.docker.internal:4443.
Run: python3 -I scripts/lab/e2e_p4b.py [--out docs/evidence/<date>/p4b-e2e.json]
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

API = "http://localhost:4000/api/v1"
NODE = "ppanel-lab-node-b"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
REG = "127.0.0.1:55000"  # same reference for the Center and for dind (lab-registry-fwd)
TAG = str(int(time.time()) % 100000)
results = []
responses = []


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:300] if info else ""))
    if not ok:
        finish(1)


def finish(code):
    if "--out" in sys.argv:
        with open(sys.argv[sys.argv.index("--out") + 1], "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": results}, f, indent=2)
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def raw(method, path, token=None, body=None, headers=None, data=None):
    h = {"Content-Type": "application/json", "X-Request-ID": str(uuid.uuid4())}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    payload = data if data is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(API + path, data=payload, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    responses.append(text)
    return status, (json.loads(text) if text else {})


def call(method, path, token=None, body=None, headers=None, expect=None):
    status, payload = raw(method, path, token, body, headers)
    if expect is not None and status not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {status} (expected {expect}): {json.dumps(payload)[:700]}")
    return status, payload


def sh(*argv, check=True):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=600)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {p.stderr[:400]}")
    return p.stdout.strip()


def node(cmd):
    return sh("docker", "exec", NODE, "sh", "-c", cmd)


def site(host, path="/"):
    return node(f"curl -s -m 10 -H 'Host: {host}' http://127.0.0.1{path} || true")


def site_json(host):
    txt = site(host)
    try:
        return json.loads(txt)
    except ValueError:
        return {"raw": txt[:120]}


def poll(path, token, done, timeout=900, every=3):
    end, last = time.time() + timeout, None
    while time.time() < end:
        _, r = call("GET", path, token, expect=200)
        last = r["data"]
        if done(last):
            return last
        time.sleep(every)
    raise SystemExit(f"timeout on {path}: {json.dumps(last)[:600]}")


BUILD_DONE = {"succeeded", "failed", "cancelled", "expired"}
DEPLOY_DONE = {"succeeded", "failed", "rolled_back", "requires_manual_recovery", "cancelled", "expired",
               "awaiting_approval"}


def env_file(path):
    out = {}
    for line in open(path):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            out[k] = v
    return out


def lab_reset():
    dk = ["docker", "exec", "ppanel-lab-dind", "docker", "-H", "unix:///run/dind/docker.sock"]
    ids = sh(*dk, "ps", "-aq", "--filter", "label=ppanel.managed=true", check=False).split()
    if ids:
        sh(*dk, "rm", "-f", *ids, check=False)
    node("rm -rf /etc/nginx/ppanel-managed /etc/nginx/conf.d/ppanel-managed.conf && nginx -t -q && nginx -s reload")
    time.sleep(2)


def build(token, app_id, sha, **extra):
    st, b = call("POST", f"/applications/{app_id}/builds", token, {"commitSha": sha, **extra},
                 {"Idempotency-Key": str(uuid.uuid4())}, expect=(200, 202))
    data = b["data"]
    if data.get("reused"):
        return data["build"], True
    return poll(f"/builds/{data['build']['id']}", token, lambda x: x["status"] in BUILD_DONE), False


def main():
    git = env_file(".lab/git.env")
    lab_reset()
    creator = call("POST", "/auth/login", body={"email": "superadmin@ppanel.local", "password": "password"},
                   expect=200)[1]["data"]["accessToken"]

    # --- enroll node-b, designate as build node
    _, e = call("POST", "/enrollments", creator, {"name": f"p4b-node-b-{TAG}", "environment": "uat", "ttlMinutes": 10},
                expect=201)
    node("pkill -f '[p]panel-agent-linux-arm64 run' || true; find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", NODE, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["data"]["token"], "--state-dir", "/var/lib/ppanel-agent")
    sid = out.split("serverId=")[1].split()[0]
    sh("docker", "exec", "-d", NODE, "sh", "-c",
       f"{AGENT} run --state-dir /var/lib/ppanel-agent > /var/log/ppanel-agent.log 2>&1")
    srv = poll(f"/servers/{sid}", creator, lambda d: d["status"] == "online" and "build" in d["capabilities"], 120)
    call("PATCH", f"/servers/{sid}", creator, {"buildNode": True}, {"If-Match": str(srv["version"])}, expect=200)
    step("node-b online with build capability, designated build node", True, caps=srv["capabilities"])

    call("POST", f"/servers/{sid}/managed-routing", creator, expect=202)
    mr = poll(f"/servers/{sid}/managed-routing", creator, lambda x: x["enabled"] or x["status"] == "failed")
    step("managed routing enabled", mr["enabled"])

    # --- container app built from Git (websrc)
    wname = f"websrc-{TAG}"
    wdom = f"{wname}.lab.test"
    _, a = call("POST", "/applications", creator, {"serverId": sid, "name": wname, "environment": "uat",
                                                   "domains": [wdom], "containerPort": 8080,
                                                   "healthcheck": {"path": "/healthz"}}, expect=201)
    app = a["data"]
    _, cur = call("GET", f"/applications/{app['id']}", creator, expect=200)
    call("PUT", f"/applications/{app['id']}/build-config", creator,
         {"repoUrl": git["PPANEL_LAB_GIT_URL_WEBSRC"], "dockerfile": "Dockerfile", "buildServerId": sid,
          "pushRepo": f"{REG}/ppanel-build/{wname}"}, {"If-Match": str(cur["data"]["version"])}, expect=(200, 201))

    st, ins = call("POST", f"/applications/{app['id']}/source/inspect", creator,
                   {"commitSha": git["PPANEL_LAB_GIT_SHA_WEBSRC"]}, expect=(200, 202))
    insp = ins["data"]
    if st == 202 or insp.get("status") == "pending":
        insp = poll(f"/applications/{app['id']}/source/inspect/{insp['id']}", creator,
                    lambda x: x.get("status") in ("succeeded", "failed"))
    step("source inspect on build node detects framework from real repo",
         (insp.get("detection") or {}).get("framework") == "dockerfile",
         files=sorted((insp.get("files") or {}).keys()), detection=insp.get("detection"))

    b1, _ = build(creator, app["id"], git["PPANEL_LAB_GIT_SHA_WEBSRC"])
    dep = poll(f"/builds/{b1['id']}", creator, lambda x: x.get("deploymentId")) if b1["status"] == "succeeded" else {}
    d1 = poll(f"/deployments/{dep['deploymentId']}", creator, lambda x: x["status"] in DEPLOY_DONE) if dep else {}
    body = site(wdom)
    step("P4-T01 Git commit -> build on node -> push digest -> deploy -> serves v1",
         b1["status"] == "succeeded" and "@sha256:" in (b1.get("image") or "") and d1.get("status") == "succeeded"
         and "websrc v1" in body, image=b1.get("image"), deployment=d1.get("status"), body=body[:40],
         commit=b1.get("commitSha"))

    again, reused = build(creator, app["id"], git["PPANEL_LAB_GIT_SHA_WEBSRC"])
    step("same commit reuses the existing build (no rebuild)", reused and again["id"] == b1["id"])

    bad, _ = build(creator, app["id"], "0" * 40)
    step("unknown commit: build fails, no deployment, v1 keeps serving",
         bad["status"] == "failed" and not bad.get("deploymentId") and "websrc v1" in site(wdom),
         code=(bad.get("error") or {}).get("code"))

    # --- webhook in build mode -> v2
    secret = os.urandom(20).hex()
    _, ig = call("POST", "/integrations/github", creator, {"name": f"p4b-{TAG}", "webhookSecret": secret}, expect=201)
    call("POST", f"/applications/{app['id']}/auto-deploy", creator,
         {"integrationId": ig["data"]["id"], "repo": "lab-org/websrc", "branches": ["main"], "mode": "build",
          "enabled": True}, expect=201)
    sha2 = git["PPANEL_LAB_GIT_SHA_WEBSRC_V2"]
    payload = json.dumps({"ref": "refs/heads/main", "after": sha2, "repository": {"full_name": "lab-org/websrc"}}).encode()
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    delivery = str(uuid.uuid4())
    hdr = {"X-GitHub-Event": "push", "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig}
    s1, h1 = raw("POST", f"/webhooks/github/{ig['data']['id']}", None, None, hdr, payload)
    s2, h2 = raw("POST", f"/webhooks/github/{ig['data']['id']}", None, None, hdr, payload)
    bids = (h1.get("data") or {}).get("buildIds") or []
    wb = poll(f"/builds/{bids[0]}", creator, lambda x: x["status"] in BUILD_DONE) if bids else {}
    wdp = poll(f"/builds/{bids[0]}", creator, lambda x: x.get("deploymentId")) if wb.get("status") == "succeeded" else {}
    wd = poll(f"/deployments/{wdp['deploymentId']}", creator, lambda x: x["status"] in DEPLOY_DONE) if wdp else {}
    step("webhook push (build mode): one build -> deploy v2; duplicate delivery no-op",
         len(bids) == 1 and wd.get("status") == "succeeded" and "websrc v2" in site(wdom)
         and (h2.get("data") or {}).get("duplicate") is True,
         result=(h1.get("data") or {}).get("result"), build=wb.get("status"), deploy=wd.get("status"))

    # --- build the stack image (v1 and v2) via a build-only container app
    iname = f"stackimg-{TAG}"
    _, ia = call("POST", "/applications", creator, {"serverId": sid, "name": iname, "environment": "uat",
                                                    "domains": [f"{iname}.lab.test"], "containerPort": 8080}, expect=201)
    _, icur = call("GET", f"/applications/{ia['data']['id']}", creator, expect=200)
    call("PUT", f"/applications/{ia['data']['id']}/build-config", creator,
         {"repoUrl": git["PPANEL_LAB_GIT_URL_STACK"], "dockerfile": "Dockerfile", "buildServerId": sid,
          "pushRepo": f"{REG}/ppanel-build/stack-{TAG}"}, {"If-Match": str(icur["data"]["version"])}, expect=(200, 201))
    s_v1, _ = build(creator, ia["data"]["id"], git["PPANEL_LAB_GIT_SHA_STACK"], deployAfter=False)
    s_v2, _ = build(creator, ia["data"]["id"], git["PPANEL_LAB_GIT_SHA_STACK_V2"], deployAfter=False)
    step("stack images built from Git (v1, v2), no deployment requested",
         s_v1["status"] == s_v2["status"] == "succeeded" and not s_v1.get("deploymentId"),
         v1=s_v1.get("image"), v2=s_v2.get("image"))

    # --- Compose app: postgres + worker + app
    db_img = "docker.io/library/postgres@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"

    def compose_yaml(app_img, worker_img):
        return f"""services:
  db:
    image: {db_img}
    environment:
      POSTGRES_USER: app
      POSTGRES_DB: app
      POSTGRES_PASSWORD: ${{DB_PASSWORD}}
    volumes:
      - pgdata:/var/lib/postgresql/data
  worker:
    image: {worker_img}
    command: ['php', '/app/worker.php']
    environment:
      DB_HOST: db
      DB_NAME: app
      DB_USER: app
      DB_PASSWORD: ${{DB_PASSWORD}}
    depends_on: [db]
  app:
    image: {app_img}
    environment:
      DB_HOST: db
      DB_NAME: app
      DB_USER: app
      DB_PASSWORD: ${{DB_PASSWORD}}
    depends_on: [db]
volumes:
  pgdata: {{}}
"""

    cname = f"stack-{TAG}"
    cdom = f"{cname}.lab.test"
    _, ca = call("POST", "/applications", creator,
                 {"kind": "compose", "serverId": sid, "name": cname, "environment": "uat", "domains": [cdom],
                  "yaml": compose_yaml(s_v1["image"], s_v1["image"]), "routeService": "app", "routePort": 8080,
                  "healthPath": "/healthz"}, expect=201)
    capp = ca["data"]
    st, d = call("POST", f"/applications/{capp['id']}/deployments", creator, {})
    step("compose deploy blocked until the DB_PASSWORD secret is set",
         (d.get("data", {}).get("deployment", {}).get("status") == "failed"
          and d["data"]["deployment"].get("error", {}).get("code") == "SECRETS_MISSING")
         or d.get("error", {}).get("code") == "SECRETS_MISSING", http=st)
    db_pw = os.urandom(12).hex()
    call("PUT", f"/applications/{capp['id']}/secrets/DB_PASSWORD", creator, {"value": db_pw}, expect=200)

    _, d = call("POST", f"/applications/{capp['id']}/deployments", creator, {},
                {"Idempotency-Key": str(uuid.uuid4())}, expect=(200, 202))
    c1 = poll(f"/deployments/{d['data']['deployment']['id']}", creator, lambda x: x["status"] in DEPLOY_DONE)
    site_json(cdom)
    time.sleep(6)
    j1 = site_json(cdom)
    step("P4-T03 compose v1 up: app serves, worker writes heartbeats into Postgres",
         c1["status"] == "succeeded" and j1.get("version") == "v1" and j1.get("hits", 0) >= 2
         and j1.get("heartbeats", 0) >= 1, deployment=c1["status"], app=j1,
         services=[(s.get("service"), s.get("action")) for s in ((c1.get("compose") or {}).get("services") or [])])

    # --- compose v2: only app image changes
    _, cur = call("GET", f"/applications/{capp['id']}", creator, expect=200)
    call("PUT", f"/applications/{capp['id']}/compose", creator,
         {"yaml": compose_yaml(s_v2["image"], s_v1["image"]), "routeService": "app", "routePort": 8080,
          "healthPath": "/healthz"}, {"If-Match": str(cur["data"]["version"])}, expect=200)
    _, d = call("POST", f"/applications/{capp['id']}/deployments", creator, {},
                {"Idempotency-Key": str(uuid.uuid4())}, expect=(200, 202))
    c2 = poll(f"/deployments/{d['data']['deployment']['id']}", creator, lambda x: x["status"] in DEPLOY_DONE)
    acts = {s.get("service"): s.get("action") for s in ((c2.get("compose") or {}).get("services") or [])}
    j2 = site_json(cdom)
    step("P4-T03 redeploy with only app changed: db+worker unchanged, data persisted",
         c2["status"] == "succeeded" and acts.get("db") == "unchanged" and acts.get("worker") == "unchanged"
         and acts.get("app") in ("replaced", "created") and j2.get("version") == "v2"
         and j2.get("hits", 0) > j1.get("hits", 0) and j2.get("heartbeats", 0) >= j1.get("heartbeats", 0),
         actions=acts, before=j1, after=j2)

    # --- rollback: previous plan, data not restored
    _, rb = call("POST", f"/applications/{capp['id']}/rollback", creator, {"reason": "e2e"}, expect=202)
    rbd = rb["data"]
    c3 = poll(f"/deployments/{rbd['deployment']['id']}", creator, lambda x: x["status"] in DEPLOY_DONE)
    j3 = site_json(cdom)
    step("compose rollback re-applies v1 plan; data NOT restored (counts keep growing)",
         c3["status"] == "succeeded" and (rbd.get("rollback") or {}).get("dataRestored") is False
         and j3.get("version") == "v1" and j3.get("hits", 0) > j2.get("hits", 0), after=j3)

    leaked = sum(1 for t in responses if db_pw in t)
    step("DB secret never appears in any API response", leaked == 0, leakedResponses=leaked)

    viewer = call("POST", "/auth/login", body={"email": "user1@ppanel.local", "password": "password"},
                  expect=200)[1]["data"]["accessToken"]
    st, d = call("POST", f"/applications/{app['id']}/builds", viewer, {"commitSha": git["PPANEL_LAB_GIT_SHA_WEBSRC"]})
    step("viewer cannot start a build", st == 403, code=d.get("error", {}).get("code"))

    legacy = node("curl -s -o /dev/null -w '%{http_code}' -H 'Host: shop.b.lab' http://127.0.0.1/")
    step("legacy site on node-b still 200", legacy == "200")
    finish(0)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/../..")
    main()
