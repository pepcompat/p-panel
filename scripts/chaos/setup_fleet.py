#!/usr/bin/env python3
"""P7 baseline fleet for the chaos scenarios (lab only).

Stops whatever Center listens on :4000, starts the snapshot Center (scripts/chaos/_lib.py), removes pPanel
artifacts from node-b (managed containers, /etc/nginx/ppanel-managed), then:
  node-a (uat): enrolled; legacy nginx site `static.example.lab` imported + adopted (nginx revisions need approval)
  node-b (uat): enrolled; managed routing; container app `p7web-<tag>` (web v1) and compose app
                `p7stack-<tag>` (postgres + web v1 as route service) deployed and serving.
Writes .lab/chaos/fleet.json, used by every other chaos script.
Run: python3 -I scripts/chaos/setup_fleet.py
"""
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (DIND, NODE_A, NODE_B, AGENT, Evidence, call, data, login, main_guard, node, poll_get,  # noqa: E402
                  save_fleet, sh, site_body, site_code, snapshot_center, start_agent, start_center, stop_agent,
                  stop_center)

TAG = str(int(time.time()) % 100000)
REG = "127.0.0.1:55000"
PG_IMG = "docker.io/library/postgres@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
DEPLOY_DONE = {"succeeded", "failed", "rolled_back", "requires_manual_recovery", "cancelled", "expired",
               "awaiting_approval"}


def images():
    env = {}
    for line in open(".lab/images.env"):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            env[k] = v.replace("lab-registry:5000", REG)
    return env


def enroll(admin, n, name):
    e = data("POST", "/enrollments", admin, {"name": name, "environment": "uat", "ttlMinutes": 10})
    stop_agent(n)
    node(n, "find /var/lib/ppanel-agent -mindepth 1 -delete; : > /var/log/ppanel-agent.log")
    out = sh("docker", "exec", n, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["token"], "--state-dir", "/var/lib/ppanel-agent")
    sid = out.split("serverId=")[1].split()[0]
    start_agent(n)
    poll_get(f"/servers/{sid}", admin, lambda d: d["status"] == "online", 90)
    return sid


def deploy(admin, app_id, body):
    d = data("POST", f"/applications/{app_id}/deployments", admin, body, {"Idempotency-Key": str(uuid.uuid4())})
    return poll_get(f"/deployments/{d['deployment']['id']}", admin, lambda x: x["status"] in DEPLOY_DONE, 300)


def main():
    ev = Evidence("setup-fleet")
    stop_center()
    snapshot_center(force=True)
    t = start_center()
    ev.step("snapshot Center started", True, startSec=t)
    admin = login()

    # node-b reset (lab only; legacy sites untouched)
    ids = sh(*DIND, "ps", "-aq", "--filter", "label=ppanel.managed=true", check=False).split()
    if ids:
        sh(*DIND, "rm", "-f", *ids, check=False)
    node(NODE_B, "rm -rf /etc/nginx/ppanel-managed /etc/nginx/conf.d/ppanel-managed.conf && nginx -t -q && nginx -s reload")

    sa = enroll(admin, NODE_A, f"p7-node-a-{TAG}")
    sb = enroll(admin, NODE_B, f"p7-node-b-{TAG}")
    ev.step("node-a and node-b enrolled + online", True, nodeA=sa, nodeB=sb)

    # node-a: import + adopt static.example.lab
    sc = data("POST", f"/servers/{sa}/discovery-scans", admin, {})
    scan = poll_get(f"/discovery-scans/{sc['scanId']}", admin, lambda d: d["status"] != "running", 120)
    findings = call("GET", f"/discovery-scans/{scan['id']}/findings?limit=100", admin, expect=200)[1]["data"]
    target = next(x for x in findings if x["kind"] == "nginx_server" and "static.example.lab" in x.get("domains", []))
    app = data("POST", f"/discovery-scans/{scan['id']}/import", admin,
               {"findingIds": [target["id"]], "mode": "observed"})["applications"][0]
    cur = data("GET", f"/applications/{app['id']}", admin)
    data("POST", f"/applications/{app['id']}/ownership", admin,
         {"toMode": "adopted", "reason": "P7 chaos baseline", "acknowledgeReasons": True},
         {"If-Match": str(cur["version"])})
    files = data("GET", f"/applications/{app['id']}/nginx/files", admin)["files"]
    f0 = files[0]
    ev.step("node-a static.example.lab imported + adopted", True, appId=app["id"],
            path=f0.get("resolvedPath") or f0["path"])

    # node-b: managed routing + container app + compose app
    call("POST", f"/servers/{sb}/managed-routing", admin, expect=202)
    mr = poll_get(f"/servers/{sb}/managed-routing", admin, lambda x: x["enabled"] or x["status"] == "failed")
    img = images()
    wname, sname = f"p7web-{TAG}", f"p7stack-{TAG}"
    web = data("POST", "/applications", admin, {"serverId": sb, "name": wname, "environment": "uat",
                                                "domains": [f"{wname}.lab.test"], "containerPort": 8080,
                                                "healthcheck": {"path": "/healthz"}})
    d1 = deploy(admin, web["id"], {"image": img["PPANEL_LAB_IMAGE_WEB_V1"]})
    yaml = f"""services:
  db:
    image: {PG_IMG}
    environment:
      POSTGRES_USER: app
      POSTGRES_DB: app
      POSTGRES_PASSWORD: ${{DB_PASSWORD}}
    volumes:
      - pgdata:/var/lib/postgresql/data
  app:
    image: {img['PPANEL_LAB_IMAGE_WEB_V1']}
    depends_on: [db]
volumes:
  pgdata: {{}}
"""
    stack = data("POST", "/applications", admin, {"kind": "compose", "serverId": sb, "name": sname,
                                                  "environment": "uat", "domains": [f"{sname}.lab.test"],
                                                  "yaml": yaml, "routeService": "app", "routePort": 8080,
                                                  "healthPath": "/healthz"})
    call("PUT", f"/applications/{stack['id']}/secrets/DB_PASSWORD", admin, {"value": os.urandom(12).hex()}, expect=200)
    d2 = deploy(admin, stack["id"], {})
    codes = {h: site_code(NODE_B, h) for h in (f"{wname}.lab.test", f"{sname}.lab.test", "shop.b.lab")}
    codes.update({h: site_code(NODE_A, h) for h in ("static.example.lab", "api.example.lab", "php.example.lab")})
    ok = mr["enabled"] and d1["status"] == "succeeded" and d2["status"] == "succeeded" and all(
        c == "200" for c in codes.values())
    ev.step("node-b container + compose apps deployed; all sites 200", ok, managedRouting=mr["enabled"],
            web=d1["status"], stack=d2["status"], codes=codes, webBody=site_body(NODE_B, f"{wname}.lab.test")[:40])
    save_fleet({"tag": TAG, "nodeA": {"serverId": sa, "container": NODE_A, "appId": app["id"],
                                      "nginxPath": f0.get("resolvedPath") or f0["path"],
                                      "sites": ["static.example.lab", "api.example.lab", "php.example.lab"]},
                "nodeB": {"serverId": sb, "container": NODE_B, "webAppId": web["id"], "stackAppId": stack["id"],
                          "webDomain": f"{wname}.lab.test", "stackDomain": f"{sname}.lab.test",
                          "sites": [f"{wname}.lab.test", f"{sname}.lab.test", "shop.b.lab"]},
                "images": img})
    ev.summary()
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main_guard(main)
