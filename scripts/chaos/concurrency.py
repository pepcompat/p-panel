#!/usr/bin/env python3
"""P7.04 — deploy / approval concurrency, lock contention, expired approvals, webhook storm (lab only).

1. Two admins deploy the same app at the same instant (and a 10-way burst): exactly one 202,
   the rest 409 DEPLOYMENT_IN_PROGRESS (or a preflight-failed record carrying it).
2. Nginx: 5 concurrent revision creates on one app → one 201, rest 409 REVISION_IN_PROGRESS;
   two apps on the same server applied concurrently → both succeed, executions never overlap
   (Center lock nginx:<serverId> + agent mutex), measured from job timestamps.
3. Two approvers approve the same plan concurrently → exactly one 200 (single-use approval);
   one approval used by two concurrent applies → exactly one job.
4. Approval expiry: approval rows aged in the dev DB (`approved_at`/`expires_at` moved 61 min back —
   TTL is a 60-min constant, not configurable) → apply refused.
5. Webhook storm: 50 concurrent signed deliveries for 5 commits (10 distinct deliveries per commit)
   → deployments created per commit counted.
Run: python3 -I scripts/chaos/concurrency.py
"""
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (API, Approver, Evidence, call, data, fleet, http, job_get, login, main_guard, node,  # noqa: E402
                  poll_get, psql, psql_rows, sh, site_body)

REV_DONE = {"valid", "invalid", "applied", "apply_failed", "reverted", "drift_blocked",
            "requires_manual_recovery", "cancelled", "awaiting_approval"}
DEPLOY_DONE = {"succeeded", "failed", "rolled_back", "requires_manual_recovery", "cancelled", "expired",
               "awaiting_approval"}
ANCHOR = "    index index.html;"


def burst(fns):
    """Run callables at (nearly) the same instant; returns their results in order."""
    out = [None] * len(fns)
    gate = threading.Barrier(len(fns))

    def run(i, f):
        gate.wait()
        out[i] = f()
    ts = [threading.Thread(target=run, args=(i, f)) for i, f in enumerate(fns)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


def code(r):
    return (r[1].get("error") or {}).get("code") if isinstance(r[1], dict) else None


def main():
    fl = fleet()
    A, B = fl["nodeA"], fl["nodeB"]
    img = fl["images"]
    ev = Evidence("concurrency")
    admin = login()
    ap1 = Approver(admin, fl["tag"] + "c1")
    ap2 = Approver(admin, fl["tag"] + "c2")

    # ------------------------------------------------ 1. two admins deploy the same app
    def dep(tok, image):
        return lambda: call("POST", f"/applications/{B['webAppId']}/deployments", tok, {"image": image},
                            {"Idempotency-Key": str(uuid.uuid4())})
    res = burst([dep(admin, img["PPANEL_LAB_IMAGE_WEB_V2"]), dep(ap1.token, img["PPANEL_LAB_IMAGE_WEB_V2"])])
    statuses = [(r[0], code(r), ((r[1].get("data") or {}).get("deployment") or {}).get("status")) for r in res]
    winners = [r for r in res if r[0] == 202 and ((r[1].get("data") or {}).get("deployment") or {}).get("status")
               not in ("failed",)]
    for r in res:
        d = (r[1].get("data") or {}).get("deployment")
        if d:
            poll_get(f"/deployments/{d['id']}", admin, lambda x: x["status"] in DEPLOY_DONE, 300)
    ev.step("1a two admins deploy same app simultaneously → exactly one proceeds, other DEPLOYMENT_IN_PROGRESS",
            len(winners) == 1 and any(c == "DEPLOYMENT_IN_PROGRESS" or s == "failed" for _, c, s in statuses),
            responses=statuses)
    res = burst([dep(admin if i % 2 else ap1.token, img["PPANEL_LAB_IMAGE_WEB_V1"]) for i in range(10)])
    statuses = [(r[0], code(r), ((r[1].get("data") or {}).get("deployment") or {}).get("status")) for r in res]
    proceeding = [r for r in res if r[0] == 202 and ((r[1].get("data") or {}).get("deployment") or {}).get("status")
                  != "failed"]
    for r in proceeding:
        poll_get(f"/deployments/{r[1]['data']['deployment']['id']}", admin, lambda x: x["status"] in DEPLOY_DONE, 300)
    counts = {}
    for s in statuses:
        counts[f"{s[0]}:{s[1] or s[2]}"] = counts.get(f"{s[0]}:{s[1] or s[2]}", 0) + 1
    ev.step("1b 10 concurrent deploys of one app → exactly one proceeds", len(proceeding) == 1, counts=counts,
            servingAfter=site_body(B["container"], B["webDomain"])[:30])

    # ------------------------------------------------ 2. nginx revision contention
    files = data("GET", f"/applications/{A['appId']}/nginx/files", admin)["files"]
    f0 = files[0]
    path, original = f0.get("resolvedPath") or f0["path"], f0["content"]

    def mk(i):
        c = original.replace(ANCHOR, ANCHOR + f"\n    location = /p7-c{i} {{ return 200 'c{i}'; }}", 1)
        return lambda: call("POST", f"/applications/{A['appId']}/nginx/revisions", admin,
                            {"files": [{"path": path, "content": c}],
                             "postchecks": [{"hostHeader": "static.example.lab", "path": f"/p7-c{i}",
                                             "expectStatus": [200]}]})
    res = burst([mk(i) for i in range(5)])
    created = [r for r in res if r[0] == 201]
    ev.step("2a 5 concurrent revision creates on one app → exactly one 201, rest 409 REVISION_IN_PROGRESS",
            len(created) == 1 and all(code(r) == "REVISION_IN_PROGRESS" for r in res if r[0] != 201),
            responses=[(r[0], code(r)) for r in res])
    rev1 = created[0][1]["data"] if created else None

    # second adopted app on the same server (api.example.lab)
    sc = data("POST", f"/servers/{A['serverId']}/discovery-scans", admin, {})
    scan = poll_get(f"/discovery-scans/{sc['scanId']}", admin, lambda d: d["status"] != "running", 120)
    finds = call("GET", f"/discovery-scans/{scan['id']}/findings?limit=100", admin, expect=200)[1]["data"]
    tgt = next(x for x in finds if x["kind"] == "nginx_server" and "api.example.lab" in x.get("domains", []))
    st, im = call("POST", f"/discovery-scans/{scan['id']}/import", admin, {"findingIds": [tgt["id"]], "mode": "observed"})
    app2 = (im.get("data") or {}).get("applications", [None])[0]
    if not app2:  # already imported by an earlier run
        apps = call("GET", f"/applications?server_id={A['serverId']}&limit=100", admin)[1].get("data") or []
        app2 = next(a for a in apps if "api.example.lab" in (a.get("domains") or []))
    cur = data("GET", f"/applications/{app2['id']}", admin)
    if cur["ownershipMode"] == "observed":
        data("POST", f"/applications/{app2['id']}/ownership", admin,
             {"toMode": "adopted", "reason": "P7 concurrency", "acknowledgeReasons": True},
             {"If-Match": str(cur["version"])})
    f2 = data("GET", f"/applications/{app2['id']}/nginx/files", admin)["files"][0]
    path2, orig2 = f2.get("resolvedPath") or f2["path"], f2["content"]
    anchor2 = "    server_name api.example.lab;"
    c2 = orig2.replace(anchor2, anchor2 + "\n    location = /p7-c2app { return 200 'c2'; }", 1)
    rev2 = data("POST", f"/applications/{app2['id']}/nginx/revisions", admin,
                {"files": [{"path": path2, "content": c2}],
                 "postchecks": [{"hostHeader": "api.example.lab", "path": "/p7-c2app", "expectStatus": [200]}]})
    for rv in (rev1, rev2):
        data("POST", f"/nginx-revisions/{rv['id']}/validate", admin)
    r1 = poll_get(f"/nginx-revisions/{rev1['id']}", admin, lambda d: d["status"] in REV_DONE)
    r2 = poll_get(f"/nginx-revisions/{rev2['id']}", admin, lambda d: d["status"] in REV_DONE)

    # ------------------------------------------------ 3. concurrent approvals of the same plan
    su1, su2 = ap1.step_up(), ap2.step_up()
    res = burst([lambda: call("POST", f"/nginx-revisions/{rev1['id']}/approve", ap1.token, {"planHash": r1["planHash"]},
                              {"X-Step-Up": su1}),
                 lambda: call("POST", f"/nginx-revisions/{rev1['id']}/approve", ap2.token, {"planHash": r1["planHash"]},
                              {"X-Step-Up": su2})])
    oks = [r for r in res if r[0] == 200]
    approvals = psql_rows(f"select approver_id, used_at is not null from nginx_revision_approvals where revision_id='{rev1['id']}'")
    ev.step("3a two approvers approve the same plan concurrently → exactly one approval recorded",
            len(oks) == 1 and len(approvals) == 1, responses=[(r[0], code(r)) for r in res], approvalRows=len(approvals))
    data("POST", f"/nginx-revisions/{rev2['id']}/approve", ap2.token, {"planHash": r2["planHash"]},
         {"X-Step-Up": ap2.step_up()})

    # one approval, two concurrent applies of rev1 + concurrent apply of rev2 (same server)
    res = burst([lambda: call("POST", f"/nginx-revisions/{rev1['id']}/apply", admin),
                 lambda: call("POST", f"/nginx-revisions/{rev1['id']}/apply", ap1.token),
                 lambda: call("POST", f"/nginx-revisions/{rev2['id']}/apply", admin)])
    a1 = poll_get(f"/nginx-revisions/{rev1['id']}", admin, lambda d: d["status"] in REV_DONE - {"valid"}, 240)
    a2 = poll_get(f"/nginx-revisions/{rev2['id']}", admin, lambda d: d["status"] in REV_DONE - {"valid"}, 240)
    jobs = psql_rows(f"select id, type, status, leased_at, finished_at, params->>'revisionId' from jobs where server_id='{A['serverId']}'"
                     f" and type='nginx.apply' and params->>'revisionId' in ('{rev1['id']}','{rev2['id']}') order by leased_at")
    overlap = None
    if len(jobs) == 2 and all(j[3] and j[4] for j in jobs):
        overlap = jobs[1][3] < jobs[0][4]
    ev.step("3b one approval → exactly one apply job for rev1 (single-use); two apps on one server apply "
            "without overlapping executions", sum(1 for j in jobs if j[5] == rev1["id"]) == 1 and overlap is False
            and a1["status"] == "applied" and a2["status"] == "applied",
            applyResponses=[(r[0], code(r)) for r in res], rev1=a1["status"], rev2=a2["status"], jobs=jobs,
            overlap=overlap)
    # put both files back (revert, tested path)
    for rv in (rev1, rev2):
        data("POST", f"/nginx-revisions/{rv['id']}/revert", admin)
    for rv in (rev1, rev2):
        poll_get(f"/nginx-revisions/{rv['id']}", admin, lambda d: d["status"] in {"reverted", "apply_failed",
                                                                                 "requires_manual_recovery"}, 240)

    # ------------------------------------------------ 4. approval expiry
    c4 = original.replace(ANCHOR, ANCHOR + "\n    location = /p7-exp { return 200 'exp'; }", 1)
    rv4 = data("POST", f"/applications/{A['appId']}/nginx/revisions", admin, {"files": [{"path": path, "content": c4}]})
    data("POST", f"/nginx-revisions/{rv4['id']}/validate", admin)
    r4 = poll_get(f"/nginx-revisions/{rv4['id']}", admin, lambda d: d["status"] in REV_DONE)
    data("POST", f"/nginx-revisions/{rv4['id']}/approve", ap1.token, {"planHash": r4["planHash"]},
         {"X-Step-Up": ap1.step_up()})
    psql(f"UPDATE nginx_revision_approvals SET approved_at = now() - interval '61 minutes', "
         f"expires_at = now() - interval '1 minute' WHERE revision_id='{rv4['id']}'")
    psql(f"UPDATE nginx_config_revisions SET updated_at = updated_at WHERE id='{rv4['id']}'")
    st, d = call("POST", f"/nginx-revisions/{rv4['id']}/apply", admin)
    view = data("GET", f"/nginx-revisions/{rv4['id']}", admin)
    jobs4 = psql(f"select count(*) from jobs where type='nginx.apply' and params->>'revisionId'='{rv4['id']}'")
    ev.step("4 expired approval (aged in DB) → apply refused, no job", st in (409, 403) and jobs4 == "0",
            http=st, code=code((st, d)), revisionStatus=view["status"], approval=view.get("approval"),
            method="UPDATE nginx_revision_approvals SET approved_at=now()-61min, expires_at=now()-1min")
    call("POST", f"/nginx-revisions/{rv4['id']}/cancel", admin)

    # ------------------------------------------------ 5. webhook storm: 50 deliveries, 5 commits
    secret = os.urandom(20).hex()
    ig = data("POST", "/integrations/github", admin, {"name": f"p7-storm-{fl['tag']}", "webhookSecret": secret})
    reg = "127.0.0.1:55000"
    shas = [hashlib.sha1(f"p7storm-{fl['tag']}-{i}-{time.time()}".encode()).hexdigest() for i in range(5)]
    src = img["PPANEL_LAB_IMAGE_WEB_V1"]
    sh("docker", "pull", "-q", src)
    for i, s in enumerate(shas):
        sh("docker", "tag", src, f"{reg}/ppanel-test/web:sha-{s[:7]}")
        sh("docker", "push", "-q", f"{reg}/ppanel-test/web:sha-{s[:7]}")
    pol = data("POST", f"/applications/{B['webAppId']}/auto-deploy", admin,
               {"integrationId": ig["id"], "repo": "lab-org/p7storm", "branches": ["main"],
                "imageTemplate": f"{reg}/ppanel-test/web:sha-{{sha7}}", "enabled": True})
    deps_before = set(x[0] for x in psql_rows(f"select id from deployments where application_id='{B['webAppId']}'"))

    def hook(s):
        payload = json.dumps({"ref": "refs/heads/main", "after": s, "repository": {"full_name": "lab-org/p7storm"}}).encode()
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        hdr = {"X-GitHub-Event": "push", "X-GitHub-Delivery": str(uuid.uuid4()), "X-Hub-Signature-256": sig,
               "X-Request-ID": str(uuid.uuid4())}
        return lambda: http("POST", f"{API}/webhooks/github/{ig['id']}", None, hdr, payload)
    t0 = time.time()
    res = burst([hook(shas[i % 5]) for i in range(50)])
    storm_sec = round(time.time() - t0, 2)
    results = {}
    for r in res:
        try:
            d = json.loads(r[1]).get("data") or {}
        except ValueError:
            d = {}
        k = f"{r[0]}:{d.get('result') or (json.loads(r[1]).get('error') or {}).get('code') if r[1] else r[0]}"
        results[k] = results.get(k, 0) + 1
    time.sleep(5)
    new = psql_rows(f"select id, status, commit_sha, trigger from deployments where application_id='{B['webAppId']}'"
                    " order by created_at")
    new = [x for x in new if x[0] not in deps_before]
    per_commit = {s[:7]: sum(1 for x in new if x[2] == s) for s in shas}
    deliveries = psql_rows(f"select result, count(*) from webhook_deliveries where integration_id='{ig['id']}' group by result")
    # wait for the storm's deployments to settle
    for x in new:
        poll_get(f"/deployments/{x[0]}", admin, lambda d: d["status"] in DEPLOY_DONE, 400)
    final = psql_rows(f"select status, count(*) from deployments where id in ('" + "','".join(x[0] for x in new) +
                      "') group by status") if new else []
    ev.step("5 webhook storm: 50 concurrent deliveries for 5 commits → exactly one deployment per commit",
            len(new) == 5 and all(v == 1 for v in per_commit.values()), stormSec=storm_sec, httpResults=results,
            deploymentsCreated=len(new), perCommit=per_commit, deliveryResults=deliveries, finalStatuses=final)
    succeeded = [x for x in psql_rows("select status from deployments where id in ('" + "','".join(x[0] for x in new) + "')")
                 if x[0] == "succeeded"] if new else []
    ev.step("5b storm deployments: how many actually ran vs refused by the app lock", "INFO",
            succeeded=len(succeeded), total=len(new),
            note="commits arriving while another deployment of the app is active hit DEPLOYMENT_IN_PROGRESS")
    call("PATCH", f"/applications/{B['webAppId']}/auto-deploy/{pol['id']}", admin, {"enabled": False},
         {"If-Match": str(pol.get("version", 1))})
    ev.put("nodeBServing", site_body(B["container"], B["webDomain"])[:40])
    ev.summary()


if __name__ == "__main__":
    main_guard(main)
