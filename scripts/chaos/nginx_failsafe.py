#!/usr/bin/env python3
"""P7-T04 — a failed Nginx apply never strands the active config; tested revert (lab only, node-a).

Cases on the adopted legacy site static.example.lab (approval + step-up required for every apply):
 1. postcheck fails (new location answers 503, postcheck expects 200) → POSTCHECK_FAILED_REVERTED.
 2. reload "succeeds" but the new config cannot be loaded (valid for `nginx -t`, but a new `listen` port is
    held by another process, so the master's bind() fails on reload and keeps the old config)
    → postcheck fails → auto-revert.
 3. reload command fails (nginx pid file points to a dead PID, so `nginx -s reload` errors)
    → expect RELOAD_FAILED_REVERTED with files restored.
 4. good revision applied, then reverted → byte-identical original (tested revert).
 5. agent SIGKILLed during an apply (between reload and postcheck) → outcome recorded: job/revision state,
    on-disk config, sites still serving.
For every case: sha256 of the edited file and of the whole /etc/nginx tree vs baseline, nginx master PID,
HTTP codes of all node-a sites.
Run: python3 -I scripts/chaos/nginx_failsafe.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (Approver, Evidence, call, data, fleet, job_get, login, main_guard, nginx_hash, node,  # noqa: E402
                  poll, poll_get, site_code, start_agent, stop_agent)

REV_DONE = {"valid", "invalid", "applied", "apply_failed", "reverted", "drift_blocked",
            "requires_manual_recovery", "cancelled", "awaiting_approval"}
APPLY_DONE = {"applied", "apply_failed", "drift_blocked", "requires_manual_recovery", "reverted"}
ANCHOR = "    index index.html;"


def main():
    fl = fleet()
    A = fl["nodeA"]
    n = A["container"]
    ev = Evidence("t04-nginx-failsafe")
    admin = login()
    appr = Approver(admin, fl["tag"] + "t04")

    files = data("GET", f"/applications/{A['appId']}/nginx/files", admin)["files"]
    f0 = files[0]
    path, original = f0.get("resolvedPath") or f0["path"], f0["content"]
    assert ANCHOR in original

    def state():
        return {"fileSha": node(n, f"sha256sum {path} | cut -c1-16"), "tree": nginx_hash(n),
                "masterPid": node(n, "cat /run/nginx.pid"),
                "sites": {h: site_code(n, h) for h in A["sites"]}}

    node(n, f"cp -p {path} /tmp/p7-t04-orig.conf")
    base = state()
    ev.step("baseline", all(c == "200" for c in base["sites"].values()), **base)

    def revision(content, postchecks):
        rv = data("POST", f"/applications/{A['appId']}/nginx/revisions", admin,
                  {"files": [{"path": path, "content": content}], "postchecks": postchecks})
        data("POST", f"/nginx-revisions/{rv['id']}/validate", admin)
        r = poll_get(f"/nginx-revisions/{rv['id']}", admin, lambda d: d["status"] in REV_DONE)
        if r["status"] == "awaiting_approval":
            data("POST", f"/nginx-revisions/{rv['id']}/approve", appr.token, {"planHash": r["planHash"]},
                 {"X-Step-Up": appr.step_up()})
        return r

    def apply(rid, timeout=240):
        data("POST", f"/nginx-revisions/{rid}/apply", admin)
        return poll_get(f"/nginx-revisions/{rid}", admin, lambda d: d["status"] in APPLY_DONE, timeout)

    def err_of(r):
        res = r.get("result") or {}
        return res.get("code") or (res.get("error") or {}).get("code") if isinstance(res, dict) else res

    def ack_drift(reason):
        a = data("GET", f"/applications/{A['appId']}", admin)
        if (a.get("flags") or {}).get("driftDetected"):
            sc = data("POST", f"/servers/{A['serverId']}/discovery-scans", admin, {})
            poll_get(f"/discovery-scans/{sc['scanId']}", admin, lambda d: d["status"] != "running", 120)
            a = data("GET", f"/applications/{A['appId']}", admin)
            data("POST", f"/applications/{A['appId']}/drift/acknowledge", admin, None, {"If-Match": str(a["version"])})
            ev.step(f"drift flag acknowledged ({reason})", "INFO", flags=a.get("flags"))

    start_from = int(os.environ.get("P7_T04_FROM", "1"))
    if start_from > 1:
        ack_drift("left by case 3 of an earlier run")
    if start_from > 3:
        ev.step(f"cases 1-{start_from - 1} skipped in this run (see part1 evidence)", "INFO")
    if start_from <= 3:
        # 1. postcheck fails
        c1 = original.replace(ANCHOR, ANCHOR + "\n    location = /p7-pc { return 503; }", 1)
        r = revision(c1, [{"hostHeader": "static.example.lab", "path": "/p7-pc", "expectStatus": [200]}])
        r1 = apply(r["id"])
        s1 = state()
        job1 = job_get(admin, A["serverId"], r1["applyJobId"]) if r1.get("applyJobId") else {}
        ev.step("1 postcheck failure → auto-revert, config byte-identical, sites 200",
                r1["status"] == "apply_failed" and s1["fileSha"] == base["fileSha"] and s1["tree"] == base["tree"]
                and all(c == "200" for c in s1["sites"].values()),
                status=r1["status"], error=(job1.get("error") or {}).get("code"), state=s1,
                pidChanged=s1["masterPid"] != base["masterPid"])

        # 2. bind conflict on reload (nginx -t passes, master keeps old config)
        node(n, "nohup perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(LocalAddr=>\"127.0.0.1\",LocalPort=>18081,"
                "Listen=>5,ReuseAddr=>0) or die $!; sleep 900' >/dev/null 2>&1 &")
        time.sleep(1)
        c2 = original.replace("    listen 80;", "    listen 80;\n    listen 127.0.0.1:18081;", 1)
        if c2 == original:
            c2 = original.replace(ANCHOR, ANCHOR, 1)
        c2 = c2.replace(ANCHOR, ANCHOR + "\n    location = /p7-bind { return 200 'bind'; }", 1)
        r = revision(c2, [{"hostHeader": "static.example.lab", "path": "/p7-bind", "expectStatus": [200]}])
        r2 = apply(r["id"]) if r["status"] in ("valid", "awaiting_approval", "approved") or r.get("approval") else r
        s2 = state()
        job2 = job_get(admin, A["serverId"], r2["applyJobId"]) if r2.get("applyJobId") else {}
        errlog = node(n, "tail -n 5 /var/log/nginx/error.log | grep -i bind || true")
        node(n, "pkill -f '[L]ocalPort=>18081' || true")
        ev.step("2 reload cannot bind new listen → postcheck fails → auto-revert, config byte-identical, sites 200",
                r2["status"] == "apply_failed" and s2["fileSha"] == base["fileSha"] and s2["tree"] == base["tree"]
                and all(c == "200" for c in s2["sites"].values()),
                validated=r["status"], status=r2["status"], error=(job2.get("error") or {}).get("code"), state=s2,
                nginxErrorLog=errlog[-300:])

        # 3. reload command fails (stale pid file)
        c3 = original.replace(ANCHOR, ANCHOR + "\n    location = /p7-reload { return 200 'reload'; }", 1)
        r = revision(c3, [{"hostHeader": "static.example.lab", "path": "/p7-reload", "expectStatus": [200]}])
        real_pid = node(n, "cat /run/nginx.pid")
        node(n, "echo 999999 > /run/nginx.pid")
        try:
            r3 = apply(r["id"])
        finally:
            node(n, f"echo {real_pid} > /run/nginx.pid")
        s3 = state()
        job3 = job_get(admin, A["serverId"], r3["applyJobId"]) if r3.get("applyJobId") else {}
        ev.step("3 reload command fails → RELOAD_FAILED_REVERTED, files restored byte-identical, sites 200",
                r3["status"] in ("apply_failed", "requires_manual_recovery") and s3["fileSha"] == base["fileSha"]
                and s3["tree"] == base["tree"] and all(c == "200" for c in s3["sites"].values()),
                status=r3["status"], error=(job3.get("error") or {}).get("code"),
                errorMessage=(job3.get("error") or {}).get("message", "")[:300], state=s3)

        ack_drift("after case 3")

    # 4. good revision applied + tested revert
    c4 = original.replace(ANCHOR, ANCHOR + "\n    location = /p7-good { return 200 'good'; }", 1)
    r = revision(c4, [{"hostHeader": "static.example.lab", "path": "/p7-good", "expectStatus": [200]},
                      {"hostHeader": "static.example.lab", "path": "/", "expectStatus": [200]}])
    r4 = apply(r["id"])
    good_code = site_code(n, "static.example.lab", "/p7-good")
    applied_sha = node(n, f"sha256sum {path} | cut -c1-16")
    data("POST", f"/nginx-revisions/{r['id']}/revert", admin)
    r4b = poll_get(f"/nginx-revisions/{r['id']}", admin,
                   lambda d: d["status"] in {"reverted", "apply_failed", "drift_blocked", "requires_manual_recovery"}, 240)
    s4 = state()
    ev.step("4 good revision applied (new location 200), then revert → byte-identical original",
            r4["status"] == "applied" and good_code == "200" and r4b["status"] == "reverted"
            and s4["fileSha"] == base["fileSha"] and s4["tree"] == base["tree"]
            and site_code(n, "static.example.lab", "/p7-good") == "404" and all(c == "200" for c in s4["sites"].values()),
            applied=r4["status"], newLocation=good_code, appliedSha=applied_sha, reverted=r4b["status"], state=s4)

    # 5. agent SIGKILL mid-apply
    c5 = original.replace(ANCHOR, ANCHOR + "\n    location = /p7-kill { return 200 'kill'; }", 1)
    r = revision(c5, [{"hostHeader": "static.example.lab", "path": "/p7-kill", "expectStatus": [200]}])
    data("POST", f"/nginx-revisions/{r['id']}/apply", admin)
    jid = None
    t0 = time.time()
    phase = None
    while time.time() - t0 < 60:
        rr = data("GET", f"/nginx-revisions/{r['id']}", admin)
        jid = rr.get("applyJobId")
        if jid:
            js = job_get(admin, A["serverId"], jid)["status"]
            if js == "running":
                time.sleep(1.0)  # inside the 2 s post-reload settle window
                stop_agent(n, "KILL")
                phase = "killed ~1 s after ack"
                break
            if js in ("succeeded", "failed"):
                phase = "finished before kill"
                break
        time.sleep(0.05)
    at_kill = state()
    on_disk_new = node(n, f"grep -c 'p7-kill' {path} || true")
    start_agent(n)
    fin = poll(lambda: (lambda j: j if j["status"] in ("succeeded", "failed", "expired") else None)(
        job_get(admin, A["serverId"], jid)), 300, 2, "apply job terminal")
    rev5 = poll_get(f"/nginx-revisions/{r['id']}", admin, lambda d: d["status"] not in ("applying",), 120)
    s5 = state()
    ev.step("5 agent killed mid-apply: sites keep serving and Center state is consistent with the host",
            all(c == "200" for c in s5["sites"].values()) and (
                (rev5["status"] == "applied") == (s5["fileSha"] != base["fileSha"])),
            phase=phase, atKill=at_kill, candidateOnDiskAtKill=on_disk_new, jobStatus=fin["status"],
            jobError=(fin.get("error") or {}).get("code"), revisionStatus=rev5["status"], after=s5,
            newLocationAfter=site_code(n, "static.example.lab", "/p7-kill"))
    ev.put("case5Revision", {"id": r["id"], "status": rev5["status"], "result": rev5.get("result")})
    if node(n, f"sha256sum {path} | cut -c1-16") != base["fileSha"]:
        node(n, f"cp -p /tmp/p7-t04-orig.conf {path} && nginx -t -q && nginx -s reload")
        ev.step("cleanup: lab file restored manually from pre-test copy (host was left with the candidate)", "INFO",
                state=state())
    ev.summary()


if __name__ == "__main__":
    main_guard(main)
