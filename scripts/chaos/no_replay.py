#!/usr/bin/env python3
"""P7-T02 — destructive (mutating) jobs never silently replay after reconnect (lab only).

A. Jobs queued while the agent is DOWN, TTL expires, agent comes back:
   node-a: nginx.apply (approved revision) + service.restart (direct job, ttlSec=30);
   node-b: container.restart (POST /applications/:id/restart).
   The workflow jobs have a fixed 600 s TTL; instead of waiting 10 min we set `jobs.expires_at = now()`
   in the dev DB (documented shortcut — the sweeper then applies the real expiry path). service.restart
   expires naturally (ttlSec=30).
   Assert: status expired, never delivered after reconnect (agent log has no line for the jobId), host
   state unchanged (nginx config hash + master PID on node-a, container StartedAt on node-b).
B. Job LEASED by an agent that is then partitioned before ack (simulated with the node's own mTLS
   identity from Python while the real agent is stopped): lease expires → expired; late ack/result → 409
   TASK_EXPIRED; real agent restarted → job never re-delivered, container not restarted.
C. Job ACKED (running) and the agent then partitioned (no heartbeats renew the running lease):
   running lease expires → expired; a late `succeeded` result is rejected (409) and not stored.
D. Real agent SIGKILLed while a container.restart is running; agent restarted → the job is not re-run
   (exactly one "executing job" log line, container restarted at most once); final Center state recorded.
Run: python3 -I scripts/chaos/no_replay.py
"""
import json
import os
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (CHAOS, DIND, Approver, Evidence, call, data, fleet, job, job_get, login, main_guard,  # noqa: E402
                  nginx_hash, node, poll, poll_get, psql, sh, site_code, start_agent, stop_agent)

GW = "https://localhost:4443"
REV_DONE = {"valid", "invalid", "applied", "apply_failed", "reverted", "drift_blocked",
            "requires_manual_recovery", "cancelled", "awaiting_approval"}


class FakeAgent:
    """Speaks the gateway protocol with the node's real mTLS identity (copied from its state dir)."""

    def __init__(self, container):
        d = os.path.join(CHAOS, "ident-" + container)
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
        for f in ("agent.crt", "agent.key", "ca.crt"):
            sh("docker", "cp", f"{container}:/var/lib/ppanel-agent/{f}", os.path.join(d, f))
        os.chmod(os.path.join(d, "agent.key"), 0o600)
        self.ctx = ssl.create_default_context(cafile=os.path.join(d, "ca.crt"))
        self.ctx.load_cert_chain(os.path.join(d, "agent.crt"), os.path.join(d, "agent.key"))

    def req(self, method, path, body=None, timeout=40):
        r = urllib.request.Request(GW + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                   headers={"Content-Type": "application/json", "X-Agent-Protocol": "1"})
        try:
            with urllib.request.urlopen(r, context=self.ctx, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def lease(self, job_id, tries=6):
        for _ in range(tries):
            st, r = self.req("GET", "/agent/v1/tasks?waitSec=5")
            for g in (r.get("data") or {}).get("tasks") or []:
                if g["jobId"] == job_id:
                    return g
        return None


def container_state(name):
    out = sh(*DIND, "inspect", "-f", "{{.State.StartedAt}} {{.RestartCount}} {{.State.Status}}", name, check=False)
    return out


def agent_log_count(n, job_id, pattern="executing job"):
    return int(node(n, f"grep -F '{job_id}' /var/log/ppanel-agent.log | grep -c -F '{pattern}' || true") or 0)


def agent_log_lines(n, job_id):
    return node(n, f"grep -F '{job_id}' /var/log/ppanel-agent.log | tail -5 || true")


def main():
    fl = fleet()
    A, B = fl["nodeA"], fl["nodeB"]
    ev = Evidence("t02-no-replay", {"leaseSec": 60, "runningLeaseSec": 120, "sweepMs": 5000})
    admin = login()
    appr = Approver(admin, fl["tag"])
    web = data("GET", f"/applications/{B['webAppId']}", admin)
    cname = web["container"]["containerName"]

    # ---------------- A: queued while agent down → expired → never delivered
    files = data("GET", f"/applications/{A['appId']}/nginx/files", admin)["files"]
    f0 = files[0]
    path, content = f0.get("resolvedPath") or f0["path"], f0["content"]
    anchor = "    index index.html;"
    new = content.replace(anchor, anchor + "\n    location = /p7-t02 { return 200 'p7 t02'; }", 1)
    rv = data("POST", f"/applications/{A['appId']}/nginx/revisions", admin,
              {"files": [{"path": path, "content": new}],
               "postchecks": [{"hostHeader": "static.example.lab", "path": "/p7-t02", "expectStatus": [200]}]})
    data("POST", f"/nginx-revisions/{rv['id']}/validate", admin)
    r = poll_get(f"/nginx-revisions/{rv['id']}", admin, lambda d: d["status"] in REV_DONE)
    data("POST", f"/nginx-revisions/{rv['id']}/approve", appr.token, {"planHash": r["planHash"]},
         {"X-Step-Up": appr.step_up()})
    srv = data("GET", f"/servers/{A['serverId']}", admin)
    call("PATCH", f"/servers/{A['serverId']}", admin, {"ownedUnits": ["nginx.service"]},
         {"If-Match": str(srv["version"])}, expect=200)

    before = {"nodeA": {"nginx": nginx_hash(A["container"]), "pid": node(A["container"], "cat /run/nginx.pid")},
              "nodeB": container_state(cname)}
    stop_agent(A["container"])
    stop_agent(B["container"])
    t_stop = time.time()
    ap = data("POST", f"/nginx-revisions/{rv['id']}/apply", admin)
    apply_job = ap.get("jobId") or data("GET", f"/nginx-revisions/{rv['id']}", admin).get("applyJobId")
    svc_job = job(admin, A["serverId"], "service.restart", {"unit": "nginx.service"}, ttl=30)["jobId"]
    rs = data("POST", f"/applications/{B['webAppId']}/restart", admin)
    restart_job = rs["jobId"]
    queued = {"nginx.apply": job_get(admin, A["serverId"], apply_job)["status"],
              "service.restart": job_get(admin, A["serverId"], svc_job)["status"],
              "container.restart": job_get(admin, B["serverId"], restart_job)["status"]}
    ev.step("A: mutating jobs created while both agents are down → queued", all(v == "queued" for v in queued.values()),
            jobs={"nginx.apply": apply_job, "service.restart": svc_job, "container.restart": restart_job}, status=queued)
    time.sleep(36)
    psql(f"UPDATE jobs SET expires_at = now() WHERE id IN ('{apply_job}','{restart_job}') AND status='queued'")
    time.sleep(7)
    exp = {"nginx.apply": job_get(admin, A["serverId"], apply_job),
           "service.restart": job_get(admin, A["serverId"], svc_job),
           "container.restart": job_get(admin, B["serverId"], restart_job)}
    ev.step("A: TTL elapsed → all three expired (service.restart naturally after 30 s; workflow jobs via expires_at=now())",
            all(j["status"] == "expired" for j in exp.values()),
            status={k: (j["status"], (j.get("error") or {}).get("code")) for k, j in exp.items()})
    start_agent(A["container"])
    start_agent(B["container"])
    poll_get(f"/servers/{A['serverId']}", admin, lambda d: d["status"] == "online", 120)
    poll_get(f"/servers/{B['serverId']}", admin, lambda d: d["status"] == "online", 120)
    time.sleep(40)  # > one long-poll cycle after reconnect
    after = {"nodeA": {"nginx": nginx_hash(A["container"]), "pid": node(A["container"], "cat /run/nginx.pid")},
             "nodeB": container_state(cname)}
    exp2 = {"nginx.apply": job_get(admin, A["serverId"], apply_job),
            "service.restart": job_get(admin, A["serverId"], svc_job),
            "container.restart": job_get(admin, B["serverId"], restart_job)}
    logs = {"nginx.apply": agent_log_lines(A["container"], apply_job),
            "service.restart": agent_log_lines(A["container"], svc_job),
            "container.restart": agent_log_lines(B["container"], restart_job)}
    rev = data("GET", f"/nginx-revisions/{rv['id']}", admin)
    ok = (all(j["status"] == "expired" and (j.get("result") in (None, {}) or j.get("resultOnlyError")) for j in exp2.values())
          and not any(logs.values()) and before == after and site_code(A["container"], "static.example.lab", "/p7-t02") != "200")
    ev.step("A: after reconnect: still expired, never delivered, host state unchanged", ok,
            before=before, after=after, agentLogLinesForJobs=logs, revisionStatus=rev["status"],
            revisionError=rev.get("result") or rev.get("error"), downSec=round(time.time() - t_stop))
    if rev["status"] not in ("applied",):
        # leave the revision in a terminal state so later scenarios can create new ones
        call("POST", f"/nginx-revisions/{rv['id']}/cancel", admin)

    # ---------------- B: leased, never acked (partition after grant)
    stop_agent(B["container"])
    fake = FakeAgent(B["container"])
    before_b = container_state(cname)
    rs = data("POST", f"/applications/{B['webAppId']}/restart", admin)
    jb = rs["jobId"]
    g = fake.lease(jb)
    jl = job_get(admin, B["serverId"], jb)
    ev.step("B: grant leased by the (partitioned) agent identity, never acked", g is not None and jl["status"] == "leased",
            jobId=jb, status=jl["status"], leaseUntil=jl.get("leaseUntil"), grantExpiresAt=(g or {}).get("expiresAt"))
    t0 = time.time()
    jx = poll(lambda: (lambda j: j if j["status"] != "leased" else None)(job_get(admin, B["serverId"], jb)), 150, 1,
              "lease expiry")
    t_exp = round(time.time() - t0, 1)
    st_ack, ack = fake.req("POST", f"/agent/v1/tasks/{jb}/ack", {"leaseToken": g["leaseToken"]})
    st_res, res = fake.req("POST", f"/agent/v1/tasks/{jb}/result",
                           {"leaseToken": g["leaseToken"], "status": "succeeded", "output": {"late": True}})
    jx2 = job_get(admin, B["serverId"], jb)
    ev.step("B: lease expired → expired; late ack and late result rejected 409, nothing stored",
            jx["status"] == "expired" and st_ack == 409 and st_res == 409 and jx2["status"] == "expired"
            and not (jx2.get("result") or {}).get("late"),
            expiredAfterSec=t_exp, error=(jx.get("error") or {}).get("code"),
            lateAck=[st_ack, (ack.get("error") or {}).get("code")], lateResult=[st_res, (res.get("error") or {}).get("code")])

    # ---------------- C: acked (running), then partition → running lease expires → late result rejected
    rs = data("POST", f"/applications/{B['webAppId']}/restart", admin)
    jc = rs["jobId"]
    g2 = fake.lease(jc)
    st_a, _ = fake.req("POST", f"/agent/v1/tasks/{jc}/ack", {"leaseToken": g2["leaseToken"]})
    jr = job_get(admin, B["serverId"], jc)
    t0 = time.time()
    jy = poll(lambda: (lambda j: j if j["status"] != "running" else None)(job_get(admin, B["serverId"], jc)), 240, 2,
              "running lease expiry")
    t_run = round(time.time() - t0, 1)
    st_res2, res2 = fake.req("POST", f"/agent/v1/tasks/{jc}/result",
                             {"leaseToken": g2["leaseToken"], "status": "succeeded", "output": {"late": True}})
    jy2 = job_get(admin, B["serverId"], jc)
    ev.step("C: acked job whose agent vanished → running lease expires → expired; late success rejected",
            st_a == 200 and jr["status"] == "running" and jy["status"] == "expired" and st_res2 == 409
            and jy2["status"] == "expired", ackStatus=st_a, expiredAfterSec=t_run,
            error=(jy.get("error") or {}).get("code"), lateResult=[st_res2, (res2.get("error") or {}).get("code")])

    start_agent(B["container"])
    poll_get(f"/servers/{B['serverId']}", admin, lambda d: d["status"] == "online", 120)
    time.sleep(40)
    after_b = container_state(cname)
    ev.step("B/C: real agent back → expired jobs never re-delivered, container never restarted",
            before_b == after_b and not agent_log_lines(B["container"], jb) and not agent_log_lines(B["container"], jc),
            before=before_b, after=after_b)

    # ---------------- D: agent SIGKILLed while container.restart runs
    before_d = container_state(cname)
    rs = data("POST", f"/applications/{B['webAppId']}/restart", admin)
    jd = rs["jobId"]
    killed_at_status = None
    t0 = time.time()
    while time.time() - t0 < 60:
        s = job_get(admin, B["serverId"], jd)["status"]
        if s == "running":
            stop_agent(B["container"], "KILL")
            killed_at_status = s
            break
        if s in ("succeeded", "failed", "expired"):
            killed_at_status = s
            break
        time.sleep(0.05)
    t_kill = time.time()
    mid = container_state(cname)
    start_agent(B["container"])
    poll_get(f"/servers/{B['serverId']}", admin, lambda d: d["status"] == "online", 120)
    fin = poll(lambda: (lambda j: j if j["status"] in ("succeeded", "failed", "expired", "cancelled") else None)(
        job_get(admin, B["serverId"], jd)), 240, 2, "job D terminal")
    time.sleep(30)
    exec_lines = agent_log_count(B["container"], jd)
    after_d = container_state(cname)
    ev.step("D: agent killed mid-run → job not re-executed after restart (one execution, no second restart)",
            killed_at_status == "running" and exec_lines == 1 and mid.split()[0] == after_d.split()[0],
            jobId=jd, killedWhile=killed_at_status, terminalAfterSec=round(time.time() - t_kill - 30, 1),
            finalStatus=fin["status"], finalError=(fin.get("error") or {}).get("code"), executingLogLines=exec_lines,
            containerBefore=before_d, containerAtKill=mid, containerAfter=after_d,
            agentLog=agent_log_lines(B["container"], jd))
    ev.step("D: Center records the interruption as AGENT_INTERRUPTED",
            (fin.get("error") or {}).get("code") == "AGENT_INTERRUPTED",
            finalStatus=fin["status"], finalError=fin.get("error"),
            note="protocol: agent reports AGENT_INTERRUPTED only if the grant is re-delivered; mutating jobs are "
                 "never re-delivered, so the Center can only expire it")
    ev.put("siteCodes", {"static.example.lab": site_code(A["container"], "static.example.lab"),
                         B["webDomain"]: site_code(B["container"], B["webDomain"])})
    ev.summary()


if __name__ == "__main__":
    main_guard(main)
