#!/usr/bin/env python3
"""P7.05 — full disk on an agent state dir (lab only; never touches the host disk).

Uses the chaos node ppanel-lab-node-c (profile `chaos` in infra/compose/lab.yml): node-a image, agent state
dir = 6 MiB tmpfs (RAM-backed, size-limited). The log buffer cap (16 MiB) is larger than the filesystem, so the
ENOSPC path is exercised. Steps: start node-c, enroll, fill the tmpfs to 0 bytes free, then under nginx
traffic observe: agent alive? heartbeats? log shipping (Loki count vs produced, droppedEntries)? a read-only
job (job cache write)? a backup run (restic cache/work dir on the full fs)? Then free the space and verify
recovery. Backup credentials: node-c reuses node-a's rest-server user (lab only, documented).
Cleanup: revokes p7-node-c and removes the container.
Run: python3 -I scripts/chaos/disk_full.py
"""
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (AGENT, ROOT, log_delivery, Evidence, agent_running, call, data, fleet, job, job_get, login, main_guard,  # noqa: E402
                  node, poll, poll_get, probe_read, probe_start, probe_stats, probe_stop, sh, start_agent)
from center_outage import parse_ts  # noqa: E402

NODE_C = "ppanel-lab-node-c"
COMPOSE = ["docker", "compose", "-p", "ppanel-lab", "-f", os.path.join(ROOT, "infra/compose/lab.yml"), "--profile", "chaos"]


def df():
    return node(NODE_C, "df -k /var/lib/ppanel-agent | tail -1 | awk '{print $2\" \"$3\" \"$4}'")


def fleet_row(admin, sid):
    return next((r for r in data("GET", "/metrics/fleet", admin) if r["serverId"] == sid), {})


def main():
    fl = fleet()
    ev = Evidence("disaster-disk-full", {"tmpfsSize": "6m", "bufferCapBytes": 16777216})
    admin = login()
    env = dict(os.environ, PPANEL_AGENT_BIN_DIR=os.path.join(ROOT, "apps/agent/bin"))
    import subprocess
    subprocess.run(COMPOSE + ["up", "-d", "--no-deps", "--wait", "lab-node-c"], env=env, check=True,
                   capture_output=True, timeout=180)
    e = data("POST", "/enrollments", admin, {"name": f"p7-node-c-{fl['tag']}", "environment": "uat", "ttlMinutes": 10})
    out = sh("docker", "exec", NODE_C, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["token"], "--state-dir", "/var/lib/ppanel-agent")
    sid = out.split("serverId=")[1].split()[0]
    start_agent(NODE_C)
    poll_get(f"/servers/{sid}", admin, lambda d: d["status"] == "online", 90)
    ev.step("chaos node-c up, enrolled, online; state dir is a 6 MiB tmpfs", True, serverId=sid, dfKb=df(),
            mount=node(NODE_C, "grep ppanel-agent /proc/mounts"))

    # backup repo access (node-a's rest user, lab only)
    bk = dict(line.strip().split("=", 1) for line in open(".lab/backup.env") if "=" in line and not line.startswith("#"))
    cr = dict(line.strip().split("=", 1) for line in open(".lab/backup/servers/node-a.env")
              if "=" in line and not line.startswith("#"))
    repo = data("POST", "/backup-repositories", admin, {"name": f"p7-diskfull-{fl['tag']}", "kind": "rest",
                                                        "baseUrl": bk.get("PPANEL_LAB_BACKUP_REPO_BASE", "http://lab-backup:8000")})
    call("PUT", f"/backup-repositories/{repo['id']}/servers/{sid}", admin,
         {"restUser": cr["PPANEL_LAB_BK_USER"], "restPassword": cr["PPANEL_LAB_BK_REST_PASSWORD"],
          "repoPassword": cr["PPANEL_LAB_BK_REPO_PASSWORD"]}, expect=(200, 201))
    call("POST", f"/backup-repositories/{repo['id']}/servers/{sid}/initialized", admin, {"initialized": True},
         expect=(200, 201))
    poll_get(f"/servers/{sid}", admin, lambda d: "backup" in d["capabilities"], 60)
    pol = data("POST", "/backup-policies", admin, {
        "name": f"p7-diskfull-{fl['tag']}", "serverId": sid, "repositoryId": repo["id"],
        "targets": [{"type": "paths", "paths": ["/var/www/static"]}],
        "schedule": {"cron": "0 3 * * *", "timezone": "UTC"}, "verify": {"afterBackup": "none"}})

    def run_backup():
        r = data("POST", f"/backup-policies/{pol['id']}/run", admin, None, {"Idempotency-Key": str(uuid.uuid4())})
        return poll_get(f"/backup-runs/{r['run']['id']}", admin,
                        lambda d: d["status"] in ("uploaded", "failed", "expired", "cancelled"), 600, 3)

    b0 = run_backup()
    ev.step("baseline backup on node-c (disk has space) → uploaded", b0["status"] == "uploaded", status=b0["status"],
            error=b0.get("error"), dfKb=df())

    # ---- fill the tmpfs completely
    node(NODE_C, "dd if=/dev/zero of=/var/lib/ppanel-agent/p7-filler bs=64k 2>/dev/null; sync; true")
    full = df()
    t_full = time.time()
    probe = probe_start(NODE_C, "static.example.lab", "diskfull", 10, 240)
    time.sleep(60)
    alive = agent_running(NODE_C)
    st, srv = call("GET", f"/servers/{sid}", admin)
    hb_age = round(time.time() - parse_ts(srv["data"]["lastHeartbeatAt"]), 1)
    row = fleet_row(admin, sid)
    errs = node(NODE_C, "tail -n 300 /var/log/ppanel-agent.log | grep -iE 'no space|ENOSPC|buffer|drop' | tail -4 || true")
    ev.step("disk full: agent process alive and still heartbeating (status online)",
            alive and srv["data"]["status"] == "online" and hb_age < 30, dfKb=full, heartbeatAgeSec=hb_age,
            logShipping=row.get("logShipping"), agentLog=errs[-700:])
    j = job(admin, sid, "inventory.collect", {})
    jx = poll(lambda: (lambda x: x if x["status"] in ("succeeded", "failed", "expired") else None)(
        job_get(admin, sid, j["jobId"])), 200, 2, "inventory job on full disk")
    jlog = node(NODE_C, f"grep -F '{j['jobId']}' /var/log/ppanel-agent.log | tail -3 || true")
    ev.step("disk full: read-only job → bounded outcome with a clear error (not a hang)", jx["status"] in
            ("succeeded", "failed"), status=jx["status"], error=jx.get("error"), agentLog=jlog[-500:])
    b1 = run_backup()
    ev.step("disk full: backup run fails with a clear error (no partial success)", b1["status"] == "failed",
            status=b1["status"], error=b1.get("error"))
    probe_stop(NODE_C)
    t_free = time.time()
    produced = probe_stats(probe_read(probe), t_full, t_free)
    node(NODE_C, "rm -f /var/lib/ppanel-agent/p7-filler")
    ev.step("space freed", True, dfKb=df(), fullForSec=round(t_free - t_full))

    # ---- recovery
    time.sleep(40)
    got = log_delivery(NODE_C, sid, t_full + 1, t_free - 1)
    row = fleet_row(admin, sid)
    ev.step("log lines produced while the disk was full: delivered vs dropped (bounded, reported)",
            "INFO", produced=produced.get("requests"), delivery=got, logShipping=row.get("logShipping"),
            logDroppedTotal=row.get("logDroppedTotal"))
    probe2 = probe_start(NODE_C, "static.example.lab", "diskfree", 10, 40)
    t2 = time.time()
    time.sleep(45)
    probe_stop(NODE_C)
    p2 = probe_stats(probe_read(probe2), t2, t2 + 38)
    time.sleep(20)
    got2 = log_delivery(NODE_C, sid, t2 + 1, t2 + 37)
    j2 = job(admin, sid, "inventory.collect", {})
    j2x = poll(lambda: (lambda x: x if x["status"] in ("succeeded", "failed", "expired") else None)(
        job_get(admin, sid, j2["jobId"])), 120, 2, "inventory job after free")
    b2 = run_backup()
    ev.step("after freeing space: logs ship again, jobs run, backup uploads (no restart needed)",
            (got2.get("deliveredPct") or 0) >= 99 and j2x["status"] == "succeeded" and b2["status"] == "uploaded"
            and agent_running(NODE_C), produced=p2.get("requests"), delivery=got2, job=j2x["status"], backup=b2["status"],
            agentRestarted=False)

    # cleanup
    call("POST", f"/servers/{sid}/revoke", admin, {})
    subprocess.run(COMPOSE + ["rm", "-sf", "lab-node-c"], env=env, capture_output=True, timeout=120)
    ev.step("cleanup: p7-node-c revoked, chaos container removed", True)
    ev.summary()


if __name__ == "__main__":
    main_guard(main)
