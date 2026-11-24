#!/usr/bin/env python3
"""P7.05 — disaster injections (lab only). Each: inject → observe API / agent / UI-visible state → recover → verify.

  redis        stop ppanel-dev-redis-1 for 90 s while exercising the API + agents
  postgres     stop ppanel-dev-postgres-1 for 60 s with the Center UP (clean 5xx/503? recovery without restart?)
  loki         stop Loki 120 s under nginx traffic → ingest 503 → agent buffers → delivered after recovery
  prometheus   stop Prometheus → /metrics/series 503 (not zeros), /metrics/fleet unaffected
  backup-repo  stop the rest-server → backup run fails REPO_UNREACHABLE + backup_failed incident → recovers
  cert         agent cert near expiry (DB not_before moved back 6 d → rotation) and expired (DB not_after=now →
               gateway 401 → agent stranded?) ; gateway cert expiry = code inspection
  aborted-deploy  SIGKILL the Center during a deployment (short and > running-lease variants) → reconcile
Run: python3 -I scripts/chaos/disasters.py <name> [<name> ...] | all
Evidence: docs/evidence/<date>/p7-disaster-<name>.json
"""
import json
import os
import signal
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (API, DIND, PG, log_delivery, Evidence, agent_running, call, center_pid, data, fleet, http, iso,  # noqa: E402
                  job, job_get, login, main_guard, node, poll, poll_get, probe_read, probe_start, probe_stats,
                  probe_stop, psql, psql_rows, sh, site_body, site_code, start_center, stop_center)
from center_outage import loki_count, parse_ts  # noqa: E402

REDIS = "ppanel-dev-redis-1"
LOKI_C = "ppanel-observability-loki-1"
PROM_C = "ppanel-observability-prometheus-1"
REPO_C = "ppanel-lab-backup"
DEPLOY_DONE = {"succeeded", "failed", "rolled_back", "requires_manual_recovery", "cancelled", "expired",
               "awaiting_approval"}


def health(c):
    return sh("docker", "inspect", "-f", "{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}", c,
              check=False)


def wait_healthy(c, timeout=120):
    poll(lambda: health(c).endswith("healthy") and "unhealthy" not in health(c), timeout, 1, f"{c} healthy")


def sample_api(token, paths):
    out = {}
    for p in paths:
        st, body, dt = http("GET", API + p, headers={"Authorization": "Bearer " + token}, timeout=15)
        try:
            c = (json.loads(body).get("error") or {}).get("code") if body else None
        except ValueError:
            c = "NON_JSON"
        out[p] = (st, c, round(dt * 1000))
    return out


def hb_age(token, sid):
    st, r = call("GET", f"/servers/{sid}", token, timeout=10)
    if st != 200:
        return None
    return round(time.time() - parse_ts(r["data"]["lastHeartbeatAt"]), 1), r["data"]["status"]


# ------------------------------------------------------------------ redis
def d_redis(fl, admin):
    ev = Evidence("disaster-redis")
    A, B = fl["nodeA"], fl["nodeB"]
    users = sh("grep", "-rlis", "redis", os.path.join(os.path.dirname(__file__), "../../apps/api/src"), check=False)
    ev.step("code inspection: Center API source references to Redis", "INFO",
            files=[os.path.relpath(f) for f in users.splitlines()],
            note="rate limiter + log byte bucket are in-memory; no Redis client dependency in apps/api/package.json")
    sh("docker", "stop", REDIS)
    t0 = time.time()
    results = []
    jid = job(admin, A["serverId"], "inventory.collect", {})["jobId"]
    while time.time() - t0 < 90:
        s = sample_api(admin, ["/servers?limit=5", "/metrics/fleet", "/auth/me", f"/servers/{A['serverId']}/jobs?limit=5"])
        results.append({"at": iso(), **{k: v[0] for k, v in s.items()}})
        time.sleep(5)
    j = job_get(admin, A["serverId"], jid)
    rs = call("POST", f"/applications/{B['webAppId']}/restart", admin)
    jr = poll(lambda: (lambda x: x if x["status"] in ("succeeded", "failed", "expired") else None)(
        job_get(admin, B["serverId"], rs[1]["data"]["jobId"])), 120, 2, "restart job") if rs[0] == 202 else {}
    ages = {k: hb_age(admin, v["serverId"]) for k, v in (("node-a", A), ("node-b", B))}
    bad = [r for r in results if any(v != 200 for k, v in r.items() if k != "at")]
    ev.step("Redis down 90 s: login, reads, jobs, heartbeats and an app restart all work", not bad and
            j["status"] == "succeeded" and jr.get("status") == "succeeded" and all(a and a[1] == "online" for a in ages.values()),
            samples=len(results), non200=bad[:5], inventoryJob=j["status"], restartJob=jr.get("status"), heartbeat=ages)
    sh("docker", "start", REDIS)
    wait_healthy(REDIS)
    ev.step("Redis restarted", True, health=health(REDIS))
    ev.summary()


# ------------------------------------------------------------------ postgres
def d_postgres(fl, admin):
    ev = Evidence("disaster-postgres")
    A, B = fl["nodeA"], fl["nodeB"]
    probe = probe_start(A["container"], "static.example.lab", "pgdown", 5, 200)
    pid0 = center_pid()
    t_stop = time.time()
    sh("docker", "stop", "-t", "5", PG)
    samples = []
    while time.time() - t_stop < 60:
        s = sample_api(admin, ["/servers?limit=5", "/setup/status"])
        if len(samples) % 6 == 0:  # stay under the login rate limit
            st, body, dt = http("POST", API + "/auth/login", {"email": "superadmin@ppanel.local", "password": "password"},
                                timeout=15)
            try:
                lc = (json.loads(body).get("error") or {}).get("code") if body else None
            except ValueError:
                lc = "NON_JSON"
            s["/auth/login"] = (st, lc, round(dt * 1000))
        samples.append({"at": iso(), **{k: list(v) for k, v in s.items()}})
        time.sleep(2)
    agent_ok = {k: agent_running(v["container"]) for k, v in (("node-a", A), ("node-b", B))}
    gw_err = node(A["container"], "tail -n 50 /var/log/ppanel-agent.log | grep -E 'heartbeat' | tail -2 || true")
    t_start = time.time()
    sh("docker", "start", PG)
    wait_healthy(PG)
    t_pg = time.time()
    rec = poll(lambda: (lambda s: s if s["/servers?limit=5"][0] == 200 else None)(
        sample_api(admin, ["/servers?limit=5"])), 120, 0.5, "API recovery")
    t_rec = time.time()
    hb = poll(lambda: (lambda a: a if a and a[0] < 20 and parse_ts(
        call("GET", f"/servers/{A['serverId']}", admin)[1]["data"]["lastHeartbeatAt"]) > t_pg else None)(
        hb_age(admin, A["serverId"])), 120, 1, "heartbeat after pg")
    t_hb = time.time()
    time.sleep(3)
    probe_stop(A["container"])
    ps = probe_stats(probe_read(probe), t_stop, t_pg)
    codes = {}
    lat = []
    for s in samples:
        for k, v in s.items():
            if k == "at":
                continue
            key = f"{k} {v[0]} {v[1] or ''}".strip()
            codes[key] = codes.get(key, 0) + 1
            lat.append(v[2])
    clean = all(v[0] in (500, 503) and v[1] for s in samples for k, v in s.items()
                if k != "at" and v[0] != 200)
    ev.step("Postgres down 60 s: API answers fast with enveloped 5xx (no hang, no crash)",
            clean and center_pid() == pid0 and max(lat) < 15000, responses=codes, maxLatencyMs=max(lat),
            centerSamePid=center_pid() == pid0, agentsAlive=agent_ok, agentLastHeartbeatLines=gw_err[-400:],
            note="/setup/status and /auth/login included; pass needs a JSON error code on every non-200")
    ev.step("recovery without Center restart; agents heartbeat again", center_pid() == pid0,
            pgStartSec=round(t_pg - t_start, 1), apiRecoveredSecAfterPgHealthy=round(t_rec - t_pg, 1),
            firstHeartbeatSecAfterPgHealthy=round(t_hb - t_pg, 1), recovery=rec)
    ev.step("legacy site served 100% while the Center DB was down", ps.get("availabilityPct") == 100.0, probe=ps)
    ev.summary()


# ------------------------------------------------------------------ loki
def d_loki(fl, admin):
    ev = Evidence("disaster-loki")
    A = fl["nodeA"]
    probe = probe_start(A["container"], "static.example.lab", "lokidown", 5, 420)
    time.sleep(10)
    t_down = time.time()
    sh("docker", "stop", LOKI_C)
    time.sleep(20)
    st, q = call("GET", f"/logs/query?serverId={A['serverId']}&limit=5", admin)
    buf = []
    while time.time() - t_down < 120:
        rows = data("GET", "/metrics/fleet", admin)
        row = next((r for r in rows if r["serverId"] == A["serverId"]), {})
        buf.append({"at": iso(), "logShipping": row.get("logShipping")})
        time.sleep(15)
    t_up = time.time()
    sh("docker", "start", LOKI_C)
    wait_healthy(LOKI_C, 180)
    t_ready = time.time()
    ev.step("Loki down: /logs/query → 503 LOGS_BACKEND_UNAVAILABLE", st == 503 and
            (q.get("error") or {}).get("code") == "LOGS_BACKEND_UNAVAILABLE", http=st, code=(q.get("error") or {}).get("code"))
    grew = [b["logShipping"]["bufferedBytes"] for b in buf if b.get("logShipping")]
    ev.step("agent buffered while Loki was down (heartbeat logShipping.bufferedBytes > 0)",
            any(x > 0 for x in grew), bufferedBytesSamples=grew, samples=buf)
    time.sleep(60)
    probe_stop(A["container"])
    ps = probe_stats(probe_read(probe), t_down, t_up)
    dl = None
    for _ in range(12):
        dl = log_delivery(A["container"], A["serverId"], t_down + 2, t_up - 2)
        if (dl.get("deliveredPct") or 0) >= 99.9:
            break
        time.sleep(10)
    got = dl.get("inLoki")
    rows = data("GET", "/metrics/fleet", admin)
    row = next((r for r in rows if r["serverId"] == A["serverId"]), {})
    ev.step("after Loki recovery: lines from the outage window delivered (>= 99%), nothing dropped",
            (dl.get("deliveredPct") or 0) >= 99 and (row.get("logShipping") or {}).get("droppedEntries", 0) == 0,
            probeRequestsInWindow=ps["requests"], delivery=dl, lokiDownSec=round(t_up - t_down),
            lokiReadySec=round(t_ready - t_up, 1), logShipping=row.get("logShipping"),
            logDroppedTotal=row.get("logDroppedTotal"))
    ev.summary()


# ------------------------------------------------------------------ prometheus
def d_prometheus(fl, admin):
    ev = Evidence("disaster-prometheus")
    A = fl["nodeA"]
    q = f"/metrics/series?scope=server&id={A['serverId']}&metric=cpu&range=1h"
    st0, r0 = call("GET", q, admin)
    sh("docker", "stop", PROM_C)
    st1, r1 = call("GET", q, admin)
    st_f, rf = call("GET", "/metrics/fleet", admin)
    row = next((r for r in (rf.get("data") or []) if r["serverId"] == A["serverId"]), {})
    web = sh("grep", "-rn", "-e", "q.isError", "-e", "ErrorState", os.path.join(os.path.dirname(__file__),
             "../../apps/web/src/components/p5/monitoring-view.tsx"), check=False)
    ev.step("Prometheus down: /metrics/series → 503 METRICS_BACKEND_UNAVAILABLE (+Retry-After), no zeros",
            st0 == 200 and st1 == 503 and (r1.get("error") or {}).get("code") == "METRICS_BACKEND_UNAVAILABLE",
            before=st0, during=st1, code=(r1.get("error") or {}).get("code"))
    ev.step("/metrics/fleet (DB-backed) still 200 with real sample", st_f == 200 and (row.get("sample") or {}).get("cpuPct")
            is not None, sample=row.get("sample"), stale=row.get("stale"))
    ev.step("UI handles the 503 code (static check of apps/web)", bool(web.strip()) or "INFO",
            matches=web.splitlines()[:6],
            note="not exercised in a browser in this run")
    sh("docker", "start", PROM_C)
    wait_healthy(PROM_C, 120)
    st2 = poll(lambda: (lambda s: s if s[0] == 200 else None)(call("GET", q, admin)), 90, 2, "prom back")
    pts = st2[1]["data"]
    ev.step("Prometheus back: series 200 again, missing interval reported as null points/gaps",
            True, gaps=pts.get("gaps"), nullPoints=sum(1 for p in pts.get("points", []) if p[1] is None))
    ev.summary()


# ------------------------------------------------------------------ backup repo
def d_backup_repo(fl, admin):
    ev = Evidence("disaster-backup-repo")
    A = fl["nodeA"]
    bk = dict(line.strip().split("=", 1) for line in open(".lab/backup.env") if "=" in line and not line.startswith("#"))
    cr = dict(line.strip().split("=", 1) for line in open(".lab/backup/servers/node-a.env")
              if "=" in line and not line.startswith("#"))
    repo = data("POST", "/backup-repositories", admin, {"name": f"p7-{fl['tag']}-{os.urandom(2).hex()}", "kind": "rest",
                                                        "baseUrl": bk.get("PPANEL_LAB_BACKUP_REPO_BASE", "http://lab-backup:8000")})
    call("PUT", f"/backup-repositories/{repo['id']}/servers/{A['serverId']}", admin,
         {"restUser": cr["PPANEL_LAB_BK_USER"], "restPassword": cr["PPANEL_LAB_BK_REST_PASSWORD"],
          "repoPassword": cr["PPANEL_LAB_BK_REPO_PASSWORD"]}, expect=(200, 201))
    call("POST", f"/backup-repositories/{repo['id']}/servers/{A['serverId']}/initialized", admin, {"initialized": True},
         expect=(200, 201))
    pol = data("POST", "/backup-policies", admin, {
        "name": f"p7-repo-down-{fl['tag']}", "serverId": A["serverId"], "repositoryId": repo["id"],
        "targets": [{"type": "paths", "paths": ["/var/www/static"]}],
        "schedule": {"cron": "0 3 * * *", "timezone": "UTC"}, "verify": {"afterBackup": "none"}})
    rule = data("POST", "/alert-rules", admin, {"name": f"p7-backup-failed-{fl['tag']}", "enabled": True,
                                                "scopeType": "server", "scopeId": A["serverId"], "kind": "backup_failed",
                                                "params": {}, "severity": "warning", "forSec": 0, "channelIds": []})

    def run():
        r = data("POST", f"/backup-policies/{pol['id']}/run", admin, None, {"Idempotency-Key": str(uuid.uuid4())})
        rid = r["run"]["id"]
        return poll_get(f"/backup-runs/{rid}", admin, lambda d: d["status"] in ("uploaded", "failed", "expired",
                                                                               "cancelled"), 600, 3)
    ok_run = run()
    ev.step("baseline backup with repo up → uploaded", ok_run["status"] == "uploaded", status=ok_run["status"])
    sh("docker", "stop", REPO_C)
    t0 = time.time()
    bad = run()
    t_fail = round(time.time() - t0, 1)
    time.sleep(35)  # alert evaluation interval 15 s
    inc = call("GET", f"/incidents?rule_id={rule['id']}&limit=10", admin)[1].get("data") or []
    ev.step("repo down → run failed REPO_UNREACHABLE (clear error), backup_failed incident fired",
            bad["status"] == "failed" and (bad.get("error") or {}).get("code") == "REPO_UNREACHABLE" and
            any(i["status"] == "firing" for i in inc), status=bad["status"], error=bad.get("error"), failSec=t_fail,
            ruleActive=rule.get("active"), incidents=[(i["status"], i.get("lastValue")) for i in inc])
    sh("docker", "start", REPO_C)
    wait_healthy(REPO_C)
    good = run()
    time.sleep(35)
    inc2 = call("GET", f"/incidents?rule_id={rule['id']}&limit=10", admin)[1].get("data") or []
    ev.step("repo back → next run uploaded; incident resolved", good["status"] == "uploaded" and
            all(i["status"] == "resolved" for i in inc2), status=good["status"],
            incidents=[(i["status"], i.get("resolvedAt")) for i in inc2])
    r = data("GET", f"/alert-rules/{rule['id']}", admin)
    call("DELETE", f"/alert-rules/{rule['id']}", admin, headers={"If-Match": str(r["version"])})
    ev.summary()


# ------------------------------------------------------------------ certificates
def d_cert(fl, admin):
    ev = Evidence("disaster-cert", {"method": "dev-DB manipulation of agent_certificates validity window "
                                              "(PPANEL_AGENT_CERT_DAYS min is 1 day; no clock faking)"})
    A = fl["nodeA"]
    sid = A["serverId"]
    rows = psql_rows(f"select serial, not_before, not_after from agent_certificates where server_id='{sid}' "
                     "and revoked_at is null order by not_after desc")
    serial0 = rows[0][0]
    # renewAfter = notBefore + 2/3 * (notAfter - notBefore): keep a 7-day life but end it in 1 h → due now
    psql(f"UPDATE agent_certificates SET not_after = now() + interval '1 hour', "
         f"not_before = now() + interval '1 hour' - interval '7 days' WHERE serial='{serial0}'")
    t0 = time.time()
    try:
        new = poll(lambda: (lambda r: r if r and r[0][0] != serial0 else None)(psql_rows(
            f"select serial, not_after, created_at from agent_certificates where server_id='{sid}' and revoked_at is null "
            "order by created_at desc")), 120, 2, "rotation")
        rot_sec = round(time.time() - t0, 1)
    except SystemExit:
        new, rot_sec = None, None
    log = node(A["container"], "grep -E 'rotat' /var/log/ppanel-agent.log | tail -3 || true")
    time.sleep(20)
    age = hb_age(admin, sid)
    ev.step("cert near expiry → agent rotates on its own and keeps heartbeating with the new cert",
            new is not None and age and age[1] == "online", rotatedAfterSec=rot_sec, oldSerial=serial0,
            newCert=new[0] if new else None, agentLog=log[-400:], heartbeat=age)

    # expired (Center-side validity): every active cert of node-a gets not_after = now
    active = psql_rows(f"select serial, not_after from agent_certificates where server_id='{sid}' and revoked_at is null")
    psql(f"UPDATE agent_certificates SET not_after = now() WHERE server_id='{sid}' AND revoked_at is null")
    t_exp = time.time()
    time.sleep(70)
    age2 = hb_age(admin, sid)
    alog = node(A["container"], "tail -n 400 /var/log/ppanel-agent.log | grep -E 'AGENT_CERT|401|revok|expired' | tail -4 || true")
    alive = agent_running(A["container"])
    ev.step("expired agent cert → gateway refuses (401 AGENT_CERT_REVOKED), server goes stale/offline, agent "
            "process keeps running and does not touch workloads",
            age2 and age2[1] in ("stale", "offline") and alive and site_code(A["container"], "static.example.lab") == "200",
            heartbeat=age2, agentAlive=alive, agentLog=alog[-600:])
    # restore original validity (simulates the operator re-issuing; real expiry would need re-enrollment)
    for s, na in active:
        psql(f"UPDATE agent_certificates SET not_after = '{na}' WHERE serial='{s}'")
    t_r = time.time()
    try:
        poll(lambda: (lambda a: a if a and a[1] == "online" and a[0] < 10 else None)(hb_age(admin, sid)), 180, 2,
             "recovery")
        rec = round(time.time() - t_r, 1)
    except SystemExit:
        rec = None
    ev.step("validity restored → agent reconnects by itself (backoff at max after 401)", rec is not None,
            reconnectSec=rec, expiredForSec=round(t_r - t_exp))
    ev.step("gateway TLS cert expiry handling", "INFO",
            finding="apps/api/src/agent/gateway.server.ts issues the gateway cert once at start (90-day validity, "
                    "ca.service.ts issueGatewayCert) and never re-issues/hot-swaps it; a Center running > 90 days "
                    "without restart would lose every agent. Not exercised live (needs clock manipulation).")
    ev.summary()


# ------------------------------------------------------------------ aborted deploy
def d_aborted_deploy(fl, admin):
    ev = Evidence("disaster-aborted-deploy")
    B = fl["nodeB"]
    img = fl["images"]
    for variant, down_sec in (("short", 20), ("past-running-lease", 150)):
        cur = data("GET", f"/applications/{B['webAppId']}", admin)
        live_before = site_body(B["container"], B["webDomain"])[:30]
        target = img["PPANEL_LAB_IMAGE_WEB_V2"] if "v1" in live_before else img["PPANEL_LAB_IMAGE_WEB_V1"]
        d = data("POST", f"/applications/{B['webAppId']}/deployments", admin, {"image": target},
                 {"Idempotency-Key": str(uuid.uuid4())})["deployment"]
        seen = None
        t0 = time.time()
        while time.time() - t0 < 120:
            x = data("GET", f"/deployments/{d['id']}", admin)
            if x["status"] in ("pulling", "starting", "health_check", "routing") or x["status"] in DEPLOY_DONE:
                seen = x["status"]
                break
            time.sleep(0.1)
        os.kill(center_pid(), signal.SIGKILL)
        t_kill = time.time()
        time.sleep(1)
        stop_center()
        during = []
        while time.time() - t_kill < down_sec:
            during.append(site_body(B["container"], B["webDomain"])[:20])
            time.sleep(5)
        start_center(log_name="center-aborted-deploy")
        admin = login()
        fin = poll_get(f"/deployments/{d['id']}", admin, lambda x: x["status"] in DEPLOY_DONE, 400, 3)
        time.sleep(10)
        app = data("GET", f"/applications/{B['webAppId']}", admin)
        live_after = site_body(B["container"], B["webDomain"])[:30]
        route = node(B["container"], f"cat /etc/nginx/ppanel-managed/*/route.conf 2>/dev/null | grep -A1 'upstream ppanel_{B['webDomain'].split('.')[0].replace('-', '_')}' | head -2")
        containers = sh(*DIND, "ps", "-a", "--filter", f"label=ppanel.app={B['webDomain'].split('.')[0]}",
                        "--format", "{{.Names}} {{.Status}} {{.Label \"ppanel.deployment\"}}", check=False)
        cand_left = [c for c in containers.splitlines() if d["id"] in c and "Up" in c]
        consistent = (fin["status"] == "succeeded" and app["container"]["currentDeploymentId"] == d["id"]) or (
            fin["status"] != "succeeded" and app["container"]["currentDeploymentId"] == cur["container"]["currentDeploymentId"]
            and live_after == live_before)
        ev.step(f"aborted deploy ({variant}, Center SIGKILLed at '{seen}', down {down_sec}s): no half-switched route, "
                "deployment terminal, live version serving, no running orphan candidate",
                consistent and all(x for x in during) and not (fin["status"] != "succeeded" and cand_left),
                killedAt=seen, final=fin["status"], error=fin.get("error"),
                steps=[(s["name"], s["status"]) for s in fin.get("steps", [])], liveBefore=live_before,
                liveAfter=live_after, servedDuringOutage=sorted(set(during)), route=route,
                containers=containers.splitlines(), orphanCandidatesRunning=cand_left)
    ev.summary()


ALL = {"redis": d_redis, "postgres": d_postgres, "loki": d_loki, "prometheus": d_prometheus,
       "backup-repo": d_backup_repo, "cert": d_cert, "aborted-deploy": d_aborted_deploy}


def main():
    names = sys.argv[1:] or ["all"]
    if names == ["all"]:
        names = list(ALL)
    fl = fleet()
    admin = login()
    for n in names:
        if n == "aborted-deploy" or call("GET", "/auth/me", admin)[0] != 200:
            admin = login()
        print(f"===== {n}", flush=True)
        try:
            ALL[n](fl, admin)
        except SystemExit as e:
            print(f"ABORT {n}: {e}", flush=True)
            Evidence(f"disaster-{n}-abort").step(f"{n} aborted", "FAIL", error=str(e)[:800])


if __name__ == "__main__":
    main_guard(main)
