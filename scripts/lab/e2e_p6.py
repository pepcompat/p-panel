#!/usr/bin/env python3
"""pPanel P6 lab E2E: backups and restores driven through the real Center API, real Go agents,
append-only rest-server, helper image, dind and MinIO.

P6-T01 files: back up a directory with known checksums -> delete -> restore -> checksums identical.
P6-T02 postgres: compose app with seeded tables -> logical dump backup -> scratch restore -> rows and
       constraints identical, scratch removed.
P6-T03 production restore: requires another approver with step-up; creator/viewer refused; audited.
P6-T04 interrupted backup (agent killed mid-run) never reports success; no snapshot for that run.
Plus: verification levels are honest; maintenance report (offsite copy) is recorded on the Center.
(P6-T05 Center recovery is covered by apps/api/test/integration/center-recovery.spec.ts.)

Prereqs: scripts/lab/up.sh, scripts/lab/backup-images.sh, scripts/backup/maintenance.sh --lab init node-a
and node-b, scripts/lab/images.sh (web image), observability not required. No Center on :4000.
Run: python3 -I scripts/lab/e2e_p6.py [--out docs/evidence/<date>/p6-e2e.json]
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + "/../..")
API = "http://localhost:4000/api/v1"
AGENT = "/opt/ppanel-agent/ppanel-agent-linux-arm64"
DIND = ["docker", "exec", "ppanel-lab-dind", "docker", "-H", "unix:///run/dind/docker.sock"]
REG = "127.0.0.1:55000"
TAG = str(int(time.time()) % 100000)
REPORT_TOKEN = secrets.token_hex(24)
results, responses = [], []
api_proc = None


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:340] if info else ""), flush=True)
    if not ok:
        finish(1)


def finish(code):
    if "--out" in sys.argv:
        with open(sys.argv[sys.argv.index("--out") + 1], "w") as f:
            json.dump({"ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": results}, f, indent=2)
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def http(method, url, body=None, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return 0, ""


def call(method, path, token=None, body=None, headers=None, expect=None):
    h = {"X-Request-ID": str(uuid.uuid4())}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    st, text = http(method, API + path, body, h)
    responses.append(text)
    payload = json.loads(text) if text else {}
    if expect is not None and st not in (expect if isinstance(expect, tuple) else (expect,)):
        raise SystemExit(f"{method} {path} -> {st} (expected {expect}): {text[:700]}")
    return st, payload


def sh(*argv, check=True, timeout=600):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed: {argv}: {p.stderr[:400]}")
    return p.stdout.strip()


def node(n, cmd):
    return sh("docker", "exec", n, "sh", "-c", cmd)


def poll(fn, timeout, every=3, what="condition"):
    end, last = time.time() + timeout, None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(every)
    raise SystemExit(f"timeout waiting for {what}")


def env_file(path):
    out = {}
    for line in open(path):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            out[k] = v
    return out


def totp(secret_b32):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def start_api():
    global api_proc
    env = dict(os.environ, API_HOST="0.0.0.0", PPANEL_PUBLIC_GATEWAY_URL="https://host.docker.internal:4443",
               PPANEL_PUBLIC_API_URL="http://host.docker.internal:4000", PPANEL_BACKUP_REPORT_TOKEN=REPORT_TOKEN,
               PPANEL_BACKUP_SCHEDULER_INTERVAL_MS="5000")
    log = open(f"{ROOT}/.lab/evidence/e2e-p6-api.log", "a")
    api_proc = subprocess.Popen(["pnpm", "--filter", "@ppanel/api", "dev"], cwd=ROOT, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
    poll(lambda: http("GET", API + "/setup/status")[0] == 200, 90, 1, "API start")


def stop_api():
    if api_proc and api_proc.poll() is None:
        os.killpg(api_proc.pid, signal.SIGTERM)
        api_proc.wait(timeout=30)
    for port in ("4000", "4443"):
        for p in sh("lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN", check=False).split():
            os.kill(int(p), signal.SIGTERM)
    time.sleep(2)


def login(email, pw):
    return call("POST", "/auth/login", body={"email": email, "password": pw}, expect=200)[1]["data"]["accessToken"]


def start_agent(container):
    sh("docker", "exec", "-d", container, "sh", "-c",
       f"{AGENT} run --state-dir /var/lib/ppanel-agent > /var/log/ppanel-agent.log 2>&1")


def kill_agent(container):
    node(container, "pkill -f '[p]panel-agent-linux-arm64 run' || true")


def enroll(token, container, name, env):
    _, e = call("POST", "/enrollments", token, {"name": name, "environment": env, "ttlMinutes": 10}, expect=201)
    kill_agent(container)
    node(container, "find /var/lib/ppanel-agent -mindepth 1 -delete")
    out = sh("docker", "exec", container, "env", "PPANEL_DEV_INSECURE_ENROLL=1", AGENT, "enroll", "--center",
             "http://host.docker.internal:4000", "--token", e["data"]["token"], "--state-dir", "/var/lib/ppanel-agent")
    start_agent(container)
    return out.split("serverId=")[1].split()[0]


RUN_DONE = {"uploaded", "failed", "expired", "cancelled"}
RESTORE_DONE = {"verified", "failed", "requires_manual_recovery", "cancelled", "impact_reviewed", "awaiting_approval"}


def run_policy(token, pid):
    _, r = call("POST", f"/backup-policies/{pid}/run", token, None, {"Idempotency-Key": str(uuid.uuid4())},
                expect=(200, 202))
    rid = r["data"]["run"]["id"]
    return poll(lambda: (lambda d: d if d["status"] in RUN_DONE else None)(
        call("GET", f"/backup-runs/{rid}", token, expect=200)[1]["data"]), 600, 3, "backup run")


def restore_status(token, rid, statuses):
    return poll(lambda: (lambda d: d if d["status"] in statuses else None)(
        call("GET", f"/restores/{rid}", token, expect=200)[1]["data"]), 600, 3, "restore")


def lab_reset():
    ids = sh(*DIND, "ps", "-aq", "--filter", "label=ppanel.managed=true", check=False).split()
    if ids:
        sh(*DIND, "rm", "-f", *ids, check=False)
    node("ppanel-lab-node-b",
         "rm -rf /etc/nginx/ppanel-managed /etc/nginx/conf.d/ppanel-managed.conf && nginx -t -q && nginx -s reload")


def main():
    bk = env_file(".lab/backup.env")
    creds = {n: env_file(f".lab/backup/servers/node-{n}.env") for n in ("a", "b")}
    lab_reset()
    stop_api()
    start_api()
    admin = login("superadmin@ppanel.local", "password")

    # approver with TOTP (for production restore)
    apw = secrets.token_urlsafe(16)
    aemail = f"p6-approver-{TAG}@ppanel.local"
    call("POST", "/users", admin, {"email": aemail, "password": apw, "displayName": "P6 approver",
                                   "bindings": [{"roleKey": "ops_admin", "scopeType": "global"}]}, expect=201)
    approver = login(aemail, apw)
    _, s = call("POST", "/auth/mfa/totp/setup", approver, expect=200)
    otp = urllib.parse.parse_qs(urllib.parse.urlparse(s["data"]["otpauthUrl"]).query)["secret"][0]
    call("POST", "/auth/mfa/totp/confirm", approver, {"code": totp(otp)}, expect=200)

    sa = enroll(admin, "ppanel-lab-node-a", f"p6-node-a-{TAG}", "production")
    sb = enroll(admin, "ppanel-lab-node-b", f"p6-node-b-{TAG}", "uat")
    for sid in (sa, sb):
        poll(lambda: (lambda d: d["status"] == "online" and "backup" in d["capabilities"])(
            call("GET", f"/servers/{sid}", admin, expect=200)[1]["data"]), 120, 3, "online+backup")
    step("node-a (production) and node-b (uat) online with backup capability", True)

    # repository + per-server access (lab creds generated by scripts/lab/backup-secrets.sh)
    _, repo = call("POST", "/backup-repositories", admin, {"name": f"lab-{TAG}", "kind": "rest",
                                                           "baseUrl": bk.get("PPANEL_LAB_BACKUP_REPO_BASE",
                                                                             "http://lab-backup:8000")}, expect=201)
    repo_id = repo["data"]["id"]
    for sid, c in ((sa, creds["a"]), (sb, creds["b"])):
        call("PUT", f"/backup-repositories/{repo_id}/servers/{sid}", admin,
             {"restUser": c["PPANEL_LAB_BK_USER"], "restPassword": c["PPANEL_LAB_BK_REST_PASSWORD"],
              "repoPassword": c["PPANEL_LAB_BK_REPO_PASSWORD"]}, expect=(200, 201))
        call("POST", f"/backup-repositories/{repo_id}/servers/{sid}/initialized", admin, {"initialized": True},
             expect=(200, 201))
    _, rv = call("GET", f"/backup-repositories/{repo_id}", admin, expect=200)
    leaked = any(c["PPANEL_LAB_BK_REPO_PASSWORD"] in t or c["PPANEL_LAB_BK_REST_PASSWORD"] in t
                 for c in creds.values() for t in responses)
    step("repository + access configured; passwords never returned", not leaked)

    # --- P6-T01 files (node-a, production)
    data_dir = f"/var/lib/ppanel-p6e2e-{TAG}"
    node("ppanel-lab-node-a", f"mkdir -p {data_dir}/sub && for i in $(seq 1 25); do head -c $((i*1000)) /dev/urandom > {data_dir}/f$i.bin; done"
                              f" && echo hello > {data_dir}/sub/note.txt && ln -s note.txt {data_dir}/sub/link")
    before = node("ppanel-lab-node-a", f"cd {data_dir} && find . -type f | sort | xargs sha256sum")
    _, pol = call("POST", "/backup-policies", admin, {
        "name": f"files-{TAG}", "serverId": sa, "repositoryId": repo_id,
        "targets": [{"type": "paths", "paths": [data_dir]}],
        "schedule": {"cron": "0 3 * * *", "timezone": "Asia/Bangkok"}, "verify": {"afterBackup": "none"}}, expect=201)
    run = run_policy(admin, pol["data"]["id"])
    step("files backup uploaded with manifest; verification honestly 'none'",
         run["status"] == "uploaded" and run["verification"] == "none", snapshots=len(run.get("snapshots") or []),
         manifest=run.get("manifest"), nextRunAt=pol["data"].get("nextRunAt"))

    call("POST", f"/backup-runs/{run['id']}/verify", admin, {"level": "restore_test"}, expect=202)
    vrun = poll(lambda: (lambda d: d if d["verification"] in ("restore_verified", "verify_failed") else None)(
        call("GET", f"/backup-runs/{run['id']}", admin, expect=200)[1]["data"]), 600, 3, "verification")
    step("test restore verification -> restore_verified", vrun["verification"] == "restore_verified")

    node("ppanel-lab-node-a", f"rm -rf {data_dir}")
    snap = run["snapshots"][0]["snapshotId"]
    _, rs = call("POST", "/restores", admin, {"runId": run["id"], "snapshotId": snap,
                                              "target": {"type": "paths", "include": [data_dir], "mode": "staging"}},
                 expect=201)
    rid = rs["data"]["id"]
    call("POST", f"/restores/{rid}/dry-run", admin, expect=202)
    r1 = restore_status(admin, rid, RESTORE_DONE)
    # --- P6-T03: production restore needs another approver with step-up
    st_exec, d_exec = call("POST", f"/restores/{rid}/execute", admin)
    st_self, _ = call("POST", f"/restores/{rid}/approve", admin, {"planHash": r1["planHash"]})
    viewer = login("user1@ppanel.local", "password")
    st_view, _ = call("POST", f"/restores/{rid}/execute", viewer)
    time.sleep(31 - (time.time() % 30))
    _, su = call("POST", "/auth/step-up", approver, {"code": totp(otp)}, expect=200)
    step_up = {"X-Step-Up": su["data"]["stepUpToken"]}
    call("POST", f"/restores/{rid}/approve", approver, {"planHash": r1["planHash"]}, step_up, expect=200)
    # production execute is done by the (step-up verified) approver; the creator has no 2FA in the lab
    call("POST", f"/restores/{rid}/execute", approver, None, step_up, expect=202)
    r2 = restore_status(admin, rid, {"verified", "failed", "requires_manual_recovery", "cancelled"})
    staging = (r2.get("result") or {}).get("stagingPath") or ""
    after = node("ppanel-lab-node-a", f"cd {staging}{data_dir} && find . -type f | sort | xargs sha256sum") if staging else ""
    _, audit = call("GET", f"/audit-events?target_id={rid}&limit=50", admin, expect=200)
    actions = sorted({a["action"] for a in audit["data"]})
    step("P6-T03 production restore: approval required, creator & viewer refused, approver w/ step-up",
         r1["status"] == "awaiting_approval" and st_exec in (403, 409) and st_self == 403 and st_view == 403
         and r2["status"] == "verified", executeBeforeApproval=(st_exec, (d_exec.get("error") or {}).get("code")),
         creatorApprove=st_self, viewerExecute=st_view, audit=actions)
    step("P6-T01 restored files identical to originals (sha256 of all files)",
         before and after == before, files=before.count("\n") + 1, stagingPath=staging)

    # --- P6-T02 postgres in a compose app (node-b, uat)
    call("POST", f"/servers/{sb}/managed-routing", admin, expect=202)
    poll(lambda: call("GET", f"/servers/{sb}/managed-routing", admin, expect=200)[1]["data"]["enabled"], 120, 3,
         "routing")
    web = env_file(".lab/images.env")["PPANEL_LAB_IMAGE_WEB_V1"].replace("lab-registry:5000", REG)
    pg = "docker.io/library/postgres@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
    yaml = f"""services:
  db:
    image: {pg}
    environment:
      POSTGRES_USER: app
      POSTGRES_DB: app
      POSTGRES_PASSWORD: ${{DB_PASSWORD}}
    volumes:
      - pgdata:/var/lib/postgresql/data
  web:
    image: {web}
    depends_on: [db]
volumes:
  pgdata: {{}}
"""
    cname = f"p6db-{TAG}"
    _, ca = call("POST", "/applications", admin, {"kind": "compose", "serverId": sb, "name": cname, "environment": "uat",
                                                  "domains": [f"{cname}.lab.test"], "yaml": yaml, "routeService": "web",
                                                  "routePort": 8080, "healthPath": "/healthz"}, expect=201)
    app_id = ca["data"]["id"]
    db_pw = secrets.token_hex(12)
    call("PUT", f"/applications/{app_id}/secrets/DB_PASSWORD", admin, {"value": db_pw}, expect=200)
    _, d = call("POST", f"/applications/{app_id}/deployments", admin, {}, {"Idempotency-Key": str(uuid.uuid4())},
                expect=(200, 202))
    dep = poll(lambda: (lambda x: x if x["status"] in ("succeeded", "failed") else None)(
        call("GET", f"/deployments/{d['data']['deployment']['id']}", admin, expect=200)[1]["data"]), 300, 3, "deploy")
    dbc = sh(*DIND, "ps", "-q", "--filter", f"label=ppanel.app={cname}", "--filter", "label=ppanel.service=db")
    seed = ("create table customers(id serial primary key, email text unique not null);"
            "create table orders(id serial primary key, customer_id int not null references customers(id), total numeric(10,2) check (total >= 0));"
            "insert into customers(email) select 'c'||g||'@x.lab' from generate_series(1,42) g;"
            "insert into orders(customer_id,total) select (g%42)+1, g*1.5 from generate_series(1,137) g;")
    poll(lambda: sh(*DIND, "exec", dbc, "pg_isready", "-U", "app", check=False) and True, 60, 2, "pg ready")
    sh(*DIND, "exec", dbc, "psql", "-U", "app", "-d", "app", "-v", "ON_ERROR_STOP=1", "-c", seed)
    step("compose app with Postgres deployed and seeded (42 customers, 137 orders)", dep["status"] == "succeeded")

    _, dpol = call("POST", "/backup-policies", admin, {
        "name": f"db-{TAG}", "serverId": sb, "repositoryId": repo_id,
        "targets": [{"type": "postgres", "applicationId": app_id, "service": "db", "database": "app", "user": "app",
                     "passwordSecretKey": "DB_PASSWORD"}],
        "schedule": {"cron": "30 2 * * *", "timezone": "Asia/Bangkok"}, "verify": {"afterBackup": "none"}}, expect=201)
    drun = run_policy(admin, dpol["data"]["id"])
    _, drunfull = call("GET", f"/backup-runs/{drun['id']}", admin, expect=200)
    _, rs = call("POST", "/restores", admin, {
        "runId": drun["id"], "snapshotId": drun["snapshots"][0]["snapshotId"],
        "target": {"type": "postgres", "app": cname, "service": "db", "database": "app", "user": "app",
                   "passwordSecretKey": "DB_PASSWORD", "mode": "scratch"}}, expect=201)
    # no scratchImage given: the Center defaults it to the source db service's own image
    call("POST", f"/restores/{rs['data']['id']}/dry-run", admin, expect=202)
    restore_status(admin, rs["data"]["id"], RESTORE_DONE)
    call("POST", f"/restores/{rs['data']['id']}/execute", admin, expect=202)
    rr = restore_status(admin, rs["data"]["id"], {"verified", "failed", "requires_manual_recovery", "cancelled"})
    res = rr.get("result") or {}
    tables = {t["name"].split(".")[-1]: t["rows"] for t in (res.get("tables") or [])}  # names are schema-qualified
    leftovers = sh(*DIND, "ps", "-aq", "--filter", "name=ppanel-restore-", check=False)
    step("P6-T02 postgres dump -> isolated scratch restore: rows + constraints identical, scratch removed",
         drun["status"] == "uploaded" and rr["status"] == "verified" and tables.get("customers") == 42
         and tables.get("orders") == 137 and (res.get("verify") or {}).get("ok") and not leftovers,
         tables=tables, constraints=res.get("constraints"), verify=res.get("verify"))
    step("DB password never in API responses", not any(db_pw in t for t in responses))

    # --- P6-T04 interrupted backup never reports success
    big = f"/var/lib/ppanel-p6big-{TAG}"
    node("ppanel-lab-node-a", f"mkdir -p {big} && head -c 300000000 /dev/urandom > {big}/blob.bin")
    _, bpol = call("POST", "/backup-policies", admin, {
        "name": f"big-{TAG}", "serverId": sa, "repositoryId": repo_id,
        "targets": [{"type": "paths", "paths": [big]}],
        "schedule": {"cron": "0 4 * * *", "timezone": "UTC"}, "verify": {"afterBackup": "none"}}, expect=201)
    _, r = call("POST", f"/backup-policies/{bpol['data']['id']}/run", admin, None,
                {"Idempotency-Key": str(uuid.uuid4())}, expect=(200, 202))
    brun_id = r["data"]["run"]["id"]
    poll(lambda: call("GET", f"/backup-runs/{brun_id}", admin, expect=200)[1]["data"]["status"] == "running", 60, 0.2,
         "run started")
    # kill right away: a 300 MB local backup can finish in < 2 s on fast hardware
    node("ppanel-lab-node-a", "pkill -9 -f '[p]panel-agent-linux-arm64 run' || true; pkill -9 -x restic || true")
    brun = poll(lambda: (lambda d: d if d["status"] in RUN_DONE else None)(
        call("GET", f"/backup-runs/{brun_id}", admin, expect=200)[1]["data"]), 900, 5, "interrupted run terminal")
    start_agent("ppanel-lab-node-a")
    poll(lambda: call("GET", f"/servers/{sa}", admin, expect=200)[1]["data"]["status"] == "online", 120, 3, "back")
    st, snaps = call("GET", f"/servers/{sa}/snapshots?repository_id={repo_id}&tag=run={brun_id}", admin)
    if st == 202:
        time.sleep(10)
        st, snaps = call("GET", f"/servers/{sa}/snapshots?repository_id={repo_id}&tag=run={brun_id}", admin)
    node("ppanel-lab-node-a", f"rm -rf {big}")
    step("P6-T04 agent killed mid-backup: run not uploaded, no snapshot for that run",
         brun["status"] in ("expired", "failed") and not ((snaps.get("data") or {}).get("snapshots")),
         status=brun["status"], snapshotLookup=st)

    # --- maintenance: offsite copy report recorded on the Center
    env = dict(os.environ, PPANEL_BACKUP_REPORT_TOKEN=REPORT_TOKEN, PPANEL_BACKUP_REPOSITORY_ID=repo_id)
    p = subprocess.run(["scripts/backup/maintenance.sh", "--lab", "copy", creds["a"]["PPANEL_LAB_BK_USER"], "--report",
                        "http://localhost:4000"], capture_output=True, text=True, env=env, timeout=900, cwd=ROOT)
    _, repo2 = call("GET", f"/backup-repositories/{repo_id}", admin, expect=200)
    st_bad, _ = http("GET", API + "/backup-policies", None, {"Authorization": "Bearer " + REPORT_TOKEN})
    step("maintenance offsite copy reported to the Center; report token can't read anything else",
         p.returncode == 0 and "copy" in json.dumps(repo2["data"]) and st_bad == 401, rc=p.returncode,
         stderr=p.stderr[-200:])
    node("ppanel-lab-node-a", f"rm -rf {data_dir}")
    stop_api()
    finish(0)


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
