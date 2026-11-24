#!/usr/bin/env python3
"""pPanel P8-T02 (LAB SUBSTITUTE): upgrade 0.7.0 -> 0.8.0-rc.1 -> rollback, with data and a mixed fleet.

No VMs are available (docs/RELEASE_CONTRACT.md §6): the hosts are the Ubuntu 24.04 systemd containers of
compose profile `ubuntu` (infra/lab/ubuntu). Results are reported as PASS (lab substitute).

"0.7.0" = commit aa92403 (P7) + the minimal P8 packaging patch (Dockerfiles, prisma as a runtime
dependency, Next.js standalone flag, a public GET /api/v1/health) — no installer, /version or
AGENT_OUTDATED existed before P8. The patch is built in a temporary git worktree OUTSIDE the repo
(--worktree), written to docs/evidence/<date>/p8-t02-v070-packaging.patch, and the worktree is removed.

Journey: build 0.7.0 (images + agents, SHA256SUMS signed with the lab key) -> fresh ubuntu lab ->
install 0.7.0 with the 0.8.0-rc.1 bundle's install.sh (--version 0.7.0 --no-start; 0.7.0 has no
/version so install.sh's version probe cannot pass) + compose up -> first boot, owner + ops admin with
TOTP -> two 0.7.0 agents -> data (nginx import -> application, e-mail channel, alert rule, backup
repository + access + 2 policies + 1 run) -> checksums of key tables + API listings -> forced failures
(missing image tag; image whose label is another version) stop upgrade.sh before anything changes ->
upgrade.sh 0.8.0-rc.1 -> everything retained (ids, counts, checksums, 2FA login, agents reconnect, 0.7.0
not outdated, mutating job accepted) -> re-run is a no-op, downgrade refused -> one agent to 0.8.0-rc.1
via install-agent.sh (no re-enroll) -> mixed fleet (read-only + mutating jobs; with
PPANEL_MIN_AGENT_VERSION=0.8.0-rc.1 the 0.7.0 agent is outdated: 409 AGENT_OUTDATED, read-only still ok)
-> post-upgrade marker data -> rollback.sh <pre-upgrade dump> 0.7.0 -> data == pre-upgrade snapshot,
marker gone, Center reports 0.7.0, both agents (0.7.0 + 0.8.0-rc.1) online, 2FA login works.

Run: python3 -I scripts/lab/e2e_p8_upgrade.py --worktree <dir outside the repo>
     [--out docs/evidence/2026-11-24/p8-t02-upgrade.json] [--skip-build] [--keep-dist] [--down]
Needs dist-release/<VERSION> from scripts/release/build.sh --save-images --sign-key .lab/p8/lab-release-signing.key
(e2e_p8_install.py builds it). Lab only: talks to the ppanel-lab-ubuntu-* containers via `docker exec`.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NEW = open(os.path.join(ROOT, "VERSION")).read().strip()
OLD, OLD_COMMIT = "0.7.0", "aa92403"
DIST_NEW = os.path.join(ROOT, "dist-release", NEW)
WORK = os.path.join(ROOT, ".lab", "p8")
DIST_OLD = os.path.join(WORK, "dist-" + OLD)
LAB_KEY = os.path.join(WORK, "lab-release-signing.key")
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence", "2026-11-24")
PATCH_OUT = os.path.join(EVIDENCE_DIR, "p8-t02-v070-packaging.patch")
COMPOSE = ["docker", "compose", "-p", "ppanel-lab", "-f", os.path.join(ROOT, "infra/compose/lab.yml"),
           "--profile", "ubuntu"]
CENTER = "ppanel-lab-ubuntu-center"
NODES = ["ppanel-lab-ubuntu-node-1", "ppanel-lab-ubuntu-node-2"]
DOMAIN = "center.ppanel.lab"
URL = f"https://{DOMAIN}/api/v1"
CACERT = "/root/agent/caddy-root.crt"
CC = "docker compose --project-directory /opt/ppanel -f /opt/ppanel/compose.yml --env-file /opt/ppanel/.env"
BUNDLE = f"/root/release/ppanel-center-{NEW}"
CONNECTED = ("online", "degraded")
RUN_DONE = {"uploaded", "failed", "expired", "cancelled"}
JOB_DONE = {"succeeded", "failed", "expired", "cancelled"}
results = []
started = time.time()
meta = {}


def step(name, ok, **info):
    results.append({"step": name, "ok": bool(ok), **info})
    print(("PASS " if ok else "FAIL ") + name + ("  " + json.dumps(info)[:300] if info else ""), flush=True)
    if not ok:
        finish(1)


def finish(code):
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else None
    if out:
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w") as f:
            json.dump({
                "test": f"P8-T02 upgrade {OLD} -> {NEW} with data + mixed-version fleet, then rollback",
                "result": ("PASS (lab substitute)" if code == 0 else "FAIL"),
                "labSubstitute": True,
                "note": "Ubuntu 24.04 systemd containers (infra/lab/ubuntu), not VMs; "
                        f"{OLD} = {OLD_COMMIT} + minimal P8 packaging patch (p8-t02-v070-packaging.patch)",
                "from": OLD, "to": NEW,
                "ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "durationSec": round(time.time() - started, 1),
                **meta,
                "steps": results,
            }, f, indent=2)
            f.write("\n")
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def sh(*argv, check=True, timeout=900, stdin=None, cwd=None):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, input=stdin, cwd=cwd)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed ({p.returncode}): {argv[:6]}: {(p.stderr or p.stdout)[-1200:]}")
    return p


def dx(container, cmd, check=True, timeout=900, workdir=None, stdin=None):
    argv = ["docker", "exec"] + (["-i"] if stdin is not None else []) + (["-w", workdir] if workdir else []) \
        + [container, "bash", "-c", cmd]
    return sh(*argv, check=check, timeout=timeout, stdin=stdin)


def sql(query):
    return dx(CENTER, f"{CC} exec -T postgres psql -U ppanel -d ppanel -At -v ON_ERROR_STOP=1",
              stdin=query).stdout.strip()


def api(method, path, token=None, body=None, headers=None, via=NODES[0]):
    argv = ["docker", "exec", "-i", via, "curl", "-sS", "--max-time", "60", "--cacert", CACERT, "-X", method,
            "-o", "/dev/stdout", "-w", "\n%{http_code}", "-H", "Content-Type: application/json",
            "-H", "X-Request-ID: " + str(uuid.uuid4())]
    if token:
        argv += ["-H", "Authorization: Bearer " + token]
    for k, v in (headers or {}).items():
        argv += ["-H", f"{k}: {v}"]
    if body is not None:
        argv += ["--data-binary", "@-"]
    argv.append(URL + path)
    p = sh(*argv, check=False, stdin=json.dumps(body) if body is not None else None, timeout=90)
    raw, _, code = p.stdout.rpartition("\n")
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"raw": raw[:300]}
    return int(code or 0), payload


def data(payload):
    return payload.get("data", payload) if isinstance(payload, dict) else payload


def poll(fn, timeout=90, every=2.0):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(every)
    return last


_last_step = {}


def totp(secret_b32):
    """TOTP for the next unused 30 s step of this secret (the Center refuses replays)."""
    counter = int(time.time()) // 30
    if _last_step.get(secret_b32, -1) >= counter:
        time.sleep(31 - (time.time() % 30))
        counter = int(time.time()) // 30
    _last_step[secret_b32] = counter
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def login_2fa(email, pw, secret):
    _, lg = api("POST", "/auth/login", body={"email": email, "password": pw})
    lgd = data(lg)
    if not lgd.get("mfaRequired"):
        return None, lgd
    st, mv = api("POST", "/auth/mfa/verify", body={"mfaToken": lgd.get("mfaToken"), "code": totp(secret)})
    return (data(mv).get("accessToken") if st == 200 else None), {"mfaRequired": True, "verifyStatus": st}


def wait_systemd(container):
    return poll(lambda: dx(container, "systemctl is-system-running", check=False).stdout.strip()
                in ("running", "degraded"), 90, 1)


def env_lines(keys):
    out = dx(CENTER, "grep -E '^(" + "|".join(keys) + ")=' /opt/ppanel/.env | sort").stdout.strip().splitlines()
    return dict(line.split("=", 1) for line in out)


def containers():
    return dx(CENTER, f"{CC} ps -q | sort | tr '\\n' ' '").stdout.strip()


def backups_list():
    return sorted(dx(CENTER, "ls -1 /opt/ppanel/backups").stdout.split())


# ---------------------------------------------------------------- data checksums (stable columns only)
# Columns that change by themselves at runtime (heartbeats, last_login_at, TOTP last_used_step, scheduler
# timestamps, agent_version) are excluded: the check is "the same records with the same content".
TABLES = {
    "users": ("id", "id,email,display_name,password_hash,status,created_at"),
    "mfa_factors": ("id", "id,user_id,type,secret_enc,confirmed_at,created_at"),
    "recovery_codes": ("id", "id,user_id,code_hash,created_at"),
    "role_bindings": ("id", "id,user_id,role_key,scope_type,scope_id,created_by_id,created_at"),
    "ca_keys": ("id", "id,purpose,algorithm,cert_pem,private_key_enc,active,not_after,created_at"),
    "agent_enrollments": ("id", "id,name,environment,token_hash,used_at,server_id,created_at"),
    "servers": ("id", "id,name,hostname,environment,group_id,tags,enrollment_id,created_at"),
    "agent_certificates": ("id", "id,server_id,serial,fingerprint_sha256,not_before,not_after,revoked_at"),
    "discovery_scans": ("id", "id,server_id,status,created_at"),
    "applications": ("id", "id,server_id,name,kind,domains,ownership_mode,source_finding_fingerprint,created_at"),
    "notification_channels": ("id", "id,name,type,enabled,config_public,config_encrypted,version,created_at"),
    "alert_rules": ("id", "id,name,enabled,scope_type,scope_id,kind,params,severity,for_sec,channel_ids,version,created_at"),
    "backup_repositories": ("id", "id,name,kind,base_url,offsite,version,created_at"),
    "backup_repo_access": ("repository_id,server_id",
                           "repository_id,server_id,rest_user,rest_password_enc,repo_password_enc,initialized_at"),
    "backup_policies": ("id", "id,name,server_id,repository_id,targets,schedule_cron,timezone,retention,verify,"
                              "enabled,deleted_at,version,created_at"),
    "backup_runs": ("id", "id,policy_id,server_id,trigger,status,created_at"),
}


def checksums():
    q = " UNION ALL ".join(
        f"SELECT '{t}' || '=' || count(*) || ':' || coalesce(md5(string_agg(row({cols})::text, '|' ORDER BY {key})), '-')"
        f" FROM {t}" for t, (key, cols) in TABLES.items()) + ";"
    rows = dict(line.split("=", 1) for line in sql(q).splitlines())
    rows["_prisma_migrations"] = sql("SELECT count(*) || ':' || max(migration_name) FROM _prisma_migrations "
                                     "WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL;")
    return rows


def listings(tok):
    out = {}
    for path in ("/users?limit=100", "/servers?limit=100", "/applications?limit=100", "/alert-rules?limit=100",
                 "/notification-channels?limit=100", "/backup-repositories?limit=100", "/backup-policies?limit=100",
                 "/backup-runs?limit=100"):
        st, p = api("GET", path, tok)
        rows = p.get("data") if st == 200 else None
        out[path.split("?")[0]] = sorted(r["id"] for r in rows) if isinstance(rows, list) else f"HTTP {st}"
    return out


def diff(a, b):
    return {k: [a.get(k), b.get(k)] for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)}


# ---------------------------------------------------------------- 0.7.0 = aa92403 + minimal packaging patch
HEALTH_TS = """import { Controller, Get } from '@nestjs/common';
import { Public } from '../common/decorators';
import { PrismaService } from '../common/prisma.service';

/**
 * P8 packaging patch for the 0.7.0 lab build (scripts/lab/e2e_p8_upgrade.py): liveness for the
 * release compose healthcheck. 0.8.0 ships the real VersionController (GET /version + /health).
 */
@Public()
@Controller()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('health')
  async health(): Promise<{ status: 'ok'; db: 'ok'; version: string }> {
    await this.prisma.$queryRaw`SELECT 1`;
    return { status: 'ok', db: 'ok', version: process.env.PPANEL_VERSION ?? 'unknown' };
  }
}
"""


def replace_once(path, old, new):
    s = open(path).read()
    assert s.count(old) == 1, f"patch anchor not unique/missing in {path}: {old[:60]!r}"
    open(path, "w").write(s.replace(old, new))


def patch_v070(wt):
    for rel in ("apps/api/Dockerfile", "apps/api/docker-entrypoint.sh", "apps/web/Dockerfile", ".dockerignore"):
        shutil.copy2(os.path.join(ROOT, rel), os.path.join(wt, rel))
    # prisma CLI is a runtime dependency (the image runs `prisma migrate deploy`) — package.json + lockfile
    pj = os.path.join(wt, "apps/api/package.json")
    replace_once(pj, '    "prisma": "6.19.3",\n    "supertest"', '    "supertest"')
    replace_once(pj, '    "otplib": "12.0.1",\n', '    "otplib": "12.0.1",\n    "prisma": "6.19.3",\n')
    lock = os.path.join(wt, "pnpm-lock.yaml")
    blk = "      prisma:\n        specifier: 6.19.3\n        version: 6.19.3(typescript@5.9.3)\n"
    replace_once(lock, "        version: 9.39.5(jiti@2.7.0)\n" + blk, "        version: 9.39.5(jiti@2.7.0)\n")
    replace_once(lock, "      otplib:\n        specifier: 12.0.1\n        version: 12.0.1\n",
                 "      otplib:\n        specifier: 12.0.1\n        version: 12.0.1\n" + blk)
    # Next.js standalone output only when the image build asks for it (same change as 0.8.0)
    nc = os.path.join(wt, "apps/web/next.config.ts")
    replace_once(nc, "import type { NextConfig } from 'next';\n",
                 "import path from 'node:path';\nimport type { NextConfig } from 'next';\n")
    replace_once(nc, "const nextConfig: NextConfig = {\n",
                 "const standalone = process.env.NEXT_OUTPUT_STANDALONE === '1';\n\nconst nextConfig: NextConfig = {\n"
                 "  ...(standalone\n    ? { output: 'standalone' as const, outputFileTracingRoot: "
                 "path.resolve(process.cwd(), '../..') }\n    : {}),\n")
    # public GET /api/v1/health for the compose healthcheck / install.sh / upgrade.sh
    os.makedirs(os.path.join(wt, "apps/api/src/health"), exist_ok=True)
    open(os.path.join(wt, "apps/api/src/health/health.controller.ts"), "w").write(HEALTH_TS)
    am = os.path.join(wt, "apps/api/src/app.module.ts")
    replace_once(am, "import { UsersService } from './users/users.service';\n",
                 "import { UsersService } from './users/users.service';\n"
                 "import { HealthController } from './health/health.controller';\n")
    replace_once(am, "      controllers: [\n        SetupController,\n",
                 "      controllers: [\n        HealthController,\n        SetupController,\n")


def build_v070(wt_parent):
    wt = os.path.join(wt_parent, "v070")
    if os.path.exists(wt):
        sh("git", "-C", ROOT, "worktree", "remove", "--force", wt, check=False)
    sh("git", "-C", ROOT, "worktree", "add", "--detach", wt, OLD_COMMIT)
    try:
        patch_v070(wt)
        sh("git", "-C", wt, "add", "-A")
        patch = sh("git", "-C", wt, "diff", "--cached", "--stat", "--patch").stdout
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        with open(PATCH_OUT, "w") as f:
            f.write(f"# pPanel {OLD} lab build = {OLD_COMMIT} + this minimal P8 packaging patch "
                    "(scripts/lab/e2e_p8_upgrade.py patch_v070)\n" + patch)
        os.makedirs(os.path.join(DIST_OLD, "images"), exist_ok=True)
        bdate = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        arch = "arm64" if os.uname().machine in ("arm64", "aarch64") else "amd64"
        for svc in ("api", "web"):
            tag = f"ppanel-{svc}:{OLD}"
            sh("docker", "buildx", "build", "--platform", f"linux/{arch}", "--load", "-f",
               os.path.join(wt, f"apps/{svc}/Dockerfile"), "-t", tag, "--build-arg", f"PPANEL_VERSION={OLD}",
               "--build-arg", f"PPANEL_COMMIT={OLD_COMMIT}", "--build-arg", f"PPANEL_BUILD_DATE={bdate}", wt,
               timeout=3600)
            sh("docker", "save", "-o", os.path.join(DIST_OLD, "images", f"ppanel-{svc}-{OLD}.tar"), tag)
            sh("docker", "rmi", tag)  # the tar is what the lab center loads; keep the host disk free
        sh("make", "-C", os.path.join(wt, "apps/agent"), "cross", f"VERSION={OLD}", f"COMMIT={OLD_COMMIT}",
           f"BUILDDATE={bdate}", "TARGETS=linux/amd64 linux/arm64", f"BIN={DIST_OLD}", timeout=1800)
    finally:
        sh("git", "-C", ROOT, "worktree", "remove", "--force", wt, check=False)
        sh("git", "-C", ROOT, "worktree", "prune", check=False)
    sh("bash", "-c", "shasum -a 256 ppanel-agent-linux-amd64 ppanel-agent-linux-arm64 > SHA256SUMS", cwd=DIST_OLD)
    sh("openssl", "pkeyutl", "-sign", "-inkey", LAB_KEY, "-rawin", "-in", os.path.join(DIST_OLD, "SHA256SUMS"),
       "-out", os.path.join(DIST_OLD, "SHA256SUMS.sig"))
    shutil.copy2(os.path.join(DIST_NEW, "ppanel-release.pub"), os.path.join(DIST_OLD, "ppanel-release.pub"))


def main():
    os.makedirs(WORK, mode=0o700, exist_ok=True)
    for n in ("install-agent.sh", "ppanel-release.pub", f"ppanel-center-{NEW}.tar.gz", "images"):
        if not os.path.exists(os.path.join(DIST_NEW, n)):
            raise SystemExit(f"{DIST_NEW}/{n} missing: run scripts/release/build.sh --save-images --sign-key {LAB_KEY}")
    wt_parent = sys.argv[sys.argv.index("--worktree") + 1] if "--worktree" in sys.argv else tempfile.mkdtemp(
        prefix="ppanel-v070-")
    if os.path.abspath(wt_parent).startswith(ROOT + os.sep):
        raise SystemExit("--worktree must be outside the repository tree")

    # ------------------------------------------------------------ 1. 0.7.0 artifacts
    have_old = all(os.path.exists(os.path.join(DIST_OLD, n)) for n in (
        "SHA256SUMS", "SHA256SUMS.sig", "ppanel-agent-linux-arm64", f"images/ppanel-api-{OLD}.tar",
        f"images/ppanel-web-{OLD}.tar"))
    t0 = time.time()
    if "--skip-build" not in sys.argv or not have_old:
        build_v070(wt_parent)
    wt_gone = os.path.join(wt_parent, "v070") not in sh("git", "-C", ROOT, "worktree", "list").stdout
    sig = sh("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", os.path.join(DIST_OLD, "ppanel-release.pub"),
             "-rawin", "-in", os.path.join(DIST_OLD, "SHA256SUMS"), "-sigfile", os.path.join(DIST_OLD, "SHA256SUMS.sig"))
    patch_files = re.findall(r"^diff --git a/(\S+)", open(PATCH_OUT).read(), re.M)
    meta["v070PackagingPatch"] = {"base": OLD_COMMIT, "file": os.path.relpath(PATCH_OUT, ROOT), "files": patch_files}
    step(f"{OLD} built from {OLD_COMMIT} + packaging patch in a temporary worktree (removed); agents signed",
         "Verified" in sig.stdout and wt_gone and len(patch_files) == 9, buildSec=round(time.time() - t0),
         patchedFiles=patch_files, images={n: os.path.getsize(os.path.join(DIST_OLD, "images", n))
                                           for n in sorted(os.listdir(os.path.join(DIST_OLD, "images")))})

    # ------------------------------------------------------------ 2. fresh ubuntu lab, install 0.7.0
    svcs = ["ubuntu-center"] + [n.replace("ppanel-lab-", "") for n in NODES]
    sh(*COMPOSE, "rm", "-sfv", *svcs, check=False)
    for v in ("ppanel-lab_ubuntu-center-docker", "ppanel-lab_ubuntu-center-containerd"):
        sh("docker", "volume", "rm", v, check=False)
    sh(*COMPOSE, "up", "-d", "--build", "--no-deps", *svcs)
    step("fresh Ubuntu systemd hosts up, nothing pPanel installed",
         all(wait_systemd(c) for c in [CENTER] + NODES)
         and dx(CENTER, "test ! -e /opt/ppanel", check=False).returncode == 0)

    dx(CENTER, "mkdir -p /root/release /root/v070")
    for n in [f"ppanel-center-{NEW}.tar.gz", "SHA256SUMS", "SHA256SUMS.sig", "ppanel-release.pub"]:
        sh("docker", "cp", os.path.join(DIST_NEW, n), f"{CENTER}:/root/release/")
    sh("docker", "cp", os.path.join(DIST_OLD, "images"), f"{CENTER}:/root/v070/")
    dx(CENTER, "sha256sum -c --ignore-missing SHA256SUMS && openssl pkeyutl -verify -pubin -inkey ppanel-release.pub "
               f"-rawin -in SHA256SUMS -sigfile SHA256SUMS.sig && tar xzf ppanel-center-{NEW}.tar.gz", workdir="/root/release")
    p = dx(CENTER, f"./install.sh --version {OLD} --domain {DOMAIN} --tls internal --image-prefix '' "
                   "--images-dir /root/v070/images --no-start", check=False, timeout=900, workdir=BUNDLE)
    up = dx(CENTER, f"{CC} up -d --quiet-pull --wait --wait-timeout 420", check=False, timeout=900)
    dx(CENTER, "rm -rf /root/v070/images")
    for _ in range(30):
        if dx(CENTER, f"{CC} exec -T proxy test -s /data/caddy/pki/authorities/local/root.crt", check=False).returncode == 0:
            break
        time.sleep(1)
    dx(CENTER, f"{CC} exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > /opt/ppanel/secrets/caddy-root.crt")
    ca_local = os.path.join(WORK, "caddy-root-upgrade.crt")
    sh("docker", "cp", f"{CENTER}:/opt/ppanel/secrets/caddy-root.crt", ca_local)
    for node in NODES:
        dx(node, "mkdir -p /root/agent")
        sh("docker", "cp", ca_local, f"{node}:{CACERT}")
    os.remove(ca_local)
    st_h, h = api("GET", "/health")
    st_v, _ = api("GET", "/version")
    pins_old = env_lines(["PPANEL_VERSION", "PPANEL_API_IMAGE", "PPANEL_WEB_IMAGE", "PPANEL_API_IMAGE_ID",
                          "PPANEL_WEB_IMAGE_ID"])
    step(f"{OLD} installed with the {NEW} bundle (install.sh --version {OLD} --no-start + compose up); "
         f"health OK through the TLS proxy; no /version before 0.8",
         p.returncode == 0 and up.returncode == 0 and st_h == 200 and data(h).get("version") == OLD and st_v == 404
         and pins_old["PPANEL_VERSION"] == OLD, health=data(h), versionStatus=st_v, pins=pins_old,
         tail=None if p.returncode == 0 and up.returncode == 0 else (p.stderr + up.stderr)[-1500:])

    # ------------------------------------------------------------ 3. first boot, users with 2FA
    setup_token = dx(CENTER, "awk -F= '/^PPANEL_SETUP_TOKEN=/{print $2}' /opt/ppanel/.env").stdout.strip()
    owner, opw = "owner@ppanel.lab", "P8u-" + secrets.token_urlsafe(18)
    st, _ = api("POST", "/setup/bootstrap", body={"email": owner, "password": opw, "displayName": "Owner",
                                                  "setupToken": setup_token})
    _, lg = api("POST", "/auth/login", body={"email": owner, "password": opw})
    tok = data(lg)["accessToken"]
    _, su = api("POST", "/auth/mfa/totp/setup", tok)
    osecret = re.search(r"secret=([A-Z2-7]+)", data(su)["otpauthUrl"]).group(1)
    st_c, _ = api("POST", "/auth/mfa/totp/confirm", tok, {"code": totp(osecret)})
    ops, ppw = "ops@ppanel.lab", "P8u-" + secrets.token_urlsafe(18)
    st_u, _ = api("POST", "/users", tok, {"email": ops, "password": ppw, "displayName": "Ops admin",
                                          "bindings": [{"roleKey": "ops_admin", "scopeType": "global"}]})
    _, lg = api("POST", "/auth/login", body={"email": ops, "password": ppw})
    otok = data(lg)["accessToken"]
    _, su = api("POST", "/auth/mfa/totp/setup", otok)
    psecret = re.search(r"secret=([A-Z2-7]+)", data(su)["otpauthUrl"]).group(1)
    st_c2, _ = api("POST", "/auth/mfa/totp/confirm", otok, {"code": totp(psecret)})
    tok, info = login_2fa(owner, opw, osecret)
    step(f"{OLD}: owner (setup token) + ops admin, both with TOTP; login requires the second factor",
         st == 201 and st_c == 200 and st_u == 201 and st_c2 == 200 and tok, login=info)

    # ------------------------------------------------------------ 4. two 0.7.0 agents
    for node in NODES:
        dx(node, "mkdir -p /root/agent070")
        for n in ["ppanel-agent-linux-arm64", "ppanel-agent-linux-amd64", "SHA256SUMS", "SHA256SUMS.sig",
                  "ppanel-release.pub"]:
            sh("docker", "cp", os.path.join(DIST_OLD, n), f"{node}:/root/agent070/")
        sh("docker", "cp", os.path.join(DIST_NEW, "install-agent.sh"), f"{node}:/root/agent/install-agent.sh")
    server_ids = []
    for i, node in enumerate(NODES):
        _, e = api("POST", "/enrollments", tok, {"name": f"p8u-{node[-6:]}", "environment": "uat", "ttlMinutes": 15})
        p = dx(node, f"bash /root/agent/install-agent.sh --center-url https://{DOMAIN} --token {data(e)['token']} "
                     f"--from-dir /root/agent070 --pubkey /root/agent070/ppanel-release.pub --ca-file {CACERT} 2>&1",
               check=False, timeout=180)
        m = re.search(r"serverId=([0-9a-f-]{36})", p.stdout)
        server_ids.append(m.group(1) if m else None)
        if not m:
            step(f"install-agent.sh {OLD} on {node}", False, tail=p.stdout[-1200:])

    def all_online(want_version=None, newer_than=None):
        out = []
        for sid in server_ids:
            st, s = api("GET", f"/servers/{sid}", tok)
            d = data(s)
            if st != 200 or d.get("status") not in CONNECTED:
                return None
            if want_version and d.get("agentVersion") != want_version.get(sid, d.get("agentVersion")):
                return None
            if newer_than and (d.get("lastHeartbeatAt") or "") <= newer_than:
                return None
            out.append(d)
        return out
    srv = poll(all_online, 90)
    step(f"two {OLD} agents enrolled with the {NEW} install-agent.sh, online over mTLS",
         srv and all(s["agentVersion"] == OLD for s in srv),
         agents=[(s["hostname"], s["agentVersion"], s["status"]) for s in srv or []])

    # ------------------------------------------------------------ 5. data
    st, sc = api("POST", f"/servers/{server_ids[0]}/discovery-scans", tok, {})
    scan = poll(lambda: (lambda d: d if d.get("status") not in (None, "running", "queued") else None)(
        data(api("GET", f"/discovery-scans/{data(sc)['scanId']}", tok)[1])), 120)
    _, fnd = api("GET", f"/discovery-scans/{scan['id']}/findings?limit=100", tok)
    target = next(f for f in fnd["data"] if "lab-site.example.lab" in (f.get("domains") or []))
    st_i, im = api("POST", f"/discovery-scans/{scan['id']}/import", tok, {"findingIds": [target["id"]], "mode": "observed"})
    app_id = data(im)["applications"][0]["id"]
    st_ch, ch = api("POST", "/notification-channels", tok, {"type": "email", "name": "p8u-oncall-mail",
                                                            "config": {"to": ["oncall@ppanel.lab"]}})
    st_r, rule = api("POST", "/alert-rules", tok, {"name": "p8u node-2 offline", "kind": "server_offline",
                                                   "scopeType": "server", "scopeId": server_ids[1], "severity": "critical",
                                                   "forSec": 300, "channelIds": [data(ch)["id"]]})
    st_repo, repo = api("POST", "/backup-repositories", tok, {"name": "p8u-repo", "kind": "rest",
                                                              "baseUrl": "https://backup.ppanel.lab:8000"})
    if st_repo != 201:
        step("backup repository created", False, status=st_repo, body=repo)
    repo_id = data(repo)["id"]
    acc = []
    for sid in server_ids:
        acc.append(api("PUT", f"/backup-repositories/{repo_id}/servers/{sid}", tok, {
            "restUser": "p8u-" + sid[-8:], "restPassword": secrets.token_hex(16), "repoPassword": secrets.token_hex(16)})[0])
        acc.append(api("POST", f"/backup-repositories/{repo_id}/servers/{sid}/initialized", tok, {"initialized": True})[0])
    pols = []
    for i, sid in enumerate(server_ids):
        st_p, pol = api("POST", "/backup-policies", tok, {
            "name": f"p8u-site-{i + 1}", "serverId": sid, "repositoryId": repo_id,
            "targets": [{"type": "paths", "paths": ["/var/www/lab-site"]}],
            "schedule": {"cron": "0 3 * * *", "timezone": "Asia/Bangkok"}, "verify": {"afterBackup": "none"}})
        pols.append(data(pol).get("id") if st_p == 201 else None)
    st_run, r = api("POST", f"/backup-policies/{pols[0]}/run", tok, None, {"Idempotency-Key": str(uuid.uuid4())})
    run0 = data(r).get("run", {})
    run_done = poll(lambda: (lambda d: d if d.get("status") in RUN_DONE else None)(
        data(api("GET", f"/backup-runs/{run0.get('id')}", tok)[1])), 180, 3)
    step(f"{OLD} data: nginx import -> application, e-mail channel, alert rule, backup repository + access, "
         "2 policies, 1 run record",
         st_i == 201 and st_ch == 201 and st_r == 201 and st_repo == 201 and all(c in (200, 201) for c in acc)
         and all(pols) and st_run in (200, 202) and run_done,
         statuses={"import": st_i, "channel": st_ch, "rule": st_r, "repo": st_repo, "access": acc, "policies": pols,
                   "run": st_run},
         applicationId=app_id, alertRuleId=data(rule).get("id"), runStatus=(run_done or {}).get("status"),
         runError=json.dumps((run_done or {}).get("error"))[:200],
         note="full restic run not attempted: the lab nodes have no restic/rest-server; the run record "
              "(terminal, with its job) is the backup data carried through the upgrade")

    # ------------------------------------------------------------ 6. snapshot before the upgrade
    snap0 = checksums()
    list0 = listings(tok)
    env0 = dx(CENTER, "sha256sum /opt/ppanel/.env | cut -c1-64").stdout.strip()
    ids0 = containers()
    bk0 = backups_list()
    meta["preUpgradeSnapshot"] = {"tables": snap0, "listingCounts": {k: len(v) for k, v in list0.items()}}
    step("pre-upgrade snapshot: checksums of 16 key tables + API listings",
         all(isinstance(v, list) and v for v in list0.values()), counts={k: v.split(":")[0] for k, v in snap0.items()})

    # ------------------------------------------------------------ 7. forced failures stop before anything changes
    bad = []
    for ver, how in (("0.8.0-rc.99", "missing"), ("0.8.0-rc.98", "mislabelled")):
        dx(CENTER, f"rm -rf /root/bad && cp -a {BUNDLE} /root/bad && echo {ver} > /root/bad/VERSION")
        if how == "mislabelled":  # a tag that exists but carries another release's image
            dx(CENTER, f"docker tag ppanel-api:{OLD} ppanel-api:{ver} && docker tag ppanel-web:{OLD} ppanel-web:{ver}")
        p = dx(CENTER, f"/root/bad/upgrade.sh {ver}", check=False, timeout=600)
        if how == "mislabelled":
            dx(CENTER, f"docker rmi ppanel-api:{ver} ppanel-web:{ver} >/dev/null")
        st_h, h = api("GET", "/health")
        bad.append({"version": ver, "case": how, "exit": p.returncode,
                    "error": next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "")[:220],
                    "envUnchanged": dx(CENTER, "sha256sum /opt/ppanel/.env | cut -c1-64").stdout.strip() == env0,
                    "containersUnchanged": containers() == ids0, "noNewDump": backups_list() == bk0,
                    "stillServing": st_h == 200 and data(h).get("version") == OLD})
    dx(CENTER, "rm -rf /root/bad")
    step("forced failures (image tag missing; tag holds a different release) stop upgrade.sh BEFORE stopping, "
         f"dumping or migrating; {OLD} keeps running untouched",
         all(b["exit"] != 0 and "nothing changed" in b["error"] and b["envUnchanged"] and b["containersUnchanged"]
             and b["noNewDump"] and b["stillServing"] for b in bad), cases=bad)

    # ------------------------------------------------------------ 8. upgrade
    dx(CENTER, "mkdir -p /root/v080")
    sh("docker", "cp", os.path.join(DIST_NEW, "images"), f"{CENTER}:/root/v080/")
    hb_before = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    t0 = time.time()
    p = dx(CENTER, f"./upgrade.sh {NEW} --images-dir /root/v080/images", check=False, timeout=1500, workdir=BUNDLE)
    upgrade_sec = round(time.time() - t0)
    dx(CENTER, "rm -rf /root/v080/images")
    summary = next((json.loads(ln) for ln in p.stdout.splitlines() if ln.startswith("{")), {})
    dump = summary.get("dump", "")
    rb_cmd = re.search(r"rollback\.sh \S+ \S+", p.stderr)
    modes = dx(CENTER, f"stat -c '%a %n' {dump} {dump[:-7]}.release.tar.gz 2>&1", check=False).stdout.split("\n")
    st_v, ver = api("GET", "/version")
    v = data(ver)
    pins_new = env_lines(["PPANEL_VERSION", "PPANEL_API_IMAGE", "PPANEL_WEB_IMAGE"])
    meta["upgrade"] = {"sec": upgrade_sec, "dump": dump, "rollbackCommand": rb_cmd.group(0) if rb_cmd else None,
                       "version": v}
    step(f"upgrade.sh {NEW}: pre-flight, images loaded + label-checked, api/web stopped, pre-upgrade dump (0600) "
         "+ release snapshot, pins, migrate deploy, healthy, /version reports the new release",
         p.returncode == 0 and summary.get("upgraded") and summary.get("from") == OLD
         and re.search(rf"/opt/ppanel/backups/pre-upgrade-{re.escape(OLD)}-{re.escape(NEW)}-\d{{8}}T\d{{6}}Z\.sql\.gz$", dump)
         and all(m.startswith("600 ") for m in modes if m) and st_v == 200 and v.get("version") == NEW
         and v.get("agentProtocol") == "1" and v.get("minAgentVersion") == OLD
         and v.get("schemaVersion") == snap0["_prisma_migrations"].split(":")[1]
         and pins_new["PPANEL_VERSION"] == NEW and "@sha256:" in pins_new["PPANEL_API_IMAGE"],
         sec=upgrade_sec, summary=summary, version=v, pins=pins_new, rollbackCommand=meta["upgrade"]["rollbackCommand"],
         tail=None if p.returncode == 0 else p.stderr[-2000:])

    # ------------------------------------------------------------ 9. everything retained
    snap1 = checksums()
    tok, info = login_2fa(owner, opw, osecret)
    list1 = listings(tok) if tok else {}
    otok, oinfo = login_2fa(ops, ppw, psecret)
    step("data retained: same ids/counts/content (16 table checksums, 8 API listings); schema unchanged "
         "(0.8.0-rc.1 adds no migration)", snap1 == snap0 and list1 == list0, tableDiff=diff(snap0, snap1),
         listingDiff=diff(list0, list1))
    step("login with password + TOTP still works for both users after the upgrade", tok and otok,
         owner=info, ops=oinfo)
    srv = poll(lambda: all_online(newer_than=hb_before), 120)
    step(f"both {OLD} agents reconnected (fresh heartbeats) and are NOT outdated (minAgentVersion {OLD} = N-1)",
         srv and all(s["agentVersion"] == OLD and s.get("agentOutdated") is False for s in srv),
         agents=[(s["hostname"], s["agentVersion"], s.get("agentOutdated"), s["lastHeartbeatAt"]) for s in srv or []])

    def run_policy(pid):
        st, r = api("POST", f"/backup-policies/{pid}/run", tok, None, {"Idempotency-Key": str(uuid.uuid4())})
        return st, r

    def wait_run(rid):
        return poll(lambda: (lambda d: d if d.get("status") in RUN_DONE else None)(
            data(api("GET", f"/backup-runs/{rid}", tok)[1])), 180, 3)

    def job(sid, typ, params):
        st, j = api("POST", f"/servers/{sid}/jobs", tok, {"type": typ, "params": params},
                    {"Idempotency-Key": str(uuid.uuid4())})
        jid = data(j).get("jobId")
        done = poll(lambda: (lambda d: d if d.get("status") in JOB_DONE else None)(
            data(api("GET", f"/servers/{sid}/jobs/{jid}", tok)[1])), 120) if jid else None
        return st, (done or {}).get("status"), data(j).get("error") or j.get("error", {}).get("code")

    st_m, r = run_policy(pols[1])
    mrun = wait_run(data(r).get("run", {}).get("id")) if st_m in (200, 202) else None
    step(f"mutating job (backup.run) accepted for a {OLD} agent on the {NEW} Center and executed by it",
         st_m == 202 and mrun is not None, status=st_m, runStatus=(mrun or {}).get("status"))

    ids1, env1, bk1 = containers(), dx(CENTER, "sha256sum /opt/ppanel/.env").stdout, backups_list()
    p = dx(CENTER, f"./upgrade.sh {NEW}", check=False, timeout=300, workdir=BUNDLE)
    step("upgrade.sh re-run on the installed version is a no-op (exit 0, no dump, .env + containers untouched)",
         p.returncode == 0 and "nothing to do" in p.stderr and bk1 == backups_list() and len(bk1) == len(bk0) + 2
         and containers() == ids1 and dx(CENTER, "sha256sum /opt/ppanel/.env").stdout == env1,
         out=p.stderr.strip()[-200:])
    dx(CENTER, f"rm -rf /root/old && cp -a {BUNDLE} /root/old && echo {OLD} > /root/old/VERSION")
    p = dx(CENTER, f"/root/old/upgrade.sh {OLD}", check=False, timeout=300)
    dx(CENTER, "rm -rf /root/old")
    st_v, ver = api("GET", "/version")
    step(f"downgrade with upgrade.sh {OLD} is refused (points to rollback.sh); {NEW} keeps running",
         p.returncode != 0 and "refusing to downgrade" in p.stderr and "rollback.sh" in p.stderr
         and data(ver).get("version") == NEW, error=p.stderr.strip().splitlines()[-1][:200])

    # ------------------------------------------------------------ 10. one agent to the new release (no re-enroll)
    n1, s1 = NODES[0], server_ids[0]
    cert0 = sql(f"SELECT serial FROM agent_certificates WHERE server_id = '{s1}' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1;")
    dx(n1, "mkdir -p /root/agent080")
    for n in ["ppanel-agent-linux-arm64", "ppanel-agent-linux-amd64", "SHA256SUMS", "SHA256SUMS.sig", "ppanel-release.pub"]:
        sh("docker", "cp", os.path.join(DIST_NEW, n), f"{n1}:/root/agent080/")
    p = dx(n1, "bash /root/agent/install-agent.sh --from-dir /root/agent080 --pubkey /root/agent080/ppanel-release.pub 2>&1",
           check=False, timeout=180)
    srv = poll(lambda: all_online(want_version={s1: NEW}), 90)
    cert1 = sql(f"SELECT serial FROM agent_certificates WHERE server_id = '{s1}' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1;")
    nsrv = sql("SELECT count(*) FROM servers;")
    step(f"node-1 agent upgraded to {NEW} with install-agent.sh (verified, not re-enrolled): same server id, "
         "same mTLS certificate, online",
         p.returncode == 0 and "signature OK" in p.stdout and "not re-enrolling" in p.stdout and srv
         and cert0 == cert1 and nsrv == "2", serverCount=nsrv, certSerialUnchanged=cert0 == cert1,
         agents=[(s["hostname"], s["agentVersion"], s.get("agentOutdated")) for s in srv or []])

    # ------------------------------------------------------------ 11. mixed-version fleet
    ro = [job(sid, "inventory.collect", {}) for sid in server_ids]
    mut = []
    for pid in pols:
        st_m, r = run_policy(pid)
        mut.append((st_m, (wait_run(data(r).get("run", {}).get("id")) or {}).get("status") if st_m == 202 else None))
    step(f"mixed fleet ({NEW} + {OLD} agents): read-only jobs succeed and mutating jobs are accepted on both",
         all(r[0] == 202 and r[1] == "succeeded" for r in ro) and all(m[0] == 202 and m[1] in RUN_DONE for m in mut),
         readOnly=ro, mutating=mut)

    # strict policy: PPANEL_MIN_AGENT_VERSION = the new release → the 0.7.0 agent is outdated
    dx(CENTER, f"sed -i 's/^PPANEL_MIN_AGENT_VERSION=.*/PPANEL_MIN_AGENT_VERSION={NEW}/' /opt/ppanel/.env && "
               f"{CC} up -d --wait --wait-timeout 300 api proxy", timeout=600)
    _, v2 = api("GET", "/version")
    _, sv = api("GET", f"/servers/{server_ids[1]}", tok)
    st_old, r_old = run_policy(pols[1])
    st_new, r_new = run_policy(pols[0])
    if st_new == 202:
        wait_run(data(r_new).get("run", {}).get("id"))
    ro_old = job(server_ids[1], "inventory.collect", {})
    dx(CENTER, "sed -i 's/^PPANEL_MIN_AGENT_VERSION=.*/PPANEL_MIN_AGENT_VERSION=/' /opt/ppanel/.env && "
               f"{CC} up -d --wait --wait-timeout 300 api proxy", timeout=600)
    _, v3 = api("GET", "/version")
    err = r_old.get("error", {})
    step(f"PPANEL_MIN_AGENT_VERSION={NEW}: {OLD} agent flagged outdated, mutating job -> 409 AGENT_OUTDATED, "
         f"read-only job still runs, {NEW} agent unaffected; reset to the N-1 default afterwards",
         data(v2).get("minAgentVersion") == NEW and data(sv).get("agentOutdated") is True and st_old == 409
         and err.get("code") == "AGENT_OUTDATED" and st_new == 202 and ro_old[0] == 202 and ro_old[1] == "succeeded"
         and data(v3).get("minAgentVersion") == OLD,
         outdatedError={"status": st_old, "code": err.get("code"), "details": err.get("details")},
         newAgentRun=st_new, readOnlyOnOutdated=ro_old)

    # post-upgrade writes that the rollback must discard
    st_mk, mk = api("POST", "/alert-rules", tok, {"name": "p8u post-upgrade marker", "kind": "server_offline",
                                                  "scopeType": "server", "scopeId": server_ids[0], "severity": "warning",
                                                  "forSec": 600, "channelIds": []})
    marker = data(mk).get("id")
    after_up = checksums()
    step("post-upgrade writes exist (marker alert rule, new backup runs, agent version change)",
         st_mk == 201 and after_up != snap0, changed=sorted(diff(snap0, after_up)))

    # ------------------------------------------------------------ 12. rollback to 0.7.0 with the pre-upgrade dump
    hb_before = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    t0 = time.time()
    p = dx(CENTER, f"/opt/ppanel/rollback.sh {dump} {OLD} --yes", check=False, timeout=1200)
    rollback_sec = round(time.time() - t0)
    rsum = next((json.loads(ln) for ln in p.stdout.splitlines() if ln.startswith("{")), {})
    snap2 = checksums()
    st_h, h = api("GET", "/health")
    st_v, _ = api("GET", "/version")
    pins_back = env_lines(list(pins_old))
    meta["rollback"] = {"sec": rollback_sec, "summary": rsum}
    step(f"rollback.sh <pre-upgrade dump> {OLD}: safety dump, restore, previous pins; Center reports {OLD}",
         p.returncode == 0 and rsum.get("rolledBack") and rsum.get("to") == OLD and st_h == 200
         and data(h).get("version") == OLD and st_v == 404 and pins_back == pins_old,
         sec=rollback_sec, summary=rsum, health=data(h), pinsRestored=pins_back == pins_old,
         tail=None if p.returncode == 0 else p.stderr[-2000:])
    step("database equals the pre-upgrade snapshot (16 table checksums + schema); post-upgrade marker gone",
         snap2 == snap0 and sql(f"SELECT count(*) FROM alert_rules WHERE id = '{marker}';") == "0",
         tableDiff=diff(snap0, snap2))
    tok, info = login_2fa(owner, opw, osecret)
    list2 = listings(tok) if tok else {}
    step(f"{OLD} after rollback: 2FA login works, API listings equal the pre-upgrade ones", tok and list2 == list0,
         login=info, listingDiff=diff(list0, list2))
    srv = poll(lambda: all_online(newer_than=hb_before, want_version={server_ids[0]: NEW, server_ids[1]: OLD}), 120)
    step(f"both agents reconnect to the rolled-back {OLD} Center ({NEW} agent newer than the Center: same protocol "
         "major, accepted)", srv is not None,
         agents=[(s["hostname"], s["agentVersion"], s["status"]) for s in srv or []])

    du = dx(CENTER, "du -sh /var/lib/docker /var/lib/containerd 2>/dev/null | tr '\\t\\n' ': '; "
                    "ls -l /opt/ppanel/backups | tail -n +2 | awk '{print $1, $5, $9}' | tr '\\n' ';'").stdout.strip()
    step("lab disk used inside the center host + backups dir", True, du=du)

    if "--keep-dist" not in sys.argv:
        shutil.rmtree(os.path.join(DIST_OLD, "images"), ignore_errors=True)
    if "--down" in sys.argv:
        sh(*COMPOSE, "rm", "-sfv", *svcs, check=False)
        for v in ("ppanel-lab_ubuntu-center-docker", "ppanel-lab_ubuntu-center-containerd"):
            sh("docker", "volume", "rm", v, check=False)
    finish(0)


if __name__ == "__main__":
    main()
