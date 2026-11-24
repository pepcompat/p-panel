#!/usr/bin/env python3
"""pPanel P8-T01 (LAB SUBSTITUTE): fresh install of the Center + two agents from the release artifacts.

No VMs are available (docs/RELEASE_CONTRACT.md §6). The "fresh Ubuntu 24.04 hosts" are the privileged
systemd containers of compose profile `ubuntu` (infra/lab/ubuntu): ppanel-lab-ubuntu-center (Docker
Engine inside) and ppanel-lab-ubuntu-node-1/-2 (nginx). Results are reported as PASS (lab substitute).

Journey: build release (images + agent binaries + bundle + SHA256SUMS, signed with a throw-away lab key)
-> verify checksums + signature -> recreate the ubuntu lab from scratch -> copy bundle + images
(docker save/load) into the center -> install.sh -> health + /version through the TLS proxy -> first
boot (setup token) -> owner enables TOTP, re-login with 2FA -> two enrollment tokens -> tampered
binary / tampered SHA256SUMS refused -> install-agent.sh --from-dir on both nodes -> both online ->
smoke (servers, facts, read-only nginx discovery with unchanged config, fleet metrics; Prometheus/Loki
reads skipped: observability profile not enabled) -> systemd hardening active + survives restart ->
install.sh and install-agent.sh re-run (idempotent) -> install-agent.sh --uninstall on node-2.

Run: python3 -I scripts/lab/e2e_p8_install.py [--out docs/evidence/2026-11-24/p8-t01-install.json]
     [--skip-build] [--down]
Lab only: talks to the ppanel-lab-ubuntu-* containers through `docker exec`. Never point it at a real host.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VERSION = open(os.path.join(ROOT, "VERSION")).read().strip()
DIST = os.path.join(ROOT, "dist-release", VERSION)
WORK = os.path.join(ROOT, ".lab", "p8")
COMPOSE = ["docker", "compose", "-p", "ppanel-lab", "-f", os.path.join(ROOT, "infra/compose/lab.yml"),
           "--profile", "ubuntu"]
CENTER = "ppanel-lab-ubuntu-center"
NODES = ["ppanel-lab-ubuntu-node-1", "ppanel-lab-ubuntu-node-2"]
DOMAIN = "center.ppanel.lab"
URL = f"https://{DOMAIN}/api/v1"
CACERT = "/root/agent/caddy-root.crt"
# connected + fresh heartbeat; `degraded` = online with cpu/mem/disk >= 95 % (shared lab VM disk)
CONNECTED = ("online", "degraded")
results = []
started = time.time()


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
                "test": "P8-T01 fresh install (Center + 2 agents)",
                "result": ("PASS (lab substitute)" if code == 0 else "FAIL"),
                "labSubstitute": True,
                "note": "Ubuntu 24.04 systemd containers (infra/lab/ubuntu), not VMs; P8-T01 on a real VM stays BLOCKED",
                "version": VERSION,
                "ranAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "durationSec": round(time.time() - started, 1),
                "steps": results,
            }, f, indent=2)
            f.write("\n")
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} steps passed")
    sys.exit(code)


def sh(*argv, check=True, timeout=900, stdin=None):
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, input=stdin)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed ({p.returncode}): {argv[:6]}: {(p.stderr or p.stdout)[-800:]}")
    return p


def dx(container, cmd, check=True, timeout=900, workdir=None):
    argv = ["docker", "exec"] + (["-w", workdir] if workdir else []) + [container, "bash", "-c", cmd]
    return sh(*argv, check=check, timeout=timeout)


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


def poll(fn, timeout=90, every=2.0):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(every)
    return last


def totp(secret_b32, step_offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int(time.time()) // 30 + step_offset
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def nginx_state(node):
    return dx(node, "find /etc/nginx -type f -o -type l | sort | xargs sha256sum | sha256sum | cut -c1-16; "
                    "cat /run/nginx.pid").stdout.split()


def wait_systemd(container):
    def ready():
        p = dx(container, "systemctl is-system-running", check=False)
        return p.stdout.strip() in ("running", "degraded")
    return poll(ready, 90, 1)


def main():
    os.makedirs(WORK, mode=0o700, exist_ok=True)

    # ------------------------------------------------------------ 1. build release artifacts
    key = os.path.join(WORK, "lab-release-signing.key")
    if not os.path.exists(key):
        sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", key)
        os.chmod(key, 0o600)
    if "--skip-build" not in sys.argv:
        t0 = time.time()
        sh(os.path.join(ROOT, "scripts/release/build.sh"), "--save-images", "--sign-key", key, timeout=3600)
        build_sec = round(time.time() - t0)
    else:
        build_sec = None
    names = sorted(os.listdir(DIST))
    need = {"SHA256SUMS", "SHA256SUMS.sig", "ppanel-release.pub", "install-agent.sh", "ppanel-agent-linux-amd64",
            "ppanel-agent-linux-arm64", f"ppanel-center-{VERSION}.tar.gz", "images"}
    sizes = {n: os.path.getsize(os.path.join(DIST, n)) for n in names if os.path.isfile(os.path.join(DIST, n))}
    images = {}
    for svc in ("api", "web"):
        p = sh("docker", "image", "inspect", "--format", "{{.Size}}", f"ppanel-{svc}:{VERSION}")
        images[f"ppanel-{svc}:{VERSION}"] = {"bytes": int(p.stdout.strip()),
                                             "savedTarBytes": os.path.getsize(os.path.join(DIST, "images", f"ppanel-{svc}-{VERSION}.tar"))}
    step("release artifacts built (images linux/arm64, agent amd64+arm64, bundle, SHA256SUMS, signed)",
         need.issubset(set(names)), buildSec=build_sec, artifacts=sizes, images=images)

    sums = sh("bash", "-c", f"cd '{DIST}' && shasum -a 256 -c SHA256SUMS").stdout.strip().splitlines()
    sig = sh("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", os.path.join(DIST, "ppanel-release.pub"), "-rawin",
             "-in", os.path.join(DIST, "SHA256SUMS"), "-sigfile", os.path.join(DIST, "SHA256SUMS.sig"))
    step("SHA256SUMS verified + ed25519 signature verified (openssl pkeyutl -rawin)",
         all(s.endswith(": OK") for s in sums) and "Verified" in sig.stdout, checked=len(sums))

    # ------------------------------------------------------------ 2. fresh ubuntu lab
    sh(*COMPOSE, "rm", "-sfv", "ubuntu-center", *[n.replace("ppanel-lab-", "") for n in NODES], check=False)
    for v in ("ppanel-lab_ubuntu-center-docker", "ppanel-lab_ubuntu-center-containerd"):
        sh("docker", "volume", "rm", v, check=False)
    sh(*COMPOSE, "up", "-d", "--build", "--no-deps", "ubuntu-center", *[n.replace("ppanel-lab-", "") for n in NODES])
    ok = all(wait_systemd(c) for c in [CENTER] + NODES)
    os_rel = dx(CENTER, ". /etc/os-release; echo $VERSION_ID").stdout.strip()
    engine = dx(CENTER, "docker version --format '{{.Server.Version}}'; docker compose version --short").stdout.split()
    step("fresh Ubuntu systemd hosts up (center: Docker Engine; nodes: nginx), nothing pPanel installed",
         ok and os_rel == "24.04" and dx(CENTER, "test ! -e /opt/ppanel", check=False).returncode == 0,
         ubuntu=os_rel, docker=engine[0], compose=engine[1], pid1=dx(NODES[0], "ps -p 1 -o comm=").stdout.strip())

    # ------------------------------------------------------------ 3. copy bundle + images, install.sh
    dx(CENTER, "mkdir -p /root/release")
    for n in [f"ppanel-center-{VERSION}.tar.gz", "SHA256SUMS", "SHA256SUMS.sig", "ppanel-release.pub", "images"]:
        sh("docker", "cp", os.path.join(DIST, n), f"{CENTER}:/root/release/")
    v = dx(CENTER, "sha256sum -c --ignore-missing SHA256SUMS && openssl pkeyutl -verify -pubin -inkey "
                   "ppanel-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig && "
                   f"tar xzf ppanel-center-{VERSION}.tar.gz", workdir="/root/release")
    step("bundle verified on the center host (checksum + signature) and unpacked", "Verified" in v.stdout)

    t0 = time.time()
    p = dx(CENTER, f"./install.sh --domain {DOMAIN} --tls internal --image-prefix '' --images-dir /root/release/images",
           check=False, timeout=1200, workdir=f"/root/release/ppanel-center-{VERSION}")
    out = p.stdout + p.stderr
    install_sec = round(time.time() - t0)
    m = re.search(r"one-time setup token \(shown once\):\s+([0-9a-f]{48})", out)
    setup_token = m.group(1) if m else None
    dx(CENTER, "rm -rf /root/release/images")  # free the lab disk; images are loaded
    env_mode = dx(CENTER, "stat -c '%a %U' /opt/ppanel/.env").stdout.strip()
    ps = dx(CENTER, "cd /opt/ppanel && docker compose ps --format '{{.Service}} {{.Health}}'").stdout.split("\n")
    step("install.sh: prerequisites, secrets generated, stack healthy, setup token printed once",
         p.returncode == 0 and setup_token is not None and env_mode == "600 root" and "ESCROW NOW" in out,
         installSec=install_sec, envFile=env_mode, services=[s for s in ps if s], exit=p.returncode,
         tail=None if p.returncode == 0 else out[-1500:])
    secrets_in_env = dx(CENTER, "grep -cE '^(PPANEL_MASTER_KEY|JWT_ACCESS_SECRET|POSTGRES_PASSWORD|PPANEL_SETUP_TOKEN)=.+' "
                                "/opt/ppanel/.env").stdout.strip()
    pins = dx(CENTER, "grep -E '^PPANEL_(API|WEB)_IMAGE=' /opt/ppanel/.env").stdout.split()
    step("images pinned by tag + digest in .env; 4 secrets generated",
         secrets_in_env == "4" and all("@sha256:" in x for x in pins), pins=pins)

    # CA of the internal TLS mode → Mac → nodes (agents enroll over verified https)
    ca_local = os.path.join(WORK, "caddy-root.crt")
    sh("docker", "cp", f"{CENTER}:/opt/ppanel/secrets/caddy-root.crt", ca_local)
    for node in NODES:
        dx(node, "mkdir -p /root/agent")
        sh("docker", "cp", ca_local, f"{node}:{CACERT}")

    st, h = api("GET", "/health")
    st2, ver = api("GET", "/version")
    gw = dx(NODES[0], f"timeout 5 openssl s_client -connect {DOMAIN}:4443 -servername {DOMAIN} </dev/null 2>/dev/null "
                      "| grep -m1 -i 'acceptable client certificate CA names' || true").stdout.strip()
    web = dx(NODES[0], f"curl -sS -o /dev/null -w '%{{http_code}}' --cacert {CACERT} https://{DOMAIN}/login").stdout
    step("health + /version through the TLS proxy (verified CA); web UI served; gateway :4443 asks for client certs",
         st == 200 and st2 == 200 and ver["data"]["version"] == VERSION and ver["data"]["agentProtocol"] == "1"
         and web == "200", version=ver.get("data"), webLogin=web, gatewayMtls=bool(gw))

    # ------------------------------------------------------------ 4. first boot + 2FA
    st, s = api("GET", "/setup/status")
    email, pw = "owner@ppanel.lab", "P8-" + secrets.token_urlsafe(18)
    st_bad, bad = api("POST", "/setup/bootstrap", body={"email": email, "password": pw, "displayName": "Owner",
                                                        "setupToken": "0" * 48})
    st_ok, boot = api("POST", "/setup/bootstrap", body={"email": email, "password": pw, "displayName": "Owner",
                                                        "setupToken": setup_token})
    st_again, again = api("POST", "/setup/bootstrap", body={"email": "x@ppanel.lab", "password": pw,
                                                            "displayName": "X", "setupToken": setup_token})
    step("first boot: wrong token refused, setup token creates the owner once",
         s["data"]["bootstrapped"] is False and st_bad == 401 and st_ok == 201 and st_again == 409,
         wrongToken=bad.get("error", {}).get("code"), second=again.get("error", {}).get("code"))

    _, lg = api("POST", "/auth/login", body={"email": email, "password": pw})
    tok = lg["data"]["accessToken"]
    _, su = api("POST", "/auth/mfa/totp/setup", tok)
    secret = re.search(r"secret=([A-Z2-7]+)", su["data"]["otpauthUrl"]).group(1)
    st, _ = api("POST", "/auth/mfa/totp/confirm", tok, {"code": totp(secret)})
    time.sleep(31 - (time.time() % 30))  # TOTP steps are single-use
    _, lg2 = api("POST", "/auth/login", body={"email": email, "password": pw})
    st3, mv = api("POST", "/auth/mfa/verify", body={"mfaToken": lg2["data"].get("mfaToken"), "code": totp(secret)})
    tok = mv.get("data", {}).get("accessToken")
    step("owner enables TOTP; login now requires the second factor",
         st == 200 and lg2["data"].get("mfaRequired") is True and st3 == 200 and tok)

    # ------------------------------------------------------------ 5. enrollment tokens + agent installs
    tokens = []
    for i, node in enumerate(NODES):
        st, e = api("POST", "/enrollments", tok, {"name": f"p8-{node[-6:]}", "environment": "uat", "ttlMinutes": 15})
        tokens.append(e["data"])
    ic = tokens[0]["installCommand"]
    step("two enrollment tokens; installCommand is the install-agent.sh form",
         len(tokens) == 2 and ic.startswith("curl -fsSLO https://") and "install-agent.sh --center-url "
         f"https://{DOMAIN} --token ppe_" in ic and f"--version {VERSION}" in ic,
         installCommand=re.sub(r"ppe_\S+", "ppe_<redacted>", ic),
         enrollCommand=re.sub(r"ppe_\S+", "ppe_<redacted>", tokens[0].get("enrollCommand", "")))

    for node in NODES:
        for n in ["install-agent.sh", "ppanel-agent-linux-arm64", "ppanel-agent-linux-amd64", "SHA256SUMS",
                  "SHA256SUMS.sig", "ppanel-release.pub"]:
            sh("docker", "cp", os.path.join(DIST, n), f"{node}:/root/agent/")

    # negative: tampered binary / tampered SHA256SUMS are refused before anything is installed
    n0 = NODES[0]
    dx(n0, "mkdir -p /root/bad1 /root/bad2 && cp /root/agent/* /root/bad1/ && cp /root/agent/* /root/bad2/ && "
           "printf 'X' | dd of=/root/bad1/ppanel-agent-linux-arm64 bs=1 seek=4096 conv=notrunc 2>/dev/null && "
           "sed -i '1s/^./0/' /root/bad2/SHA256SUMS")
    b1 = dx(n0, "bash /root/agent/install-agent.sh --center-url https://x --token ppe_x --from-dir /root/bad1 "
                "--pubkey /root/bad1/ppanel-release.pub 2>&1", check=False)
    b2 = dx(n0, "bash /root/agent/install-agent.sh --center-url https://x --token ppe_x --from-dir /root/bad2 "
                "--pubkey /root/bad2/ppanel-release.pub 2>&1", check=False)
    nothing = dx(n0, "test ! -e /usr/local/bin/ppanel-agent && test ! -e /etc/systemd/system/ppanel-agent.service",
                 check=False).returncode == 0
    dx(n0, "rm -rf /root/bad1 /root/bad2")
    step("tampered binary → CHECKSUM MISMATCH; tampered SHA256SUMS → SIGNATURE FAILED; nothing installed",
         b1.returncode != 0 and "CHECKSUM MISMATCH" in b1.stdout and b2.returncode != 0
         and "SIGNATURE VERIFICATION FAILED" in b2.stdout and nothing)

    server_ids = []
    for node, t in zip(NODES, tokens):
        p = dx(node, "bash /root/agent/install-agent.sh --center-url https://" + DOMAIN + " --token " + t["token"]
               + " --from-dir /root/agent --pubkey /root/agent/ppanel-release.pub --ca-file " + CACERT + " 2>&1",
               check=False, timeout=180)
        sid = re.search(r"serverId=([0-9a-f-]{36})", p.stdout)
        server_ids.append(sid.group(1) if sid else None)
        perms = dx(node, "stat -c '%a' /var/lib/ppanel-agent /etc/ppanel-agent /var/lib/ppanel-agent/agent.key "
                         "2>/dev/null | tr '\\n' ' '", check=False).stdout.strip()
        step(f"install-agent.sh on {node}: signature + checksum OK, enrolled, service active",
             p.returncode == 0 and sid and "signature OK" in p.stdout and "checksum OK" in p.stdout
             and "ppanel-agent.service active" in p.stdout, serverId=server_ids[-1], modes=perms,
             tail=None if p.returncode == 0 else p.stdout[-1200:])

    def all_online():
        out = []
        for sid in server_ids:
            st, s = api("GET", f"/servers/{sid}", tok)
            if st != 200 or s["data"]["status"] not in CONNECTED:
                return None
            out.append(s["data"])
        return out
    servers = poll(all_online, 90)
    step("both agents online (fresh heartbeats over mTLS)", servers is not None and len(servers) == 2,
         statuses=[(x["hostname"], x["status"], (x.get("metrics") or {}).get("diskPct")) for x in servers or []])

    # ------------------------------------------------------------ 6. smoke suite
    st, lst = api("GET", "/servers?limit=20", tok)
    step("smoke: list servers", st == 200 and {s["id"] for s in lst["data"]} >= set(server_ids),
         total=lst.get("paginate", {}).get("total"))
    facts = [{"hostname": s["hostname"], "agentVersion": s["agentVersion"], "agentOutdated": s.get("agentOutdated"),
              "os": s["os"], "capabilities": s["capabilities"], "cert": bool(s["certificate"])} for s in servers]
    step("smoke: server facts (agent version = release, not outdated, Ubuntu 24.04, mTLS cert issued)",
         all(f["agentVersion"] == VERSION and f["agentOutdated"] is False and f["os"]["version"] == "24.04"
             and f["cert"] for f in facts), facts=facts)

    before = nginx_state(NODES[0])
    st, sc = api("POST", f"/servers/{server_ids[0]}/discovery-scans", tok, {})
    scan = poll(lambda: (lambda r: r[1]["data"] if r[1].get("data", {}).get("status") not in (None, "running", "queued")
                         else None)(api("GET", f"/discovery-scans/{sc['data']['scanId']}", tok)), 120) if st == 202 else None
    after = nginx_state(NODES[0])
    st_f, fnd = api("GET", f"/discovery-scans/{scan['id']}/findings?limit=100", tok) if scan else (0, {})
    domains = sorted({d for x in fnd.get("data", []) for d in (x.get("domains") or [])})
    step("smoke: read-only nginx discovery completed, config checksum + master PID unchanged",
         scan and scan["status"] == "completed" and before == after and "lab-site.example.lab" in domains,
         summary=scan and scan.get("summary"), domains=domains, nginx=before)

    st, fleet = api("GET", "/metrics/fleet", tok)
    sampled = [x for x in fleet.get("data", []) if x.get("serverId") in server_ids and x.get("sample")]
    st_s, series = api("GET", f"/metrics/series?scope=server&id={server_ids[0]}&metric=cpu&range=1h", tok)
    st_l, logs = api("GET", f"/logs/query?serverId={server_ids[0]}&limit=5", tok)
    step("smoke: fleet metrics from heartbeats (DB); Prometheus/Loki reads SKIPPED (observability profile off)",
         st == 200 and len(sampled) == 2 and st_s in (200, 503) and st_l in (200, 503),
         fleetSampled=len(sampled), metricsSeries={"status": st_s, "code": series.get("error", {}).get("code")},
         logsQuery={"status": st_l, "code": logs.get("error", {}).get("code")},
         note="enable COMPOSE_PROFILES=observability in /opt/ppanel/.env for metric series / log search")

    # ------------------------------------------------------------ 7. systemd hardening + restart
    props = "NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,RestrictSUIDSGID,LockPersonality," \
            "SystemCallArchitectures,RestrictAddressFamilies,CapabilityBoundingSet,ReadWritePaths,Restart,User"
    show = dx(NODES[0], f"systemctl show ppanel-agent -p {props}").stdout.strip().splitlines()
    sp = dict(line.split("=", 1) for line in show)
    pid1 = dx(NODES[0], "systemctl show ppanel-agent -p MainPID --value").stdout.strip()
    ro = dx(NODES[0], f"nsenter -t {pid1} -m sh -c 'touch /usr/local/p8-probe 2>&1; touch /etc/nginx/.p8-probe "
                      "&& rm /etc/nginx/.p8-probe && echo nginx-rw'", check=False).stdout
    step("systemd hardening active (systemctl show) and enforced (/usr read-only, /etc/nginx writable)",
         sp.get("NoNewPrivileges") == "yes" and sp.get("ProtectSystem") == "strict" and sp.get("PrivateTmp") == "yes"
         and sp.get("RestrictSUIDSGID") == "yes" and sp.get("Restart") == "always" and "Read-only file system" in ro
         and "nginx-rw" in ro, props=sp)

    _, s0 = api("GET", f"/servers/{server_ids[0]}", tok)
    hb0 = s0["data"]["lastHeartbeatAt"]
    dx(NODES[0], "systemctl restart ppanel-agent")
    pid2 = poll(lambda: (lambda v: v if v not in ("0", pid1) else None)(
        dx(NODES[0], "systemctl show ppanel-agent -p MainPID --value").stdout.strip()), 30, 1)
    newer = poll(lambda: (lambda s: s["data"] if s["data"]["status"] in CONNECTED and s["data"]["lastHeartbeatAt"] != hb0
                          else None)(api("GET", f"/servers/{server_ids[0]}", tok)[1]), 60)
    step("agent survives `systemctl restart` (new PID, fresh heartbeat, online)",
         pid2 and newer is not None, pidBefore=pid1, pidAfter=pid2)
    dx(NODES[1], "kill -9 $(systemctl show ppanel-agent -p MainPID --value)")
    back = poll(lambda: dx(NODES[1], "systemctl show ppanel-agent -p MainPID --value").stdout.strip() not in ("0", ""), 30, 1)
    step("Restart=always: killed agent is restarted by systemd", back)

    # ------------------------------------------------------------ 8. idempotency
    ids0 = dx(CENTER, "cd /opt/ppanel && docker compose ps -q | sort | tr '\\n' ' '").stdout
    env0 = dx(CENTER, "sha256sum /opt/ppanel/.env | cut -c1-64").stdout
    p = dx(CENTER, "./install.sh", check=False, timeout=900, workdir=f"/root/release/ppanel-center-{VERSION}")
    out2 = p.stdout + p.stderr
    ids1 = dx(CENTER, "cd /opt/ppanel && docker compose ps -q | sort | tr '\\n' ' '").stdout
    env1 = dx(CENTER, "sha256sum /opt/ppanel/.env | cut -c1-64").stdout
    st, s = api("GET", "/setup/status")
    step("install.sh re-run is idempotent (no new secrets, .env unchanged, containers not recreated, still healthy)",
         p.returncode == 0 and "generated secrets" not in out2 and env0 == env1 and ids0 == ids1
         and "one-time setup token" not in out2 and s["data"]["bootstrapped"] is True, containers=len(ids1.split()))
    st_v, ver2 = api("GET", "/version")
    p = dx(NODES[0], "bash /root/agent/install-agent.sh --from-dir /root/agent --pubkey /root/agent/ppanel-release.pub 2>&1",
           check=False, timeout=120)
    still = poll(lambda: (lambda s: s if s["data"]["status"] in CONNECTED else None)(
        api("GET", f"/servers/{server_ids[0]}", tok)[1]), 60)
    _, lst2 = api("GET", "/servers?limit=20", tok)
    step("install-agent.sh re-run without a token: verified, not re-enrolled, same server online",
         p.returncode == 0 and "not re-enrolling" in p.stdout and still is not None
         and len(lst2["data"]) == len(lst["data"]) and ver2["data"]["schemaVersion"] == ver["data"]["schemaVersion"])

    # ------------------------------------------------------------ 9. uninstall (node-2)
    p = dx(NODES[1], "bash /root/agent/install-agent.sh --uninstall 2>&1", check=False)
    gone = dx(NODES[1], "test ! -e /usr/local/bin/ppanel-agent && test ! -e /etc/systemd/system/ppanel-agent.service "
                        "&& test -e /var/lib/ppanel-agent/identity.json && ! systemctl is-active --quiet ppanel-agent",
              check=False).returncode == 0
    step("install-agent.sh --uninstall: unit + binary removed, state kept (no --purge)", p.returncode == 0 and gone)

    du = dx(CENTER, "du -sh /var/lib/docker /var/lib/containerd 2>/dev/null | tr '\\t\\n' ': '").stdout.strip()
    step("lab disk used inside the center host", True, du=du)

    if "--down" in sys.argv:
        sh(*COMPOSE, "rm", "-sfv", "ubuntu-center", *[n.replace("ppanel-lab-", "") for n in NODES], check=False)
        for v in ("ppanel-lab_ubuntu-center-docker", "ppanel-lab_ubuntu-center-containerd"):
            sh("docker", "volume", "rm", v, check=False)
    finish(0)


if __name__ == "__main__":
    main()
