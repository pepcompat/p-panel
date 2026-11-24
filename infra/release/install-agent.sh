#!/usr/bin/env bash
# pPanel Agent installer (P8.01, docs/RELEASE_CONTRACT.md §5, docs/INSTALL.md §6).
#
#   sudo bash install-agent.sh --center-url https://center.example.com --token ppe_… [options]
#   sudo bash install-agent.sh --uninstall [--purge]
#
# Downloads the agent binary + SHA256SUMS (+ SHA256SUMS.sig) of a release (or takes them from --from-dir),
# verifies the checksum (always) and the ed25519 signature (whenever a public key is given or embedded),
# installs /usr/local/bin/ppanel-agent, creates /var/lib/ppanel-agent (0700) and /etc/ppanel-agent,
# enrolls once with the one-time token and installs + starts the hardened ppanel-agent.service.
# Re-running is safe: an enrolled host is not re-enrolled (the token is then not needed) and the binary
# is replaced only after verification.
#
# Options:
#   --center-url URL     Center base URL (https://…, the web/API origin) — required to enroll
#   --token TOKEN        one-time enrollment token (ppe_…); or env PPANEL_ENROLL_TOKEN
#   --version V          release to install (default: latest release)
#   --from-dir DIR       take ppanel-agent-linux-<arch>, SHA256SUMS[, SHA256SUMS.sig] from DIR (offline/lab)
#   --download-base URL  release download base (default https://github.com/pepcompat/ppanel/releases/…)
#   --pubkey FILE        ed25519 public key (PEM) — makes the signature check mandatory
#   --ca-file FILE       CA bundle to trust for the Center API (Center installed with `--tls internal`)
#   --force-enroll       re-enroll even if this host already has an identity
#   --uninstall          stop + disable the service and remove the binary and unit
#   --purge              with --uninstall: also delete /var/lib/ppanel-agent and /etc/ppanel-agent
#   --print-unit         print the embedded systemd unit and exit
set -euo pipefail
umask 022

# Release signing public key (PEM). Filled in by scripts/release/build.sh / release.yml when the release
# is signed; empty = unsigned release (signature checked only with --pubkey).
EMBEDDED_PUBKEY=''

REPO_RELEASES="https://github.com/pepcompat/ppanel/releases"
BIN=/usr/local/bin/ppanel-agent
STATE=/var/lib/ppanel-agent
ETC=/etc/ppanel-agent
UNIT=/etc/systemd/system/ppanel-agent.service

CENTER=""
TOKEN="${PPANEL_ENROLL_TOKEN:-}"
VERSION=""
FROM_DIR=""
BASE=""
PUBKEY=""
CA_FILE=""
FORCE=0
UNINSTALL=0
PURGE=0

log() { printf '[install-agent] %s\n' "$*" >&2; }
die() {
  printf '[install-agent] ERROR: %s\n' "$*" >&2
  exit 1
}

unit_content() {
  cat <<'UNIT_EOF'
# pPanel Agent — systemd unit (P8, docs/RELEASE_CONTRACT.md §5, docs/INSTALL.md "least privileges").
# Installed by install-agent.sh to /etc/systemd/system/ppanel-agent.service (the script embeds this exact
# file; scripts/release/build.sh fails if the two drift).
#
# Runs as root with a reduced capability bounding set: it must reload nginx (signal the root master,
# write /etc/nginx), run `nginx -t`/`nginx -T` (root-only includes and TLS key paths), talk to the Docker
# socket (host-root-equivalent; GETs for inventory, typed container ops only) and call systemctl over
# D-Bus for allowlisted units. It opens NO listening socket; all connections are outbound.
# Restore targets outside the paths below need a drop-in: `systemctl edit ppanel-agent` →
#   [Service]
#   ReadWritePaths=/srv/myapp/data

[Unit]
Description=pPanel Agent
Documentation=https://github.com/pepcompat/ppanel/blob/main/docs/INSTALL.md
After=network-online.target docker.service nginx.service
Wants=network-online.target
ConditionPathExists=/var/lib/ppanel-agent/identity.json

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/usr/local/bin/ppanel-agent check-config --config /etc/ppanel-agent/config.yaml
ExecStart=/usr/local/bin/ppanel-agent run --config /etc/ppanel-agent/config.yaml
Restart=always
RestartSec=5s
TimeoutStopSec=45s
KillMode=mixed
UMask=0077

# --- filesystem: everything read-only except what the agent manages ---
ProtectSystem=strict
# state (identity, key, job cache, log buffer, backup work dir, restore staging)
ReadWritePaths=/var/lib/ppanel-agent
# nginx typed jobs write candidates / managed files here; `nginx -t`/`-T` open logs, temp and pid paths
ReadWritePaths=-/etc/nginx -/var/log/nginx -/var/lib/nginx -/var/cache/nginx -/run/nginx -/run/nginx.pid
# optional operator backup staging outside the state dir (backup.workDir)
ReadWritePaths=-/var/backups/ppanel-agent
StateDirectory=ppanel-agent
StateDirectoryMode=0700
ConfigurationDirectory=ppanel-agent
ConfigurationDirectoryMode=0750
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes

# --- privileges ---
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_CHOWN CAP_FOWNER
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# MemoryDenyWriteExecute is intentionally NOT set: it is inherited by `nginx -T`
# and breaks PCRE JIT in some nginx builds.

# --- kernel / devices ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# AF_UNIX: docker.sock + D-Bus; AF_INET/6: Center; AF_NETLINK: interface addresses
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

# --- resources (bounded) ---
MemoryMax=512M
TasksMax=128
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
UNIT_EOF
}

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --center-url) CENTER="${2:?}"; shift 2 ;;
    --token) TOKEN="${2:?}"; shift 2 ;;
    --version) VERSION="${2:?}"; shift 2 ;;
    --from-dir) FROM_DIR="${2:?}"; shift 2 ;;
    --download-base) BASE="${2:?}"; shift 2 ;;
    --pubkey) PUBKEY="${2:?}"; shift 2 ;;
    --ca-file) CA_FILE="${2:?}"; shift 2 ;;
    --force-enroll) FORCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --print-unit) unit_content; exit 0 ;;
    -h | --help) usage 0 ;;
    *) log "unknown option: $1"; usage 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now ppanel-agent.service 2>/dev/null || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$STATE" "$ETC"
    log "purged $STATE and $ETC"
  else
    log "kept $STATE (identity) and $ETC; add --purge to delete them"
  fi
  log "uninstalled. Revoke the server in the Center (Servers → Revoke) so its certificate stops working."
  exit 0
fi

[ "$PURGE" -eq 0 ] || die "--purge only makes sense with --uninstall"
for c in sha256sum openssl install; do command -v "$c" >/dev/null 2>&1 || die "missing prerequisite: $c"; done

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m) (linux amd64/arm64 only)" ;;
esac
NAME="ppanel-agent-linux-$ARCH"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"

# ---------------------------------------------------------------- fetch
if [ -n "$FROM_DIR" ]; then
  if [ ! -f "$FROM_DIR/$NAME" ] || [ ! -f "$FROM_DIR/SHA256SUMS" ]; then
    die "$FROM_DIR must contain $NAME and SHA256SUMS"
  fi
  cp "$FROM_DIR/$NAME" "$FROM_DIR/SHA256SUMS" "$work/"
  [ -f "$FROM_DIR/SHA256SUMS.sig" ] && cp "$FROM_DIR/SHA256SUMS.sig" "$work/"
  log "using artifacts from $FROM_DIR"
else
  command -v curl >/dev/null 2>&1 || die "missing prerequisite: curl"
  if [ -z "$BASE" ]; then
    if [ -n "$VERSION" ]; then BASE="$REPO_RELEASES/download/v${VERSION#v}"; else BASE="$REPO_RELEASES/latest/download"; fi
  fi
  case "$BASE" in https://*) ;; *) die "--download-base must be https://" ;; esac
  for f in "$NAME" SHA256SUMS; do
    curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$f" "$BASE/$f" || die "download failed: $BASE/$f"
  done
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/SHA256SUMS.sig" "$BASE/SHA256SUMS.sig" 2>/dev/null || rm -f "$work/SHA256SUMS.sig"
  log "downloaded $NAME from $BASE"
fi

# ---------------------------------------------------------------- verify (checksum mandatory, signature when a key is known)
if [ -z "$PUBKEY" ] && [ -n "$EMBEDDED_PUBKEY" ]; then
  printf '%s\n' "$EMBEDDED_PUBKEY" >"$work/release.pub"
  PUBKEY="$work/release.pub"
fi
if [ -n "$PUBKEY" ]; then
  [ -f "$work/SHA256SUMS.sig" ] || die "a release public key is configured but SHA256SUMS.sig is missing"
  openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1 ||
    die "SIGNATURE VERIFICATION FAILED for SHA256SUMS — do not install"
  log "signature OK (ed25519, SHA256SUMS)"
else
  log "WARNING: no release public key given — checksum verified, signature NOT verified (unsigned or no --pubkey)"
fi
line="$(awk -v n="$NAME" '$2 == n || $2 == "*" n { print; exit }' "$work/SHA256SUMS")"
[ -n "$line" ] || die "$NAME is not listed in SHA256SUMS"
(cd "$work" && printf '%s\n' "$line" | sha256sum -c --quiet -) || die "CHECKSUM MISMATCH for $NAME — do not install"
log "checksum OK ($NAME)"

# ---------------------------------------------------------------- install
install -m 0755 "$work/$NAME" "$BIN.new"
mv -f "$BIN.new" "$BIN"
install -d -m 0700 "$STATE"
install -d -m 0750 "$ETC"
log "installed $BIN ($("$BIN" version 2>/dev/null | head -n1 || echo unknown))"

if [ -n "$CA_FILE" ]; then
  [ -f "$CA_FILE" ] || die "--ca-file $CA_FILE not found"
  install -m 0644 "$CA_FILE" "$ETC/center-ca.pem"
fi
if [ ! -f "$ETC/config.yaml" ]; then
  [ -n "$CENTER" ] || die "--center-url is required for a first install"
  umask 027
  cat >"$ETC/config.yaml" <<CFG_EOF
# /etc/ppanel-agent/config.yaml — written by install-agent.sh (see apps/agent/packaging/config.example.yaml)
centerUrl: $CENTER
stateDir: $STATE
logLevel: info
CFG_EOF
  umask 022
fi

# ---------------------------------------------------------------- enroll (once)
if [ -f "$STATE/identity.json" ] && [ "$FORCE" -eq 0 ]; then
  log "already enrolled ($STATE/identity.json); not re-enrolling (use --force-enroll)"
else
  [ -n "$CENTER" ] || die "--center-url is required to enroll"
  [ -n "$TOKEN" ] || die "--token (or PPANEL_ENROLL_TOKEN) is required to enroll"
  case "$CENTER" in https://*) ;; *) die "--center-url must be https://" ;; esac
  args=(enroll --center "$CENTER" --config "$ETC/config.yaml" --state-dir "$STATE")
  [ -f "$ETC/center-ca.pem" ] && args+=(--ca-file "$ETC/center-ca.pem")
  [ "$FORCE" -eq 1 ] && args+=(--force)
  # token via environment, never argv (ps)
  systemctl stop ppanel-agent.service 2>/dev/null || true
  PPANEL_ENROLL_TOKEN="$TOKEN" "$BIN" "${args[@]}" >&2 || die "enrollment failed"
fi
TOKEN=""

# ---------------------------------------------------------------- systemd
unit_content >"$UNIT.new"
chmod 0644 "$UNIT.new"
mv -f "$UNIT.new" "$UNIT"
systemctl daemon-reload
systemctl enable ppanel-agent.service >/dev/null 2>&1
systemctl restart ppanel-agent.service
for _ in $(seq 1 20); do
  if systemctl is-active --quiet ppanel-agent.service; then break; fi
  sleep 1
done
systemctl is-active --quiet ppanel-agent.service || {
  journalctl -u ppanel-agent.service -n 40 --no-pager >&2 || true
  die "ppanel-agent.service is not active"
}
log "ppanel-agent.service active (journalctl -u ppanel-agent -f)"
