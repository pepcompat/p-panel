#!/usr/bin/env bash
# pPanel Agent installer.
#
# Verifies the binary's SHA-256 BEFORE installing anything. Nothing is executed
# from the downloaded artifact until the checksum matches.
#
# Usage (as root):
#   install.sh --sha256 <hex> --binary ./ppanel-agent-linux-amd64 [--unit ./ppanel-agent.service]
#   install.sh --sha256 <hex> --url https://center.example.com/downloads/ppanel-agent-linux-amd64
#   optional enrollment (token via env so it does not appear in `ps`):
#   PPANEL_ENROLL_TOKEN=ppe_... install.sh ... --center https://center.example.com:4000 [--ca-file center-ca.pem]
set -euo pipefail
umask 077

BIN_DST=/usr/local/bin/ppanel-agent
CFG_DIR=/etc/ppanel-agent
STATE_DIR=/var/lib/ppanel-agent
UNIT_DST=/etc/systemd/system/ppanel-agent.service
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sha256="" binary="" url="" unit="${SCRIPT_DIR}/../packaging/ppanel-agent.service"
center="" ca_file="" example_cfg="${SCRIPT_DIR}/../packaging/config.example.yaml"

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sha256)  sha256="${2:-}"; shift 2 ;;
    --binary)  binary="${2:-}"; shift 2 ;;
    --url)     url="${2:-}"; shift 2 ;;
    --unit)    unit="${2:-}"; shift 2 ;;
    --center)  center="${2:-}"; shift 2 ;;
    --ca-file) ca_file="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root"
[[ "$sha256" =~ ^[0-9a-fA-F]{64}$ ]] || die "--sha256 <64 hex chars> is required"
[ -n "$binary" ] || [ -n "$url" ] || die "one of --binary or --url is required"
[ -f "$unit" ] || die "systemd unit not found: $unit"

workdir="$(mktemp -d)"
cleanup() { rm -f -- "$workdir/ppanel-agent"; rmdir -- "$workdir" 2>/dev/null || true; }
trap cleanup EXIT

if [ -n "$url" ]; then
  [[ "$url" == https://* ]] || die "--url must be https"
  command -v curl >/dev/null || die "curl is required for --url"
  curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 -o "$workdir/ppanel-agent" -- "$url"
else
  [ -f "$binary" ] || die "binary not found: $binary"
  cp -- "$binary" "$workdir/ppanel-agent"
fi

if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$workdir/ppanel-agent" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$workdir/ppanel-agent" | awk '{print $1}')"
fi
expected="$(printf '%s' "$sha256" | tr 'A-F' 'a-f')"
if [ "$actual" != "$expected" ]; then
  die "checksum mismatch: expected $expected got $actual - NOT installing"
fi
echo "checksum OK ($actual)"

install -o root -g root -m 0755 "$workdir/ppanel-agent" "$BIN_DST"
install -d -o root -g root -m 0750 "$CFG_DIR"
install -d -o root -g root -m 0700 "$STATE_DIR"
if [ ! -f "$CFG_DIR/config.yaml" ] && [ -f "$example_cfg" ]; then
  install -o root -g root -m 0640 "$example_cfg" "$CFG_DIR/config.yaml"
fi
[ -f "$CFG_DIR/owned-units" ] || install -o root -g root -m 0640 /dev/null "$CFG_DIR/owned-units"
install -o root -g root -m 0644 "$unit" "$UNIT_DST"

"$BIN_DST" version
"$BIN_DST" check-config --config "$CFG_DIR/config.yaml"

if command -v systemctl >/dev/null; then
  systemctl daemon-reload
fi

if [ -n "$center" ]; then
  [ -n "${PPANEL_ENROLL_TOKEN:-}" ] || die "set PPANEL_ENROLL_TOKEN in the environment to enroll"
  enroll_args=(enroll --center "$center" --config "$CFG_DIR/config.yaml")
  [ -n "$ca_file" ] && enroll_args+=(--ca-file "$ca_file")
  "$BIN_DST" "${enroll_args[@]}"
  if command -v systemctl >/dev/null; then
    systemctl enable --now ppanel-agent.service
  fi
else
  echo "installed. Enroll with: PPANEL_ENROLL_TOKEN=ppe_... $BIN_DST enroll --center https://<center>:4000"
  echo "then: systemctl enable --now ppanel-agent.service"
fi
