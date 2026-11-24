#!/usr/bin/env bash
# pPanel Center installer (P8.01/P8.02, docs/RELEASE_CONTRACT.md §4, docs/INSTALL.md).
#
#   sudo ./install.sh --domain center.example.com --tls ops@example.com [options]
#
# Idempotent: re-running keeps every existing secret and image pin in /opt/ppanel/.env, adds keys that a
# newer env.template introduced, and converges the stack (`docker compose up -d --wait`). It never
# changes the installed version — use upgrade.sh for that. No curl|bash: run it from the unpacked
# release bundle (ppanel-center-<version>.tar.gz, checksum/signature verified, see docs/INSTALL.md).
#
# Options:
#   --domain NAME         public DNS name for the web UI + API (required on first install)
#   --tls MODE            `internal` (Caddy CA; lab/private) or an e-mail address for ACME (default: internal)
#   --gateway-host NAME   name agents use for the mTLS gateway :4443 (default: --domain; prefer a private name)
#   --gateway-bind IP     address :4443 is published on (default 0.0.0.0; use a private IP if you can)
#   --dir DIR             install root (default /opt/ppanel)
#   --version V           release to install (default: the bundle's VERSION file)
#   --image-prefix P      registry prefix (default ghcr.io/pepcompat/; '' = local images ppanel-api:<v>)
#   --images-dir DIR      `docker load` every *.tar / *.tar.gz in DIR first (offline / lab installs)
#   --no-start            write files only, do not start the stack
#   -h | --help
set -euo pipefail
umask 022

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR=/opt/ppanel
DOMAIN=""
TLS=""
GATEWAY_HOST=""
GATEWAY_BIND=""
VERSION=""
IMAGE_PREFIX="__unset__"
IMAGES_DIR=""
START=1
MIN_RAM_MB="${PPANEL_INSTALL_MIN_RAM_MB:-1900}"

log() { printf '[install] %s\n' "$*" >&2; }
warn() { printf '[install] WARNING: %s\n' "$*" >&2; }
die() {
  printf '[install] ERROR: %s\n' "$*" >&2
  exit 1
}
usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?}"; shift 2 ;;
    --tls) TLS="${2:?}"; shift 2 ;;
    --gateway-host) GATEWAY_HOST="${2:?}"; shift 2 ;;
    --gateway-bind) GATEWAY_BIND="${2:?}"; shift 2 ;;
    --dir) DIR="${2:?}"; shift 2 ;;
    --version) VERSION="${2:?}"; shift 2 ;;
    --image-prefix) IMAGE_PREFIX="${2-}"; shift 2 ;;
    --images-dir) IMAGES_DIR="${2:?}"; shift 2 ;;
    --no-start) START=0; shift ;;
    -h | --help) usage 0 ;;
    *) warn "unknown option: $1"; usage 2 ;;
  esac
done

ENV_FILE="$DIR/.env"
compose() { docker compose --project-directory "$DIR" -f "$DIR/compose.yml" --env-file "$ENV_FILE" "$@"; }

# ---------------------------------------------------------------- .env helpers (values never in argv)
env_get() {
  [ -f "$2" ] || return 0
  K="$1" awk 'BEGIN { k = ENVIRON["K"] "=" } index($0, k) == 1 { print substr($0, length(k) + 1); exit }' "$2"
}
env_set() {
  local tmp
  tmp="$(mktemp "$3.XXXXXX")"
  K="$1" V="$2" awk '
    BEGIN { k = ENVIRON["K"] "="; v = ENVIRON["V"]; done = 0 }
    !done && index($0, k) == 1 { print k v; done = 1; next }
    { print }
    END { if (!done) print k v }' "$3" >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$3"
}
env_default() { # set only when empty
  [ -n "$(env_get "$1" "$3")" ] || env_set "$1" "$2" "$3"
}

version_ge() { # version_ge 24.0.7 24 → true when $1 >= $2 (numeric dotted)
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$2" ]
}

port_busy() {
  if command -v ss >/dev/null 2>&1; then
    [ -n "$(ss -Htln "sport = :$1" 2>/dev/null)" ]
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
  fi
}

# ---------------------------------------------------------------- prerequisites
[ "$(id -u)" -eq 0 ] || die "run as root (sudo): it writes $DIR and manages Docker"
for c in docker openssl curl awk sed; do command -v "$c" >/dev/null 2>&1 || die "missing prerequisite: $c"; done
docker_ver="$(docker version --format '{{.Server.Version}}' 2>/dev/null)" || die "Docker Engine is not running"
version_ge "${docker_ver%%[-+]*}" 24 || die "Docker Engine >= 24 required (found $docker_ver)"
compose_ver="$(docker compose version --short 2>/dev/null | sed 's/^v//')" || die "Docker Compose v2 plugin required"
version_ge "${compose_ver%%[-+]*}" 2.20 || die "Docker Compose >= 2.20 required (found $compose_ver)"
if [ -r /proc/meminfo ]; then
  ram_mb=$(($(awk '/^MemTotal:/ { print $2 }' /proc/meminfo) / 1024))
  [ "$ram_mb" -ge "$MIN_RAM_MB" ] || die "at least 2 GB RAM required (found ${ram_mb} MB)"
fi
log "prerequisites: docker $docker_ver, compose $compose_ver${ram_mb:+, ${ram_mb} MB RAM}"

existing=0
[ -f "$ENV_FILE" ] && existing=1

# bundle version
if [ -z "$VERSION" ]; then
  if [ -f "$BUNDLE/VERSION" ]; then
    VERSION="$(tr -d '[:space:]' <"$BUNDLE/VERSION")"
  elif [ -f "$BUNDLE/../../VERSION" ]; then
    VERSION="$(tr -d '[:space:]' <"$BUNDLE/../../VERSION")"
  fi
fi
installed="$(env_get PPANEL_VERSION "$ENV_FILE")"
if [ -n "$installed" ]; then
  [ -z "$VERSION" ] || [ "$VERSION" = "$installed" ] ||
    die "pPanel $installed is installed in $DIR; use upgrade.sh $VERSION to change versions"
  VERSION="$installed"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "no valid release version (use --version)"

# ports (ignore the ones our own running stack already holds)
own_stack=0
if [ "$existing" -eq 1 ] && [ -n "$(compose ps --status running -q proxy 2>/dev/null || true)" ]; then own_stack=1; fi
if [ "$START" -eq 1 ] && [ "$own_stack" -eq 0 ]; then
  for p in "$(env_get PPANEL_HTTPS_PORT "$ENV_FILE")" 4443; do
    p="${p:-443}"
    if port_busy "$p"; then die "port $p is already in use on this host"; fi
  done
fi

# ---------------------------------------------------------------- files
log "installing bundle files into $DIR"
install -d -m 0755 "$DIR" "$DIR/observability" "$DIR/lib" "$DIR/systemd"
install -d -m 0711 "$DIR/secrets"
install -d -m 0700 "$DIR/backups"
if [ "$BUNDLE" != "$DIR" ]; then
  install -m 0644 "$BUNDLE/compose.yml" "$BUNDLE/Caddyfile" "$BUNDLE/env.template" "$DIR/"
  install -m 0644 "$BUNDLE"/observability/*.yml "$DIR/observability/"
  install -m 0644 "$BUNDLE"/systemd/*.service "$DIR/systemd/"
  for s in install.sh install-agent.sh backup-center.sh upgrade.sh rollback.sh; do
    [ -f "$BUNDLE/$s" ] && install -m 0755 "$BUNDLE/$s" "$DIR/$s"
  done
  # P6.06 Center backup scripts (bundled by scripts/release/build.sh; repo checkout: scripts/backup)
  for f in center-backup.sh center-restore.sh _center-common.sh; do
    if [ -f "$BUNDLE/lib/$f" ]; then
      install -m 0755 "$BUNDLE/lib/$f" "$DIR/lib/$f"
    elif [ -f "$BUNDLE/../../scripts/backup/$f" ]; then
      install -m 0755 "$BUNDLE/../../scripts/backup/$f" "$DIR/lib/$f"
    fi
  done
fi
printf '%s\n' "$VERSION" >"$DIR/VERSION"

# ---------------------------------------------------------------- .env (0600 root; secrets generated once)
if [ "$existing" -eq 0 ]; then
  [ -n "$DOMAIN" ] || die "--domain is required for the first install"
  (umask 077 && cp "$DIR/env.template" "$ENV_FILE")
else
  # keys introduced by a newer env.template are appended with their template defaults
  while IFS= read -r line; do
    case "$line" in '#'* | '') continue ;; esac
    key="${line%%=*}"
    grep -q "^${key}=" "$ENV_FILE" || printf '%s\n' "$line" >>"$ENV_FILE"
  done <"$DIR/env.template"
fi
chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"

[ -n "$DOMAIN" ] && env_set PPANEL_DOMAIN "$DOMAIN" "$ENV_FILE"
[ -n "$TLS" ] && env_set PPANEL_TLS "$TLS" "$ENV_FILE"
[ -n "$GATEWAY_HOST" ] && env_set PPANEL_GATEWAY_HOST "$GATEWAY_HOST" "$ENV_FILE"
[ -n "$GATEWAY_BIND" ] && env_set PPANEL_GATEWAY_BIND "$GATEWAY_BIND" "$ENV_FILE"
DOMAIN="$(env_get PPANEL_DOMAIN "$ENV_FILE")"
[ -n "$DOMAIN" ] || die "PPANEL_DOMAIN is empty in $ENV_FILE (use --domain)"
env_default PPANEL_GATEWAY_HOST "$DOMAIN" "$ENV_FILE"
env_set PPANEL_VERSION "$VERSION" "$ENV_FILE"

generated=""
gen() { # gen KEY <openssl rand args…>
  local k="$1"
  shift
  if [ -z "$(env_get "$k" "$ENV_FILE")" ]; then
    env_set "$k" "$(openssl rand "$@" | tr -d '\n')" "$ENV_FILE"
    generated="$generated $k"
  fi
}
gen PPANEL_MASTER_KEY -base64 32
gen JWT_ACCESS_SECRET -base64 48
gen POSTGRES_PASSWORD -hex 24
gen PPANEL_METRICS_SCRAPE_TOKEN -hex 32
[ "$existing" -eq 0 ] && gen PPANEL_SETUP_TOKEN -hex 24
[ -n "$generated" ] && log "generated secrets:$generated (stored only in $ENV_FILE)"

# Prometheus reads the scrape bearer from a file (nobody:nogroup inside the container)
(umask 077 && env_get PPANEL_METRICS_SCRAPE_TOKEN "$ENV_FILE" >"$DIR/secrets/scrape-token")
chown 65534:65534 "$DIR/secrets/scrape-token" 2>/dev/null || true
chmod 0400 "$DIR/secrets/scrape-token"

# ---------------------------------------------------------------- images (pinned by tag + digest)
if [ "$IMAGE_PREFIX" != "__unset__" ]; then env_set PPANEL_IMAGE_PREFIX "$IMAGE_PREFIX" "$ENV_FILE"; fi
prefix="$(env_get PPANEL_IMAGE_PREFIX "$ENV_FILE")"

if [ -n "$IMAGES_DIR" ]; then
  [ -d "$IMAGES_DIR" ] || die "--images-dir $IMAGES_DIR is not a directory"
  for f in "$IMAGES_DIR"/*.tar "$IMAGES_DIR"/*.tar.gz; do
    [ -f "$f" ] || continue
    log "docker load $(basename "$f")"
    docker load -q -i "$f" >/dev/null
  done
fi

# pin_image <ref> → ref@sha256:<registry digest> when the image came from a registry, else ref
pin_image() {
  local ref="$1" repo="${1%:*}" dig
  dig="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null | grep -m1 "^${repo}@" || true)"
  if [ -n "$dig" ]; then printf '%s@%s' "$ref" "${dig#*@}"; else printf '%s' "$ref"; fi
}
ensure_image() { # ensure_image <ENV_KEY> <name>
  local key="$1" name="$2" ref cur
  cur="$(env_get "$key" "$ENV_FILE")"
  ref="${cur:-${prefix}${name}:${VERSION}}"
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    log "pulling $ref"
    docker pull -q "$ref" >/dev/null || die "cannot pull $ref (offline? use --images-dir)"
  fi
  if [ -z "$cur" ]; then
    ref="$(pin_image "$ref")"
    env_set "$key" "$ref" "$ENV_FILE"
  fi
  env_set "${key}_ID" "$(docker image inspect --format '{{.Id}}' "$ref")" "$ENV_FILE"
  log "$key=$ref"
}
ensure_image PPANEL_API_IMAGE ppanel-api
ensure_image PPANEL_WEB_IMAGE ppanel-web

compose config --quiet || die "compose configuration is invalid (see above)"
if [ "$START" -eq 0 ]; then
  log "files written; start with: cd $DIR && docker compose up -d --wait"
  exit 0
fi

# ---------------------------------------------------------------- start + verify
log "starting the stack (first start runs database migrations)"
compose up -d --quiet-pull --wait --wait-timeout 420 || {
  compose ps >&2 || true
  compose logs --tail 60 api >&2 || true
  die "stack did not become healthy"
}

for svc in api web; do
  key="PPANEL_$(printf '%s' "$svc" | tr '[:lower:]' '[:upper:]')_IMAGE_ID"
  want="$(env_get "$key" "$ENV_FILE")"
  got="$(docker inspect --format '{{.Image}}' "$(compose ps -q "$svc")")"
  [ "$want" = "$got" ] || die "$svc runs image $got, expected pinned $want"
done

https_port="$(env_get PPANEL_HTTPS_PORT "$ENV_FILE")"
https_port="${https_port:-443}"
tls_mode="$(env_get PPANEL_TLS "$ENV_FILE")"
curl_tls=()
if [ "${tls_mode:-internal}" = internal ]; then
  # Caddy's internal root CA: agents need it for enrollment (install-agent.sh --ca-file)
  for _ in $(seq 1 30); do
    if compose exec -T proxy test -s /data/caddy/pki/authorities/local/root.crt 2>/dev/null; then break; fi
    sleep 1
  done
  compose exec -T proxy cat /data/caddy/pki/authorities/local/root.crt >"$DIR/secrets/caddy-root.crt"
  chmod 0644 "$DIR/secrets/caddy-root.crt"
  curl_tls=(--cacert "$DIR/secrets/caddy-root.crt")
fi
base="https://$DOMAIN:$https_port"
[ "$https_port" = 443 ] && base="https://$DOMAIN"
probe() { curl -fsS --max-time 10 "${curl_tls[@]}" --resolve "$DOMAIN:$https_port:127.0.0.1" "$base$1"; }
ok=0
for _ in $(seq 1 30); do
  if probe /api/v1/health >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
if [ "$ok" -eq 0 ] && [ "${tls_mode:-internal}" != internal ]; then
  warn "TLS verification through the proxy failed (ACME certificate not issued yet? DNS/port 80 reachable?)"
  curl_tls=(-k)
  probe /api/v1/health >/dev/null && ok=1
fi
[ "$ok" -eq 1 ] || die "health check through the proxy failed: $base/api/v1/health"
ver_json="$(probe /api/v1/version)"
printf '%s' "$ver_json" | grep -q "\"version\":\"$VERSION\"" || die "Center reports an unexpected version: $ver_json"
log "healthy: $base (version $VERSION)"

status_json="$(probe /api/v1/setup/status || true)"
cat >&2 <<EOF

================================================================================
 pPanel $VERSION is running at $base
   agent gateway (mTLS): $(env_get PPANEL_GATEWAY_HOST "$ENV_FILE"):4443 — allow it ONLY from managed hosts
   config + secrets:     $ENV_FILE (0600 root)

 !!! ESCROW NOW: copy PPANEL_MASTER_KEY from $ENV_FILE to OFFLINE storage, separate from database
 !!! backups (docs/INSTALL.md §4). Without it no DB backup can be decrypted.
EOF
if [ "${tls_mode:-internal}" = internal ]; then
  printf '   internal TLS root CA: %s (agents: install-agent.sh --ca-file)\n' "$DIR/secrets/caddy-root.crt" >&2
fi
if printf '%s' "$status_json" | grep -q '"bootstrapped":false'; then
  if [ "$existing" -eq 0 ]; then
    printf '\n First boot: open %s/setup and use this one-time setup token (shown once):\n   %s\n' \
      "$base" "$(env_get PPANEL_SETUP_TOKEN "$ENV_FILE")" >&2
  else
    printf '\n First boot not completed yet: the setup token is PPANEL_SETUP_TOKEN in %s\n' "$ENV_FILE" >&2
  fi
fi
printf '================================================================================\n' >&2
