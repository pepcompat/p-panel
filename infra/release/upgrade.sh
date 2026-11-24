#!/usr/bin/env bash
# pPanel Center upgrade (P8.04, docs/RELEASE_CONTRACT.md §2/§4, docs/UPGRADE_RUNBOOK.md).
#
#   sudo ./upgrade.sh <version> [options]        # run from the UNPACKED bundle of <version>
#
# Order: pre-flight (running version, pending migrations, disk, bundle = <version>) → resolve the new
# images (load/pull; label must say <version>) → stop api + web → pre-upgrade dump
# /opt/ppanel/backups/pre-upgrade-<from>-<to>-<ts>.sql.gz (+ .release.tar.gz: compose files and the
# previous .env pins) → install the new bundle files → pin the new images in .env → `prisma migrate
# deploy` (new image) → start → health + version check. Nothing on the host changes until the new images
# are present and verified, so a bad tag stops the upgrade with the old version still running.
# Any failure after api/web were stopped prints the exact rollback.sh command.
# Re-running with the installed version is a no-op (or resumes migrate + start if the stack is unhealthy).
# Downgrades are refused: use rollback.sh <pre-upgrade dump> <previous version>.
#
# Options:
#   --images-dir DIR      `docker load` every *.tar / *.tar.gz in DIR first (offline / lab upgrades)
#   --image-prefix P      registry prefix for the new images (default: PPANEL_IMAGE_PREFIX in .env)
#   --dir DIR             install root (default /opt/ppanel)
#   --wait-timeout SEC    how long to wait for a healthy stack (default 420)
#   -h | --help
set -euo pipefail
umask 022

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR=/opt/ppanel
TARGET=""
IMAGES_DIR=""
IMAGE_PREFIX="__unset__"
WAIT_TIMEOUT=420

log() { printf '[upgrade] %s\n' "$*" >&2; }
warn() { printf '[upgrade] WARNING: %s\n' "$*" >&2; }
die() {
  printf '[upgrade] ERROR: %s\n' "$*" >&2
  exit 1
}
usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --images-dir) IMAGES_DIR="${2:?}"; shift 2 ;;
    --image-prefix) IMAGE_PREFIX="${2-}"; shift 2 ;;
    --dir) DIR="${2:?}"; shift 2 ;;
    --wait-timeout) WAIT_TIMEOUT="${2:?}"; shift 2 ;;
    -h | --help) usage 0 ;;
    -*) warn "unknown option: $1"; usage 2 ;;
    *)
      [ -z "$TARGET" ] || die "only one version argument is allowed"
      TARGET="${1#v}"
      shift
      ;;
  esac
done

ENV_FILE="$DIR/.env"
compose() { docker compose --project-directory "$DIR" -f "$DIR/compose.yml" --env-file "$ENV_FILE" "$@"; }

# ---------------------------------------------------------------- helpers (.env values never in argv, never sourced)
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

SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
# semver_cmp A B → prints -1 | 0 | 1 (SemVer 2.0 precedence; 0.8.0-rc.1 < 0.8.0)
semver_cmp() {
  A="$1" B="$2" awk 'BEGIN {
    a = ENVIRON["A"]; b = ENVIRON["B"]
    pa = index(a, "-") ? substr(a, index(a, "-") + 1) : ""; ca = index(a, "-") ? substr(a, 1, index(a, "-") - 1) : a
    pb = index(b, "-") ? substr(b, index(b, "-") + 1) : ""; cb = index(b, "-") ? substr(b, 1, index(b, "-") - 1) : b
    split(ca, x, "."); split(cb, y, ".")
    for (i = 1; i <= 3; i++) if (x[i] + 0 != y[i] + 0) { print (x[i] + 0 < y[i] + 0) ? -1 : 1; exit }
    if (pa == pb) { print 0; exit }
    if (pa == "") { print 1; exit }
    if (pb == "") { print -1; exit }
    n = split(pa, p, "."); m = split(pb, q, ".")
    for (i = 1; i <= (n > m ? n : m); i++) {
      if (i > n) { print -1; exit }
      if (i > m) { print 1; exit }
      np = (p[i] ~ /^[0-9]+$/); nq = (q[i] ~ /^[0-9]+$/)
      if (np && nq) { if (p[i] + 0 != q[i] + 0) { print (p[i] + 0 < q[i] + 0) ? -1 : 1; exit } ; continue }
      if (np != nq) { print np ? -1 : 1; exit }
      if (p[i] != q[i]) { print (p[i] < q[i]) ? -1 : 1; exit }
    }
    print 0 }'
}

# center_info → "<http status> <version> <schemaVersion>" from inside the api container ("000 - -" if down).
# GET /api/v1/version exists from 0.8.0; older Centers answer 404 and we fall back to /api/v1/health.
center_info() {
  compose exec -T api node -e '
    const get = (p) => fetch("http://127.0.0.1:" + (process.env.API_PORT || 4000) + "/api/v1" + p)
      .then(async (r) => ({ s: r.status, j: await r.json().catch(() => ({})) }));
    (async () => {
      let r = await get("/version");
      if (r.s === 404) r = await get("/health");
      const d = (r.j && r.j.data) || r.j || {};
      console.log(r.s + " " + (d.version || "-") + " " + (d.schemaVersion || "-"));
    })().catch(() => console.log("000 - -"));' 2>/dev/null || echo "000 - -"
}
api_healthy() {
  local st
  st="$(compose exec -T api node -e 'fetch("http://127.0.0.1:" + (process.env.API_PORT || 4000) + "/api/v1/health")
    .then((r) => console.log(r.status), () => console.log(0))' 2>/dev/null || echo 0)"
  [ "$st" = 200 ]
}
running_image() { # running_image <service> → image ID of its running container (empty if none)
  local id
  id="$(compose ps -q "$1" 2>/dev/null | head -n1)"
  if [ -n "$id" ]; then docker inspect --format '{{.Image}}' "$id" 2>/dev/null || true; fi
}
pins_running() { # every pinned image ID is the one actually running
  local svc key
  for svc in api web; do
    key="PPANEL_$(printf '%s' "$svc" | tr '[:lower:]' '[:upper:]')_IMAGE_ID"
    [ "$(running_image "$svc")" = "$(env_get "$key" "$ENV_FILE")" ] || return 1
  done
}
pin_image() { # ref → ref@sha256:<digest> when the image has a matching repo digest
  local ref="$1" repo="${1%:*}" dig
  dig="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null | grep -m1 "^${repo}@" || true)"
  if [ -n "$dig" ]; then printf '%s@%s' "$ref" "${dig#*@}"; else printf '%s' "$ref"; fi
}
migrate_status() { # prisma migrate status with the image currently pinned in .env
  compose run --rm --no-deps -T api migrate-status 2>&1
}
db_size_mb() {
  compose exec -T postgres psql -U ppanel -d ppanel -At -c "SELECT pg_database_size('ppanel') / 1048576" 2>/dev/null |
    tr -d '\r' || echo 0
}
free_mb() { df -Pm "$1" 2>/dev/null | awk 'NR == 2 { print $4 }'; }

# ---------------------------------------------------------------- 1. pre-flight (read-only)
[ -n "$TARGET" ] || usage 2
[[ "$TARGET" =~ $SEMVER_RE ]] || die "invalid version '$TARGET' (SemVer MAJOR.MINOR.PATCH[-pre])"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo): it edits $ENV_FILE and manages Docker"
[ -f "$ENV_FILE" ] || die "$ENV_FILE not found: pPanel is not installed in $DIR (use install.sh)"
for c in docker awk sed gzip tar; do command -v "$c" >/dev/null 2>&1 || die "missing prerequisite: $c"; done
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin required"

FROM="$(env_get PPANEL_VERSION "$ENV_FILE")"
[[ "$FROM" =~ $SEMVER_RE ]] || die "PPANEL_VERSION in $ENV_FILE is '$FROM' (not a release version)"

# the bundle we run from must be the target release (it carries the new compose.yml / scripts)
if [ "$BUNDLE" != "$DIR" ]; then
  [ -f "$BUNDLE/compose.yml" ] || die "$BUNDLE is not a pPanel Center bundle (no compose.yml)"
  bundle_ver="$(tr -d '[:space:]' <"$BUNDLE/VERSION" 2>/dev/null || true)"
  [ "$bundle_ver" = "$TARGET" ] ||
    die "this bundle is '${bundle_ver:-unknown}', not $TARGET: unpack ppanel-center-$TARGET.tar.gz and run its upgrade.sh"
else
  warn "running from $DIR itself: compose.yml and scripts are NOT updated (run the bundle's upgrade.sh for that)"
fi

[ -n "$(compose ps --status running -q postgres 2>/dev/null)" ] ||
  die "postgres is not running (cd $DIR && docker compose up -d --wait) — fix the current install first"

read -r st reported schema <<<"$(center_info)"
case "$st" in
  200) ;;
  000) reported="-" ;;
  *) die "the running Center answers HTTP $st on /api/v1/version|health — fix it before upgrading" ;;
esac

# ---- same version: no-op when healthy, otherwise resume migrate + start (an interrupted upgrade)
if [ "$TARGET" = "$FROM" ]; then
  if [ "$reported" = "$TARGET" ] && pins_running && api_healthy; then
    log "pPanel $TARGET is already installed, pinned and healthy — nothing to do"
    exit 0
  fi
  warn "pinned to $TARGET but the stack is not running it healthily (Center reports '$reported'): resuming migrate + start"
  RESUME=1
else
  RESUME=0
  [ "$st" = 200 ] || die "the Center is not running/healthy (api down) — fix it before upgrading"
  [ "$reported" = "$FROM" ] ||
    die "$ENV_FILE pins $FROM but the running Center reports '$reported' — resolve the mismatch first"
  case "$(semver_cmp "$TARGET" "$FROM")" in
    -1) die "refusing to downgrade $FROM → $TARGET. Roll back with: $DIR/rollback.sh <pre-upgrade dump> $TARGET" ;;
    0) die "version $TARGET equals $FROM in precedence but differs textually; refusing" ;;
  esac
  ms="$(migrate_status)" || true
  printf '%s' "$ms" | grep -q 'Database schema is up to date' ||
    die "the current database has pending or failed migrations (prisma migrate status):
$(printf '%s' "$ms" | tail -n 12)"
  [ -n "$(env_get PPANEL_MASTER_KEY "$ENV_FILE")" ] || die "PPANEL_MASTER_KEY is empty in $ENV_FILE"
  fp="$(env_get PPANEL_MASTER_KEY "$ENV_FILE" | openssl dgst -sha256 2>/dev/null | awk '{ print substr($NF, 1, 16) }' || true)"
  log "pre-flight OK: $FROM → $TARGET (schema ${schema/#-/unknown}); master key fingerprint ${fp:-n/a} — confirm it matches your escrowed copy"
  need=$(($(db_size_mb) * 2 + 256))
  have="$(free_mb "$DIR/backups")"
  [ "${have:-0}" -ge "$need" ] || die "not enough free space in $DIR/backups for the pre-upgrade dump (${have:-?} MB < $need MB)"
fi

# ---------------------------------------------------------------- 2. new images (still nothing changed)
[ "$IMAGE_PREFIX" = "__unset__" ] && IMAGE_PREFIX="$(env_get PPANEL_IMAGE_PREFIX "$ENV_FILE")"
if [ -n "$IMAGES_DIR" ]; then
  [ -d "$IMAGES_DIR" ] || die "--images-dir $IMAGES_DIR is not a directory"
  for f in "$IMAGES_DIR"/*.tar "$IMAGES_DIR"/*.tar.gz; do
    [ -f "$f" ] || continue
    log "docker load $(basename "$f")"
    docker load -q -i "$f" >/dev/null || die "docker load $f failed — nothing changed, $FROM is still running"
  done
fi
declare -A NEW_REF NEW_ID
for svc in api web; do
  ref="${IMAGE_PREFIX}ppanel-${svc}:${TARGET}"
  if [ "$RESUME" -eq 1 ]; then
    ref="$(env_get "PPANEL_$(printf '%s' "$svc" | tr '[:lower:]' '[:upper:]')_IMAGE" "$ENV_FILE")"
  fi
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    log "pulling $ref"
    docker pull -q "$ref" >/dev/null 2>&1 ||
      die "cannot get image $ref (wrong version/prefix? offline: use --images-dir) — nothing changed, $FROM is still running"
  fi
  label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$ref" 2>/dev/null || true)"
  [ "$label" = "$TARGET" ] ||
    die "image $ref is labelled version '${label:-none}', expected $TARGET — refusing; nothing changed, $FROM is still running"
  NEW_REF[$svc]="$(pin_image "$ref")"
  NEW_ID[$svc]="$(docker image inspect --format '{{.Id}}' "$ref")"
  log "new $svc image: ${NEW_REF[$svc]}"
done

# ---------------------------------------------------------------- 3. maintenance: stop api + web, dump
TS="$(date -u +%Y%m%dT%H%M%SZ)"
DUMP=""
ROLLBACK_HINT=""
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -n "$ROLLBACK_HINT" ]; then
    printf '\n[upgrade] FAILED after the Center was stopped. Restore %s exactly with:\n  sudo %s\n' \
      "$FROM" "$ROLLBACK_HINT" >&2
    printf '[upgrade] (or fix the cause and re-run: sudo %s/upgrade.sh %s — it resumes migrate + start)\n\n' \
      "$BUNDLE" "$TARGET" >&2
  fi
}
trap on_exit EXIT

if [ "$RESUME" -eq 0 ]; then
  log "stopping api + web (maintenance window; agents reconnect afterwards)"
  compose stop api web >/dev/null 2>&1 || die "cannot stop api/web"
  DUMP="$DIR/backups/pre-upgrade-${FROM}-${TARGET}-${TS}.sql.gz"
  bc="$DIR/backup-center.sh"
  [ -x "$bc" ] || bc="$BUNDLE/backup-center.sh"
  if ! PPANEL_DIR="$DIR" "$bc" dump "$DUMP" >&2; then
    compose up -d >/dev/null 2>&1 || true
    die "pre-upgrade dump failed — restarted $FROM unchanged"
  fi
  # previous compose files + .env (pins) next to the dump: rollback.sh restores them from here
  keep=()
  for f in compose.yml Caddyfile env.template VERSION observability systemd .env; do
    [ -e "$DIR/$f" ] && keep+=("$f")
  done
  (umask 077 && tar -C "$DIR" -czf "${DUMP%.sql.gz}.release.tar.gz" "${keep[@]}")
  chmod 0600 "$DUMP" "${DUMP%.sql.gz}.release.tar.gz"
  ROLLBACK_HINT="$DIR/rollback.sh $DUMP $FROM"
  [ -x "$DIR/rollback.sh" ] || [ -f "$BUNDLE/rollback.sh" ] || ROLLBACK_HINT="<bundle>/rollback.sh $DUMP $FROM"
  log "pre-upgrade dump: $DUMP"
else
  DUMP="$(find "$DIR/backups" -maxdepth 1 -name "pre-upgrade-*-${TARGET}-*.sql.gz" 2>/dev/null | sort | tail -n1)"
  if [ -n "$DUMP" ]; then
    prev="$(basename "$DUMP" | sed -E "s/^pre-upgrade-(.+)-${TARGET//./\\.}-[0-9TZ]+\.sql\.gz$/\1/")"
    ROLLBACK_HINT="$DIR/rollback.sh $DUMP $prev"
  fi
fi

# ---------------------------------------------------------------- 4. new bundle files + pins
if [ "$BUNDLE" != "$DIR" ] && [ "$RESUME" -eq 0 ]; then
  log "installing the $TARGET bundle files into $DIR"
  install -d -m 0755 "$DIR/observability" "$DIR/lib" "$DIR/systemd"
  install -m 0644 "$BUNDLE/compose.yml" "$BUNDLE/Caddyfile" "$BUNDLE/env.template" "$DIR/"
  install -m 0644 "$BUNDLE"/observability/*.yml "$DIR/observability/"
  install -m 0644 "$BUNDLE"/systemd/*.service "$DIR/systemd/"
  for s in install.sh install-agent.sh backup-center.sh upgrade.sh rollback.sh; do
    [ -f "$BUNDLE/$s" ] && install -m 0755 "$BUNDLE/$s" "$DIR/$s"
  done
  for f in center-backup.sh center-restore.sh _center-common.sh; do
    [ -f "$BUNDLE/lib/$f" ] && install -m 0755 "$BUNDLE/lib/$f" "$DIR/lib/$f"
  done
  # keys introduced by the new env.template are appended with their defaults; existing values are kept
  while IFS= read -r line; do
    case "$line" in '#'* | '') continue ;; esac
    key="${line%%=*}"
    grep -q "^${key}=" "$ENV_FILE" || printf '%s\n' "$line" >>"$ENV_FILE"
  done <"$DIR/env.template"
  ROLLBACK_HINT="${ROLLBACK_HINT/#<bundle>/$DIR}"
fi
env_set PPANEL_VERSION "$TARGET" "$ENV_FILE"
env_set PPANEL_IMAGE_PREFIX "$IMAGE_PREFIX" "$ENV_FILE"
env_set PPANEL_API_IMAGE "${NEW_REF[api]}" "$ENV_FILE"
env_set PPANEL_WEB_IMAGE "${NEW_REF[web]}" "$ENV_FILE"
env_set PPANEL_API_IMAGE_ID "${NEW_ID[api]}" "$ENV_FILE"
env_set PPANEL_WEB_IMAGE_ID "${NEW_ID[web]}" "$ENV_FILE"
printf '%s\n' "$TARGET" >"$DIR/VERSION"
compose config --quiet || die "compose configuration is invalid after the upgrade (see above)"

# ---------------------------------------------------------------- 5. migrate (new image), start, verify
log "prisma migrate deploy ($TARGET)"
compose run --rm --no-deps -T api migrate >&2 || die "database migration failed"
log "starting the $TARGET stack"
compose up -d --quiet-pull --wait --wait-timeout "$WAIT_TIMEOUT" >&2 || {
  compose ps >&2 || true
  compose logs --tail 60 api >&2 || true
  die "stack did not become healthy"
}
pins_running || die "running containers do not use the pinned $TARGET images"
read -r st reported schema <<<"$(center_info)"
if [ "$st" != 200 ] || [ "$reported" != "$TARGET" ]; then
  die "Center reports HTTP $st version '$reported', expected $TARGET"
fi
api_healthy || die "GET /api/v1/health is not 200"
trap - EXIT

printf '{"upgraded":true,"from":"%s","to":"%s","schemaVersion":"%s","dump":"%s"}\n' \
  "$FROM" "$TARGET" "$schema" "$DUMP"
cat >&2 <<EOF

================================================================================
 pPanel $FROM → $TARGET: healthy (schema $schema)
 pre-upgrade dump: ${DUMP:-n/a}
 rollback (loses every change written after the dump):
   sudo ${ROLLBACK_HINT:-$DIR/rollback.sh <pre-upgrade dump> <previous version>}
 next: upgrade the agents (Center first, then agents) — docs/UPGRADE_RUNBOOK.md §5
================================================================================
EOF
