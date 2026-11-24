#!/usr/bin/env bash
# pPanel Center rollback (P8.04, docs/RELEASE_CONTRACT.md §4, docs/UPGRADE_RUNBOOK.md §7).
#
#   sudo /opt/ppanel/rollback.sh <backup-file> <previous-version> [options]
#   e.g. sudo /opt/ppanel/rollback.sh /opt/ppanel/backups/pre-upgrade-0.7.0-0.8.0-rc.1-<ts>.sql.gz 0.7.0
#
# Puts the Center back on <previous-version> with the database EXACTLY as in <backup-file> (the
# pre-upgrade dump upgrade.sh printed). Everything written after that dump is LOST (jobs, audit events,
# heartbeats, users/apps/rules created since): a safety dump of the current database is taken first
# (backups/pre-rollback-<current>-<ts>.sql.gz) so nothing is destroyed irrecoverably.
#
# Order: verify the dump + previous images (nothing changes if they are missing) → safety dump → stop
# api + web → restore (schema reset + dump, one transaction) → restore the previous compose files and
# image pins (from <dump>.release.tar.gz when present) → start → verify version + health + schema.
# The master key (PPANEL_MASTER_KEY) must be the one the dump was taken with; it is never changed here.
#
# Options:
#   --images-dir DIR   `docker load` every *.tar / *.tar.gz in DIR first (previous images, offline)
#   --dir DIR          install root (default /opt/ppanel)
#   --yes              do not ask for confirmation (non-interactive)
#   --wait-timeout SEC how long to wait for a healthy stack (default 420)
#   -h | --help
set -euo pipefail
umask 022

DIR=/opt/ppanel
DUMP=""
PREV=""
IMAGES_DIR=""
YES=0
WAIT_TIMEOUT=420

log() { printf '[rollback] %s\n' "$*" >&2; }
warn() { printf '[rollback] WARNING: %s\n' "$*" >&2; }
die() {
  printf '[rollback] ERROR: %s\n' "$*" >&2
  exit 1
}
usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --images-dir) IMAGES_DIR="${2:?}"; shift 2 ;;
    --dir) DIR="${2:?}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --wait-timeout) WAIT_TIMEOUT="${2:?}"; shift 2 ;;
    -h | --help) usage 0 ;;
    -*) warn "unknown option: $1"; usage 2 ;;
    *)
      if [ -z "$DUMP" ]; then DUMP="$1"; elif [ -z "$PREV" ]; then PREV="${1#v}"; else die "too many arguments"; fi
      shift
      ;;
  esac
done

ENV_FILE="$DIR/.env"
compose() { docker compose --project-directory "$DIR" -f "$DIR/compose.yml" --env-file "$ENV_FILE" "$@"; }
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
# same probe as upgrade.sh: /version (0.8.0+) or /health (older) from inside the api container
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
psql_q() { compose exec -T postgres psql -U ppanel -d ppanel -At -v ON_ERROR_STOP=1 -c "$1" | tr -d '\r'; }
LATEST_MIGRATION_SQL="SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name DESC LIMIT 1"

# ---------------------------------------------------------------- 1. checks (nothing changes yet)
if [ -z "$DUMP" ] || [ -z "$PREV" ]; then usage 2; fi
[[ "$PREV" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "invalid version '$PREV'"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -f "$ENV_FILE" ] || die "$ENV_FILE not found (set --dir)"
[ -f "$DUMP" ] || die "backup file $DUMP not found"
gzip -t "$DUMP" 2>/dev/null || die "$DUMP is not a valid gzip file"
gzip -dc "$DUMP" | tail -n 5 | grep -q 'PostgreSQL database dump complete' || die "$DUMP is incomplete (no pg_dump end marker)"
# the dump's own schema version: last _prisma_migrations row in its COPY block
dump_schema="$(gzip -dc "$DUMP" | awk '
  /^COPY public\._prisma_migrations \(/ {
    h = $0; sub(/^[^(]*\(/, "", h); sub(/\).*$/, "", h); n = split(h, c, ", ")
    for (i = 1; i <= n; i++) col[c[i]] = i
    on = 1; next
  }
  on && /^\\\.$/ { exit }
  on {
    split($0, f, "\t")
    if (f[col["finished_at"]] != "\\N" && f[col["rolled_back_at"]] == "\\N" && f[col["migration_name"]] > m)
      m = f[col["migration_name"]]
  }
  END { print m }')"

CUR="$(env_get PPANEL_VERSION "$ENV_FILE")"
SNAP="${DUMP%.sql.gz}.release.tar.gz"
prefix="$(env_get PPANEL_IMAGE_PREFIX "$ENV_FILE")"
api_ref="${prefix}ppanel-api:${PREV}"
web_ref="${prefix}ppanel-web:${PREV}"
SNAPDIR=""
cleanup() { [ -z "$SNAPDIR" ] || rm -rf "$SNAPDIR"; }
trap cleanup EXIT
if [ -f "$SNAP" ]; then
  SNAPDIR="$(mktemp -d)"
  chmod 700 "$SNAPDIR"
  tar -C "$SNAPDIR" -xzf "$SNAP" || die "cannot unpack $SNAP"
  snap_ver="$(env_get PPANEL_VERSION "$SNAPDIR/.env")"
  [ "$snap_ver" = "$PREV" ] || die "$SNAP belongs to version '$snap_ver', not $PREV — wrong dump or version?"
  api_ref="$(env_get PPANEL_API_IMAGE "$SNAPDIR/.env")"
  web_ref="$(env_get PPANEL_WEB_IMAGE "$SNAPDIR/.env")"
  [ "$(env_get PPANEL_MASTER_KEY "$SNAPDIR/.env")" = "$(env_get PPANEL_MASTER_KEY "$ENV_FILE")" ] ||
    die "PPANEL_MASTER_KEY differs from the one in use when the dump was taken — the restored secrets would be unreadable"
  log "release snapshot $SNAP: version $snap_ver"
else
  warn "no release snapshot next to the dump ($SNAP): using $api_ref / $web_ref and the current compose files"
fi

if [ -n "$IMAGES_DIR" ]; then
  [ -d "$IMAGES_DIR" ] || die "--images-dir $IMAGES_DIR is not a directory"
  for f in "$IMAGES_DIR"/*.tar "$IMAGES_DIR"/*.tar.gz; do
    [ -f "$f" ] || continue
    log "docker load $(basename "$f")"
    docker load -q -i "$f" >/dev/null || die "docker load $f failed"
  done
fi
for ref in "$api_ref" "$web_ref"; do
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    log "pulling $ref"
    docker pull -q "$ref" >/dev/null 2>&1 || die "previous image $ref is not available (use --images-dir) — nothing changed"
  fi
  label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$ref" 2>/dev/null || true)"
  [ -z "$label" ] || [ "$label" = "$PREV" ] || die "image $ref is labelled '$label', expected $PREV — nothing changed"
done
api_id="$(docker image inspect --format '{{.Id}}' "$api_ref")"
web_id="$(docker image inspect --format '{{.Id}}' "$web_ref")"

log "rollback ${CUR:-?} → $PREV, database from $(basename "$DUMP") (schema ${dump_schema:-unknown})"
log "every change written after that dump will be LOST (a safety dump of the current database is taken first)"
if [ "$YES" -eq 0 ]; then
  [ -t 0 ] || die "not a terminal: pass --yes to confirm"
  printf '[rollback] type the version %s to continue: ' "$PREV" >&2
  read -r answer
  [ "$answer" = "$PREV" ] || die "aborted"
fi

# ---------------------------------------------------------------- 2. safety dump, stop, restore
if [ -z "$(compose ps --status running -q postgres 2>/dev/null)" ]; then
  compose up -d --wait postgres >&2 || die "cannot start postgres"
fi
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAFETY="$DIR/backups/pre-rollback-${CUR:-unknown}-${TS}.sql.gz"
bc="$DIR/backup-center.sh"
[ -x "$bc" ] || bc="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backup-center.sh"
PPANEL_DIR="$DIR" "$bc" dump "$SAFETY" >&2 || die "safety dump of the current database failed — nothing changed"
log "safety dump of the current database: $SAFETY"

log "stopping api + web"
compose stop api web >/dev/null 2>&1 || die "cannot stop api/web"
psql_q "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = 'ppanel' AND pid <> pg_backend_pid()" >/dev/null

log "restoring the database (schema reset + dump, single transaction)"
# Reset first: --clean only drops objects that exist in the dump, so tables/columns added by a newer
# migration would survive and break the next upgrade. ON_ERROR_STOP + --single-transaction = all or nothing.
if ! { printf 'DROP SCHEMA IF EXISTS public CASCADE;\nCREATE SCHEMA public;\n'; gzip -dc "$DUMP"; } |
  compose exec -T postgres psql -U ppanel -d ppanel -q -v ON_ERROR_STOP=1 --single-transaction >/dev/null; then
  die "restore failed and was rolled back (database unchanged, api/web stopped). Fix the cause and re-run, or restart with: cd $DIR && docker compose up -d"
fi
got_schema="$(psql_q "$LATEST_MIGRATION_SQL")"
[ "$got_schema" = "$dump_schema" ] || die "restored schema '$got_schema' != dump schema '$dump_schema'"

# ---------------------------------------------------------------- 3. previous release files + pins, start
if [ -n "$SNAPDIR" ]; then
  for f in compose.yml Caddyfile env.template; do
    [ -f "$SNAPDIR/$f" ] && install -m 0644 "$SNAPDIR/$f" "$DIR/$f"
  done
  [ -d "$SNAPDIR/observability" ] && install -m 0644 "$SNAPDIR"/observability/*.yml "$DIR/observability/"
fi
env_set PPANEL_VERSION "$PREV" "$ENV_FILE"
env_set PPANEL_API_IMAGE "$api_ref" "$ENV_FILE"
env_set PPANEL_WEB_IMAGE "$web_ref" "$ENV_FILE"
env_set PPANEL_API_IMAGE_ID "$api_id" "$ENV_FILE"
env_set PPANEL_WEB_IMAGE_ID "$web_id" "$ENV_FILE"
printf '%s\n' "$PREV" >"$DIR/VERSION"
compose config --quiet || die "compose configuration is invalid (see above)"

log "starting $PREV"
compose up -d --quiet-pull --wait --wait-timeout "$WAIT_TIMEOUT" >&2 || {
  compose ps >&2 || true
  compose logs --tail 60 api >&2 || true
  die "stack did not become healthy on $PREV"
}

# ---------------------------------------------------------------- 4. verify
for pair in "api:$api_id" "web:$web_id"; do
  svc="${pair%%:*}"
  got="$(docker inspect --format '{{.Image}}' "$(compose ps -q "$svc" | head -n1)")"
  [ "$got" = "${pair#*:}" ] || die "$svc runs $got, expected the pinned $PREV image ${pair#*:}"
done
read -r st reported _ <<<"$(center_info)"
[ "$st" = 200 ] || die "Center answers HTTP $st after the rollback"
if [ "$reported" = "-" ]; then
  # a Center without /version and without a version in /health: trust the verified image label
  reported="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$api_ref")"
fi
[ "$reported" = "$PREV" ] || die "Center reports version '$reported', expected $PREV"
schema_now="$(psql_q "$LATEST_MIGRATION_SQL")"

printf '{"rolledBack":true,"from":"%s","to":"%s","schemaVersion":"%s","restoredFrom":"%s","safetyDump":"%s"}\n' \
  "${CUR:-unknown}" "$PREV" "$schema_now" "$DUMP" "$SAFETY"
cat >&2 <<EOF

================================================================================
 pPanel is back on $PREV (schema $schema_now), database = $(basename "$DUMP")
 lost: everything written after that dump (still inside the safety dump $SAFETY)
 agents: keep running; one already upgraded to a newer version stays connected (same protocol
 major) — downgrade it with install-agent.sh --version $PREV if you want the fleet uniform.
================================================================================
EOF
