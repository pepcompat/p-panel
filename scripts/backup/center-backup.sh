#!/usr/bin/env bash
# pPanel Center backup (P6.06, docs/RECOVERY_RUNBOOK.md).
#
#   center-backup.sh init        # once: restic init of the SEPARATE Center repository
#   center-backup.sh [backup]    # pg_dump --format=custom → restic (tag ppanel-center)
#   center-backup.sh snapshots   # list Center snapshots
#
# Env:
#   DATABASE_URL                   Center DB (postgresql://user:pass@host:port/db?schema=public)
#   PPANEL_CENTER_BACKUP_REPO      restic repository for the Center ONLY (not a server repo): rest:https://center:<pw>@backup:8000/center/ or an absolute path
#   PPANEL_CENTER_BACKUP_PASSWORD  restic password of that repo (escrowed offline; NOT stored in the repo)
#   PPANEL_CENTER_ENV_FILE         optional Center .env — copied with every secret value removed
#   PPANEL_BACKUP_TOOLS            auto | host | docker (pinned postgres:16.6-alpine + restic/restic:0.17.3)
#
# NOT included (by design): PPANEL_MASTER_KEY, JWT secrets, PPANEL_CENTER_BACKUP_PASSWORD, any
# secret value of the .env. The master key and repo passwords go to offline escrow (runbook §2).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/backup/_center-common.sh
. "$HERE/_center-common.sh"

cmd="${1:-backup}"
require_repo_env
need_tools
work="$(mktemp -d "${TMPDIR:-/tmp}/ppanel-center-backup.XXXXXX")"
trap 'rm -rf "$work"' EXIT

case "$cmd" in
  init)
    restic_tool "$work" init
    log "Center repository initialised"
    exit 0
    ;;
  snapshots)
    restic_tool "$work" snapshots --tag ppanel-center
    exit 0
    ;;
  backup) ;;
  *) die "usage: $0 [init|backup|snapshots]" ;;
esac

: "${DATABASE_URL:?set DATABASE_URL (Center database)}"
pg_env_from_url "$DATABASE_URL"
t0="$(now_ms)"
stage="$work/ppanel-center"
mkdir -p "$stage"
chmod 700 "$work" "$stage"

log "pg_dump --format=custom $PGDATABASE@$PGHOST:$PGPORT"
pg_tool "$work" pg_dump --format=custom --no-owner --no-privileges --compress=6 \
  --file "$stage/center.dump"
t_dump="$(now_ms)"
pg_tool "$work" psql -At -v ON_ERROR_STOP=1 \
  -c "SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name" \
  >"$stage/migrations.txt"
server_version="$(pg_tool "$work" psql -At -c 'SHOW server_version')"

if [ -n "${PPANEL_CENTER_ENV_FILE:-}" ]; then
  [ -r "$PPANEL_CENTER_ENV_FILE" ] || die "PPANEL_CENTER_ENV_FILE is not readable"
  # keep keys, drop every value that could be a secret (and any URL that may embed credentials)
  awk -F= '
    /^[[:space:]]*(#|$)/ { print; next }
    {
      key=$1; sub(/^[[:space:]]*(export[[:space:]]+)?/, "", key)
      if (key ~ /(SECRET|PASSWORD|PASS|TOKEN|KEY|PRIVATE|CREDENTIAL|DATABASE_URL|REDIS_URL|SMTP_URL|_REPO)$/ || key ~ /(SECRET|PASSWORD|TOKEN|MASTER)/)
        print key "=<removed: restore from offline escrow>"
      else print
    }' "$PPANEL_CENTER_ENV_FILE" >"$stage/center.env.sanitized"
fi

dump_sha="$(sha256_file "$stage/center.dump")"
dump_bytes="$(wc -c <"$stage/center.dump" | tr -d ' ')"
migrations="$(wc -l <"$stage/migrations.txt" | tr -d ' ')"
cat >"$stage/manifest.json" <<JSON
{
  "kind": "ppanel-center-backup",
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "database": "$PGDATABASE",
  "postgresServerVersion": "$server_version",
  "dump": { "file": "center.dump", "format": "custom", "bytes": $dump_bytes, "sha256": "$dump_sha" },
  "migrations": $migrations,
  "envIncluded": $([ -f "$stage/center.env.sanitized" ] && echo true || echo false),
  "masterKeyIncluded": false,
  "note": "PPANEL_MASTER_KEY and the repo passwords are NOT in this backup — restore them from offline escrow"
}
JSON

log "restic backup → Center repository"
restic_tool "$work" backup --json --host ppanel-center --tag ppanel-center "$stage" >"$work/restic.json"
summary="$(grep '"message_type":"summary"' "$work/restic.json" | tail -1)"
[ -n "$summary" ] || die "restic did not report a summary"
snapshot="$(printf '%s' "$summary" | sed -E 's/.*"snapshot_id":"([a-f0-9]+)".*/\1/')"
t_end="$(now_ms)"
printf '{"snapshot":"%s","dumpBytes":%s,"dumpSha256":"%s","migrations":%s,"dumpMs":%s,"totalMs":%s}\n' \
  "$snapshot" "$dump_bytes" "$dump_sha" "$migrations" "$((t_dump - t0))" "$((t_end - t0))"
log "Center backup done: snapshot $snapshot ($dump_bytes bytes, $((t_end - t0)) ms)"
