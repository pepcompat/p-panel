#!/usr/bin/env bash
# pPanel Center restore (P6.06, docs/RECOVERY_RUNBOOK.md).
#
#   center-restore.sh <snapshot|latest> <target-db-url>
#
# Restores a Center snapshot into a FRESH (empty) database, verifies the dump checksum, then checks
# the Prisma migration status of the restored DB against this checkout. It never touches the
# running Center's database and refuses a non-empty target.
#
# Env: PPANEL_CENTER_BACKUP_REPO, PPANEL_CENTER_BACKUP_PASSWORD (from offline escrow),
#      PPANEL_BACKUP_TOOLS (auto|host|docker), PPANEL_RESTORE_KEEP_DIR (optional: copy restored files there),
#      PPANEL_SKIP_MIGRATION_STATUS=1 to skip the `prisma migrate status` check.
# After it: start the API with the SAME PPANEL_MASTER_KEY (escrow) against <target-db-url>.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=scripts/backup/_center-common.sh
. "$HERE/_center-common.sh"

[ $# -eq 2 ] || die "usage: $0 <snapshot|latest> <target-db-url>"
snapshot="$1"
target_url="$2"
[[ "$snapshot" =~ ^([a-f0-9]{8,64}|latest)$ ]] || die "snapshot must be a restic id or 'latest'"
require_repo_env
need_tools
work="$(mktemp -d "${TMPDIR:-/tmp}/ppanel-center-restore.XXXXXX")"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
t0="$(now_ms)"

log "restic restore $snapshot"
if [ "$snapshot" = latest ]; then
  restic_tool "$work" restore latest --tag ppanel-center --host ppanel-center --target "$work/r" >&2
else
  restic_tool "$work" restore "$snapshot" --target "$work/r" >&2
fi
t_fetch="$(now_ms)"
manifest="$(find "$work/r" -name manifest.json -path '*ppanel-center*' | head -1)"
[ -n "$manifest" ] || die "snapshot has no ppanel-center/manifest.json"
dir="$(dirname "$manifest")"
want="$(sed -nE 's/.*"sha256": "([a-f0-9]{64})".*/\1/p' "$manifest" | head -1)"
got="$(sha256_file "$dir/center.dump")"
[ "$want" = "$got" ] || die "dump checksum mismatch (manifest $want, file $got)"
log "dump checksum ok ($got)"

pg_env_from_url "$target_url"
tables="$(pg_tool "$work" psql -At -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
[ "$tables" = 0 ] || die "target database $PGDATABASE is not empty ($tables tables) — restore only into a fresh database"

log "pg_restore → $PGDATABASE@$PGHOST:$PGPORT"
pg_tool "$work" pg_restore --no-owner --no-privileges --exit-on-error --single-transaction \
  --dbname "$PGDATABASE" "$dir/center.dump"
t_restore="$(now_ms)"
users="$(pg_tool "$work" psql -At -c 'SELECT count(*) FROM users')"
servers="$(pg_tool "$work" psql -At -c "SELECT count(*) FROM servers WHERE status <> 'revoked'")"
ca="$(pg_tool "$work" psql -At -c 'SELECT count(*) FROM ca_keys')"
inflight="$(pg_tool "$work" psql -At -c "SELECT count(*) FROM jobs WHERE status IN ('queued','leased','running')")"
log "restored: users=$users servers=$servers ca_keys=$ca in-flight-jobs=$inflight (these expire; they are not replayed)"

status="skipped"
if [ "${PPANEL_SKIP_MIGRATION_STATUS:-0}" != 1 ]; then
  log "prisma migrate status (restored DB vs this checkout)"
  # migrate status needs a host-reachable URL (the original one, not the docker-rewritten host)
  if (cd "$ROOT/apps/api" && DATABASE_URL="$target_url" pnpm exec prisma migrate status >"$work/status.txt" 2>&1); then
    status="up_to_date"
  else
    status="pending_or_failed"
    log "migrations differ — review, then run: DATABASE_URL=<target> pnpm --filter @ppanel/api prisma:migrate"
    sed 's/^/  /' "$work/status.txt" >&2
  fi
fi
if [ -n "${PPANEL_RESTORE_KEEP_DIR:-}" ]; then
  mkdir -p "$PPANEL_RESTORE_KEEP_DIR"
  cp "$dir"/manifest.json "$dir"/migrations.txt "$PPANEL_RESTORE_KEEP_DIR"/
  [ -f "$dir/center.env.sanitized" ] && cp "$dir/center.env.sanitized" "$PPANEL_RESTORE_KEEP_DIR"/
fi
t_end="$(now_ms)"
printf '{"snapshot":"%s","database":"%s","users":%s,"servers":%s,"caKeys":%s,"inflightJobs":%s,"migrationStatus":"%s","fetchMs":%s,"restoreMs":%s,"totalMs":%s}\n' \
  "$snapshot" "$PGDATABASE" "$users" "$servers" "$ca" "$inflight" "$status" \
  "$((t_fetch - t0))" "$((t_restore - t_fetch))" "$((t_end - t0))"
log "next: start the API with the SAME PPANEL_MASTER_KEY against this database; agents reconnect with their current certificates"
