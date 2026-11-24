#!/usr/bin/env bash
# pPanel Center backup for an installed Center (/opt/ppanel). docs/INSTALL.md §8, RECOVERY_RUNBOOK.md.
#
#   sudo /opt/ppanel/backup-center.sh dump [FILE]       # local pg_dump → /opt/ppanel/backups/center-<v>-<ts>.sql.gz
#   sudo /opt/ppanel/backup-center.sh restic init       # P6.06 restic Center backup (separate repo), once
#   sudo /opt/ppanel/backup-center.sh restic [backup]   # pg_dump --format=custom → restic (lib/center-backup.sh)
#   sudo /opt/ppanel/backup-center.sh restic snapshots
#
# `dump` needs only Docker (pg_dump runs inside the postgres container; plain SQL, gzip, 0600). It is
# what upgrade.sh uses for its pre-upgrade dump. `restic` reuses scripts/backup/center-backup.sh with
# DATABASE_URL pointed at the loopback-published PostgreSQL and PPANEL_CENTER_BACKUP_REPO/_PASSWORD
# from .env (or the environment). The master key is NEVER part of any backup: escrow it offline.
set -euo pipefail

DIR="${PPANEL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
ENV_FILE="$DIR/.env"
log() { printf '[backup-center] %s\n' "$*" >&2; }
die() {
  printf '[backup-center] ERROR: %s\n' "$*" >&2
  exit 1
}
env_get() {
  K="$1" awk 'BEGIN { k = ENVIRON["K"] "=" } index($0, k) == 1 { print substr($0, length(k) + 1); exit }' "$ENV_FILE"
}
compose() { docker compose --project-directory "$DIR" -f "$DIR/compose.yml" --env-file "$ENV_FILE" "$@"; }

[ -f "$ENV_FILE" ] || die "$ENV_FILE not found (is pPanel installed in $DIR? set PPANEL_DIR)"
[ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE (run as root)"

cmd="${1:-dump}"
[ $# -gt 0 ] && shift
case "$cmd" in
  dump)
    ver="$(env_get PPANEL_VERSION)"
    out="${1:-$DIR/backups/center-${ver:-unknown}-$(date -u +%Y%m%dT%H%M%SZ).sql.gz}"
    install -d -m 0700 "$(dirname "$out")"
    [ -n "$(compose ps --status running -q postgres)" ] || die "postgres is not running (cd $DIR && docker compose up -d postgres)"
    tmp="$out.partial"
    (
      umask 077
      compose exec -T postgres pg_dump -U ppanel -d ppanel --no-owner --no-privileges --clean --if-exists |
        gzip -6 >"$tmp"
    )
    gzip -t "$tmp" || die "dump is corrupt"
    # a valid pg_dump ends with this marker; an interrupted one does not
    gzip -dc "$tmp" | tail -n 5 | grep -q 'PostgreSQL database dump complete' || die "dump is incomplete"
    mv -f "$tmp" "$out"
    chmod 0600 "$out"
    migration="$(compose exec -T postgres psql -U ppanel -d ppanel -At -c \
      "SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name DESC LIMIT 1" | tr -d '\r')"
    printf '{"file":"%s","bytes":%s,"version":"%s","schemaVersion":"%s"}\n' \
      "$out" "$(wc -c <"$out" | tr -d ' ')" "${ver:-unknown}" "$migration"
    ;;
  restic)
    lib="$DIR/lib/center-backup.sh"
    [ -x "$lib" ] || die "$lib missing (bundle incomplete; re-run install.sh)"
    PPANEL_CENTER_BACKUP_REPO="${PPANEL_CENTER_BACKUP_REPO:-$(env_get PPANEL_CENTER_BACKUP_REPO)}"
    PPANEL_CENTER_BACKUP_PASSWORD="${PPANEL_CENTER_BACKUP_PASSWORD:-$(env_get PPANEL_CENTER_BACKUP_PASSWORD)}"
    [ -n "$PPANEL_CENTER_BACKUP_REPO" ] || die "set PPANEL_CENTER_BACKUP_REPO (env or $ENV_FILE)"
    [ -n "$PPANEL_CENTER_BACKUP_PASSWORD" ] || die "set PPANEL_CENTER_BACKUP_PASSWORD (env; escrowed offline)"
    pw="$(env_get POSTGRES_PASSWORD)"
    port="$(env_get PPANEL_DB_LOCAL_PORT)"
    DATABASE_URL="postgresql://ppanel:${pw}@127.0.0.1:${port:-55432}/ppanel?schema=public"
    PPANEL_CENTER_ENV_FILE="$ENV_FILE"
    export DATABASE_URL PPANEL_CENTER_BACKUP_REPO PPANEL_CENTER_BACKUP_PASSWORD PPANEL_CENTER_ENV_FILE
    exec "$lib" "${1:-backup}"
    ;;
  -h | --help) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "usage: $0 dump [FILE] | restic [init|backup|snapshots]" ;;
esac
