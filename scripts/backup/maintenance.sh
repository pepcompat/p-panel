#!/usr/bin/env bash
# pPanel backup MAINTENANCE identity (ADR-0009, docs/AGENT_PROTOCOL.md "Backups and restores (P6)").
#
# Agents only hold an append-only credential (rest-server --private-repos --append-only): they can create and
# read snapshots but never forget/prune/delete. Everything destructive or repository-wide runs HERE, as the
# operator, against the full-access maintenance listener on the same data (never reachable from the nodes):
#
#   maintenance.sh [global opts] init   <serverUser>                        restic init (agents cannot)
#   maintenance.sh [global opts] prune  <serverUser> [--keep-last N] [--keep-daily N] [--keep-weekly N] [--keep-monthly N]
#                                                                           restic forget --prune (retention)
#   maintenance.sh [global opts] copy   <serverUser>                        restic copy → offsite S3 (inits it once)
#   maintenance.sh [global opts] check  <serverUser> [--read-data-subset P]  restic check (P = 1..100, percent)
#   maintenance.sh [global opts] unlock <serverUser>                        remove stale locks (REPO_LOCKED)
#   maintenance.sh [global opts] snapshots <serverUser>                     list (read-only)
#
# Global options:
#   --lab                     use the lab: .lab/backup.env + .lab/backup/{admin,minio}.env + servers/<user>.env,
#                             restic runs in the lab helper image on the ppanel-lab-backup-admin network
#   --report <centerUrl>      POST the outcome to <centerUrl>/api/v1/backup-maintenance/reports
#                             (Authorization: Bearer $PPANEL_BACKUP_REPORT_TOKEN — a report-only token)
#   --repository-id <uuid>    the Center's backup repository id for the report (or PPANEL_BACKUP_REPOSITORY_ID)
#
# Environment (production; never put secrets in argv — they are read from env/files only):
#   PPANEL_BACKUP_ADMIN_URL            maintenance rest-server base URL, e.g. https://backup.internal:8001
#   PPANEL_BACKUP_ADMIN_USER / _PASSWORD   its credential
#   PPANEL_BACKUP_REPO_PASSWORD_FILE   file holding <serverUser>'s repo password (from the Center recovery export)
#   PPANEL_BACKUP_S3_ENDPOINT / PPANEL_BACKUP_S3_BUCKET, AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   (copy)
#   RESTIC_BIN (default: restic in PATH, >= 0.17)   or PPANEL_BACKUP_RESTIC_DOCKER_IMAGE (+ _DOCKER_NETWORK)
# The offsite repository uses the same repo password as the primary one (restic copy re-encrypts nothing).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
log() { printf '[ppanel-backup %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

LAB=0
REPORT_URL=""
REPO_ID="${PPANEL_BACKUP_REPOSITORY_ID:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lab) LAB=1; shift ;;
    --report) REPORT_URL="${2:?--report needs a URL}"; shift 2 ;;
    --repository-id) REPO_ID="${2:?--repository-id needs a uuid}"; shift 2 ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) break ;;
  esac
done
CMD="${1:-}"; USER_="${2:-}"
[[ -n "${CMD}" && -n "${USER_}" ]] || { sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 2; }
shift 2
[[ "${USER_}" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "invalid server user '${USER_}'"

if [[ "${LAB}" == 1 ]]; then
  BK="${REPO_ROOT}/.lab/backup"
  [[ -f "${REPO_ROOT}/.lab/backup.env" ]] || die ".lab/backup.env missing (run scripts/lab/backup-images.sh)"
  set -a
  # shellcheck disable=SC1091
  source "${BK}/admin.env"
  # shellcheck disable=SC1091
  source "${BK}/minio.env"
  # shellcheck disable=SC1090
  [[ -f "${BK}/servers/${USER_}.env" ]] && source "${BK}/servers/${USER_}.env"
  set +a
  # restic runs in the lab helper image ON the admin network (lab-backup-admin, lab-minio are not on labnet)
  PPANEL_BACKUP_RESTIC_DOCKER_IMAGE="${PPANEL_BACKUP_RESTIC_DOCKER_IMAGE:-127.0.0.1:55000/ppanel-backup/helper:lab}"
  PPANEL_BACKUP_DOCKER_NETWORK="${PPANEL_BACKUP_DOCKER_NETWORK:-ppanel-lab-backup-admin}"
  PPANEL_BACKUP_ADMIN_URL="http://lab-backup-admin:8000"
  PPANEL_BACKUP_S3_ENDPOINT="http://lab-minio:9000"
  PPANEL_BACKUP_S3_BUCKET="${PPANEL_BACKUP_S3_BUCKET:-ppanel-offsite}"
  AWS_ACCESS_KEY_ID="${MINIO_ROOT_USER:-}"
  AWS_SECRET_ACCESS_KEY="${MINIO_ROOT_PASSWORD:-}"
  REPO_PASSWORD="${PPANEL_LAB_BK_REPO_PASSWORD:-}"
else
  if [[ -n "${PPANEL_BACKUP_REPO_PASSWORD_FILE:-}" ]]; then
    REPO_PASSWORD="$(head -1 "${PPANEL_BACKUP_REPO_PASSWORD_FILE}")"
  else
    REPO_PASSWORD="${RESTIC_PASSWORD:-}"
  fi
fi
[[ -n "${REPO_PASSWORD:-}" ]] || die "no repository password for ${USER_} (PPANEL_BACKUP_REPO_PASSWORD_FILE)"
: "${PPANEL_BACKUP_ADMIN_URL:?PPANEL_BACKUP_ADMIN_URL is required}"
: "${PPANEL_BACKUP_ADMIN_USER:?PPANEL_BACKUP_ADMIN_USER is required}"
: "${PPANEL_BACKUP_ADMIN_PASSWORD:?PPANEL_BACKUP_ADMIN_PASSWORD is required}"

# Secrets go to restic via env only.
export RESTIC_PASSWORD="${REPO_PASSWORD}"
export RESTIC_REST_USERNAME="${PPANEL_BACKUP_ADMIN_USER}"
export RESTIC_REST_PASSWORD="${PPANEL_BACKUP_ADMIN_PASSWORD}"
export RESTIC_FROM_PASSWORD="${REPO_PASSWORD}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}" AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
REPO="rest:${PPANEL_BACKUP_ADMIN_URL%/}/${USER_}/"

restic_() {
  if [[ -n "${PPANEL_BACKUP_RESTIC_DOCKER_IMAGE:-}" ]]; then
    docker run --rm -i --network "${PPANEL_BACKUP_DOCKER_NETWORK:?}" --read-only --tmpfs /tmp --cap-drop ALL \
      --security-opt no-new-privileges:true \
      -e RESTIC_PASSWORD -e RESTIC_REST_USERNAME -e RESTIC_REST_PASSWORD -e RESTIC_FROM_PASSWORD \
      -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e HOME=/tmp \
      "${PPANEL_BACKUP_RESTIC_DOCKER_IMAGE}" --no-cache "$@"
  else
    "${RESTIC_BIN:-restic}" --no-cache "$@"
  fi
}

report() { # <kind> <ok:true|false> <detail>
  [[ -n "${REPORT_URL}" ]] || return 0
  [[ -n "${PPANEL_BACKUP_REPORT_TOKEN:-}" ]] || { log "WARN: --report given but PPANEL_BACKUP_REPORT_TOKEN unset; not reported"; return 0; }
  [[ "${REPO_ID}" =~ ^[0-9a-fA-F-]{36}$ ]] || { log "WARN: --repository-id <uuid> required for --report; not reported"; return 0; }
  local detail hdr body rid
  detail="$(printf '%s' "$3" | tr -c 'A-Za-z0-9 .:_=/,-' ' ' | cut -c1-500)"
  rid="$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]' || cat /proc/sys/kernel/random/uuid)"
  hdr="$(mktemp)"; chmod 600 "${hdr}"
  # the token goes through a 0600 header file, never argv
  printf 'Authorization: Bearer %s\nContent-Type: application/json\nAccept: application/json\nX-Request-ID: %s\n' \
    "${PPANEL_BACKUP_REPORT_TOKEN}" "${rid}" >"${hdr}"
  body="$(printf '{"repositoryId":"%s","serverUser":"%s","kind":"%s","ok":%s,"finishedAt":"%s","detail":"%s"}' \
    "${REPO_ID}" "${USER_}" "$1" "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${detail}")"
  if curl -fsS -m 20 -H @"${hdr}" --data-binary "${body}" "${REPORT_URL%/}/api/v1/backup-maintenance/reports" >/dev/null; then
    log "reported ${1} ok=${2} to ${REPORT_URL}"
  else
    log "WARN: report to ${REPORT_URL} failed"
  fi
  rm -f "${hdr}"
}

run_kind() { # <kind> <restic args...>
  local kind="$1"; shift
  local out rc=0
  out="$(restic_ "$@" 2>&1)" || rc=$?
  printf '%s\n' "${out}"
  if [[ "${rc}" == 0 ]]; then
    report "${kind}" true "$(printf '%s' "${out}" | tail -3 | tr '\n' ' ')"
  else
    report "${kind}" false "exit ${rc}: $(printf '%s' "${out}" | tail -3 | tr '\n' ' ')"
  fi
  return "${rc}"
}

case "${CMD}" in
  init)
    log "restic init ${USER_} via the maintenance listener"
    run_kind init -r "${REPO}" init
    ;;
  prune)
    keep=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --keep-last|--keep-daily|--keep-weekly|--keep-monthly|--keep-yearly)
          [[ "${2:-}" =~ ^[0-9]{1,4}$ ]] || die "$1 needs a number"; keep+=("$1" "$2"); shift 2 ;;
        *) die "unknown prune option $1" ;;
      esac
    done
    [[ ${#keep[@]} -gt 0 ]] || die "prune needs at least one --keep-* option"
    log "restic forget --prune ${USER_} ${keep[*]}"
    run_kind prune -r "${REPO}" forget --prune --group-by host,paths "${keep[@]}"
    ;;
  copy)
    : "${PPANEL_BACKUP_S3_ENDPOINT:?PPANEL_BACKUP_S3_ENDPOINT is required for copy}"
    : "${PPANEL_BACKUP_S3_BUCKET:?PPANEL_BACKUP_S3_BUCKET is required for copy}"
    DST="s3:${PPANEL_BACKUP_S3_ENDPOINT%/}/${PPANEL_BACKUP_S3_BUCKET}/${USER_}"
    if ! restic_ -r "${DST}" cat config >/dev/null 2>&1; then
      log "initialising offsite repo ${DST} (same chunker params as the primary)"
      restic_ -r "${DST}" init --from-repo "${REPO}" --copy-chunker-params >/dev/null
    fi
    log "restic copy ${USER_} → ${DST}"
    run_kind copy -r "${DST}" copy --from-repo "${REPO}"
    ;;
  check)
    args=(-r "${REPO}" check)
    if [[ "${1:-}" == "--read-data-subset" ]]; then
      [[ "${2:-}" =~ ^[0-9]{1,3}$ ]] || die "--read-data-subset needs a percentage"
      args+=("--read-data-subset=${2}%")
    fi
    run_kind check "${args[@]}"
    ;;
  unlock)
    run_kind unlock -r "${REPO}" unlock
    ;;
  snapshots)
    restic_ -r "${REPO}" snapshots "$@"
    ;;
  offsite-snapshots)
    : "${PPANEL_BACKUP_S3_ENDPOINT:?}" "${PPANEL_BACKUP_S3_BUCKET:?}"
    restic_ -r "s3:${PPANEL_BACKUP_S3_ENDPOINT%/}/${PPANEL_BACKUP_S3_BUCKET}/${USER_}" snapshots "$@"
    ;;
  *) die "unknown subcommand ${CMD}" ;;
esac
