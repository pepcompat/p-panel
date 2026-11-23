#!/usr/bin/env bash
# Shared helpers for center-backup.sh / center-restore.sh (sourced, not executed).
# Tools: host `pg_dump`/`pg_restore`/`psql`/`restic` when present, else pinned Docker images.
# Secrets (DB password, restic password, rest-server credentials in the repo URL) are passed ONLY
# via environment variables — never argv, never logged.

PG_IMAGE="${PPANEL_PG_IMAGE:-postgres:16.6-alpine}"
RESTIC_IMAGE="${PPANEL_RESTIC_IMAGE:-restic/restic:0.17.3}"
TOOLS="${PPANEL_BACKUP_TOOLS:-auto}" # auto | host | docker

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() {
  log "ERROR: $*"
  exit 1
}

now_ms() { node -e 'process.stdout.write(String(Date.now()))'; }

need_tools() {
  if [ "$TOOLS" = auto ]; then
    if command -v pg_dump >/dev/null && command -v pg_restore >/dev/null && command -v psql >/dev/null && command -v restic >/dev/null; then
      TOOLS=host
    elif command -v docker >/dev/null; then
      TOOLS=docker
    else
      die "need pg_dump/pg_restore/psql/restic on PATH or docker"
    fi
  fi
  log "tools: $TOOLS"
}

# docker networking: on Linux use the host network; Docker Desktop reaches the host via host.docker.internal
docker_net_args() {
  if [ "$(uname -s)" = Linux ]; then
    printf '%s\n' --network=host
  else
    printf '%s\n' --add-host=host.docker.internal:host-gateway
  fi
}

docker_host() {
  local h="$1"
  if [ "$TOOLS" = docker ] && [ "$(uname -s)" != Linux ]; then
    case "$h" in 127.0.0.1 | localhost | ::1) h=host.docker.internal ;; esac
  fi
  printf '%s' "$h"
}

urldecode() {
  local s="${1//+/ }"
  printf '%b' "${s//%/\\x}"
}

# Exports PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE from a postgresql:// URL (query string dropped).
pg_env_from_url() {
  local url="$1" rest auth hostport
  case "$url" in postgresql://* | postgres://*) ;; *) die "not a postgresql:// URL" ;; esac
  rest="${url#*://}"
  rest="${rest%%\?*}"
  auth="${rest%%@*}"
  [ "$auth" = "$rest" ] && auth=""
  hostport="${rest#*@}"
  hostport="${hostport%%/*}"
  PGDATABASE="$(urldecode "${rest##*/}")"
  PGUSER="$(urldecode "${auth%%:*}")"
  if [ "${auth#*:}" != "$auth" ]; then PGPASSWORD="$(urldecode "${auth#*:}")"; else PGPASSWORD=""; fi
  PGHOST="${hostport%%:*}"
  if [ "${hostport#*:}" != "$hostport" ]; then PGPORT="${hostport##*:}"; else PGPORT=5432; fi
  PGHOST="$(docker_host "$PGHOST")"
  export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
}

# pg_tool <workdir> <tool> args… — runs pg_dump/pg_restore/psql (host or container, workdir mounted)
pg_tool() {
  local work="$1"
  shift
  if [ "$TOOLS" = host ]; then
    "$@"
  else
    local net
    net="$(docker_net_args)"
    docker run --rm -i "$net" --user "$(id -u):$(id -g)" \
      -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -e PGDATABASE \
      -v "$work:$work" -w "$work" "$PG_IMAGE" "$@"
  fi
}

# restic_tool <workdir> args… — RESTIC_REPOSITORY / RESTIC_PASSWORD come from the environment
restic_tool() {
  local work="$1"
  shift
  if [ "$TOOLS" = host ]; then
    restic --no-cache "$@"
  else
    local net mounts=()
    net="$(docker_net_args)"
    case "$RESTIC_REPOSITORY" in
      /*)
        mkdir -p "$RESTIC_REPOSITORY"
        mounts=(-v "$RESTIC_REPOSITORY:$RESTIC_REPOSITORY")
        ;;
      rest:*)
        if [ "$(uname -s)" != Linux ]; then
          RESTIC_REPOSITORY="$(printf '%s' "$RESTIC_REPOSITORY" | sed -E 's#@(127\.0\.0\.1|localhost)([:/])#@host.docker.internal\2#; s#//(127\.0\.0\.1|localhost)([:/])#//host.docker.internal\2#')"
          export RESTIC_REPOSITORY
        fi
        ;;
    esac
    docker run --rm -i "$net" --user "$(id -u):$(id -g)" \
      -e RESTIC_REPOSITORY -e RESTIC_PASSWORD -e RESTIC_REST_USERNAME -e RESTIC_REST_PASSWORD \
      -v "$work:$work" -w "$work" "${mounts[@]}" "$RESTIC_IMAGE" --no-cache "$@"
  fi
}

require_repo_env() {
  : "${PPANEL_CENTER_BACKUP_REPO:?set PPANEL_CENTER_BACKUP_REPO (separate restic repo for the Center, e.g. rest:https://center:…@backup:8000/center/ or an absolute path)}"
  : "${PPANEL_CENTER_BACKUP_PASSWORD:?set PPANEL_CENTER_BACKUP_PASSWORD (restic password of the Center repo; NOT the master key)}"
  RESTIC_REPOSITORY="$PPANEL_CENTER_BACKUP_REPO"
  RESTIC_PASSWORD="$PPANEL_CENTER_BACKUP_PASSWORD"
  export RESTIC_REPOSITORY RESTIC_PASSWORD
}

sha256_file() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
