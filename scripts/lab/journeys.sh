#!/usr/bin/env bash
# P8-T03 user journeys (docs/ACCEPTANCE.md): real web UI (production build) against the real Center API.
#
#   scripts/lab/journeys.sh [--lab] [--skip-build] [--evidence <dir>]
#
#   --lab        also run the journeys that need lab agents (J02 enroll, J05 deploy approval);
#                prereqs: scripts/lab/up.sh + scripts/lab/images.sh (agent binary mounted in the nodes)
#   --skip-build reuse apps/api/dist and apps/web/.next from a previous run
#   --evidence   write <dir>/p8-t03-journeys.json and copy screenshots to <dir>/p8-journeys/
#
# What it does: (re)creates DB `ppanel_journeys`, `prisma migrate deploy` (NO seeder: J01 needs first
# boot; the Playwright `seed` project seeds after J01), builds and starts the API (`node dist/main.js`,
# :4000, gateway :4443 only with --lab) and the web (`next start`, :3100), runs
# playwright.journeys.config.ts, then kills every process it started (ports 4000/4443/3100 free again).
# Per-run secrets come from `openssl rand` and are never printed. Lab/CI only.
#
# Env: JOURNEYS_PG_BASE  postgres URL without DB (default: dev compose postgresql://ppanel:ppanel_dev_only@127.0.0.1:55432)
#      JOURNEYS_PSQL     "docker" (default when psql is missing: docker exec ppanel-dev-postgres-1) or "host"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB=0
BUILD=1
EVIDENCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lab) LAB=1 ;;
    --skip-build) BUILD=0 ;;
    --evidence)
      EVIDENCE="$2"
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

PG_BASE="${JOURNEYS_PG_BASE:-postgresql://ppanel:ppanel_dev_only@127.0.0.1:55432}"
DB_NAME=ppanel_journeys
DB_URL="${PG_BASE}/${DB_NAME}?schema=public"
ART="${JOURNEYS_ARTIFACTS:-${ROOT}/.lab/journeys}"
API_BASE="http://localhost:4000/api/v1"
WEB_URL="http://localhost:3100"
PORTS=(4000 3100)
[[ $LAB == 1 ]] && PORTS+=(4443)

log() { printf '[journeys %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

listeners() { lsof -nP -ti "tcp:$1" -sTCP:LISTEN 2>/dev/null || true; }

for p in "${PORTS[@]}"; do
  if [[ -n "$(listeners "$p")" ]]; then
    echo "port $p is already in use — stop whatever listens there first (this script never kills foreign processes)" >&2
    exit 1
  fi
done

psql_run() { # sql
  if [[ "${JOURNEYS_PSQL:-}" == "host" ]] || { [[ -z "${JOURNEYS_PSQL:-}" ]] && command -v psql >/dev/null; }; then
    psql "${PG_BASE}/postgres" -v ON_ERROR_STOP=1 -qc "$1"
  else
    docker exec ppanel-dev-postgres-1 psql -U ppanel -d postgres -v ON_ERROR_STOP=1 -qc "$1"
  fi
}

API_PID=""
WEB_PID=""
LAB_AGENT_STARTED=0
# shellcheck disable=SC2317  # invoked via trap
cleanup() {
  local rc=$?
  set +e
  for pid in "$WEB_PID" "$API_PID"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  done
  sleep 2
  for pid in "$WEB_PID" "$API_PID"; do
    [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null
  done
  # ports were free at start, so anything listening now was started by this run (e.g. next-server child)
  for p in "${PORTS[@]}"; do
    for pid in $(listeners "$p"); do kill "$pid" 2>/dev/null; done
  done
  if [[ $LAB_AGENT_STARTED == 1 ]]; then
    docker exec ppanel-lab-node-b sh -c "pkill -f '[p]panel-agent-linux-arm64 run' || true" >/dev/null 2>&1
  fi
  sleep 1
  for p in "${PORTS[@]}"; do
    [[ -n "$(listeners "$p")" ]] && log "WARNING: port $p still in use"
  done
  log "teardown done (exit $rc)"
  exit "$rc"
}
trap cleanup EXIT INT TERM

mkdir -p "$ART"
rm -rf "${ART:?}/screens" "${ART:?}/test-results" "${ART:?}/html" "${ART:?}/results.json"

# --- per-run secrets (never printed)
export NODE_ENV=development
export DATABASE_URL="$DB_URL"
PPANEL_MASTER_KEY="$(openssl rand -base64 32)"
JWT_ACCESS_SECRET="$(openssl rand -base64 48)"
PPANEL_SETUP_TOKEN="$(openssl rand -hex 24)"
export PPANEL_MASTER_KEY JWT_ACCESS_SECRET PPANEL_SETUP_TOKEN

log "recreating database ${DB_NAME}"
psql_run "DROP DATABASE IF EXISTS ${DB_NAME} WITH (FORCE)"
psql_run "CREATE DATABASE ${DB_NAME}"

if [[ $BUILD == 1 ]]; then
  log "building API (prisma generate + tsup)"
  pnpm --filter @ppanel/api build >"${ART}/build-api.log" 2>&1 || {
    tail -40 "${ART}/build-api.log"
    exit 1
  }
  log "building web (next build, NEXT_PUBLIC_API_BASE=${API_BASE})"
  NODE_ENV=production NEXT_PUBLIC_API_BASE="$API_BASE" pnpm --filter @ppanel/web build >"${ART}/build-web.log" 2>&1 || {
    tail -40 "${ART}/build-web.log"
    exit 1
  }
fi

log "prisma migrate deploy"
(cd "${ROOT}/apps/api" && pnpm exec prisma migrate deploy >"${ART}/migrate.log" 2>&1) || {
  tail -40 "${ART}/migrate.log"
  exit 1
}

log "starting API on :4000"
(
  cd "${ROOT}/apps/api"
  export API_PORT=4000 WEB_ORIGIN="$WEB_URL" PPANEL_PUBLIC_WEB_URL="$WEB_URL" LOG_LEVEL=warn
  if [[ $LAB == 1 ]]; then
    export API_HOST=0.0.0.0 PPANEL_PUBLIC_GATEWAY_URL=https://host.docker.internal:4443 \
      PPANEL_PUBLIC_API_URL=http://host.docker.internal:4000
  else
    export API_HOST=127.0.0.1 PPANEL_DISABLE_GATEWAY=1
  fi
  exec node --enable-source-maps dist/main.js
) >"${ART}/api.log" 2>&1 &
API_PID=$!

log "starting web on :3100 (next start)"
(
  cd "${ROOT}/apps/web"
  export NODE_ENV=production PORT=3100
  exec node_modules/.bin/next start -p 3100
) >"${ART}/web.log" 2>&1 &
WEB_PID=$!

wait_http() { # url what seconds
  local end=$((SECONDS + $3))
  until curl -fs -o /dev/null "$1"; do
    if ((SECONDS > end)); then
      log "timeout waiting for $2"
      tail -30 "${ART}/api.log" "${ART}/web.log" || true
      exit 1
    fi
    sleep 1
  done
}
wait_http "${API_BASE}/setup/status" "API" 90
wait_http "${WEB_URL}/login" "web" 90
log "API + web up"

if [[ $LAB == 1 ]]; then
  LAB_AGENT_STARTED=1
  # remove pPanel artefacts left on node-b by earlier runs (same reset as e2e_p4.py); legacy sites untouched
  docker exec ppanel-lab-dind docker -H unix:///run/dind/docker.sock ps -aq --filter label=ppanel.managed=true |
    xargs -r docker exec ppanel-lab-dind docker -H unix:///run/dind/docker.sock rm -f >/dev/null || true
  docker exec ppanel-lab-node-b sh -c \
    'rm -rf /etc/nginx/ppanel-managed /etc/nginx/conf.d/ppanel-managed.conf && nginx -t -q && nginx -s reload'
fi

log "running Playwright journeys (lab=${LAB})"
set +e
(
  cd "${ROOT}/apps/web"
  JOURNEYS_LAB="$LAB" JOURNEYS_ARTIFACTS="$ART" JOURNEYS_API_BASE="$API_BASE" E2E_BASE_URL="$WEB_URL" \
    JOURNEYS_SETUP_TOKEN="$PPANEL_SETUP_TOKEN" JOURNEYS_DATABASE_URL="$DB_URL" \
    node_modules/.bin/playwright test -c playwright.journeys.config.ts
)
PW_RC=$?
set -e

if [[ -n "$EVIDENCE" ]]; then
  node "${ROOT}/scripts/lab/journeys-report.mjs" "${ART}/results.json" "${EVIDENCE}/p8-t03-journeys.json" \
    --lab "$LAB" --shots "${ART}/screens" --shots-out "${EVIDENCE}/p8-journeys"
  (cd "$ROOT" && node_modules/.bin/prettier --write "${EVIDENCE}/p8-t03-journeys.json" >/dev/null)
fi
log "playwright exit ${PW_RC}; artifacts in ${ART} (traces/videos only for failures)"
exit "$PW_RC"
