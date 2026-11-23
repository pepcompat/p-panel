#!/usr/bin/env bash
# Start the pPanel observability backends (Prometheus, Loki, Mailpit, lab receiver) on 127.0.0.1.
# Generates the Prometheus scrape bearer token once (gitignored .lab/observability/scrape-token, 0600).
# The Center must use the same token: PPANEL_METRICS_SCRAPE_TOKEN_FILE=<repo>/.lab/observability/scrape-token
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT=ppanel-observability
COMPOSE_FILE="${ROOT}/infra/observability/compose.yml"
TOKEN_DIR="${ROOT}/.lab/observability"
TOKEN_FILE="${TOKEN_DIR}/scrape-token"

log() { printf '[observability] %s\n' "$*"; }

mkdir -p "${TOKEN_DIR}"
if [ ! -s "${TOKEN_FILE}" ]; then
  umask 077
  openssl rand -hex 32 | tr -d '\n' >"${TOKEN_FILE}"
  log "generated scrape token ${TOKEN_FILE}"
fi
chmod 0600 "${TOKEN_FILE}"
# Prometheus runs as nobody inside the container and must read the bind-mounted file.
# Docker Desktop (macOS) maps ownership; on Linux allow read for the container user only via ACL-less fallback.
if [ "$(uname -s)" = "Linux" ]; then chmod 0644 "${TOKEN_FILE}"; fi

docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" config --quiet
docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" up -d --build --wait --wait-timeout 180
log "up: prometheus http://127.0.0.1:59090  loki http://127.0.0.1:53100  mailpit smtp://127.0.0.1:51025 (ui http://127.0.0.1:58025)  receiver http://127.0.0.1:58080"
log "Center env: PPANEL_PROMETHEUS_URL=http://127.0.0.1:59090 PPANEL_LOKI_URL=http://127.0.0.1:53100 PPANEL_SMTP_URL=smtp://127.0.0.1:51025 PPANEL_METRICS_SCRAPE_TOKEN_FILE=${TOKEN_FILE}"
