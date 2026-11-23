#!/usr/bin/env bash
# Stop the pPanel observability backends. Removes ONLY the ppanel-observability compose project.
# Data volumes are kept unless --volumes is given.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
args=(down --remove-orphans)
if [ "${1:-}" = "--volumes" ]; then args+=(--volumes); fi
docker compose -p ppanel-observability -f "${ROOT}/infra/observability/compose.yml" "${args[@]}"
