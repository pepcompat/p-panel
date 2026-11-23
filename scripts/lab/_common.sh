#!/usr/bin/env bash
# Shared helpers for pPanel lab scripts. Sourced, not executed.
# Safety: every compose call is pinned to project `ppanel-lab` and infra/compose/lab.yml.
set -euo pipefail

LAB_PROJECT="ppanel-lab"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_COMPOSE_FILE="${REPO_ROOT}/infra/compose/lab.yml"
# shellcheck disable=SC2034  # used by sourcing scripts
LAB_NODES=(ppanel-lab-node-a ppanel-lab-node-b)
# P4 services (node-b's docker-in-docker engine + local registry)
# shellcheck disable=SC2034
LAB_P4_SERVICES=(ppanel-lab-dind ppanel-lab-registry ppanel-lab-registry-fwd ppanel-lab-git)

# P4b: fixture repos served read-only by lab-git (scripts/lab/git-fixtures.sh fills it).
mkdir -p "${REPO_ROOT}/.lab/git"

# Agent binary mount: prefer apps/agent/bin if the agent team has built it, else an empty
# gitignored placeholder so compose never creates directories inside apps/.
if [[ -z "${PPANEL_AGENT_BIN_DIR:-}" ]]; then
  if [[ -d "${REPO_ROOT}/apps/agent/bin" ]]; then
    export PPANEL_AGENT_BIN_DIR="${REPO_ROOT}/apps/agent/bin"
  else
    mkdir -p "${REPO_ROOT}/.lab/agent-bin"
    export PPANEL_AGENT_BIN_DIR="${REPO_ROOT}/.lab/agent-bin"
  fi
fi

lab_compose() {
  docker compose -p "${LAB_PROJECT}" -f "${LAB_COMPOSE_FILE}" "$@"
}

log() { printf '[ppanel-lab %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
