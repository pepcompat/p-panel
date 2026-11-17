#!/usr/bin/env bash
# Stop and remove ONLY ppanel-lab resources (containers, network, the project's named volumes).
# Never touches other compose projects (e.g. ppanel-dev, amas-*). Built images are kept for speed;
# pass --images to also remove ppanel-lab-node-{a,b}:dev.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

remove_images=0
[[ "${1:-}" == "--images" ]] && remove_images=1

log "stopping project ${LAB_PROJECT} (containers + network + project volumes)"
lab_compose down --volumes --remove-orphans --timeout 10

if (( remove_images )); then
  docker image rm ppanel-lab-node-a:dev ppanel-lab-node-b:dev 2>/dev/null || true
fi

leftover="$(docker ps -a --filter "label=com.docker.compose.project=${LAB_PROJECT}" -q)"
if [[ -n "${leftover}" ]]; then
  log "ERROR: leftover ${LAB_PROJECT} containers: ${leftover}"; exit 1
fi
log "down. no ${LAB_PROJECT} containers remain"
