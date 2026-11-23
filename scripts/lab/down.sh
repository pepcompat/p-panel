#!/usr/bin/env bash
# Stop and remove ONLY ppanel-lab resources (containers, network, the project's named volumes —
# including the P4 dind engine data/socket volumes, so every container deployed INSIDE lab-dind goes
# with them, and the lab registry storage).
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
  # P4 test images built by scripts/lab/images.sh (local tags only)
  docker images --format '{{.Repository}}:{{.Tag}}' | grep '^127\.0\.0\.1:55000/ppanel-test/' | xargs -r docker image rm 2>/dev/null || true
fi

leftover="$(docker ps -a --filter "label=com.docker.compose.project=${LAB_PROJECT}" -q)"
if [[ -n "${leftover}" ]]; then
  log "ERROR: leftover ${LAB_PROJECT} containers: ${leftover}"; exit 1
fi
leftover_vols="$(docker volume ls --filter "label=com.docker.compose.project=${LAB_PROJECT}" -q)"
if [[ -n "${leftover_vols}" ]]; then
  log "ERROR: leftover ${LAB_PROJECT} volumes: ${leftover_vols}"; exit 1
fi
rm -f "${REPO_ROOT}/.lab/images.env" "${REPO_ROOT}/.lab/backup.env"
# .lab/backup/ (generated lab credentials) is kept; the repositories themselves were in the backup-data volume.
log "down. no ${LAB_PROJECT} containers or volumes remain"
