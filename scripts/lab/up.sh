#!/usr/bin/env bash
# Start the pPanel lab (2 disposable nodes + 2 tiny upstreams). Idempotent.
# Publishes NO ports. Contacts no remote host except Docker Hub for pinned base images.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

log "validating ${LAB_COMPOSE_FILE}"
lab_compose config --quiet
log "agent bin mount: ${PPANEL_AGENT_BIN_DIR} -> /opt/ppanel-agent (ro)"
log "building + starting project ${LAB_PROJECT}"
lab_compose up -d --build --wait --wait-timeout 120
log "up. run scripts/lab/status.sh for details"
