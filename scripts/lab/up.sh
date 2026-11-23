#!/usr/bin/env bash
# Start the pPanel lab (2 disposable nodes + 2 tiny upstreams + P4: node-b dind engine + local registry). Idempotent.
# Publishes loopback-only ports: lab registry 127.0.0.1:55000; P6 lab-backup-admin 127.0.0.1:58001, lab-minio 127.0.0.1:59000. Contacts no remote host except Docker Hub for pinned base images.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# P6: backup lab credentials (.lab/backup/, gitignored) must exist before compose mounts them
"$(dirname "${BASH_SOURCE[0]}")/backup-secrets.sh"
log "validating ${LAB_COMPOSE_FILE}"
lab_compose config --quiet
log "agent bin mount: ${PPANEL_AGENT_BIN_DIR} -> /opt/ppanel-agent (ro)"
log "building + starting project ${LAB_PROJECT}"
lab_compose up -d --build --wait --wait-timeout 300
"$(dirname "${BASH_SOURCE[0]}")/backup-secrets.sh" --bucket
log "up. run scripts/lab/status.sh for details"
log "P4: build + push test images with scripts/lab/images.sh (writes .lab/images.env)"
log "P4b: create the lab-git fixture repos with scripts/lab/git-fixtures.sh (writes .lab/git.env)"
log "P6: build + push the backup helper with scripts/lab/backup-images.sh (writes .lab/backup.env), then"
log "    scripts/backup/maintenance.sh init node-a / node-b; real-lab tests: scripts/lab/agent_backup_lab.sh"
