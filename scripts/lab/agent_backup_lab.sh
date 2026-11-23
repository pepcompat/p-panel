#!/usr/bin/env bash
# P6 real-lab test of the agent's backups/restores (backup.run / backup.snapshots / backup.verify / restore.run):
# cross-compiles the backupops test binary (linux/arm64), copies it into the lab nodes and runs, with each node's
# OWN append-only credential (.lab/backup/servers/<node>.env, passed via --env-file — never argv):
#   node-a  TestLabP6Files   P6-T01 files backup → delete → staging restore → identical checksums; backup.verify;
#                            append-only proof (agent `restic forget` refused); P6-T04 cancel mid-run → BACKUP_FAILED
#                            and no snapshot for that run
#   node-b  TestLabP6Docker  P6-T02 postgres dump (helper on lab-dind) → scratch restore → row counts + constraint
#                            names identical, scratch removed; volume backup → staging restore verified
# then, as the MAINTENANCE identity (scripts/backup/maintenance.sh --lab): prune works where the agent's forget
# failed, copy → offsite MinIO, offsite snapshots listed, check.
# Requires: scripts/lab/up.sh, scripts/lab/backup-images.sh, maintenance.sh --lab init node-a|node-b. Lab only.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

BK="${REPO_ROOT}/.lab/backup"
ENV_FILE="${REPO_ROOT}/.lab/backup.env"
MAINT="${REPO_ROOT}/scripts/backup/maintenance.sh"
[[ -f "${ENV_FILE}" ]] || { log "ERROR: ${ENV_FILE} missing (run scripts/lab/backup-images.sh)"; exit 1; }
# shellcheck disable=SC1090
source "${ENV_FILE}"

bin="$(mktemp -d)/backupops.test"
log "building backupops test binary (linux/arm64)"
(cd "${REPO_ROOT}/apps/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o "${bin}" ./internal/backupops)

rc=0
run_node() { # <node> <server user> <test regexp> [extra -e ...]
  local node="$1" user="$2" re="$3"; shift 3
  docker cp "${bin}" "${node}:/tmp/backupops.test" >/dev/null
  log "== ${node}: ${re}"
  docker exec --env-file "${BK}/servers/${user}.env" -e PPANEL_LAB_BACKUP=1 "$@" "${node}" \
    /tmp/backupops.test -test.run "${re}" -test.v -test.count=1 -test.timeout 30m || rc=$?
  docker exec "${node}" rm -f /tmp/backupops.test
}

run_node ppanel-lab-node-a node-a '^TestLabP6Files$'
run_node ppanel-lab-node-b node-b '^TestLabP6Docker$' \
  -e "PPANEL_LAB_BACKUP_HELPER_IMAGE=${PPANEL_LAB_BACKUP_HELPER_IMAGE}" -e "PPANEL_LAB_BACKUP_SCRATCH_PG=${PPANEL_LAB_BACKUP_SCRATCH_PG}"
rm -rf "$(dirname "${bin}")"

log "== maintenance identity (lab-backup-admin): prune / copy / check"
before="$("${MAINT}" --lab snapshots node-a --json | grep -o '"short_id"' | wc -l | tr -d ' ')"
"${MAINT}" --lab prune node-a --keep-last 1 >/dev/null || rc=$?
after="$("${MAINT}" --lab snapshots node-a --json | grep -o '"short_id"' | wc -l | tr -d ' ')"
log "node-a snapshots: ${before} before prune, ${after} after (--keep-last 1 per host+paths group)"
[[ "${after}" -lt "${before}" ]] || { log "ERROR: prune by the maintenance identity removed nothing"; rc=1; }
"${MAINT}" --lab copy node-a | tail -3 || rc=$?
off="$("${MAINT}" --lab offsite-snapshots node-a --json | grep -o '"short_id"' | wc -l | tr -d ' ')"
log "offsite (MinIO s3 ppanel-offsite/node-a) snapshots: ${off}"
[[ "${off}" -ge "${after}" && "${off}" -gt 0 ]] || { log "ERROR: offsite copy incomplete"; rc=1; }
"${MAINT}" --lab copy node-b | tail -1 || rc=$?
"${MAINT}" --lab check node-a | tail -2 || rc=$?
"${MAINT}" --lab check node-b | tail -2 || rc=$?
log "dind ppanel.backup containers now (expect none):"
docker exec ppanel-lab-dind docker -H unix:///run/dind/docker.sock ps -a --filter label=ppanel.backup --format '  {{.Names}} {{.Status}}'
exit "${rc}"
