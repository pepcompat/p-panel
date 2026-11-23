#!/usr/bin/env bash
# P4 real-lab test of the agent's container.* operations against the lab-dind engine:
# cross-compiles the containerops test binary (linux/arm64), copies it into ppanel-lab-node-b,
# creates one UNLABELLED container directly in dind (operator-made, must never be touched) and runs
# TestLabDindContainers inside node-b. Requires: scripts/lab/up.sh + scripts/lab/images.sh.
# Lab only. Leaves the lab running; removes only what it created.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

NODE=ppanel-lab-node-b
DIND=ppanel-lab-dind
UNMANAGED=ppanel-labtest-0badc0de
ENV_FILE="${REPO_ROOT}/.lab/images.env"
[[ -f "${ENV_FILE}" ]] || { log "ERROR: ${ENV_FILE} missing (run scripts/lab/images.sh)"; exit 1; }
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

bin="$(mktemp -d)/containerops.test"
log "building containerops test binary (linux/arm64)"
(cd "${REPO_ROOT}/apps/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o "${bin}" ./internal/containerops)
docker cp "${bin}" "${NODE}:/tmp/containerops.test" >/dev/null

dk() { docker exec "${DIND}" docker -H unix:///run/dind/docker.sock "$@"; }
log "creating unlabelled fixture container ${UNMANAGED} directly in dind"
dk rm -f "${UNMANAGED}" >/dev/null 2>&1 || true
dk run -d --name "${UNMANAGED}" "${PPANEL_LAB_IMAGE_WEB_V1}" >/dev/null

rc=0
docker exec -e PPANEL_LAB_DIND=1 -e PPANEL_LAB_UNMANAGED="${UNMANAGED}" \
  -e PPANEL_LAB_IMAGE_WEB_V1 -e PPANEL_LAB_IMAGE_WEB_V2 -e PPANEL_LAB_IMAGE_BROKEN -e PPANEL_LAB_IMAGE_ENVECHO \
  "${NODE}" /tmp/containerops.test -test.run 'TestLabDindContainers' -test.v -test.count=1 -test.timeout 10m || rc=$?

log "cleanup: removing ${UNMANAGED} and the test binary"
dk rm -f "${UNMANAGED}" >/dev/null 2>&1 || true
docker exec "${NODE}" rm -f /tmp/containerops.test
rm -rf "$(dirname "${bin}")"
log "dind containers now:"; dk ps -a --format '  {{.Names}}  {{.Status}}  {{.Labels}}'
exit "${rc}"
