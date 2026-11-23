#!/usr/bin/env bash
# P4b real-lab test of the agent's build node + compose execution (image.build, compose.apply):
# cross-compiles the handlers test binary (linux/arm64), copies it into ppanel-lab-node-b (the lab build
# node: git installed, /etc/ppanel-agent/config.yaml with build.enabled) and runs TestLabBuildAndCompose
# against lab-dind (Engine API), lab-git (git://lab-git/*.git) and lab-registry (push).
# Requires: scripts/lab/up.sh + scripts/lab/git-fixtures.sh. Lab only. Leaves the lab running; the test
# removes the containers it created (named volumes are kept — the agent never removes volumes).
# Set PPANEL_LAB_BUILD_TEMPLATE=0 to skip the nestjs template build (needs the npm registry).
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

NODE=ppanel-lab-node-b
ENV_FILE="${REPO_ROOT}/.lab/git.env"
[[ -f "${ENV_FILE}" ]] || { log "ERROR: ${ENV_FILE} missing (run scripts/lab/git-fixtures.sh)"; exit 1; }
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

bin="$(mktemp -d)/handlers.test"
log "building handlers test binary (linux/arm64)"
(cd "${REPO_ROOT}/apps/agent" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o "${bin}" ./internal/handlers)
docker cp "${bin}" "${NODE}:/tmp/handlers.test" >/dev/null

envs=(-e PPANEL_LAB_BUILD=1 -e "PPANEL_LAB_BUILD_TEMPLATE=${PPANEL_LAB_BUILD_TEMPLATE:-1}")
for k in $(grep -oE '^PPANEL_LAB_GIT_[A-Z0-9_]+' "${ENV_FILE}"); do envs+=(-e "${k}"); done

rc=0
docker exec "${envs[@]}" "${NODE}" /tmp/handlers.test -test.run 'TestLabBuildAndCompose' -test.v -test.count=1 -test.timeout 40m || rc=$?

docker exec "${NODE}" rm -f /tmp/handlers.test
rm -rf "$(dirname "${bin}")"
log "dind containers now:"
docker exec ppanel-lab-dind docker -H unix:///run/dind/docker.sock ps -a --format '  {{.Names}}  {{.Status}}'
exit "${rc}"
