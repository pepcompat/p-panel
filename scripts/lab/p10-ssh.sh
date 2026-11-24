#!/usr/bin/env bash
# P10 lab SSH target (docs/P10_SSH_CONTRACT.md §8). LAB ONLY — never point this at a real host.
#
#   p10-ssh.sh up       build + start lab-node-s (profile `p10`, --no-deps: node-a/node-b are never recreated)
#   p10-ssh.sh down     stop + remove lab-node-s (its agent state volume is kept; `down --volumes` removes it too)
#   p10-ssh.sh rekey    delete the sshd host keys, generate new ones and restart sshd (= "changed host key")
#   p10-ssh.sh status   container state, sshd host key fingerprints, loopback reachability of 127.0.0.1:52222
#
# lab-node-s = the lab node image (node-a layers) built with WITH_SSHD=1: hardened openssh-server, user `ops`
# (uid 1001, no password), host keys generated at the first start. sshd is published on 127.0.0.1:52222 only.
# The pPanel agent binary is mounted at /opt/ppanel-agent like on the other nodes (not auto-started).
# Never touches other projects (amas-*, ppanel-dev) or the P9 services.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

P10_SERVICE=lab-node-s
P10_CONTAINER=ppanel-lab-node-s
P10_PORT=52222

p10_compose() { lab_compose --profile p10 "$@"; }

fingerprints() {
  docker exec "${P10_CONTAINER}" sh -c 'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done'
}

sshd_pid() { docker exec "${P10_CONTAINER}" cat /run/sshd.pid 2>/dev/null; }

wait_sshd() { # wait until sshd answers with an SSH banner on the published loopback port
  local i
  for i in $(seq 1 40); do
    if python3 -I - "${P10_PORT}" <<'PY' 2>/dev/null; then return 0; fi
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2)
s.settimeout(2)
sys.exit(0 if s.recv(64).startswith(b"SSH-2.0-") else 1)
PY
    sleep 0.5
  done
  log "ERROR: sshd not reachable on 127.0.0.1:${P10_PORT}"
  return 1
}

cmd="${1:-}"
case "${cmd}" in
  up)
    lab_compose config --quiet
    log "agent bin mount: ${PPANEL_AGENT_BIN_DIR} -> /opt/ppanel-agent (ro)"
    p10_compose up -d --build --no-deps --wait --wait-timeout 180 "${P10_SERVICE}"
    wait_sshd
    log "lab-node-s up: sshd on 127.0.0.1:${P10_PORT} (user ops, public key only)"
    fingerprints
    ;;
  down)
    shift
    p10_compose rm -s -f "${P10_SERVICE}" >/dev/null
    if [[ "${1:-}" == "--volumes" ]]; then
      docker volume rm -f "${LAB_PROJECT}_node-s-agent-state" >/dev/null
      log "removed volume ${LAB_PROJECT}_node-s-agent-state"
    fi
    log "lab-node-s removed"
    ;;
  rekey)
    docker inspect "${P10_CONTAINER}" >/dev/null 2>&1 || { log "ERROR: ${P10_CONTAINER} is not running (p10-ssh.sh up)"; exit 1; }
    log "old host keys:"
    fingerprints
    pid="$(sshd_pid)"
    docker exec "${P10_CONTAINER}" sh -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && /usr/sbin/sshd -t'
    # SIGHUP: the listening sshd re-executes itself and loads the new host keys (same pid, sessions unaffected)
    docker exec "${P10_CONTAINER}" kill -HUP "${pid}"
    sleep 1
    wait_sshd
    log "new host keys (sshd restarted):"
    fingerprints
    ;;
  status)
    docker ps -a --filter "name=^${P10_CONTAINER}$" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
    if docker inspect "${P10_CONTAINER}" >/dev/null 2>&1; then
      echo "sshd pid: $(sshd_pid || echo '-')"
      fingerprints || true
      if wait_sshd >/dev/null 2>&1; then echo "127.0.0.1:${P10_PORT}: SSH banner OK"; else echo "127.0.0.1:${P10_PORT}: unreachable"; fi
      docker exec "${P10_CONTAINER}" sh -c 'ps -eo pid,user,args | grep -E "[s]shd" || true'
    fi
    ;;
  *)
    echo "usage: $0 up|down [--volumes]|rekey|status" >&2
    exit 2
    ;;
esac
