#!/usr/bin/env bash
# P9 lab networking (docs/P9_NETWORK_CONTRACT.md §6). LAB ONLY. Requires scripts/lab/up.sh first.
#
#   p9-net.sh up              start the profile-`p9` services (lab-center-private, lab-do-fake, lab-gateway) and
#                             attach the EXISTING node-a / node-b to their "VPC" networks (docker network connect)
#   p9-net.sh down            detach the nodes, remove the p9 services and the p9 networks
#   p9-net.sh cut <node>      disconnect node-a|node-b|gateway from its VPC network ("private path offline")
#   p9-net.sh restore <node>  reconnect it with its lab address
#   p9-net.sh status          print the attachments
#
# Never runs `compose up` for lab-node-b or anything depending on it (recreating node-b makes lab-dind lose its
# network namespace). Never touches other projects (amas-*, ppanel-dev). Lab truth (matches infra/lab/do-fake):
#   ppanel-lab-vpc-a 10.110.0.0/24: lab-center-private .2, node-a .11, gateway .20
#   ppanel-lab-vpc-b 10.120.0.0/24: lab-center-private .2, node-b .12
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

P9_SERVICES=(lab-center-private lab-do-fake lab-gateway)
VPC_A=ppanel-lab-vpc-a
VPC_B=ppanel-lab-vpc-b

# node -> "container network ip"
node_attach() {
  case "$1" in
    node-a) echo "ppanel-lab-node-a ${VPC_A} 10.110.0.11" ;;
    node-b) echo "ppanel-lab-node-b ${VPC_B} 10.120.0.12" ;;
    gateway) echo "ppanel-lab-gateway ${VPC_A} 10.110.0.20" ;;
    *) log "ERROR: unknown node '$1' (node-a|node-b|gateway)"; exit 2 ;;
  esac
}

attached() { # container network
  docker inspect -f "{{if index .NetworkSettings.Networks \"$2\"}}yes{{end}}" "$1" 2>/dev/null | grep -q yes
}

connect() {
  local c net ip
  read -r c net ip <<<"$(node_attach "$1")"
  docker inspect "${c}" >/dev/null 2>&1 || { log "ERROR: ${c} is not running (scripts/lab/up.sh first)"; exit 1; }
  if attached "${c}" "${net}"; then
    log "${c} already on ${net}"
  else
    docker network connect --ip "${ip}" "${net}" "${c}"
    log "${c} connected to ${net} as ${ip}"
  fi
}

disconnect() {
  local c net ip
  read -r c net ip <<<"$(node_attach "$1")"
  if attached "${c}" "${net}"; then
    docker network disconnect "${net}" "${c}"
    log "${c} disconnected from ${net} (was ${ip})"
  else
    log "${c} not on ${net}"
  fi
}

cmd="${1:-}"
case "${cmd}" in
  up)
    docker image inspect ppanel-lab-node-a:dev >/dev/null 2>&1 || { log "ERROR: ppanel-lab-node-a:dev missing (scripts/lab/up.sh)"; exit 1; }
    log "starting p9 services: ${P9_SERVICES[*]} (--no-deps: existing lab services are left untouched)"
    lab_compose --profile p9 up -d --no-deps --no-build --wait --wait-timeout 120 "${P9_SERVICES[@]}"
    connect node-a
    connect node-b
    log "p9 up. fake DigitalOcean API: http://127.0.0.1:58090 (token \${PPANEL_LAB_DO_TOKEN:-lab-do-token-not-a-secret})"
    ;;
  down)
    for n in node-a node-b; do
      c="$(node_attach "${n}" | cut -d' ' -f1)"
      if docker inspect "${c}" >/dev/null 2>&1; then disconnect "${n}"; fi
    done
    log "removing p9 services"
    lab_compose --profile p9 rm --stop --force "${P9_SERVICES[@]}" >/dev/null
    for net in "${VPC_A}" "${VPC_B}" ppanel-lab-p9-egress; do
      if docker network inspect "${net}" >/dev/null 2>&1; then
        docker network rm "${net}" >/dev/null && log "network ${net} removed"
      fi
    done
    vol="${LAB_PROJECT}_gateway-agent-state"
    if docker volume inspect "${vol}" >/dev/null 2>&1; then
      docker volume rm "${vol}" >/dev/null && log "volume ${vol} removed"
    fi
    log "p9 down"
    ;;
  cut)
    [[ -n "${2:-}" ]] || { log "usage: $0 cut <node-a|node-b|gateway>"; exit 2; }
    disconnect "$2"
    ;;
  restore)
    [[ -n "${2:-}" ]] || { log "usage: $0 restore <node-a|node-b|gateway>"; exit 2; }
    connect "$2"
    ;;
  status)
    for n in node-a node-b gateway; do
      read -r c net ip <<<"$(node_attach "${n}")"
      if attached "${c}" "${net}"; then s="on ${net} (${ip})"; else s="NOT on ${net}"; fi
      printf '  %-22s %s\n' "${c}" "${s}"
    done
    docker ps --filter "label=com.docker.compose.project=${LAB_PROJECT}" --filter "name=ppanel-lab-center-private" \
      --filter "name=ppanel-lab-do-fake" --filter "name=ppanel-lab-gateway" --format '  {{.Names}}  {{.Status}}'
    ;;
  *)
    echo "usage: $0 up|down|cut <node>|restore <node>|status" >&2
    exit 2
    ;;
esac
