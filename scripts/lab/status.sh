#!/usr/bin/env bash
# Show lab state: containers, health, nginx -t, package versions, per-site HTTP probes, P4 dind + registry.
# Read-only: never reloads/edits anything inside the nodes.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

lab_compose ps --format 'table {{.Name}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
rc=0
for n in "${LAB_NODES[@]}"; do
  echo "== ${n}"
  if ! docker inspect -f '{{.State.Running}}' "$n" 2>/dev/null | grep -q true; then
    echo "   NOT RUNNING"; rc=1; continue
  fi
  docker exec "$n" sh -c 'echo "   os: $(. /etc/os-release; echo $PRETTY_NAME) arch=$(uname -m) kernel=$(uname -r)"
    echo "   nginx: $(nginx -v 2>&1)"
    command -v php-fpm8.3 >/dev/null && echo "   php-fpm: $(php-fpm8.3 -v | head -1)" || echo "   php-fpm: (not installed)"
    echo "   nginx -t: $(nginx -t 2>&1 | tail -1)"
    echo "   agent mount: $(ls -1 /opt/ppanel-agent 2>/dev/null | tr "\n" " ")"' || rc=1
done
echo "== ppanel-lab-dind (node-b engine, privileged LAB-ONLY sidecar)"
if docker inspect -f '{{.State.Running}}' ppanel-lab-dind 2>/dev/null | grep -q true; then
  docker exec ppanel-lab-dind docker -H unix:///run/dind/docker.sock version --format '   engine: {{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}' || rc=1
  docker exec ppanel-lab-dind docker -H unix:///run/dind/docker.sock ps -a --format '   {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' || rc=1
  docker exec ppanel-lab-node-b sh -c 'test -S /var/run/docker.sock && echo "   node-b /var/run/docker.sock: socket ok" || echo "   node-b /var/run/docker.sock: MISSING"'
else
  echo "   NOT RUNNING"; rc=1
fi
echo "== ppanel-lab-registry (127.0.0.1:55000 on the Mac, lab-registry:5000 in the lab)"
if curl -fsS http://127.0.0.1:55000/v2/_catalog 2>/dev/null; then echo; else echo "   NOT REACHABLE"; rc=1; fi
echo "== P6 backup services"
for c in "${LAB_P6_SERVICES[@]}"; do
  printf '   %s: %s\n' "$c" "$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null || echo 'NOT PRESENT')"
done
for n in "${LAB_NODES[@]}"; do
  printf '   %s restic: %s\n' "$n" "$(docker exec "$n" /usr/local/bin/restic version 2>/dev/null || echo 'missing')"
done
exit $rc
