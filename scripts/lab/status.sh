#!/usr/bin/env bash
# Show lab state: containers, health, nginx -t, package versions, per-site HTTP probes.
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
exit $rc
