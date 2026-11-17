#!/usr/bin/env bash
# Read-only evidence for P3-T01: sha256 of every nginx config file (and symlink targets)
# plus nginx master PID, its start time (since boot, in clock ticks) and worker PIDs.
# Run before and after Discover/Observe; outputs must be identical.
# Usage: scripts/lab/checksum-nginx.sh [--out FILE]
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

out=""
[[ "${1:-}" == "--out" ]] && out="${2:?--out needs a file}"

collect() {
  for n in "${LAB_NODES[@]}"; do
    echo "### node=${n}"
    docker exec "$n" sh -c '
      set -e
      cd /
      find etc/nginx -type l | sort | while read -r l; do echo "symlink $l -> $(readlink "$l")"; done
      find etc/nginx etc/ssl/ppanel-lab -type f | sort | xargs sha256sum
      pid=$(cat /run/nginx.pid)
      # field 22 of /proc/<pid>/stat = starttime (clock ticks since boot); stable unless restarted
      st=$(sed -e "s/^.*) //" /proc/$pid/stat | cut -d" " -f20)
      echo "nginx_master_pid $pid"
      echo "nginx_master_starttime_ticks $st"
      echo "nginx_master_lstart $(ps -o lstart= -p $pid)"
      echo "nginx_worker_pids $(pgrep -P $pid | sort -n | tr "\n" " ")"
    '
  done
}

data="$(collect)"
digest="$(printf '%s\n' "$data" | shasum -a 256 | cut -d' ' -f1)"
report="$(printf '%s\n### aggregate_sha256 %s\n' "$data" "$digest")"
if [[ -n "$out" ]]; then printf '%s\n' "$report" > "$out"; fi
printf '%s\n' "$report"
