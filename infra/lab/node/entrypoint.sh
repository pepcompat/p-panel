#!/bin/sh
# pPanel lab node entrypoint (PID 1 is tini). Approximates a host where nginx and php-fpm
# are long-running services. There is NO systemd here: services are plain processes.
set -eu

role="${PPANEL_LAB_NODE_ROLE:-?}"
echo "[ppanel-lab] node role=${role} starting $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if command -v php-fpm8.3 >/dev/null 2>&1 && [ "${PPANEL_LAB_PHP_FPM:-1}" = "1" ]; then
  mkdir -p /run/php
  php-fpm8.3 --daemonize
  echo "[ppanel-lab] php-fpm8.3 started"
fi

# Validate before start, exactly like an operator would.
nginx -t

# The agent binary (built by apps/agent) is bind-mounted read-only at /opt/ppanel-agent.
# It is NOT started automatically: tests start it explicitly with `docker exec -d`.
if [ -x /opt/ppanel-agent/ppanel-agent-linux-arm64 ]; then
  echo "[ppanel-lab] agent binary present at /opt/ppanel-agent (not auto-started)"
fi

exec nginx -g 'daemon off;'
