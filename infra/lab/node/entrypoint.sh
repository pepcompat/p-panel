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

# P4 (node-b only): the lab-dind sidecar's Engine socket lives on a shared volume; expose it at the
# standard path so the agent's default `docker.socket` (/var/run/docker.sock) works. No docker CLI
# is installed in the node: the agent must use the Engine API.
if [ -n "${PPANEL_LAB_DIND_SOCKET:-}" ]; then
  mkdir -p "$(dirname "${PPANEL_LAB_DIND_SOCKET}")"
  ln -sfn "${PPANEL_LAB_DIND_SOCKET}" /var/run/docker.sock
  echo "[ppanel-lab] /var/run/docker.sock -> ${PPANEL_LAB_DIND_SOCKET} (lab-dind sidecar)"
fi

# P10 (lab-node-s only: image built with WITH_SSHD=1). Host keys are generated at the first start of the
# container (never baked into the image); `scripts/lab/p10-ssh.sh rekey` regenerates them. sshd runs in the
# foreground in the background of this shell (-D -e: logs to the container log); tini reaps it.
if [ -x /usr/sbin/sshd ]; then
  mkdir -p /run/sshd
  chmod 0755 /run/sshd
  if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    ssh-keygen -A
    echo "[ppanel-lab] sshd host keys generated (first start)"
  fi
  /usr/sbin/sshd -t
  /usr/sbin/sshd -D -e &
  echo "[ppanel-lab] sshd started (pid $!)"
fi

# Validate before start, exactly like an operator would.
nginx -t

# The agent binary (built by apps/agent) is bind-mounted read-only at /opt/ppanel-agent.
# It is NOT started automatically: tests start it explicitly with `docker exec -d`.
if [ -x /opt/ppanel-agent/ppanel-agent-linux-arm64 ]; then
  echo "[ppanel-lab] agent binary present at /opt/ppanel-agent (not auto-started)"
fi

exec nginx -g 'daemon off;'
