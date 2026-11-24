# pPanel P8 lab — Ubuntu 24.04 with systemd as PID 1 (LAB SUBSTITUTE for a fresh VM, RELEASE_CONTRACT §6).
#   ROLE=center : + Docker Engine (docker.io) + compose v2 (docker-compose-v2), all from the Ubuntu archive
#   ROLE=node   : + nginx (a managed host for install-agent.sh)
# Runs PRIVILEGED (systemd needs cgroups/mounts, dockerd needs iptables/overlay) — lab only, compose profile
# `ubuntu`, never started by scripts/lab/up.sh. See infra/lab/ubuntu/README.md.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

ARG ROLE=node
ENV DEBIAN_FRONTEND=noninteractive container=docker

RUN set -eux; \
    apt-get update; \
    pkgs="systemd systemd-sysv dbus ca-certificates curl openssl iproute2 procps less"; \
    case "$ROLE" in \
      center) pkgs="$pkgs docker.io docker-compose-v2 gzip" ;; \
      node) pkgs="$pkgs nginx" ;; \
      *) echo "unknown ROLE $ROLE"; exit 1 ;; \
    esac; \
    apt-get install -y --no-install-recommends $pkgs; \
    rm -rf /var/lib/apt/lists/*; \
    # units that make no sense in a container (no ttys, no udev, no kernel modules)
    for u in getty.target console-getty.service systemd-udevd.service systemd-udev-trigger.service \
             systemd-modules-load.service sys-kernel-config.mount sys-kernel-debug.mount \
             systemd-remount-fs.service systemd-firstboot.service systemd-resolved.service \
             systemd-networkd-wait-online.service apt-daily.timer apt-daily-upgrade.timer \
             motd-news.timer e2scrub_reap.service; do \
      systemctl mask "$u" || true; \
    done; \
    if [ "$ROLE" = center ]; then systemctl enable docker.service containerd.service; fi; \
    if [ "$ROLE" = node ]; then systemctl enable nginx.service; fi; \
    echo "ppanel-lab-$ROLE" > /etc/ppanel-lab-role

# node: one plain site so the agent's read-only nginx discovery has something to find
COPY node-site.conf /etc/nginx/sites-available/lab-site.conf
RUN if [ "$ROLE" = node ]; then \
      ln -sf /etc/nginx/sites-available/lab-site.conf /etc/nginx/sites-enabled/lab-site.conf; \
      mkdir -p /var/www/lab-site && echo "ppanel lab site" > /var/www/lab-site/index.html; \
    else rm -f /etc/nginx/sites-available/lab-site.conf; fi

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
