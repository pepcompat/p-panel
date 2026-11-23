# pPanel lab node — a DISPOSABLE container approximation of an Ubuntu 24.04 VM.
# Not a VM: shared kernel, no real systemd, no real Docker engine. See infra/lab/README.md.
#
# Build context: infra/   (compose sets context: ..)
# Base pinned by tag AND multi-arch index digest (resolved 2026-11-17 via `docker buildx imagetools inspect ubuntu:24.04`).

# P6: host restic for the agent's `paths` backups (backup.resticPath default /usr/local/bin/restic).
# Official release binary, verified against the release SHA256SUMS (Ubuntu 24.04 ships restic 0.16.4 < 0.17).
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8 AS restic
ARG TARGETARCH
ARG RESTIC_VERSION=0.19.1
ARG RESTIC_SHA256_arm64=a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465
ARG RESTIC_SHA256_amd64=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl bzip2; \
    arch="${TARGETARCH:-arm64}"; \
    case "$arch" in arm64) sum="$RESTIC_SHA256_arm64";; amd64) sum="$RESTIC_SHA256_amd64";; *) echo "unsupported arch $arch"; exit 1;; esac; \
    curl -fsSL -o /tmp/restic.bz2 "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_${arch}.bz2"; \
    echo "${sum}  /tmp/restic.bz2" | sha256sum -c -; \
    bunzip2 /tmp/restic.bz2; \
    install -m 0755 /tmp/restic /usr/local/bin/restic; \
    /usr/local/bin/restic version

FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

ARG NODE_ROLE=a
ARG WITH_PHP=1
# P4b: the build node (node-b) needs the git binary for image.build / source.inspect source fetches.
ARG WITH_GIT=0
ENV DEBIAN_FRONTEND=noninteractive \
    PPANEL_LAB_NODE_ROLE=${NODE_ROLE}

# nginx + (optional) php-fpm + tools a real host typically has; versions come from the
# Ubuntu 24.04 archive at build time and are printed by scripts/lab/status.sh.
RUN set -eux; \
    apt-get update; \
    pkgs="nginx curl ca-certificates openssl procps iproute2 tini"; \
    if [ "$WITH_PHP" = "1" ]; then pkgs="$pkgs php8.3-fpm"; fi; \
    if [ "$WITH_GIT" = "1" ]; then pkgs="$pkgs git"; fi; \
    apt-get install -y --no-install-recommends $pkgs; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default; \
    mkdir -p /opt/ppanel-agent /var/lib/ppanel-agent /etc/ssl/ppanel-lab; \
    chmod 0700 /var/lib/ppanel-agent

# Legacy nginx fixtures for this node (copied, not bind-mounted, so the lab node owns its
# config like a real host and every `down/up` cycle starts from the same pristine state).
COPY nginx/fixtures/node-${NODE_ROLE}/ /etc/nginx/
COPY lab/node/www/ /var/www/
COPY lab/node/apps/node-${NODE_ROLE}/ /opt/apps/

# sites-enabled: symlink every sites-available file except *.disabled.conf (realistic Debian layout).
RUN set -eux; \
    mkdir -p /etc/nginx/sites-enabled; \
    for f in /etc/nginx/sites-available/*.conf; do \
      case "$f" in *.disabled.conf) continue;; esac; \
      ln -s "$f" "/etc/nginx/sites-enabled/$(basename "$f")"; \
    done; \
    # Self-signed TLS cert for the TLS fixture. Generated at build time, never committed
    # (repo .gitignore excludes *.pem/*.key). Lab-only, CN=secure.example.lab.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
      -subj "/CN=secure.example.lab" \
      -addext "subjectAltName=DNS:secure.example.lab,DNS:*.secure.example.lab" \
      -keyout /etc/ssl/ppanel-lab/secure.example.lab.key \
      -out /etc/ssl/ppanel-lab/secure.example.lab.crt; \
    chmod 0600 /etc/ssl/ppanel-lab/secure.example.lab.key
# NOTE: `nginx -t` is NOT run at build time: upstream hostnames (lab-upstream-*) only
# resolve on the compose network. The entrypoint runs `nginx -t` before starting.

COPY --from=restic /usr/local/bin/restic /usr/local/bin/restic

COPY lab/node/entrypoint.sh /usr/local/bin/ppanel-lab-entrypoint
RUN chmod 0755 /usr/local/bin/ppanel-lab-entrypoint

EXPOSE 80 443
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ppanel-lab-entrypoint"]
