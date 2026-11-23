# pPanel backup HELPER image (P6, docs/AGENT_PROTOCOL.md "Backups and restores (P6)").
#
# The agent runs this image as a hardened, short-lived container (no published ports, CapDrop ALL,
# no-new-privileges, memory/pids limits, labels ppanel.managed/ppanel.app/ppanel.backup) with a FIXED
# argv as the container command — there is no shell entrypoint and the agent never uses `docker exec`.
#   - default ENTRYPOINT is restic (volume backups, `--stdin-from-command -- pg_dump|mysqldump`, dump/restore);
#   - the agent overrides the entrypoint only with psql / pg_isready / mysql (row counts, readiness, dump load).
# Runs as the non-root user 10001 by default; the agent switches to uid 0 ONLY for volume backups
# (CapAdd DAC_READ_SEARCH: read every file) and volume restores (CHOWN/FOWNER/DAC_OVERRIDE).
#
# Contents: restic (official release binary, sha256-pinned), postgresql-client 16, mariadb-client.
# Build + push to the lab registry with scripts/lab/backup-images.sh (writes the digest to .lab/backup.env).
# Base pinned by tag AND multi-arch index digest (same as infra/lab/node/Dockerfile).

FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8 AS restic
ARG TARGETARCH
# restic 0.19.1 (2026-07-05) — SHA256SUMS from https://github.com/restic/restic/releases/download/v0.19.1/SHA256SUMS
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
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates postgresql-client-16 mariadb-client; \
    rm -rf /var/lib/apt/lists/*; \
    for b in psql pg_dump pg_isready mysql mysqldump; do command -v "$b"; done; \
    groupadd -g 10001 ppanel; \
    useradd -u 10001 -g 10001 -d /tmp -s /usr/sbin/nologin -M ppanel; \
    mkdir -p /work; chown 10001:10001 /work; chmod 0700 /work
COPY --from=restic /usr/local/bin/restic /usr/local/bin/restic
LABEL org.opencontainers.image.title="ppanel-backup-helper" \
      org.opencontainers.image.description="restic + postgresql-client-16 + mariadb-client for pPanel P6 helper containers"
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/restic"]
CMD ["version"]
