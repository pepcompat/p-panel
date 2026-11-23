# pPanel LAB ONLY — read-only `git daemon` (git:// protocol) serving the fixture repos created by
# scripts/lab/git-fixtures.sh (.lab/git/*.git, mounted read-only at /srv/git).
# git:// is unauthenticated and unencrypted: acceptable ONLY on the isolated lab network, and only
# because lab-node-b's agent config names `lab-git` in build.gitHostsAllowlist. Production = https.
# Base pinned by tag + multi-arch index digest (resolved 2026-11-23).
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN apk add --no-cache git-daemon && mkdir -p /srv/git
# Repos on the bind mount are owned by the host user; the daemon runs as nobody (65534).
ENV GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=*
USER 65534:65534
EXPOSE 9418
ENTRYPOINT ["git", "daemon", "--export-all", "--base-path=/srv/git", "--reuseaddr", "--informative-errors", "--verbose", "--listen=0.0.0.0", "--port=9418", "/srv/git"]
