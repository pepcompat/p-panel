#!/usr/bin/env bash
# Build pPanel release artifacts locally (docs/RELEASE_CONTRACT.md §3). Same layout as release.yml.
#
#   scripts/release/build.sh [--version V] [--out DIR] [--sign-key FILE] [--platform P]
#                            [--image-prefix P] [--save-images] [--skip-images] [--skip-agent]
#
#   --version V        release version (default: root VERSION)
#   --out DIR          output directory (default dist-release/<version>)
#   --sign-key FILE    ed25519 private key (PEM): writes SHA256SUMS.sig + ppanel-release.pub and embeds the
#                      public key in install-agent.sh. Without it the release is UNSIGNED.
#   --platform P       image platform for the local --load build (default: linux/<host arch>)
#   --image-prefix P   tag prefix for the images (default '' → ppanel-api:<v>, ppanel-web:<v>)
#   --save-images      also `docker save` both images to <out>/images/*.tar (offline installs, lab E2E)
#   --skip-images / --skip-agent   build only part of the release
#
# Output (<out>/):
#   ppanel-agent-linux-amd64, ppanel-agent-linux-arm64, install-agent.sh,
#   ppanel-center-<v>.tar.gz (infra/release + Center backup scripts + VERSION),
#   SHA256SUMS [, SHA256SUMS.sig, ppanel-release.pub] [, images/ppanel-{api,web}-<v>.tar]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION=""
OUT=""
SIGN_KEY=""
PLATFORM=""
PREFIX=""
SAVE=0
IMAGES=1
AGENT=1
OPENSSL="${OPENSSL:-openssl}"

log() { printf '[release] %s\n' "$*" >&2; }
die() {
  printf '[release] ERROR: %s\n' "$*" >&2
  exit 1
}
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    --sign-key) SIGN_KEY="${2:?}"; shift 2 ;;
    --platform) PLATFORM="${2:?}"; shift 2 ;;
    --image-prefix) PREFIX="${2-}"; shift 2 ;;
    --save-images) SAVE=1; shift ;;
    --skip-images) IMAGES=0; shift ;;
    --skip-agent) AGENT=0; shift ;;
    -h | --help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

VERSION="${VERSION:-$(tr -d '[:space:]' <"$ROOT/VERSION")}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "invalid version '$VERSION'"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT="${OUT:-$ROOT/dist-release/$VERSION}"
case "$(uname -m)" in x86_64 | amd64) host_arch=amd64 ;; *) host_arch=arm64 ;; esac
PLATFORM="${PLATFORM:-linux/$host_arch}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

log "pPanel $VERSION (commit $COMMIT, $BUILD_DATE) → $OUT"

# ---------------------------------------------------------------- images
if [ "$IMAGES" -eq 1 ]; then
  for svc in api web; do
    tag="${PREFIX}ppanel-${svc}:${VERSION}"
    log "image $tag ($PLATFORM)"
    docker buildx build --platform "$PLATFORM" --load \
      -f "$ROOT/apps/$svc/Dockerfile" -t "$tag" \
      --build-arg "PPANEL_VERSION=$VERSION" \
      --build-arg "PPANEL_COMMIT=$COMMIT" \
      --build-arg "PPANEL_BUILD_DATE=$BUILD_DATE" \
      "$ROOT" >&2
    if [ "$SAVE" -eq 1 ]; then
      mkdir -p "$OUT/images"
      docker save -o "$OUT/images/ppanel-${svc}-${VERSION}.tar" "$tag"
      log "saved images/ppanel-${svc}-${VERSION}.tar"
    fi
  done
fi

# ---------------------------------------------------------------- agent binaries (apps/agent Makefile)
if [ "$AGENT" -eq 1 ]; then
  log "agent binaries linux/amd64 + linux/arm64"
  make -C "$ROOT/apps/agent" cross VERSION="$VERSION" COMMIT="$COMMIT" BUILDDATE="$BUILD_DATE" \
    TARGETS="linux/amd64 linux/arm64" BIN="$OUT" >&2
fi

# ---------------------------------------------------------------- install-agent.sh (+ embedded public key)
cp "$ROOT/infra/release/install-agent.sh" "$OUT/install-agent.sh"
chmod 0755 "$OUT/install-agent.sh"
# the unit embedded in install-agent.sh must be byte-identical to infra/release/systemd/ppanel-agent.service
diff -q <(bash "$OUT/install-agent.sh" --print-unit) "$ROOT/infra/release/systemd/ppanel-agent.service" >/dev/null ||
  die "install-agent.sh embedded unit differs from infra/release/systemd/ppanel-agent.service"
if [ -n "$SIGN_KEY" ]; then
  [ -f "$SIGN_KEY" ] || die "--sign-key $SIGN_KEY not found"
  "$OPENSSL" pkey -in "$SIGN_KEY" -pubout -out "$OUT/ppanel-release.pub" 2>/dev/null ||
    die "cannot read the signing key (ed25519 PEM expected; OPENSSL=$OPENSSL)"
  PUB="$(cat "$OUT/ppanel-release.pub")" awk '
    /^EMBEDDED_PUBKEY=/ { print "EMBEDDED_PUBKEY='\''" ENVIRON["PUB"] "'\''"; next } { print }' \
    "$ROOT/infra/release/install-agent.sh" >"$OUT/install-agent.sh"
  chmod 0755 "$OUT/install-agent.sh"
fi

# ---------------------------------------------------------------- Center bundle
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
bundle="$stage/ppanel-center-$VERSION"
mkdir -p "$bundle/lib"
(cd "$ROOT/infra/release" && tar -cf - --exclude '.DS_Store' .) | (cd "$bundle" && tar -xf -)
cp "$OUT/install-agent.sh" "$bundle/install-agent.sh"
cp "$ROOT/scripts/backup/center-backup.sh" "$ROOT/scripts/backup/center-restore.sh" \
  "$ROOT/scripts/backup/_center-common.sh" "$bundle/lib/"
printf '%s\n' "$VERSION" >"$bundle/VERSION"
chmod 0755 "$bundle"/*.sh "$bundle"/lib/*.sh
tarball="ppanel-center-$VERSION.tar.gz"
# portable archive: root-owned entries, no macOS xattrs / AppleDouble files
if [[ "$(tar --version 2>/dev/null)" == *bsdtar* ]]; then
  if command -v xattr >/dev/null 2>&1; then xattr -cr "$stage" 2>/dev/null || true; fi
  tar_opts=(--uid 0 --gid 0 --uname root --gname root --no-xattrs --no-acls --no-fflags --no-mac-metadata)
else
  tar_opts=(--owner=0 --group=0 --numeric-owner --no-xattrs --sort=name)
fi
COPYFILE_DISABLE=1 tar "${tar_opts[@]}" -C "$stage" -czf "$OUT/$tarball" "ppanel-center-$VERSION"
log "bundle $tarball"

# ---------------------------------------------------------------- checksums + signature
(
  cd "$OUT"
  files=("$tarball" install-agent.sh)
  for a in ppanel-agent-linux-amd64 ppanel-agent-linux-arm64; do [ -f "$a" ] && files+=("$a"); done
  sha256 "${files[@]}" | sort -k2 >SHA256SUMS
)
rm -f "$OUT/SHA256SUMS.sig"
if [ -n "$SIGN_KEY" ]; then
  "$OPENSSL" pkeyutl -sign -inkey "$SIGN_KEY" -rawin -in "$OUT/SHA256SUMS" -out "$OUT/SHA256SUMS.sig"
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$OUT/ppanel-release.pub" -rawin \
    -in "$OUT/SHA256SUMS" -sigfile "$OUT/SHA256SUMS.sig" >/dev/null || die "signature self-check failed"
  log "signed SHA256SUMS (ed25519)"
else
  rm -f "$OUT/ppanel-release.pub"
  log "UNSIGNED release (no --sign-key)"
fi
cat "$OUT/SHA256SUMS" >&2
log "done: $OUT"
