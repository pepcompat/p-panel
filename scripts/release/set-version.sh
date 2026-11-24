#!/usr/bin/env bash
# Set the single product version (docs/RELEASE_CONTRACT.md §1).
#   scripts/release/set-version.sh 0.8.0-rc.1
# Updates: root VERSION (source of truth), every workspace package.json "version", apps/agent/VERSION.
# Image tags and the agent -ldflags read VERSION at build time (scripts/release/build.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ver="${1:-}"
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if [[ ! "$ver" =~ $semver ]]; then
  echo "usage: $0 <MAJOR.MINOR.PATCH[-pre]>   (no leading v)" >&2
  exit 2
fi

printf '%s\n' "$ver" >"$ROOT/VERSION"
printf '%s\n' "$ver" >"$ROOT/apps/agent/VERSION"

for f in "$ROOT/package.json" "$ROOT"/apps/*/package.json "$ROOT"/packages/*/package.json; do
  [ -f "$f" ] || continue
  # only the top-level "version" key (2-space indent), keeps formatting byte-identical otherwise
  tmp="$(mktemp "${f}.XXXXXX")"
  awk -v v="$ver" '
    !done && /^  "version": "[^"]*",?$/ { sub(/"version": "[^"]*"/, "\"version\": \"" v "\""); done = 1 }
    { print }
  ' "$f" >"$tmp"
  cat "$tmp" >"$f"
  rm -f "$tmp"
  echo "  ${f#"$ROOT"/} -> $ver"
done
# web client version sent as X-Client-Version
cfg="$ROOT/apps/web/src/lib/config.ts"
if [ -f "$cfg" ]; then
  tmp="$(mktemp "${cfg}.XXXXXX")"
  sed -E "s/^export const CLIENT_VERSION = '[^']*';/export const CLIENT_VERSION = '${ver}';/" "$cfg" >"$tmp"
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
  echo "  apps/web/src/lib/config.ts -> $ver"
fi
echo "VERSION=$ver (VERSION, apps/agent/VERSION, web CLIENT_VERSION)"
