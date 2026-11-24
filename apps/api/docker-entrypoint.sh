#!/bin/sh
# pPanel API container entrypoint (apps/api/Dockerfile). Never calls a package manager at runtime.
#   serve           prisma migrate deploy (unless PPANEL_SKIP_MIGRATE=1), then the API (default)
#   migrate         prisma migrate deploy, then exit (upgrade.sh)
#   migrate-status  prisma migrate status, then exit
set -eu
cd /app
prisma=node_modules/.bin/prisma

case "${1:-serve}" in
  serve)
    if [ "${PPANEL_SKIP_MIGRATE:-0}" != "1" ]; then
      echo "[ppanel-api] prisma migrate deploy" >&2
      "$prisma" migrate deploy
    fi
    exec node --enable-source-maps dist/main.js
    ;;
  migrate) exec "$prisma" migrate deploy ;;
  migrate-status) exec "$prisma" migrate status ;;
  *) exec "$@" ;;
esac
