# syntax=docker/dockerfile:1.7
# pPanel Center API — production image (P8.01, docs/RELEASE_CONTRACT.md §3).
# Build context = repo root:
#   docker build -f apps/api/Dockerfile -t ppanel-api:$(cat VERSION) \
#     --build-arg PPANEL_VERSION=$(cat VERSION) --build-arg PPANEL_COMMIT=$(git rev-parse --short HEAD) \
#     --build-arg PPANEL_BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) .
# Runtime: non-root (uid 1001), read-only app files, `prisma migrate deploy` then `node dist/main.js`.
# Entrypoint sub-commands (used by infra/release/*.sh): `migrate` (deploy migrations, exit),
# `migrate-status`, `serve` (default; set PPANEL_SKIP_MIGRATE=1 to skip the boot migration).

ARG NODE_IMAGE=node:22.23.5-alpine3.24@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

FROM ${NODE_IMAGE} AS base
ENV PNPM_HOME=/pnpm \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CHECKPOINT_DISABLE=1 \
    PRISMA_HIDE_UPDATE_MESSAGE=1
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo

# ---------------------------------------------------------------- build
FROM base AS build
# Prisma engines detect libssl at generate time (linux-musl-<arch>-openssl-3.0.x)
RUN apk add --no-cache openssl
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY packages/shared-contracts/package.json packages/shared-contracts/
RUN --mount=type=cache,id=ppanel-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter @ppanel/api...
COPY packages/shared-contracts packages/shared-contracts
COPY apps/api apps/api
# prisma.config.ts + prisma/ are in apps/api → `prisma generate` sees the real schema (not an empty client)
RUN pnpm --filter @ppanel/api build
# production dependency closure only (prisma CLI is a runtime dependency for `migrate deploy`)
RUN --mount=type=cache,id=ppanel-pnpm-store,target=/pnpm/store \
    pnpm --filter @ppanel/api deploy --prod --legacy /out \
 && cd /out \
 && node_modules/.bin/prisma generate \
 && node_modules/.bin/prisma version >/dev/null \
 && rm -rf src test scripts tsconfig.json tsup.config.ts vitest*.ts eslint.config.mjs DEPENDENCIES.md prisma/seed.ts \
 && rm -rf /out/dist && cp -r /repo/apps/api/dist /out/dist \
 # prune what a PostgreSQL-only, library-engine runtime never loads (other DB providers' wasm,
 # source maps, typings, the optional typescript peer) — ~200 MB
 && cd /out/node_modules/.pnpm \
 && find . -type f \( -name '*.map' -o -name '*.d.ts' -o -name '*.d.mts' -o -name '*.d.cts' \
      -o -name '*.md' -o -name '*cockroachdb*' -o -name '*mysql*' -o -name '*sqlserver*' -o -name '*sqlite*' \) \
      -not -path '*/.prisma/client/*' -delete \
 && rm -rf typescript@* @types+*

# ---------------------------------------------------------------- runtime
FROM ${NODE_IMAGE} AS runtime
RUN apk add --no-cache openssl tini \
 && addgroup -S -g 1001 ppanel \
 && adduser -S -D -H -u 1001 -G ppanel -h /nonexistent ppanel
WORKDIR /app
# app files stay root-owned and read-only for the service user (no chown -R layer)
COPY --from=build /out/node_modules ./node_modules
COPY --from=build /out/package.json /out/prisma.config.ts ./
COPY --from=build /out/prisma ./prisma
COPY --from=build /out/dist ./dist
COPY --chmod=0755 apps/api/docker-entrypoint.sh /usr/local/bin/ppanel-api

ARG PPANEL_VERSION=0.0.0-dev
ARG PPANEL_COMMIT=unknown
ARG PPANEL_BUILD_DATE=
ENV NODE_ENV=production \
    API_HOST=0.0.0.0 \
    API_PORT=4000 \
    AGENT_GATEWAY_PORT=4443 \
    CHECKPOINT_DISABLE=1 \
    PRISMA_HIDE_UPDATE_MESSAGE=1 \
    PPANEL_VERSION=${PPANEL_VERSION} \
    PPANEL_COMMIT=${PPANEL_COMMIT} \
    PPANEL_BUILD_DATE=${PPANEL_BUILD_DATE}
LABEL org.opencontainers.image.title="ppanel-api" \
      org.opencontainers.image.description="pPanel Center API + mTLS agent gateway" \
      org.opencontainers.image.source="https://github.com/pepcompat/ppanel" \
      org.opencontainers.image.version="${PPANEL_VERSION}" \
      org.opencontainers.image.revision="${PPANEL_COMMIT}" \
      org.opencontainers.image.created="${PPANEL_BUILD_DATE}"

USER 1001:1001
EXPOSE 4000 4443
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=6 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.API_PORT||4000)+'/api/v1/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ppanel-api"]
CMD ["serve"]
