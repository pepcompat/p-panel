# syntax=docker/dockerfile:1.7
# pPanel web UI — production image (P8.01, docs/RELEASE_CONTRACT.md §3).
# Build context = repo root:  docker build -f apps/web/Dockerfile -t ppanel-web:$(cat VERSION) .
#
# API base: the bundle talks to the SAME ORIGIN `/api/v1` (NEXT_PUBLIC_API_BASE is baked as a relative
# path). The Center proxy (infra/release/Caddyfile) routes /api/* to the API and everything else here,
# so one image works for any domain without a rebuild. CSP connect-src is then just 'self'.
# Runtime: Next.js standalone server, non-root (uid 1001), app files root-owned / read-only.

ARG NODE_IMAGE=node:22.23.5-alpine3.24@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

FROM ${NODE_IMAGE} AS build
ENV PNPM_HOME=/pnpm \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    NEXT_TELEMETRY_DISABLED=1
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
WORKDIR /repo
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY apps/web/package.json apps/web/
COPY packages/shared-contracts/package.json packages/shared-contracts/
RUN --mount=type=cache,id=ppanel-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter @ppanel/web...
COPY packages/shared-contracts packages/shared-contracts
COPY apps/web apps/web
ENV NODE_ENV=production \
    NEXT_OUTPUT_STANDALONE=1 \
    NEXT_PUBLIC_API_BASE=/api/v1 \
    NEXT_PUBLIC_API_MOCK=0
# build cache is dropped in this stage so it never reaches a runtime layer. apps/web/public is optional:
# git does not track empty directories, so a clean checkout (release.yml) may not have it.
RUN pnpm --filter @ppanel/web build \
 && rm -rf apps/web/.next/cache \
 && mkdir -p /out \
 && cp -a apps/web/.next/standalone/. /out/ \
 && mkdir -p /out/apps/web/.next /out/apps/web/public \
 && cp -a apps/web/.next/static /out/apps/web/.next/static \
 && if [ -d apps/web/public ]; then cp -a apps/web/public/. /out/apps/web/public/; fi

FROM ${NODE_IMAGE} AS runtime
RUN apk add --no-cache tini \
 && addgroup -S -g 1001 ppanel \
 && adduser -S -D -H -u 1001 -G ppanel -h /nonexistent ppanel
WORKDIR /app
COPY --from=build /out ./
ARG PPANEL_VERSION=0.0.0-dev
ARG PPANEL_COMMIT=unknown
ARG PPANEL_BUILD_DATE=
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3100 \
    PPANEL_VERSION=${PPANEL_VERSION}
LABEL org.opencontainers.image.title="ppanel-web" \
      org.opencontainers.image.description="pPanel web UI" \
      org.opencontainers.image.source="https://github.com/pepcompat/ppanel" \
      org.opencontainers.image.version="${PPANEL_VERSION}" \
      org.opencontainers.image.revision="${PPANEL_COMMIT}" \
      org.opencontainers.image.created="${PPANEL_BUILD_DATE}"
USER 1001:1001
EXPOSE 3100
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3100)+'/login').then(r=>process.exit(r.status<500?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/web/server.js"]
