# pPanel built-in Dockerfile template: NestJS — written into the build context as Dockerfile.ppanel
# by the agent. Classic-builder compatible (no BuildKit-only syntax).
# Requirements: package.json with a "build" script producing dist/main.js (nest build).
# Runtime: non-root user `node` (uid 1000), production dependencies only, `node dist/main` on :3000.
# Base pinned by tag + multi-arch index digest (resolved 2026-11-23).
ARG NODE_IMAGE=node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./
RUN set -eu; \
    if [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then corepack enable yarn && yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi
COPY . .
RUN set -eu; \
    if [ -f pnpm-lock.yaml ]; then pnpm run build; \
    elif [ -f yarn.lock ]; then yarn run build; \
    else npm run build; fi; \
    test -f dist/main.js || { echo "pPanel nestjs template: dist/main.js missing after build" >&2; exit 1; }

FROM ${NODE_IMAGE} AS prod-deps
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./
RUN set -eu; \
    if [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm install --frozen-lockfile --prod; \
    elif [ -f yarn.lock ]; then corepack enable yarn && yarn install --frozen-lockfile --production; \
    elif [ -f package-lock.json ]; then npm ci --omit=dev --no-audit --no-fund; \
    else npm install --omit=dev --no-audit --no-fund; fi; \
    mkdir -p node_modules

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000
COPY --from=prod-deps --chown=1000:1000 /app/node_modules ./node_modules
COPY --from=build --chown=1000:1000 /app/dist ./dist
COPY --from=build --chown=1000:1000 /app/package.json ./package.json
USER node
EXPOSE 3000
CMD ["node", "dist/main"]
