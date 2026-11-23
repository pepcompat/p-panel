# pPanel built-in Dockerfile template: Next.js (standalone output) — written into the build context
# as Dockerfile.ppanel by the agent. Classic-builder compatible (no BuildKit-only syntax).
# Requirements: package.json with a "build" script and `output: "standalone"` in next.config.*.
# Runtime: non-root (uid 1001), `node server.js` on 0.0.0.0:3000.
# Base pinned by tag + multi-arch index digest (resolved 2026-11-23).
ARG NODE_IMAGE=node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat
COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./
RUN set -eu; \
    if [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then corepack enable yarn && yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN set -eu; \
    if [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm run build; \
    elif [ -f yarn.lock ]; then corepack enable yarn && yarn run build; \
    else npm run build; fi; \
    if [ ! -f .next/standalone/server.js ]; then \
      echo "pPanel nextjs template: .next/standalone/server.js missing — set output: 'standalone' in next.config" >&2; exit 1; \
    fi; \
    mkdir -p public

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN addgroup -S -g 1001 nextjs && adduser -S -D -H -u 1001 -G nextjs nextjs
COPY --from=build --chown=1001:1001 /app/public ./public
COPY --from=build --chown=1001:1001 /app/.next/standalone ./
COPY --from=build --chown=1001:1001 /app/.next/static ./.next/static
USER 1001:1001
EXPOSE 3000
CMD ["node", "server.js"]
