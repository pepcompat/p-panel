# pPanel — Dependencies (pinned & validated)

Brief §0.7: prefer stable releases; pin images by version **and** digest where practical. Update this
file whenever a version changes, with the date and the command used to verify.

## 1. Toolchain

| Tool                           | Dev host (2026-11-17)                | CI                        | Pin mechanism                                                         |
| ------------------------------ | ------------------------------------ | ------------------------- | --------------------------------------------------------------------- |
| Node.js                        | v24.11.0                             | 22 (`actions/setup-node`) | `engines.node >=22` in root `package.json`                            |
| pnpm                           | 10.33.0                              | 10.33.0                   | `packageManager: pnpm@10.33.0`, `pnpm-lock.yaml`, `--frozen-lockfile` |
| Go                             | 1.25.6 darwin/arm64                  | 1.25.x                    | `apps/agent/go.mod` (`go 1.25`), `go.sum`                             |
| Docker Engine                  | 29.7.2 (Docker Desktop, linux/arm64) | runner default            | —                                                                     |
| Docker Compose                 | v5.5.1                               | runner default            | compose spec, `name:` set per file                                    |
| Prettier / husky / lint-staged | ^3.3.3 / ^9.1.7 / ^15.2.10           | same (lockfile)           | root `package.json`                                                   |

## 2. Container images

Digests resolved 2026-11-17 with `docker buildx imagetools inspect <image>` (multi-arch index digest).

| Image                | Tag          | Index digest                                                              | Used by                                                           |
| -------------------- | ------------ | ------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| ubuntu               | 24.04        | `sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8` | `infra/lab/node/Dockerfile` (pinned by digest)                    |
| busybox              | 1.37.0       | `sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` | `infra/compose/lab.yml` upstreams (pinned by digest)              |
| postgres             | 16.6-alpine  | `sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef` | `infra/compose/dev.yml`, CI service (tag-pinned; digest recorded) |
| redis                | 7.4.1-alpine | `sha256:c1e88455c85225310bbea54816e9c3f4b5295815e6dbf80c34d40afc6df28275` | `infra/compose/dev.yml`, CI service (tag-pinned; digest recorded) |
| zricethezav/gitleaks | v8.21.2      | `sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | secret scan (local + CI, pinned by digest)                        |
| koalaman/shellcheck  | v0.10.0      | `sha256:2097951f02e735b613f4a34de20c40f937a6c8f18ecb170612c88c34517221fb` | CI lint of `scripts/lab/*.sh`                                     |
| rhysd/actionlint     | 1.7.7        | (not pinned; local check only)                                            | workflow lint, run manually                                       |

## 3. Lab node packages (Ubuntu 24.04 archive at build time — not pinned per package)

Recorded from `docker run --rm --entrypoint dpkg-query ppanel-lab-node-a:dev -W …` on 2026-11-17:

| Package              | Version                               |
| -------------------- | ------------------------------------- |
| nginx / nginx-common | 1.24.0-2ubuntu7.19                    |
| php8.3-fpm           | 8.3.6-0ubuntu0.24.04.13 (node-a only) |
| openssl              | 3.0.13-0ubuntu3.16                    |
| curl                 | 8.5.0-2ubuntu10.16                    |
| tini                 | 0.19.0-1                              |

## 4. GitHub Actions

`actions/checkout@v4`, `pnpm/action-setup@v4`, `actions/setup-node@v4`, `actions/setup-go@v5`
(major-tag pinned; pin to commit SHA before P8 release hardening).

## 5. Application-level dependencies

Each app owns its own list — see:

- `apps/api/DEPENDENCIES.md` (NestJS, Prisma, argon2, Zod, …)
- `apps/web/DEPENDENCIES.md` (Next.js, React, Tailwind, shadcn/ui, Playwright, Vitest, …)
- `apps/agent/DEPENDENCIES.md` (Go modules)
- `packages/shared-contracts` (TypeScript, Zod)

_Owners: fill these files when the app's dependencies are validated (brief §0.7)._
