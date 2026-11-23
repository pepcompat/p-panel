# @ppanel/api — pinned dependencies

All versions are pinned exactly in `package.json` (validated 2026-11-17, Node 24.11 / pnpm 10.33, PostgreSQL 16.6).

| Package                                                    | Version                    | Why                                                                                                                 |
| ---------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| @nestjs/common, @nestjs/core, @nestjs/platform-express     | 11.2.10                    | HTTP framework (Express 5 adapter)                                                                                  |
| express                                                    | 5.2.1                      | body parser + separate mTLS gateway app (same version Nest 11.2 uses)                                               |
| @nestjs/jwt                                                | 11.0.2                     | HS256 access / MFA / step-up tokens (distinct audiences)                                                            |
| @prisma/client, prisma                                     | 6.19.3                     | ORM + migrations (`prisma.config.ts`)                                                                               |
| argon2                                                     | 0.45.2                     | argon2id password hashing (m=19456, t=2, p=1)                                                                       |
| otplib                                                     | 12.0.1                     | TOTP (RFC 6238)                                                                                                     |
| @peculiar/x509                                             | 1.14.3                     | internal ECDSA P-256 CA, CSR parsing/verification, cert issuance (Node WebCrypto)                                   |
| zod                                                        | 3.25.76                    | DTO validation via shared-contracts schemas (same major as `@ppanel/shared-contracts`)                              |
| diff                                                       | 8.0.4                      | unified diffs for Nginx revision drafts (P3.05; ships own types)                                                    |
| cookie-parser                                              | 1.4.7                      | refresh-token cookie                                                                                                |
| reflect-metadata                                           | 0.2.2 / rxjs 7.8.2         | Nest runtime peers                                                                                                  |
| typescript                                                 | 5.9.3                      | typecheck only                                                                                                      |
| tsup                                                       | 8.5.1 + @swc/core 1.16.22  | bundles `src/main.ts` → `dist/main.js` (SWC keeps `emitDecoratorMetadata`; inlines the TS-source workspace package) |
| vitest                                                     | 3.2.7 + unplugin-swc 1.6.0 | unit + integration tests                                                                                            |
| supertest                                                  | 7.3.2                      | HTTP integration tests                                                                                              |
| eslint 9.39.5, @eslint/js 9.39.5, typescript-eslint 8.73.0 |                            | lint (bans `child_process` and `docker.sock` in src)                                                                |
| tsx                                                        | 4.23.15                    | runs the dev seeder                                                                                                 |
| nodemailer (+ @types/nodemailer 8.0.2)                     | 10.3.1                     | P5 email notification channel (SMTP from `PPANEL_SMTP_URL`; lab: Mailpit)                                           |

Not used yet: Redis/BullMQ (jobs are Postgres-backed with row locks + durable leases; rate limiter is in-memory — move to Redis for multi-instance).

pnpm note: `pnpm` reports "Ignored build scripts" for argon2/@prisma/*/esbuild/@swc/core. Nothing breaks: argon2 and SWC ship prebuilt
binaries, and `pnpm build`/`typecheck` run `prisma generate` explicitly. A fresh checkout must run `pnpm --filter @ppanel/api prisma:generate` (or `build`) once.
