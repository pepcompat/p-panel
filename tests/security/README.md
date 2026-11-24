# Security tests

Home for automated security test suites (`pnpm test:security`, brief §17). Each test references a
threat in `docs/SECURITY_THREAT_MODEL.md` §3 and a test ID in `docs/TEST_REPORT.md`.

| Area                                                | Test IDs               | Location                                                             | Status                       |
| --------------------------------------------------- | ---------------------- | -------------------------------------------------------------------- | ---------------------------- |
| Secret scan (gitleaks, pinned)                      | P0-T02                 | CI job `secrets` / local `docker run zricethezav/gitleaks:v8.21.2 …` | executed locally 2026-11-17  |
| Route inventory, AuthN/Z matrix, IDOR, RBAC scope   | P1-T03, P5-T02, E2E-16 | `tests/security/authz/`                                              | automated (P7.01) 2026-11-23 |
| CSRF, GET side-effect audit                         | P7.01                  | `tests/security/csrf/`                                               | automated (P7.01)            |
| JWT / session / MFA / step-up / self-approval       | P1-T03, P7.01          | `tests/security/auth/`                                               | automated (P7.01)            |
| Enrollment / mTLS spoof, revoked cert, gateway IDOR | P1-T01, P1-T02         | `apps/api` integration + `tests/security/gateway/`                   | automated                    |
| Job replay / expiry                                 | P2-T01, P2-T02, P7-T02 | `apps/api/test/integration/jobs.spec.ts`                             | automated (P2)               |
| Injection, path traversal, header injection         | P3-T04, P4-T05, P7.01  | `tests/security/injection/`                                          | automated (P7.01)            |
| Malicious Compose policy / fuzz                     | P4-T05, P7.02          | `tests/security/injection/` + shared-contracts `*.fuzz.test.ts`      | automated                    |
| Webhook spoof/replay                                | P4-T06                 | `tests/security/webhooks/`                                           | automated (P7.01)            |
| Secret leakage canary scan (DB, logs, responses)    | P4-T02, P5-T03, P7-T03 | `tests/security/leakage/`                                            | automated (P7-T03)           |
| SSRF (webhooks, registry, git, Telegram, health)    | P7.01                  | `tests/security/ssrf/`                                               | automated (P7.01)            |
| XSS rendering + CSP                                 | P7.01                  | `apps/web/tests/unit/security-xss.test.tsx`                          | automated (P7.01)            |
| SSH gateway (XSS/WS hijack, host key)               | P10-T2, P10-T3         | `tests/security/ssh/`                                                | TODO (P10)                   |
| MCP auth / scope / self-approval / prompt injection | P13-T1…T5              | `tests/security/mcp/`                                                | TODO (P13)                   |

Run: `pnpm test:security` (typechecks `tests/security/tsconfig.json`, then runs
`apps/api/vitest.security.config.ts` against the isolated database `ppanel_security`, created and migrated
automatically). Results and findings: `docs/SECURITY_TEST_REPORT.md`.

Rules: tests run only against localhost or `ppanel-lab`; never against production hosts; use fake
secrets that are obviously test values (e.g. `TEST_FAKE_KEY_…`) and allowlist them in gitleaks config if needed.
