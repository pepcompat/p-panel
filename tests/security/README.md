# Security tests

Home for automated security test suites (`pnpm test:security`, brief §17). Each test references a
threat in `docs/SECURITY_THREAT_MODEL.md` §3 and a test ID in `docs/TEST_REPORT.md`.

| Area                                                | Test IDs                       | Location (planned)                                                   | Status                      |
| --------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------- | --------------------------- |
| Secret scan (gitleaks, pinned)                      | P0-T02                         | CI job `secrets` / local `docker run zricethezav/gitleaks:v8.21.2 …` | executed locally 2026-11-17 |
| AuthN/Z: IDOR, RBAC scope, CSRF, step-up            | P1-T03, P5-T02, P7-T03, E2E-16 | `tests/security/authz/`                                              | TODO                        |
| Enrollment / mTLS spoof, revoked cert               | P1-T01, P1-T02                 | `apps/api` integration + here                                        | TODO                        |
| Job replay / expiry                                 | P2-T01, P2-T02, P7-T02         | `tests/security/jobs/`                                               | TODO                        |
| Nginx path traversal / symlink / ownership upgrade  | P3-T04                         | `tests/security/nginx/`                                              | TODO                        |
| Malicious Compose policy                            | P4-T05, P7.02 fuzz             | `tests/security/compose/`                                            | TODO                        |
| Webhook spoof/replay                                | P4-T06                         | `tests/security/webhooks/`                                           | TODO                        |
| Log redaction / secret leakage                      | P4-T02, P5-T03, P14-T3         | `tests/security/redaction/`                                          | TODO                        |
| SSRF on healthcheck/targets                         | P7.01                          | `tests/security/ssrf/`                                               | TODO                        |
| SSH gateway (XSS/WS hijack, host key)               | P10-T2, P10-T3                 | `tests/security/ssh/`                                                | TODO                        |
| MCP auth / scope / self-approval / prompt injection | P13-T1…T5                      | `tests/security/mcp/`                                                | TODO                        |

Rules: tests run only against localhost or `ppanel-lab`; never against production hosts; use fake
secrets that are obviously test values (e.g. `TEST_FAKE_KEY_…`) and allowlist them in gitleaks config if needed.
