# pPanel acceptance: user journeys J01–J12 (P8.03 / P8-T03)

The brief names journeys J01–J12 for P8-T03 without defining them. This file defines them from the
acceptance matrix (brief §8, E2E-01..18) and the features built in P1–P7, says which test executes each
one, and links the evidence. Status is what was **executed**, never what is expected.

Status values: **PASS** (executed, all checks green) · **PASS (lab substitute)** (executed against the
container lab, not real VMs) · **PARTIAL** (part of the journey executed) · **NOT RUN** / **BLOCKED**
(reason given).

## How journeys are executed

| Kind                      | What it drives                                                                                                                                                                | Runner                                                                                                                                       | Evidence                                                                                                                                                                                                          |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Playwright UI journey** | the production web build (`next start`, :3100) in Chromium against the real Center API (`node dist/main.js`, :4000) and a fresh DB `ppanel_journeys` — never the mock adapter | `scripts/lab/journeys.sh [--lab] [--evidence <dir>]` → `apps/web/playwright.journeys.config.ts` → `apps/web/tests/e2e/journeys/*.journey.ts` | `docs/evidence/2026-11-24/p8-t03-journeys.json`, screenshots `docs/evidence/2026-11-24/p8-journeys/*.png`; traces + videos kept for failures under `.lab/journeys/test-results/` (CI: `journeys-traces` artifact) |
| **Lab API E2E**           | the real Center API + real Go agents in the container lab (nginx nodes, dind, registry, lab-git, rest-server, MinIO, Prometheus/Loki/Mailpit)                                 | `python3 -I scripts/lab/e2e_p3.py … e2e_p6.py --out <json>`                                                                                  | `docs/evidence/2026-11-24/p{3,4,4b,5,6}-lab-e2e.json` (2026-11-24 re-runs)                                                                                                                                        |
| **P7 lab scenarios**      | outage / no-replay / failsafe scenarios                                                                                                                                       | see `docs/RESILIENCE_REPORT.md`                                                                                                              | `docs/evidence/2026-11-24/p7-*.json`                                                                                                                                                                              |
| **Integration**           | API + real Postgres (+ real gateway) in vitest                                                                                                                                | `pnpm test:integration` (CI `node` job)                                                                                                      | spec files named below                                                                                                                                                                                            |

`journeys.sh` recreates `ppanel_journeys`, runs `prisma migrate deploy` (no seeder, so J01 sees a real
first boot), builds and starts API + web with per-run secrets from `openssl rand` (never printed), runs
the Playwright projects in order **first-boot (J01) → seed (dev seeder: superadmin/admin/dev/user1,
password `password`) → journeys (J02, J05, J11)**, writes the report, and kills every process it started
(ports 4000/4443/3100 free afterwards). Without `--lab` (CI) the gateway is disabled and the lab-agent
journeys (J02, J05) are skipped and reported as NOT RUN. With `--lab` it resets pPanel artefacts on
`ppanel-lab-node-b` (same reset as `e2e_p4.py`), re-enrolls that node's agent into the journeys Center,
and stops that agent at teardown.

CI (`.github/workflows/ci.yml` job `journeys`) runs J01 + J11 on every push/PR against a service
Postgres, uploads the JSON/HTML report + screenshots always and traces/videos/server logs on failure.

## Journeys

### J01 — First boot + 2FA

- **Matrix:** E2E-01. **Executes:** Playwright `j01-first-boot.journey.ts` (UI; also in CI).
- **Steps:** empty Center → `/login` shows "Create the first administrator" → a wrong setup token is
  refused (still not bootstrapped) → correct token creates the platform owner → a second bootstrap is
  refused → owner signs in → `/setup/2fa` → QR generated, TOTP computed from the secret in the
  `totp/setup` response (what an authenticator app reads from the QR) → confirm → 10 recovery codes shown
  once → acknowledge → sign out → password alone yields only an MFA challenge (no token, checked on the
  API too) → TOTP → app → audit log shows `setup.bootstrap`.
- **Expected:** secure admin setup; no session without the second factor.
- **Status:** see the results table.

### J02 — Enroll servers and see them online

- **Matrix:** E2E-02. **Executes:** Playwright `j02-enroll-server.journey.ts` (UI, `--lab`); lab API
  E2Es enroll node-a + node-b on every run (`e2e_p3.py`…`e2e_p6.py`); P7 fleet setup
  (`docs/evidence/2026-11-24/p7-setup-fleet.json`).
- **Steps:** superadmin → Servers → Enroll server → name + **Production** → one-time token (install
  command masked in the screenshot) → real Go agent on `ppanel-lab-node-b` enrolls with it → card shows
  **Online** → agent killed and restarted → heartbeat resumes, still online → server detail.
- **Expected:** nodes visible, reconnect works.
- **Gap:** the brief asks for 3 agents; the lab has 2 nodes (VMs BLOCKED) → E2E-02 stays PARTIAL.

### J03 — Import an existing nginx host without changing it

- **Matrix:** E2E-03. **Executes:** lab API E2E `e2e_p3.py` (P3-T01/T02 + import).
- **Steps:** enroll → read-only discovery scan → findings incl. duplicate-domain conflict → import in
  Observe mode (managed via import refused) → adopt → nginx config hash and master PID unchanged.
- **Expected:** no config change, no downtime. UI coverage of the import wizard is mock-only
  (`tests/e2e/p3.spec.ts`).

### J04 — Safe nginx change with approval

- **Matrix:** E2E-04 (+ P3-T03/T04, P7-T04). **Executes:** lab API E2E `e2e_p3.py`; failsafe scenarios
  `p7-t04-nginx-failsafe.json`.
- **Steps:** broken revision → `nginx -t` blocks it, host unchanged → good revision validates (dry run)
  → apply without approval refused → creator cannot approve own revision → second user approves the
  planHash with step-up → apply + postcheck → revert → external edit detected as drift → viewer denied.
- **Expected:** preflight blocks reload; production changes need a second person with 2FA.
- **UI:** the nginx revision approval panel is exercised only in mock mode (`tests/e2e/p3.spec.ts`);
  the same `PlanApproval` + step-up component is driven against the real API in J05.

### J05 — Deploy a container app with approval, then roll back

- **Matrix:** E2E-05, E2E-06, E2E-09. **Executes:** Playwright `j05-deploy-approval.journey.ts` (UI
  approval half, `--lab`) + lab API E2E `e2e_p4.py` (v1 → v2 → broken candidate → rollback, secrets).
- **Steps (UI journey):** server from J02 (production) → legacy discovery → managed routing (requester
  step-up, second person approves) → requester creates a production deployment → `awaiting_approval`, no
  job → requester sees "waiting for approver" in Approvals → approver signs in with TOTP, sees the
  planHash, approves with a fresh 2FA step-up → deployment page shows **Succeeded** → site serves v1
  through the managed nginx route on the node.
- **Steps (`e2e_p4.py`):** preflight blocks (routing disabled, legacy domain conflict, tag-only image,
  missing secret) → v1 → v2 → broken candidate fails while v2 keeps serving → rollback to v1 → restart vs
  redeploy → secret never in API responses/logs/audit.
- **Expected:** healthy app; stable app preserved on a broken release; HTTPS/ACME BLOCKED (no public DNS).

### J06 — Build from Git + Compose stack

- **Matrix:** E2E-07. **Executes:** lab API E2E `e2e_p4b.py`.
- **Steps:** designate build node → inspect source → build from lab-git → deploy → same commit reused →
  bad commit fails with no deployment → Compose app (app + worker + Postgres, secret) → v2 changes only
  the app, DB data persists → rollback re-applies v1 plan without restoring data.
- **Expected:** persistent data survives redeploy (PHP stand-in for Laravel).

### J07 — Auto deploy from a GitHub webhook

- **Matrix:** E2E-08. **Executes:** lab API E2E `e2e_p4.py` (image mode) and `e2e_p4b.py` (build mode).
- **Steps:** signed webhook → one deployment per commit; bad signature, duplicate delivery and wrong
  branch ignored; production → `awaiting_approval` (never auto-applied).
- **Expected:** single job per commit under branch rules.

### J08 — Central logs search with sanitization

- **Matrix:** E2E-12. **Executes:** lab API E2E `e2e_p5.py` (P5-T02/T03).
- **Steps:** real nginx access logs with secrets → Loki → search through the Center → secrets redacted;
  server-scoped viewer cannot read another server's logs/metrics/incidents.
- **Expected:** scoped search and sanitization. UI log viewer: mock-only (`tests/e2e/p5.spec.ts`).

### J09 — Alert → acknowledge → resolve

- **Matrix:** E2E-13. **Executes:** lab API E2E `e2e_p5.py` (P5-T01).
- **Steps:** agent stopped → `server_offline` fires → signed webhook (+ email/telegram channel tests) →
  acknowledgment recorded → agent back → incident resolved.
- **Expected:** actionable alert and acknowledgment.

### J10 — Backup and verified restore

- **Matrix:** E2E-14, E2E-15. **Executes:** lab API E2E `e2e_p6.py` (P6-T01..T04);
  `apps/api/test/integration/center-recovery.spec.ts` (P6-T05).
- **Steps:** files backup → delete → restore → checksums identical; Postgres logical dump → scratch
  restore → rows/constraints identical; production restore needs another approver with step-up; agent
  killed mid-backup never reports success; Center DB restored into a fresh DB with the same master key.
- **Expected:** file/DB restored and verified; Center state recoverable.

### J11 — RBAC denial is enforced and audited

- **Matrix:** E2E-16 (+ P7-T03). **Executes:** Playwright `j11-rbac-denial.journey.ts` (UI; also in
  CI); RBAC steps in every lab API E2E; security suite (`pnpm test:security`, 114 tests).
- **Steps:** viewer `user1` signs in → servers readable → Enroll server and Audit log show the forbidden
  state (no enroll button) → the same enrollment sent straight to the API → 403 → audit row
  `http.post` / `denied` for that actor (API) → owner opens the Audit log UI filtered by the viewer and
  sees the denied row; no server was created.
- **Expected:** denied and audited; the UI is not the security boundary.

### J12 — Center outage: managed apps keep running

- **Matrix:** E2E-10, E2E-11. **Executes:** `e2e_p5.py` (P5-T04) and P7 scenarios
  `p7-t01-outage-api.json` (API down 601 s, 100 % availability), `p7-t02-no-replay.json` (no replay of
  stale privileged jobs).
- **Steps:** Center API (and DB) stopped → managed + legacy sites keep serving → agents buffer logs within
  their cap → Center back → agents reconnect, logs delivered; jobs queued/leased during the outage expire
  and are never re-delivered.
- **Expected:** managed apps remain up; no replay of stale privileged jobs.

## Results (P8-T03 run 2026-11-24)

Command: `scripts/lab/journeys.sh --lab --evidence docs/evidence/2026-11-24` (lab mode; the same
J01/J11/seed also passed in CI mode without `--lab`). Report: `docs/evidence/2026-11-24/p8-t03-journeys.json`;
screenshots: `docs/evidence/2026-11-24/p8-journeys/` (10 PNG, ~1 MB; token/QR areas masked).

| Journey                          | Executed by                            | Result                                                                                                                                  | Evidence                                                               |
| -------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| J01 First boot + 2FA             | Playwright UI (real API)               | **PASS**                                                                                                                                | `p8-t03-journeys.json` J01, `p8-journeys/j01-*.png`                    |
| J02 Enroll servers               | Playwright UI + real agent (lab)       | **PASS (lab substitute, 1 node in UI)**                                                                                                 | `p8-t03-journeys.json` J02, `p8-journeys/j02-*.png`                    |
| J03 Import existing nginx        | `e2e_p3.py`                            | PASS (lab), 19/19                                                                                                                       | `p3-lab-e2e.json`                                                      |
| J04 Safe nginx change + approval | `e2e_p3.py`, P7-T04                    | PASS (lab), 19/19                                                                                                                       | `p3-lab-e2e.json`, `p7-t04-nginx-failsafe.json`                        |
| J05 Deploy + approval + rollback | Playwright UI (lab) + `e2e_p4.py`      | **PASS (lab)**: requester waits, approver approves the planHash with step-up in the UI, deployment succeeds; API half PASS (lab), 15/15 | `p8-t03-journeys.json` J05, `p8-journeys/j05-*.png`, `p4-lab-e2e.json` |
| J06 Git build + Compose          | `e2e_p4b.py`                           | PASS (lab), 15/15                                                                                                                       | `p4b-lab-e2e.json`                                                     |
| J07 Auto-deploy webhook          | `e2e_p4.py`, `e2e_p4b.py`              | PASS (lab)                                                                                                                              | `p4-lab-e2e.json`, `p4b-lab-e2e.json`                                  |
| J08 Logs search                  | `e2e_p5.py`                            | PASS (lab), 7/7                                                                                                                         | `p5-lab-e2e.json`                                                      |
| J09 Alert → ack → resolve        | `e2e_p5.py`                            | PASS (lab), 7/7                                                                                                                         | `p5-lab-e2e.json`                                                      |
| J10 Backup + verified restore    | `e2e_p6.py`, `center-recovery.spec.ts` | PASS (lab), 11/11; P6-T05 PASS (integration)                                                                                            | `p6-lab-e2e.json`                                                      |
| J11 RBAC denial audited          | Playwright UI (real API)               | **PASS**                                                                                                                                | `p8-t03-journeys.json` J11, `p8-journeys/j11-*.png`                    |
| J12 Center outage                | `e2e_p5.py`, P7-T01/T02                | PASS (container lab)                                                                                                                    | `p5-lab-e2e.json`, `p7-t01-outage-api.json`, `p7-t02-no-replay.json`   |

Lab API E2E results are the 2026-11-24 re-runs already in `docs/evidence/2026-11-24/` (not re-executed
by P8-T03).

## E2E-01..18 → journeys

| Matrix | Scenario                         | Journey              | Executed by                        | Status                                      | Evidence                                               |
| ------ | -------------------------------- | -------------------- | ---------------------------------- | ------------------------------------------- | ------------------------------------------------------ |
| E2E-01 | First boot + 2FA                 | J01                  | Playwright UI                      | PASS                                        | `p8-t03-journeys.json`                                 |
| E2E-02 | Enroll 3 agents                  | J02                  | Playwright UI (lab) + lab API E2Es | PARTIAL (2 lab nodes; 3rd node/VMs BLOCKED) | `p8-t03-journeys.json`, `p7-setup-fleet.json`          |
| E2E-03 | Import existing Nginx            | J03                  | `e2e_p3.py`                        | PASS (lab)                                  | `p3-lab-e2e.json`                                      |
| E2E-04 | Invalid Nginx change             | J04                  | `e2e_p3.py`                        | PASS (lab)                                  | `p3-lab-e2e.json`, `p7-t04-nginx-failsafe.json`        |
| E2E-05 | GitHub Next.js deploy            | J05                  | Playwright UI (lab) + `e2e_p4.py`  | PARTIAL (HTTP; HTTPS/ACME BLOCKED)          | `p8-t03-journeys.json`, `p4-lab-e2e.json`              |
| E2E-06 | NestJS secrets                   | J05                  | `e2e_p4.py`                        | PASS (lab)                                  | `p4-lab-e2e.json`                                      |
| E2E-07 | Laravel + DB Compose             | J06                  | `e2e_p4b.py`                       | PASS (PHP stand-in)                         | `p4b-lab-e2e.json`                                     |
| E2E-08 | GitHub auto deploy               | J07                  | `e2e_p4.py`, `e2e_p4b.py`          | PASS (lab)                                  | `p4-lab-e2e.json`, `p4b-lab-e2e.json`                  |
| E2E-09 | Broken release                   | J05                  | `e2e_p4.py`                        | PASS (lab)                                  | `p4-lab-e2e.json`                                      |
| E2E-10 | Center outage                    | J12                  | `e2e_p5.py`, P7-T01                | PASS (container lab)                        | `p5-lab-e2e.json`, `p7-t01-outage-api.json`            |
| E2E-11 | Agent reconnect, no stale replay | J12 (+J02 reconnect) | P7-T02                             | PASS (lab + integration)                    | `p7-t02-no-replay.json`                                |
| E2E-12 | Central logs                     | J08                  | `e2e_p5.py`                        | PASS (lab)                                  | `p5-lab-e2e.json`                                      |
| E2E-13 | Fleet monitoring alert           | J09                  | `e2e_p5.py`                        | PASS (lab)                                  | `p5-lab-e2e.json`                                      |
| E2E-14 | Backups                          | J10                  | `e2e_p6.py`                        | PASS (lab)                                  | `p6-lab-e2e.json`                                      |
| E2E-15 | Center disaster recovery         | J10                  | `center-recovery.spec.ts`          | PASS (integration)                          | `apps/api/test/integration/center-recovery.spec.ts`    |
| E2E-16 | Unauthorized operation           | J11                  | Playwright UI + security suite     | PASS                                        | `p8-t03-journeys.json`, `docs/SECURITY_TEST_REPORT.md` |
| E2E-17 | Clean Ubuntu install             | — (P8-T01)           | workstream A `e2e_p8_install.py`   | not part of P8-T03                          | `docs/INSTALL.md`                                      |
| E2E-18 | Center/agent upgrade             | — (P8-T02)           | workstream C `e2e_p8_upgrade.py`   | not part of P8-T03                          | `docs/UPGRADE_RUNBOOK.md`                              |

All `p*-lab-e2e.json` / `p7-*.json` paths are under `docs/evidence/2026-11-24/`.

## Findings from the journeys

1. **Audit filter "Action starts with" did an exact match — fixed.** The web now sends
   `action[prefix]=<value>` (`apps/web/src/components/settings/audit-view.tsx`).
2. **J05 was first blocked by lab disk** (Docker VM 90 % → `DISK_LOW`, correct product behaviour). After
   the build cache was pruned (volumes untouched) it ran and exposed two real gaps, both fixed:
   deployments had no display labels (`applicationName`, `createdByLabel` now returned by the API, so the
   Approvals list shows the app and requester), and the journey navigated away before the approve call
   finished (it now waits for the response). Final run: 5/5 PASS.
3. One earlier run saw a React hydration error (#418) on `/login` in J11; it did not reproduce in the next
   two runs. Tracked as a flake.
4. The dev seeder's `superadmin` (platform owner) has no 2FA (visible in J02 screenshots: "2FA not
   enabled"). Dev-only by design; production owners are created through J01 and enrol TOTP.

## Not covered by UI journeys (honest gaps)

- J03, J04, J06–J10, J12 are executed through the real API by the lab E2E scripts, not through the UI.
  Their UI screens are covered only by the mock-mode Playwright specs (`tests/e2e/p3..p6.spec.ts`), which
  verify rendering and gating, not the Center's behaviour.
- J02/J05 need the container lab and run only with `--lab` (not in CI).
- No video is kept for passing journeys (Playwright `retain-on-failure`); screenshots are the evidence.
