> **CONSOLIDATED EDITION v3.0 (2026-11-17)** — Replaces prior design briefs and includes public/private IP, central SSH, firewall policies, software marketplace, and MCP/AI operations.
> **Existing artifact:** preserve and incrementally edit `W3 Server Panel.dc.html` when available; never overwrite unrelated work.

# W3 Server Panel — Claude Design Master Brief

> Role: **Claude Design / Senior Product Designer + UX Architect**  
> Project: **W3 Server Panel**  
> Status: Design specification for implementation, not a mockup-only exercise  
> Target: Responsive web application for desktop-first infrastructure operators, usable on tablet and mobile  
> Language: **English default (`en`)**, Thai optional (`th`), complete locale coverage

---

## 0. Instructions to Claude Design (read first)

You own **product information architecture, UX flows, screens, responsive states, interaction specifications, accessibility, and developer handoff**. Design a *real* centralized infrastructure management panel, not an illustrative SaaS landing page. Follow this document as the single design brief. Do not silently remove security confirmations, failure states, or complex workflows to make a screen prettier.

**Execution protocol**
1. Inspect the existing design/code/repository when provided; otherwise create a versioned design specification and reusable design assets in an organized workspace.
2. Produce a sitemap, persona/task flows, low-fidelity wireframes, high-fidelity layouts, component system, responsive specs, and handoff contracts.
3. Work in the phases below. Check every TODO only after providing an artifact and validating its acceptance criteria.
4. Explicitly label assumptions, blockers, missing backend dependencies and UX tradeoffs. Do not claim functionality is working because a clickable prototype exists.
5. Keep every operation classified as `read-only`, `write`, `destructive`, or `privileged`. Expose scopes, risks, permission requirements, dry-run/preflight, and confirmation where applicable.
6. If tools can create actual editable frames/components, use them; otherwise deliver implementation-ready Markdown specs with exact screen states and component names. Do not claim an editable design file unless it exists.
7. At every phase, supply a **Design QA Report** with evidence, issues, fixes, and checked TODOs.

**Definition of done:** engineers can implement every MVP screen without inventing flows, permissions, error handling, or missing states.

---

## 1. Product purpose and non-negotiable principles

A self-hosted **central control plane** that manages multiple Ubuntu/Debian servers via remotely enrolled **Go agents**, and controls existing Nginx-based applications without forcing an immediate migration. Central operations include monitoring, log search, backups, safe management, deployment, rollback, alerts and an accessible guided deployment wizard.

### Product principles
- **Agent-first:** enroll nodes from one center; no inbound public management port required on managed hosts.
- **Legacy-friendly:** Discover → Observe → Adopt → Managed; import must be non-invasive by default.
- **One pane of glass:** fleet, workloads, domain routing, deploy history, logs, metrics, backups, policy, audit.
- **Workloads survive control-plane outages:** show stale/offline status and reconciliation.
- **Safe by default:** no accidental production changes, secret leaks, auto-replayed dangerous jobs, or unreviewed Nginx config rewrites.
- **Progressive disclosure:** novices get a wizard; operators can see advanced options, exact changes and logs.
- **Honest status:** distinguish `unmanaged`, `discovered`, `observed`, `adopted`, `managed`, `unsupported`, `partial`, `unknown`.

### Target users
- **Platform Owner**: global infrastructure visibility, security policy, restore approvals.
- **Ops Admin**: server enrollment, runtime management, deployments and backups.
- **Developer/Deployer**: projects, builds, deploys, logs under restricted scope.
- **Viewer/Auditor**: read-only metrics, deployment history and audit trails.

### Initial scope (MVP-A and MVP-B)
**MVP-A**: login + 2FA, fleet enrollment, inventory, health status, discovery/import preview, read-only adoption, permission-gated management, GitHub/image/Compose deployments, deploy wizard, Nginx config validation+safe reload, health checks, history, app rollback, audit events.

**MVP-B**: centralized monitoring, searchable system/app logs, alerts, backup policy, file+database backup, offsite repositories, restore preview+approval+verification, recovery drills, operational hardening.

**Explicitly later / no false promises**: multi-tenant untrusted workloads, Kubernetes, full mail/DNS hosting, browser root shell, fully automatic migration of arbitrary Nginx/PHP configurations, guaranteed zero-downtime Compose deployments, automatic universal DB rollback. **An audited SSH gateway with human-controlled web terminal is included as an extended milestone, not a root shell exposed through the Go Agent or MCP.**

---

## 2. IA / navigation system

**Global:** environment indicator (PRODUCTION/UAT/DEV), fleet health, active jobs, alerts, search, notifications, account, 2FA/security.

**Primary nav (extend with Network, Firewall Policies, SSH & Credentials, Plugins & Software, Runtimes, Databases, AI & MCP and Approvals; do not hide previously listed sections):**
1. **Overview**: cross-fleet summary, incidents, recent deploys, storage warnings.
2. **Servers**: grid/table, filters, add/enroll, server detail with Overview / Inventory / Services / Nginx / Docker / Metrics / Logs / Backups / Events / Settings.
3. **Applications**: portfolio, discovery status, ownership mode, server/environment/domain, detailed runtime/deploys/logs/settings.
4. **Deployments**: all jobs, pending approval, history, rollback, deployment detail timeline.
5. **Discovery & Import**: scan jobs, findings, import wizard, adoption mode, risk review.
6. **Monitoring**: fleet metrics, server drilldown, service health and incidents.
7. **Logs**: central query, live tail, retention indicators, query access boundaries.
8. **Backups**: policies, schedules, repositories, snapshots, restore jobs, drill reports.
9. **Alerts**: rules, incidents, channels, acknowledgment.
10. **Settings**: users/roles, GitHub integration, credentials, agent certificates, audit, global policies, appearance.

**Cross-links:** each application links to its server, domain, proxy config (read-only diff view), deploys, logs and backups; each server links to affected applications; each failure has a contextual troubleshooting view.

---

## 3. Design system specification

Create `design-tokens.md`, `components.md`, `interaction-patterns.md`, `responsive.md` and implementable component inventory.

- Design: professional infrastructure console, high information density without clutter; calm neutrals, clear semantic status colors, restrained typography.
- Default desktop layout: collapsible sidebar, top environment bar, 12-column grid, sticky critical actions where needed.
- Breakpoints: mobile 360–767; tablet 768–1199; desktop ≥1200. Test widths **360, 390, 768, 1024, 1280, 1440**.
- Define spacing (4px rhythm), typography, icon sizes, navigation, elevation, borders, focus rings, overlays, responsive tables.
- Light and dark theme with semantic design tokens, never encode status through color alone.
- WCAG 2.2 AA target: keyboard navigation, visible focus, labels, sufficient contrast, accessible modal/trap/return focus, 44px touch targets where practical, no auto-refresh that steals focus.
- i18n: no fixed-width labels, Thai line breaks, UTC timestamps stored with local display and explicit timezone, numbers and bytes with consistent units.
- Shared components: StatusBadge, EnvironmentBadge, ServerCard, ResourceMeter, ServiceStatus, AppCard, DataTable, FilterBar, EmptyState, ErrorState, PermissionNotice, RiskBanner, NginxDiffViewer, ConfigPreflight, LogViewer, Timeline, JobProgress, ApprovalDialog, SecretInput, KeyValueEditor, RetentionSelector, BackupSnapshotRow, HealthCheckEditor, StepperWizard, RetryAction, Toast, Skeleton, ConfirmDestructiveAction.
- Every page: loading, empty, partial data, stale, offline, permission denied, API error, success and long-running job state.

---

## 4. Required screen inventory and detailed acceptance

### 4.1 Authentication + workspace
- Sign in, 2FA setup/challenge/recovery, sign out, session expiry, insufficient permissions, first-admin bootstrap.
- Show actor, active environment and scope. No secrets in toasts or logs.

### 4.2 Overview dashboard
- Counts: registered/online/offline servers, unhealthy apps, queued/running/failed jobs, recent backups, active alerts.
- Cross-fleet resource usage, latest deployments, unhealthy application shortcuts, center storage/retention warnings.
- Explicit `last updated` and unknown/stale data states.

### 4.3 Server fleet
- **Card-style server listing**, environment group headers Production/UAT/Development, filters by environment/tags/OS/connection, enroll wizard, one-time token display, agent installation steps, token expiry, success confirmation.
- Server detail: telemetry, agent certificate/version, connection heartbeat, host capacity, docker runtime, nginx status, discovered apps, logs/backups, allowed actions.
- Disable dangerous actions while offline; show why, never imply a job succeeded on timeout.

### 4.4 Legacy discovery/import
- Scan selection → live scan progress → findings grouped by Nginx server block, domains, roots, upstream, TLS, Docker/systemd/PHP-FPM dependencies → unresolved ambiguities → review → **Observe (default)** → explicit Adopt/Managed opt-in.
- Findings have confidence and provenance; never invent runtime, repo or ownership mapping.
- Show **before/after Nginx config diff**, current effective config, duplicate/conflicting domains, missing certs, unsupported directives, linked container/process.
- Default scan is read-only. Clearly separate *import into inventory* from *taking ownership*.
- Nginx write flow: backup config → generate proposed change → diff → `nginx -t` preflight → approved atomic replacement/reload → postcheck → revert if failed.
- Import may be `manual review required`; no generic “zero downtime guaranteed” badge.

### 4.5 Application portfolio + details
- Application types: Dockerfile/image, Compose, existing Nginx static/PHP/proxy.
- Identity fields: project, app, environment, server, domains, runtime, ownership mode, health status, deployment status.
- Tabs: Overview / Deployments / Domains / Env & Secrets / Logs / Metrics / Backups / Settings.
- Safe separation: `redeploy` vs `restart` vs `rollback` vs `restore data`; include exact effect summaries.

### 4.6 New deployment wizard
Minimum steps (step labels may adapt):
1. **Source**: GitHub (connected repo/branch/commit), registry image@digest, Compose file, existing app import.
2. **Detection/Runtime**: framework detection, selected build method, confidence, manual overrides.
3. **Target**: environment/server, capability checks, resource limits, storage/mount restrictions.
4. **Configure**: build args, command, port, env secrets, healthcheck, persistent volumes, dependencies.
5. **Domain**: hostname, nginx/managed proxy route, DNS preflight, TLS strategy; detect collision.
6. **Review**: exact plan, version/digest, risk flags, reversible/nonreversible steps, approval.
7. **Execution**: job states queued/running/validation/starting/health-check/switching/success/failed/cancelled/rollback-pending, live logs and recovery CTA.

**GitHub push auto deploy**: setup, allowlisted repo and branch, commit pinning, webhook delivery history, approvals per environment, lock/concurrency and prior-job behavior.

**Failures**: invalid repo authorization, unsupported stack, missing secrets, missing DNS, port 80/443 conflict, insufficient disk, failed image build, unhealthy candidate, stale agent, failed rollback. Show immediate actionable guidance.

### 4.7 Nginx manager
- List sites, search, live config and syntax errors, TLS expiry, proxy target, enable/disable *only when supported*.
- Versioned config diff, test button, explicit change approval, reload result and rollback of config.
- Native Nginx stays source of truth for discovered unmanaged sites; surface external edits/conflict indicators.

### 4.8 Monitoring/alerts/logs
- Fleet metrics + individual server time-series, services, thresholds, storage estimate.
- Logs query filters: server/app/source/severity/time, retention, labels, sanitized content, no access beyond role scope.
- Live tail reconnection, capped output and pause functionality.
- Alert rules, channels, test channel, mute/acknowledge/resolve and incident timeline.

### 4.9 Backup/restore
- Policy builder: server/apps/paths/databases, schedule + timezone, repository, retention, exclusion, verification, encryption/key ownership.
- Snapshot listing: status, size, target, timestamp, checksum/verification, offsite copy state.
- Restore wizard: select snapshot → target → conflicting paths/data → dry-run → confirmation/approval → progress → integrity/application postcheck.
- Must label differences: config rollback is **not** database/data restore; backup success ≠ restore verified.

### 4.10 Admin/security
- Scoped role editor, approval policy for prod/destructive actions, session management, enrollment and certificate revoke/rotate, audit event explorer, secret rotation, safe defaults.
- Policy violations show the **rule and remediation** without exposing credentials.

---

## 5. Core user journeys to storyboard and prototype

For **every** journey, create screen-by-screen flow with happy path, failure path, permission path, cancellation path and recovery path.

- J01: Bootstrap center → enable 2FA → enroll 3 agents behind NAT → health overview.
- J02: Scan existing Nginx → map sites and upstreams → import in Observe mode with zero config changes.
- J03: Review risky legacy app → approve ownership → preview diff → validate → reload safely → observe health.
- J04: Connect GitHub → detect Next.js → choose server/domain → test DNS → deploy → health passes → open site.
- J05: Deploy Laravel + worker + Postgres using Compose → persistent volume survives redeploy.
- J06: Push commit → webhook auto-deploy → failed healthcheck → stable version preserved/reverted.
- J07: Central log query from one server → cross-link incident + deploy logs → audit trail.
- J08: Disk nearing threshold → alert → find affected apps → operator acknowledges.
- J09: Schedule backup → snapshot copied offsite → restore to isolated target → verify.
- J10: Center disconnects → apps remain online → agent reconnects → reconciled statuses; stale dangerous jobs not replayed.
- J11: Developer attempts restricted server edit → forbidden state + audit event.
- J12: Restore request on production → impact preview → approval required → execution recorded.

---

## 6. Design project deliverables

Use the following paths in design workspace or equivalent named sections:

```text
/design/
  00-product-brief.md
  01-information-architecture.md
  02-design-tokens.md
  03-components.md
  04-user-journeys.md
  05-screen-inventory.md
  06-responsive-and-accessibility.md
  07-error-and-risk-states.md
  08-handoff-api-contracts.md
  09-design-qa-report.md
  screens/
  prototypes/
```

For each screen hand off: screen ID, route, role permissions, data bindings, fields, actions, confirmation requirements, loading/empty/error/offline states, accessibility notes, responsive layout and acceptance checks. Do not invent backend endpoints as implemented; proposed contracts must be marked `PROPOSED`.

### Required pages (minimum)
`/login`, `/setup/2fa`, `/overview`, `/servers`, `/servers/new`, `/servers/:id`, `/servers/:id/nginx`, `/applications`, `/applications/:id`, `/deployments`, `/deployments/new`, `/deployments/:id`, `/imports`, `/imports/:id`, `/monitoring`, `/logs`, `/backups`, `/backups/:id`, `/restore/new`, `/alerts`, `/settings/users`, `/settings/security`, `/settings/integrations`, `/settings/audit`.

---

## 7. Phase-by-phase TODO and mandatory tests

### Phase D0 — Product framing and IA
- [ ] D0.01 Confirm MVP-A / MVP-B vs explicitly deferred functionality.
- [ ] D0.02 Define personas, permissions and production safety guardrails.
- [ ] D0.03 Deliver sitemap, navigation and cross-entity links.
- [ ] D0.04 Map application ownership states and job lifecycle terminology.
- [ ] D0.05 Review all screens for hidden destructive operations.
- [ ] **TEST D0-A:** reviewer can find every required feature in IA, with no orphan screen.
- [ ] **TEST D0-B:** all privileged/destructive tasks have a visible permission+approval path.
- [ ] **GATE D0:** brief, IA and permissions approved or recorded as assumptions.

### Phase D1 — Design system + navigation shell
- [ ] D1.01 Define light/dark semantic tokens and Thai typography.
- [ ] D1.02 Design desktop/tablet/mobile navigation.
- [ ] D1.03 Implement shared tables/cards/forms/filters/statuses/component variants.
- [ ] D1.04 Design loading, partial, offline, stale, empty, denied, errored states.
- [ ] D1.05 Document keyboard and screen-reader expectations.
- [ ] **TEST D1-A:** manual keyboard path login → overview → server → app → deploy works without mouse.
- [ ] **TEST D1-B:** 360, 390, 768, 1024, 1280, 1440 widths have no clipped primary action.
- [ ] **TEST D1-C:** semantic status understandable without color; contrast meets WCAG AA target.
- [ ] **GATE D1:** component system and base responsive shell ready.

### Phase D2 — Fleet and legacy adoption
- [ ] D2.01 Overview, fleet list, enrollment and server detail screens.
- [ ] D2.02 Legacy scan progress, findings, uncertainty and risk badges.
- [ ] D2.03 Observe/Adopt/Managed selection and explicit ownership confirmation.
- [ ] D2.04 Nginx config preview, diff, preflight, apply, revert screens.
- [ ] D2.05 Offline/reconnect/conflicting config states.
- [ ] **TEST D2-A:** simulated import never requires changing Nginx before Observe completes.
- [ ] **TEST D2-B:** ambiguous upstream/config displays “manual review” rather than forced choice.
- [ ] **TEST D2-C:** failed `nginx -t` visibly blocks Apply and provides revert/resolution UI.
- [ ] **GATE D2:** J01/J02/J03/J10 walkthroughs pass.

### Phase D3 — Deployment wizard + application lifecycle
- [ ] D3.01 App portfolio + details + deployment history.
- [ ] D3.02 Wizard for GitHub, image, Compose and import paths.
- [ ] D3.03 Preflight checks: permissions, agent, DNS, ports, secrets, resources, proxy.
- [ ] D3.04 Live progress, errors, cancellation, health check, rollback UX.
- [ ] D3.05 GitHub webhook + auto deploy rules/approvals.
- [ ] **TEST D3-A:** Next.js happy-path prototype from repo selection to deployed health view.
- [ ] **TEST D3-B:** missing secret, port collision and unhealthy candidate have explicit blocked/recovery states.
- [ ] **TEST D3-C:** user can distinguish restart, redeploy, rollback and data restore.
- [ ] **GATE D3:** J04/J05/J06 pass against complete screen contracts.

### Phase D4 — Monitoring, logs, alerts and backups
- [ ] D4.01 Fleet and server-level metric charts with time intervals and stale markers.
- [ ] D4.02 Central logs query, filtering and streaming behavior.
- [ ] D4.03 Alerts rules, channel setup, incident lifecycle and notification tests.
- [ ] D4.04 Backup policies, snapshots and restore wizard with safety approvals.
- [ ] D4.05 Storage and retention visibility with capacity warnings.
- [ ] **TEST D4-A:** server-offline, log-retention-expired and no-metrics states are distinct.
- [ ] **TEST D4-B:** destructive restore cannot be reached without explicit impact confirmation.
- [ ] **TEST D4-C:** backup successful but unverified restore is honestly marked as unverified.
- [ ] **GATE D4:** J07/J08/J09/J12 pass.

### Phase D5 — Handoff, QA and completeness
- [ ] D5.01 Export all screens, states, specs and assets (or deliver coherent Markdown equivalents).
- [ ] D5.02 Each screen has route, bindings, permissions, all statuses, validation and action behavior.
- [ ] D5.03 Design tokens/components map to reusable code components.
- [ ] D5.04 Run mobile/tablet/desktop visual checks and accessibility review.
- [ ] D5.05 Audit every TODO against a verifiable artifact; mark unsupported/deferred items.
- [ ] **TEST D5-A:** developer can implement a wizard without asking what happens after failed preflight.
- [ ] **TEST D5-B:** operator can follow J01–J12 from design without guessing.
- [ ] **GATE D5:** design handoff complete, versioned, defects documented.

---

## 8. Design QA matrix (must fill after each phase)

| ID | Screen / Journey | Desktop | Tablet | Mobile | Keyboard/AA | Offline/Error | Safe action | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|
| DQA-001 | Login/2FA | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |
| DQA-002 | Enroll server | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |
| DQA-003 | Legacy import | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |
| DQA-004 | Deployment wizard | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |
| DQA-005 | Nginx safe edit | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |
| DQA-006 | Monitoring/logs | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |
| DQA-007 | Backup/restore | TODO | TODO | TODO | TODO | TODO | TODO | Link/shot | NOT RUN |

---

## 9. Required final response format for Claude Design

At each phase: `Completed`, `TODO remaining`, `Artifacts/URLs`, `UX decisions`, `Accessibility/responsive test results`, `Known issues`, `Needs review`, `Next phase`. Never mark tests PASS unless actually executed and accompanied by evidence. For interactive UI created from code, provide runnable entrypoint and setup instructions; for Figma/editable design provide real file/page references only.

**START NOW:** execute Phase D0, generate the IA and task flows, then proceed phase by phase through D5. Do not stop at visual mockups. When information is missing, document a safe default and continue; ask only if the choice causes irreversible production risk.


---

## 10. Consolidated additions: authoritative product contract

This section **extends and supersedes conflicting earlier wording**. The original D0–D5 design phases remain mandatory; also complete D6–D10 below. If the previous HTML design already exists, modify it incrementally. **Do not deliver only a written description when editable HTML/design source is available.** Deliver visual UI for each module and interactive happy/error/approval states.

### 10.1 Default language and environment taxonomy

- [ ] Default locale **`en`**, switchable **`th`**; persist selection per user; fallback to English for absent strings, report missing keys.
- [ ] Translate navigation, errors, validation, warning/approval dialogs, terminal controls, empty states, notifications, help and wizard content. Do not translate command output or host logs.
- [ ] Server fleet **Card Style by default**, optional table view on desktop. Cards show name, Production/UAT/Development group, provider/region, OS, status, agent status, public IPv4, private IPv4, connection path, CPU/RAM/disk, critical alerts and quick actions.
- [ ] Filter/search/sort by environment, tags, provider, VPC, capabilities and status; group cards into collapsible Production/UAT/Development clusters.
- [ ] Clarify environment is a user-managed label, not automatically a network/firewall trust boundary.

### 10.2 Public/private address and DigitalOcean networking

- [ ] Per-server Network screen: public IPv4/IPv6, private IPv4, additional interfaces, subnet/CIDR, gateway, DNS, VPC UUID/name, region, detected path and last verified timestamp.
- [ ] Separate editable **management endpoint** from **application backend endpoint**; distinguish detected address, override, and verification status.
- [ ] Preferred connection: Auto, Private preferred, Private-only, Public preferred, Public-only; show connectivity and reason for failover; **never silently downgrade** from Private-only to Public.
- [ ] Network diagnosis: VPC membership discovery, routing, ping/TCP checks, reachable SSH endpoint, reachable app port, firewall conflicts. Show Private IP reachability independently from shared VPC membership; ping alone does not prove same VPC.
- [ ] DigitalOcean inventory integration screen: **read-only** Droplet ID, VPC UUID, region, interfaces, firewall IDs. Permit cloud firewall management only through separate privileged workflow.
- [ ] Display an explicit note: editing W3 endpoint metadata does not edit Ubuntu netplan/network interface or change Public IP.
- [ ] Network topology screen: Center (control plane), optional dedicated Gateway, private links, public ingress, agent path, selected target server; show warnings if traffic would traverse a public endpoint.
- [ ] Gateway mode selector: *Direct Public Ingress* (existing), *W3 Gateway Reverse Proxy* (opt-in), *Hybrid* (per-domain choice). Show shadow test, TLS readiness, backend health, DNS cutover and rollback plan. Never imply moving DNS is instant or guarantees zero downtime.

### 10.3 Human SSH gateway and key administration

- [ ] Server card and detail have **Open Terminal**, with server, effective endpoint (public/private), SSH user, SSH port, authentication method and access scope visible.
- [ ] Terminal UI: tabbed sessions, connect/reconnect/disconnect, full-screen, focus/keyboard handling, resize, idle timeout, disconnected/stale session states, explicit exit status.
- [ ] Credentials area: generate/register SSH public keys, upload existing private key **only into backend-approved encrypted secret storage**, show public fingerprint, assignment, rotation, revoke and host key fingerprint. Private keys must never be rendered to browsers or exposed in APIs.
- [ ] First-connect TOFU/approved host key screen; changed host key = **block connection with prominent warning**, not a dismissible toast.
- [ ] Production terminal requires scoped RBAC, step-up MFA, just-in-time approval where policy requires, session audit and optional explicitly approved recording policy.
- [ ] No unrestricted SSH shell as an MCP tool; the human terminal is a separate privileged Center SSH gateway with no direct browser possession of host keys.

### 10.4 Firewall management: local + shared + DigitalOcean

- [ ] Per-server firewall cards and rule table: source/destination, protocol, port ranges, allow/deny, direction, address/interface, rule origin, desired vs observed, last applied, rule change diff.
- [ ] Shared policies by environment/group/server, versioning, inheritance, dry-run, drift detection, conflict handling, override precedence, staged rollout and history.
- [ ] Clearly distinguish **host firewall** (UFW/nftables adapter) from **DigitalOcean Cloud Firewall**, with capability badges and separate rule sources.
- [ ] Protected-management-path warning for SSH, Center/Agent connection and web ports. A lockout-prone policy has hard-blocked apply until a safe recovery mechanism and appropriate approval exist.
- [ ] Safety wizard: Select → Diff → Impact/Reachability Check → Canary/Approval → Apply with timed rollback → Verify → Commit/Restore.
- [ ] Partially applied fleet policy: per-target success/error and Resume/Retry/Restore, never a misleading fleet-wide green state.

### 10.5 Plugins & Software catalog (aaPanel-like, server-scoped)

Design Marketplace list + Plugin Detail + Installed Inventory + Install/Update/Configure/Uninstall wizard, with a **manifest-based signed/allowlisted plugin concept**, not arbitrary downloaded shell scripts.

- [ ] Categories: Security, Web Servers, Runtimes, Databases, Containers, Networking, Monitoring, Backups, Utilities.
- [ ] Initial catalog cards: Fail2ban, UFW, Nginx, Apache, Docker Engine, Docker Compose, PHP/PHP-FPM, Node.js, Python, Composer, Git, PostgreSQL, MySQL/MariaDB, Redis, MongoDB, Certbot, Cron manager, systemd service manager, log viewer.
- [ ] Each entry: description, compatibility, OS/architecture, version, dependency graph, risk, installed state, drift, supported actions, verification/rollback capability.
- [ ] Installer wizard: Target(s) → Version/Options → Preflight (disk, ports, conflicts, packages, services) → Full impact & plan → Approval → Install Job → Verification/Status.
- [ ] Show **unsupported** and **manual intervention required** rather than implying availability of every plugin/version. Demo/mock capability status must be labeled.
- [ ] Per-server runtime dashboard: installed PHP versions/FPM pools/extensions, Node versions, Python environments, Docker components, service controls. Application-scoped vs host-wide changes visibly separate.
- [ ] Database inventory and management screen: engine/version, host, port/bind, DBs/users/grants, service state, backup status; create/manage flows require risk/scope/secret handling and approvals.

### 10.6 AI & MCP Operations UI

Design a first-class **AI & MCP** menu with:

- [ ] MCP Connections: endpoint, status, protocol, authorization method, last verified, copy-safe connection instructions (never credentials).
- [ ] AI Agents: card view for Claude Code / Codex / Hermes / custom identities; owner, environments, server groups, scopes, last activity, revoke.
- [ ] Tool Catalog: searchable tools, input fields and risk classification (READ / LOW / HIGH / DESTRUCTIVE); per-agent permitted tools.
- [ ] Policies & Automation: by environment/project/server/tool; GitHub push and schedule triggers; dry-run and active/disabled state.
- [ ] Approval Inbox: exact target, commit/image digest, plan hash, risk, expiry, approver, approve/reject and invalidated/revoked states.
- [ ] AI Job Timeline: Requested → Planning → Validation → Awaiting Approval → Queued → Running → Verify → Completed/Failed/Rollback; live logs (redacted), duration, immutable artifact and audit actor.
- [ ] Tool execution detail: inputs with secrets hidden, structured outputs, result, retries, idempotency key, correlation ID, ownership and access-denied evidence.
- [ ] AI incident diagnostics and suggested corrective action: show evidence and human review before production mutation.
- [ ] Explicit distinction between **AI proposed** action and **Center authorized/executed/verified** action.

### 10.7 Updated Server Details tabs

Use responsive scrollable tabs or responsive subnavigation, not 15 cramped tabs:

1. Overview; 2. Applications; 3. Network; 4. Terminal; 5. Firewall; 6. Software; 7. Runtimes; 8. Databases; 9. Monitoring; 10. Logs; 11. Backups; 12. Events & Audit; 13. Settings.

Global modules must deep-link into these scoped server tabs, retaining active environment and filters.

## 11. Extended design phases with atomic checklists and tests

### D6 — Fleet cards + network/VPC + Gateway UX
- [ ] D6-01 Convert existing Servers listing into grouped cards; ensure existing flows remain accessible.
- [ ] D6-02 Add public/private IP, IP copying, network endpoints and connectivity badges.
- [ ] D6-03 Design VPC inventory and Private/Public path diagnostics.
- [ ] D6-04 Design Gateway optional routing + shadow-testing and reversible cutover.
- [ ] D6-T1 Switch `en↔th`, verify all new labels and errors; record screenshots.
- [ ] D6-T2 Filter Production/UAT/Development; ensure cards and counts match.
- [ ] D6-T3 Model unreachable private endpoint, public-only and stale agent independently.
**Gate:** no implied automatic OS network mutation; all three environment groupings and Gateway modes visible.

### D7 — SSH + firewall lifecycle
- [ ] D7-01 Design SSH terminal, key metadata/assignments and host-key warnings.
- [ ] D7-02 Design permission denied, MFA/approval, disconnected, timed-out and failed SSH.
- [ ] D7-03 Design host firewall and DigitalOcean firewall separate inventories.
- [ ] D7-04 Design shared policy wizard, canary, rollback, partial failure and drift.
- [ ] D7-T1 Walkthrough host key mismatch: connection blocked.
- [ ] D7-T2 Walkthrough firewall lockout proposal: cannot apply without safe recovery.
- [ ] D7-T3 Walkthrough apply to UAT → test → propose Production → approval.
**Gate:** no production-changing action can skip preflight/approval states.

### D8 — Plugin installer + runtimes + databases
- [ ] D8-01 Catalog categories, cards, installed state and capabilities.
- [ ] D8-02 Full install wizard with version/dependency/conflict/approval/job progress.
- [ ] D8-03 Runtime configuration and service manager with scope indicators.
- [ ] D8-04 Database lifecycle, credential-safe forms and restore confirmation.
- [ ] D8-T1 Fail2ban install happy/fail/unsupported OS paths.
- [ ] D8-T2 Node.js version selection conflicting with existing runtime.
- [ ] D8-T3 PostgreSQL creation with secret masking, port conflict and backup warning.
**Gate:** pending, partial, failed and verification states designed per operation.

### D9 — MCP/AI Operations + approvals
- [ ] D9-01 AI agent cards, connection instructions and tool catalog.
- [ ] D9-02 Fine-grained scopes, environment policy matrix and access revocation.
- [ ] D9-03 Approval Inbox, single-use plan-bound approval and expiry handling.
- [ ] D9-04 AI deployment timeline, failure rollback and troubleshooting views.
- [ ] D9-T1 Agent with UAT-only scope cannot initiate Production deploy.
- [ ] D9-T2 Change commit after approval and show invalidated approval.
- [ ] D9-T3 Disable AI client mid-job; model cancellation/reconciliation status honestly.
**Gate:** no pretend direct shell/root, no secret exposure in UI or snippets.

### D10 — Integrated design release, handoff and QA
- [ ] D10-01 Re-run full D0–D9 navigation and E2E flow map without regressions.
- [ ] D10-02 Produce `docs/design/SCREEN_INVENTORY.md`, `INTERACTION_CONTRACTS.md`, `LOCALES_EN_TH.md`, `COMPONENTS.md`, `DESIGN_TEST_REPORT.md`.
- [ ] D10-03 Test viewports 360, 390, 768, 1024, 1280, 1440 + light/dark + keyboard navigation.
- [ ] D10-04 Review 3 personas: Owner, Operator, Developer with RBAC differences.
- [ ] D10-05 Link every UI action to an API/tool contract ID and label not-yet-implemented backend actions.
- [ ] D10-T1 No inaccessible dialogs, missing translations or broken state navigation.
- [ ] D10-T2 AI prod approval, firewall rollback, private IP diagnosis and plugin install flows complete in prototype.
**Gate:** deliver editable existing `.dc.html` plus evidence-backed handoff; do not claim backend works based on prototype.

## 12. Cross-team contracts and Definition of Done

Each designed action must map to `feature_id`, `screen_id`, `action_id`, `minimum_role`, `resource_scope`, `risk_level`, `preflight`, `approval_policy`, `API operation`, `loading/partial/error/success`, `test_ids`. Match IDs with Claude Code's `docs/FEATURE_MATRIX.md`.

Mandatory test journeys (repeat in both locales): server enrollment; group cards; private/public endpoint selection; Nginx read-only adoption; SSH key approval and terminal; shared firewall canary/rollback; plugin Fail2ban install; PHP/Node runtime; PostgreSQL backup; Git UAT deploy; Prod approval; AI MCP read/status/deploy; Center outage. **PASS only if prototype interaction and state coverage can be demonstrated**, otherwise BLOCKED with reason.

## 13. Final delivery format

- Updated `W3 Server Panel.dc.html` (or source design artifact found in workspace).
- Design system and component inventory, sitemap and navigation cross-links.
- Screens and fully described state/permission/approval variants.
- `docs/design/DESIGN_TODO.md` with per-item `[ ]`/`[x]` and artifact links.
- `docs/design/DESIGN_TEST_REPORT.md` with `PASS/FAIL/BLOCKED`, evidence and tested locale/viewport.
- `docs/design/HANDOFF.md` + screen-to-API contract matrix.
- A **final unresolved gaps list** without overstating completeness.
