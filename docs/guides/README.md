# pPanel operator guides

Task-oriented guides for operating a pPanel Center and its fleet. Each guide lists the purpose, who may
do it (permissions and roles), the UI steps with the equivalent API call, what you should see, failure
modes with recovery, and limitations.

These guides describe the product as built in `0.8.0-rc.1` (see [RELEASE_CONTRACT.md](../RELEASE_CONTRACT.md)).
When a guide and the contract disagree, [API_CONTRACTS.md](../API_CONTRACTS.md) and
[AGENT_PROTOCOL.md](../AGENT_PROTOCOL.md) are authoritative.

| Guide                                             | Covers                                                                                    |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Enroll servers](enroll-servers.md)               | Enrollment token, agent install, revoke, certificate renewal, environments, addresses     |
| [Import existing Nginx](import-nginx.md)          | Read-only scan, Discover → Observe → Adopt → Managed, drift                               |
| [Nginx changes and TLS](nginx-changes-and-tls.md) | Revisions, `nginx -t`, approval with step-up, apply, revert, failsafe, TLS                |
| [Deploy applications](deploy.md)                  | Container apps, secrets, deploy, rollback, Compose apps, Git builds on build nodes        |
| [Auto-deploy from GitHub](auto-deploy.md)         | Webhook integrations, branch rules, image templates, build mode, "latest wins" coalescing |
| [Central logs](logs.md)                           | Query, live tail, scoping, redaction, retention, buffering during a Center outage         |
| [Alerts and incidents](alerts.md)                 | Rules, channels (email, Telegram, signed webhook), acknowledge, auto-resolve              |
| [Backup and restore](backup-restore.md)           | Repositories, append-only restic, policies, runs, verification, restore wizard            |
| [Emergency recovery](emergency-recovery.md)       | Center outage, agent offline, manual-recovery states, Center disaster recovery            |
| [Network and Gateway](network-and-gateway.md)     | Server cards/groups, private/public paths, VPC inventory, diagnostics, Gateway routing    |

Install, upgrade and compatibility live in their own documents: see [INSTALL.md](../INSTALL.md),
[UPGRADE_RUNBOOK.md](../UPGRADE_RUNBOOK.md), [MIGRATION_RUNBOOK.md](../MIGRATION_RUNBOOK.md) and
[COMPATIBILITY.md](../COMPATIBILITY.md). The runbook index is [runbooks/README.md](../runbooks/README.md).

## Conventions used in every guide

- **API paths** are relative to `/api/v1` on the Center (for example `POST /enrollments` means
  `POST https://<center>/api/v1/enrollments`). Send `Authorization: Bearer <access token>`,
  `Content-Type: application/json` and an `X-Request-ID: <uuid>`. Responses use the COMPATTANA envelope
  `{ success, statusCode, message, data, meta: { requestId } }`; errors are `{ error: { code, message, details } }`.
- **Versioned resources** take `If-Match: <version>`. A stale version returns 409 `VERSION_CONFLICT`:
  reload and retry, never force.
- **Step-up**: production and privileged actions need a fresh TOTP. Call `POST /auth/step-up { code }`
  and send the returned token as header `X-Step-Up` (valid 5 minutes). Without TOTP enabled you get
  403 `MFA_REQUIRED`; set it up under **Settings → Security → Set up 2FA**.
- **Approvals** are plan-hash bound, single use, expire 60 minutes after approval, and the approver must
  be a different user from the creator (`APPROVER_IS_CREATOR`).
- **Audit**: every mutating call (including denied ones) writes an audit event. Find it under
  **Settings → Audit log** (`GET /audit-events`, needs `audit.read`).

## Roles

Permissions are granted through scoped role bindings (global ⊇ environment ⊇ server), managed under
**Settings → Users & roles**. Built-in roles:

| Role                              | Permissions                                            |
| --------------------------------- | ------------------------------------------------------ |
| Platform Owner (`platform_owner`) | all                                                    |
| Ops Admin (`ops_admin`)           | all except `users.manage`                              |
| Deployer (`deployer`)             | `fleet.read`, `apps.read`, `apps.deploy`, `nginx.read` |
| Viewer / Auditor (`viewer`)       | `fleet.read`, `apps.read`, `nginx.read`, `audit.read`  |

The UI only enables buttons the Center grants (`allowedActions`). The Center re-checks every call.
