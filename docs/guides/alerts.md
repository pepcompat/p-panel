# Alerts and incidents

Define alert rules, send notifications to email, Telegram or a signed webhook, and work incidents
through acknowledge and automatic resolve. Verified by `scripts/lab/e2e_p5.py` (P5-T01: agent loss →
incident → HMAC-valid webhook → viewer ack refused, admin ack recorded → auto-resolved; email and Telegram
channel tests).

## Prerequisites and permissions

| Task                                  | Permission                                           | Built-in roles            |
| ------------------------------------- | ---------------------------------------------------- | ------------------------- |
| See incidents                         | `fleet.read` (scope-filtered)                        | all four                  |
| Acknowledge or comment on an incident | `fleet.read` + `servers.operate` in the target scope | Platform Owner, Ops Admin |
| Create, edit, delete rules            | `policies.manage` covering the rule's scope          | Platform Owner, Ops Admin |
| Manage notification channels          | global `policies.manage`                             | Platform Owner, Ops Admin |

Email needs `PPANEL_SMTP_URL` (and `PPANEL_SMTP_FROM`) on the Center. Notification links use
`PPANEL_PUBLIC_WEB_URL`. Metric thresholds need fresh heartbeats; they do not need Prometheus.

UI: **Alerts** (`/alerts`) with tabs **Incidents**, **Rules**, **Channels**; incident detail at
`/incidents/:id`.

## 1. Create a notification channel

**Channels → + New channel** → choose **Webhook**, **Email** or **Telegram** → **Create channel** →
**Send test**.

| Type     | Config                              | Notes                                                                                                      |
| -------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Webhook  | `url`, `signingSecret` (≥ 16 chars) | https only in production; private, loopback and metadata addresses refused unless allowlisted (SSRF guard) |
| Email    | `to[]`                              | sent through the Center's SMTP relay                                                                       |
| Telegram | `botToken`, `chatId`                | notify only, with a dashboard link; nothing can be approved or acknowledged from Telegram                  |

```http
POST /notification-channels
{ "name": "ops-webhook", "type": "webhook", "config": { "url": "https://hooks.example.com/ppanel", "signingSecret": "…" } }
POST /notification-channels/:id/test        → { delivered, error?, deliveryId }
```

Secrets are encrypted and write-only (`{ set: true }` in reads). `PATCH` with `If-Match` merges config, so
omitted secrets are kept. Enable/disable from the channel card.

### Verifying the webhook signature

Each webhook POST carries `X-PPanel-Event` and `X-PPanel-Signature: sha256=<hex>`, the HMAC-SHA256 of the
raw request body with the channel's signing secret. Body: `{ incident, event, sentAt }`. Verify on the
receiver by recomputing the HMAC over the raw body and comparing in constant time. Timeout 5 s, 3 retries
with backoff on network errors, 5xx, 429 and 408; redirects are not followed.

Notifications contain rule name, target name, severity, value and a link to
`<PPANEL_PUBLIC_WEB_URL>/incidents/<id>` — never secrets or log lines.

## 2. Create a rule

**Rules → + New rule**: **Name**, **Kind**, **Scope** (all servers in scope, environment, server or
application), **Severity** (info, warning, critical), **For (seconds)**, **Notify channels**, **Enabled**.

| Kind               | Fires when                                                                                                  | Params                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `server_offline`   | server offline or stale for at least `forSec`                                                               | `forSec` **≥ 90** (default 90)                      |
| `metric_threshold` | latest **fresh** sample of `cpu`, `memory`, `disk` or `load1` is `gt` / `lt` `value`                        | `metric`, `op`, `value`                             |
| `app_down`         | managed app's current container not running / unhealthy / missing, or last deployment needs manual recovery | —                                                   |
| `log_dropped`      | an agent reported dropped log entries within the window                                                     | `windowSec` (default 300), `minEntries` (default 1) |
| `backup_failed`    | latest finished backup run of a policy failed/expired, or its verification failed                           | target type `backup_policy`                         |

```http
POST /alert-rules
{ "name": "prod offline", "kind": "server_offline", "scopeType": "environment", "scopeId": "production",
  "severity": "critical", "forSec": 120, "channelIds": ["…"], "enabled": true }
```

Rules are evaluated by the Center every 15 s. Stale data never fires a threshold (it fires
`server_offline` instead), and unknown data never fires or resolves an incident. For 90 s after a Center
start, stale servers count as unknown for `server_offline`, so reconnecting agents do not raise false
incidents. `kind` cannot change after creation (PATCH → 422); edits use `If-Match`.

## 3. Work an incident

Incidents open when a rule fires (one per rule and target) and **resolve automatically** when the
condition clears. **Incidents** tab filters by status (Open, Firing, Acknowledged, Resolved, All),
severity and target. The detail shows the timeline (Fired, Notified, Notification failed, Acknowledged,
Resolved, Comment) and links to server monitoring, the application and **Logs around this incident**.

- **Acknowledge** (`POST /incidents/:id/acknowledge { comment? }`): records you as the responder and stops
  repeat notifications. It does not resolve the incident. Only firing incidents can be acknowledged
  (409 `INCIDENT_STATE_INVALID`).
- **Add comment** (`POST /incidents/:id/comment`).
- Disabling, deleting or re-scoping a rule resolves its open incidents (reason `rule_disabled`,
  `rule_deleted`, `rule_scope_changed`); a target leaving scope resolves with `target_out_of_scope`.

## Failure modes

| Symptom                             | Meaning / recovery                                                                                    |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 422 `VALIDATION_FAILED` on `forSec` | `server_offline` needs `forSec >= 90`                                                                 |
| 422 `WEBHOOK_URL_NOT_ALLOWED`       | http in production, a private/loopback/metadata address, or credentials in the URL (`details.reason`) |
| 422 `CHANNEL_NOT_FOUND`             | Rule references a deleted channel                                                                     |
| Timeline **Notification failed**    | Receiver down or rejecting; check the channel's last delivery, fix, **Send test**                     |
| 403 on acknowledge                  | You lack `servers.operate` on the target (audited as denied)                                          |

## Limitations

- No acknowledgement or approval from Telegram, email or webhooks (by design).
- No escalation policies, schedules or silences in this release.
- The rule form still shows older hints: **For (seconds)** says "default 60" and accepts 0–86400, and
  **Backup failed** says "Reserved for P6 — accepted but inactive". The Center enforces `forSec >= 90` for
  `server_offline` (and defaults it to 90), and `backup_failed` rules are active.
