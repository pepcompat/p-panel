# Nginx changes and TLS

Change the Nginx config of an adopted or managed application through a reviewed revision:
**draft → `nginx -t` validation → approval (when required) → atomic apply + reload → postchecks →
automatic revert on any failure**. Verified end to end by `scripts/lab/e2e_p3.py`; the failsafe cases
(postcheck failure, bind failure, reload failure, tested revert, agent killed mid-apply) by
`scripts/chaos/nginx_failsafe.py` (P7-T04, [RESILIENCE_REPORT.md](../RESILIENCE_REPORT.md)).

## Prerequisites and permissions

| Step                                | Permission         | Built-in roles            | Extra                              |
| ----------------------------------- | ------------------ | ------------------------- | ---------------------------------- |
| Read current files, list revisions  | `nginx.read`       | all four                  | —                                  |
| Create, validate, cancel a revision | `nginx.write`      | Platform Owner, Ops Admin | app must be Adopted or Managed     |
| Approve                             | `approvals.decide` | Platform Owner, Ops Admin | step-up always; approver ≠ creator |
| Apply, revert                       | `nginx.write`      | Platform Owner, Ops Admin | step-up in production              |

Approval is required when the environment is **production** or the application is **Adopted** (not yet
Managed). Otherwise `approval.required = false`. Set up TOTP first (**Settings → Security**): approvals and
production actions need a fresh 2FA code.

## 1. Read the current files

Application → **Nginx** tab → **Current files on the host** (read via `nginx.read_files`).
`GET /applications/:id/nginx/files` waits up to 20 s; a 202 `{ jobId, status: "pending" }` means poll with
`?jobId=`. Symlinked files are edited through their real path. Files that were not returned in full are
marked **truncated** and cannot be edited here.

## 2. Create a revision draft

Edit a file in **New revision draft**, review the **Diff preview**, optionally add **Postchecks** (Host
header, path, scheme, expected status), then **Create revision draft**. A draft writes nothing to the host.

```http
POST /applications/:id/nginx/revisions
{ "files": [{ "path": "/etc/nginx/sites-available/shop.conf", "content": "…" }],
  "postchecks": [{ "hostHeader": "shop.example.com", "path": "/", "scheme": "http", "expectStatus": [200] }] }
```

Paths must be among the application's Nginx files, or new files under
`/etc/nginx/ppanel-managed/<applicationName>/`. Only one open revision per application
(409 `REVISION_IN_PROGRESS`).

## 3. Validate

**Validate (nginx -t)** → `POST /nginx-revisions/:id/validate` (202). The agent backs up the originals,
writes the candidate atomically, runs `nginx -t`, then **always restores the originals**. Nginx is never
reloaded by validation.

What you should see: **Valid** (or **Awaiting approval** if approval is required), or **nginx -t failed**
with the test output. An invalid revision cannot be applied: fix the draft and create a new revision.

## 4. Approve (second person, step-up)

Another user opens the same revision → **Approve plan {hash}** and enters a 2FA code.

```http
POST /auth/step-up        { "code": "123456" }        → { stepUpToken }
POST /nginx-revisions/:id/approve
X-Step-Up: <stepUpToken>
{ "planHash": "<current planHash>" }
```

Rules: approver ≠ creator (`APPROVER_IS_CREATOR`), planHash must match (`PLAN_HASH_MISMATCH`), single use,
expires 60 minutes after approval (`APPROVAL_EXPIRED`). A second approval of the same unexpired plan →
409 `APPROVAL_ALREADY_EXISTS`. Nginx revision approvals are made from the application's Nginx tab; the
**Approvals** page does not list them.

## 5. Apply

**Apply + reload** → confirm. `POST /nginx-revisions/:id/apply` (production: `X-Step-Up`) → 202.

The agent re-checks every file's checksum, backs up the originals, writes atomically, runs `nginx -t`,
reloads (`systemctl reload nginx`, or `nginx -s reload` without systemd), waits 2 s and runs the
postchecks against `127.0.0.1` with your Host headers.

What you should see: **Applied: files written atomically, Nginx reloaded and postchecks passed.** The
application's last-known checksums are updated, so the next scan does not report pPanel's own change as
drift.

## 6. Revert

On an applied revision: **Revert** → `POST /nginx-revisions/:id/revert` (production: `X-Step-Up`). The
agent checks that the files still match what was applied, restores the backup taken at apply time, runs
`nginx -t` and reloads. Status → **Reverted**. Blocked with `DRIFT_DETECTED` if the files changed since,
and `BACKUP_NOT_FOUND` if the backup is gone (backups of the last 20 revisions are kept on the host).

## Failsafe: what happens when something fails

| Result                                                                                                 | Host state                                                               | What to do                                                                          |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `NGINX_TEST_FAILED`                                                                                    | Originals restored, no reload                                            | Fix the draft, new revision                                                         |
| `RELOAD_FAILED_REVERTED`                                                                               | Originals restored + reloaded                                            | Check the reload error (for example a port in use)                                  |
| `POSTCHECK_FAILED_REVERTED`                                                                            | Originals restored + reloaded; per-probe results in the job              | Fix the config or the postcheck                                                     |
| `DRIFT_DETECTED` → **Drift blocked**                                                                   | Nothing written                                                          | Acknowledge drift, new revision ([import-nginx.md](import-nginx.md#5-drift))        |
| `PATH_NOT_ALLOWED`                                                                                     | Nothing written                                                          | Use an allowed path (no symlinks, under `/etc/nginx/`)                              |
| Apply never ran (`TTL_EXPIRED`, `REJECTED_EXPIRED`, `AGENT_STATE_WRITE_FAILED`) or `AGENT_INTERRUPTED` | Not applied (an interrupted job was rolled back by the agent at restart) | Revision returns to **Awaiting approval** (approve again) or **Valid**; apply again |
| **Manual recovery required** (`REVERT_FAILED_MANUAL_RECOVERY`)                                         | Automatic restore or reload failed                                       | See [emergency-recovery.md](emergency-recovery.md#nginx-manual-recovery)            |

If the agent process dies mid-apply, it finds its in-flight journal at the next start, restores the backup
and reloads before accepting new jobs, as long as every file is still the original or the candidate.

## TLS

- **Legacy Nginx sites** keep their own TLS directives. You can change `ssl_certificate` lines like any
  other config through a revision, and postchecks support `scheme: "https"` (loopback, certificate not
  verified, SNI = Host header).
- **Managed container routes** support **HTTP only** or **Existing certificate on the server**
  (`tls: { certPath, keyPath }` under `/etc/ssl/` or `/etc/letsencrypt/live/`, checked by `nginx -t`).
- **Let’s Encrypt (ACME)** is **BLOCKED**: the deploy wizard shows it disabled with "Issuance needs public
  DNS pointing at the server, which this lab does not have." The API contract states "ACME issuance is
  BLOCKED (needs public DNS)". pPanel does not issue or renew certificates.

## Limitations

- No TLS status or certificate-expiry view for Nginx sites (feature F-NGX-01 is PROPOSED); check expiry on
  the host or with your own monitoring.
- ACME / HTTPS issuance: BLOCKED (see above).
- No fleet-wide revision list; approvals for revisions are made per application.
- Discovered and Observed applications are read-only: adopt them first.
