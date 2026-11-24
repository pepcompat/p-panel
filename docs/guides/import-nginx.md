# Import existing Nginx

Bring an existing, hand-managed Nginx host under pPanel without changing it, then take ownership one
step at a time. Existing Nginx is the source of truth until you explicitly adopt it
([ADR-0004](../adr/0004-existing-nginx-source-of-truth.md)).

Flow: **read-only scan → import (Discover or Observe) → Adopt → Managed**, with drift detection on every
scan. Verified end to end by `scripts/lab/e2e_p3.py`.

## Prerequisites and permissions

| Step                                 | Permission                              | Built-in roles            |
| ------------------------------------ | --------------------------------------- | ------------------------- |
| Run a discovery scan, read findings  | `nginx.read`                            | all four                  |
| Import findings                      | `servers.operate`                       | Platform Owner, Ops Admin |
| Discovered ↔ Observed, any downgrade | `servers.operate`                       | Platform Owner, Ops Admin |
| → Adopted, → Managed                 | `nginx.write` (+ step-up in production) | Platform Owner, Ops Admin |
| Acknowledge drift                    | `nginx.write`                           | Platform Owner, Ops Admin |

The server must be enrolled and online ([enroll-servers.md](enroll-servers.md)).

## 1. Run a read-only scan

UI: **Discovery & Import** (`/imports`) → **Run read-only scan**, choose the server and sources →
**Start read-only scan**. Also available from **Server → Applications**.

API: `POST /servers/:id/discovery-scans { "sources": ["nginx","docker","systemd","php-fpm","ports"] }`
→ 202 `{ scanId, jobId }`. Poll `GET /discovery-scans/:id`.

What you should see: the scan moves Running → Completed and shows counts (Nginx servers, upstreams,
duplicates, manual review, PHP-FPM pools, listeners, containers) and the config files with SHA-256. The
scan only reads: no file is written, no service reloads, ownership does not change. If the server is not
online the job waits and expires (`Expired`) if the agent does not reconnect in time.

## 2. Review findings

Open the scan (**View results**, `/imports/:scanId`). Tabs: **Findings**, **Config files**, **Drift**.
`GET /discovery-scans/:id/findings?kind=&manual_review=`.

Each finding shows provenance (file, line, included from), listen, domains, confidence and links
(upstream, `fastcgi_pass`, root). **Manual review** flags come with reasons such as unsupported
directives (for example `if`) or a duplicate `server_name`. The scanner never invents runtime, repository
or ownership mappings; unknown links stay empty.

## 3. Import into inventory

Select Nginx server blocks → choose **Import mode** → **Import {n} as Observe** (default) or
**Import {n} as Discover**.

API: `POST /discovery-scans/:id/import { "findingIds": [...], "mode": "observed" }` → 201
`{ applications }`.

- **Discovered**: recorded in inventory only.
- **Observed**: inventory plus health and metrics visibility. No config is written.

Adopted and Managed cannot be set here (422 `IMPORT_MODE_NOT_ALLOWED`). Import is idempotent per finding
fingerprint: re-importing updates the last scan, never ownership. Manual-review reasons stay on the
application.

## 4. Take ownership, one tier at a time

UI: open the application (**Applications** → the app) → **Ownership** card → **Move to {mode} ↑** or
**Back to {mode} ↓**. Enter a **Reason (audited)**. When manual-review reasons exist, tick **I reviewed
these reasons**. Production asks for a 2FA code for Adopt and Managed.

API:

```http
POST /applications/:id/ownership
If-Match: <version>
X-Step-Up: <token>              (production, → adopted / → managed)
{ "toMode": "adopted", "reason": "web team owns shop.example.com", "acknowledgeReasons": true }
```

| Tier       | Effect                                                                                        |
| ---------- | --------------------------------------------------------------------------------------------- |
| Discovered | Recorded in inventory only                                                                    |
| Observed   | Read-only visibility; pPanel never writes config                                              |
| Adopted    | pPanel may propose Nginx revisions; every apply needs validation and approval by another user |
| Managed    | pPanel manages the app's Nginx config end to end with versioned, validated revisions          |

Rules enforced by the Center:

- One step at a time, up or down; skipping → 422 `OWNERSHIP_STEP_INVALID`.
- → Adopted with manual-review or conflict flags requires `acknowledgeReasons: true`, else 422
  `MANUAL_REVIEW_REQUIRED` (`details.reasons`).
- Unsupported directives block → Managed (422 `UNSUPPORTED_CONFIG`). Keep the app Adopted or rewrite those
  directives through a revision first.
- Moving down is always allowed with `servers.operate` and cancels open draft revisions.
- **Ownership changes never touch the host.** History: **Ownership history** tab
  (`GET /applications/:id/ownership-history`).

Next: change config through revisions, see [nginx-changes-and-tls.md](nginx-changes-and-tls.md).

## 5. Drift

Every scan compares each file's SHA-256 with the previous scan and with the checksums pPanel last
applied. A change not explained by a pPanel revision is **drift**: the scan's Drift tab shows it with
**Changed by: External edit**, the application gets the **Drift** flag, and open `draft`, `valid` or
`approved` revisions touching that file become **Drift blocked**.

While drift is flagged, creating or applying revisions returns 409 `DRIFT_REVIEW_REQUIRED`. To clear it:

1. Look at the current files on the host (application **Nginx** tab, **Current files on the host**).
2. **Acknowledge drift…** → **Accept current files as baseline** (`POST /applications/:id/drift/acknowledge`).
   This records the current checksums as the accepted baseline and is audited. Nothing on the host changes.
3. Blocked revisions stay blocked. Create a new revision from the current files.

If a checksum shows **unknown — rescan before acknowledging**, run a new scan first.

## Failure modes

| Symptom                           | Meaning / recovery                                                                                 |
| --------------------------------- | -------------------------------------------------------------------------------------------------- |
| Scan `Failed`, `RESULT_TRUNCATED` | The report was too large or truncated; nothing changed on the host. Narrow the sources and rescan. |
| Scan `Expired`                    | The agent was offline for the job's TTL. Bring the agent back and rescan.                          |
| 403 on import or ownership        | Missing permission or out of scope; audited as denied.                                             |
| 422 `MANUAL_REVIEW_REQUIRED`      | Review the reasons, then retry with `acknowledgeReasons: true`.                                    |
| 409 `VERSION_CONFLICT`            | Someone changed the application. Reload and retry.                                                 |

## Limitations

- Discovery covers Nginx, PHP-FPM pools, listening ports, Docker containers and systemd units. Importing
  creates applications from **Nginx server blocks** only.
- There is no fleet-wide drift view; drift is per scan and per application (the Applications page shows a
  banner when any application has drift).
