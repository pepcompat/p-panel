# Auto-deploy from GitHub

Deploy a container application automatically when a matching branch is pushed, through a GitHub
**repository webhook**. Each push resolves to exactly one deployment pinned to a digest and a commit.
Verified by `scripts/lab/e2e_p4.py` (image mode) and `scripts/lab/e2e_p4b.py` (build mode); the
coalescing behaviour by `apps/api/test/integration/deployments.spec.ts`.

## Prerequisites and permissions

| Task                                    | Permission                        | Built-in roles            |
| --------------------------------------- | --------------------------------- | ------------------------- |
| Create a webhook integration            | `policies.manage`                 | Platform Owner, Ops Admin |
| Create or enable an auto-deploy policy  | `apps.deploy` + `policies.manage` | Platform Owner, Ops Admin |
| Edit or delete a policy, see deliveries | `apps.deploy`                     | + Deployer                |
| List an app's policies                  | `apps.read`                       | all four                  |

The application must be a managed **container** app that already deploys manually
([deploy.md](deploy.md)). For image mode, CI must push images whose tag contains the commit SHA, to a
registry on the Center's allowlist (`PPANEL_REGISTRY_ALLOWLIST`), with the app's registry credential set
if the registry is private. For build mode, the app needs a build config and a build node.

## 1. Create a webhook integration

UI: **Settings → Integrations** (`/settings/integrations`) → **Add webhook integration**: **Name** and
**Webhook secret** (at least 16 characters) → **Create integration**.

API: `POST /integrations/github { "name": "shop", "webhookSecret": "…" }` → `{ id, webhookUrl }`.

Then in GitHub → repository → Settings → Webhooks: payload URL = the shown **Payload URL**
(`https://<center>/api/v1/webhooks/github/<id>`), content type `application/json`, the same secret,
event **push**. The secret is stored encrypted and never shown again.

## 2. Add an auto-deploy policy

UI: application → **Settings** → **Auto-deploy policies** → **Add policy**: **Integration**,
**Repository** (`org/name`), **Branches** (comma-separated; exact names or globs like `release/*`),
**Mode**, **Image template** (image mode), **Enabled** → **Save policy**.

```http
POST /applications/:id/auto-deploy
{ "integrationId": "…", "repo": "org/shop-api", "branches": ["main", "release/*"],
  "mode": "image", "imageTemplate": "registry.example.com/org/shop-api:sha-{sha7}", "enabled": true }
```

- **Image mode** (default): on a push pPanel renders the template with `{sha}` (40 hex) or `{sha7}`,
  resolves the tag to a digest with the registry API, and creates a deployment `trigger: webhook` pinned
  to that digest with `sourceRef.commitSha` = the pushed commit. The template host must be allowlisted
  (422 `REGISTRY_NOT_ALLOWED`).
- **Build mode**: pPanel builds the pushed commit on the build node (one build per commit per app), then
  deploys the produced digest. Needs a build config (409 `BUILD_CONFIG_MISSING`).
- **Production**: webhook deployments always wait for approval; they are never applied automatically.

Edit, enable/disable or delete with `PATCH` / `DELETE /applications/:id/auto-deploy/:policyId`.

## 3. What happens on a push

Every delivery is verified (`X-Hub-Signature-256`, HMAC-SHA256, constant time) and de-duplicated by
`X-GitHub-Delivery`. Only `push` events act; others are recorded and ignored. History:
**Settings → Integrations → Delivery history** (`GET /integrations/github/:id/deliveries`).

| Delivery result                 | Meaning                                                                                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `deployed`                      | A deployment was created for this commit                                                                                                 |
| `awaiting_approval`             | Production: deployment created, waiting in **Approvals**                                                                                 |
| `building`                      | Build mode: build started; becomes `deployed` / `awaiting_approval` when its deployment is created                                       |
| `queued`                        | Another deployment of the app is running; this commit is the app's single pending commit and deploys when it ends                        |
| `superseded`                    | Was queued, replaced by a newer push (reason `superseded_by:<deliveryId>`)                                                               |
| `ignored`                       | Reasons such as `branch_not_allowed`, `no_matching_policy`, `already_deployed`, `already_queued`, `already_built`, `event_not_supported` |
| `failed`                        | Deployment could not be created (for example `preflight_failed:<CODE>`, image resolve failure)                                           |
| 401 `WEBHOOK_SIGNATURE_INVALID` | Bad signature: audited, not stored                                                                                                       |
| 200 `{ duplicate: true }`       | Same `X-GitHub-Delivery` seen before: no effect                                                                                          |

### Coalescing: latest wins

When pushes arrive while a deployment of the same app is running (image mode), pPanel keeps **one**
pending commit per app. A newer push replaces the pending one (the older delivery becomes `superseded`).
When the running deployment ends, the pending commit deploys automatically and its delivery turns
`deployed`, `awaiting_approval` or `failed` with reason `dequeued`. Duplicates of a commit that is running,
deployed or queued are `ignored` (`already_deployed` / `already_queued`). Result: at most one deployment
per commit, and the newest commit is eventually deployed. (This is the fix for P7 finding F-7, where a
webhook storm previously lost every commit but the first.)

## Failure modes and recovery

- **No deployment after a push**: check the delivery row. `branch_not_allowed` / `no_matching_policy` →
  fix the policy branches or repository name. `failed` with `preflight_failed:SECRETS_MISSING` or another
  preflight code → fix it (see [deploy.md](deploy.md#preflight-checks)) and push again or deploy manually.
- **Image not found**: the tag rendered from the template does not exist yet (CI not finished) → the
  delivery fails; GitHub does not redeliver a 200. Push again or deploy the digest manually.
- **Signature invalid**: the secret in GitHub differs from the integration's secret. Create a new
  integration if the secret is lost (it is never shown again).

## Limitations

- **GitHub App** installation flow is **BLOCKED** (no App credentials in this installation;
  `GET /integrations/github/app` → `{ available: false, reason }`). Repository webhooks work with any
  GitHub repository.
- Coalescing applies to image mode. Build mode deduplicates per commit; if a deployment is still running
  when a build finishes, the build records a `deployError` instead of queuing.
- The Delivery history badge knows only deployed / awaiting approval / ignored / duplicate / invalid
  signature / failed. `queued`, `superseded` and `building` deliveries are currently shown as **ignored**
  with their reason text (for example `(queued_behind_deployment)`); `GET /integrations/github/:id/deliveries`
  returns the real `result`.
- No auto-deploy for Compose apps; no test stage in the pipeline.
