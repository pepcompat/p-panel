# Enroll servers

Add a Linux server to the fleet, keep its agent identity healthy, and remove it when needed.

The agent connects **outbound** to the Center: enrollment over HTTPS to the API, then mutual TLS to the
agent gateway (port 4443). Nothing listens on the managed host. Protocol details:
[AGENT_PROTOCOL.md](../AGENT_PROTOCOL.md).

## Prerequisites and permissions

| Task                         | Permission        | Built-in roles            | Extra                                                  |
| ---------------------------- | ----------------- | ------------------------- | ------------------------------------------------------ |
| Create an enrollment token   | `servers.enroll`  | Platform Owner, Ops Admin | —                                                      |
| Edit name, environment, tags | `servers.operate` | Platform Owner, Ops Admin | `If-Match`                                             |
| Designate a build node       | `policies.manage` | Platform Owner, Ops Admin | see [deploy.md](deploy.md#5-git-builds-on-build-nodes) |
| Revoke an agent              | `servers.revoke`  | Platform Owner, Ops Admin | step-up when the server is production                  |
| Create server groups         | `policies.manage` | Platform Owner, Ops Admin | API only                                               |

The host needs root access for the install and outbound reach to the Center API and gateway. The agent
binary, systemd unit and least-privilege notes are in [INSTALL.md](../INSTALL.md) (see the agent install
section).

## 1. Create a one-time enrollment token

UI: **Servers → + Enroll server** (opens the enroll form on the Servers page; the same form is at
`/servers/new`). Fill **Server name** (lowercase letters, digits and
dashes, max 63), **Environment** (Production, UAT or Development), optional **Tags** and **Token
lifetime**, then **Create one-time token**.

API:

```http
POST /enrollments
{ "name": "app-prod-01", "environment": "production", "tags": ["web"], "ttlMinutes": 15 }
```

→ 201 `{ enrollmentId, token, expiresAt, installCommand }`. `ttlMinutes` is 5–60 (default 15).

What you should see: the token and the install command, **shown only once**. The Center stores only a
SHA-256 of the token. `GET /enrollments` lists tokens as `pending`, `used` or `expired`, never the
token itself.

## 2. Install the agent on the host

Run the install as root on the host. See [INSTALL.md](../INSTALL.md) for `install-agent.sh`
(`--center-url`, `--token`, checksum and signature verification, systemd unit). The command the UI shows
is the agent's own enroll step: `sudo ppanel-agent enroll --center <center> --token <token>`.

What you should see in the UI: the server appears as **Enrolling → Online**. A server is `online` while
heartbeats (every 15 s) are fresh, `stale` after 45 s without one and `offline` after 120 s.

Failure modes:

- **401 `ENROLLMENT_TOKEN_INVALID`**: the token is unknown, already used or expired (one message for all
  three, by design). Create a new token. A token can enroll exactly one server, even under concurrent use.
- **Rate limit**: the public enroll endpoint allows 10 requests per minute per IP.
- **426 `AGENT_PROTOCOL_UNSUPPORTED`**: the agent speaks an unknown protocol major. Install a matching
  agent version (see [COMPATIBILITY.md](../COMPATIBILITY.md)).

## 3. Environments, groups and tags

- **Environment** (`production`, `uat`, `development`) is a property of each server. The **Servers**
  page groups cards by environment (Production first) and filters by it. Production drives the approval
  and step-up rules in the other guides. Environment groups are labels for grouping and approval policy,
  **not** a network or firewall trust boundary.
- Change name, environment or tags under **Server → Settings → Identity & labels → Save changes**
  (`PATCH /servers/:id` with `If-Match`; 409 `VERSION_CONFLICT` if someone else saved first).
- **Server groups** are named groups with an optional environment: `GET /server-groups`,
  `POST /server-groups { name, description?, environment? }`, then assign with
  `PATCH /servers/:id { groupId }`.

## 4. Public and private addresses

**Server → Network** shows the addresses the agent detected (public/private, IPv4/IPv6, interface,
source) and the **Preferred management connection** (Auto, Private preferred, Private-only, Public
preferred, Public-only). **Save connection policy** calls `PATCH /servers/:id { connectionPolicy }` with
`If-Match`. Editing this metadata never changes netplan, interfaces, routes or the public IP.

## 5. Certificate renewal

Agent certificates are short-lived (`PPANEL_AGENT_CERT_DAYS`, default 7 days). The heartbeat response
carries `certRenewAfter` (two thirds of the lifetime) and the agent renews by itself through
`POST /agent/v1/certificate/rotate`; the old certificate stays valid until it expires unless revoked.
**Server → Settings → Agent certificate** shows the serial and expiry.

Failure modes:

- **Certificate expired** (for example the host was off longer than the lifetime): the gateway answers
  401 `AGENT_CERT_REVOKED`, the server turns `stale` then `offline`, and workloads keep running. An
  expired certificate cannot be rotated: re-enroll the server with a new token.
- **Gateway TLS certificate**: the Center checks its own gateway certificate every 6 hours and renews it
  below 30 days, without a restart.

## 6. Revoke an agent

UI: **Server → Settings → Revoke agent…**. Type the server name to confirm; production also asks for a
2FA code. API:

```http
POST /servers/:id/revoke
X-Step-Up: <token>        (production only)
```

What you should see: **Agent revoked · recorded in audit**. The certificate is revoked at once, the agent
is rejected on its next call (401 `AGENT_CERT_REVOKED`), outstanding jobs are cancelled and the server
shows **Revoked**. Workloads on the host keep running. To manage the host again, re-enroll it.

To clean up the host itself, remove the agent and its state directory as described in
[INSTALL.md](../INSTALL.md) (`--uninstall`, `--purge`).

## Limitations

- **Rotate certificate…** in Server → Settings is shown but disabled (backend PROPOSED): there is no
  operator-triggered rotation endpoint. Renewal is automatic.
- Server groups have no UI; use the API.
- The connection policy is stored and audited but not yet enforced by the Center (planned for P9).
  Address overrides (`source: override`) have no API yet, and **Run diagnostics** on the Network tab is
  not implemented.
- Real-VM enrollment and network-drop tests are BLOCKED (container lab only, see `docs/TEST_REPORT.md`).
