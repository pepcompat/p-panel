# Network, server groups and Gateway routing

Covers P9: server cards and groups, management paths (private/public) and the connection policy, VPC
inventory, network diagnostics, and per-domain Gateway routing with shadow tests. Contract:
[P9_NETWORK_CONTRACT.md](../P9_NETWORK_CONTRACT.md); API details: [API_CONTRACTS.md](../API_CONTRACTS.md) §11;
topology rules: [NETWORK_TOPOLOGY.md](../NETWORK_TOPOLOGY.md).

**Ground rule:** nothing here changes DNS, netplan, routes, public IPs, host firewalls or cloud firewalls.
Diagnostics and probes are read-only; Gateway changes are Nginx revisions on the gateway host only.

## 1. Server cards and groups

- **Servers** shows a card per server: environment, group, public IPv4, private IPv4 (✓ verified),
  connection policy, the active management path and a health dot per path, and region/VPC with its source.
  "VPC unknown" means no provider or inventory record exists yet — pPanel never derives a VPC from agent
  facts, ping or region. Filter by environment, group, tag or policy (`GET /servers?group_id=…&tags[contains]=…`).
- **Servers → Groups** (`/servers/groups`): create, rename, delete (409 `GROUP_NOT_EMPTY` while servers
  remain) and assign servers. Needs `policies.manage`. API: `GET/POST /server-groups`,
  `GET/PATCH/DELETE /server-groups/:id`; assign with `PATCH /servers/:id { groupId }` (`null` removes).

## 2. Management paths and connection policy

The Center can listen on a public and a private management path (`PPANEL_GATEWAY_LISTENERS`,
`PPANEL_PUBLIC_GATEWAY_URL`, `PPANEL_PRIVATE_GATEWAY_URL`; see [INSTALL.md](../INSTALL.md)). Agents learn the
endpoints at enrollment and from every heartbeat, probe each one every 60 s and report the results.

| Policy              | Agent dials          | Notes                                              |
| ------------------- | -------------------- | -------------------------------------------------- |
| `auto`              | private, then public | public only when no private endpoint is advertised |
| `private_preferred` | private, then public | falls back to public when private is down          |
| `private_only`      | private only         | **fails closed**: offline rather than public       |
| `public_preferred`  | public, then private |                                                    |
| `public_only`       | public only          |                                                    |

Change it on **Server → Network → Connection policy** (`PATCH /servers/:id { connectionPolicy }`, `If-Match`;
needs `servers.operate`, step-up in production). Switching to `private_only` is refused with 422
`PRIVATE_PATH_UNVERIFIED` unless the agent reported a healthy private probe in the last 5 minutes. A request
on a path the policy forbids gets 403 `CONNECTION_PATH_NOT_ALLOWED` (audited).

**What you should see when the private path breaks under `private_only`:** the server goes stale, then
offline; workloads keep running; no public connection is attempted. When the path returns the agent
reconnects on its own.

## 3. VPC inventory

- **Network → Providers**: add a DigitalOcean token (read-only scopes are enough; step-up required). The
  token is encrypted and never shown again. **Sync** reads droplets and VPCs (GET only) and matches them to
  servers by droplet id, then private IPv4. API: `POST /provider-integrations`, `POST …/:id/sync`.
- **Network → Inventory**: paste or upload JSON rows `{ serverId | hostname, region, vpcUuid, vpcName,
dropletId, privateIpv4, publicIpv4 }` when no API token is available (`POST /network/inventory { rows }`,
  all-or-nothing).
- **Network → Topology** (`GET /network/topology`): region → VPC → servers, plus findings:
  `VPC_UNKNOWN`, `SAME_REGION_DIFFERENT_VPC`, `PRIVATE_IP_CONFLICT`, `PROVIDER_STALE`, `INVENTORY_MISMATCH`.

## 4. Diagnostics

- **Server → Network → Run diagnostics** (`POST /servers/:id/network-diagnostics`, `servers.operate`):
  interfaces, MTU, routes (read from `/proc`), DNS lookups, TCP checks and the Center endpoint probes. Targets
  are limited to private ranges and the Center's endpoints; ports to a fixed list plus known app ports.
- **Network → Connectivity**: test from one server to another's private IPv4 (`POST /network/connectivity-tests
{ fromServerId, toServerId, port }`). A failure between servers in different VPCs is expected unless
  peering exists; it proves the route, it does not create one.

## 5. Gateway routing

1. **Designate a gateway** (`Network → Gateways`, `POST /gateways { serverId, name }`, `policies.manage`).
   The gateway is an enrolled server running Nginx; its routing config lives on that host, so it keeps
   serving while the Center is down.
2. **Add routes** per domain with a mode:
   - **Direct** — no gateway config; DNS points at the app server.
   - **Hybrid** — the gateway serves the domain while DNS still points direct (for shadow tests and staged moves).
   - **Gateway** — DNS is expected to point at the gateway.
     Backends default to the server's private IPv4; a backend in another VPC is flagged.
3. **Create a plan** (`POST /gateways/:id/plans`). pPanel renders one file per domain under
   `/etc/nginx/ppanel-gateway/` and validates it with `nginx -t` through the normal Nginx revision flow.
4. **Shadow test** (`POST /gateway-plans/:id/shadow-test`). An agent sends real requests with a Host/SNI
   override to the gateway's private address and to the current direct origin, and compares status and body
   hash. No DNS is involved. Before apply the "via gateway" side reflects the config already live; re-run the
   test after apply for a meaningful comparison (stored as `verification`).
5. **Approve** (production gateways): a second person with step-up approves the exact plan hash, which
   covers routes, rendered files and shadow results.
6. **Apply** (`POST /gateway-plans/:id/apply`, step-up in production) — applied as an Nginx revision with
   postchecks and automatic revert. **Roll back** with `POST /gateway-plans/:id/rollback`.
7. **Cut over DNS yourself.** The plan's cutover block lists the records to change, TTL advice, verification
   commands and the rollback steps (point DNS back, the direct origin keeps serving). pPanel never edits DNS.

## Failure modes

| Symptom                                   | Meaning / action                                                                        |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| 422 `PRIVATE_PATH_UNVERIFIED`             | no healthy private probe in 5 min; check the private endpoint and the server's VPC      |
| 403 `CONNECTION_PATH_NOT_ALLOWED` in logs | agent tried a path the policy forbids; expected after a policy change                   |
| `PROVIDER_AUTH_FAILED`                    | token wrong or revoked; add a new integration                                           |
| 422 `NO_PRIVATE_ADDRESS`                  | the gateway or target has no known private IPv4; sync provider data or import inventory |
| shadow `match: false`                     | gateway and origin differ (status or body); fix the route before applying               |
| plan `failed` after apply                 | Nginx postcheck failed and the revision reverted; see the revision output               |

## Limitations

- Lab-verified only (Docker bridges stand in for VPCs, a fake DO API for DigitalOcean). Real VPC UUIDs of
  the production droplets need a read-only DO token or an inventory (BLOCKED until supplied).
- At most 19 routes per gateway (one Nginx revision holds 20 files). Removed domains become comment-only stub files.
- HTTPS termination on the gateway depends on ACME, which is BLOCKED (no public DNS).
- Provider sync state is held in memory and assumes a single Center process.
