# P9 contract — private networking, server cards/groups, Gateway

Brief §P9 + §13.1. Every P9 workstream codes against this file; changes go through the lead. All routes under
`/api/v1`, COMPATTANA envelopes, camelCase bodies, snake_case filter fields. **Gate: no production route,
DNS, netplan, firewall or public-IP changes. Lab only.**

## 1. Management paths (P9-03)

- The Center gateway gets **one listener per path**: `PPANEL_GATEWAY_LISTENERS=public=0.0.0.0:4443,private=0.0.0.0:4444`
  (default when unset: one `public` listener on `AGENT_GATEWAY_HOST:AGENT_GATEWAY_PORT`, unchanged behaviour).
  The path of a request is the label of the listener it arrived on — never a client claim.
- Advertised endpoints: `PPANEL_PUBLIC_GATEWAY_URL` (existing) and new `PPANEL_PRIVATE_GATEWAY_URL` (optional).
  Enrollment response adds `gatewayEndpoints: [{ path: 'public'|'private', url }]` (keeps `gatewayUrl`).
- Heartbeat response adds `connection: { policy: ConnectionPolicy, endpoints: [{ path, url }] }`. The agent
  persists it (`<stateDir>/connection.json`, 0600) and keeps using the last one during a Center outage.
- Agent dial order by policy: `private_only` → [private]; `public_only` → [public]; `private_preferred` →
  [private, public]; `public_preferred` → [public, private]; `auto` → [private, public] when a private endpoint
  exists, else [public]. **`private_only` never dials public, even if private is down (fail closed).**
- Agent probes every advertised endpoint (TLS handshake + `/agent/v1/ping`, 5 s timeout) every 60 s and
  reports `connection: { activePath, endpoints: [{ path, url, ok, latencyMs, checkedAt, error? }] }` in the
  heartbeat body. Error strings are short codes (`DIAL_TIMEOUT`, `TLS_FAILED`, `REFUSED`, `DNS_FAILED`).
- Center enforcement: a request on a listener whose path the server's policy does not allow → 403
  `CONNECTION_PATH_NOT_ALLOWED` (audited once per server per 10 min). The agent treats that as "path
  forbidden" and does not retry it until the next policy it receives allows it.
- Changing a server to `private_only` requires a healthy private probe reported within the last 5 min, else
  422 `PRIVATE_PATH_UNVERIFIED`. `PATCH /servers/:id` with a policy change needs `servers.manage` + step-up in
  production.
- Lab: the private endpoint is a TCP forwarder container on the lab "VPC" network that forwards to the
  host's `:4444` listener; cutting a node off that network is how "private offline" is tested.

## 2. Provider inventory (P9-01)

- `ProviderIntegration` (table `provider_integrations`): `id, provider ('digitalocean'), name, token_enc
(AES-256-GCM via PPANEL_MASTER_KEY), api_base (default https://api.digitalocean.com; lab override via
PPANEL_DO_API_BASE allowlist), status ('ok'|'error'|'unverified'), last_sync_at, last_error, created_by`.
  Token never returned. Only `GET` requests are ever sent (client refuses other methods).
  - `POST /provider-integrations` (`settings.manage`, step-up) → validates with `GET /v2/account`.
  - `GET /provider-integrations`, `DELETE /provider-integrations/:id`, `POST /provider-integrations/:id/sync` (202).
  - Sync reads `/v2/droplets` (paginated) and `/v2/vpcs`, matches droplets to servers by droplet id (agent
    metadata) then by private IPv4, and writes `ServerNetworkInventory` rows with `source: 'provider'`.
- `POST /network/inventory` (`servers.manage`): user-provided rows `[{ serverId | hostname, region?, vpcUuid?,
vpcName?, dropletId?, privateIpv4?, publicIpv4? }]`, `source: 'inventory'`. Strict schema, ≤ 500 rows.
- Agent facts add `provider` from the DigitalOcean metadata service (`http://169.254.169.254/metadata/v1.json`,
  no redirects, 2 s timeout, ≤ 64 KiB; URL overridable in agent config for the lab): `name: 'digitalocean',
dropletId, region, interfaces: { private: [ipv4], public: [ipv4] }`. Absent → `provider: null`. The agent
  never assumes a VPC.
- `ServerNetworkInventory` (one row per server per source): `server_id, source ('agent'|'provider'|'inventory'),
region, vpc_uuid, vpc_name, droplet_id, private_ipv4, public_ipv4, observed_at`.
- `GET /network/topology` → `{ regions: [{ region, vpcs: [{ vpcUuid, vpcName, source, servers: [id] }],
unknownVpc: [id] }], findings: [{ code, serverIds, message }] }`. A VPC is **known** only from
  `provider` or `inventory`; `agent` facts alone never set it. Finding codes: `VPC_UNKNOWN`,
  `SAME_REGION_DIFFERENT_VPC`, `PRIVATE_IP_CONFLICT`, `PROVIDER_STALE` (> 24 h), `INVENTORY_MISMATCH`
  (provider vs inventory disagree). "Same VPC" is never inferred from ping or from same region.

## 3. Server cards and groups (P9-02)

- `Server` view adds (additive): `groupName: string | null`, `publicIpv4: string | null`, `privateIpv4:
string | null` (preferred verified address per scope), `connection: { policy, activePath: 'public' |
'private' | null, endpoints: [{ path, ok, latencyMs, checkedAt }] }`, `network: { region, vpcUuid, vpcName,
vpcSource: 'provider'|'inventory'|null }`.
- `GET /servers` filters: `environment`, `group_id`, `tags[contains]`, `connection_policy`, `status`.
- Groups: existing `GET/POST /server-groups`; add `PATCH /server-groups/:id`, `DELETE /server-groups/:id`
  (409 `GROUP_NOT_EMPTY` unless empty), `GET /server-groups/:id`. The three environment groups
  (Production/UAT/Development) are the `environment` field; `ServerGroup` is a free grouping inside them.

## 4. Network diagnostics (P9-04)

- New read-only typed job `network.diagnose` (agent never changes OS config, routes or addresses). Params:
  `{ resolve: string[] (≤ 10 hostnames), tcp: [{ host: IP literal, port }] (≤ 20), includeRoutes: boolean }`.
  Agent validates: `tcp.host` must be an IP literal in RFC 1918 / 100.64/10 / fd00::/8, or an address of an
  advertised Center endpoint; ports from `{22, 80, 443, 4443, 4444, 5432, 6379, 3306}` or an app host port the
  Center lists in `allowedPorts`. Result: `{ interfaces: [{ name, mtu, up, addresses }], routes: [{ dst,
gateway, iface, metric }] (from /proc/net/route, ipv6_route), dns: [{ host, addresses, error? }], tcp: [{
host, port, ok, latencyMs, error? }], centerEndpoints: [...same as heartbeat probe] }`.
- `NetworkConnectivityTest` (table `network_connectivity_tests`): `id, server_id, target_server_id?, kind
('diagnose'|'pair'), params, result, status, job_id, requested_by, created_at, finished_at`.
- `POST /servers/:id/network-diagnostics` (`servers.read` is not enough: `servers.manage`) → 202 `{ testId, jobId }`.
  `POST /network/connectivity-tests { fromServerId, toServerId, port }` → runs `network.diagnose` on `from`
  with `tcp: [{ host: <to's private IPv4>, port }]` (422 `NO_PRIVATE_ADDRESS` if unknown).
  `GET /network-diagnostics/:testId`, `GET /servers/:id/network-diagnostics` (list).

## 5. Gateway routing (P9-05)

- A **Gateway** is an enrolled server designated as a gateway (`Gateway`: `id, server_id, name, status,
created_at`). It runs plain Nginx as a reverse proxy; its config lives on the host, so routing keeps working
  while the Center is down. `POST/GET/DELETE /gateways` (`policies.manage`).
- `GatewayRoute`: `id, gateway_id, domain, mode ('direct'|'hybrid'|'gateway'), backends: [{ serverId, address
(private IPv4 preferred), port }], health_path, created_at, updated_at`. `direct` = no gateway config (DNS
  points at the app server); `hybrid` = the gateway serves the domain while DNS still points direct (used
  for shadow tests and staged moves); `gateway` = DNS is expected to point at the gateway.
  `GET/POST/PATCH/DELETE /gateways/:id/routes`.
- `GatewayChangePlan`: `id, gateway_id, routes_snapshot, rendered (files), plan_hash, nginx_revision_id,
status ('draft'|'validated'|'shadow_tested'|'awaiting_approval'|'applied'|'failed'|'rolled_back'),
shadow_results, created_by, approved_by`. Flow:
  1. `POST /gateways/:id/plans` renders the routes into managed files under
     `/etc/nginx/ppanel-gateway/` (one `<domain>.conf` each, upstream by private address) and creates an
     **Nginx revision** on the gateway server through the existing P3 revision service (validate with
     `nginx -t`, apply with postchecks, automatic revert, drift). No new file-writing job type.
  2. `POST /gateway-plans/:id/shadow-test` → typed read-only job `http.probe` on a chosen probe server
     (default: the gateway itself) with `{ url: 'http://<domain><path>', resolveTo: '<gateway address>',
expectStatus }` — Host/SNI override, no DNS change. Probes are limited to the plan's domains and the
     gateway's known addresses. The plan also probes the current direct origin and compares status and
     body hash → `shadowResults: [{ domain, viaGateway: { status, latencyMs, bodySha256 }, direct: {...},
match }]`.
  3. Approval: production gateways need a second person with step-up (same rules as nginx revisions);
     `plan_hash` binds routes + rendered files + shadow results.
  4. `POST /gateway-plans/:id/apply` applies the nginx revision; `POST /gateway-plans/:id/rollback` reverts it.
- Every plan response carries a `cutover` block: DNS records to change by hand, TTL advice, verification
  commands, and the rollback steps (revert DNS, keep direct origin serving). **pPanel never edits DNS.**
- New job types (agent allowlist): `network.diagnose` (read-only), `http.probe` (read-only; GET/HEAD only,
  ≤ 1 MiB body read, 10 s, no redirects followed, target host must equal the override address).

## 6. Lab topology (P9-T1..T4)

- Docker networks `ppanel-lab-vpc-a` and `ppanel-lab-vpc-b` (same "region" `lab1`). node-a + gateway on
  vpc-a, node-b on vpc-b; a forwarder `lab-center-private` on both VPC networks → host `:4444`.
- `lab-do-fake`: fake DigitalOcean API (`/v2/account`, `/v2/droplets`, `/v2/vpcs`, bearer token check) and
  per-node metadata (`/metadata/<node>/v1.json`), reflecting the lab truth (two VPCs, same region).
- New profile `p9` in `infra/compose/lab.yml`; `scripts/lab/up.sh` must keep working unchanged. Never
  recreate lab-node-b with a plain `compose up` (lab-dind netns gotcha) — attach networks with
  `docker network connect` instead where possible.
- `scripts/lab/e2e_p9.py`: P9-T1 (provider sync detects same region / different VPC; topology finding;
  route verified by a pair connectivity test that fails across VPCs and passes within one), P9-T2 (node on
  `private_only`, cut off the private network → never connects over public, Center 403 on public path,
  reconnects when restored), P9-T3 (Center stopped → gateway still serves the hybrid route; routes unchanged),
  P9-T4 (plan → validate → shadow test via Host/SNI override → approve → apply → rollback; documented
  cutover/rollback). Evidence `docs/evidence/<date>/p9-*.json`.

## 7. Ownership

| Workstream  | Owns                                                                                                                                |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Agent + lab | `apps/agent/**`, `infra/lab/**`, `infra/compose/lab.yml`, `scripts/lab/e2e_p9.py`, `docs/AGENT_PROTOCOL.md` (P9 section)            |
| API         | `apps/api/**`, `packages/shared-contracts/**`, `docs/API_CONTRACTS.md` (P9 section)                                                 |
| Web         | `apps/web/**` (Network page, Gateway pages, groups, server card fields, mocks)                                                      |
| Lead        | this file, `docs/IMPLEMENTATION_STATUS.md`, `docs/TEST_REPORT.md`, `docs/guides/network-and-gateway.md`, `docs/NETWORK_TOPOLOGY.md` |
