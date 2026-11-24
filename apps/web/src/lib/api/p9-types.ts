/**
 * P9 shapes (docs/P9_NETWORK_CONTRACT.md). Imported from @ppanel/shared-contracts (network.ts, jobs.ts,
 * server.ts); this file only adds web aliases and the few UI constants the contract package lacks.
 */
import type {
  ConnectivityTestStatus,
  GatewayChangePlan,
  GatewayPlanStatus,
  Server,
} from '@ppanel/shared-contracts';

export type {
  ConnectionPath as MgmtPath,
  ConnectionPolicy,
  ConnectivityTestStatus as TestStatus,
  CreateConnectivityTestInput as PairTestInput,
  CreateGatewayInput,
  CreateGatewayRouteInput,
  CreateNetworkDiagnosticsInput as DiagnoseParams,
  CreateProviderIntegrationInput as CreateIntegrationInput,
  CreateServerGroupInput,
  Gateway,
  GatewayBackend as RouteBackend,
  GatewayChangePlan,
  GatewayCutover,
  GatewayPlanStatus as PlanStatus,
  GatewayRoute,
  GatewayRouteMode as RouteMode,
  NetworkConnectivityTest,
  NetworkDiagnoseResult as DiagnoseResult,
  NetworkDiagnosticsCreated as TestAccepted,
  NetworkInventoryEntry as ServerNetworkInventory,
  NetworkInventoryRow as InventoryRowInput,
  NetworkSource as InventorySource,
  NetworkTopology as Topology,
  ProviderIntegration,
  ProviderStatus as IntegrationStatus,
  ServerConnectionView as ServerConnection,
  ServerGroup,
  ServerNetworkView,
  ShadowProbe as ProbeOutcome,
  ShadowResult,
  ShadowTestInput,
  TopologyFindingCode as FindingCode,
  UpdateGatewayRouteInput,
  UpdateServerGroupInput,
} from '@ppanel/shared-contracts';

export {
  CONNECTION_PATHS as MGMT_PATHS,
  DIAGNOSE_DEFAULT_PORTS as DIAG_PORTS,
  GATEWAY_MAX_ROUTES,
  GATEWAY_PLAN_STATUSES as PLAN_STATUSES,
  GATEWAY_ROUTE_MODES as ROUTE_MODES,
  HEALTH_PATH_RE,
  NETWORK_INVENTORY_MAX_ROWS,
  TOPOLOGY_FINDING_CODES as FINDING_CODES,
  dialOrder,
  isDiagnosePrivateAddress,
  networkInventoryRowSchema,
} from '@ppanel/shared-contracts';

/** P9 fields are part of the shared `Server` view; kept as an alias for readability. */
export type ServerView = Server;
export type EndpointProbe = Server['connection']['endpoints'][number] & { url?: string };
export type TopologyFinding =
  import('@ppanel/shared-contracts').NetworkTopology['findings'][number];

export const DIAG_MAX_RESOLVE = 10;
export const DIAG_MAX_TCP = 20;

export const TEST_ACTIVE: readonly ConnectivityTestStatus[] = ['queued', 'running'];

/** Plan statuses during which a job runs on the gateway (the UI polls and disables actions). */
export const PLAN_RUNNING: readonly GatewayPlanStatus[] = [
  'shadow_testing',
  'applying',
  'rolling_back',
];

/** web-only: GET /gateways/:id/plans is assumed (not named in the contract). */
export type GatewayPlanList = GatewayChangePlan[];
