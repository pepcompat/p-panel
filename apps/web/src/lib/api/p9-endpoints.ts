/** P9 endpoints (docs/P9_NETWORK_CONTRACT.md). Provider tokens are write-only: never read back. */
import type { ConnectionPolicy } from '@ppanel/shared-contracts';
import { api } from './index';
import type { Query } from './client';
import type {
  CreateGatewayInput,
  CreateGatewayRouteInput,
  CreateIntegrationInput,
  CreateServerGroupInput,
  DiagnoseParams,
  Gateway,
  GatewayChangePlan,
  GatewayRoute,
  InventoryRowInput,
  NetworkConnectivityTest,
  PairTestInput,
  ProviderIntegration,
  ServerGroup,
  ServerNetworkInventory,
  ServerView,
  ShadowTestInput,
  TestAccepted,
  Topology,
  UpdateGatewayRouteInput,
  UpdateServerGroupInput,
} from './p9-types';

const enc = encodeURIComponent;
const stepUp = (token?: string) => (token ? { 'X-Step-Up': token } : undefined);

export const serverNetApi = {
  /** PATCH /servers/:id { connectionPolicy } — production needs X-Step-Up; 422 PRIVATE_PATH_UNVERIFIED. */
  setPolicy: (id: string, policy: ConnectionPolicy, version: number, stepUpToken?: string) =>
    api.patch<ServerView>(
      `/servers/${enc(id)}`,
      { connectionPolicy: policy },
      { headers: { 'If-Match': String(version), ...stepUp(stepUpToken) } },
    ),
  /** PATCH /servers/:id { groupId } — null removes the server from its group (sent explicitly). */
  setGroup: (id: string, groupId: string | null, version: number) =>
    api
      .request<ServerView>('PATCH', `/servers/${enc(id)}`, {
        body: { groupId },
        keepNulls: true,
        headers: { 'If-Match': String(version) },
      })
      .then((r) => r.data),
};

export const groupsApi = {
  list: (query?: Query) =>
    api
      .list<ServerGroup>('/server-groups', { query: { limit: 100, ...query } })
      .then((r) => r.items),
  get: (id: string) => api.get<ServerGroup>(`/server-groups/${enc(id)}`),
  create: (body: CreateServerGroupInput) => api.post<ServerGroup>('/server-groups', body),
  update: (id: string, body: UpdateServerGroupInput) =>
    api
      .request<ServerGroup>('PATCH', `/server-groups/${enc(id)}`, { body, keepNulls: true })
      .then((r) => r.data),
  /** 409 GROUP_NOT_EMPTY unless the group has no servers. */
  remove: (id: string) => api.del(`/server-groups/${enc(id)}`),
};

export const networkApi = {
  topology: () => api.get<Topology>('/network/topology'),
  importInventory: (rows: InventoryRowInput[]) =>
    api.post<
      | { upserted?: number; imported?: number; rows?: ServerNetworkInventory[] }
      | ServerNetworkInventory[]
    >('/network/inventory', { rows }),
  /** 202 { testId, jobId }; 422 NO_PRIVATE_ADDRESS when the target has no known private IPv4. */
  pairTest: (body: PairTestInput) => api.post<TestAccepted>('/network/connectivity-tests', body),
};

export const integrationsApi = {
  list: () =>
    api
      .list<ProviderIntegration>('/provider-integrations', { query: { limit: 100 } })
      .then((r) => r.items),
  /** Step-up required. The token is sent once and never returned. */
  create: (body: CreateIntegrationInput, stepUpToken: string) =>
    api.post<ProviderIntegration>('/provider-integrations', body, {
      headers: stepUp(stepUpToken),
    }),
  remove: (id: string) => api.del(`/provider-integrations/${enc(id)}`),
  /** 202 */
  sync: (id: string) => api.post<unknown>(`/provider-integrations/${enc(id)}/sync`),
};

export const diagnosticsApi = {
  run: (serverId: string, params: DiagnoseParams) =>
    api.post<TestAccepted>(`/servers/${enc(serverId)}/network-diagnostics`, params),
  list: (serverId: string) =>
    api
      .list<NetworkConnectivityTest>(`/servers/${enc(serverId)}/network-diagnostics`, {
        query: { limit: 20 },
      })
      .then((r) => r.items),
  get: (testId: string) => api.get<NetworkConnectivityTest>(`/network-diagnostics/${enc(testId)}`),
};

export const gatewaysApi = {
  list: () => api.list<Gateway>('/gateways', { query: { limit: 100 } }).then((r) => r.items),
  get: (id: string) => api.get<Gateway>(`/gateways/${enc(id)}`),
  create: (body: CreateGatewayInput) => api.post<Gateway>('/gateways', body),
  remove: (id: string) => api.del(`/gateways/${enc(id)}`),
  routes: (id: string) =>
    api
      .list<GatewayRoute>(`/gateways/${enc(id)}/routes`, { query: { limit: 100 } })
      .then((r) => r.items),
  createRoute: (id: string, body: CreateGatewayRouteInput) =>
    api.post<GatewayRoute>(`/gateways/${enc(id)}/routes`, body),
  updateRoute: (
    id: string,
    route: Pick<GatewayRoute, 'id' | 'version'>,
    body: UpdateGatewayRouteInput,
  ) =>
    api.patch<GatewayRoute>(`/gateways/${enc(id)}/routes/${enc(route.id)}`, body, {
      headers: { 'If-Match': String(route.version) },
    }),
  removeRoute: (id: string, routeId: string) =>
    api.del(`/gateways/${enc(id)}/routes/${enc(routeId)}`),
  /** web-assumed list endpoint for a gateway's change plans */
  plans: (id: string) =>
    api
      .list<GatewayChangePlan>(`/gateways/${enc(id)}/plans`, { query: { limit: 50 } })
      .then((r) => r.items),
  createPlan: (id: string) => api.post<GatewayChangePlan>(`/gateways/${enc(id)}/plans`),
};

export const plansApi = {
  get: (id: string) => api.get<GatewayChangePlan>(`/gateway-plans/${enc(id)}`),
  /** 202 */
  shadowTest: (id: string, body: ShadowTestInput = {}) =>
    api.post<GatewayChangePlan>(`/gateway-plans/${enc(id)}/shadow-test`, body),
  /** Same rules as nginx revisions: plan-hash bound, second person, step-up in production. */
  approve: (id: string, planHash: string, stepUpToken: string) =>
    api.post<GatewayChangePlan>(
      `/gateway-plans/${enc(id)}/approve`,
      { planHash },
      { headers: stepUp(stepUpToken) },
    ),
  apply: (id: string, stepUpToken?: string) =>
    api.post<GatewayChangePlan>(`/gateway-plans/${enc(id)}/apply`, undefined, {
      headers: stepUp(stepUpToken),
    }),
  rollback: (id: string, stepUpToken?: string) =>
    api.post<GatewayChangePlan>(`/gateway-plans/${enc(id)}/rollback`, undefined, {
      headers: stepUp(stepUpToken),
    }),
};
