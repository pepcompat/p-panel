/** P9 shared helpers: agent provider facts, per-source network inventory, preferred addresses. */
import type {
  AgentProviderFacts,
  ConnectionPath,
  ConnectionPolicy,
  NetworkSource,
  ServerConnectionView,
  ServerNetworkView,
} from '@ppanel/shared-contracts';
import { Prisma } from '@prisma/client';
import { uuidv7 } from '../common/ids';

/** `servers.provider` JSON (the Server view keeps `{ name, region, dropletId, vpcUuid }`). */
export function agentProviderJson(
  p: AgentProviderFacts | null,
): Prisma.InputJsonValue | typeof Prisma.DbNull {
  if (!p) return Prisma.DbNull;
  return {
    name: p.name,
    region: p.region ?? null,
    dropletId: p.dropletId,
    // the agent never knows the VPC (only the provider API / inventory may set it)
    vpcUuid: null,
    interfaces: { private: p.interfaces.private, public: p.interfaces.public },
  };
}

/** One `agent` inventory row per server mirrors the latest provider facts (null → row removed). */
export async function upsertAgentInventory(
  tx: Prisma.TransactionClient,
  serverId: string,
  p: AgentProviderFacts | null,
  now: Date,
): Promise<void> {
  if (!p) {
    await tx.serverNetworkInventory.deleteMany({ where: { serverId, source: 'agent' } });
    return;
  }
  const data = {
    region: p.region ?? null,
    vpcUuid: null,
    vpcName: null,
    dropletId: p.dropletId,
    privateIpv4: p.interfaces.private[0] ?? null,
    publicIpv4: p.interfaces.public[0] ?? null,
    observedAt: now,
  };
  await tx.serverNetworkInventory.upsert({
    where: { serverId_source: { serverId, source: 'agent' } },
    create: { id: uuidv7(), serverId, source: 'agent', ...data },
    update: data,
  });
}

export interface InventoryLike {
  source: string;
  region: string | null;
  vpcUuid: string | null;
  vpcName: string | null;
  dropletId: string | null;
  privateIpv4: string | null;
  publicIpv4: string | null;
  observedAt: Date;
}
export interface AddressLike {
  family: string;
  scope: string;
  address: string;
  source: string;
}

const bySource = (inv: InventoryLike[], source: NetworkSource) =>
  inv.find((r) => r.source === source);

/**
 * Preferred verified IPv4 per scope: provider API → user inventory → operator override →
 * agent-detected address → agent provider facts.
 */
export function preferredIpv4(
  addresses: AddressLike[],
  inventory: InventoryLike[],
  scope: 'public' | 'private',
): string | null {
  const key = scope === 'private' ? 'privateIpv4' : 'publicIpv4';
  for (const src of ['provider', 'inventory'] as const) {
    const v = bySource(inventory, src)?.[key];
    if (v) return v;
  }
  for (const src of ['override', 'detected']) {
    const a = addresses.find((x) => x.family === 'ipv4' && x.scope === scope && x.source === src);
    if (a) return a.address;
  }
  return bySource(inventory, 'agent')?.[key] ?? null;
}

/** Every IPv4 the Center knows for a server (addresses + inventory rows of all sources). */
export function knownIpv4s(addresses: AddressLike[], inventory: InventoryLike[]): Set<string> {
  const out = new Set<string>();
  for (const a of addresses) if (a.family === 'ipv4') out.add(a.address);
  for (const r of inventory) {
    if (r.privateIpv4) out.add(r.privateIpv4);
    if (r.publicIpv4) out.add(r.publicIpv4);
  }
  return out;
}

/** Region from any source (provider → inventory → agent); VPC only from provider or inventory. */
export function networkView(inventory: InventoryLike[]): ServerNetworkView {
  const provider = bySource(inventory, 'provider');
  const inv = bySource(inventory, 'inventory');
  const agent = bySource(inventory, 'agent');
  const vpcRow = provider?.vpcUuid ? provider : inv?.vpcUuid ? inv : null;
  return {
    region: provider?.region ?? inv?.region ?? agent?.region ?? null,
    vpcUuid: vpcRow?.vpcUuid ?? null,
    vpcName: vpcRow?.vpcName ?? null,
    vpcSource: vpcRow ? (vpcRow.source as 'provider' | 'inventory') : null,
  };
}

export interface StoredEndpoint {
  path: ConnectionPath;
  url: string;
  ok: boolean;
  latencyMs: number | null;
  checkedAt: string;
  error?: string;
}

export function storedEndpoints(v: unknown): StoredEndpoint[] {
  return Array.isArray(v) ? (v as StoredEndpoint[]) : [];
}

export function connectionView(
  policy: string,
  row: { activePath: string | null; endpoints: unknown; reportedAt: Date } | null,
): ServerConnectionView {
  return {
    policy: policy as ConnectionPolicy,
    activePath: (row?.activePath as ConnectionPath | null) ?? null,
    endpoints: storedEndpoints(row?.endpoints).map((e) => ({
      path: e.path,
      ok: e.ok,
      latencyMs: e.latencyMs ?? null,
      checkedAt: e.checkedAt,
      ...(e.error ? { error: e.error } : {}),
    })),
    reportedAt: row?.reportedAt.toISOString() ?? null,
  };
}

/** Private probes count as healthy for `private_only` when reported (Center clock) ≤ 5 min ago. */
export const PRIVATE_PROBE_MAX_AGE_MS = 5 * 60_000;

export function hasHealthyPrivateProbe(
  row: { endpoints: unknown; reportedAt: Date } | null,
  now = Date.now(),
): boolean {
  if (!row || now - row.reportedAt.getTime() > PRIVATE_PROBE_MAX_AGE_MS) return false;
  return storedEndpoints(row.endpoints).some((e) => {
    if (e.path !== 'private' || !e.ok) return false;
    const checked = Date.parse(e.checkedAt);
    // agent clock: the probe must not predate the report by more than the window
    return (
      Number.isFinite(checked) && row.reportedAt.getTime() - checked <= PRIVATE_PROBE_MAX_AGE_MS
    );
  });
}
