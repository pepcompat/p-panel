/** P9 topology + findings (pure; unit-tested). "Same VPC" is never inferred from ping or region. */
import {
  type NetworkTopology,
  PROVIDER_STALE_AFTER_HOURS,
  type TopologyFindingCode,
} from '@ppanel/shared-contracts';
import { type AddressLike, type InventoryLike, networkView, preferredIpv4 } from './network-common';

export interface TopologyServer {
  id: string;
  name: string;
  addresses: AddressLike[];
  inventory: InventoryLike[];
}

export function computeTopology(servers: TopologyServer[], now = Date.now()): NetworkTopology {
  type Region = NetworkTopology['regions'][number];
  const regions = new Map<string, Region>();
  const regionKey = (r: string | null) => r ?? '\u0000unknown';
  const findings: NetworkTopology['findings'] = [];
  const add = (code: TopologyFindingCode, serverIds: string[], message: string) => {
    if (serverIds.length)
      findings.push({ code, serverIds: [...new Set(serverIds)].sort(), message });
  };
  const unknownVpc: string[] = [];

  for (const s of servers) {
    const v = networkView(s.inventory);
    const key = regionKey(v.region);
    let reg = regions.get(key);
    if (!reg) {
      reg = { region: v.region, vpcs: [], unknownVpc: [] };
      regions.set(key, reg);
    }
    if (!v.vpcUuid || !v.vpcSource) {
      reg.unknownVpc.push(s.id);
      unknownVpc.push(s.id);
      continue;
    }
    let vpc = reg.vpcs.find((x) => x.vpcUuid === v.vpcUuid);
    if (!vpc) {
      vpc = { vpcUuid: v.vpcUuid, vpcName: v.vpcName, source: v.vpcSource, servers: [] };
      reg.vpcs.push(vpc);
    }
    // provider beats inventory as the VPC's source label once any member is provider-backed
    if (v.vpcSource === 'provider') vpc.source = 'provider';
    if (!vpc.vpcName && v.vpcName) vpc.vpcName = v.vpcName;
    vpc.servers.push(s.id);
  }

  add(
    'VPC_UNKNOWN',
    unknownVpc,
    'No provider or inventory data says which VPC these servers are in (agent facts never set a VPC).',
  );
  for (const reg of regions.values()) {
    if (reg.region !== null && reg.vpcs.length > 1)
      add(
        'SAME_REGION_DIFFERENT_VPC',
        reg.vpcs.flatMap((v) => v.servers),
        `Region ${reg.region} has ${reg.vpcs.length} VPCs (${reg.vpcs
          .map((v) => v.vpcName ?? v.vpcUuid)
          .join(', ')}); private traffic does not cross VPCs without peering.`,
      );
  }
  const byIp = new Map<string, string[]>();
  for (const s of servers) {
    const ip = preferredIpv4(s.addresses, s.inventory, 'private');
    if (ip) byIp.set(ip, [...(byIp.get(ip) ?? []), s.id]);
  }
  for (const [ip, ids] of byIp)
    if (ids.length > 1)
      add('PRIVATE_IP_CONFLICT', ids, `Private IPv4 ${ip} is reported for ${ids.length} servers.`);

  const staleCut = now - PROVIDER_STALE_AFTER_HOURS * 3_600_000;
  add(
    'PROVIDER_STALE',
    servers
      .filter((s) =>
        s.inventory.some((r) => r.source === 'provider' && r.observedAt.getTime() < staleCut),
      )
      .map((s) => s.id),
    `Provider data is older than ${PROVIDER_STALE_AFTER_HOURS} h; run a provider sync.`,
  );
  const mismatch: string[] = [];
  for (const s of servers) {
    const p = s.inventory.find((r) => r.source === 'provider');
    const i = s.inventory.find((r) => r.source === 'inventory');
    if (!p || !i) continue;
    const differs = (a: string | null, b: string | null) => a !== null && b !== null && a !== b;
    if (
      differs(p.vpcUuid, i.vpcUuid) ||
      differs(p.region, i.region) ||
      differs(p.privateIpv4, i.privateIpv4) ||
      differs(p.publicIpv4, i.publicIpv4) ||
      differs(p.dropletId, i.dropletId)
    )
      mismatch.push(s.id);
  }
  add(
    'INVENTORY_MISMATCH',
    mismatch,
    'Provider API and user inventory disagree (region, VPC, droplet or address); the provider value is shown.',
  );

  const sorted = [...regions.values()].sort((a, b) =>
    a.region === null ? 1 : b.region === null ? -1 : a.region.localeCompare(b.region),
  );
  for (const r of sorted) r.vpcs.sort((a, b) => a.vpcUuid.localeCompare(b.vpcUuid));
  return { regions: sorted, findings };
}
