/**
 * Mock-mode seed data. Server fleet mirrors the design prototype (design/W3 Server Panel.dc.html,
 * SERVERS + NET tables) re-shaped into the shared-contracts `Server` read model.
 * Dev accounts follow the COMPATTANA seeder convention: dev / superadmin / admin / user1, password "password".
 */
import type {
  ConnectionPolicy,
  Environment,
  RoleBinding,
  RoleKey,
  Server,
  ServerStatus,
} from '@ppanel/shared-contracts';
import type { AuditEvent } from '@/lib/api/types';

export interface MockUser {
  id: string;
  email: string;
  username: string;
  displayName: string;
  password: string;
  mfaEnabled: boolean;
  createdAt: string;
  lastLoginAt: string | null;
  bindings: RoleBinding[];
}

const id = (n: number) => `01934f2a-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ago = (sec: number) => new Date(Date.now() - sec * 1000).toISOString();

function user(
  n: number,
  username: string,
  displayName: string,
  role: RoleKey,
  mfa: boolean,
): MockUser {
  const uid = id(100 + n);
  return {
    id: uid,
    email: `${username}@ppanel.local`,
    username,
    displayName,
    password: 'password',
    mfaEnabled: mfa,
    createdAt: ago(86400 * (30 - n)),
    lastLoginAt: ago(3600 * n),
    bindings: [{ id: id(200 + n), userId: uid, roleKey: role, scopeType: 'global' }],
  };
}

export function seedUsers(): MockUser[] {
  const users = [
    user(1, 'superadmin', 'Super Admin', 'platform_owner', true),
    user(2, 'admin', 'Ops Admin', 'ops_admin', false),
    user(3, 'dev', 'Dev Deployer', 'deployer', false),
    user(4, 'user1', 'Viewer One', 'viewer', false),
  ];
  // admin is scoped to production + uat only to exercise scoped bindings in the UI
  users[1]!.bindings = [
    {
      id: id(211),
      userId: users[1]!.id,
      roleKey: 'ops_admin',
      scopeType: 'environment',
      scopeId: 'production',
    },
    {
      id: id(212),
      userId: users[1]!.id,
      roleKey: 'ops_admin',
      scopeType: 'environment',
      scopeId: 'uat',
    },
    { id: id(213), userId: users[1]!.id, roleKey: 'viewer', scopeType: 'global' },
  ];
  return users;
}

interface ServerSeed {
  name: string;
  env: Environment;
  os: [string, string];
  tags: string[];
  status: ServerStatus;
  hbAgo: number;
  agent: string;
  caps: string[];
  metrics: [number, number, number] | null;
  pub: string | null;
  pub6: string | null;
  priv: string;
  privVerified: boolean;
  policy: ConnectionPolicy;
  droplet: string;
  vpc: string;
}

const VPC = {
  prod: '5f1c2a9e-7b3d-4c11-9a0e-2d6b8f3e1c40',
  legacy: 'a07e44d1-90c2-4f6b-8e15-77c3d2b0f9aa',
  uat: 'c3d90b12-5e7a-4a0f-b6d1-0e4f8a2c7b55',
  dev: '9e7a6b54-1c2d-4e3f-8a9b-0c1d2e3f4a5b',
};

const SEEDS: ServerSeed[] = [
  {
    name: 'app-prod-01',
    env: 'production',
    os: ['ubuntu', '24.04'],
    tags: ['web'],
    status: 'online',
    hbAgo: 3,
    agent: '0.4.2',
    caps: ['docker', 'nginx', 'systemd'],
    metrics: [38, 61, 72],
    pub: '159.89.201.14',
    pub6: '2400:6180:0:d0::1a2:3001',
    priv: '10.104.0.11',
    privVerified: true,
    policy: 'private_preferred',
    droplet: '412883101',
    vpc: VPC.prod,
  },
  {
    name: 'app-prod-02',
    env: 'production',
    os: ['ubuntu', '24.04'],
    tags: ['web'],
    status: 'online',
    hbAgo: 5,
    agent: '0.4.2',
    caps: ['docker', 'nginx', 'systemd'],
    metrics: [22, 48, 41],
    pub: '159.89.201.37',
    pub6: '2400:6180:0:d0::1a2:3002',
    priv: '10.104.0.12',
    privVerified: true,
    policy: 'private_preferred',
    droplet: '412883117',
    vpc: VPC.prod,
  },
  {
    name: 'web-legacy-02',
    env: 'production',
    os: ['ubuntu', '22.04'],
    tags: ['legacy'],
    status: 'degraded',
    hbAgo: 4,
    agent: '0.4.2',
    caps: ['nginx', 'php-fpm', 'systemd'],
    metrics: [71, 83, 91],
    pub: '128.199.77.90',
    pub6: null,
    priv: '10.130.0.20',
    privVerified: false,
    policy: 'auto',
    droplet: '318004422',
    vpc: VPC.legacy,
  },
  {
    name: 'db-prod-01',
    env: 'production',
    os: ['debian', '12'],
    tags: ['db'],
    status: 'stale',
    hbAgo: 360,
    agent: '0.4.1',
    caps: ['systemd'],
    metrics: [17, 52, 58],
    pub: null,
    pub6: null,
    priv: '10.104.0.30',
    privVerified: true,
    policy: 'private_only',
    droplet: '412883150',
    vpc: VPC.prod,
  },
  {
    name: 'worker-uat-01',
    env: 'uat',
    os: ['ubuntu', '24.04'],
    tags: ['worker'],
    status: 'offline',
    hbAgo: 1080,
    agent: '0.4.0',
    caps: ['docker', 'systemd'],
    metrics: null,
    pub: '167.71.12.5',
    pub6: null,
    priv: '10.110.0.8',
    privVerified: true,
    policy: 'private_only',
    droplet: '420115032',
    vpc: VPC.uat,
  },
  {
    name: 'app-uat-01',
    env: 'uat',
    os: ['ubuntu', '24.04'],
    tags: ['web'],
    status: 'online',
    hbAgo: 2,
    agent: '0.4.2',
    caps: ['docker', 'nginx', 'systemd'],
    metrics: [12, 34, 29],
    pub: '167.71.12.9',
    pub6: null,
    priv: '10.110.0.5',
    privVerified: true,
    policy: 'private_preferred',
    droplet: '420115019',
    vpc: VPC.uat,
  },
  {
    name: 'dev-01',
    env: 'development',
    os: ['ubuntu', '24.04'],
    tags: ['web'],
    status: 'online',
    hbAgo: 4,
    agent: '0.4.3-rc1',
    caps: ['docker', 'nginx', 'systemd'],
    metrics: [9, 27, 44],
    pub: '178.128.40.2',
    pub6: null,
    priv: '10.120.0.3',
    privVerified: true,
    policy: 'public_preferred',
    droplet: '431002201',
    vpc: VPC.dev,
  },
  {
    name: 'dev-sandbox-02',
    env: 'development',
    os: ['debian', '12'],
    tags: ['sandbox'],
    status: 'online',
    hbAgo: 3,
    agent: '0.4.3-rc1',
    caps: ['docker', 'systemd'],
    metrics: [4, 18, 22],
    pub: '178.128.40.7',
    pub6: null,
    priv: '10.120.0.4',
    privVerified: true,
    policy: 'auto',
    droplet: '431002255',
    vpc: VPC.dev,
  },
];

export function seedServers(): Server[] {
  return SEEDS.map((s, i) => {
    const stale = s.status === 'stale' || s.status === 'offline';
    const addresses: Server['addresses'] = [];
    if (s.pub)
      addresses.push({
        family: 'ipv4',
        scope: 'public',
        address: s.pub,
        interface: 'eth0',
        source: 'detected',
        verifiedAt: ago(120),
      });
    if (s.pub6)
      addresses.push({
        family: 'ipv6',
        scope: 'public',
        address: s.pub6,
        interface: 'eth0',
        source: 'detected',
        verifiedAt: ago(120),
      });
    addresses.push({
      family: 'ipv4',
      scope: 'private',
      address: s.priv,
      interface: 'eth1',
      source: 'detected',
      verifiedAt: s.privVerified ? ago(300) : null,
    });
    return {
      id: id(i + 1),
      name: s.name,
      hostname: s.name,
      environment: s.env,
      groupId: null,
      tags: s.tags,
      status: s.status,
      lastHeartbeatAt: ago(s.hbAgo),
      agentVersion: s.agent,
      os: {
        id: s.os[0],
        version: s.os[1],
        arch: 'amd64',
        kernel: s.os[0] === 'ubuntu' ? '6.8.0-48-generic' : '6.1.0-26-amd64',
      },
      provider: { name: 'digitalocean', region: 'sgp1', dropletId: s.droplet, vpcUuid: s.vpc },
      addresses,
      connectionPolicy: s.policy,
      metrics: s.metrics
        ? {
            cpuPct: s.metrics[0],
            memPct: s.metrics[1],
            diskPct: s.metrics[2],
            sampledAt: ago(stale ? s.hbAgo : 10),
            stale,
          }
        : null,
      capabilities: s.caps,
      certificate: {
        serial: (0x5a3c00 + i * 7919).toString(16) + 'e1f04b2d9c',
        notAfter: new Date(Date.now() + 86400e3 * (54 - i)).toISOString(),
      },
      allowedActions: [],
      createdAt: ago(86400 * (40 - i)),
      updatedAt: ago(3600),
      version: 3,
    } satisfies Server;
  });
}

export function seedAudit(users: MockUser[], servers: Server[]): AuditEvent[] {
  const [owner, ops, dev] = users;
  const events: Array<[number, MockUser | null, string, Server | undefined, AuditEvent['result']]> =
    [
      [60, ops!, 'auth.login', undefined, 'success'],
      [1800, ops!, 'server.update', servers[0], 'success'],
      [2600, dev!, 'nginx.write', servers[2], 'denied'],
      [3300, ops!, 'discovery.scan', servers[2], 'success'],
      [4000, null, 'alert.fire', servers[2], 'success'],
      [9000, owner!, 'enrollment.create', undefined, 'success'],
      [12000, owner!, 'role_binding.create', undefined, 'success'],
      [15000, dev!, 'server.revoke', servers[6], 'denied'],
      [20000, null, 'server.status.offline', servers[4], 'success'],
      [26000, owner!, 'auth.mfa.enable', undefined, 'success'],
      [40000, ops!, 'server.update', servers[5], 'failure'],
      [52000, owner!, 'auth.login', undefined, 'success'],
    ];
  const out: AuditEvent[] = events.map(([sec, actor, action, target, result], i) => ({
    id: id(500 + i),
    actorId: actor?.id ?? null,
    actorType: actor ? 'user' : 'system',
    actorLabel: actor?.displayName ?? 'system',
    action,
    targetType: target
      ? 'server'
      : action.startsWith('auth')
        ? 'session'
        : action.startsWith('role')
          ? 'user'
          : 'enrollment',
    targetId: target?.id ?? null,
    targetLabel: target?.name ?? null,
    result,
    requestId: `0193${(1000 + i).toString(16)}-7c1e-7000-8000-${String(i).padStart(12, 'a')}`,
    diffHash: result === 'success' ? `sha256:${(i * 7919).toString(16).padStart(8, '0')}…` : null,
    createdAt: ago(sec),
  }));
  // pad history so pagination is meaningful
  for (let i = 0; i < 36; i++) {
    out.push({
      id: id(600 + i),
      actorId: null,
      actorType: 'agent',
      actorLabel: servers[i % servers.length]!.name,
      action: 'agent.heartbeat.recovered',
      targetType: 'server',
      targetId: servers[i % servers.length]!.id,
      targetLabel: servers[i % servers.length]!.name,
      result: 'success',
      requestId: null,
      diffHash: null,
      createdAt: ago(60000 + i * 3600),
    });
  }
  return out;
}
