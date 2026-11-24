// pPanel LAB fake DigitalOcean (P9, docs/P9_NETWORK_CONTRACT.md §2/§6). LAB ONLY. No dependencies.
//
// API (bearer token = env PPANEL_LAB_DO_TOKEN, GET only, like the real read-only use):
//   GET /v2/account
//   GET /v2/droplets?page=N&per_page=M   (paginated; default per_page is 2 here so the Center MUST follow links.pages.next)
//   GET /v2/vpcs?page=N&per_page=M
// Per-node droplet metadata (no auth, like the link-local service at 169.254.169.254/metadata/v1.json):
//   GET /metadata/<node>/v1.json         node = node-a | node-b | gateway
//   GET /healthz
//
// Lab truth (must match infra/compose/lab.yml + scripts/lab/p9-net.sh): ONE region `lab1`, TWO VPCs.
//   vpc-a 10.110.0.0/24: node-a 10.110.0.11, gateway 10.110.0.20
//   vpc-b 10.120.0.0/24: node-b 10.120.0.12
// Public IPv4s are TEST-NET-3 placeholders (203.0.113.0/24): the lab has no real public addresses.
import { createServer } from 'node:http';

const TOKEN = process.env.PPANEL_LAB_DO_TOKEN || 'lab-do-token-not-a-secret';
const PORT = Number(process.env.PORT || 8080);
const DEFAULT_PER_PAGE = 2;
const REGION = { slug: 'lab1', name: 'pPanel Lab 1', available: true };

const VPCS = [
  {
    id: '5a4c1d0e-0000-4000-8000-00000000a001',
    urn: 'do:vpc:5a4c1d0e-0000-4000-8000-00000000a001',
    name: 'ppanel-lab-vpc-a',
    description: 'lab VPC A',
    region: 'lab1',
    ip_range: '10.110.0.0/24',
    default: true,
    created_at: '2026-11-01T00:00:00Z',
  },
  {
    id: '5a4c1d0e-0000-4000-8000-00000000b002',
    urn: 'do:vpc:5a4c1d0e-0000-4000-8000-00000000b002',
    name: 'ppanel-lab-vpc-b',
    description: 'lab VPC B',
    region: 'lab1',
    ip_range: '10.120.0.0/24',
    default: false,
    created_at: '2026-11-01T00:00:00Z',
  },
];

// node key -> droplet
const NODES = {
  'node-a': { id: 910001, name: 'lab-node-a', vpc: 0, priv: '10.110.0.11', pub: '203.0.113.11' },
  'node-b': { id: 910002, name: 'lab-node-b', vpc: 1, priv: '10.120.0.12', pub: '203.0.113.12' },
  gateway: { id: 910003, name: 'lab-gateway', vpc: 0, priv: '10.110.0.20', pub: '203.0.113.20' },
  // a droplet that is NOT a pPanel server (sync must ignore it, not invent a server)
  spare: { id: 910004, name: 'lab-spare', vpc: 1, priv: '10.120.0.99', pub: '203.0.113.99' },
};

function droplet(n) {
  return {
    id: n.id,
    name: n.name,
    memory: 1024,
    vcpus: 1,
    disk: 25,
    locked: false,
    status: 'active',
    created_at: '2026-11-01T00:00:00Z',
    region: REGION,
    size_slug: 's-1vcpu-1gb',
    vpc_uuid: VPCS[n.vpc].id,
    networks: {
      v4: [
        { ip_address: n.priv, netmask: '255.255.255.0', gateway: '0.0.0.0', type: 'private' },
        { ip_address: n.pub, netmask: '255.255.255.0', gateway: '203.0.113.1', type: 'public' },
      ],
      v6: [],
    },
    tags: ['ppanel-lab'],
  };
}

function metadata(key, n) {
  return {
    droplet_id: n.id,
    hostname: n.name,
    vendor_data: '',
    public_keys: [],
    auth_key: '',
    region: 'lab1',
    interfaces: {
      private: [
        {
          ipv4: { ip_address: n.priv, netmask: '255.255.255.0', gateway: '0.0.0.0' },
          mac: macFor(n.id, 2),
          type: 'private',
        },
      ],
      public: [
        {
          ipv4: { ip_address: n.pub, netmask: '255.255.255.0', gateway: '203.0.113.1' },
          mac: macFor(n.id, 1),
          type: 'public',
        },
      ],
    },
    floating_ip: { ipv4: { active: false } },
    dns: { nameservers: ['127.0.0.11'] },
    tags: ['ppanel-lab'],
    features: { dhcp_enabled: false },
    _lab: { node: key },
  };
}

function macFor(id, k) {
  const h = (id + k).toString(16).padStart(6, '0').slice(-6);
  return `de:ad:be:${h.slice(0, 2)}:${h.slice(2, 4)}:${h.slice(4, 6)}`;
}

function send(res, status, body) {
  const b = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(b),
  });
  res.end(b);
}

function paginate(req, url, items, key) {
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1);
  const per = Math.min(
    200,
    Math.max(
      1,
      parseInt(url.searchParams.get('per_page') || String(DEFAULT_PER_PAGE), 10) ||
        DEFAULT_PER_PAGE,
    ),
  );
  const last = Math.max(1, Math.ceil(items.length / per));
  const base = `http://${req.headers.host}${url.pathname}`;
  const pages = {};
  if (page < last) {
    pages.next = `${base}?page=${page + 1}&per_page=${per}`;
    pages.last = `${base}?page=${last}&per_page=${per}`;
  }
  if (page > 1) {
    pages.first = `${base}?page=1&per_page=${per}`;
    pages.prev = `${base}?page=${page - 1}&per_page=${per}`;
  }
  return {
    [key]: items.slice((page - 1) * per, page * per),
    links: { pages },
    meta: { total: items.length },
  };
}

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://lab-do-fake');
  let status = 200;
  const done = (s, body) => {
    status = s;
    send(res, s, body);
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        method: req.method,
        path: url.pathname,
        query: url.search,
        status,
      }),
    );
  };
  if (url.pathname === '/healthz') return done(200, { ok: true });
  if (req.method !== 'GET')
    return done(405, { id: 'method_not_allowed', message: 'lab fake: GET only' });
  const md = url.pathname.match(/^\/metadata\/([a-z-]+)\/v1\.json$/);
  if (md) {
    const n = NODES[md[1]];
    return n
      ? done(200, metadata(md[1], n))
      : done(404, { id: 'not_found', message: 'no such lab node' });
  }
  if (!url.pathname.startsWith('/v2/')) return done(404, { id: 'not_found', message: 'not found' });
  if ((req.headers.authorization || '') !== `Bearer ${TOKEN}`)
    return done(401, { id: 'Unauthorized', message: 'Unable to authenticate you' });
  switch (url.pathname) {
    case '/v2/account':
      return done(200, {
        account: {
          uuid: '0c0ffee0-0000-4000-8000-0000000000aa',
          email: 'lab@ppanel.lab',
          email_verified: true,
          status: 'active',
          droplet_limit: 25,
          team: { uuid: '0c0ffee0-0000-4000-8000-0000000000ab', name: 'pPanel Lab' },
        },
      });
    case '/v2/droplets':
      return done(200, paginate(req, url, Object.values(NODES).map(droplet), 'droplets'));
    case '/v2/vpcs':
      return done(200, paginate(req, url, VPCS, 'vpcs'));
    default:
      return done(404, {
        id: 'not_found',
        message: 'The resource you were accessing could not be found.',
      });
  }
});

server.listen(PORT, '0.0.0.0', () =>
  console.log(JSON.stringify({ msg: 'lab-do-fake listening', port: PORT })),
);
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
