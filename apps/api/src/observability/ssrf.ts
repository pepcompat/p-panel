/**
 * Webhook SSRF guard (P5.05): scheme policy, DNS resolution and private/loopback/link-local/metadata
 * address blocking. The caller connects to the *resolved* address (no second lookup → no DNS
 * rebinding window). Cloud metadata addresses are blocked even for allowlisted hosts.
 */
import { lookup } from 'node:dns/promises';
import net from 'node:net';
import { ERROR_CODES } from '@ppanel/shared-contracts';
import { AppError } from '../common/app-error';

export interface WebhookPolicy {
  production: boolean;
  /** host or host:port allowed over http (non-production only) */
  httpAllowlist: string[];
  /** host or host:port exempt from the private-range block */
  privateAllowlist: string[];
}

export interface ResolvedTarget {
  url: URL;
  address: string;
  family: 4 | 6;
}

const METADATA = new Set(['169.254.169.254', 'fd00:ec2::254', '100.100.100.200']);

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}
function inV4(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split('/') as [string, string];
  const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}

const BLOCKED_V4 = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

function expandV6(ip: string): number[] {
  const [head, tail] = ip.split('::') as [string, string | undefined];
  const parse = (s: string) => (s ? s.split(':') : []);
  let h = parse(head);
  let t = tail === undefined ? [] : parse(tail);
  // embedded IPv4 in the last group
  const fix = (arr: string[]) => {
    const last = arr[arr.length - 1];
    if (last && last.includes('.')) {
      const n = v4ToInt(last);
      arr.splice(arr.length - 1, 1, ((n >>> 16) & 0xffff).toString(16), (n & 0xffff).toString(16));
    }
    return arr;
  };
  h = fix(h);
  t = fix(t);
  const fill = tail === undefined ? [] : new Array(8 - h.length - t.length).fill('0');
  return [...h, ...fill, ...t].map((g) => parseInt(g || '0', 16));
}

/** True for any address a webhook must not reach without an allowlist entry. */
export function isPrivateAddress(ip: string): boolean {
  const kind = net.isIP(ip);
  if (kind === 4) return BLOCKED_V4.some((c) => inV4(ip, c));
  if (kind !== 6) return true;
  const g = expandV6(ip.toLowerCase().split('%')[0]!);
  if (g.every((x) => x === 0)) return true; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1
  // IPv4-mapped ::ffff:a.b.c.d and NAT64 64:ff9b::/96 → check the embedded IPv4
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff)
    return isPrivateAddress(`${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`);
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0))
    return isPrivateAddress(`${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`);
  // deprecated IPv4-compatible ::a.b.c.d and IPv4-translated ::ffff:0:a.b.c.d (SEC-P7-05)
  if (
    g.slice(0, 6).every((x) => x === 0) ||
    (g.slice(0, 4).every((x) => x === 0) && g[4] === 0xffff && g[5] === 0)
  )
    return isPrivateAddress(`${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`);
  // 6to4 2002:AABB:CCDD::/48 embeds a.b.c.d in groups 1–2
  if (g[0] === 0x2002)
    return isPrivateAddress(`${g[1]! >> 8}.${g[1]! & 255}.${g[2]! >> 8}.${g[2]! & 255}`);
  if (g[0] === 0x2001 && g[1] === 0) return true; // Teredo 2001::/32 (tunnels to arbitrary v4)
  if (g[0] === 0x0100 && g.slice(1, 4).every((x) => x === 0)) return true; // discard 100::/64
  if ((g[0]! & 0xffc0) === 0xfec0) return true; // deprecated site-local fec0::/10
  if ((g[0]! & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0]! & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0]! & 0xff00) === 0xff00) return true; // multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  return false;
}

export function isMetadataAddress(ip: string): boolean {
  return METADATA.has(ip.toLowerCase());
}

function hostMatches(list: string[], url: URL): boolean {
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  return list.some((e) => e === host || e === `${host}:${port}`);
}

function deny(reason: string): AppError {
  return new AppError(422, ERROR_CODES.WEBHOOK_URL_NOT_ALLOWED, 'Webhook URL is not allowed', {
    reason,
  });
}

/** Static checks (no DNS): scheme, credentials, port. Used at channel create/update. */
export function checkWebhookUrl(raw: string, policy: WebhookPolicy): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw deny('invalid_url');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw deny('scheme_not_allowed');
  if (url.protocol === 'http:' && (policy.production || !hostMatches(policy.httpAllowlist, url)))
    throw deny(policy.production ? 'https_required' : 'http_host_not_allowlisted');
  if (url.username || url.password) throw deny('credentials_in_url');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isMetadataAddress(host)) throw deny('metadata_address');
    if (isPrivateAddress(host) && !hostMatches(policy.privateAllowlist, url))
      throw deny('private_address');
  }
  return url;
}

export type Resolver = (host: string) => Promise<Array<{ address: string; family: number }>>;
const defaultResolver: Resolver = (host) => lookup(host, { all: true, verbatim: true });

/** Full check incl. DNS: every resolved address must pass (a mixed answer is rejected). */
export async function resolveWebhookTarget(
  raw: string,
  policy: WebhookPolicy,
  resolver: Resolver = defaultResolver,
): Promise<ResolvedTarget> {
  const url = checkWebhookUrl(raw, policy);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  let addrs: Array<{ address: string; family: number }>;
  if (net.isIP(host)) addrs = [{ address: host, family: net.isIP(host) }];
  else {
    try {
      addrs = await resolver(host);
    } catch {
      throw deny('dns_resolution_failed');
    }
  }
  if (addrs.length === 0) throw deny('dns_resolution_failed');
  const allowPrivate = hostMatches(policy.privateAllowlist, url);
  for (const a of addrs) {
    if (isMetadataAddress(a.address)) throw deny('metadata_address');
    if (isPrivateAddress(a.address) && !allowPrivate) throw deny('private_address');
  }
  const first = addrs[0]!;
  return { url, address: first.address, family: first.family === 6 ? 6 : 4 };
}
