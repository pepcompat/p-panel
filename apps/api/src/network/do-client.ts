/**
 * P9 DigitalOcean API client — read-only by construction: it can only send GET (any other method is
 * refused before a socket is opened), to an allowlisted API base, after the SSRF guard resolved the
 * host (the request connects to the checked address, no second lookup). Bounded: timeout per request,
 * response size cap, page cap, redirects are never followed.
 */
import { DEFAULT_DO_API_BASE, ERROR_CODES } from '@ppanel/shared-contracts';
import http from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { AppError } from '../common/app-error';
import { normalizeApiBase } from '../config/config';
import { isMetadataAddress, isPrivateAddress, type Resolver } from '../observability/ssrf';

export const DO_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const DO_MAX_PAGES = 50;
export const DO_PER_PAGE = 200;

export type ProviderErrorCode =
  | typeof ERROR_CODES.PROVIDER_AUTH_FAILED
  | typeof ERROR_CODES.PROVIDER_UNAVAILABLE
  | typeof ERROR_CODES.PROVIDER_API_NOT_ALLOWED;

export class ProviderError extends Error {
  constructor(
    readonly code: ProviderErrorCode,
    message: string,
    readonly httpStatus?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

function notAllowed(reason: string): AppError {
  return new AppError(
    422,
    ERROR_CODES.PROVIDER_API_NOT_ALLOWED,
    'Provider API base is not allowed',
    { reason },
  );
}

/**
 * Static api_base policy: must normalise to exactly one allowlisted base (the official API or a
 * PPANEL_DO_API_BASE entry); http only outside production. Returns the canonical base.
 */
export function checkApiBase(
  raw: string | undefined,
  allowlist: string[],
  production: boolean,
): string {
  const base = normalizeApiBase(raw ?? DEFAULT_DO_API_BASE);
  if (!base) throw notAllowed('invalid_url');
  if (!allowlist.includes(base)) throw notAllowed('not_allowlisted');
  if (base.startsWith('http:') && production) throw notAllowed('https_required');
  return base;
}

export interface DoClientOptions {
  apiBase: string;
  token: string;
  timeoutMs: number;
  /** operator-allowlisted lab base: private addresses allowed (metadata addresses never) */
  allowPrivate: boolean;
  resolver?: Resolver;
}

const defaultResolver: Resolver = (host) => lookup(host, { all: true, verbatim: true });

export class DoClient {
  private readonly base: URL;

  constructor(private readonly o: DoClientOptions) {
    this.base = new URL(o.apiBase);
  }

  /** The ONLY transport entry point; refuses every method but GET. */
  async request(method: string, pathAndQuery: string): Promise<unknown> {
    if (method !== 'GET')
      throw new ProviderError(
        ERROR_CODES.PROVIDER_API_NOT_ALLOWED,
        `provider client is read-only (refused ${method})`,
      );
    if (!/^\/v2\/[a-z0-9_/-]+(\?[A-Za-z0-9_=&-]*)?$/.test(pathAndQuery))
      throw new ProviderError(ERROR_CODES.PROVIDER_API_NOT_ALLOWED, 'invalid provider API path');
    const url = new URL(this.base.pathname.replace(/\/$/, '') + pathAndQuery, this.base);
    const address = await this.resolve(url.hostname.replace(/^\[|\]$/g, ''));
    return this.send(url, address);
  }

  get<T>(pathAndQuery: string): Promise<T> {
    return this.request('GET', pathAndQuery) as Promise<T>;
  }

  /** Follows DigitalOcean page links by page number (never by the returned URL), ≤ DO_MAX_PAGES. */
  async listAll<T>(path: string, key: string): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; page <= DO_MAX_PAGES; page++) {
      const body = (await this.get<Record<string, unknown>>(
        `${path}?page=${page}&per_page=${DO_PER_PAGE}`,
      )) as { links?: { pages?: { next?: unknown } } } & Record<string, unknown>;
      const items = body[key];
      if (!Array.isArray(items))
        throw new ProviderError(ERROR_CODES.PROVIDER_UNAVAILABLE, `malformed ${key} page`);
      out.push(...(items as T[]));
      if (!body.links?.pages?.next || items.length === 0) return out;
    }
    throw new ProviderError(
      ERROR_CODES.PROVIDER_UNAVAILABLE,
      `more than ${DO_MAX_PAGES} pages of ${key}`,
    );
  }

  private async resolve(host: string): Promise<{ address: string; family: 4 | 6 }> {
    let addrs: Array<{ address: string; family: number }>;
    if (net.isIP(host)) addrs = [{ address: host, family: net.isIP(host) }];
    else {
      try {
        addrs = await (this.o.resolver ?? defaultResolver)(host);
      } catch {
        throw new ProviderError(
          ERROR_CODES.PROVIDER_UNAVAILABLE,
          'provider API host did not resolve',
        );
      }
    }
    if (addrs.length === 0)
      throw new ProviderError(
        ERROR_CODES.PROVIDER_UNAVAILABLE,
        'provider API host did not resolve',
      );
    for (const a of addrs) {
      if (isMetadataAddress(a.address))
        throw new ProviderError(ERROR_CODES.PROVIDER_API_NOT_ALLOWED, 'metadata address refused');
      if (isPrivateAddress(a.address) && !this.o.allowPrivate)
        throw new ProviderError(ERROR_CODES.PROVIDER_API_NOT_ALLOWED, 'private address refused');
    }
    const first = addrs[0]!;
    return { address: first.address, family: first.family === 6 ? 6 : 4 };
  }

  private send(url: URL, target: { address: string; family: 4 | 6 }): Promise<unknown> {
    const pinned: LookupFunction = (_host, opts, cb) => {
      if ((opts as { all?: boolean }).all)
        (cb as (e: null, a: Array<{ address: string; family: number }>) => void)(null, [
          { address: target.address, family: target.family },
        ]);
      else cb(null, target.address, target.family);
    };
    const mod = url.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      const req = mod.request(
        url,
        {
          method: 'GET',
          lookup: pinned,
          agent: false,
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${this.o.token}`,
            'User-Agent': 'ppanel-center',
          },
        },
        (res) => {
          const status = res.statusCode ?? 0;
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (c: Buffer) => {
            size += c.length;
            if (size > DO_MAX_RESPONSE_BYTES) {
              req.destroy();
              reject(new ProviderError(ERROR_CODES.PROVIDER_UNAVAILABLE, 'response too large'));
              return;
            }
            chunks.push(c);
          });
          res.on('error', () =>
            reject(new ProviderError(ERROR_CODES.PROVIDER_UNAVAILABLE, 'response aborted')),
          );
          res.on('end', () => {
            if (status === 401 || status === 403)
              return reject(
                new ProviderError(
                  ERROR_CODES.PROVIDER_AUTH_FAILED,
                  'provider rejected the token',
                  status,
                ),
              );
            if (status < 200 || status >= 300)
              // 3xx included: redirects are never followed
              return reject(
                new ProviderError(
                  ERROR_CODES.PROVIDER_UNAVAILABLE,
                  `provider API answered HTTP ${status}`,
                  status,
                ),
              );
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
              reject(new ProviderError(ERROR_CODES.PROVIDER_UNAVAILABLE, 'malformed JSON'));
            }
          });
        },
      );
      req.setTimeout(this.o.timeoutMs, () => {
        req.destroy();
        reject(new ProviderError(ERROR_CODES.PROVIDER_UNAVAILABLE, 'provider API timed out'));
      });
      req.on('error', (e) => {
        if (e instanceof ProviderError) return reject(e);
        reject(new ProviderError(ERROR_CODES.PROVIDER_UNAVAILABLE, 'provider API unreachable'));
      });
      req.end();
    });
  }
}

// ---------------------------------------------------------------- DigitalOcean shapes (subset)

export interface DoDroplet {
  id: number | string;
  name?: string;
  region?: { slug?: string } | null;
  vpc_uuid?: string | null;
  networks?: { v4?: Array<{ ip_address?: string; type?: string }> } | null;
}
export interface DoVpc {
  id: string;
  name?: string;
  region?: string;
}

/** Normalised droplet facts (only well-formed values survive). */
export function normalizeDroplet(d: DoDroplet): {
  dropletId: string;
  name: string | null;
  region: string | null;
  vpcUuid: string | null;
  privateIpv4: string | null;
  publicIpv4: string | null;
} | null {
  const id = typeof d.id === 'number' ? String(d.id) : d.id;
  if (typeof id !== 'string' || !/^\d{1,20}$/.test(id)) return null;
  const v4 = Array.isArray(d.networks?.v4) ? d.networks.v4 : [];
  const ip = (type: string) => {
    const hit = v4.find((n) => n?.type === type && net.isIPv4(String(n.ip_address ?? '')));
    return hit ? String(hit.ip_address) : null;
  };
  const region = typeof d.region?.slug === 'string' && /^[a-z0-9-]{1,32}$/.test(d.region.slug);
  const vpc = typeof d.vpc_uuid === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(d.vpc_uuid);
  return {
    dropletId: id,
    name: typeof d.name === 'string' ? d.name.slice(0, 255) : null,
    region: region ? d.region!.slug! : null,
    vpcUuid: vpc ? d.vpc_uuid! : null,
    privateIpv4: ip('private'),
    publicIpv4: ip('public'),
  };
}
