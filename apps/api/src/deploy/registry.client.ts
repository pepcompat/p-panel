import { Inject, Injectable } from '@nestjs/common';
import { ERROR_CODES } from '@ppanel/shared-contracts';
import { createHash } from 'node:crypto';
import { AppError } from '../common/app-error';
import { APP_CONFIG, type AppConfig } from '../config/config';

/** Manifest media types accepted when resolving a tag (OCI index/manifest + Docker v2 list/manifest). */
export const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(', ');

/** Dev-only registries that are always allowed (and spoken to over plain HTTP) outside production. */
export const DEV_REGISTRIES = ['lab-registry:5000', '127.0.0.1:55000'];
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const TIMEOUT_MS = 10_000;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

export interface ImageRef {
  host: string;
  name: string;
  tag: string;
}

/** `host[:port]/repo[/…]:tag` with an explicit registry host. */
export function parseTaggedRef(ref: string): ImageRef | null {
  const m =
    /^([a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?)\/([a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*):([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/.exec(
      ref,
    );
  if (!m) return null;
  return { host: m[1]!, name: m[2]!, tag: m[3]! };
}

function listOf(v: string): string[] {
  return v
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

function resolveFailed(message: string, details?: unknown): AppError {
  return new AppError(502, ERROR_CODES.IMAGE_RESOLVE_FAILED, message, details);
}

/** Parses `WWW-Authenticate: Bearer realm="…",service="…",scope="…"` (or `Basic realm=…`). */
export function parseChallenge(
  h: string | null,
): { scheme: string; params: Record<string, string> } | null {
  if (!h) return null;
  const m = /^(\w+)\s*(.*)$/.exec(h.trim());
  if (!m) return null;
  const params: Record<string, string> = {};
  for (const p of m[2]!.matchAll(/(\w+)="([^"]*)"/g)) params[p[1]!.toLowerCase()] = p[2]!;
  return { scheme: m[1]!.toLowerCase(), params };
}

/**
 * Registry HTTP API v2 client used to turn `repo:tag` into an immutable digest. SSRF guard: only
 * hosts in `PPANEL_REGISTRY_ALLOWLIST`, the app's own registry-auth host, and (outside production)
 * the lab registries are contacted; bearer-token realms must be allowlisted too. No redirects.
 */
@Injectable()
export class RegistryClient {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  allowedHosts(extra: string[] = []): Set<string> {
    const out = new Set(listOf(this.config.PPANEL_REGISTRY_ALLOWLIST));
    if (!this.config.isProduction) for (const h of DEV_REGISTRIES) out.add(h);
    for (const h of extra) out.add(h.toLowerCase());
    return out;
  }

  private scheme(host: string): 'http' | 'https' {
    const insecure = new Set(listOf(this.config.PPANEL_REGISTRY_INSECURE));
    if (!this.config.isProduction) for (const h of DEV_REGISTRIES) insecure.add(h);
    return insecure.has(host) ? 'http' : 'https';
  }

  private async request(url: string, init: RequestInit): Promise<Response> {
    try {
      return await fetch(url, {
        ...init,
        redirect: 'manual',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (e) {
      throw resolveFailed(`Registry request failed: ${(e as Error).message}`);
    }
  }

  private async bearerToken(
    challenge: Record<string, string>,
    allowed: Set<string>,
    auth: { username: string; password: string } | null,
  ): Promise<string> {
    const realm = challenge.realm;
    let u: URL;
    try {
      u = new URL(realm ?? '');
    } catch {
      throw resolveFailed('Registry token realm is invalid');
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:')
      throw resolveFailed('Unsupported token realm');
    if (!allowed.has(u.host.toLowerCase()))
      throw new AppError(
        422,
        ERROR_CODES.REGISTRY_NOT_ALLOWED,
        'Token realm host is not allowlisted',
        {
          host: u.host,
        },
      );
    if (challenge.service) u.searchParams.set('service', challenge.service);
    if (challenge.scope) u.searchParams.set('scope', challenge.scope);
    const res = await this.request(u.toString(), {
      method: 'GET',
      headers: auth
        ? {
            Authorization: `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`,
          }
        : {},
    });
    if (!res.ok) throw resolveFailed(`Registry token endpoint returned ${res.status}`);
    const body = (await res.json().catch(() => ({}))) as { token?: string; access_token?: string };
    const token = body.token ?? body.access_token;
    if (!token) throw resolveFailed('Registry token endpoint returned no token');
    return token;
  }

  /** Resolve `host/repo:tag` → `host/repo@sha256:…` (HEAD, falling back to GET + sha256 of the body). */
  async resolveDigest(
    ref: string,
    opts: {
      auth?: { username: string; password: string } | null;
      extraAllowedHosts?: string[];
    } = {},
  ): Promise<string> {
    const p = parseTaggedRef(ref);
    if (!p)
      throw new AppError(
        422,
        ERROR_CODES.IMAGE_RESOLVE_FAILED,
        'Image reference must be host/repo:tag',
        { ref },
      );
    const allowed = this.allowedHosts(opts.extraAllowedHosts);
    if (!allowed.has(p.host))
      throw new AppError(
        422,
        ERROR_CODES.REGISTRY_NOT_ALLOWED,
        `Registry ${p.host} is not allowlisted`,
        {
          host: p.host,
        },
      );
    const url = `${this.scheme(p.host)}://${p.host}/v2/${p.name}/manifests/${encodeURIComponent(p.tag)}`;
    const auth = opts.auth ?? null;
    let authorization: string | undefined;
    const send = (method: 'HEAD' | 'GET') =>
      this.request(url, {
        method,
        headers: {
          Accept: MANIFEST_ACCEPT,
          ...(authorization ? { Authorization: authorization } : {}),
        },
      });
    let res = await send('HEAD');
    if (res.status === 401) {
      const ch = parseChallenge(res.headers.get('www-authenticate'));
      if (ch?.scheme === 'basic' && auth)
        authorization = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`;
      else if (ch?.scheme === 'bearer')
        authorization = `Bearer ${await this.bearerToken(ch.params, allowed, auth)}`;
      else throw resolveFailed('Registry requires authentication', { status: 401 });
      res = await send('HEAD');
    }
    if (res.status === 404)
      throw resolveFailed(`Tag ${p.tag} not found in ${p.host}/${p.name}`, { status: 404 });
    if (res.status >= 300 && res.status < 400)
      throw resolveFailed('Registry redirects are not followed');
    if (!res.ok && res.status !== 405)
      throw resolveFailed(`Registry returned ${res.status}`, { status: res.status });
    let digest = res.ok ? res.headers.get('docker-content-digest') : null;
    if (!digest) {
      const g = await send('GET');
      if (!g.ok) throw resolveFailed(`Registry returned ${g.status}`, { status: g.status });
      const buf = Buffer.from(await g.arrayBuffer());
      if (buf.length > MAX_MANIFEST_BYTES) throw resolveFailed('Manifest too large');
      digest =
        g.headers.get('docker-content-digest') ??
        `sha256:${createHash('sha256').update(buf).digest('hex')}`;
    }
    if (!DIGEST_RE.test(digest)) throw resolveFailed('Registry returned an invalid digest');
    return `${p.host}/${p.name}@${digest}`;
  }
}
