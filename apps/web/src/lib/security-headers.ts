/**
 * P7.01 browser security policy for the web UI. Pure (no Next imports) so it is unit-testable.
 *
 * Scripts: per-request nonce + 'strict-dynamic' — no 'unsafe-inline' scripts. Next.js applies the nonce
 * from the request's Content-Security-Policy header to its own inline/bootstrap scripts; our only
 * inline script (theme init) receives it explicitly. 'unsafe-eval' is added in `next dev` only
 * (React Refresh). Styles keep 'unsafe-inline' for React `style={}` attributes (no script execution).
 */
export interface CspOptions {
  nonce: string;
  dev: boolean;
  /** absolute API base (NEXT_PUBLIC_API_BASE); its origin is allowed for fetch/EventSource */
  apiBase?: string;
}

export function apiOrigin(apiBase: string | undefined): string | null {
  if (!apiBase) return null;
  try {
    const u = new URL(apiBase);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
  } catch {
    return null;
  }
}

export function buildCsp({ nonce, dev, apiBase }: CspOptions): string {
  const api = apiOrigin(apiBase);
  const connect = ["'self'", ...(api ? [api] : []), ...(dev ? ['ws:', 'wss:'] : [])];
  const directives: Record<string, string[]> = {
    'default-src': ["'self'"],
    'script-src': [
      "'self'",
      `'nonce-${nonce}'`,
      "'strict-dynamic'",
      ...(dev ? ["'unsafe-eval'"] : []),
    ],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'blob:'],
    'font-src': ["'self'", 'data:'],
    'connect-src': connect,
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
    'worker-src': ["'self'", 'blob:'],
  };
  const parts = Object.entries(directives).map(([k, v]) => `${k} ${v.join(' ')}`);
  // only when the API itself is https (an http API base would otherwise be silently broken)
  if (!dev && api?.startsWith('https:')) parts.push('upgrade-insecure-requests');
  return parts.join('; ');
}

/** Static headers (also set in next.config for non-middleware responses such as static assets). */
export function staticSecurityHeaders(production: boolean): Array<{ key: string; value: string }> {
  return [
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'Referrer-Policy', value: 'same-origin' },
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
    { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
    ...(production
      ? [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }]
      : []),
  ];
}

export function newNonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
