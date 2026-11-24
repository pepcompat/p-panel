import { NextResponse, type NextRequest } from 'next/server';
import { buildCsp, newNonce } from '@/lib/security-headers';

/** Per-request CSP nonce (P7.01). Next reads the nonce from the request CSP header for its scripts. */
export function middleware(request: NextRequest) {
  const nonce = newNonce();
  const csp = buildCsp({
    nonce,
    dev: process.env.NODE_ENV !== 'production',
    apiBase: process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:4000/api/v1',
  });
  const reqHeaders = new Headers(request.headers);
  reqHeaders.set('x-nonce', nonce);
  reqHeaders.set('Content-Security-Policy', csp);
  const res = NextResponse.next({ request: { headers: reqHeaders } });
  res.headers.set('Content-Security-Policy', csp);
  return res;
}

export const config = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|favicon.ico).*)',
      missing: [{ type: 'header', key: 'next-router-prefetch' }],
    },
  ],
};
