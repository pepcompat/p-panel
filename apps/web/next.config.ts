import path from 'node:path';
import type { NextConfig } from 'next';
import { staticSecurityHeaders } from './src/lib/security-headers';

// P8: the production image (apps/web/Dockerfile) builds with NEXT_OUTPUT_STANDALONE=1 → minimal
// `.next/standalone` server (traced from the monorepo root). Dev / CI / Playwright are unaffected.
const standalone = process.env.NEXT_OUTPUT_STANDALONE === '1';

const nextConfig: NextConfig = {
  ...(standalone
    ? { output: 'standalone' as const, outputFileTracingRoot: path.resolve(process.cwd(), '../..') }
    : {}),
  reactStrictMode: true,
  poweredByHeader: false,
  devIndicators: false,
  // shared-contracts ships TypeScript source; let Next transpile it.
  transpilePackages: ['@ppanel/shared-contracts'],
  async headers() {
    return [
      {
        source: '/:path*',
        headers: staticSecurityHeaders(process.env.NODE_ENV === 'production'),
      },
    ];
  },
};

export default nextConfig;
