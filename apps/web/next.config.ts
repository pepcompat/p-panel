import type { NextConfig } from 'next';
import { staticSecurityHeaders } from './src/lib/security-headers';

const nextConfig: NextConfig = {
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
