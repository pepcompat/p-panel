import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import { IBM_Plex_Mono, IBM_Plex_Sans_Thai } from 'next/font/google';
import { AppProviders } from '@/components/providers/app-providers';
import { themeInitScript } from '@/components/providers/theme';
import './globals.css';

const plexThai = IBM_Plex_Sans_Thai({
  weight: ['400', '500', '600', '700'],
  subsets: ['thai', 'latin'],
  variable: '--font-plex-thai',
  display: 'swap',
});
const plexMono = IBM_Plex_Mono({
  weight: ['400', '500'],
  subsets: ['latin'],
  variable: '--font-plex-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: { default: 'pPanel', template: '%s · pPanel' },
  description: 'pPanel — self-hosted multi-server infrastructure control panel',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { width: 'device-width', initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // per-request CSP nonce set by src/middleware.ts (P7.01: no 'unsafe-inline' scripts)
  const nonce = (await headers()).get('x-nonce') ?? undefined;
  return (
    <html
      lang="en"
      data-theme="light"
      suppressHydrationWarning
      className={`${plexThai.variable} ${plexMono.variable}`}
    >
      <head>
        {/* browsers hide `nonce` from the DOM after parsing, so its value never matches on hydration */}
        <script
          nonce={nonce}
          suppressHydrationWarning
          dangerouslySetInnerHTML={{ __html: themeInitScript }}
        />
      </head>
      <body>
        <AppProviders>{children}</AppProviders>
      </body>
    </html>
  );
}
