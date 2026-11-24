/**
 * P7.01 XSS: user-controlled strings (server names/tags, step messages, log tails, …) render as text,
 * never as markup; the source tree has no unsafe HTML sinks except the nonce'd constant theme script;
 * the CSP never allows inline scripts.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { ServerCard } from '@/components/servers/server-card';
import { DeploymentTimeline, ImageRef } from '@/components/p4/bits';
import { buildCsp, staticSecurityHeaders } from '@/lib/security-headers';
import { makeServer, renderWith } from './test-utils';

const PAYLOADS = [
  '<script>window.__xss=1</script>',
  '<img src=x onerror="window.__xss=1">',
  '"><svg onload=window.__xss=1>',
  'javascript:window.__xss=1//',
  '{{constructor.constructor("window.__xss=1")()}}',
];

function assertInert(root: HTMLElement) {
  expect(root.querySelector('script')).toBeNull();
  expect(root.querySelector('svg[onload], img[onerror], [onerror], [onload]')).toBeNull();
  for (const a of root.querySelectorAll('a[href]'))
    expect(a.getAttribute('href') ?? '').not.toMatch(/^\s*javascript:/i);
  expect((window as unknown as { __xss?: number }).__xss).toBeUndefined();
}

describe('stored XSS payloads render as text', () => {
  for (const p of PAYLOADS) {
    it(`ServerCard name/hostname/tags: ${p.slice(0, 24)}`, () => {
      const { container } = renderWith(
        <ServerCard
          server={makeServer({ name: p, hostname: p, tags: [p, 'ok'], allowedActions: [] })}
          now={Date.now()}
        />,
      );
      assertInert(container);
      expect(container.textContent).toContain(p);
    });

    it(`DeploymentTimeline step message / log tail / error code: ${p.slice(0, 24)}`, () => {
      const d = {
        id: 'd1',
        steps: [
          {
            name: 'pull',
            status: 'failed',
            startedAt: null,
            finishedAt: null,
            message: p,
            errorCode: p,
            logTail: [p, `line2 ${p}`],
          },
        ],
      } as unknown as Parameters<typeof DeploymentTimeline>[0]['d'];
      const { container } = renderWith(<DeploymentTimeline d={d} now={Date.now()} />);
      assertInert(container);
      expect(screen.getByTestId('log-tail').textContent).toContain(p);
    });
  }

  it('ImageRef renders an attacker-controlled image string as text', () => {
    const p = PAYLOADS[1]!;
    const { container } = renderWith(<ImageRef image={p} />);
    assertInert(container);
  });
});

describe('no unsafe HTML sinks in apps/web/src', () => {
  const SINKS =
    /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(/;
  /** file → justification */
  const ALLOW: Record<string, string> = {
    'app/layout.tsx':
      'constant theme-init script (no user data), carries the per-request CSP nonce',
  };
  function walk(dir: string, out: string[] = []): string[] {
    for (const f of readdirSync(dir)) {
      const p = path.join(dir, f);
      if (statSync(p).isDirectory()) walk(p, out);
      else if (/\.(tsx?|jsx?)$/.test(f)) out.push(p);
    }
    return out;
  }
  it('only allow-listed files use an HTML sink', () => {
    const src = path.resolve(__dirname, '../../src');
    const hits = walk(src)
      .filter((f) => SINKS.test(readFileSync(f, 'utf8')))
      .map((f) => path.relative(src, f));
    expect(hits.filter((h) => !ALLOW[h])).toEqual([]);
  });
  it('the allow-listed theme script embeds no runtime value', () => {
    const theme = readFileSync(
      path.resolve(__dirname, '../../src/components/providers/theme.tsx'),
      'utf8',
    );
    const m = /themeInitScript = `([^`]*)`/.exec(theme);
    expect(m).not.toBeNull();
    // only the THEME_STORAGE_KEY constant is interpolated
    expect([...m![1]!.matchAll(/\$\{([^}]+)\}/g)].map((x) => x[1])).toEqual(['THEME_STORAGE_KEY']);
  });
});

describe('CSP', () => {
  it('production: nonce + strict-dynamic, no unsafe-inline / unsafe-eval scripts, framing denied', () => {
    const csp = buildCsp({
      nonce: 'abc123',
      dev: false,
      apiBase: 'https://api.example.test/api/v1',
    });
    const script = /script-src ([^;]+)/.exec(csp)![1]!;
    expect(script).toContain("'nonce-abc123'");
    expect(script).toContain("'strict-dynamic'");
    expect(script).not.toContain('unsafe-inline');
    expect(script).not.toContain('unsafe-eval');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(/connect-src ([^;]+)/.exec(csp)![1]).toBe("'self' https://api.example.test");
  });
  it('dev only adds unsafe-eval (React Refresh) and websockets', () => {
    const csp = buildCsp({ nonce: 'n', dev: true, apiBase: 'http://localhost:4000/api/v1' });
    expect(/script-src ([^;]+)/.exec(csp)![1]).toContain("'unsafe-eval'");
    expect(/script-src ([^;]+)/.exec(csp)![1]).not.toContain('unsafe-inline');
  });
  it('upgrade-insecure-requests only with an https API base', () => {
    expect(
      buildCsp({ nonce: 'n', dev: false, apiBase: 'https://api.example.test/api/v1' }),
    ).toContain('upgrade-insecure-requests');
    expect(
      buildCsp({ nonce: 'n', dev: false, apiBase: 'http://localhost:4000/api/v1' }),
    ).not.toContain('upgrade-insecure-requests');
  });
  it('a javascript: API base never lands in connect-src', () => {
    const csp = buildCsp({ nonce: 'n', dev: false, apiBase: 'javascript:alert(1)' });
    expect(csp).not.toContain('javascript');
  });
  it('static headers: nosniff, DENY, HSTS in production only', () => {
    const prod = Object.fromEntries(staticSecurityHeaders(true).map((h) => [h.key, h.value]));
    expect(prod['X-Content-Type-Options']).toBe('nosniff');
    expect(prod['X-Frame-Options']).toBe('DENY');
    expect(prod['Strict-Transport-Security']).toMatch(/max-age=\d+/);
    const dev = Object.fromEntries(staticSecurityHeaders(false).map((h) => [h.key, h.value]));
    expect(dev['Strict-Transport-Security']).toBeUndefined();
  });
});
