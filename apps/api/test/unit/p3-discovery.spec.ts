import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createNginxRevisionSchema } from '@ppanel/shared-contracts';
import { describe, expect, it } from 'vitest';
import { applicationKindOf, parseScanResult, slugify } from '../../src/discovery/scan-parser';
import {
  checkRevisionPath,
  computePlanHash,
  contentSha256,
  unifiedDiff,
} from '../../src/nginx/nginx-plan';

const fixture = JSON.parse(
  readFileSync(path.join(__dirname, '../fixtures/discovery-scan-result.json'), 'utf8'),
);
const SOURCES = ['nginx', 'docker', 'systemd', 'php-fpm', 'ports'];

describe('scan parser (P3.03, real captured report)', () => {
  it('maps the real lab report: 9 nginx servers, 1 duplicate, 5 manual review', () => {
    const p = parseScanResult(fixture, SOURCES);
    expect(p.nginxOk).toBe(true);
    expect(p.summary).toMatchObject({
      nginxServers: 9,
      duplicates: 1,
      manualReview: 5,
      upstreams: 1,
      phpFpmPools: 1,
      listeners: 3,
      containers: 0,
    });
    expect(p.summary.sourceStatus).toMatchObject({ nginx: 'ok', 'php-fpm': 'ok', ports: 'ok' });
    expect(p.summary.sourceStatus.docker).toBe('missing'); // not in this captured run
    expect(p.configFiles).toHaveLength(16);
    const servers = p.findings.filter((f) => f.kind === 'nginx_server');
    expect(servers).toHaveLength(9);
    expect(new Set(servers.map((f) => f.fingerprint)).size).toBe(9);
    // duplicate conflict cross-references Center ids, both ways
    const dups = servers.filter((f) => f.conflicts.length > 0);
    expect(dups).toHaveLength(2);
    expect(dups[0]!.conflicts[0]).toMatchObject({
      type: 'duplicate_server_name',
      with: [dups[1]!.id],
      name: 'dup.example.lab',
      port: 80,
    });
    const php = servers.find((f) => f.title === 'php.example.lab')!;
    expect(php).toMatchObject({
      domains: ['php.example.lab', '*.php.example.lab'],
      confidence: 'medium',
      manualReviewRequired: true,
      unsupportedDirectives: ['set'],
      provenance: {
        file: '/etc/nginx/sites-enabled/02-php-legacy.conf',
        line: 2,
        includedFrom: '/etc/nginx/nginx.conf:30',
      },
    });
    expect(php.links).toMatchObject({
      fastcgiPass: 'unix:/run/php/php8.3-fpm.sock',
      root: '/var/www/php',
      phpFpmPool: 'www',
      processes: [],
    });
    expect(applicationKindOf(php.links)).toBe('nginx_php');
    const unusual = servers.find((f) => f.title === 'unusual.example.lab')!;
    expect(unusual.domains).toEqual(['unusual.example.lab']); // regex server_name is not a domain
    expect(unusual.unsupportedDirectives).toEqual([
      'if',
      'rewrite',
      'sub_filter',
      'sub_filter_once',
    ]);
    const catchAll = servers.find((f) => f.domains.length === 0)!;
    expect(catchAll.title).toBe('_');
    expect(applicationKindOf(catchAll.links)).toBe('unknown');
  });

  it('fingerprints are stable across scans (ids are not)', () => {
    const a = parseScanResult(fixture, SOURCES);
    const b = parseScanResult(fixture, SOURCES);
    expect(a.findings.map((f) => f.fingerprint)).toEqual(b.findings.map((f) => f.fingerprint));
    expect(a.findings[0]!.id).not.toBe(b.findings[0]!.id);
  });

  it('tolerates garbage / missing sections without inventing data', () => {
    const p = parseScanResult({ nginx: { status: 'unavailable' } }, ['nginx', 'docker']);
    expect(p.nginxOk).toBe(false);
    expect(p.findings).toEqual([]);
    expect(p.summary.sourceStatus).toEqual({ nginx: 'unavailable', docker: 'missing' });
    expect(parseScanResult(null, []).findings).toEqual([]);
  });

  it('slugify produces safe managed-dir names', () => {
    expect(slugify('php.example.lab')).toBe('php-example-lab');
    expect(slugify('*.x.lab')).toBe('wildcard-x-lab');
    expect(slugify('../../etc')).toBe('etc');
    expect(slugify('___')).toBe('app');
  });
});

describe('nginx revision plan helpers (P3.05, P3-T04 path part)', () => {
  const files = [
    { path: '/etc/nginx/sites-enabled/05-duplicate-a.conf', lastKnownSha256: 'a'.repeat(64) },
    {
      path: '/etc/nginx/sites-enabled/x.conf',
      lastKnownSha256: null,
      resolvedPath: '/etc/nginx/sites-available/x.conf',
    },
  ];
  it('allows app files, symlink targets and the app managed dir only', () => {
    expect(checkRevisionPath(files[0]!.path, 'dup-example-lab', files)).toBeNull();
    expect(
      checkRevisionPath('/etc/nginx/sites-available/x.conf', 'dup-example-lab', files),
    ).toBeNull();
    expect(
      checkRevisionPath(
        '/etc/nginx/ppanel-managed/dup-example-lab/extra.conf',
        'dup-example-lab',
        files,
      ),
    ).toBeNull();
    for (const bad of [
      '/etc/nginx/nginx.conf',
      '/etc/nginx/ppanel-managed/other-app/x.conf',
      '/etc/nginx/ppanel-managed/dup-example-lab/',
      '/etc/nginx/ppanel-managed/dup-example-lab/../other/x.conf',
      '/etc/nginx//sites-enabled/05-duplicate-a.conf',
      '/etc/passwd',
      '/etc/nginx/sites-enabled/05-duplicate-a.conf\n',
    ])
      expect(checkRevisionPath(bad, 'dup-example-lab', files), bad).not.toBeNull();
  });

  it('request schema rejects traversal, NUL and duplicate paths', () => {
    const ok = { files: [{ path: '/etc/nginx/a.conf', content: 'x' }] };
    expect(createNginxRevisionSchema.safeParse(ok).success).toBe(true);
    for (const p of [
      '/etc/nginx/../shadow',
      '/etc/nginx/a/../../b',
      '/var/www/a.conf',
      'etc/nginx/a',
    ])
      expect(
        createNginxRevisionSchema.safeParse({ files: [{ path: p, content: 'x' }] }).success,
        p,
      ).toBe(false);
    expect(
      createNginxRevisionSchema.safeParse({
        files: [{ path: '/etc/nginx/a.conf', content: 'a\u0000' }],
      }).success,
    ).toBe(false);
    expect(createNginxRevisionSchema.safeParse({ files: [ok.files[0], ok.files[0]] }).success).toBe(
      false,
    );
  });

  it('planHash is order independent and binds every checksum and postcheck', () => {
    const f1 = { path: '/etc/nginx/a.conf', beforeSha256: null, afterSha256: 'b'.repeat(64) };
    const f2 = {
      path: '/etc/nginx/b.conf',
      beforeSha256: 'c'.repeat(64),
      afterSha256: 'd'.repeat(64),
    };
    const h = computePlanHash('srv', [f1, f2], []);
    expect(h).toMatch(/^[a-f0-9]{64}$/);
    expect(computePlanHash('srv', [f2, f1], [])).toBe(h);
    expect(computePlanHash('srv2', [f1, f2], [])).not.toBe(h);
    expect(computePlanHash('srv', [f1, { ...f2, afterSha256: 'e'.repeat(64) }], [])).not.toBe(h);
    expect(computePlanHash('srv', [f1, f2], [{ hostHeader: 'a', path: '/' }])).not.toBe(h);
  });

  it('unified diff shows removed and added lines; new files diff from /dev/null', () => {
    const d = unifiedDiff('/etc/nginx/a.conf', 'listen 80;\nroot /a;\n', 'listen 80;\nroot /b;\n');
    expect(d).toContain('--- a/etc/nginx/a.conf');
    expect(d).toContain('+++ b/etc/nginx/a.conf');
    expect(d).toContain('-root /a;');
    expect(d).toContain('+root /b;');
    expect(unifiedDiff('/etc/nginx/n.conf', null, 'x\n')).toContain('--- /dev/null');
    expect(contentSha256('x')).toBe(
      '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881',
    );
  });
});
