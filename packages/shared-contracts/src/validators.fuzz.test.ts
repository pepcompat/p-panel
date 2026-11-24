/**
 * P7.02 property tests for shared validators used at trust boundaries:
 * isValidHostname (nginx route template injection boundary), nginxPathSchema / hostPathSchema (agent
 * path policies), image reference regexes, branchMatches (webhook) and renderImageTemplate.
 * The former KNOWN GAPS (Center/agent path divergence, branchMatches ReDoS, invalid rendered tags)
 * were fixed in the P7.02 follow-up and are now regression guards.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  BRANCH_PATTERN_RE,
  branchMatches,
  GIT_URL_RE,
  gitSourceSchema,
  hostPathSchema,
  IMAGE_DIGEST_REF_RE,
  IMAGE_REPO_RE,
  IMAGE_TEMPLATE_RE,
  isDigestPinned,
  isValidHostname,
  MANAGED_CONTAINER_RE,
  nginxPathSchema,
  renderImageTemplate,
  SYSTEMD_UNIT_RE,
} from './index';
import { NUM_RUNS } from './fuzz-helpers.fuzz.test';

const anyString = fc.oneof(
  fc.string({ unit: 'binary', maxLength: 300 }),
  fc.string({
    unit: fc.constantFrom(...'abz09.-_/:;{}$ "\'\n\r\t\0*@[]%\\'.split('')),
    maxLength: 80,
  }),
);
const segs = (p: string) => p.split('/');

describe('isValidHostname — route template injection boundary', () => {
  it('accepted hostnames contain only LDH labels (no template/control characters)', () => {
    fc.assert(
      fc.property(fc.oneof(anyString, fc.domain()), (h) => {
        if (!isValidHostname(h)) return;
        expect(h.length).toBeLessThanOrEqual(253);
        expect(h).toMatch(/^[a-z0-9.-]+$/);
        const labels = h.split('.');
        expect(labels.length).toBeGreaterThanOrEqual(2);
        for (const l of labels) {
          expect(l.length).toBeGreaterThan(0);
          expect(l.length).toBeLessThanOrEqual(63);
          expect(l.startsWith('-') || l.endsWith('-')).toBe(false);
        }
        expect(labels[labels.length - 1]).toMatch(/^[a-z]/);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  it('rejects every string carrying an nginx-significant character', () => {
    fc.assert(
      fc.property(
        fc.domain(),
        fc.constantFrom(';', '{', '}', '$', ' ', '"', "'", '\n', '\0', '*', '/', '\\', '#'),
        fc.nat(),
        (d, c, at) => {
          const i = at % (d.length + 1);
          expect(isValidHostname(d.slice(0, i) + c + d.slice(i))).toBe(false);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });
  it('non-strings are rejected', () => {
    fc.assert(
      fc.property(fc.anything(), (v) => typeof v === 'string' || !isValidHostname(v)),
      { numRuns: NUM_RUNS },
    );
  });
});

describe('nginxPathSchema / hostPathSchema — agent path policies', () => {
  const nginxish = fc
    .array(
      fc.oneof(
        fc.constantFrom('..', '.', '', 'conf.d', 'ppanel-managed', 'a.conf', '..x'),
        fc.string({ maxLength: 6 }),
      ),
      { maxLength: 6 },
    )
    .map((p) => '/etc/nginx/' + p.join('/'));
  it('accepted nginx paths stay under /etc/nginx/ with no traversal, // or NUL', () => {
    fc.assert(
      fc.property(fc.oneof(nginxish, anyString), (p) => {
        if (!nginxPathSchema.safeParse(p).success) return;
        expect(p.startsWith('/etc/nginx/')).toBe(true);
        expect(segs(p)).not.toContain('..');
        expect(p).not.toContain('//');
        expect(p).not.toMatch(/[\0\n\r\\ ]/);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  const hostish = fc
    .array(
      fc.oneof(
        fc.constantFrom('..', '.', '', 'proc', 'srv', 'www', '-x'),
        fc.string({ maxLength: 6 }),
      ),
      { maxLength: 6 },
    )
    .map((p) => '/' + p.join('/'));
  it('accepted host paths are absolute with no .. segment, // or control characters', () => {
    fc.assert(
      fc.property(fc.oneof(hostish, anyString), (p) => {
        if (!hostPathSchema.safeParse(p).success) return;
        expect(p.startsWith('/')).toBe(true);
        expect(segs(p)).not.toContain('..');
        expect(p).not.toContain('//');
        expect(p).not.toMatch(/[\0\n\r\\ ]/);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  // The Go agent (nginxops.ValidPath / backupops.CheckHostPath / buildops.relPathOK) refuses these;
  // the Center schemas now refuse them too (previously only rejected on the agent).
  for (const p of ['/etc/nginx/./x', '/etc/nginx/x/', '/etc/nginx/.', '/etc/nginx/a/../b'])
    it(`nginxPathSchema rejects ${JSON.stringify(p)} (agent parity)`, () =>
      expect(nginxPathSchema.safeParse(p).success).toBe(false));
  for (const p of [
    '/a/./b',
    '/srv/',
    '/',
    '/.',
    '/proc',
    '/proc/self/environ',
    '/sys/kernel',
    '/dev/sda',
    '/run/secrets',
  ])
    it(`hostPathSchema rejects ${JSON.stringify(p)} (agent parity)`, () =>
      expect(hostPathSchema.safeParse(p).success).toBe(false));
  for (const p of ['/srv/data', '/etc/app', '/procx', '/var/run-x', '/etc/nginx/conf.d/a.conf'])
    it(`hostPathSchema accepts ${JSON.stringify(p)}`, () =>
      expect(hostPathSchema.safeParse(p).success).toBe(true));
  it('nginxPathSchema accepts canonical paths', () => {
    for (const p of [
      '/etc/nginx/nginx.conf',
      '/etc/nginx/ppanel-managed/a/b.conf',
      '/etc/nginx/.x',
    ])
      expect(nginxPathSchema.safeParse(p).success).toBe(true);
  });
  it('accepted nginx/host paths have no "." segment and no trailing slash', () => {
    fc.assert(
      fc.property(fc.oneof(nginxish, hostish), (p) => {
        for (const schema of [nginxPathSchema, hostPathSchema]) {
          if (!schema.safeParse(p).success) continue;
          expect(segs(p)).not.toContain('.');
          expect(p.endsWith('/')).toBe(false);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });
  it('gitSourceSchema.subdir rejects .git / .. / absolute / // (agent relPathOK parity)', () => {
    const src = (subdir: string) =>
      gitSourceSchema.safeParse({
        url: 'https://git.example/a/b',
        commitSha: 'a'.repeat(40),
        subdir,
      });
    for (const bad of ['.git', 'a/.git', '.git/hooks', 'a/.GIT/x', '../x', '/abs', 'a//b'])
      expect(src(bad).success).toBe(false);
    for (const ok of ['', 'apps/web', '.github', 'a/.gitkeep-dir', 'a/'])
      expect(src(ok).success).toBe(true);
  });
});

describe('image / name regexes', () => {
  const hex = fc.stringMatching(/^[a-f0-9]{64}$/);
  it('IMAGE_DIGEST_REF_RE: accepted refs end in @sha256:<64 lowercase hex> and carry no option/space/traversal', () => {
    const near = fc
      .tuple(
        fc.oneof(
          fc.constantFrom(
            'r.example/a',
            'R.example/a',
            '-r/a',
            'r..e/a',
            'r/a/',
            'localhost:5000/a',
            'a b/c',
          ),
          fc.string({ maxLength: 20 }),
        ),
        fc.oneof(hex, fc.string({ maxLength: 70 })),
      )
      .map(([r, h]) => `${r}@sha256:${h}`);
    fc.assert(
      fc.property(fc.oneof(near, anyString), (s) => {
        if (!IMAGE_DIGEST_REF_RE.test(s)) return;
        expect(s).toMatch(/@sha256:[a-f0-9]{64}$/);
        expect(s.startsWith('-')).toBe(false);
        expect(s).not.toMatch(/\s|\.\.|\/\/|[A-Z]/);
        expect(isDigestPinned(s)).toBe(true);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  it('IMAGE_REPO_RE never carries a tag or digest; GIT_URL_RE never credentials/options', () => {
    fc.assert(
      fc.property(anyString, (s) => {
        if (IMAGE_REPO_RE.test(s)) {
          expect(s).not.toContain('@');
          expect(s.split('/').slice(1).join('/')).not.toContain(':');
        }
        if (GIT_URL_RE.test(s)) {
          expect(s).toMatch(/^(https|git):\/\//);
          expect(s).not.toMatch(/@|\s|\\|%|\?|#/);
        }
        if (MANAGED_CONTAINER_RE.test(s)) expect(s).toMatch(/^ppanel-[a-z0-9-]+-[a-f0-9]{8}$/);
        if (SYSTEMD_UNIT_RE.test(s)) expect(s.startsWith('-')).toBe(false);
      }),
      { numRuns: NUM_RUNS },
    );
  });
});

describe('branchMatches / renderImageTemplate (webhook auto-deploy)', () => {
  const branch = fc.stringMatching(/^[A-Za-z0-9._\/-]{1,60}$/);
  const pattern = fc
    .stringMatching(/^[A-Za-z0-9._\/*-]{1,30}$/)
    .filter((p) => (p.match(/\*/g) ?? []).length <= 3);
  it('never throws; exact patterns compare literally; regex metacharacters are literal', () => {
    fc.assert(
      fc.property(pattern, branch, (p, b) => {
        const m = branchMatches(p, b);
        if (!p.includes('*')) expect(m).toBe(p === b);
        else {
          const [pre, ...rest] = p.split('*');
          const post = rest[rest.length - 1]!;
          if (m) {
            expect(b.startsWith(pre!)).toBe(true);
            expect(b.endsWith(post)).toBe(true);
          }
          expect(branchMatches(p, p.replace(/\*/g, ''))).toBe(true);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });
  // Formerly exponential backtracking (the glob became /^.*a.*a…$/, ~5.7 s for this input); the
  // matcher is now a two-pointer glob without RegExp.
  it('ReDoS guard: branchMatches("*a*a*a*a*a*a*c", "a"*60) finishes within 50 ms', () => {
    const p = '*a'.repeat(6) + '*c';
    expect(BRANCH_PATTERN_RE.test(p)).toBe(true);
    const t = performance.now();
    expect(branchMatches(p, 'a'.repeat(60))).toBe(false);
    expect(branchMatches('*a'.repeat(5) + '*c', 'a'.repeat(60))).toBe(false);
    expect(performance.now() - t).toBeLessThan(50);
  });
  it('ReDoS guard: worst-case pattern/branch at maximum lengths finishes within 50 ms', () => {
    const p = '*a'.repeat(126) + '*c'; // 254 chars
    expect(BRANCH_PATTERN_RE.test(p)).toBe(true);
    const t = performance.now();
    for (let i = 0; i < 10; i++) expect(branchMatches(p, 'a'.repeat(255))).toBe(false);
    expect(performance.now() - t).toBeLessThan(50);
  });
  it('branchMatches agrees with a reference glob (`*` = any run, including `/`)', () => {
    const ref = (p: string, b: string) => {
      // DP reference matcher (no regex)
      const m = p.length;
      const n = b.length;
      let prev = Array<boolean>(n + 1).fill(false);
      prev[0] = true;
      for (let i = 1; i <= m; i++) {
        const cur = Array<boolean>(n + 1).fill(false);
        cur[0] = prev[0]! && p[i - 1] === '*';
        for (let j = 1; j <= n; j++)
          cur[j] =
            p[i - 1] === '*' ? prev[j]! || cur[j - 1]! : prev[j - 1]! && p[i - 1] === b[j - 1];
        prev = cur;
      }
      return prev[n]!;
    };
    const small = fc.stringMatching(/^[ab\/*]{0,10}$/);
    const smallB = fc.stringMatching(/^[ab\/]{0,12}$/);
    fc.assert(
      fc.property(fc.oneof(pattern, small), fc.oneof(branch, smallB), (p, b) => {
        if (!p.includes('*')) return;
        expect(branchMatches(p, b)).toBe(ref(p, b));
      }),
      { numRuns: NUM_RUNS },
    );
    expect(branchMatches('release/*', 'release/1.2/hotfix')).toBe(true);
    expect(branchMatches('*', '')).toBe(true);
    expect(branchMatches('feat-*-x', 'feat--x')).toBe(true);
    expect(branchMatches('feat-*-x', 'feat-x')).toBe(false);
  });

  const template = fc
    .tuple(
      fc.constantFrom('ghcr.io/acme/web', 'registry.example:5000/a/b'),
      fc.constantFrom('{sha}', '{sha7}', '{branch}-{sha7}', 'v1-{sha}', '{branch}'),
    )
    .map(([r, t]) => `${r}:${t}`);
  const sha = fc.stringMatching(/^[a-f0-9]{40}$/);
  it('rendered references never contain characters outside the Docker reference alphabet', () => {
    fc.assert(
      fc.property(template, sha, fc.string({ unit: 'binary', maxLength: 300 }), (t, s, b) => {
        expect(IMAGE_TEMPLATE_RE.test(t)).toBe(true);
        const out = renderImageTemplate(t, s, b);
        if (out === null) {
          // only a template whose tag starts with / consists of {branch} can fail to render
          expect(t).toContain('{branch}');
          return;
        }
        expect(out).toMatch(/^[a-z0-9.:\/-]+:[A-Za-z0-9_.-]*$/);
        expect(out).not.toMatch(/\{sha7?\}|\{branch\}/);
      }),
      { numRuns: NUM_RUNS },
    );
  });
  // Docker tags: [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}. Empty, long or '-'/'.'-leading branches used to
  // render invalid tags (counterexample: template "…:{branch}", branch "" → "ghcr.io/acme/web:").
  it('renderImageTemplate("…:{branch}", sha, "") fails (null) instead of an empty tag', () => {
    expect(renderImageTemplate('ghcr.io/acme/web:{branch}', 'a'.repeat(40), '')).toBeNull();
    expect(renderImageTemplate('ghcr.io/acme/web:{branch}', 'a'.repeat(40), '-/.')).toBeNull();
    expect(renderImageTemplate('ghcr.io/acme/web:{branch}', 'a'.repeat(40), '.feat/x')).toBe(
      'ghcr.io/acme/web:feat-x',
    );
  });
  it('renderImageTemplate yields a valid Docker tag for any branch (or null)', () => {
    fc.assert(
      fc.property(
        sha,
        fc.oneof(
          fc.stringMatching(/^[A-Za-z0-9._\/-]{1,255}$/),
          fc.string({ unit: 'binary', maxLength: 300 }),
        ),
        fc.constantFrom('{branch}-{sha7}', '{branch}', 'v1-{branch}-{branch}', 'b-{branch}-{sha}'),
        (s, b, tagT) => {
          const out = renderImageTemplate(`ghcr.io/acme/web:${tagT}`, s, b);
          const sanitized = b.replace(/[^A-Za-z0-9_.-]/g, '-').replace(/^[.-]+/, '');
          if (out === null) {
            // only possible when the template starts with {branch} and nothing usable is left
            expect(tagT.startsWith('{branch}') && sanitized === '').toBe(true);
            return;
          }
          const tag = out.slice('ghcr.io/acme/web:'.length);
          expect(tag).toMatch(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/);
          if (tagT.includes('{sha7}')) expect(tag.endsWith(s.slice(0, 7))).toBe(true);
          if (tagT.includes('{sha}')) expect(tag.endsWith(s)).toBe(true);
        },
      ),
      { numRuns: NUM_RUNS },
    );
  });
  it('IMAGE_TEMPLATE_RE requires an explicit registry host', () => {
    for (const ok of [
      'ghcr.io/acme/web:{sha}',
      'registry.example:5000/a/b:{sha7}',
      'localhost/a:{sha}',
      'localhost:5000/a:{sha}',
      'reg:5000/app:sha-{sha7}',
    ])
      expect(IMAGE_TEMPLATE_RE.test(ok)).toBe(true);
    for (const bad of ['acme/web:{sha}', 'library/nginx:{sha7}', 'localhostx/a:{sha}', 'web:{sha}'])
      expect(IMAGE_TEMPLATE_RE.test(bad)).toBe(false);
  });
});
