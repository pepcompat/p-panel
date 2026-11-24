/**
 * Shared secret-redaction patterns for log lines (P5). Mirrored in Go (apps/agent) — both sides must
 * pass `testdata/redaction-golden.json`. Order matters: more specific patterns first.
 * Each pattern keeps the non-secret prefix (group 1) and replaces the secret part with [REDACTED].
 */
export const REDACTED = '[REDACTED]';

export interface RedactionPattern {
  name: string;
  /** JavaScript/Go-compatible regex source (RE2 subset: no lookbehind/backreferences). */
  source: string;
  flags: string;
  /** Replacement using $1 for the kept prefix. */
  replacement: string;
}

export const REDACTION_PATTERNS: readonly RedactionPattern[] = [
  {
    name: 'private_key_block',
    source: '-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----',
    flags: 'g',
    replacement: REDACTED,
  },
  {
    name: 'url_userinfo',
    source: '([a-zA-Z][a-zA-Z0-9+.-]*://[^\\s:/@]+:)[^\\s@/]+@',
    flags: 'g',
    replacement: `$1${REDACTED}@`,
  },
  {
    name: 'authorization_header',
    source:
      '((?:^|[\\s"\'{,])(?:proxy-)?authorization["\']?\\s*[:=]\\s*["\']?)(?:bearer |basic |token )?[^\\s"\',}]+',
    flags: 'gi',
    replacement: `$1${REDACTED}`,
  },
  {
    name: 'bearer_token',
    source: '(\\bbearer\\s+)[A-Za-z0-9\\-._~+/]+=*',
    flags: 'gi',
    replacement: `$1${REDACTED}`,
  },
  {
    name: 'jwt',
    source: '\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}',
    flags: 'g',
    replacement: REDACTED,
  },
  {
    name: 'github_token',
    source: '\\bgh[pousr]_[A-Za-z0-9]{20,}',
    flags: 'g',
    replacement: REDACTED,
  },
  {
    name: 'slack_token',
    source: '\\bxox[abposr]-[A-Za-z0-9-]{10,}',
    flags: 'g',
    replacement: REDACTED,
  },
  {
    name: 'aws_access_key',
    source: '\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b',
    flags: 'g',
    replacement: REDACTED,
  },
  {
    name: 'ppanel_enrollment_token',
    source: '\\bppe_[A-Za-z0-9_-]{16,}',
    flags: 'g',
    replacement: REDACTED,
  },
  {
    name: 'key_value_secret',
    source:
      '((?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|passw(?:or)?d|pwd)["\']?\\s*[:=]\\s*["\']?)[^\\s"\'&,;}]+',
    flags: 'gi',
    replacement: `$1${REDACTED}`,
  },
];

/** Shortest known secret value redacted verbatim (Go: redact.MinSecretLen). */
export const MIN_SECRET_LEN = 6;
/** Bound of the (known values ∘ patterns) fixpoint loop (Go: maxSecretPasses). */
const MAX_SECRET_PASSES = 8;

const COMPILED = REDACTION_PATTERNS.map((p) => ({ re: new RegExp(p.source, p.flags), p }));

/** Shared patterns only (Go: redact.Line). */
export function redactPatterns(line: string): string {
  let out = line;
  for (const { re, p } of COMPILED) {
    re.lastIndex = 0;
    out = out.replace(re, p.replacement);
  }
  return out;
}

/** Mark every (overlapping) occurrence of every value, merge ranges, replace each range once. */
function replaceKnownOnce(s: string, values: readonly string[]): string | null {
  const spans: Array<[number, number]> = [];
  for (const v of values) {
    for (let i = s.indexOf(v); i >= 0; i = s.indexOf(v, i + 1)) spans.push([i, i + v.length]);
  }
  if (spans.length === 0) return null;
  spans.sort((a, b) => a[0] - b[0]);
  let out = '';
  let last = 0;
  let [a, b] = spans[0]!;
  for (const [x, y] of spans.slice(1)) {
    if (x <= b) {
      if (y > b) b = y;
      continue;
    }
    out += s.slice(last, a) + REDACTED;
    last = b;
    [a, b] = [x, y];
  }
  out += s.slice(last, a) + REDACTED + s.slice(b);
  return out;
}

/**
 * Apply all shared patterns, then exact known secret values — mirrors the Go agent's
 * `Redactor.Redact` (apps/agent/internal/redact): values shorter than 6 chars or contained in the
 * `[REDACTED]` marker are ignored; every occurrence (overlapping included) is replaced in one pass;
 * (values ∘ patterns) is repeated until a fixed point, and if that does not converge within 8 passes
 * the whole line is replaced (fail closed). The result never contains a known value and redactLine is
 * idempotent on its own output.
 */
export function redactLine(line: string, knownSecrets: readonly string[] = []): string {
  let s = redactPatterns(line);
  const values = [...new Set(knownSecrets)]
    .filter((v) => v.length >= MIN_SECRET_LEN && !REDACTED.includes(v))
    .sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
  if (values.length === 0) return s;
  for (let pass = 0; pass < MAX_SECRET_PASSES; pass++) {
    const replaced = replaceKnownOnce(s, values);
    if (replaced === null) return s;
    const out = redactPatterns(replaced);
    if (out === s) return s;
    s = out;
  }
  const replaced = replaceKnownOnce(s, values);
  if (replaced !== null || redactPatterns(s) !== s) return REDACTED;
  return s;
}
