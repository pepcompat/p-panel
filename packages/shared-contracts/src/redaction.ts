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

/** Apply all shared patterns, then exact known secret values (longest first, ≥ 6 chars). */
export function redactLine(line: string, knownSecrets: readonly string[] = []): string {
  let out = line;
  for (const p of REDACTION_PATTERNS)
    out = out.replace(new RegExp(p.source, p.flags), p.replacement);
  const secrets = [...knownSecrets]
    .filter((s) => s.length >= 6)
    .sort((a, b) => b.length - a.length);
  for (const s of secrets) out = out.split(s).join(REDACTED);
  return out;
}
