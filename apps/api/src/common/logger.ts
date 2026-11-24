import type { LoggerService } from '@nestjs/common';
import { currentRequestId } from './request-context';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';
const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40, fatal: 50 };

const SECRET_KEY_RE =
  /pass(word|phrase)?|secret|token|ticket|authorization|cookie|api[-_]?key|private[-_]?key|private|credential|recovery|csr|otp|^code$|set-cookie|master/i;
const VALUE_PATTERNS: Array<[RegExp, string]> = [
  [/ppe_[A-Za-z0-9_-]{10,}/g, 'ppe_[REDACTED]'],
  [/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g, '[REDACTED_JWT]'],
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]'],
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    '[REDACTED_PRIVATE_KEY]',
  ],
  [/\$argon2id?\$[^\s"']+/g, '[REDACTED_HASH]'],
  [/([a-z][a-z0-9+.-]*:\/\/[^:@\s/]+:)[^@\s]+@/gi, '$1[REDACTED]@'],
];

export function redactString(s: string): string {
  let out = s;
  for (const [re, rep] of VALUE_PATTERNS) out = out.replace(re, rep);
  return out;
}

/** Recursively redact secret-looking keys and values. Never throws. */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[TRUNCATED]';
  if (typeof value === 'string') return redactString(value);
  if (value === null || typeof value !== 'object') return value;
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactString(value.message),
      stack: value.stack && redactString(value.stack),
    };
  }
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] =
      SECRET_KEY_RE.test(k) && v !== undefined && v !== null && typeof v !== 'boolean'
        ? '[REDACTED]'
        : redact(v, depth + 1);
  }
  return out;
}

/** Shortest secret value that is replaced verbatim (shorter values would shred unrelated text). */
export const MIN_KNOWN_SECRET_LEN = 4;

/**
 * Redacts *known* secret values (e.g. an application's decrypted env secrets) wherever they appear in
 * strings, object keys excluded, recursively. Used for `container.logs` output and job results.
 */
export function redactKnownValues<T>(value: T, secrets: readonly string[], depth = 0): T {
  const list = [...new Set(secrets.filter((s) => s.length >= MIN_KNOWN_SECRET_LEN))].sort(
    (a, b) => b.length - a.length,
  );
  if (list.length === 0) return value;
  const scrub = (v: unknown, d: number): unknown => {
    if (d > 12) return v;
    if (typeof v === 'string') {
      let out = v;
      for (const s of list) if (out.includes(s)) out = out.split(s).join('[REDACTED]');
      return out;
    }
    if (Array.isArray(v)) return v.map((x) => scrub(x, d + 1));
    if (v !== null && typeof v === 'object') {
      const o: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) o[k] = scrub(x, d + 1);
      return o;
    }
    return v;
  };
  return scrub(value, depth) as T;
}

/** True when any known secret value occurs anywhere in `value` (serialized). */
export function containsKnownValue(value: unknown, secrets: readonly string[]): boolean {
  return (
    JSON.stringify(redactKnownValues(value ?? null, secrets)) !== JSON.stringify(value ?? null)
  );
}

export interface LogSink {
  write(line: string): void;
}

export class JsonLogger implements LoggerService {
  private min: number;
  constructor(
    level: LogLevel = 'info',
    private readonly sink: LogSink = process.stdout,
  ) {
    this.min = LEVELS[level];
  }

  setLevel(level: LogLevel): void {
    this.min = LEVELS[level];
  }

  emit(level: LogLevel, message: unknown, fields: Record<string, unknown> = {}): void {
    if (LEVELS[level] < this.min) return;
    const entry: Record<string, unknown> = {
      level,
      message: typeof message === 'string' ? redactString(message) : redact(message),
      timestamp: new Date().toISOString(),
      requestId: (fields.requestId as string | undefined) ?? currentRequestId(),
      ...(redact(fields) as Record<string, unknown>),
    };
    if (entry.requestId === undefined) delete entry.requestId;
    try {
      this.sink.write(JSON.stringify(entry) + '\n');
    } catch {
      /* logging must never crash the process */
    }
  }

  // ---- Nest LoggerService ----
  log(message: unknown, ...rest: unknown[]): void {
    this.emit('info', message, ctx(rest));
  }
  error(message: unknown, ...rest: unknown[]): void {
    const [stack, context] = rest as [string | undefined, string | undefined];
    this.emit('error', message, {
      ...(context ? { context } : {}),
      ...(typeof stack === 'string' ? { stack } : {}),
    });
  }
  warn(message: unknown, ...rest: unknown[]): void {
    this.emit('warn', message, ctx(rest));
  }
  debug(message: unknown, ...rest: unknown[]): void {
    this.emit('debug', message, ctx(rest));
  }
  verbose(message: unknown, ...rest: unknown[]): void {
    this.emit('debug', message, ctx(rest));
  }
  fatal(message: unknown, ...rest: unknown[]): void {
    this.emit('fatal', message, ctx(rest));
  }
}

function ctx(rest: unknown[]): Record<string, unknown> {
  const last = rest[rest.length - 1];
  return typeof last === 'string' ? { context: last } : {};
}

/** Process-wide logger; level set from config at boot. */
export const logger = new JsonLogger((process.env.LOG_LEVEL as LogLevel | undefined) ?? 'info');
