import { describe, expect, it } from 'vitest';
import { JsonLogger, redact } from '../../src/common/logger';
import { requestContext } from '../../src/common/request-context';

describe('structured JSON logger', () => {
  it('emits {level,message,timestamp,requestId} and redacts secrets', () => {
    const lines: string[] = [];
    const log = new JsonLogger('debug', { write: (l) => lines.push(l) });
    requestContext.run({ requestId: 'req-1' }, () => {
      log.emit(
        'info',
        'login with Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl token ppe_abcdefghijklmnopqrstuvwxyz',
        {
          password: 'hunter2',
          refreshToken: 'abc',
          nested: { csrPem: '---', apiKey: 'k', fine: 'visible' },
          authorization: 'Bearer zzz',
        },
      );
    });
    const e = JSON.parse(lines[0]!);
    expect(e).toMatchObject({
      level: 'info',
      requestId: 'req-1',
      password: '[REDACTED]',
      refreshToken: '[REDACTED]',
      authorization: '[REDACTED]',
    });
    expect(e.nested).toEqual({ csrPem: '[REDACTED]', apiKey: '[REDACTED]', fine: 'visible' });
    expect(new Date(e.timestamp).toISOString()).toBe(e.timestamp);
    expect(lines[0]).not.toMatch(/hunter2|eyJhbGci|ppe_abcdef/);
  });

  it('respects min level', () => {
    const lines: string[] = [];
    const log = new JsonLogger('warn', { write: (l) => lines.push(l) });
    log.emit('info', 'x');
    log.emit('error', 'y');
    expect(lines).toHaveLength(1);
  });

  it('redacts private keys and argon2 hashes in free text, keeps booleans', () => {
    const out = redact({
      msg: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY----- $argon2id$v=19$m=19456,t=2,p=1$abc$def', // gitleaks:allow (fake test fixture)
      mfaEnabled: true,
    }) as Record<string, string>;
    expect(out.msg).not.toContain('AAAA');
    expect(out.msg).not.toContain('$argon2id$');
    expect(out.mfaEnabled).toBe(true);
    expect(redact('db postgres://ppanel:s3cret@127.0.0.1:5432/x')).toBe(
      'db postgres://ppanel:[REDACTED]@127.0.0.1:5432/x',
    );
  });
});
