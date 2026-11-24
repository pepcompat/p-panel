/**
 * P7 resilience fixes (docs/RESILIENCE_REPORT.md): F-11 DB outage → 503, F-14 server_offline forSec.
 */
import {
  createAlertRuleSchema,
  effectiveForSec,
  ERROR_CODES,
  SERVER_OFFLINE_MIN_FOR_SEC,
  validateAlertRule,
  WEBHOOK_DELIVERY_RESULTS,
} from '@ppanel/shared-contracts';
import { Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';
import { isDatabaseUnavailable, toErrorResponse } from '../../src/common/exception.filter';

const known = (code: string) =>
  new Prisma.PrismaClientKnownRequestError(`boom ${code}`, { code, clientVersion: '6.19.3' });

describe('F-11: database unavailable → 503 SERVICE_UNAVAILABLE', () => {
  it.each([
    [
      'init error',
      new Prisma.PrismaClientInitializationError("Can't reach database server", '6.19.3', 'P1001'),
    ],
    ['P1001', known('P1001')],
    ['P1002', known('P1002')],
    ['P1017', known('P1017')],
    ['P2024 pool timeout', known('P2024')],
    [
      'unknown request error with ECONNREFUSED',
      new Prisma.PrismaClientUnknownRequestError('connect ECONNREFUSED 127.0.0.1:55432', {
        clientVersion: '6.19.3',
      }),
    ],
  ])('%s', (_name, err) => {
    expect(isDatabaseUnavailable(err)).toBe(true);
    const r = toErrorResponse(err);
    expect(r.status).toBe(503);
    expect(r.headers).toEqual({ 'Retry-After': '5' });
    expect(r.body.error).toMatchObject({
      code: ERROR_CODES.SERVICE_UNAVAILABLE,
      details: { retryAfterSec: 5 },
    });
    expect(JSON.stringify(r.body)).not.toContain('55432');
  });

  it('other database errors stay 500 INTERNAL_ERROR', () => {
    for (const err of [known('P2002'), known('P2025'), new Error('ECONNREFUSED somewhere else')]) {
      expect(isDatabaseUnavailable(err)).toBe(false);
      const r = toErrorResponse(err);
      expect([r.status, r.body.error.code]).toEqual([500, 'INTERNAL_ERROR']);
    }
  });
});

describe('F-14: server_offline forSec minimum', () => {
  const base = { name: 'r', scopeType: 'global' as const, kind: 'server_offline' as const };
  it('create: forSec < 90 → issue on forSec; omitted → 90; other kinds keep 0 / 60', () => {
    const short = createAlertRuleSchema.safeParse({ ...base, forSec: 15 });
    expect(short.success).toBe(false);
    if (!short.success) expect(short.error.issues.map((i) => i.path.join('.'))).toEqual(['forSec']);
    expect(createAlertRuleSchema.parse({ ...base, forSec: 90 }).forSec).toBe(90);
    expect(createAlertRuleSchema.parse(base).forSec).toBe(SERVER_OFFLINE_MIN_FOR_SEC);
    expect(createAlertRuleSchema.parse({ ...base, kind: 'app_down', forSec: 0 }).forSec).toBe(0);
    expect(createAlertRuleSchema.parse({ ...base, kind: 'app_down' }).forSec).toBe(60);
  });
  it('update: validated only when forSec is part of the patch', () => {
    const v = { kind: 'server_offline' as const, scopeType: 'global' as const, params: {} };
    expect(validateAlertRule(v)).toEqual([]);
    expect(validateAlertRule({ ...v, forSec: 30 })).toEqual([
      expect.objectContaining({ path: 'forSec' }),
    ]);
    expect(validateAlertRule({ ...v, forSec: 120 })).toEqual([]);
  });
  it('evaluator clamps legacy rules', () => {
    expect(effectiveForSec('server_offline', 15)).toBe(90);
    expect(effectiveForSec('server_offline', 300)).toBe(300);
    expect(effectiveForSec('metric_threshold', 0)).toBe(0);
  });
});

describe('F-7: delivery results', () => {
  it('queued / superseded are valid, non-failed results (backward compatible: old values kept)', () => {
    expect(WEBHOOK_DELIVERY_RESULTS).toEqual(
      expect.arrayContaining([
        'deployed',
        'awaiting_approval',
        'ignored',
        'failed',
        'building',
        'queued',
        'superseded',
      ]),
    );
  });
});
