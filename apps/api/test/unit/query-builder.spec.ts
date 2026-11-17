import { describe, expect, it } from 'vitest';
import { AppError } from '../../src/common/app-error';
import { buildWhere, parseQuery, type FieldMap } from '../../src/common/query-builder';

const fields: FieldMap = {
  action: { prop: 'action', type: 'string' },
  actor_id: { prop: 'actorId', type: 'string' },
  created_at: { prop: 'createdAt', type: 'date' },
  attempt: { prop: 'attempt', type: 'number' },
};
const opts = { sortable: ['createdAt', 'action'] };

describe('query builder', () => {
  it('defaults', () => {
    const q = parseQuery('/x', opts);
    expect(q).toMatchObject({ page: 1, limit: 20, skip: 0, sort: 'createdAt', order: 'desc', filters: [] });
  });
  it('parses control params and snake_case sort', () => {
    const q = parseQuery('/x?page=3&limit=10&sort=created_at&order=asc&q=login', opts);
    expect(q).toMatchObject({ page: 3, limit: 10, skip: 20, sort: 'createdAt', order: 'asc', q: 'login' });
  });
  it('rejects out-of-range limit / bad sort / bad order', () => {
    expect(() => parseQuery('/x?limit=101', opts)).toThrow(AppError);
    expect(() => parseQuery('/x?limit=0', opts)).toThrow(AppError);
    expect(() => parseQuery('/x?sort=password', opts)).toThrow(AppError);
    expect(() => parseQuery('/x?order=sideways', opts)).toThrow(AppError);
  });
  it('builds typed operators', () => {
    const q = parseQuery(
      '/x?action=a&actor_id[in]=u1,u2&created_at[gte]=2026-01-01T00:00:00Z&attempt[between]=1,3&action[ne]=b&actor_id[isnull]=false',
      opts,
    );
    expect(buildWhere(q, fields)).toEqual({
      AND: [
        { action: { equals: 'a' } },
        { actorId: { in: ['u1', 'u2'] } },
        { createdAt: { gte: new Date('2026-01-01T00:00:00Z') } },
        { attempt: { gte: 1, lte: 3 } },
        { action: { not: 'b' } },
        { NOT: { actorId: null } },
      ],
    });
  });
  it('supports or[i][field] groups', () => {
    const q = parseQuery('/x?or[0][action]=a&or[0][actor_id]=u', opts);
    expect(buildWhere(q, fields)).toEqual({ AND: [{ OR: [{ action: { equals: 'a' } }, { actorId: { equals: 'u' } }] }] });
  });
  it('rejects unknown fields, operators and bad values', () => {
    expect(() => buildWhere(parseQuery('/x?password=1', opts), fields)).toThrow(AppError);
    expect(() => buildWhere(parseQuery('/x?action[regex]=1', opts), fields)).toThrow(AppError);
    expect(() => buildWhere(parseQuery('/x?created_at[gte]=yesterday', opts), fields)).toThrow(AppError);
    expect(() => buildWhere(parseQuery('/x?attempt[contains]=1', opts), fields)).toThrow(AppError);
    expect(() => parseQuery('/x?a[b][c]=1', opts)).toThrow(AppError);
  });
});
