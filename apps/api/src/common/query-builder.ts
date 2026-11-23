import { DEFAULT_LIMIT, DEFAULT_PAGE, MAX_LIMIT, type Paginate } from '@ppanel/shared-contracts';
import { AppError } from './app-error';

/**
 * Query Builder standard: page, limit, sort, order, q, `field[op]=value`, `or[i][field]=value`.
 * Field names are snake_case and must be allow-listed per endpoint; values are typed and validated.
 */
export type FieldType = 'string' | 'uuid' | 'date' | 'number' | 'boolean';
export interface FieldDef {
  prop: string;
  type: FieldType;
}
export type FieldMap = Record<string, FieldDef>;

export interface Filter {
  field: string;
  op: string;
  value: string;
}
export interface ParsedQuery {
  page: number;
  limit: number;
  skip: number;
  sort: string;
  order: 'asc' | 'desc';
  q?: string;
  filters: Filter[];
  or: Filter[][];
  raw: URLSearchParams;
}

const CONTROL = new Set([
  'page',
  'limit',
  'sort',
  'order',
  'q',
  'searchBy',
  'searchType',
  'fields',
  'include',
  'waitSec',
]);
const FILTER_RE = /^([a-z][a-z0-9_]*)(?:\[([a-z]+)\])?$/;
const OR_RE = /^or\[(\d{1,2})\]\[([a-z][a-z0-9_]*)\](?:\[([a-z]+)\])?$/;
const OPS = new Set([
  'eq',
  'ne',
  'in',
  'nin',
  'gt',
  'gte',
  'lt',
  'lte',
  'between',
  'bt',
  'contains',
  'like',
  'prefix',
  'isnull',
]);

function snakeToCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

export function parseQuery(
  originalUrl: string,
  opts: { sortable: string[]; defaultSort?: string },
): ParsedQuery {
  const qs = originalUrl.includes('?') ? originalUrl.slice(originalUrl.indexOf('?') + 1) : '';
  const raw = new URLSearchParams(qs);
  const page = intParam(raw.get('page'), DEFAULT_PAGE, 1, 1_000_000, 'page');
  const limit = intParam(raw.get('limit'), DEFAULT_LIMIT, 1, MAX_LIMIT, 'limit');
  const orderRaw = (raw.get('order') ?? 'desc').toLowerCase();
  if (orderRaw !== 'asc' && orderRaw !== 'desc')
    throw AppError.badRequest('order must be asc or desc');
  const defaultSort = opts.defaultSort ?? 'createdAt';
  // accept camelCase or snake_case sort names
  const sortRaw = raw.get('sort');
  const sort = sortRaw ? snakeToCamel(sortRaw) : defaultSort;
  if (!opts.sortable.includes(sort))
    throw AppError.badRequest(`sort must be one of: ${opts.sortable.join(', ')}`);
  const q = raw.get('q')?.trim() || undefined;
  if (q && q.length > 200) throw AppError.badRequest('q too long');

  const filters: Filter[] = [];
  const orGroups = new Map<number, Filter[]>();
  for (const [key, value] of raw.entries()) {
    if (CONTROL.has(key)) continue;
    const orm = OR_RE.exec(key);
    if (orm) {
      const idx = Number(orm[1]);
      const list = orGroups.get(idx) ?? [];
      list.push({ field: orm[2]!, op: orm[3] ?? 'eq', value });
      orGroups.set(idx, list);
      continue;
    }
    const m = FILTER_RE.exec(key);
    if (!m) throw AppError.badRequest(`Unsupported query parameter: ${key}`);
    filters.push({ field: m[1]!, op: m[2] ?? 'eq', value });
  }
  return {
    page,
    limit,
    skip: (page - 1) * limit,
    sort,
    order: orderRaw,
    q,
    filters,
    or: [...orGroups.entries()].sort((a, b) => a[0] - b[0]).map(([, f]) => f),
    raw,
  };
}

function intParam(v: string | null, def: number, min: number, max: number, name: string): number {
  if (v === null || v === '') return def;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max)
    throw AppError.badRequest(`${name} must be an integer between ${min} and ${max}`);
  return n;
}

function coerce(def: FieldDef, field: string, v: string): unknown {
  switch (def.type) {
    case 'number': {
      const n = Number(v);
      if (!Number.isFinite(n)) throw AppError.badRequest(`${field}: expected number`);
      return n;
    }
    case 'boolean':
      if (v !== 'true' && v !== 'false') throw AppError.badRequest(`${field}: expected true|false`);
      return v === 'true';
    case 'date': {
      const d = new Date(v);
      if (Number.isNaN(d.getTime())) throw AppError.badRequest(`${field}: expected ISO-8601 date`);
      return d;
    }
    case 'uuid':
      if (!/^[0-9a-f-]{36}$/i.test(v)) throw AppError.badRequest(`${field}: expected uuid`);
      return v;
    default:
      if (v.length > 200) throw AppError.badRequest(`${field}: value too long`);
      return v;
  }
}

function filterToWhere(f: Filter, fields: FieldMap): Record<string, unknown> {
  const def = fields[f.field];
  if (!def)
    throw AppError.badRequest(`Unsupported filter field: ${f.field}`, {
      allowed: Object.keys(fields),
    });
  if (!OPS.has(f.op)) throw AppError.badRequest(`Unsupported operator: ${f.op}`);
  const list = () => f.value.split(',').map((x) => coerce(def, f.field, x.trim()));
  let cond: unknown;
  switch (f.op) {
    case 'eq':
      cond = { equals: coerce(def, f.field, f.value) };
      break;
    case 'ne':
      cond = { not: coerce(def, f.field, f.value) };
      break;
    case 'in':
      cond = { in: list() };
      break;
    case 'nin':
      cond = { notIn: list() };
      break;
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      cond = { [f.op]: coerce(def, f.field, f.value) };
      break;
    case 'between':
    case 'bt': {
      const [a, b] = list();
      if (a === undefined || b === undefined)
        throw AppError.badRequest(`${f.field}[${f.op}] expects "from,to"`);
      cond = { gte: a, lte: b };
      break;
    }
    case 'contains':
    case 'like':
      if (def.type !== 'string') throw AppError.badRequest(`${f.op} only applies to text fields`);
      cond = { contains: f.value, mode: 'insensitive' };
      break;
    case 'prefix':
      if (def.type !== 'string') throw AppError.badRequest(`prefix only applies to text fields`);
      cond = { startsWith: f.value };
      break;
    case 'isnull':
      return f.value === 'false' ? { NOT: { [def.prop]: null } } : { [def.prop]: null };
  }
  return { [def.prop]: cond };
}

/** Builds a Prisma `where` (AND of filters, plus OR groups). */
export function buildWhere(
  pq: ParsedQuery,
  fields: FieldMap,
  skip: string[] = [],
): Record<string, unknown> {
  const and: Record<string, unknown>[] = pq.filters
    .filter((f) => !skip.includes(f.field))
    .map((f) => filterToWhere(f, fields));
  for (const group of pq.or) and.push({ OR: group.map((f) => filterToWhere(f, fields)) });
  return and.length ? { AND: and } : {};
}

export function paginate(pq: ParsedQuery, total: number): Paginate {
  return { page: pq.page, limit: pq.limit, total };
}
