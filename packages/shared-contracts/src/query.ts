/** Query Builder standard (COMPATTANA). Control params camelCase; filter fields snake_case. */
export const DEFAULT_PAGE = 1;
export const DEFAULT_LIMIT = 20;
export const MAX_LIMIT = 100;
export const FILTER_OPERATORS = [
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
] as const;
export type FilterOperator = (typeof FILTER_OPERATORS)[number];
