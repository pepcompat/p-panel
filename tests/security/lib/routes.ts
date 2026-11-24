/**
 * Route inventory from Nest metadata (controller + handler `path`/`method`, `@Public`, coarse
 * `@RequirePermission`) cross-checked against the live Express router stack.
 */
import { AppModule } from '../../../apps/api/src/app.module';
import { IS_PUBLIC, PERMISSION } from '../../../apps/api/src/common/decorators';
import type { TestApp } from '../../../apps/api/test/integration/helpers';

// @nestjs/common/constants (kept literal: this suite only resolves modules through apps/api)
const PATH_METADATA = 'path';
const METHOD_METADATA = 'method';
const RequestMethod = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'ALL', 'OPTIONS', 'HEAD'];

export interface RouteInfo {
  method: string;
  /** full path, e.g. `/api/v1/servers/:id` */
  path: string;
  isPublic: boolean;
  permission?: string;
  handler: string;
}

const join = (...parts: string[]) =>
  '/' +
  parts
    .map((p) => p.replace(/^\/+|\/+$/g, ''))
    .filter(Boolean)
    .join('/');

export function nestRoutes(t: TestApp): RouteInfo[] {
  const controllers = (AppModule.forRoot(t.config).controllers ?? []) as Array<
    new (...a: unknown[]) => unknown
  >;
  const out: RouteInfo[] = [];
  for (const ctrl of controllers) {
    const base = (Reflect.getMetadata(PATH_METADATA, ctrl) as string | undefined) ?? '';
    const proto = ctrl.prototype as Record<string, unknown>;
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === 'constructor') continue;
      const fn = proto[name];
      if (typeof fn !== 'function') continue;
      const sub = Reflect.getMetadata(PATH_METADATA, fn) as string | string[] | undefined;
      const m = Reflect.getMetadata(METHOD_METADATA, fn) as number | undefined;
      if (sub === undefined || m === undefined) continue;
      for (const s of Array.isArray(sub) ? sub : [sub]) {
        out.push({
          method: RequestMethod[m]!,
          path: join('api/v1', base, s),
          isPublic: !!(Reflect.getMetadata(IS_PUBLIC, fn) ?? Reflect.getMetadata(IS_PUBLIC, ctrl)),
          permission:
            (Reflect.getMetadata(PERMISSION, fn) as string | undefined) ??
            (Reflect.getMetadata(PERMISSION, ctrl) as string | undefined),
          handler: `${ctrl.name}.${name}`,
        });
      }
    }
  }
  return out.sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method));
}

/** Routes actually mounted in Express (method + path), excluding middleware. */
export function expressRoutes(t: TestApp): string[] {
  const inst = t.app.getHttpAdapter().getInstance() as {
    router?: { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> };
    _router?: { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> };
  };
  const stack = (inst.router ?? inst._router)?.stack ?? [];
  const out: string[] = [];
  for (const l of stack) {
    if (!l.route) continue;
    for (const [m, on] of Object.entries(l.route.methods))
      if (on && m !== '_all') out.push(`${m.toUpperCase()} ${l.route.path}`);
  }
  return [...new Set(out)].sort();
}

export const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`;
