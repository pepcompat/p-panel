/** Pure helpers for Nginx revisions: Center-side path policy, unified diffs and plan hashes. */
import { NGINX_MANAGED_DIR, nginxPathSchema } from '@ppanel/shared-contracts';
import { createTwoFilesPatch } from 'diff';
import { sha256Hex, stableStringify } from '../common/crypto';

export interface NginxFileEntry {
  path: string;
  lastKnownSha256: string | null;
  /** real path when `path` is a symlink (learned from nginx.read_files) */
  resolvedPath?: string | null;
}

export interface PlanFile {
  path: string;
  beforeSha256: string | null;
  afterSha256: string;
}

export function managedDirFor(applicationName: string): string {
  return `${NGINX_MANAGED_DIR}${applicationName}/`;
}

/**
 * Defense in depth (the agent re-checks): a revision path must be a canonical /etc/nginx path and be
 * one of the application's known files (or their symlink targets), or a file under the app's own
 * managed directory. Returns a reason string when rejected.
 */
export function checkRevisionPath(
  path: string,
  applicationName: string,
  files: NginxFileEntry[],
): string | null {
  if (!nginxPathSchema.safeParse(path).success) return 'path is not a canonical /etc/nginx path';
  const known = new Set<string>();
  for (const f of files) {
    known.add(f.path);
    if (f.resolvedPath) known.add(f.resolvedPath);
  }
  if (known.has(path)) return null;
  const dir = managedDirFor(applicationName);
  if (path.startsWith(dir) && path.length > dir.length) return null;
  return `path is not one of the application's nginx files nor under ${dir}`;
}

export function unifiedDiff(path: string, before: string | null, after: string): string {
  return createTwoFilesPatch(
    before === null ? '/dev/null' : `a${path}`,
    `b${path}`,
    before ?? '',
    after,
    undefined,
    undefined,
    { context: 3 },
  );
}

/** sha256(serverId + sorted(path, beforeSha256, afterSha256) + postchecks) — binds approvals to the exact plan. */
export function computePlanHash(
  serverId: string,
  files: PlanFile[],
  postchecks: unknown[],
): string {
  const sorted = [...files]
    .map((f) => ({ path: f.path, beforeSha256: f.beforeSha256, afterSha256: f.afterSha256 }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return sha256Hex(stableStringify({ serverId, files: sorted, postchecks }));
}

export function contentSha256(content: string): string {
  return sha256Hex(Buffer.from(content, 'utf8'));
}
