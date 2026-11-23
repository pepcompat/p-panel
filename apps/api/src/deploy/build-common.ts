/** Pure build helpers shared by the builds workflow and the Application read model. */
import { type BuildConfig, buildLimitsSchema } from '@ppanel/shared-contracts';
import type { BuildConfig as BuildConfigRow } from '@prisma/client';

/** `org/name` when the URL path has exactly two segments (`.git` stripped) — used for sourceRef. */
export function repoOf(url: string): string | null {
  try {
    const parts = new URL(url).pathname
      .replace(/\.git$/, '')
      .split('/')
      .filter(Boolean);
    const r = parts.join('/');
    return parts.length === 2 && /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(r)
      ? r
      : null;
  } catch {
    return null;
  }
}

export function toBuildConfig(r: BuildConfigRow, gitSet: boolean): BuildConfig {
  return {
    repoUrl: r.repoUrl,
    repo: repoOf(r.repoUrl),
    subdir: r.subdir,
    dockerfile: r.dockerfile,
    template: (r.template as BuildConfig['template']) ?? null,
    buildArgs: (r.buildArgs ?? {}) as Record<string, string>,
    target: r.target,
    buildServerId: r.buildServerId,
    pushRepo: r.pushRepo,
    network: r.network as BuildConfig['network'],
    limits: buildLimitsSchema.parse(r.limits ?? {}),
    gitAuth: { set: gitSet },
    updatedAt: r.updatedAt.toISOString(),
    version: r.version,
  };
}
