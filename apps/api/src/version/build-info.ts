import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

/**
 * P8 build identity (docs/RELEASE_CONTRACT.md §1). Images get it from build args → env
 * (`PPANEL_VERSION`, `PPANEL_COMMIT`, `PPANEL_BUILD_DATE`); a source checkout falls back to the root
 * `VERSION` file so `GET /version` is meaningful in dev too.
 */
export interface BuildInfo {
  version: string;
  commit: string;
  buildDate: string | null;
}

const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

/** Strict SemVer 2.0 (a leading `v` is tolerated). Returns null for anything else (e.g. `dev`). */
export function parseSemver(v: string | null | undefined): SemVer | null {
  if (!v) return null;
  const m = SEMVER_RE.exec(v.trim().replace(/^v/, ''));
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ? m[4].split('.') : [],
  };
}

/** SemVer precedence: <0, 0, >0. A prerelease sorts before its release (0.8.0-rc.1 < 0.8.0). */
export function compareSemver(a: SemVer, b: SemVer): number {
  for (const k of ['major', 'minor', 'patch'] as const) if (a[k] !== b[k]) return a[k] - b[k];
  if (!a.prerelease.length || !b.prerelease.length)
    return b.prerelease.length - a.prerelease.length;
  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i++) {
    const x = a.prerelease[i];
    const y = b.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny && Number(x) !== Number(y)) return Number(x) - Number(y);
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Mixed-version policy (§2): Center N supports agents N and N-1 minor → `<major>.<minor-1>.0`
 * (`<major>.0.0` for a `.0` minor). Unparseable Center versions enforce nothing (`0.0.0`).
 */
export function deriveMinAgentVersion(centerVersion: string): string {
  const v = parseSemver(centerVersion);
  if (!v) return '0.0.0';
  return `${v.major}.${Math.max(0, v.minor - 1)}.0`;
}

/**
 * True only when the agent reported a parseable SemVer lower than `minAgentVersion`. Unknown
 * (never reported) and unparseable versions are not flagged: the Center cannot judge them.
 */
export function isAgentOutdated(
  agentVersion: string | null | undefined,
  minAgentVersion: string,
): boolean {
  const a = parseSemver(agentVersion);
  const min = parseSemver(minAgentVersion);
  if (!a || !min) return false;
  return compareSemver(a, min) < 0;
}

function versionFile(): string | null {
  // dist/main.js → apps/api/dist; src/version/*.ts → apps/api/src/version (tests / tsx)
  let dir = __dirname;
  for (let i = 0; i < 5; i++) {
    const f = path.join(dir, 'VERSION');
    if (existsSync(f) && existsSync(path.join(dir, 'pnpm-workspace.yaml'))) {
      const v = readFileSync(f, 'utf8').trim();
      return v || null;
    }
    dir = path.dirname(dir);
  }
  return null;
}

export function resolveBuildInfo(env: {
  PPANEL_VERSION?: string;
  PPANEL_COMMIT?: string;
  PPANEL_BUILD_DATE?: string;
}): BuildInfo {
  const buildDate = env.PPANEL_BUILD_DATE?.trim();
  return {
    version: env.PPANEL_VERSION?.trim() || versionFile() || '0.0.0-dev',
    commit: env.PPANEL_COMMIT?.trim() || 'unknown',
    buildDate:
      buildDate && !Number.isNaN(Date.parse(buildDate)) ? new Date(buildDate).toISOString() : null,
  };
}
