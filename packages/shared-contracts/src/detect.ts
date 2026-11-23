// P4.03 — framework detection. Pure (no I/O) so the UI can preview the same result as the Center.

export const FRAMEWORKS = [
  'nextjs',
  'nestjs',
  'laravel',
  'dockerfile',
  'compose',
  'unknown',
] as const;
export type Framework = (typeof FRAMEWORKS)[number];
export type BuildMethod = 'compose' | 'dockerfile' | 'framework_default' | 'none';

export interface DetectResult {
  framework: Framework;
  confidence: 'high' | 'medium' | 'low';
  evidence: string[];
  suggested: { containerPort: number | null; healthcheckPath: string; buildMethod: BuildMethod };
}

const COMPOSE_NAMES = ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'];

function base(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] ?? path;
}

function parseJson(text: string | undefined): Record<string, unknown> | null {
  if (text === undefined) return null;
  try {
    const v = JSON.parse(text) as unknown;
    return v !== null && typeof v === 'object' && !Array.isArray(v)
      ? (v as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function deps(pkg: Record<string, unknown> | null, field: string): Record<string, string> {
  const v = pkg?.[field];
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, string>)
    : {};
}

/** First `EXPOSE <port>` in a Dockerfile, or null. */
export function dockerfileExposedPort(text: string): number | null {
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*EXPOSE\s+(\d{1,5})(?:\/tcp)?\b/i.exec(line);
    if (m) {
      const p = Number(m[1]);
      if (p >= 1 && p <= 65535) return p;
    }
  }
  return null;
}

/**
 * Detects the framework from a few repository files (names → small contents). Precedence: Compose
 * (multi-service) → Next.js → NestJS → Laravel → plain Dockerfile → unknown. A Dockerfile, when
 * present, always becomes the suggested build method.
 */
export function detectFramework(input: Record<string, string>): DetectResult {
  const files = new Map<string, string>();
  for (const [k, v] of Object.entries(input)) if (!files.has(base(k))) files.set(base(k), v);
  const evidence: string[] = [];
  const dockerfile = files.get('Dockerfile');
  const exposed = dockerfile !== undefined ? dockerfileExposedPort(dockerfile) : null;
  const buildFor = (fallback: BuildMethod): BuildMethod =>
    dockerfile !== undefined ? 'dockerfile' : fallback;

  const compose = COMPOSE_NAMES.find((n) => files.has(n));
  if (compose) {
    evidence.push(`${compose} present`);
    return {
      framework: 'compose',
      confidence: 'high',
      evidence,
      suggested: { containerPort: exposed, healthcheckPath: '/', buildMethod: 'compose' },
    };
  }

  const pkgText = files.get('package.json');
  const pkg = parseJson(pkgText);
  if (pkgText !== undefined && pkg === null) evidence.push('package.json is not valid JSON');
  const all = { ...deps(pkg, 'devDependencies'), ...deps(pkg, 'dependencies') };
  const scripts = deps(pkg, 'scripts');

  const nextConfig = [...files.keys()].find((n) => /^next\.config\.(js|mjs|cjs|ts)$/.test(n));
  if (all.next || nextConfig) {
    if (all.next) evidence.push(`package.json depends on next@${all.next}`);
    if (nextConfig) evidence.push(`${nextConfig} present`);
    if (typeof scripts.build === 'string' && scripts.build.includes('next'))
      evidence.push('build script runs next');
    return {
      framework: 'nextjs',
      confidence: all.next && (nextConfig || scripts.build?.includes('next')) ? 'high' : 'medium',
      evidence,
      suggested: {
        containerPort: exposed ?? 3000,
        healthcheckPath: '/',
        buildMethod: buildFor('framework_default'),
      },
    };
  }

  if (all['@nestjs/core'] || files.has('nest-cli.json')) {
    if (all['@nestjs/core'])
      evidence.push(`package.json depends on @nestjs/core@${all['@nestjs/core']}`);
    if (files.has('nest-cli.json')) evidence.push('nest-cli.json present');
    return {
      framework: 'nestjs',
      confidence: all['@nestjs/core'] && files.has('nest-cli.json') ? 'high' : 'medium',
      evidence,
      suggested: {
        containerPort: exposed ?? 3000,
        healthcheckPath: '/',
        buildMethod: buildFor('framework_default'),
      },
    };
  }

  const composer = parseJson(files.get('composer.json'));
  const phpReq = { ...deps(composer, 'require-dev'), ...deps(composer, 'require') };
  if (phpReq['laravel/framework'] || files.has('artisan')) {
    if (phpReq['laravel/framework'])
      evidence.push(`composer.json requires laravel/framework ${phpReq['laravel/framework']}`);
    if (files.has('artisan')) evidence.push('artisan present');
    return {
      framework: 'laravel',
      confidence: phpReq['laravel/framework'] && files.has('artisan') ? 'high' : 'medium',
      evidence,
      suggested: {
        containerPort: exposed ?? 80,
        healthcheckPath: '/',
        buildMethod: buildFor('framework_default'),
      },
    };
  }

  if (dockerfile !== undefined) {
    evidence.push('Dockerfile present');
    if (exposed) evidence.push(`Dockerfile EXPOSE ${exposed}`);
    return {
      framework: 'dockerfile',
      confidence: exposed ? 'high' : 'medium',
      evidence,
      suggested: { containerPort: exposed, healthcheckPath: '/', buildMethod: 'dockerfile' },
    };
  }

  return {
    framework: 'unknown',
    confidence: 'low',
    evidence: evidence.length ? evidence : ['no known framework markers'],
    suggested: { containerPort: null, healthcheckPath: '/', buildMethod: 'none' },
  };
}
