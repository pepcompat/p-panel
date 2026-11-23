/**
 * Center-generated Nginx route for a managed container app (§7.3). No user free text reaches the
 * template: every interpolated value is re-validated here (defense in depth on top of the DTOs).
 */
import {
  APP_SLUG_RE,
  isValidHostname,
  MANAGED_PORT_MAX,
  MANAGED_PORT_MIN,
  NGINX_MANAGED_DIR,
  TLS_PATH_RE,
} from '@ppanel/shared-contracts';
import { UUID_RE } from '../common/ids';

export class RouteTemplateError extends Error {
  constructor(
    message: string,
    public readonly field: string,
  ) {
    super(message);
    this.name = 'RouteTemplateError';
  }
}

export interface RouteInput {
  deploymentId: string;
  app: string;
  hostPort: number;
  domains: string[];
  tls?: { certPath: string; keyPath: string } | null;
}

/** App slug → nginx upstream name (`my-app` → `ppanel_my_app`). */
export function upstreamName(app: string): string {
  if (!APP_SLUG_RE.test(app)) throw new RouteTemplateError('invalid app slug', 'app');
  return `ppanel_${app.replace(/-/g, '_')}`;
}

export function routePath(app: string): string {
  if (!APP_SLUG_RE.test(app)) throw new RouteTemplateError('invalid app slug', 'app');
  return `${NGINX_MANAGED_DIR}${app}/route.conf`;
}

/** Throws RouteTemplateError on the first invalid domain (strict hostname regex). */
export function assertDomains(domains: unknown): asserts domains is string[] {
  if (!Array.isArray(domains) || domains.length < 1 || domains.length > 10)
    throw new RouteTemplateError('1–10 domains required', 'domains');
  for (const d of domains)
    if (!isValidHostname(d))
      throw new RouteTemplateError(`invalid domain ${JSON.stringify(d)}`, 'domains');
  if (new Set(domains).size !== domains.length)
    throw new RouteTemplateError('duplicate domain', 'domains');
}

export function renderRoute(input: RouteInput): string {
  if (!UUID_RE.test(input.deploymentId))
    throw new RouteTemplateError('invalid deployment id', 'deploymentId');
  const upstream = upstreamName(input.app);
  if (
    !Number.isInteger(input.hostPort) ||
    input.hostPort < MANAGED_PORT_MIN ||
    input.hostPort > MANAGED_PORT_MAX
  )
    throw new RouteTemplateError('host port out of the managed range', 'hostPort');
  assertDomains(input.domains);
  const tlsLines: string[] = [];
  if (input.tls) {
    for (const [field, p] of [
      ['tls.certPath', input.tls.certPath],
      ['tls.keyPath', input.tls.keyPath],
    ] as const)
      if (!TLS_PATH_RE.test(p) || p.split('/').includes('..'))
        throw new RouteTemplateError(`invalid ${field}`, field);
    tlsLines.push(
      '    listen 443 ssl;',
      `    ssl_certificate ${input.tls.certPath};`,
      `    ssl_certificate_key ${input.tls.keyPath};`,
    );
  }
  return [
    `# managed by pPanel — deployment ${input.deploymentId}`,
    `upstream ${upstream} { server 127.0.0.1:${input.hostPort}; keepalive 16; }`,
    'server {',
    '    listen 80;',
    ...tlsLines,
    `    server_name ${input.domains.join(' ')};`,
    '    location / {',
    `        proxy_pass http://${upstream};`,
    '        proxy_http_version 1.1;',
    '        proxy_set_header Host $host;',
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '        proxy_set_header X-Forwarded-Proto $scheme;',
    '    }',
    '}',
    '',
  ].join('\n');
}
