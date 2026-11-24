/**
 * P9 Gateway rendering (pure; unit-tested). The Center renders every byte of the gateway's Nginx
 * files from validated fields only — domain (strict hostname), backend IPv4 literals + ports, health
 * path for postchecks. There is no way to pass a user-controlled Nginx directive.
 */
import {
  GATEWAY_INCLUDE_CONF_CONTENT,
  GATEWAY_INCLUDE_CONF_PATH,
  type GatewayCutover,
  type GatewayRoute,
  HEALTH_PATH_RE,
  HOSTNAME_RE,
  NGINX_GATEWAY_DIR,
  type ShadowResult,
} from '@ppanel/shared-contracts';
import net from 'node:net';
import { sha256Hex, stableStringify } from '../common/crypto';
import { contentSha256, type NginxFileEntry } from '../nginx/nginx-plan';

export interface RenderedFile {
  path: string;
  sha256: string;
  content: string;
  /** null for the include file */
  domain: string | null;
}

export const gatewayFilePath = (domain: string) => `${NGINX_GATEWAY_DIR}${domain}.conf`;

function assertSafe(route: GatewayRoute): void {
  if (!HOSTNAME_RE.test(route.domain)) throw new Error(`unsafe domain ${route.domain}`);
  if (!HEALTH_PATH_RE.test(route.healthPath)) throw new Error('unsafe health path');
  if (route.backends.length === 0) throw new Error('route without backends');
  for (const b of route.backends) {
    if (!net.isIPv4(b.address)) throw new Error(`backend address ${b.address} is not IPv4`);
    if (!Number.isInteger(b.port) || b.port < 1 || b.port > 65535) throw new Error('bad port');
  }
}

export function upstreamName(route: Pick<GatewayRoute, 'id' | 'domain'>): string {
  return `ppanel_gw_${route.domain.replace(/[^a-z0-9]/g, '_')}_${route.id.replace(/-/g, '').slice(-8)}`;
}

/** `server_name <domain>` → upstream of private backend addresses; plain HTTP reverse proxy. */
export function renderRouteConf(gatewayId: string, route: GatewayRoute): string {
  assertSafe(route);
  const up = upstreamName(route);
  const servers = route.backends
    .map((b) => `    server ${b.address}:${b.port} max_fails=3 fail_timeout=10s;`)
    .join('\n');
  return [
    `# Managed by pPanel gateway ${gatewayId} (route ${route.id}, mode ${route.mode}).`,
    '# Rendered by the Center from validated fields; manual edits are reported as drift.',
    `upstream ${up} {`,
    servers,
    '    keepalive 16;',
    '}',
    '',
    'server {',
    '    listen 80;',
    '    listen [::]:80;',
    `    server_name ${route.domain};`,
    '',
    '    location / {',
    `        proxy_pass http://${up};`,
    '        proxy_http_version 1.1;',
    '        proxy_set_header Connection "";',
    '        proxy_set_header Host $host;',
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '        proxy_set_header X-Forwarded-Proto $scheme;',
    '        proxy_connect_timeout 5s;',
    '        proxy_read_timeout 60s;',
    '        proxy_send_timeout 60s;',
    '    }',
    '}',
    '',
  ].join('\n');
}

/** Content written for a domain that left the gateway (revisions cannot delete files). */
export function renderRemovedConf(domain: string, gatewayId: string): string {
  if (!HOSTNAME_RE.test(domain)) throw new Error(`unsafe domain ${domain}`);
  return `# Managed by pPanel gateway ${gatewayId}: ${domain} is no longer routed by this gateway.\n`;
}

/**
 * Files of one plan: the include file, one `<domain>.conf` per hybrid/gateway route, and a
 * "removed" stub for every gateway file the host still has from an earlier applied plan.
 */
export function renderPlanFiles(
  gatewayId: string,
  routes: GatewayRoute[],
  knownFiles: NginxFileEntry[],
): RenderedFile[] {
  const out: RenderedFile[] = [
    {
      path: GATEWAY_INCLUDE_CONF_PATH,
      content: GATEWAY_INCLUDE_CONF_CONTENT,
      sha256: contentSha256(GATEWAY_INCLUDE_CONF_CONTENT),
      domain: null,
    },
  ];
  const active = [...routes]
    .filter((r) => r.mode !== 'direct')
    .sort((a, b) => a.domain.localeCompare(b.domain));
  const activePaths = new Set<string>();
  for (const r of active) {
    const content = renderRouteConf(gatewayId, r);
    const path = gatewayFilePath(r.domain);
    activePaths.add(path);
    out.push({ path, content, sha256: contentSha256(content), domain: r.domain });
  }
  const stale = knownFiles
    .filter((f) => f.lastKnownSha256 !== null && f.path.startsWith(NGINX_GATEWAY_DIR))
    .filter((f) => !activePaths.has(f.path))
    .map((f) => f.path.slice(NGINX_GATEWAY_DIR.length).replace(/\.conf$/, ''))
    .filter((d) => HOSTNAME_RE.test(d))
    .sort();
  for (const domain of stale) {
    const content = renderRemovedConf(domain, gatewayId);
    out.push({ path: gatewayFilePath(domain), content, sha256: contentSha256(content), domain });
  }
  return out;
}

/** plan_hash = sha256(gateway, routes snapshot, rendered files, nginx revision plan, shadow results). */
export function computeGatewayPlanHash(input: {
  gatewayId: string;
  routes: GatewayRoute[];
  rendered: Array<Pick<RenderedFile, 'path' | 'sha256'>>;
  revisionPlanHash: string | null;
  shadowResults: ShadowResult[] | null;
}): string {
  return sha256Hex(
    stableStringify({
      gatewayId: input.gatewayId,
      routes: [...input.routes]
        .map((r) => ({
          id: r.id,
          domain: r.domain,
          mode: r.mode,
          backends: r.backends.map((b) => ({
            serverId: b.serverId,
            address: b.address,
            port: b.port,
          })),
          healthPath: r.healthPath,
          version: r.version,
        }))
        .sort((a, b) => a.domain.localeCompare(b.domain)),
      rendered: [...input.rendered]
        .map((f) => ({ path: f.path, sha256: f.sha256 }))
        .sort((a, b) => a.path.localeCompare(b.path)),
      revisionPlanHash: input.revisionPlanHash,
      shadowResults: input.shadowResults
        ? [...input.shadowResults].sort((a, b) => a.domain.localeCompare(b.domain))
        : null,
    }),
  );
}

/** DNS cutover + rollback instructions. pPanel never edits DNS. */
export function buildCutover(
  planId: string,
  routes: GatewayRoute[],
  gateway: { publicIpv4: string | null; privateIpv4: string | null },
  directTargetOf: (r: GatewayRoute) => string | null,
): GatewayCutover {
  const gw = gateway.publicIpv4;
  const dnsChanges = [...routes]
    .sort((a, b) => a.domain.localeCompare(b.domain))
    .map((r) => {
      const direct = directTargetOf(r);
      return {
        domain: r.domain,
        mode: r.mode,
        recordType: 'A' as const,
        target: r.mode === 'gateway' ? gw : direct,
        directTarget: direct,
        action:
          r.mode === 'gateway'
            ? ('point_to_gateway' as const)
            : r.mode === 'direct'
              ? ('point_to_direct' as const)
              : ('none' as const),
      };
    });
  const probeAddr = gw ?? gateway.privateIpv4 ?? '<gateway-ip>';
  const verification = [...routes]
    .sort((a, b) => a.domain.localeCompare(b.domain))
    .filter((r) => r.mode !== 'direct')
    .flatMap((r) => [
      `curl -sS -o /dev/null -w '%{http_code}\\n' --resolve ${r.domain}:80:${probeAddr} http://${r.domain}${r.healthPath}`,
      `dig +short A ${r.domain}`,
    ]);
  return {
    dnsChanges,
    ttlAdvice:
      'Lower the TTL of every record you will change to 60 s at least one old-TTL period (e.g. 24 h) before the change; raise it again after the new target is verified.',
    verification,
    rollback: [
      'Point each changed DNS record back to its directTarget (the app server).',
      'Keep the direct origin serving the domain (do not stop or reconfigure its Nginx) until the old TTL has expired everywhere.',
      `Then remove the gateway config: POST /api/v1/gateway-plans/${planId}/rollback (reverts the Nginx revision on the gateway).`,
    ],
    note: 'pPanel never edits DNS. Make the DNS changes by hand at your DNS provider.',
  };
}
