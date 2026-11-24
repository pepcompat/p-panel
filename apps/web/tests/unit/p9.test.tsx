import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import type { GatewayChangePlan } from '@/lib/api/p9-types';
import {
  cutoverText,
  isPrivateIp,
  matchesFilters,
  parseInventory,
  pathState,
  planGate,
  planStepState,
  policyChangeCheck,
  validateDiagnose,
  validateRoute,
  vpcDisplay,
} from '@/lib/p9-gates';
import { ServerCard } from '@/components/servers/server-card';
import { ConnectionSummary } from '@/components/p9/net-bits';
import { makeServer, meWithRole, renderWith } from './test-utils';

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

function plan(over: Partial<GatewayChangePlan> = {}): GatewayChangePlan {
  return {
    id: 'p1',
    gatewayId: 'g1',
    status: 'awaiting_approval',
    routesSnapshot: [],
    rendered: [],
    planHash: 'a'.repeat(64),
    nginxRevisionId: 'r1',
    nginxRevisionStatus: 'validated',
    validation: { valid: true, nginxTestOutput: 'ok' },
    shadowResults: [
      {
        domain: 'shop.w3.co',
        url: 'http://shop.w3.co/',
        viaGateway: { status: 200, latencyMs: 1, bodySha256: 'x' },
        direct: { status: 200, latencyMs: 1, bodySha256: 'x' },
        match: true,
      },
    ],
    verification: null,
    approval: { required: true, approvedBy: null, approvedAt: null },
    cutover: {
      dnsChanges: [
        {
          domain: 'shop.w3.co',
          mode: 'gateway',
          recordType: 'A',
          target: '203.0.113.9',
          directTarget: '198.51.100.4',
          action: 'point_to_gateway',
        },
        {
          domain: 'blog.w3.co',
          mode: 'hybrid',
          recordType: 'A',
          target: '198.51.100.4',
          directTarget: '198.51.100.4',
          action: 'none',
        },
      ],
      ttlAdvice: 'Lower TTL first.',
      verification: ['dig +short shop.w3.co A'],
      rollback: ['Set A shop.w3.co back to 198.51.100.4.'],
      note: 'pPanel never edits DNS.',
    },
    createdBy: 'creator',
    createdAt: ago(60),
    updatedAt: ago(30),
    allowedActions: ['shadow_test', 'approve'],
    ...over,
  };
}

const owner = meWithRole('platform_owner', true).permissions;
const viewer = meWithRole('viewer').permissions;

describe('P9 gates', () => {
  it('private ranges for diagnostics match the agent rule', () => {
    expect(
      ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '100.64.0.1', 'fd12::1'].every(
        isPrivateIp,
      ),
    ).toBe(true);
    expect(
      ['8.8.8.8', '172.32.0.1', '100.128.0.1', '127.0.0.1', '169.254.169.254', '2001:db8::1'].some(
        isPrivateIp,
      ),
    ).toBe(false);
  });

  it('validateDiagnose: hostnames only, IP:port lines, private targets, port warning', () => {
    expect(validateDiagnose('center.ppanel.internal', '10.104.0.5:4444').params).toEqual({
      resolve: ['center.ppanel.internal'],
      tcp: [{ host: '10.104.0.5', port: 4444 }],
      includeRoutes: true,
    });
    expect(validateDiagnose('10.0.0.1', '').errors.resolve).toBe('p9.diag.err.hostname');
    expect(validateDiagnose('', 'db:5432').errors.tcp).toBe('p9.diag.err.ipLiteral');
    expect(validateDiagnose('', 'just a host').errors.tcp).toBe('p9.diag.err.tcpFormat');
    expect(validateDiagnose('', '8.8.8.8:443').errors.tcp).toBe('p9.diag.err.privateOnly');
    expect(validateDiagnose('', '159.89.200.5:4443', true, ['159.89.200.5']).params).not.toBeNull();
    expect(validateDiagnose(Array(11).fill('a.b').join('\n'), '').errors.resolve).toBe(
      'p9.diag.err.resolveMax',
    );
    const w = validateDiagnose('', '10.0.0.2:8080');
    expect(w.params).not.toBeNull();
    expect(w.errors.portWarning).toEqual(['8080']);
  });

  it('parseInventory: JSON shape, strict rows, exactly one of serverId/hostname', () => {
    expect(parseInventory('nope').fatal).toBe('p9.inv.err.json');
    expect(parseInventory('{"a":1}').fatal).toBe('p9.inv.err.shape');
    expect(parseInventory('[]').fatal).toBe('p9.inv.err.empty');
    const tooMany = JSON.stringify(Array.from({ length: 501 }, () => ({ hostname: 'a' })));
    expect(parseInventory(tooMany).fatal).toBe('p9.inv.err.tooMany');
    const ok = parseInventory(
      '{"rows":[{"hostname":"dev-01","region":"sgp1","privateIpv4":"10.0.0.3"}]}',
    );
    expect(ok.issues).toEqual([]);
    expect(ok.rows).toHaveLength(1);
    const bad = parseInventory(
      JSON.stringify([
        { hostname: 'a', colour: 'red' },
        { privateIpv4: '10.0.0.999', hostname: 'b' },
        {},
      ]),
    );
    expect(bad.rows).toHaveLength(0);
    expect(bad.issues.map((i) => i.row)).toEqual(expect.arrayContaining([1, 2, 3]));
    expect(bad.issues.find((i) => i.row === 1)!.message).toMatch(/colour/);
  });

  it('validateRoute: domain, duplicate, health path, backends', () => {
    const base = {
      domain: 'shop.example.com',
      mode: 'hybrid' as const,
      healthPath: '/healthz',
      backends: [{ serverId: 's1', address: '', port: '80' }],
    };
    expect(validateRoute(base)).toEqual({});
    expect(validateRoute({ ...base, domain: 'localhost' }).domain).toBe('p9.route.err.domain');
    expect(validateRoute(base, ['shop.example.com']).domain).toBe('p9.route.err.duplicate');
    expect(validateRoute(base, ['shop.example.com'], true).domain).toBeUndefined();
    expect(validateRoute({ ...base, healthPath: 'healthz' }).healthPath).toBe(
      'p9.route.err.healthPath',
    );
    expect(validateRoute({ ...base, backends: [] }).backends).toBe('p9.route.err.noBackends');
    expect(
      validateRoute({
        ...base,
        backends: [
          { serverId: 's1', address: 'x', port: '80' },
          { serverId: '', address: '', port: '1' },
        ],
      }).backendRows,
    ).toEqual({ 0: 'p9.route.err.address', 1: 'p9.route.err.server' });
    expect(
      validateRoute({ ...base, backends: [{ serverId: 's1', address: '', port: '70000' }] })
        .backendRows,
    ).toEqual({
      0: 'p9.route.err.port',
    });
  });

  it('pathState: fail closed for private_only with a down private path; never claims private when public is active', () => {
    const s = makeServer({
      connectionPolicy: 'private_only',
      connection: {
        policy: 'private_only',
        activePath: null,
        endpoints: [
          {
            path: 'private',
            ok: false,
            latencyMs: null,
            checkedAt: ago(20),
            error: 'DIAL_TIMEOUT',
          },
          { path: 'public', ok: true, latencyMs: 20, checkedAt: ago(20) },
        ],
        reportedAt: ago(20),
      },
    });
    expect(pathState(s)).toMatchObject({
      failClosed: true,
      key: 'p9.path.failClosed',
      activePath: null,
    });
    const fallback = makeServer({
      connectionPolicy: 'auto',
      connection: { ...s.connection, policy: 'auto', activePath: 'public' },
    });
    expect(pathState(fallback)).toMatchObject({
      key: 'p9.path.activePublicFallback',
      activePath: 'public',
      tone: 'warn',
    });
  });

  it('policyChangeCheck: step-up in production, private_only needs a fresh healthy private probe', () => {
    const s = makeServer();
    expect(policyChangeCheck(s, 'private_only')).toMatchObject({
      needsStepUp: true,
      privateUnverified: false,
      failClosedWarning: true,
    });
    const old = makeServer({
      environment: 'development',
      connection: {
        ...s.connection,
        endpoints: [{ path: 'private', ok: true, latencyMs: 2, checkedAt: ago(600) }],
      },
    });
    expect(policyChangeCheck(old, 'private_only')).toMatchObject({
      needsStepUp: false,
      privateUnverified: true,
    });
    expect(policyChangeCheck(s, 'public_only').publicWarning).toBe(true);
    expect(policyChangeCheck(s, s.connectionPolicy).needsStepUp).toBe(false);
  });

  it('vpcDisplay never derives a VPC from agent facts', () => {
    const s = makeServer({
      provider: { name: 'digitalocean', region: 'sgp1', dropletId: '1', vpcUuid: 'agent-said' },
    });
    expect(vpcDisplay(s)).toMatchObject({ known: false });
    const known = makeServer({
      network: { region: 'sgp1', vpcUuid: 'v1', vpcName: 'prod', vpcSource: 'inventory' },
    });
    expect(vpcDisplay(known)).toMatchObject({ known: true, source: 'inventory', name: 'prod' });
  });

  it('matchesFilters: group (incl. ungrouped), tag, policy', () => {
    const s = makeServer({ groupId: 'g1', tags: ['web'] });
    expect(matchesFilters(s, { groupId: 'g1', tag: 'web', policy: 'private_preferred' })).toBe(
      true,
    );
    expect(matchesFilters(s, { groupId: '__none', tag: '', policy: '' })).toBe(false);
    expect(matchesFilters(s, { groupId: '', tag: 'db', policy: '' })).toBe(false);
    expect(matchesFilters(s, { groupId: '', tag: '', policy: 'public_only' })).toBe(false);
  });

  it('planGate: requester cannot approve own plan; apply waits for approval; viewer blocked', () => {
    const p = plan();
    expect(planGate('approve', p, owner, 'creator')).toMatchObject({
      allowed: false,
      reason: { key: 'p9.plan.gate.ownPlan' },
    });
    expect(planGate('approve', p, owner, 'someone-else').allowed).toBe(true);
    expect(planGate('approve', p, viewer, 'someone-else').reason?.key).toBe('perm.missing');
    expect(planGate('apply', p, owner, 'creator').reason?.key).toBe('p9.plan.gate.needApproval');
    const approved = plan({
      approval: { required: true, approvedBy: 'x', approvedAt: ago(5) },
      allowedActions: ['apply'],
    });
    expect(planGate('apply', approved, owner, 'creator').allowed).toBe(true);
    expect(
      planGate('apply', plan({ status: 'validated', shadowResults: null }), owner, 'c').reason?.key,
    ).toBe('p9.plan.gate.needShadow');
    expect(
      planGate('rollback', plan({ status: 'applied', allowedActions: ['rollback'] }), owner, 'c')
        .allowed,
    ).toBe(true);
    expect(
      planGate('shadow_test', plan({ status: 'shadow_testing' }), owner, 'c').reason?.key,
    ).toBe('p9.plan.gate.busy');
    // the API's allowedActions has the last word
    expect(planGate('approve', plan({ allowedActions: [] }), owner, 'other').reason?.key).toBe(
      'perm.actionNotAllowed',
    );
  });

  it('planStepState follows create → validate → shadow → approval → apply', () => {
    expect(
      planStepState(
        plan({
          status: 'draft',
          validation: { valid: null, nginxTestOutput: null },
          shadowResults: null,
        }),
      ),
    ).toMatchObject({
      validate: 'running',
      shadow: 'todo',
    });
    expect(planStepState(plan())).toMatchObject({
      validate: 'done',
      shadow: 'done',
      approval: 'current',
      apply: 'todo',
    });
    expect(
      planStepState(
        plan({
          approval: { required: false, approvedBy: null, approvedAt: null },
          status: 'shadow_tested',
        }),
      ),
    ).toMatchObject({
      approval: 'skipped',
      apply: 'current',
    });
    expect(
      planStepState(
        plan({
          status: 'failed',
          validation: { valid: false, nginxTestOutput: 'x' },
          shadowResults: null,
        }),
      ).validate,
    ).toBe('failed');
    expect(
      planStepState(
        plan({
          status: 'applied',
          approval: { required: true, approvedBy: 'x', approvedAt: ago(1) },
        }),
      ).apply,
    ).toBe('done');
  });

  it('cutoverText lists only records to change and states that pPanel never edits DNS', () => {
    const txt = cutoverText(plan());
    expect(txt).toContain('A shop.w3.co -> 203.0.113.9');
    expect(txt).not.toContain('blog.w3.co ->');
    expect(txt).toMatch(/never edits DNS/);
    expect(txt).toContain('1. Set A shop.w3.co back to 198.51.100.4.');
  });
});

describe('P9 server card', () => {
  it('shows env, group, verified private marker, policy + active path dots and an honest VPC label', () => {
    renderWith(
      <ServerCard
        server={makeServer({
          groupName: 'storefront',
          network: { region: 'sgp1', vpcUuid: null, vpcName: null, vpcSource: null },
        })}
        now={Date.now()}
      />,
    );
    const card = screen.getByTestId('server-card');
    expect(within(card).getByText('PRODUCTION')).toBeInTheDocument();
    expect(within(card).getByTestId('card-group')).toHaveTextContent('storefront');
    expect(within(card).getByTestId('private-verified')).toHaveAttribute('data-verified', 'true');
    expect(within(card).getByTestId('active-path')).toHaveAttribute('data-path', 'private');
    const dots = within(card).getByTestId('path-dots');
    expect(dots.querySelector('[data-path="private"]')).toHaveAttribute('data-health', 'ok');
    expect(within(card).getByTestId('vpc-label')).toHaveAttribute('data-source', 'unknown');
    expect(within(card).getByText('VPC unknown')).toBeInTheDocument();
  });

  it('renders the provider-sourced VPC name and the fail-closed state (TH locale)', () => {
    const s = makeServer({
      connectionPolicy: 'private_only',
      network: { region: 'sgp1', vpcUuid: '5f1c', vpcName: 'prod-sgp1', vpcSource: 'provider' },
      connection: {
        policy: 'private_only',
        activePath: null,
        endpoints: [
          {
            path: 'private',
            ok: false,
            latencyMs: null,
            checkedAt: ago(10),
            error: 'DIAL_TIMEOUT',
          },
        ],
        reportedAt: ago(10),
      },
    });
    renderWith(<ConnectionSummary server={s} now={Date.now()} />, { locale: 'th' });
    expect(screen.getByTestId('active-path')).toHaveTextContent('ปิดการเชื่อมต่อ');
    renderWith(<ServerCard server={s} now={Date.now()} />);
    expect(screen.getByTestId('vpc-label')).toHaveAttribute('data-source', 'provider');
    expect(screen.getByText('prod-sgp1')).toBeInTheDocument();
  });
});
