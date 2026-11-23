import { beforeEach, describe, expect, it } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { en } from '@/i18n/en';
import { SecretInput } from '@/components/p4/secret-input';
import { PreflightList } from '@/components/p4/bits';
import {
  deployReady,
  deploymentGate,
  hostnameError,
  initialWizard,
  lifecycleActions,
  maxReachableStep,
  resolveImage,
  stepIssues,
  volumeError,
  WIZARD_STEPS,
  type WizardState,
} from '@/lib/p4-gates';
import type { Application } from '@/lib/api/p3-types';
import type { Deployment, PreflightCheck } from '@/lib/api/p4-types';
import { BUILTIN_ROLES } from '@ppanel/shared-contracts';
import { mockFetch, resetMockState } from '@/mocks/adapter';
import { createApiClient } from '@/lib/api/client';
import type { LoginSuccess } from '@/lib/api/types';
import { renderWith } from './test-utils';

const DIGEST = 'a'.repeat(64);
const PINNED = `registry.example.lab/w3/shop-api@sha256:${DIGEST}`;

describe('SecretInput', () => {
  it('never renders the value and clears it after submit', async () => {
    const user = userEvent.setup();
    const seen: string[] = [];
    const { container } = renderWith(
      <SecretInput
        secretKey="STRIPE_SECRET_KEY"
        status={{ set: true, version: 2 }}
        onSubmit={async (v) => {
          seen.push(v);
        }}
      />,
    );
    expect(screen.getByTestId('secret-status')).toHaveTextContent('set ✓ v2');
    const input = screen.getByLabelText('STRIPE_SECRET_KEY') as HTMLInputElement;
    expect(input.type).toBe('password');
    expect(input.getAttribute('autocomplete')).toBe('new-password');
    await user.type(input, 'sk_live_TOPSECRET');
    // Uncontrolled: the value is only a DOM property, never an attribute or text node.
    expect(container.innerHTML).not.toContain('TOPSECRET');
    expect(input.getAttribute('value')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Replace' }));
    await waitFor(() => expect(seen).toEqual(['sk_live_TOPSECRET']));
    expect(input.value).toBe('');
    expect(container.innerHTML).not.toContain('TOPSECRET');
    expect(document.body.textContent).not.toContain('TOPSECRET');
  });

  it('keeps the value only in the field when submit fails, and shows the error', async () => {
    const user = userEvent.setup();
    renderWith(
      <SecretInput
        secretKey="DB_PASSWORD"
        status={{ set: false }}
        onSubmit={() => Promise.reject(new Error('boom'))}
      />,
    );
    const input = screen.getByLabelText('DB_PASSWORD') as HTMLInputElement;
    await user.type(input, 'hunter2hunter2');
    await user.click(screen.getByRole('button', { name: 'Set' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('CLIENT_ERROR');
    expect(input.value).toBe('hunter2hunter2');
    expect(document.body.textContent).not.toContain('hunter2hunter2');
  });
});

describe('deploy wizard gating', () => {
  const ctx = {
    servers: [
      { id: 'on', status: 'online' as const, capabilities: ['docker', 'nginx'] },
      { id: 'off', status: 'offline' as const, capabilities: ['docker'] },
      { id: 'nodocker', status: 'online' as const, capabilities: ['nginx'] },
    ],
  };
  const valid = (): WizardState => {
    const w = initialWizard('new');
    w.source.repo = 'registry.example.lab/w3/shop-api';
    w.source.ref = `sha256:${DIGEST}`;
    w.target.serverId = 'on';
    w.config.name = 'shop-api';
    w.domain.domains = ['shop.example.lab'];
    return w;
  };

  it('starts at Source; every step must be valid before the next one opens', () => {
    const w = initialWizard('new');
    expect(maxReachableStep(w, ctx)).toBe(0);
    expect(stepIssues('source', w, ctx)).toContain('wiz.src.issue.image');
    const ok = valid();
    expect(maxReachableStep(ok, ctx)).toBe(WIZARD_STEPS.indexOf('review'));
  });

  it('a tag must be resolved to a pasted digest of the same repo', () => {
    const r = resolveImage('registry.example.lab/w3/shop-api', 'v1.4.2');
    expect(r.kind).toBe('tag');
    const w = valid();
    w.source.ref = 'v1.4.2';
    expect(stepIssues('source', w, ctx)).toEqual(['wiz.src.issue.digest']);
    w.source.digestRef = `registry.example.lab/w3/other@sha256:${DIGEST}`;
    expect(stepIssues('source', w, ctx)).toEqual(['wiz.src.issue.digest']);
    w.source.digestRef = PINNED;
    expect(stepIssues('source', w, ctx)).toEqual([]);
    expect(resolveImage(PINNED, '').kind).toBe('pinned');
  });

  it('GitHub App source cannot proceed; empty Git / Compose sources are blocked', () => {
    for (const kind of ['github', 'compose', 'git'] as const) {
      const w = valid();
      w.source.kind = kind;
      expect(maxReachableStep(w, ctx)).toBe(0);
    }
  });

  it('offline or docker-less servers block the Target step', () => {
    const w = valid();
    w.target.serverId = 'off';
    expect(stepIssues('target', w, ctx)).toEqual(['wiz.tgt.issue.offline']);
    w.target.serverId = 'nodocker';
    expect(stepIssues('target', w, ctx)).toEqual(['wiz.tgt.issue.offline']);
    expect(maxReachableStep(w, ctx)).toBe(WIZARD_STEPS.indexOf('target'));
  });

  it('declared secrets need a staged value; host paths are refused; hostnames validated', () => {
    const w = valid();
    w.config.secrets = [{ id: '1', key: 'API_KEY', staged: false }];
    expect(stepIssues('configure', w, ctx)).toContain('wiz.cfg.issue.secretValue');
    w.config.secrets[0]!.staged = true;
    expect(stepIssues('configure', w, ctx)).toEqual([]);
    expect(volumeError({ name: '/var/lib/data', mountPath: '/data' })).toBe(
      'wiz.cfg.vol.err.hostPath',
    );
    expect(volumeError({ name: './data', mountPath: '/data' })).toBe('wiz.cfg.vol.err.hostPath');
    expect(volumeError({ name: 'uploads', mountPath: '/app/uploads' })).toBeNull();
    expect(hostnameError('*.example.com')).toBe('wiz.dom.err.wildcard');
    expect(hostnameError('http://x.com')).toBe('wiz.dom.err.chars');
    expect(hostnameError('shop.example.com')).toBeNull();
    w.domain.domains = ['bad host'];
    expect(stepIssues('domain', w, ctx)).toContain('wiz.dom.issue.invalid');
  });
});

describe('preflight → deploy', () => {
  const checks = (failing: string[] = []): PreflightCheck[] =>
    (
      ['agent_online', 'managed_routing', 'image_pinned', 'domain_conflict', 'port_alloc'] as const
    ).map((c) => ({
      check: c,
      ok: !failing.includes(c),
      code: failing.includes(c) ? 'X' : undefined,
      message: c,
    }));

  it('deploy is disabled until preflight ran for this plan and every check passed', () => {
    const base = { stale: false, canDeploy: true, busy: false };
    expect(deployReady({ ...base, checks: null })).toEqual({
      ready: false,
      reason: 'wiz.rev.block.notRun',
    });
    expect(deployReady({ ...base, checks: checks(['port_alloc']) }).reason).toBe(
      'wiz.rev.block.failing',
    );
    expect(deployReady({ ...base, checks: checks(), stale: true }).reason).toBe(
      'wiz.rev.block.stale',
    );
    expect(deployReady({ ...base, checks: checks(), canDeploy: false }).reason).toBe(
      'wiz.rev.block.perm',
    );
    expect(deployReady({ ...base, checks: checks() })).toEqual({ ready: true, reason: null });
  });

  it('renders each check with status, code and remediation', () => {
    renderWith(
      <PreflightList
        checks={[
          { check: 'agent_online', ok: false, code: 'AGENT_OFFLINE', message: 'Agent is offline' },
          { check: 'disk', ok: true, warning: true, code: 'DISK_UNKNOWN', message: 'stale' },
          { check: 'lock', ok: true, message: 'free' },
        ]}
      />,
    );
    const rows = screen.getAllByTestId('preflight-check');
    expect(rows.map((r) => r.getAttribute('data-ok'))).toEqual(['false', 'true', 'true']);
    expect(rows[0]).toHaveTextContent('AGENT_OFFLINE');
    expect(rows[0]).toHaveTextContent('Fix:');
    expect(rows[1]).toHaveTextContent('warning');
  });
});

describe('deployment approval + lifecycle actions', () => {
  const dep = (over: Partial<Deployment> = {}) =>
    ({
      status: 'awaiting_approval',
      createdBy: 'u1',
      approval: { required: true, approvedBy: null, approvedAt: null, expiresAt: null },
      ...over,
    }) as Deployment;
  const owner = [...BUILTIN_ROLES.platform_owner];

  it('creator cannot approve; cancel only before route switch', () => {
    expect(deploymentGate('approve', dep(), owner, 'u1').reason?.key).toBe(
      'dep.reason.selfApproval',
    );
    expect(deploymentGate('approve', dep(), owner, 'u2').allowed).toBe(true);
    expect(deploymentGate('approve', dep(), [...BUILTIN_ROLES.deployer], 'u2').reason?.key).toBe(
      'perm.missing',
    );
    expect(deploymentGate('cancel', dep({ status: 'pulling' }), owner, 'u1').allowed).toBe(true);
    expect(deploymentGate('cancel', dep({ status: 'routing' }), owner, 'u1').reason?.key).toBe(
      'dep.reason.pastRoute',
    );
    expect(
      deploymentGate('cancel', dep({ status: 'pulling', allowedActions: [] }), owner, 'u1').allowed,
    ).toBe(false);
  });

  const app = (over: Partial<NonNullable<Application['container']>> = {}) =>
    ({
      environment: 'uat',
      allowedActions: ['deploy', 'redeploy', 'rollback', 'restart', 'start', 'stop'],
      container: {
        currentDeploymentId: 'd2',
        previousDeploymentId: 'd1',
        rollbackAvailable: true,
        runtimeState: 'running',
        ...over,
      },
    }) as unknown as Application;

  it('restart / redeploy / rollback / stop / start are distinct with their own effect', () => {
    const items = lifecycleActions(app(), owner, false);
    expect(items.map((i) => i.action)).toEqual([
      'restart',
      'redeploy',
      'rollback',
      'stop',
      'start',
    ]);
    const effects = items.map((i) => en[i.effect]);
    expect(new Set(effects).size).toBe(5);
    expect(items.find((i) => i.action === 'rollback')!.warning).toBe('life.rollback.noData');
    expect(en['life.rollback.noData']).toMatch(/never restores data/);
    expect(items.filter((i) => i.createsDeployment).map((i) => i.action)).toEqual([
      'redeploy',
      'rollback',
    ]);
    // running container: start blocked, others allowed
    expect(items.find((i) => i.action === 'start')!.gate.allowed).toBe(false);
    expect(items.filter((i) => i.gate.allowed).map((i) => i.action)).toEqual([
      'restart',
      'redeploy',
      'rollback',
      'stop',
    ]);
  });

  it('rollback needs a kept previous container; actions follow allowedActions and active deployments', () => {
    const noPrev = lifecycleActions(
      app({ rollbackAvailable: false, previousDeploymentId: null }),
      owner,
      false,
    );
    expect(noPrev.find((i) => i.action === 'rollback')!.gate.reason?.key).toBe(
      'life.block.noPrevious',
    );
    const busy = lifecycleActions(app(), owner, true);
    expect(busy.find((i) => i.action === 'redeploy')!.gate.reason?.key).toBe('life.block.active');
    const viewer = lifecycleActions(app(), [...BUILTIN_ROLES.viewer], false);
    expect(viewer.every((i) => !i.gate.allowed)).toBe(true);
  });
});

function client() {
  let tok: string | null = null;
  const c = createApiClient({
    baseUrl: 'http://mock/api/v1',
    clientVersion: 't',
    fetch: mockFetch as typeof fetch,
    tokenStore: { get: () => tok, set: (t) => (tok = t) },
  });
  return {
    c,
    async login(email: string) {
      const r = await c.post<LoginSuccess>(
        '/auth/login',
        { email, password: 'password' },
        { auth: false },
      );
      tok = r.accessToken;
    },
  };
}

describe('mock P4 (contract §7)', () => {
  beforeEach(() => resetMockState());

  it('preflight reports agent offline / no port; production waits for a different approver', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const apps = (await c.list<Application>('/applications')).items.filter(
      (a) => a.kind === 'container',
    );
    const byName = (n: string) => apps.find((a) => a.name === n)!;
    const pf = async (n: string) =>
      (
        await c.post<{ checks: PreflightCheck[] }>(
          `/applications/${byName(n).id}/deployments/preflight`,
          { image: PINNED },
        )
      ).checks;
    expect((await pf('queue-worker')).find((x) => !x.ok)?.code).toBe('AGENT_OFFLINE');
    expect((await pf('shop-api')).every((x) => x.ok)).toBe(true);

    const store = byName('storefront');
    const r = await c.post<{ deployment: Deployment }>(
      `/applications/${store.id}/deployments`,
      { image: PINNED },
      {
        headers: { 'Idempotency-Key': 'k1' },
      },
    );
    expect(r.deployment.status).toBe('awaiting_approval');
    await expect(
      c.post(`/deployments/${r.deployment.id}/approve`, { planHash: r.deployment.planHash }),
    ).rejects.toMatchObject({ code: 'APPROVER_IS_CREATOR' });
    // tag-only images refused
    await expect(
      c.post(`/applications/${byName('shop-api').id}/deployments`, {
        image: 'registry.example.lab/w3/shop-api:v1',
      }),
    ).rejects.toMatchObject({ code: 'IMAGE_NOT_PINNED' });
  });

  it('secrets are write-only and compose violations carry rule + path', async () => {
    const { c, login } = client();
    await login('admin@ppanel.local');
    const shop = (await c.list<Application>('/applications')).items.find(
      (a) => a.name === 'shop-api',
    )!;
    await act(async () => {
      await c.request('PUT', `/applications/${shop.id}/secrets/NEW_TOKEN`, {
        body: { value: 'very-secret-value' },
      });
    });
    const list = await c.list<Record<string, unknown>>(`/applications/${shop.id}/secrets`);
    expect(JSON.stringify(list.items)).not.toContain('very-secret-value');
    expect(list.items.find((s) => s.key === 'NEW_TOKEN')).toMatchObject({ set: true, version: 1 });
    const v = await c.post<{ valid: boolean; violations: Array<{ rule: string; path: string }> }>(
      '/deploy/compose/validate',
      {
        yaml: 'services:\n  web:\n    image: nginx:latest\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n',
      },
    );
    expect(v.valid).toBe(false);
    expect(v.violations.map((x) => x.rule)).toEqual(
      expect.arrayContaining(['privileged', 'host_network', 'docker_socket', 'image_not_pinned']),
    );
    expect(v.violations.find((x) => x.rule === 'privileged')!.path).toBe('services.web.privileged');
  });
});
