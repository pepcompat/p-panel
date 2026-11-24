import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import {
  J02_NODE,
  J02_PREFIX,
  LAB,
  TAG,
  apiLogin,
  createMfaUser,
  evidence,
  expectCall,
  nodeExec,
  poll,
  shot,
  signIn,
  signOut,
} from './lib';

// J05 (UI half) — production container deploy waits for a second person: the requester sees
// "waiting for approver", the approver approves the planHash in the Approvals UI with a fresh 2FA
// step-up, and the deployment goes live on the lab node. Lab only; uses the server enrolled by J02.
// Setup (users, managed routing, app, deployment request) goes through the API; deploy v2 / broken
// candidate / rollback are covered by scripts/lab/e2e_p4.py (see docs/ACCEPTANCE.md).

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../..');
const TERMINAL = ['succeeded', 'failed', 'rolled_back', 'requires_manual_recovery', 'cancelled'];

function labImage(key: string): string {
  const line = readFileSync(path.join(ROOT, '.lab/images.env'), 'utf8')
    .split('\n')
    .find((l) => l.startsWith(`${key}=`));
  if (!line) throw new Error(`${key} missing in .lab/images.env (run scripts/lab/images.sh)`);
  return line.slice(key.length + 1).replace('lab-registry:5000', '127.0.0.1:55000');
}

test('J05 production deploy: second-person approval with step-up in the UI', async ({
  page,
  request,
}, info) => {
  test.skip(!LAB, 'needs lab agents (scripts/lab/journeys.sh --lab)');
  test.setTimeout(480_000);
  const admin = await apiLogin(request, 'superadmin@ppanel.local');
  const servers = await expectCall<Array<{ id: string; name: string; status: string }>>(
    request,
    'GET',
    '/servers?limit=100',
    200,
    { token: admin },
  );
  const server = servers.find((s) => s.name.startsWith(J02_PREFIX) && s.status === 'online');
  expect(server, 'J02 must have enrolled an online production server').toBeTruthy();
  const sid = server!.id;
  // The Center's preflight refuses deployments on a node whose disk is >= 90 % (DISK_LOW). The lab
  // nodes share the Docker VM disk, so report that honestly as BLOCKED instead of a product failure.
  const blockedByDisk = (pct: number | null | undefined) =>
    `BLOCKED: lab node disk ${pct}% >= 90% (DISK_LOW preflight); free Docker VM disk and re-run`;
  const detail = await expectCall<{ metrics?: { diskPct?: number | null } | null }>(
    request,
    'GET',
    `/servers/${sid}`,
    200,
    { token: admin },
  );
  const disk = detail.metrics?.diskPct ?? null;
  if (disk !== null && disk >= 90) {
    evidence(info, 'precheck: lab node disk too full for a deployment', { diskPct: disk });
    test.skip(true, blockedByDisk(disk));
  }

  const requester = await createMfaUser(request, admin, 'j05-requester', 'ops_admin');
  const approver = await createMfaUser(request, admin, 'j05-approver', 'ops_admin');
  evidence(info, 'requester + approver (ops_admin, TOTP) created');

  // legacy discovery (preflight knows existing nginx domains), then managed routing (prod → approval)
  const scan = await expectCall<{ scanId: string }>(
    request,
    'POST',
    `/servers/${sid}/discovery-scans`,
    202,
    { token: admin, body: {} },
  );
  await poll(
    async () =>
      (
        await expectCall<{ status: string }>(
          request,
          'GET',
          `/discovery-scans/${scan.scanId}`,
          200,
          {
            token: admin,
          },
        )
      ).status !== 'running',
    120_000,
    'discovery scan',
  );
  const stepUp = async (u: typeof requester) =>
    (
      await expectCall<{ stepUpToken: string }>(request, 'POST', '/auth/step-up', 200, {
        token: u.token,
        body: { code: await u.totp.next() },
      })
    ).stepUpToken;
  await expectCall(request, 'POST', `/servers/${sid}/managed-routing`, 202, {
    token: requester.token,
    headers: { 'X-Step-Up': await stepUp(requester) },
  });
  const mr = await poll(
    async () => {
      const m = await expectCall<{ enabled: boolean; status: string; planHash: string }>(
        request,
        'GET',
        `/servers/${sid}/managed-routing`,
        200,
        { token: admin },
      );
      return m.enabled || ['awaiting_approval', 'failed'].includes(m.status) ? m : null;
    },
    120_000,
    'managed routing plan',
  );
  if (!mr.enabled) {
    expect(mr.status).toBe('awaiting_approval');
    await expectCall(request, 'POST', `/servers/${sid}/managed-routing/approve`, 202, {
      token: approver.token,
      body: { planHash: mr.planHash },
      headers: { 'X-Step-Up': await stepUp(approver) },
    });
    await poll(
      async () =>
        (
          await expectCall<{ enabled: boolean; status: string }>(
            request,
            'GET',
            `/servers/${sid}/managed-routing`,
            200,
            { token: admin },
          )
        ).enabled,
      180_000,
      'managed routing enabled',
    );
  }
  evidence(info, 'managed routing enabled on the production server (approved by second person)');

  // the requester asks for a production deployment → awaiting_approval, no job yet
  const appName = `j05-web-${TAG}`;
  const domain = `${appName}.lab.test`;
  const app = await expectCall<{ id: string }>(request, 'POST', '/applications', 201, {
    token: requester.token,
    body: {
      serverId: sid,
      name: appName,
      environment: 'production',
      domains: [domain],
      containerPort: 8080,
      healthcheck: { path: '/healthz' },
    },
  });
  const created = await expectCall<{
    deployment: { id: string; status: string; error?: unknown; preflight?: unknown };
  }>(request, 'POST', `/applications/${app.id}/deployments`, [200, 202], {
    token: requester.token,
    body: { image: labImage('PPANEL_LAB_IMAGE_WEB_V1'), reason: 'J05 journey' },
    headers: { 'Idempotency-Key': randomUUID() },
  });
  const depId = created.deployment.id;
  const pre = (created.deployment.preflight ?? []) as Array<{
    ok: boolean;
    code?: string;
    details?: { diskPct?: number };
  }>;
  const diskCheck = pre.find((c) => !c.ok && c.code === 'DISK_LOW');
  if (created.deployment.status === 'failed' && diskCheck) {
    evidence(info, 'deployment refused by DISK_LOW preflight (environment)', {
      deploymentId: depId,
      diskPct: diskCheck.details?.diskPct,
    });
    test.skip(true, blockedByDisk(diskCheck.details?.diskPct));
  }
  expect(created.deployment.status, JSON.stringify(created).slice(0, 1500)).toBe(
    'awaiting_approval',
  );
  evidence(info, 'production deployment awaiting approval', { deploymentId: depId });

  // UI — the requester cannot approve their own request
  await signIn(page, requester.email, requester.password, {
    totp: requester.totp,
    next: '/approvals',
  });
  await expect(page.getByTestId('approval-item').filter({ hasText: appName })).toBeVisible({
    timeout: 30_000,
  });
  await page.getByTestId('approval-item').filter({ hasText: appName }).click();
  await expect(page.getByTestId('waiting-approver')).toBeVisible();
  await shot(page, info, 'j05-1-requester-waits');
  await signOut(page);

  // UI — the approver approves the exact planHash with a fresh 2FA code
  await signIn(page, approver.email, approver.password, {
    totp: approver.totp,
    next: '/approvals',
  });
  const item = page.getByTestId('approval-item').filter({ hasText: appName });
  await expect(item).toBeVisible({ timeout: 30_000 });
  await item.click();
  const panel = page.getByTestId('approval-panel');
  const planHash = (await panel.getByTestId('plan-hash').innerText()).trim();
  expect(planHash).toMatch(/^[0-9a-f]{16,}$/);
  await shot(page, info, 'j05-2-approver-panel');
  await panel.getByLabel('2FA code').fill(await approver.totp.next());
  // wait for the approve call itself: navigating away right after the click can cancel it
  const approved = page.waitForResponse(
    (r) => r.request().method() === 'POST' && /\/deployments\/[^/]+\/approve/.test(r.url()),
    { timeout: 30_000 },
  );
  await panel.getByRole('button', { name: /^Approve plan/ }).click();
  const approveRes = await approved;
  expect(approveRes.status(), await approveRes.text()).toBeLessThan(300);
  evidence(info, 'approver approved planHash in UI with step-up', {
    planHash: planHash.slice(0, 16),
  });

  // the deployment runs and goes live
  await page.goto(`/deployments/${depId}`);
  await expect(page.getByTestId('deployment-status').first()).toHaveAttribute(
    'data-status',
    /succeeded|failed|rolled_back|requires_manual_recovery|cancelled/,
    { timeout: 240_000 },
  );
  const final = await expectCall<{ status: string; approval?: unknown }>(
    request,
    'GET',
    `/deployments/${depId}`,
    200,
    { token: admin },
  );
  expect(TERMINAL).toContain(final.status);
  expect(final.status).toBe('succeeded');
  await shot(page, info, 'j05-3-deployment-succeeded');
  const body = nodeExec(J02_NODE, `curl -s -m 5 -H 'Host: ${domain}' http://127.0.0.1/ || true`);
  expect(body).toContain('v1');
  evidence(info, 'site serves v1 through managed nginx route', { domain, body: body.slice(0, 60) });
});
