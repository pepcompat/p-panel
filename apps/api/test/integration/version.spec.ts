import { readdirSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  agentCall,
  bearer,
  bootApp,
  enrollAgent,
  type EnrolledAgent,
  heartbeatBody,
  login,
  resetDb,
  type TestApp,
} from './helpers';

// P8 (RELEASE_CONTRACT §1–§2): GET /version, GET /health, AGENT_OUTDATED.
const LATEST_MIGRATION = readdirSync(path.join(__dirname, '../../prisma/migrations'))
  .filter((d) => /^\d{14}_/.test(d))
  .sort()
  .at(-1);

let t: TestApp;
let port: number;
let owner: string;
let agent: EnrolledAgent;

beforeAll(async () => {
  t = await bootApp({
    PPANEL_VERSION: '0.8.0-rc.1',
    PPANEL_COMMIT: 'abc1234',
    PPANEL_BUILD_DATE: '2026-11-24T10:00:00Z',
    PPANEL_MIN_AGENT_VERSION: '0.7.0',
  });
  port = await t.gateway.start(0, '127.0.0.1');
});
afterAll(async () => {
  await t.gateway.stop();
  await t.close();
});
beforeEach(async () => {
  t.limiter.reset();
  await resetDb(t.prisma);
  owner = await login(t, 'superadmin');
  agent = await enrollAgent(t, owner); // enrolls reporting agentVersion 0.1.0
  await t.http
    .patch(`/api/v1/servers/${agent.serverId}`)
    .set(bearer(owner))
    .send({ ownedUnits: ['nginx.service'] });
});

const heartbeat = (seq: number, agentVersion: string) =>
  agentCall(port, agent.creds, 'POST', '/agent/v1/heartbeat', heartbeatBody(seq, { agentVersion }));
const createJob = (body: Record<string, unknown>) =>
  t.http.post(`/api/v1/servers/${agent.serverId}/jobs`).set(bearer(owner)).send(body);
const restart = { type: 'service.restart', params: { unit: 'nginx.service' } };

describe('GET /api/v1/version (public)', () => {
  it('returns build identity + compatibility policy in the success envelope, no auth', async () => {
    const r = await t.http.get('/api/v1/version');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      success: true,
      statusCode: 0,
      meta: { requestId: expect.any(String) },
    });
    expect(r.body.data).toEqual({
      version: '0.8.0-rc.1',
      commit: 'abc1234',
      buildDate: '2026-11-24T10:00:00.000Z',
      agentProtocol: '1',
      minAgentVersion: '0.7.0',
      schemaVersion: LATEST_MIGRATION,
    });
    expect(r.headers['cache-control']).toBe('no-store');
  });

  it('GET /api/v1/health → 200 ok with DB reachable', async () => {
    const r = await t.http.get('/api/v1/health');
    expect(r.status).toBe(200);
    expect(r.body.data).toEqual({ status: 'ok', db: 'ok', version: '0.8.0-rc.1' });
  });
});

describe('AGENT_OUTDATED (mixed-version policy)', () => {
  it('outdated agent: flagged in server facts, mutating job → 409, read-only job still runs', async () => {
    const s = await t.http.get(`/api/v1/servers/${agent.serverId}`).set(bearer(owner));
    expect(s.body.data).toMatchObject({ agentVersion: '0.1.0', agentOutdated: true });

    const bad = await createJob(restart);
    expect(bad.status).toBe(409);
    expect(bad.body.error).toMatchObject({
      code: 'AGENT_OUTDATED',
      details: { agentVersion: '0.1.0', minAgentVersion: '0.7.0', jobType: 'service.restart' },
    });
    expect(await t.prisma.job.count()).toBe(0);

    const ro = await createJob({ type: 'inventory.collect', params: {} });
    expect(ro.status).toBe(202);
  });

  it('Center workflows (createInternal) refuse mutating jobs for an outdated agent too', async () => {
    await expect(
      t.prisma.$transaction((tx) =>
        t.jobs.createInternal(tx, {
          serverId: agent.serverId,
          type: 'service.restart',
          params: { unit: 'nginx.service' },
          actorId: null,
          ttlSec: 60,
        }),
      ),
    ).rejects.toMatchObject({ status: 409, code: 'AGENT_OUTDATED' });
  });

  it('agent N-1 minor and N are current; upgrading via heartbeat clears the flag', async () => {
    expect((await heartbeat(1, '0.7.0')).status).toBe(200);
    let s = await t.http.get(`/api/v1/servers/${agent.serverId}`).set(bearer(owner));
    expect(s.body.data).toMatchObject({ agentVersion: '0.7.0', agentOutdated: false });
    expect((await createJob(restart)).status).toBe(202);

    expect((await heartbeat(2, '0.8.0-rc.1')).status).toBe(200);
    s = await t.http.get(`/api/v1/servers/${agent.serverId}`).set(bearer(owner));
    expect(s.body.data.agentOutdated).toBe(false);

    // a prerelease of the minimum is still older than the minimum
    expect((await heartbeat(3, '0.7.0-rc.2')).status).toBe(200);
    s = await t.http.get(`/api/v1/servers/${agent.serverId}`).set(bearer(owner));
    expect(s.body.data.agentOutdated).toBe(true);
  });

  it('unparseable agent versions (dev builds) are not judged', async () => {
    expect((await heartbeat(1, 'dev')).status).toBe(200);
    const s = await t.http.get(`/api/v1/servers/${agent.serverId}`).set(bearer(owner));
    expect(s.body.data.agentOutdated).toBe(false);
    expect((await createJob(restart)).status).toBe(202);
  });
});
