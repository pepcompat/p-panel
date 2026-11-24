/**
 * P7.01 / P4-T06 GitHub webhook spoof & replay (threat TB8-S/R).
 */
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { buildWorld, MARK_A, type World } from '../lib/world';

const SECRET = 'webhook-secret-0123456789'; // set by buildWorld()
const AFTER = 'ab'.repeat(20);

let w: World;
beforeAll(async () => {
  w = await buildWorld();
  // deploymentA is the live deployment of commit AFTER → commit-level dedupe applies
  await w.t.prisma.deployment.update({
    where: { id: w.ids.deploymentA },
    data: { commitSha: AFTER },
  });
});
afterAll(async () => w.t.close());

const payload = (after = AFTER) =>
  JSON.stringify({
    ref: 'refs/heads/main',
    after,
    repository: { full_name: `org/${MARK_A}` },
  });
const sign = (body: string | Buffer, secret = SECRET) =>
  `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;

function post(body: string | Buffer, headers: Record<string, string>) {
  let r = w.t.http
    .post(`/api/v1/webhooks/github/${w.ids.integration}`)
    .set('Content-Type', 'application/json')
    .set('X-GitHub-Event', 'push');
  for (const [k, v] of Object.entries(headers)) r = r.set(k, v);
  return r.send(body);
}

describe('signature', () => {
  it('missing / wrong / malformed signatures are 401 and create no delivery row', async () => {
    const body = payload();
    const bad: Array<Record<string, string>> = [
      {},
      { 'X-Hub-Signature-256': sign(body, 'wrong-secret-0123456789') },
      { 'X-Hub-Signature-256': sign(payload('cd'.repeat(20))) }, // signature of another body
      { 'X-Hub-Signature-256': sign(body).toUpperCase() },
      { 'X-Hub-Signature-256': sign(body).replace('sha256=', 'sha1=') },
      { 'X-Hub-Signature-256': sign(body).slice(0, -2) },
      { 'X-Hub-Signature-256': `${sign(body)}00` },
      { 'X-Hub-Signature': `sha1=${createHmac('sha1', SECRET).update(body).digest('hex')}` },
    ];
    const rows0 = await w.t.prisma.webhookDelivery.count();
    for (const h of bad) {
      const r = await post(body, {
        'X-GitHub-Delivery': `d-${Math.random()}`.replace('.', ''),
        ...h,
      });
      expect(r.status, JSON.stringify(h)).toBe(401);
      expect(r.body.error.code).toBe('WEBHOOK_SIGNATURE_INVALID');
    }
    expect(await w.t.prisma.webhookDelivery.count()).toBe(rows0);
  });

  it('verification is constant-time over the raw body bytes', () => {
    const src = readFileSync(
      path.resolve(__dirname, '../../../apps/api/src/deploy/webhooks.service.ts'),
      'utf8',
    );
    const fn = src.slice(
      src.indexOf('export function verifyGithubSignature'),
      src.indexOf('interface PushPayload'),
    );
    expect(fn).toContain('timingSafeEqual(given, expected)');
    // only the (public) lengths are compared directly
    expect(fn.replace(/given\.length === expected\.length/, '')).not.toMatch(/===|\.equals\(/);
  });

  it('whitespace-reformatted JSON (same JSON, different bytes) fails: HMAC is over raw bytes', async () => {
    const body = payload();
    const r = await post(JSON.stringify(JSON.parse(body), null, 2), {
      'X-GitHub-Delivery': 'reformat-1',
      'X-Hub-Signature-256': sign(body),
    });
    expect(r.status).toBe(401);
  });
});

describe('replay', () => {
  it('same delivery id → duplicate, no second processing', async () => {
    const body = payload();
    const h = { 'X-GitHub-Delivery': 'dup-delivery-1', 'X-Hub-Signature-256': sign(body) };
    const first = await post(body, h);
    expect(first.status).toBe(200);
    expect(first.body.data.duplicate).toBe(false);
    const again = await post(body, h);
    expect(again.status).toBe(200);
    expect(again.body.data).toEqual({ duplicate: true, deliveryId: 'dup-delivery-1' });
    expect(
      await w.t.prisma.webhookDelivery.count({ where: { deliveryId: 'dup-delivery-1' } }),
    ).toBe(1);
  });

  it('captured payload replayed with a NEW delivery id: recorded, but commit-level dedupe → no deployment', async () => {
    const body = payload();
    const deps0 = await w.t.prisma.deployment.count();
    const r = await post(body, {
      'X-GitHub-Delivery': 'replay-new-id-2',
      'X-Hub-Signature-256': sign(body),
    });
    expect(r.status).toBe(200);
    expect(r.body.data.duplicate).toBe(false);
    expect(r.body.data.reasons).toContain('already_deployed');
    expect(r.body.data.deploymentIds).toEqual([]);
    expect(await w.t.prisma.deployment.count()).toBe(deps0);
  });
});

describe('transport', () => {
  it('oversized body (> 1 MiB) is 413 before any processing', async () => {
    const big = Buffer.alloc(1024 * 1024 + 10, 0x20);
    const r = await post(big, { 'X-GitHub-Delivery': 'big-1', 'X-Hub-Signature-256': sign(big) });
    expect(r.status).toBe(413);
    expect(r.body.error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  it('wrong content-type cannot bypass the signature (raw bytes are always verified)', async () => {
    const body = payload();
    for (const ct of [
      'text/plain',
      'application/x-www-form-urlencoded',
      'multipart/form-data; boundary=x',
    ]) {
      const bad = await w.t.http
        .post(`/api/v1/webhooks/github/${w.ids.integration}`)
        .set('Content-Type', ct)
        .set('X-GitHub-Delivery', `ct-${ct.length}`)
        .set('X-Hub-Signature-256', sign('{}'))
        .send(body);
      expect(bad.status, ct).toBe(401);
    }
  });

  it('missing delivery id with a valid signature is 400 (no unkeyed processing)', async () => {
    const body = payload();
    const r = await post(body, { 'X-Hub-Signature-256': sign(body) });
    expect(r.status).toBe(400);
  });

  it('unknown integration id is 404 without touching the signature path', async () => {
    const r = await w.t.http
      .post('/api/v1/webhooks/github/01a207ea-0000-7000-8000-000000000000')
      .set('Content-Type', 'application/json')
      .send('{}');
    expect(r.status).toBe(404);
  });
});
