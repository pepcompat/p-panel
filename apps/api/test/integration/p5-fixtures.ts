/** P5 test fixtures: fake Loki / Prometheus / notification receiver, gzip log batches, SSE reader. */
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import zlib from 'node:zlib';
import { encryptSecret } from '../../src/common/crypto';
import { uuidv7 } from '../../src/common/ids';
import type { AgentCreds, AgentResponse, TestApp } from './helpers';

export interface Recorded {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface FakeServer {
  url: string;
  port: number;
  requests: Recorded[];
  close(): Promise<void>;
}

export function startFake(
  handler: (req: Recorded, res: http.ServerResponse) => void,
): Promise<FakeServer> {
  const requests: Recorded[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const rec: Recorded = {
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      requests.push(rec);
      handler(rec, res);
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        url: `http://127.0.0.1:${port}`,
        port,
        requests,
        close: () =>
          new Promise<void>((r) => {
            server.closeAllConnections();
            server.close(() => r());
          }),
      });
    }),
  );
}

export interface LokiStreamJson {
  stream: Record<string, string>;
  values: Array<[string, string]>;
}

/** Fake Loki: stores pushes; query_range answers with EVERY stored stream (scope is the Center's job). */
export async function startFakeLoki() {
  const state = {
    mode: 'up' as 'up' | 'down',
    streams: [] as LokiStreamJson[],
    queries: [] as URLSearchParams[],
  };
  const fake = await startFake((req, res) => {
    if (state.mode === 'down') {
      res.writeHead(503).end('down');
      return;
    }
    if (req.path.startsWith('/loki/api/v1/push')) {
      const body = JSON.parse(req.body) as { streams: LokiStreamJson[] };
      state.streams.push(...body.streams);
      res.writeHead(204).end();
      return;
    }
    if (req.path.startsWith('/loki/api/v1/query_range')) {
      const q = new URL(req.path, 'http://x').searchParams;
      state.queries.push(q);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'success',
          data: { resultType: 'streams', result: state.streams },
        }),
      );
      return;
    }
    res.writeHead(404).end();
  });
  return Object.assign(fake, { state });
}

/** Fake Prometheus: records PromQL; answers a matrix with 2 points at start and start+step. */
export async function startFakeProm() {
  const state = { mode: 'up' as 'up' | 'down', queries: [] as URLSearchParams[] };
  const fake = await startFake((req, res) => {
    if (state.mode === 'down') {
      res.writeHead(503).end();
      return;
    }
    const q = new URLSearchParams(req.body);
    state.queries.push(q);
    const start = Number(q.get('start'));
    const step = parseInt(q.get('step') ?? '15', 10);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'success',
        data: {
          resultType: 'matrix',
          result: [
            {
              metric: {},
              values: [
                [start, '12.5'],
                [start + step, '0'],
              ],
            },
          ],
        },
      }),
    );
  });
  return Object.assign(fake, { state });
}

/** Notification receiver (webhook + fake Telegram API). */
export async function startReceiver() {
  const state = { status: 200 };
  const fake = await startFake((req, res) => {
    res.writeHead(state.status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: state.status < 300, result: { message_id: 1 } }));
  });
  return Object.assign(fake, { state });
}

export function logBatch(
  entries: Array<Record<string, unknown>>,
  extra: Record<string, unknown> = {},
) {
  return {
    batchId: randomUUID(),
    seq: 1,
    sentAt: new Date().toISOString(),
    entries,
    ...extra,
  };
}

export function entry(line: string, extra: Record<string, unknown> = {}) {
  return { ts: new Date().toISOString(), source: 'agent', level: 'info', line, ...extra };
}

/** mTLS POST /agent/v1/logs with gzip (or a raw body). */
export function postLogs(
  port: number,
  creds: AgentCreds,
  body: unknown,
  opts: { raw?: Buffer; gzip?: boolean } = {},
): Promise<AgentResponse & { headers: http.IncomingHttpHeaders }> {
  const json = opts.raw ?? Buffer.from(JSON.stringify(body));
  const payload = opts.gzip === false || opts.raw ? json : zlib.gzipSync(json);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        servername: 'localhost',
        method: 'POST',
        path: '/agent/v1/logs',
        key: creds.keyPem,
        cert: creds.certPem,
        ca: creds.caPem,
        agent: false,
        headers: {
          'X-Agent-Protocol': '1',
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
          ...(opts.gzip === false ? {} : { 'Content-Encoding': 'gzip' }),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: unknown = text;
          try {
            parsed = JSON.parse(text);
          } catch {
            /* keep */
          }
          resolve({ status: res.statusCode ?? 0, body: parsed, headers: res.headers });
        });
      },
    );
    req.on('error', (e: NodeJS.ErrnoException) => {
      // the server may answer 413 and close while we are still writing
      if (e.code === 'EPIPE' || e.code === 'ECONNRESET')
        resolve({ status: 413, body: { error: { code: 'PAYLOAD_TOO_LARGE' } }, headers: {} });
      else reject(e);
    });
    req.end(payload);
  });
}

/** Inserts a managed container app with a current deployment (+ optional secrets). */
export async function createManagedApp(
  t: TestApp,
  opts: {
    serverId: string;
    name: string;
    createdBy: string;
    containerName?: string;
    secrets?: Record<string, string>;
    status?: string;
  },
): Promise<{ appId: string; deploymentId: string; containerName: string }> {
  const appId = uuidv7();
  const deploymentId = uuidv7();
  const containerName = opts.containerName ?? `ppanel-${opts.name}-${deploymentId.slice(-8)}`;
  await t.prisma.application.create({
    data: {
      id: appId,
      serverId: opts.serverId,
      name: opts.name,
      kind: 'container',
      ownershipMode: 'managed',
      sourceFindingFingerprint: `managed:${appId}`,
    },
  });
  await t.prisma.containerApp.create({
    data: {
      applicationId: appId,
      containerPort: 3000,
      healthcheck: {},
      resources: {},
      createdBy: opts.createdBy,
    },
  });
  await t.prisma.deployment.create({
    data: {
      id: deploymentId,
      applicationId: appId,
      serverId: opts.serverId,
      number: 1,
      trigger: 'manual',
      image: `lab-registry:5000/x@sha256:${'a'.repeat(64)}`,
      status: opts.status ?? 'succeeded',
      planHash: 'b'.repeat(64),
      approvalRequired: false,
      containerName,
      hostPort: 20001,
    },
  });
  await t.prisma.containerApp.update({
    where: { applicationId: appId },
    data: { currentDeploymentId: deploymentId },
  });
  for (const [key, value] of Object.entries(opts.secrets ?? {}))
    await t.prisma.secret.create({
      data: {
        id: uuidv7(),
        applicationId: appId,
        key,
        valueEncrypted: encryptSecret(t.config.masterKey, value, `secret:${appId}:${key}`),
        createdBy: opts.createdBy,
        updatedBy: opts.createdBy,
      },
    });
  return { appId, deploymentId, containerName };
}

export interface SseEvent {
  event: string;
  id?: string;
  data: unknown;
}

/** Opens an SSE stream and collects events until it ends or `timeoutMs`. */
export function readSse(
  url: string,
  opts: {
    timeoutMs?: number;
    headers?: Record<string, string>;
    until?: (e: SseEvent[]) => boolean;
  } = {},
): Promise<{
  status: number;
  headers: http.IncomingHttpHeaders;
  events: SseEvent[];
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const events: SseEvent[] = [];
    let body = '';
    const req = http.get(url, { headers: opts.headers }, (res) => {
      let buf = '';
      const finish = () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, events, body });
      const timer = setTimeout(() => {
        req.destroy();
        finish();
      }, opts.timeoutMs ?? 10_000);
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        body += chunk;
        buf += chunk;
        let idx: number;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const ev: SseEvent = { event: 'message', data: null };
          let isEvent = false;
          for (const line of block.split('\n')) {
            if (line.startsWith('event: ')) {
              ev.event = line.slice(7);
              isEvent = true;
            } else if (line.startsWith('id: ')) ev.id = line.slice(4);
            else if (line.startsWith('data: ')) {
              try {
                ev.data = JSON.parse(line.slice(6));
              } catch {
                ev.data = line.slice(6);
              }
            }
          }
          if (isEvent) events.push(ev);
          if (opts.until?.(events)) {
            clearTimeout(timer);
            req.destroy();
            return finish();
          }
        }
      });
      res.on('end', () => {
        clearTimeout(timer);
        finish();
      });
      res.on('error', () => undefined);
    });
    req.on('error', (e: NodeJS.ErrnoException) => {
      if (e.code === 'ECONNRESET') return;
      reject(e);
    });
  });
}
