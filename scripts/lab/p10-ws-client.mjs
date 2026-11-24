#!/usr/bin/env node
// P10 lab WebSocket client for GET /api/v1/ssh/stream (docs/P10_SSH_CONTRACT.md §5). LAB / E2E ONLY.
// Used by scripts/lab/e2e_p10.py; no new dependency: `ws` is resolved from apps/api/node_modules.
//
// Input: ONE JSON object on stdin (the ticket never goes on the command line or into the URL):
//   { url, origin, timeoutMs?, steps: [ ... ] }
// Steps run in order:
//   { "text": <object|string> }                 send a text frame (object → JSON), e.g. the auth message
//   { "stdin": "echo hi\n" }                    send a binary frame (stdin bytes)
//   { "waitMessage": "ready", "timeoutMs"? }    wait for a server text frame { type: <value> }
//   { "waitOutput": "<regex>", "timeoutMs"? }   wait until the accumulated stdout matches
//   { "sleepMs": 500 }
//   { "keepalive": { "everyMs": 2000, "forMs": 60000, "data": "\n" } }
//                                               send stdin every everyMs until closed or forMs elapsed
//   { "waitClose": 30000 }                      wait for the server to close
//   { "close": 1000 }                           close from the client
// Output (stdout, one JSON line): { upgradeStatus, opened, messages: [text frames], stdout (≤ 64 KiB, utf8),
//   stdoutBytes, closeCode, closeReason, closedBy, durationMs, failedStep, error }
// Exit code 0 whenever the run itself worked (assertions are made by the caller).
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(here, '../../apps/api/package.json'));
const WebSocket = require('ws');

const MAX_STDOUT = 64 * 1024;

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const cfg = await readStdin();
const started = Date.now();
const out = {
  upgradeStatus: null,
  opened: false,
  messages: [],
  stdout: '',
  stdoutBytes: 0,
  closeCode: null,
  closeReason: null,
  closedBy: null,
  durationMs: 0,
  failedStep: null,
  error: null,
};
let stdoutBuf = Buffer.alloc(0);
let closed = false;
const waiters = new Set();
const notify = () => {
  for (const w of [...waiters]) w();
};

function waitFor(pred, timeoutMs, what) {
  return new Promise((resolve, reject) => {
    if (pred()) return resolve(true);
    const t = setTimeout(() => {
      waiters.delete(check);
      reject(new Error(`timeout waiting for ${what}`));
    }, timeoutMs);
    const check = () => {
      if (pred()) {
        clearTimeout(t);
        waiters.delete(check);
        resolve(true);
      } else if (closed && what !== 'close') {
        clearTimeout(t);
        waiters.delete(check);
        reject(new Error(`closed while waiting for ${what}`));
      }
    };
    waiters.add(check);
  });
}

const ws = new WebSocket(cfg.url, {
  origin: cfg.origin,
  handshakeTimeout: 10_000,
  maxPayload: 1024 * 1024,
  perMessageDeflate: false,
});

ws.on('unexpected-response', (_req, res) => {
  out.upgradeStatus = res.statusCode;
  closed = true;
  res.resume();
  notify();
});
ws.on('upgrade', (res) => {
  out.upgradeStatus = res.statusCode;
});
ws.on('open', () => {
  out.opened = true;
  notify();
});
ws.on('message', (data, isBinary) => {
  if (isBinary) {
    out.stdoutBytes += data.length;
    if (stdoutBuf.length < MAX_STDOUT)
      stdoutBuf = Buffer.concat([stdoutBuf, data]).subarray(0, MAX_STDOUT);
    out.stdout = stdoutBuf.toString('utf8');
  } else {
    const s = data.toString('utf8');
    let m;
    try {
      m = JSON.parse(s);
    } catch {
      m = { raw: s.slice(0, 500) };
    }
    out.messages.push(m);
  }
  notify();
});
ws.on('close', (code, reason) => {
  if (out.closeCode === null) {
    out.closeCode = code;
    out.closeReason = reason.toString('utf8');
    if (!out.closedBy) out.closedBy = 'server';
  }
  closed = true;
  notify();
});
ws.on('error', (e) => {
  if (!out.error) out.error = String(e.message || e);
  closed = true;
  notify();
});

const timeoutMs = cfg.timeoutMs ?? 60_000;
const hardStop = setTimeout(() => finish('global timeout'), timeoutMs + 5_000);

function finish(err) {
  if (err && !out.error) out.error = err;
  out.durationMs = Date.now() - started;
  clearTimeout(hardStop);
  try {
    if (!closed) ws.terminate();
  } catch {
    /* ignore */
  }
  process.stdout.write(JSON.stringify(out) + '\n');
  process.exit(0);
}

try {
  await waitFor(() => out.opened || closed, 15_000, 'open');
  if (!out.opened) finish(null);
  for (const [i, s] of (cfg.steps || []).entries()) {
    out.failedStep = i;
    if (s.text !== undefined) {
      if (closed) throw new Error('closed before send');
      ws.send(typeof s.text === 'string' ? s.text : JSON.stringify(s.text));
    } else if (s.stdin !== undefined) {
      if (closed) throw new Error('closed before send');
      ws.send(Buffer.from(s.stdin, 'utf8'), { binary: true });
    } else if (s.waitMessage !== undefined) {
      await waitFor(
        () => out.messages.some((m) => m.type === s.waitMessage),
        s.timeoutMs ?? 15_000,
        `message ${s.waitMessage}`,
      );
    } else if (s.waitOutput !== undefined) {
      const re = new RegExp(s.waitOutput);
      await waitFor(() => re.test(out.stdout), s.timeoutMs ?? 15_000, `output /${s.waitOutput}/`);
    } else if (s.sleepMs !== undefined) {
      await new Promise((r) => setTimeout(r, s.sleepMs));
    } else if (s.keepalive !== undefined) {
      const { everyMs = 2000, forMs = 60_000, data = '\n' } = s.keepalive;
      const end = Date.now() + forMs;
      while (!closed && Date.now() < end) {
        ws.send(Buffer.from(data, 'utf8'), { binary: true });
        await new Promise((r) => setTimeout(r, everyMs));
      }
    } else if (s.waitClose !== undefined) {
      await waitFor(() => closed, s.waitClose, 'close');
    } else if (s.close !== undefined) {
      if (!closed) {
        out.closedBy = 'client';
        ws.close(s.close);
        await waitFor(() => closed, 10_000, 'close');
      }
    }
  }
  out.failedStep = null;
  finish(null);
} catch (e) {
  finish(String(e.message || e));
}
