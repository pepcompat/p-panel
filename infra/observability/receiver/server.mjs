// Lab receiver for webhook / Telegram notification channels (P5.05). Records every request in a
// bounded in-memory ring and exposes it for tests. No dependencies; never use outside the lab.
//   GET    /_health    → 200
//   GET    /_requests  → { requests: [{ at, method, path, headers, body }] } (newest last)
//   DELETE /_requests  → clears
//   /_status/<code>/…  → answers with <code> (exercise retries)
//   anything else      → 200 Telegram-shaped `{ ok: true, result: { message_id } }`
import http from 'node:http';

const MAX_REQUESTS = 200;
const MAX_BODY = 256 * 1024;
const requests = [];
let messageId = 0;

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://receiver');
  const send = (status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  if (url.pathname === '/_health') return send(200, { ok: true });
  if (url.pathname === '/_requests' && req.method === 'GET') return send(200, { requests });
  if (url.pathname === '/_requests' && req.method === 'DELETE') {
    requests.length = 0;
    return send(200, { ok: true });
  }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size <= MAX_BODY) chunks.push(c);
  });
  req.on('end', () => {
    requests.push({
      at: new Date().toISOString(),
      method: req.method,
      path: url.pathname,
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8'),
    });
    if (requests.length > MAX_REQUESTS) requests.shift();
    const forced = /^\/_status\/(\d{3})(?:\/|$)/.exec(url.pathname);
    if (forced) return send(Number(forced[1]), { ok: false });
    send(200, { ok: true, result: { message_id: ++messageId } });
  });
});

server.listen(8080, '0.0.0.0', () => console.log('receiver listening on :8080'));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
