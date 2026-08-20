/**
 * dsh-http-debug — plain-Node usage of the core API.
 *
 * Run after `npm run build`:
 *   node examples/usage.mjs
 */
import { HttpDebug } from '../lib/index.js';
import { createServer } from 'node:http';

// 1) Spin up a tiny local echo server (whitelisted so the guard lets us in).
const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end(JSON.stringify({ path: req.url, method: req.method, body }));
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const http = new HttpDebug({
  config: { ssrf: { whitelist: ['127.0.0.1'] }, history: { maxEntries: 5 } },
});

// 2) A normal request.
const first = await http.request({
  url: `${base}/items?page=2`,
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ q: 'tea' }),
  validateJson: true,
  includeHar: true,
});
console.log('first:', first.status, 'ok=', first.ok, 'historyId=', first.historyId);
console.log('  json valid:', first.json.valid, '| har present:', Boolean(first.har));

// 3) This one is refused by the SSRF guard (private network, not whitelisted).
try {
  await http.request({ url: 'http://10.0.0.5/steal' });
} catch (error) {
  console.log('blocked:', error.code, '-', error.message);
}

// 4) History introspection.
console.log('history list:', JSON.stringify(http.historyList()));

// 5) Replay the first request.
const replayed = await http.request({ historyId: first.historyId });
console.log('replayed:', replayed.status, '| new historyId =', replayed.historyId);

server.close();
process.exit(0);
