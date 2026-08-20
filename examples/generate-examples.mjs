/**
 * Generate `examples/response.example.json` and `examples/har.example.har`
 * against a local echo server, to illustrate the structured output.
 *
 * Run after `npm run build`:
 *   npm run generate-examples
 */
import { writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { HttpDebug } from '../lib/index.js';
import { buildHarLog } from '../lib/index.js';

const here = dirname(fileURLToPath(import.meta.url));

const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    if (req.url === '/items') {
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close', 'x-demo': 'v1' });
      res.end(JSON.stringify({ items: [{ id: 1, name: 'tea' }, { id: 2, name: 'sugar' }] }));
    } else if (req.url === '/binary') {
      res.writeHead(200, { 'content-type': 'application/octet-stream', connection: 'close' });
      res.end(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    } else {
      res.writeHead(404, { connection: 'close' });
      res.end('not found');
    }
  });
});

await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const http = new HttpDebug({ config: { ssrf: { whitelist: ['127.0.0.1'] } } });

const response = await http.request({
  url: `${base}/items`,
  headers: { 'accept': 'application/json' },
  validateJson: true,
  includeHar: true,
});

await writeFile(join(here, 'response.example.json'), JSON.stringify(response, null, 2), 'utf8');

const harLog = buildHarLog(
  { method: response.method, url: response.url, headers: response.headers },
  {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    contentType: response.contentType,
    body: response.body,
    bodyEncoding: response.bodyEncoding,
    bodySizeBytes: response.bodySizeBytes,
  },
  { durationMs: response.durationMs },
);
await writeFile(join(here, 'har.example.har'), JSON.stringify(harLog, null, 2), 'utf8');

server.close();
console.log('wrote examples/response.example.json and examples/har.example.har');
process.exit(0);
